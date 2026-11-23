# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k6_cilium_runtime"

class K6CiliumRuntimeTest < Minitest::Test
  Runtime = Conformance::K6CiliumRuntime
  BOOT = "11111111-1111-4111-8111-111111111111"
  POD = "22222222-2222-4222-8222-222222222222"
  INTERFACE = "lxc0123456789ab"
  ADDRESS = "10.244.0.53"
  SANDBOX = "pod#{POD}-0123456789ab".freeze

  def test_unavailable_agent_is_adequate_only_with_fresh_empty_kernel_and_journal_readback
    kernel = Minitest::Mock.new
    observer = Runtime.new("/unused", BOOT, kernel: kernel)
    loopback = {"kind" => "link", "metadata" => {"ifname" => "lo", "ifindex" => 1, "netns_inode" => 12}}
    workload = {"kind" => "link", "metadata" => {"ifname" => INTERFACE, "ifindex" => 12,
                                                 "mac" => "02:00:00:00:00:01", "kind" => "veth"}}
    host_route = {"kind" => "route", "metadata" => {"family" => "ipv4", "destination" => "#{ADDRESS}/32", "ifname" => INTERFACE}}
    kernel.expect(:resources, [loopback], kinds: %w[link address route])
    kernel.expect(:resources, [loopback, workload, host_route], kinds: %w[link address route])
    kernel.expect(:resources, [], kinds: %w[link address route])
    api = lambda do |_, kind, *|
      if kind == "node"
        {"metadata" => {"name" => "worker-0", "uid" => POD}, "status" => {"nodeInfo" => {"bootID" => BOOT}}}
      else
        {"items" => []}
      end
    end
    observer.stub(:kubectl, api) do
      snapshot, errors = observer.observe("worker-0", "post-uninstall", {})

      assert_empty errors
      assert_empty snapshot.fetch("kernel_links")
      assert_nil snapshot.fetch("agent_pod_uid")
      assert_equal POD, snapshot.fetch("worker_uid")

      snapshot, errors = observer.observe("worker-0", "post-uninstall", {SANDBOX => [ADDRESS]})

      assert_match(/still present/, errors.fetch(0))
      assert_equal([INTERFACE], snapshot.fetch("kernel_links").map { |link| link.fetch("ifname") })
      assert_equal({SANDBOX => [ADDRESS]}, snapshot.fetch("journal_ip_addresses"))
      assert_equal [ADDRESS], snapshot.fetch("kernel_pod_addresses")
      assert_raises(ArgumentError) { observer.observe("worker-0", "post-uninstall", {}) }
    end
    kernel.verify
  end

  def test_live_endpoint_has_to_agree_with_pod_ip_journal_and_kernel
    observer = Runtime.new("/unused", BOOT)
    agent = {"metadata" => {"name" => "cilium-test"}}
    pod = {"metadata" => {"uid" => POD, "name" => "k6-cilium-client", "namespace" => "k6-cilium"},
           "status" => {"phase" => "Running", "podIP" => ADDRESS}}
    row = {"id" => 123, "status" => {"state" => "ready", "external-identifiers" => {"cni-attachment-id" => "#{SANDBOX}:eth0"},
                                     "networking" => {"interface-name" => INTERFACE, "interface-index" => 12,
                                                      "host-mac" => "02:00:00:00:00:01", "addressing" => [{"ipv4" => ADDRESS}]}}}
    kernel = [{"ifname" => INTERFACE, "ifindex" => 12, "mac" => "02:00:00:00:00:01", "kind" => "veth"}]
    observer.stub(:kubectl, [row]) do
      evidence = observer.send(:endpoint_rows, agent, [pod], kernel, {SANDBOX => [ADDRESS]}).fetch(0)

      assert_equal [POD, ADDRESS, INTERFACE, 12, 123], evidence.values_at("pod_uid", "ipv4", "ifname", "ifindex", "endpoint_id")
      assert_raises(ArgumentError) { observer.send(:endpoint_rows, agent, [pod], kernel, {SANDBOX => ["10.244.0.99"]}) }
      assert_raises(ArgumentError) { observer.send(:endpoint_rows, agent, [pod], [], {SANDBOX => [ADDRESS]}) }
    end
  end

  def test_verifier_needs_the_same_worker_and_empty_post_uninstall_inventory
    start = Time.utc(2026, 1, 1)
    timestamp = ->(offset) { (start + offset).iso8601 }
    stages = %w[install ready smoke scale upgrade rollback restart uninstall].each_with_index.map do |name, index|
      {"stage" => name, "started_at" => timestamp.call((index * 4) + 1), "finished_at" => timestamp.call((index * 4) + 2)}
    end
    observations = %w[baseline install ready smoke scale upgrade rollback restart post-uninstall].each_with_index.map do |stage, index|
      {"stage" => stage, "worker" => "worker-0", "worker_uid" => BOOT, "boot_id" => BOOT, "netns_inode" => 12,
       "captured_at" => timestamp.call((index * 4) - (index.zero? ? 0 : 1)),
       "kernel_links" => [], "kernel_pod_addresses" => [], "journal_ip_addresses" => {}, "endpoints" => []}
    end
    smoke = observations.find { |row| row["stage"] == "smoke" }
    smoke["agent_pod_uid"] = BOOT
    Runtime::SMOKE_PODS.each_with_index do |name, index|
      uid = format("33333333-3333-4333-8333-%012d", index)
      link = {"ifname" => format("lxc%012x", index), "ifindex" => 13 + index, "mac" => format("02:00:00:00:00:%02x", index)}
      sandbox = "pod#{uid}-0123456789ab"
      ip = "10.244.0.#{10 + index}"
      smoke.fetch("journal_ip_addresses")[sandbox] = [ip]
      smoke.fetch("kernel_links") << link.merge("kind" => "veth")
      smoke.fetch("endpoints") << link.merge("pod" => name, "pod_uid" => uid, "state" => "ready",
                                             "namespace" => "k6-cilium", "endpoint_id" => 123 + index,
                                             "sandbox" => sandbox, "ipv4" => ip)
    end
    runtime = {"cilium" => observations, "observed_pod_uids" => smoke.fetch("endpoints").map { |row| row["pod_uid"] },
               "baseline_at" => observations.first.fetch("captured_at"), "post_uninstall_at" => observations.last.fetch("captured_at")}

    Runtime.verify!(runtime, stages)

    observations.last.fetch("kernel_links") << {"ifname" => INTERFACE, "ifindex" => 12}

    assert_raises(ArgumentError) { Runtime.verify!(runtime, stages) }

    observations.last["kernel_links"] = []
    observations.last["worker_uid"] = POD

    assert_raises(ArgumentError) { Runtime.verify!(runtime, stages) }
  end
end
