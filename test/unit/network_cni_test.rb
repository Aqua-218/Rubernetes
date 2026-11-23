# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"
require "tmpdir"

# The node agent as a CNI runtime: which plugins it runs, in which order,
# with what input, and what it remembers for the DEL that follows.
class NetworkCNITest < Minitest::Test
  CNI = Rubernetes::Network::CNI

  def setup
    @directory = Dir.mktmpdir
    @conf = File.join(@directory, "net.d")
    @bin = File.join(@directory, "bin")
    FileUtils.mkdir_p([@conf, @bin])
    @calls = []
    @results = {}
    @refusals = {}
    %w[bridge portmap loopback tuning].each { |type| FileUtils.touch(File.join(@bin, type)) }
    FileUtils.chmod(0o755, Dir[File.join(@bin, "*")])
    write_network("10-main.conflist", "plugins" => [{"type" => "bridge", "bridge" => "cni0", "ipam" => {"type" => "host-local"}},
                                                    {"type" => "portmap", "capabilities" => {"portMappings" => true}}])
    @cni = CNI.new(state_dir: File.join(@directory, "state"), conf_dir: @conf, bin_dirs: [@bin], runner: method(:run_plugin))
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def write_network(name, document)
    File.write(File.join(@conf, name), JSON.generate({"cniVersion" => "1.0.0", "name" => "pods"}.merge(document)))
  end

  # Stands in for the plugin binaries.
  def run_plugin(environment, path, input)
    type = File.basename(path)
    command = environment.fetch("CNI_COMMAND")
    @calls << {type: type, command: command, environment: environment, input: JSON.parse(input)}
    return [JSON.generate({"code" => 11, "msg" => @refusals.fetch([type, command])}), "", false] if @refusals.key?([type, command])

    [command == "ADD" && @results.key?(type) ? JSON.generate(@results.fetch(type)) : "", "", true]
  end

  BRIDGE_RESULT = {
    "cniVersion" => "1.0.0",
    "interfaces" => [{"name" => "cni0"}, {"name" => "veth1a2b"}, {"name" => "eth0", "sandbox" => "/proc/42/ns/net"}],
    "ips" => [{"address" => "10.88.0.7/16", "gateway" => "10.88.0.1", "interface" => 2}, {"address" => "fd00::7/64", "interface" => 2}]
  }.freeze

  def sandbox = {"sandbox_id" => "sb-1", "netns" => {"path" => "/proc/42/ns/net", "pid" => 42}}

  def pod(**spec)
    {"metadata" => {"namespace" => "shop", "name" => "web", "uid" => "pod-uid"},
     "spec" => {"containers" => [{"name" => "c", "ports" => [{"containerPort" => 80, "hostPort" => 8080}, {"containerPort" => 9090}]}]}
         .merge(spec.transform_keys(&:to_s))}
  end

  def sequence = @calls.map { |call| "#{call[:command]} #{call[:type]}" }

  def test_add_runs_loopback_then_the_chain_and_answers_with_the_addresses
    @results["bridge"] = BRIDGE_RESULT
    result = @cni.add(sandbox, pod)

    assert_equal ["ADD loopback", "ADD bridge", "ADD portmap"], sequence
    assert_equal %w[10.88.0.7 fd00::7], result.fetch("ips")
    assert_equal "veth1a2b", result.fetch("interface"), "the host end, for the node's own bookkeeping"
    assert_equal "eth0", result.fetch("pod_interface")
    assert_equal "cni", result.fetch("backend")
  end

  def test_each_plugin_is_told_who_it_works_for_and_what_came_before
    @results["bridge"] = BRIDGE_RESULT
    @cni.add(sandbox, pod)
    loopback, bridge, portmap = @calls

    assert_equal "lo", loopback[:environment].fetch("CNI_IFNAME")
    assert_equal({"CNI_COMMAND" => "ADD", "CNI_CONTAINERID" => "sb-1", "CNI_NETNS" => "/proc/42/ns/net", "CNI_IFNAME" => "eth0",
                  "CNI_PATH" => @bin}, bridge[:environment].slice("CNI_COMMAND", "CNI_CONTAINERID", "CNI_NETNS", "CNI_IFNAME", "CNI_PATH"))
    assert_equal "IgnoreUnknown=1;K8S_POD_NAMESPACE=shop;K8S_POD_NAME=web;K8S_POD_INFRA_CONTAINER_ID=sb-1;K8S_POD_UID=pod-uid",
                 bridge[:environment].fetch("CNI_ARGS")
    assert_equal({"type" => "bridge", "bridge" => "cni0", "ipam" => {"type" => "host-local"}, "cniVersion" => "1.0.0", "name" => "pods"},
                 bridge[:input])
    assert_equal BRIDGE_RESULT, portmap[:input].fetch("prevResult"), "a chained plugin works on its predecessor's result"
    assert_equal({"portMappings" => [{"hostPort" => 8080, "containerPort" => 80, "protocol" => "tcp"}]}, portmap[:input].fetch("runtimeConfig"))
    refute bridge[:input].key?("runtimeConfig"), "only a plugin that declares the capability is handed the mappings"
  end

  def test_delete_runs_the_chain_backwards_with_what_add_ended_on
    @results["bridge"] = BRIDGE_RESULT
    @cni.add(sandbox, pod)
    @calls.clear
    # The configuration changed since: DEL still belongs to the network ADD used.
    write_network("10-main.conflist", "plugins" => [{"type" => "tuning"}])
    again = CNI.new(state_dir: File.join(@directory, "state"), conf_dir: @conf, bin_dirs: [@bin], runner: method(:run_plugin))

    assert_equal "removed", again.delete("sb-1").fetch("state"), "an agent that restarted is told only the sandbox ID"
    assert_equal ["DEL portmap", "DEL bridge"], sequence
    assert_equal BRIDGE_RESULT, @calls.first[:input].fetch("prevResult")
    assert_equal "/proc/42/ns/net", @calls.first[:environment].fetch("CNI_NETNS")

    @calls.clear
    again.delete("sb-1")

    assert_empty @calls, "a sandbox that is detached is done"
  end

  def test_delete_after_namespace_loss_does_not_reuse_the_stored_proc_path
    @cni.add(sandbox, pod)
    @calls.clear

    assert_equal "removed", @cni.delete("sb-1", namespace_gone: true).fetch("state")
    assert_equal ["DEL portmap", "DEL bridge"], sequence
    assert_equal(["", ""], @calls.map { |call| call[:environment].fetch("CNI_NETNS") })
  end

  def test_a_chain_that_fails_half_way_is_undone_and_nothing_is_remembered
    @results["bridge"] = BRIDGE_RESULT
    @refusals[%w[portmap ADD]] = "iptables is missing"
    error = assert_raises(CNI::PluginError) { @cni.add(sandbox, pod) }

    assert_equal "CNI ADD portmap: iptables is missing", error.message
    assert_equal ["ADD loopback", "ADD bridge", "ADD portmap", "DEL portmap", "DEL bridge"], sequence
    assert_empty Dir[File.join(@directory, "state", "*.json")]
  end

  def test_a_delete_that_fails_keeps_the_record_for_the_retry
    @cni.add(sandbox, pod)
    @refusals[%w[bridge DEL]] = "device busy"

    assert_match(/CNI DEL failed for sandbox sb-1: CNI DEL bridge: device busy/, assert_raises(CNI::PluginError) { @cni.delete(sandbox) }.message)

    @refusals.clear
    @calls.clear
    @cni.delete(sandbox)

    assert_equal ["DEL portmap", "DEL bridge"], sequence
  end

  def test_a_host_network_pod_is_not_attached
    host_sandbox = {"sandbox_id" => "host-sb"}
    host_pod = pod(hostNetwork: true)
    result = @cni.add(host_sandbox, host_pod)

    assert_empty @calls
    assert_empty result.fetch("ips")
    assert @cni.check(host_sandbox, host_pod)
    assert_equal "removed", @cni.delete(host_sandbox, host_pod).fetch("state")
    assert_empty @calls
  end

  def test_the_first_configuration_by_name_is_the_network_and_a_conf_is_a_list_of_one
    File.write(File.join(@conf, "05-single.conf"), JSON.generate({"cniVersion" => "0.4.0", "name" => "single", "type" => "tuning"}))
    @cni.add(sandbox, pod)

    assert_equal ["ADD loopback", "ADD tuning"], sequence
    assert_equal "single", @calls.last[:input].fetch("name")
  end

  def test_check_is_run_for_networks_that_have_it
    @results["bridge"] = BRIDGE_RESULT
    @cni.add(sandbox, pod)
    @calls.clear

    assert @cni.check(sandbox, pod)
    assert_equal ["CHECK bridge", "CHECK portmap"], sequence
    assert_raises(Rubernetes::Network::ValidationError) { @cni.check({"sandbox_id" => "other", "netns" => {"path" => "/proc/1/ns/net"}}) }
  end

  def test_what_cannot_work_is_refused_before_a_plugin_runs
    write_network("10-main.conflist", "plugins" => [{"type" => "calico"}])

    assert_match(/CNI plugin "calico" is not in/, assert_raises(Rubernetes::Network::ValidationError) { @cni.add(sandbox, pod) }.message)
    assert_raises(Rubernetes::Network::OwnershipError) { @cni.add({"sandbox_id" => "sb-2"}, pod) }

    FileUtils.rm_f(Dir[File.join(@conf, "*")])

    assert_match(/no CNI network configuration in/, assert_raises(Rubernetes::Network::ValidationError) { @cni.add(sandbox, pod) }.message)
  end
end
