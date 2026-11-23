# frozen_string_literal: true

require "ipaddr"
require "json"
require "open3"
require "time"
require_relative "../../lib/rubernetes/network/native_observer"

module Conformance
  # Workload attachments made by the pinned Cilium fixture are visible in
  # three independent places: the runtime's CNI journal, the agent's endpoint
  # table, and the worker's kernel link inventory.
  class K6CiliumRuntime
    NAMESPACE = "k6-cilium"
    SMOKE_PODS = %w[k6-cilium-client k6-cilium-server].freeze
    WORKLOAD_LINK = /\Alxc[[:xdigit:]]{12}\z/
    UUID = /\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/
    POOL = IPAddr.new("10.244.0.0/16")
    DRIVER_INTERFACES = %w[cilium_host cilium_net cilium_vxlan lxc_health].freeze

    def self.verify!(runtime, stages)
      observations = runtime.fetch("cilium")
      expected = ["baseline", *stages.map { |stage| stage.fetch("stage") }.reject { |stage| stage == "uninstall" }, "post-uninstall"]
      unless observations.map { |summary| summary.fetch("stage") } == expected &&
             observations.map { |summary| summary.fetch("boot_id") }.uniq.one? &&
             UUID.match?(observations.first.fetch("boot_id")) &&
             observations.map { |summary| summary.fetch("worker_uid") }.uniq.one? &&
             UUID.match?(observations.first.fetch("worker_uid")) &&
             observations.map { |summary| summary.fetch("netns_inode") }.uniq.one? &&
             observations.first.fetch("netns_inode").is_a?(Integer) && observations.first.fetch("netns_inode").positive? &&
             observations.all? { |summary| summary["worker"] == "worker-0" }
        raise ArgumentError, "Cilium worker observation does not identify one guest across the recorded stages"
      end

      before, after = observations.values_at(0, -1)
      unless [before.fetch("captured_at"), after.fetch("captured_at")] == runtime.values_at("baseline_at", "post_uninstall_at")
        raise ArgumentError, "Cilium runtime initial and final snapshots do not match the recorded cleanup interval"
      end
      unless [before, after].all? do |summary|
        empty_runtime = %w[kernel_links kernel_pod_addresses endpoints].all? { |key| summary.fetch(key) == [] }
        summary["agent_pod_uid"].nil? && summary.fetch("journal_ip_addresses") == {} && empty_runtime
      end
        raise ArgumentError, "Cilium workload resources are present outside the install and uninstall interval"
      end

      observations[1...-1].zip(stages).each do |summary, stage|
        captured = Time.iso8601(summary.fetch("captured_at"))
        next_start = stages.fetch(expected.index(summary.fetch("stage"))).fetch("started_at")
        next if captured.between?(Time.iso8601(stage.fetch("finished_at")), Time.iso8601(next_start))

        raise ArgumentError, "Cilium #{summary.fetch("stage")} observation falls outside its stage"
      end
      smoke = observations.find { |summary| summary["stage"] == "smoke" }
      endpoints = smoke.fetch("endpoints")
      unless !smoke["agent_pod_uid"].to_s.empty? && endpoints.map { |endpoint| endpoint["pod"] }.sort == SMOKE_PODS &&
             endpoints.map { |endpoint| endpoint["pod_uid"] }.uniq.length == SMOKE_PODS.size &&
             endpoints.all? { |endpoint| smoke_endpoint?(endpoint, runtime, smoke) }
        raise ArgumentError, "Cilium smoke did not corroborate both Pod identities in the agent, journal and kernel"
      end
    end

    def self.smoke_endpoint?(endpoint, runtime, smoke)
      uid = endpoint.fetch("pod_uid")
      kernel_link = smoke.fetch("kernel_links").any? do |link|
        link["kind"] == "veth" && link.values_at("ifname", "ifindex", "mac") == endpoint.values_at("ifname", "ifindex", "mac")
      end
      endpoint["state"] == "ready" && endpoint["namespace"] == NAMESPACE && endpoint["endpoint_id"].is_a?(Integer) &&
        runtime.fetch("observed_pod_uids").include?(uid) && endpoint.fetch("sandbox").start_with?("pod#{uid}-") &&
        smoke.fetch("journal_ip_addresses").fetch(endpoint["sandbox"], []).include?(endpoint.fetch("ipv4")) &&
        POOL.include?(endpoint.fetch("ipv4")) && kernel_link
    end
    private_class_method :smoke_endpoint?

    def self.local(descriptor, kubeconfig)
      boot = descriptor["cilium_guest_boot_id"]
      return unless boot && boot == ENV["RUBERNETES_K6_CILIUM_GUEST"]
      return unless File.read("/sys/class/dmi/id/sys_vendor").strip == "QEMU" &&
                    File.read("/proc/sys/kernel/random/boot_id").strip == boot

      workers = descriptor.fetch("processes").select { |entry| entry["executable"] == "rubernetes-agent" }
      return unless workers.map { |entry| entry.fetch("name") } == ["agent-worker-0"] && !descriptor["isolated_worker_networks"]

      # Netlink is sampled in this process. Bind it to the same guest network
      # namespace as the live worker before reading any kernel identities.
      pid = workers.first.fetch("pid")
      return unless File.identical?("/proc/#{pid}/ns/net", "/proc/self/ns/net") &&
                    File.binread("/proc/#{pid}/cmdline").split("\0").include?(workers.first.fetch("config"))

      new(kubeconfig, boot)
    rescue SystemCallError, KeyError
      nil
    end

    def initialize(kubeconfig, boot, kernel: Rubernetes::Network::NativeObserver.new)
      @kubeconfig = kubeconfig
      @boot = boot
      @kernel = kernel
      @kubectl = File.expand_path("../../build/tools/kubectl-v1.36.2", __dir__)
    end

    def observe(worker, stage, journal)
      node = kubectl("get", "node", worker)
      worker_uid = node.dig("metadata", "uid")
      unless node.dig("metadata", "name") == worker && worker_uid.is_a?(String) &&
             node.dig("status", "nodeInfo", "bootID") == @boot
        raise ArgumentError, "the API Node identity does not match the Cilium guest"
      end

      resources = @kernel.resources(kinds: %w[link address route]).group_by { |row| row.fetch("kind") }
      links = resources.fetch("link", []).map { |row| row.fetch("metadata") }
      loopback = links.find { |row| row["ifname"] == "lo" }
      raise ArgumentError, "Cilium native network inventory is missing loopback" unless loopback

      pods = kubectl("get", "pods").fetch("items")
      agent = pods.find do |pod|
        pod.dig("metadata", "labels", "k8s-app") == "cilium" && pod.dig("spec", "nodeName") == worker &&
          !pod.dig("metadata", "deletionTimestamp") && pod.dig("status", "phase") == "Running"
      end
      workloads = links.filter_map do |link|
        next unless WORKLOAD_LINK.match?(link.fetch("ifname"))

        raise ArgumentError, "Cilium workload link is not a veth" unless link["kind"] == "veth"

        link.slice("ifname", "ifindex", "mac", "kind")
      end
      pod_addresses = kernel_pod_addresses(resources.fetch("address", []), resources.fetch("route", []))
      endpoints = agent ? endpoint_rows(agent, pods, links, journal) : []
      witnesses = {"boot_id" => @boot, "worker" => worker, "worker_uid" => worker_uid, "stage" => stage,
                   "netns_inode" => loopback.fetch("netns_inode"),
                   "agent_pod_uid" => agent&.dig("metadata", "uid"), "kernel_links" => workloads,
                   "kernel_pod_addresses" => pod_addresses, "journal_ip_addresses" => journal.sort.to_h,
                   "endpoints" => endpoints}
      errors = []
      if !agent && (!journal.empty? || !workloads.empty? || !pod_addresses.empty?)
        errors << "no agent endpoint readback and workload resources are still present"
      end
      ready_pods = endpoints.filter_map { |row| row.fetch("pod") if row.fetch("state") == "ready" }
      errors << "agent endpoint readback did not cover both live smoke Pods" if stage == "smoke" && (ready_pods & SMOKE_PODS).sort != SMOKE_PODS
      [witnesses, errors]
    rescue Rubernetes::Network::NetlinkError => error
      raise ArgumentError, "Cilium kernel network readback failed: #{error.message}"
    end

    private

    def endpoint_rows(agent, pods, links, journal)
      name = agent.fetch("metadata").fetch("name")
      raw = kubectl("exec", name, "-c", "cilium-agent", "--", "cilium-dbg", "endpoint", "list", "-o", "json", output: false)
      raise ArgumentError, "Cilium endpoint inventory is not a list" unless raw.is_a?(Array)

      live = pods.to_h { |pod| [pod.fetch("metadata").fetch("uid"), pod] }
      raw.filter_map do |endpoint|
        status = endpoint.fetch("status")
        attachment = status.fetch("external-identifiers", {})["cni-attachment-id"]
        next if attachment.to_s.empty? && [1, 4].include?(status.dig("identity", "id")) # host and health endpoints

        match = /\A(pod([0-9a-f]{8}-[0-9a-f-]{27})-[0-9a-f]{12}):eth0\z/.match(attachment.to_s)
        raise ArgumentError, "Cilium endpoint has an unknown attachment identity" unless match

        sandbox, uid = match.captures
        networking = status.fetch("networking")
        interface = networking.fetch("interface-name")
        index = networking.fetch("interface-index")
        ip = networking.fetch("addressing").filter_map { |row| row["ipv4"] }.first
        raise ArgumentError, "Cilium endpoint did not report its numeric ID and fixture IPv4" unless
          endpoint.fetch("id").is_a?(Integer) && ip && POOL.include?(ip)

        link = links.find { |row| row["ifname"] == interface && row["ifindex"] == index }
        unless link && WORKLOAD_LINK.match?(interface) && link["kind"] == "veth" && link["mac"] == networking.fetch("host-mac")
          raise ArgumentError, "Cilium endpoint link is missing from the worker"
        end

        pod = live[uid]
        record = journal[sandbox]
        running_pod = pod && pod.dig("status", "phase") == "Running" && !pod.dig("metadata", "deletionTimestamp")
        if running_pod && !(record && record.include?(ip) && pod.dig("status", "podIP") == ip)
          raise ArgumentError, "Cilium endpoint address does not agree with the runtime journal and Pod"
        end

        {"endpoint_id" => endpoint.fetch("id"), "pod_uid" => uid, "pod" => pod&.dig("metadata", "name"),
         "namespace" => pod&.dig("metadata", "namespace"), "sandbox" => sandbox,
         "ipv4" => ip, "ifname" => interface, "ifindex" => index, "mac" => networking.fetch("host-mac"),
         "state" => status.fetch("state")}.compact
      end
    end

    def kernel_pod_addresses(addresses, routes)
      assigned = addresses.filter_map do |resource|
        address = resource.fetch("metadata")
        next unless address["family"] == "ipv4" && !DRIVER_INTERFACES.include?(address["ifname"])

        address.fetch("address")
      end
      host_routes = routes.filter_map do |resource|
        route = resource.fetch("metadata")
        next unless route["family"] == "ipv4" && !DRIVER_INTERFACES.include?(route["ifname"])

        destination = route.fetch("destination")
        destination.delete_suffix("/32") if destination.end_with?("/32")
      end
      (assigned + host_routes).select { |ip| POOL.include?(ip) }.uniq.sort
    end

    def kubectl(*, output: true)
      format = output ? %w[-o json] : []
      json(@kubectl, "--kubeconfig", @kubeconfig, "--request-timeout=12s", "-n", NAMESPACE, *, *format)
    end

    def json(*command)
      stdout, _stderr, status = Open3.capture3({"NO_PROXY" => "*", "no_proxy" => "*"}, *command)
      raise ArgumentError, "#{File.basename(command.first)} failed while reading Cilium runtime state" unless status.success?

      JSON.parse(stdout)
    end
  end
end
