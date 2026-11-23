# frozen_string_literal: true

require "digest"
require "json"
require "open3"
require "uri"

module Rubernetes
  module Cluster
    # Each worker has its own Linux host network. The control namespace routes
    # addresses and Pod CIDRs through point-to-point veth uplinks.
    class WorkerNetworks
      IPV4_TRANSIT = IPAddr.new("169.254.128.0")
      IPV6_TRANSIT = IPAddr.new("fd00:d8:ffff::")
      PEER = "rbn-uplink"
      IPV6_SOURCE_WAIT_SECONDS = 5

      def initialize(root, pod_cidrs)
        @state = File.join(root, "network", "worker-topology.json")
        @scope = Digest::SHA256.hexdigest(root)[0, 8]
        @pod_cidrs = pod_cidrs
      end

      def prepare!
        return if ready?

        cleanup!
        @pod_cidrs.each_index do |index|
          raise Error, "worker network #{name(index)} is already in use" if namespace_exists?(index) || host_link_exists?(index)
        end
        FileUtils.mkdir_p(File.dirname(@state))
        topology = {"namespace" => current_namespace, "workers" => @pod_cidrs.length, "pod_cidrs" => @pod_cidrs}
        write_state(topology)
        forwarding!
        @pod_cidrs.each_with_index { |cidrs, index| prepare_worker!(index, cidrs) }
        Network::HostForward.new.ensure!(@pod_cidrs.flatten + transit_cidrs)
        write_state(topology.merge("ready" => true))
      rescue StandardError
        cleanup!
        raise
      end

      def cleanup!
        return unless File.file?(@state)

        previous = JSON.parse(File.binread(@state))
        if previous.fetch("namespace") != current_namespace && previous.fetch("workers").times.any? { |index| namespace_exists?(index) }
          raise Error, "enter the cluster's control network namespace before removing its workers"
        end

        if previous.fetch("namespace") == current_namespace
          previous.fetch("workers").times do |index|
            run("ip", "link", "delete", link_name(index), required: false)
            run("ip", "netns", "delete", name(index), required: false) if namespace_exists?(index)
          end
          Network::HostForward.new.remove!(previous.fetch("pod_cidrs").flatten + transit_cidrs(previous.fetch("workers")))
        end
        FileUtils.rm_f(@state)
      end

      def command(index)
        ["nsenter", "--net=/run/netns/#{name(index)}", "--"]
      end

      def process_command(index, executable)
        command(index) + ["unshare", "--uts", "--", "sh", "-c", 'hostname "$1" && shift && exec "$@"', "_", "worker-#{index}"] + executable
      end

      def endpoint(index, primary_family, local_endpoint)
        host = addresses(index, primary_family).first
        URI::HTTPS.build(host: host, port: URI(local_endpoint).port).to_s
      end

      def control_addresses
        @pod_cidrs.each_index.flat_map { |index| %w[ipv4 ipv6].map { |family| addresses(index, family).first } }
      end

      # Once the agent has its bridge address, host-network connections use
      # that advertised node IP unless a more-specific route selects another.
      def prefer_node_sources!(index, sources)
        sources.each do |source|
          address = IPAddr.new(source)
          ipv4 = address.ipv4?
          gateway = addresses(index, ipv4 ? "ipv4" : "ipv6").first
          wait_for_ipv6_source!(index, address.to_s) unless ipv4
          run(*command(index), "ip", ipv4 ? "-4" : "-6", "route", "replace", "default", "via", gateway, "dev", PEER, "src", source)
        end
      end

      def proxy_environment(api_addresses:, service_cidrs:, environment: ENV)
        exclusions = environment.values_at("NO_PROXY", "no_proxy").compact.flat_map { |value| value.split(/\s*,\s*/) }
        exclusions += control_addresses + api_addresses + @pod_cidrs.flatten + service_cidrs
        no_proxy = exclusions.uniq.join(",")
        {"NO_PROXY" => no_proxy, "no_proxy" => no_proxy}
      end

      private

      # The kubelet can report Ready while its bridge address is tentative.
      # Keep the transit route until duplicate address detection completes.
      def wait_for_ipv6_source!(index, source)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + IPV6_SOURCE_WAIT_SECONDS
        loop do
          return if ipv6_source_ready?(index, source)
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep(0.05)
        end
        raise Error, "worker-#{index} IPv6 source #{source} did not become usable"
      end

      def ipv6_source_ready?(index, source)
        args = ["ip", "-j", "-6", "address", "show", "to", "#{source}/128", "-tentative", "-dadfailed"]
        output, status = Open3.capture2e(*command(index), *args)
        raise Error, "could not inspect worker-#{index} IPv6 source #{source}: #{output.strip}" unless status.success?

        JSON.parse(output).any? do |link|
          link.fetch("addr_info", []).any? { |address| address["local"] == source }
        end
      end

      def current_namespace
        File.readlink("/proc/self/ns/net")
      end

      def ready?
        return false unless File.file?(@state)

        previous = JSON.parse(File.binread(@state))
        previous["ready"] && previous["namespace"] == current_namespace && previous["pod_cidrs"] == @pod_cidrs &&
          @pod_cidrs.each_index.all? { |index| namespace_exists?(index) && host_link_exists?(index) }
      end

      def name(index) = "rbnw#{@scope}-#{index}"
      def link_name(index) = "rw#{@scope}h#{index}"
      def namespace_exists?(index) = File.exist?("/run/netns/#{name(index)}")
      def host_link_exists?(index) = run("ip", "link", "show", link_name(index), required: false)

      def write_state(topology)
        temporary = "#{@state}.new"
        File.write(temporary, JSON.generate(topology), perm: 0o600)
        File.rename(temporary, @state)
      ensure
        FileUtils.rm_f(temporary)
      end

      def addresses(index, family)
        prefix, base, stride = family == "ipv4" ? [30, IPV4_TRANSIT, 4] : [64, IPV6_TRANSIT, 1 << 64]
        network = base.to_i + (stride * index)
        [IPAddr.new(network + 1, base.family).to_s, IPAddr.new(network + 2, base.family).to_s, prefix]
      end

      def transit_cidrs(count = @pod_cidrs.length)
        count.times.flat_map do |index|
          %w[ipv4 ipv6].map do |family|
            address, _, prefix = addresses(index, family)
            "#{IPAddr.new("#{address}/#{prefix}")}/#{prefix}"
          end
        end
      end

      def prepare_worker!(index, cidrs)
        namespace = name(index)
        device = link_name(index)
        run("ip", "netns", "add", namespace)
        run("ip", "link", "add", device, "type", "veth", "peer", "name", PEER, "netns", namespace)
        run("ip", "link", "set", device, "up")
        run(*command(index), "ip", "link", "set", "lo", "up")
        run(*command(index), "ip", "link", "set", PEER, "up")
        forwarding!(*command(index))
        %w[ipv4 ipv6].each { |family| route_family!(index, device, family, cidrs) }
        # The worker's local masquerade rules preserve source addresses when
        # Pod traffic is routed through another worker's uplink.
        run(*command(index), RbConfig.ruby, *Cluster.load_path_arguments,
            "-rrubernetes/network/host_forward", "-e", "Rubernetes::Network::HostForward.new.ensure!(ARGV)", "--", *@pod_cidrs.flatten)
      end

      def route_family!(index, device, family, cidrs)
        address, peer_address, prefix = addresses(index, family)
        protocol = family == "ipv4" ? "-4" : "-6"
        no_dad = family == "ipv6" ? ["nodad"] : []
        run("ip", protocol, "address", "add", "#{address}/#{prefix}", "dev", device, *no_dad)
        run(*command(index), "ip", protocol, "address", "add", "#{peer_address}/#{prefix}", "dev", PEER, *no_dad)
        run(*command(index), "ip", protocol, "route", "add", "default", "via", address, "dev", PEER)
        cidrs.each do |cidr|
          next unless IPAddr.new(cidr).ipv4? == (family == "ipv4")

          run("ip", protocol, "route", "add", cidr, "via", peer_address, "dev", device)
        end
      end

      def forwarding!(*prefix)
        run(*prefix, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0",
            "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.all.forwarding=1", "net.ipv6.conf.default.forwarding=1")
      end

      def run(*argv, required: true)
        output, status = Open3.capture2e(*argv)
        raise Error, "worker network #{argv.join(" ")} failed: #{output.strip}" if required && !status.success?

        status.success?
      end
    end
  end
end
