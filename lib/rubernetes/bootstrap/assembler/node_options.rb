# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The agent's configuration sections with their defaults applied: paths,
      # DNS, the streaming endpoint and the addresses the Node publishes.
      module NodeOptions
        private

        def qos_cgroups(process)
          paths = process.fetch("runtime_paths", process.fetch("runtime", {})) || {}
          {"enabled" => process.fetch("cgroups_per_qos", true) != false,
           "root" => process.fetch("cgroup_root", paths.fetch("cgroup_root", Runtime::Native::Configuration::DEFAULT_CGROUP_ROOT)),
           "hierarchy" => Platform::Linux::KubeletCgroupLayout::HIERARCHY,
           "enforce_node_allocatable" => process.fetch("enforce_node_allocatable", ["pods"]),
           "system_reserved_cgroup" => process["system_reserved_cgroup"],
           "kube_reserved_cgroup" => process["kube_reserved_cgroup"],
           "memory_reservation_policy" => process.fetch("memory_reservation_policy", "None"),
           "qos_reserved" => process["qos_reserved"]}.compact
        end

        def native_agent_profile?(process)
          profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
          %i[host_integration kernel_isolation l3].include?(profile)
        end

        def pod_root(process, journal_path)
          process["pod_root"] || File.join(File.dirname(journal_path), "pods")
        end

        def cluster_domain(process)
          (process["cluster_domain"] || dns_options(process)["cluster_domain"] || "cluster.local").to_s
        end

        def dns_options(process)
          options = (process["dns"] || {}).to_h
          {
            "enabled" => options.fetch("enabled", true) != false,
            "port" => Integer(options.fetch("port", DEFAULT_DNS_PORT)),
            "bind_addresses" => Array(options["bind_addresses"]),
            "cluster_dns" => Array(options["cluster_dns"]),
            "upstreams" => Array(options["upstreams"]),
            "cluster_domain" => options["cluster_domain"],
            "resolv_conf" => options["resolv_conf"] || process["resolv_conf"] || "/etc/resolv.conf",
            "positive_ttl" => options.fetch("positive_ttl", 5),
            "negative_ttl" => options.fetch("negative_ttl", 5),
            "hosts" => options["hosts"],
            "nat64_prefix" => options["nat64_prefix"],
            # The resolver's own identity (the cluster DNS add-on's, CoreDNS
            # running as its service account): it watches every Service,
            # EndpointSlice and Pod, which a node identity may not.
            "kubeconfig" => options["kubeconfig"]
          }
        end

        # The node's bridge addresses double as the Pods' DNS server; creating
        # the bridge here means the address exists before the first Pod.
        def node_gateway_addresses(network, process)
          @node_gateways ||= {}
          key = process.fetch("node_name").to_s
          @node_gateways[key] ||= begin
            gateways = network.ensure_node_bridge(owner: "node:#{key}")
            gateways.values.map { |entry| entry.fetch("address") }
          rescue StandardError => error
            raise Config::Error, "node bridge could not be prepared for cluster DNS: #{error.message}"
          end
        end

        def streaming_options(process)
          options = (process["streaming"] || {}).to_h
          {
            "enabled" => options.fetch("enabled", true) != false,
            "host" => options.fetch("host", "127.0.0.1"),
            "port" => Integer(options.fetch("port", DEFAULT_STREAMING_PORT)),
            "advertise_address" => options["advertise_address"] || options["address"] || options.fetch("host", "127.0.0.1")
          }
        end

        # The API server resolves the streaming endpoint from the Node's own
        # status.addresses, so the agent has to publish one.
        #
        # A loopback address is not a node address.  kubelet refuses one outright
        # -- "--node-ip cannot be a loopback address" (pkg/kubelet/kubelet.go) --
        # because everything that dials a node by its InternalIP does so from
        # somewhere else: another node, a Pod, the API server.  Publishing
        # 127.0.0.1 sent every one of those callers to its own loopback instead,
        # so a HostPort listener was unreachable from the Pod that was meant to
        # reach it.  With nothing better configured the node's own Pod bridge
        # address is the address its Pods and this host share.
        def node_addresses(process, gateways: [])
          configured = Array(process["addresses"])
          return configured unless configured.empty?

          advertised = streaming_options(process).fetch("advertise_address").to_s
          advertised = routable_node_address(gateways) || advertised if loopback_address?(advertised)
          [{"type" => "InternalIP", "address" => advertised},
           {"type" => "Hostname", "address" => process.fetch("node_name")}]
        end

        def loopback_address?(value)
          address = IPAddr.new(value.to_s)
          address.loopback? || value.to_s == "0.0.0.0" || value.to_s == "::"
        rescue IPAddr::Error
          # A host name is not a loopback address.
          false
        end

        def routable_node_address(gateways)
          Array(gateways).map(&:to_s).find { |address| !address.empty? && !loopback_address?(address) }
        end
      end
    end
  end
end
