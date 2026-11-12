# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The Pod network: a CNI plugin chain, or the node's own bridge network
      # with its IPAM, ownership ledger, sysctls and NetworkPolicy engine.
      module NetworkBuilder
        private

        def build_network(process, adapters: {}, logger: nil)
          injected = adapters[:network] || adapters["network"]
          return injected if injected

          options = process["network"]
          return nil unless options

          config = options.to_h
          return build_cni_network(config, logger) if config["plugin"] == "cni"

          runtime_profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
          native_profile = %i[host_integration kernel_isolation l3].include?(runtime_profile) || config["profile"].to_s == "native"
          interface = build_network_interface(config, adapters, native_profile: native_profile, logger: logger)
          # A node agent is one Ruby process on one interpreter lock; the
          # network attach work runs in a worker process of its own so it uses
          # another core (see Network::Worker).  "worker": false keeps it in
          # the agent.
          return interface unless native_profile && config.fetch("worker", true) != false

          Network::Worker.fork_for(interface, logger: logger)
        end

        # CNI plugins own the whole Pod network: no IPAM, bridge, policy engine
        # or worker process of ours beside them.
        def build_cni_network(config, logger)
          cni = config.fetch("cni", {})
          Network::CNI.new(state_dir: "#{config.fetch("state_path")}.cni", logger: logger,
                           conf_dir: cni.fetch("conf_dir", Network::CNI::DEFAULT_CONF_DIR),
                           bin_dirs: cni.fetch("bin_dirs", Network::CNI::DEFAULT_BIN_DIRS))
        end

        # The node's own bridge network; every part can be injected.
        def build_network_interface(config, adapters, native_profile:, logger:)
          adapter = adapters[:network_adapter] || adapters["network_adapter"]
          netlink = adapters[:netlink] || adapters["netlink"]
          netlink ||= Network::Netlink.new if adapter.nil?
          # IPAM takes keyword arguments and collects anything unrecognised into
          # **_options.  A configuration read from YAML has String keys, so
          # splatting it verbatim drops every CIDR into that catch-all and leaves
          # the keywords nil -- the agent then fails with "at least one cluster
          # CIDR is required" while the config plainly sets one.
          ipam_options = config.slice("cluster_cidr", "ipv4_cidr", "ipv6_cidr", "node_subnet_prefix",
                                      "ipv4_node_prefix", "ipv6_node_prefix")
            .transform_keys(&:to_sym)
          state_path = config.fetch("state_path")
          ipam = Network::IPAM.new(**ipam_options, state_path: "#{state_path}.ipam.json", fsync: config.fetch("fsync", true))
          observer = adapters[:network_observer] || adapters["network_observer"]
          observer ||= Network::NativeObserver.new(netlink: netlink) if native_profile && netlink
          ledger, journal = network_ledger(config, adapters, native_profile)
          sysctl_manager = adapters[:network_sysctl_manager] || adapters["network_sysctl_manager"]
          if native_profile && sysctl_manager.nil?
            sysctl_manager = Network::SysctlManager.new(state_path: "#{state_path}.sysctl.json", journal: journal,
                                                        fsync: config.fetch("fsync", true))
          end
          policy_engine = build_network_policy(config, native_profile: native_profile, adapters: adapters)
          bridge_manager = adapters[:network_bridge_manager] || adapters["network_bridge_manager"] ||
                           Network::BridgeManager.new(netlink: netlink, adapter: adapter)
          topology = adapters[:network_topology] || adapters["network_topology"] ||
                     Network::Topology.new(netlink: netlink, adapter: adapter,
                                           bridge_name: config.fetch("bridge_name", Network::Topology::DEFAULT_BRIDGE),
                                           mtu: config.fetch("mtu", 1500), bridge_manager: bridge_manager, clock: @clock)
          Network::Interface.new(
            ipam: ipam,
            topology: topology,
            netlink: netlink,
            adapter: adapter,
            ledger: ledger,
            observer: observer,
            policy_engine: policy_engine,
            bridge_manager: bridge_manager,
            sysctl_manager: sysctl_manager,
            state_path: state_path,
            bridge_name: config.fetch("bridge_name", Network::Topology::DEFAULT_BRIDGE),
            mtu: config.fetch("mtu", 1500),
            # Attaching one Pod's network persists its operation about twenty
            # times, and two fsyncs apiece put every concurrent Pod start on the
            # node behind the disk.  The rename still leaves a whole state on
            # disk; only the durability barrier is coalesced, exactly as the
            # node's lifecycle state already does.  "fsync": false in the config
            # still means no barrier at all.
            fsync: config.fetch("fsync", true) == false ? false : :deferred,
            require_observer: native_profile,
            # The cluster-wide Pod CIDRs, not this node's slice: the host has to
            # forward to every node's Pods, not only its own.
            cluster_cidrs: ipam_options.values_at(:cluster_cidr, :ipv4_cidr, :ipv6_cidr).flatten.compact,
            logger: logger
          )
        end

        # [ledger, journal]: a native node records what it owns in a ledger of
        # its own unless one was injected (then there is no journal).
        def network_ledger(config, adapters, native_profile)
          ledger = adapters[:network_ledger] || adapters["network_ledger"]
          return [ledger, nil] unless native_profile && ledger.nil?

          journal_path = config.fetch("ledger_path", "#{config.fetch("state_path")}.ledger.wal")
          journal = Runtime::Native::RollbackJournal.new(journal_path, fsync: config.fetch("fsync", true))
          [Runtime::Native::OwnershipLedger.new(journal: journal, clock: @clock), journal]
        end

        def build_network_policy(config, native_profile:, adapters:)
          injected_engine = adapters[:network_policy_engine] || adapters["network_policy_engine"]
          return injected_engine if injected_engine

          policy_adapter = adapters[:network_policy_adapter] || adapters["network_policy_adapter"]
          backend = config["policy_backend"]&.to_s&.downcase
          backend ||= "nftables" if native_profile && policy_adapter.nil?
          return nil if backend == "disabled" || (backend.nil? && policy_adapter.nil?)

          policy_adapter ||= case backend
                             when "ebpf"
                               Network::EBPFPolicyAdapter.new
                             when "nftables"
                               Network::NftablesPolicyAdapter.new(
                                 table_name: config.fetch("policy_table", "rubernetes_policy"),
                                 instance_identity: config["policy_instance_identity"]
                               )
                             else
                               raise Config::Error, "network.policy_backend must select ebpf or nftables"
                             end
          packet_matrix = adapters[:network_policy_packet_matrix] || adapters["network_policy_packet_matrix"]
          policy_adapter.verify_packet_matrix!(matrix: packet_matrix) if packet_matrix
          Network::PolicyEngine.new(adapter: policy_adapter, clock: @clock)
        end
      end
    end
  end
end
