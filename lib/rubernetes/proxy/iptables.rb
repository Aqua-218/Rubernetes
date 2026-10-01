# frozen_string_literal: true

require "digest"
require "ipaddr"
require "open3"
require "socket"
require_relative "backend"

module Rubernetes
  module Proxy
    # pkg/proxy/iptables: the iptables proxier.  The service rules are
    # rendered as an iptables-restore program (filter and nat tables, the
    # KUBE-SERVICES / KUBE-NODEPORTS / KUBE-POSTROUTING / KUBE-MARK-MASQ /
    # KUBE-FORWARD / KUBE-EXTERNAL-SERVICES / KUBE-PROXY-FIREWALL chains and
    # the hashed per-service KUBE-SVC / KUBE-SVL / KUBE-EXT / KUBE-FW /
    # KUBE-SEP chains, exactly as upstream names and orders them) and
    # restored without flushing; a partial sync rewrites only the changed
    # services' chains.  Metrics: kubeproxy_sync_proxy_rules_iptables_total /
    # _last{ip_family,table}, _iptables_restore_failures_total and
    # _iptables_partial_restore_failures_total{ip_family}, and the nfacct
    # counters kubeproxy_iptables_ct_state_invalid_dropped_packets_total and
    # kubeproxy_iptables_localhost_nodeports_accepted_packets_total.
    module Iptables
      MASQUERADE_MARK = "0x4000"
      FULL_SYNC_PERIOD_SECONDS = 3600.0
      LARGE_CLUSTER_ENDPOINTS_THRESHOLD = 1000
      CT_STATE_INVALID_COUNTER = "ct_state_invalid_dropped_pkts"
      LOCALHOST_NODEPORTS_COUNTER = "localhost_nps_accepted_pkts"
      CHAINS = {
        services: "KUBE-SERVICES", external_services: "KUBE-EXTERNAL-SERVICES", node_ports: "KUBE-NODEPORTS",
        postrouting: "KUBE-POSTROUTING", mark_masq: "KUBE-MARK-MASQ", forward: "KUBE-FORWARD",
        proxy_firewall: "KUBE-PROXY-FIREWALL", canary: "KUBE-PROXY-CANARY", kubelet_firewall: "KUBE-FIREWALL"
      }.freeze
      # iptablesJumpChains (+ the kubelet firewall duplicate): table, chain, hook chain, comment, extra args.
      JUMP_CHAINS = [
        ["filter", "KUBE-EXTERNAL-SERVICES", "INPUT", "kubernetes externally-visible service portals", %w[-m conntrack --ctstate NEW]],
        ["filter", "KUBE-EXTERNAL-SERVICES", "FORWARD", "kubernetes externally-visible service portals", %w[-m conntrack --ctstate NEW]],
        ["filter", "KUBE-NODEPORTS", "INPUT", "kubernetes health check service ports", []],
        ["filter", "KUBE-SERVICES", "FORWARD", "kubernetes service portals", %w[-m conntrack --ctstate NEW]],
        ["filter", "KUBE-SERVICES", "OUTPUT", "kubernetes service portals", %w[-m conntrack --ctstate NEW]],
        ["filter", "KUBE-FORWARD", "FORWARD", "kubernetes forwarding rules", []],
        ["filter", "KUBE-PROXY-FIREWALL", "INPUT", "kubernetes load balancer firewall", %w[-m conntrack --ctstate NEW]],
        ["filter", "KUBE-PROXY-FIREWALL", "OUTPUT", "kubernetes load balancer firewall", %w[-m conntrack --ctstate NEW]],
        ["filter", "KUBE-PROXY-FIREWALL", "FORWARD", "kubernetes load balancer firewall", %w[-m conntrack --ctstate NEW]],
        ["nat", "KUBE-SERVICES", "OUTPUT", "kubernetes service portals", []],
        ["nat", "KUBE-SERVICES", "PREROUTING", "kubernetes service portals", []],
        ["nat", "KUBE-POSTROUTING", "POSTROUTING", "kubernetes postrouting rules", []],
        ["filter", "KUBE-FIREWALL", "INPUT", "", []],
        ["filter", "KUBE-FIREWALL", "OUTPUT", "", []]
      ].freeze

      BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

      # base32.StdEncoding of a SHA-256, first 16 characters.
      def self.hash16(text)
        digest = Digest::SHA256.digest(text)
        bits = digest.unpack1("B*")
        (0...16).map { |index| BASE32[bits[index * 5, 5].to_i(2)] }.join
      end

      def self.service_chain(service_port_name, protocol) = "KUBE-SVC-#{hash16(service_port_name + protocol)}"
      def self.local_chain(service_port_name, protocol) = "KUBE-SVL-#{hash16(service_port_name + protocol)}"
      def self.firewall_chain(service_port_name, protocol) = "KUBE-FW-#{hash16(service_port_name + protocol)}"
      def self.external_chain(service_port_name, protocol) = "KUBE-EXT-#{hash16(service_port_name + protocol)}"
      def self.endpoint_chain(service_port_name, protocol, endpoint) = "KUBE-SEP-#{hash16(service_port_name + protocol + endpoint)}"
      def self.service_chain?(name) = name.start_with?("KUBE-SVC-", "KUBE-SVL-", "KUBE-SEP-", "KUBE-EXT-", "KUBE-FW-")
      def self.probability(n) = format("%0.10f", 1.0 / n)

      # One Service port as the proxier sees it, assembled from the compiler's
      # per-front-end rules (ClusterIP / ExternalIP / LoadBalancer / NodePort
      # / HealthCheckNodePort share a service port).
      ServicePort = Struct.new(:name_string, :protocol, :port, :cluster_ips, :external_ips, :load_balancer_ips, :node_port, :health_check_node_port,
                               :external_policy_local, :internal_policy_local, :session_affinity, :affinity_timeout, :source_ranges,
                               :endpoints, :hints, keyword_init: true) do
        def externally_accessible? = !external_ips.empty? || !load_balancer_ips.empty? || node_port.to_i.positive?
        def uses_cluster_endpoints? = !internal_policy_local || !external_policy_local || !externally_accessible?
        def uses_local_endpoints? = internal_policy_local || (external_policy_local && externally_accessible?)
      end

      # Builds the restore program for one IP family.
      class Renderer
        attr_reader :node_name, :node_ips, :family, :masquerade_all, :localhost_node_ports, :nfacct_counters

        def initialize(family: "IPv4", node_name: nil, node_ips: [], masquerade_all: false, localhost_node_ports: true, nfacct_counters: {},
                       conntrack_tcp_liberal: false, node_zone: nil, cluster_cidr: nil)
          @family = family
          @node_name = node_name.to_s
          @node_ips = Array(node_ips).map(&:to_s)
          @masquerade_all = masquerade_all
          @localhost_node_ports = localhost_node_ports && family == "IPv4"
          @nfacct_counters = nfacct_counters
          @conntrack_tcp_liberal = conntrack_tcp_liberal
          @node_zone = node_zone
          @cluster_cidr = cluster_cidr
        end

        def ipv6? = @family == "IPv6"

        def family_of(ip)
          IPAddr.new(ip.to_s).ipv6? ? "IPv6" : "IPv4"
        rescue ArgumentError
          nil
        end

        # The compiler's rules grouped into ServicePorts for this family.
        def service_ports(rules)
          groups = {}
          Array(rules).each do |rule|
            next if rule.health_check && rule.kind == "HealthCheckNodePort" && rule.protocol != "TCP"

            service_port = rule.metadata["servicePort"] || {}
            port_name = (service_port["name"] || "").to_s
            name_string = port_name.empty? ? rule.service_key : "#{rule.service_key}:#{port_name}"
            key = [name_string, rule.protocol]
            entry = groups[key] ||= ServicePort.new(name_string: name_string, protocol: rule.protocol, port: rule.port, cluster_ips: [], external_ips: [],
                                                    load_balancer_ips: [], node_port: 0, health_check_node_port: 0,
                                                    external_policy_local: rule.external_traffic_policy == "Local",
                                                    internal_policy_local: rule.internal_traffic_policy == "Local",
                                                    session_affinity: rule.session_affinity, affinity_timeout: rule.session_affinity_timeout_seconds,
                                                    source_ranges: Array(rule.metadata["loadBalancerSourceRanges"]).map(&:to_s),
                                                    endpoints: [], hints: rule.metadata["topologyAwareHints"])
            case rule.kind
            when "ClusterIP" then entry.cluster_ips << rule.virtual_ip if family_of(rule.virtual_ip) == @family
            when "ExternalIP" then entry.external_ips << rule.virtual_ip if family_of(rule.virtual_ip) == @family
            when "LoadBalancer" then entry.load_balancer_ips << rule.virtual_ip if family_of(rule.virtual_ip) == @family
            when "NodePort" then entry.node_port = rule.node_port.to_i
            when "HealthCheckNodePort" then entry.health_check_node_port = rule.node_port.to_i
            end
            next if rule.health_check

            rule.backends.each do |backend|
              next unless family_of(backend.address) == @family
              next if entry.endpoints.any? { |existing| existing.address == backend.address && existing.port == backend.port }

              entry.endpoints << backend
            end
          end
          groups.values.select do |entry|
            !entry.cluster_ips.empty? || !entry.external_ips.empty? || !entry.load_balancer_ips.empty? || entry.node_port.positive?
          end
            .sort_by(&:name_string)
        end

        # proxy.CategorizeEndpoints: [cluster, local, all reachable, has any].
        def categorize(service_port)
          endpoints = service_port.endpoints
          return [[], [], [], false] if endpoints.empty?

          cluster = []
          local = []
          has_any = false
          if service_port.uses_cluster_endpoints?
            ready = endpoints.select(&:healthy?)
            ready = apply_hints(service_port, ready)
            cluster = ready.empty? ? endpoints.select { |endpoint| endpoint.serving? && endpoint.terminating? } : ready
            has_any = true unless cluster.empty?
          end
          if service_port.uses_local_endpoints?
            local_ready = endpoints.select { |endpoint| endpoint.healthy? && endpoint.local_to?(@node_name) }
            has_any ||= endpoints.any? { |endpoint| endpoint.healthy? || (endpoint.serving? && endpoint.terminating?) }
            local = if local_ready.empty?
                      endpoints.select do |endpoint|
                        endpoint.serving? && endpoint.terminating? && endpoint.local_to?(@node_name)
                      end
                    else
                      local_ready
                    end
          end
          [cluster, local, (cluster + local).uniq { |endpoint| [endpoint.address, endpoint.port] }, has_any]
        end

        # Topology-aware hints: endpoints hinted for this node's zone, when
        # every endpoint carries a hint and the node has a zone.
        def apply_hints(service_port, endpoints)
          return endpoints if @node_zone.to_s.empty? || (service_port.hints.to_s.downcase == "disabled" && service_port.hints)
          return endpoints unless endpoints.all? { |endpoint| endpoint.respond_to?(:hints) && !Array(endpoint.hints).empty? }

          hinted = endpoints.select { |endpoint| Array(endpoint.hints).map(&:to_s).include?(@node_zone.to_s) }
          hinted.empty? ? endpoints : hinted
        end

        Program = Struct.new(:text, :filter_rules, :nat_rules, :active_chains, :skipped_nat_rules, :no_local_internal, :no_local_external,
                             keyword_init: true)

        # syncProxyRules' rule generation.  +changed_services+ (partial sync):
        # only these services' chain bodies are rewritten; nil rewrites all.
        # +existing_chains+: the KUBE-* chains currently in the nat table (a
        # full sync deletes the stale service chains).
        def render(rules, changed_services: nil, existing_chains: [])
          filter_rules = []
          nat_rules = []
          skipped_nat_rules = 0
          filter_chains = %w[KUBE-SERVICES KUBE-EXTERNAL-SERVICES KUBE-FORWARD KUBE-NODEPORTS KUBE-PROXY-FIREWALL].map do |chain|
            ":#{chain} - [0:0]"
          end
          nat_chains = %w[KUBE-SERVICES KUBE-NODEPORTS KUBE-POSTROUTING KUBE-MARK-MASQ].map { |chain| ":#{chain} - [0:0]" }
          nat_rules << "-A KUBE-POSTROUTING -m mark ! --mark #{MASQUERADE_MARK}/#{MASQUERADE_MARK} -j RETURN"
          nat_rules << "-A KUBE-POSTROUTING -j MARK --xor-mark #{MASQUERADE_MARK}"
          nat_rules << "-A KUBE-POSTROUTING -m comment --comment \"kubernetes service traffic requiring SNAT\" -j MASQUERADE --random-fully"
          nat_rules << "-A KUBE-MARK-MASQ -j MARK --or-mark #{MASQUERADE_MARK}"
          if @localhost_node_ports
            filter_chains << ":KUBE-FIREWALL - [0:0]"
            filter_rules << "-A KUBE-FIREWALL -m comment --comment \"block incoming localnet connections\" -d 127.0.0.0/8 ! -s 127.0.0.0/8 -m conntrack ! " \
                            "--ctstate RELATED,ESTABLISHED,DNAT -j DROP"
          end
          active_chains = []
          no_local_internal = 0
          no_local_external = 0
          service_ports(rules).each do |svc|
            protocol = svc.protocol.downcase
            name = svc.name_string
            cluster_endpoints, local_endpoints, reachable, has_endpoints = categorize(svc)
            cluster_chain = Iptables.service_chain(name, svc.protocol)
            local_chain = Iptables.local_chain(name, svc.protocol)
            uses_cluster_chain = !cluster_endpoints.empty? && svc.uses_cluster_endpoints?
            uses_local_chain = !local_endpoints.empty? && svc.uses_local_endpoints?
            internal_chain = cluster_chain
            has_internal = has_endpoints
            if svc.internal_policy_local
              internal_chain = local_chain
              has_internal = false if local_endpoints.empty?
            end
            external_policy_chain = cluster_chain
            has_external = has_endpoints
            if svc.external_policy_local
              external_policy_chain = local_chain
              has_external = false if local_endpoints.empty?
            end
            external_chain = Iptables.external_chain(name, svc.protocol)
            uses_external_chain = has_endpoints && svc.externally_accessible?
            lb_chain = external_chain
            fw_chain = Iptables.firewall_chain(name, svc.protocol)
            uses_fw_chain = has_endpoints && !svc.load_balancer_ips.empty? && !svc.source_ranges.empty?
            lb_chain = fw_chain if uses_fw_chain
            internal_filter = external_filter = nil
            if has_endpoints
              unless has_internal
                internal_filter = ["DROP", "\"#{name} has no local endpoints\""]
                no_local_internal += 1
              end
              unless has_external
                external_filter = ["DROP", "\"#{name} has no local endpoints\""]
                no_local_external += 1
              end
            else
              internal_filter = ["REJECT", "\"#{name} has no endpoints\""]
              external_filter = internal_filter
            end
            svc.cluster_ips.each do |cluster_ip|
              if has_internal
                nat_rules << "-A KUBE-SERVICES -m comment --comment \"#{name} cluster IP\" -m #{protocol} -p #{protocol} -d #{cluster_ip} --dport " \
                             "#{svc.port} -j #{internal_chain}"
              else
                filter_rules << "-A KUBE-SERVICES -m comment --comment #{internal_filter[1]} -m #{protocol} -p #{protocol} -d #{cluster_ip} --dport " \
                                "#{svc.port} -j #{internal_filter[0]}"
              end
            end
            svc.external_ips.each do |external_ip|
              if has_endpoints
                nat_rules << "-A KUBE-SERVICES -m comment --comment \"#{name} external IP\" -m #{protocol} -p #{protocol} -d #{external_ip} --dport " \
                             "#{svc.port} -j #{external_chain}"
              end
              unless has_external
                filter_rules << "-A KUBE-EXTERNAL-SERVICES -m comment --comment #{external_filter[1]} -m #{protocol} -p #{protocol} -d #{external_ip} " \
                                "--dport #{svc.port} -j #{external_filter[0]}"
              end
            end
            svc.load_balancer_ips.each do |lb_ip|
              if has_endpoints
                nat_rules << "-A KUBE-SERVICES -m comment --comment \"#{name} loadbalancer IP\" -m #{protocol} -p #{protocol} -d #{lb_ip} --dport " \
                             "#{svc.port} -j #{lb_chain}"
              end
              if uses_fw_chain
                filter_rules << "-A KUBE-PROXY-FIREWALL -m comment --comment \"#{name} traffic not accepted by #{fw_chain}\" -m #{protocol} -p #{protocol} " \
                                "-d #{lb_ip} --dport #{svc.port} -j DROP"
              end
            end
            unless has_external
              svc.load_balancer_ips.each do |lb_ip|
                filter_rules << "-A KUBE-EXTERNAL-SERVICES -m comment --comment #{external_filter[1]} -m #{protocol} -p #{protocol} -d #{lb_ip} --dport " \
                                "#{svc.port} -j #{external_filter[0]}"
              end
            end
            if svc.node_port.positive?
              if has_endpoints
                if @localhost_node_ports && @nfacct_counters[LOCALHOST_NODEPORTS_COUNTER]
                  nat_rules << "-A KUBE-NODEPORTS -m comment --comment #{name} -m #{protocol} -p #{protocol} -d 127.0.0.0/8 --dport #{svc.node_port} -m nfacct --nfacct-name #{LOCALHOST_NODEPORTS_COUNTER} -j #{external_chain}"
                end
                nat_rules << "-A KUBE-NODEPORTS -m comment --comment #{name} -m #{protocol} -p #{protocol} --dport #{svc.node_port} -j #{external_chain}"
              end
              unless has_external
                filter_rules << "-A KUBE-EXTERNAL-SERVICES -m comment --comment #{external_filter[1]} -m addrtype --dst-type LOCAL -m #{protocol} -p #{protocol} --dport #{svc.node_port} -j #{external_filter[0]}"
              end
            end
            if svc.health_check_node_port.positive?
              filter_rules << "-A KUBE-NODEPORTS -m comment --comment \"#{name} health check node port\" -m tcp -p tcp --dport #{svc.health_check_node_port} -j ACCEPT"
            end
            # Partial sync: an unchanged service keeps its chains as they are.
            service_key = name.split(":").first
            skip = !changed_services.nil? && !changed_services.include?(service_key)
            body_chains = skip ? nil : nat_chains
            body_rules = skip ? nil : nat_rules
            write = lambda do |line|
              if body_rules then body_rules << line
              else skipped_nat_rules += 1
              end
            end
            if has_internal
              svc.cluster_ips.each do |cluster_ip|
                args = "-m comment --comment \"#{name} cluster IP\" -m #{protocol} -p #{protocol} -d #{cluster_ip} --dport #{svc.port}"
                if @masquerade_all
                  write.call("-A #{internal_chain} #{args} -j KUBE-MARK-MASQ")
                elsif @cluster_cidr
                  write.call("-A #{internal_chain} #{args} ! -s #{@cluster_cidr} -j KUBE-MARK-MASQ")
                end
              end
            end
            if uses_external_chain
              body_chains&.push(":#{external_chain} - [0:0]")
              active_chains << external_chain
              if svc.external_policy_local
                if @cluster_cidr
                  write.call("-A #{external_chain} -m comment --comment \"pod traffic for #{name} external destinations\" -s #{@cluster_cidr} -j #{cluster_chain}")
                end
                write.call("-A #{external_chain} -m comment --comment \"masquerade LOCAL traffic for #{name} external destinations\" -m addrtype --src-type LOCAL -j KUBE-MARK-MASQ")
                write.call("-A #{external_chain} -m comment --comment \"route LOCAL traffic for #{name} external destinations\" -m addrtype --src-type LOCAL -j #{cluster_chain}")
              else
                write.call("-A #{external_chain} -m comment --comment \"masquerade traffic for #{name} external destinations\" -j KUBE-MARK-MASQ")
              end
              write.call("-A #{external_chain} -j #{external_policy_chain}") if has_external
            end
            if uses_fw_chain
              body_chains&.push(":#{fw_chain} - [0:0]")
              active_chains << fw_chain
              allow_from_node = false
              svc.source_ranges.each do |cidr|
                write.call("-A #{fw_chain} -m comment --comment \"#{name} loadbalancer IP\" -s #{cidr} -j #{external_chain}")
                allow_from_node ||= @node_ips.any? do |ip|
                  IPAddr.new(cidr).include?(IPAddr.new(ip))
                rescue StandardError
                  false
                end
              end
              if allow_from_node
                svc.load_balancer_ips.each do |lb_ip|
                  write.call("-A #{fw_chain} -m comment --comment \"#{name} loadbalancer IP\" -s #{lb_ip} -j #{external_chain}")
                end
              end
              write.call("-A #{fw_chain} -m comment --comment \"other traffic to #{name} will be dropped by KUBE-PROXY-FIREWALL\"")
            end
            if uses_cluster_chain
              body_chains&.push(":#{cluster_chain} - [0:0]")
              active_chains << cluster_chain
              write_endpoint_rules(write, name, svc, cluster_chain, cluster_endpoints)
            end
            if uses_local_chain
              body_chains&.push(":#{local_chain} - [0:0]")
              active_chains << local_chain
              write_endpoint_rules(write, name, svc, local_chain, local_endpoints)
            end
            reachable.each do |endpoint|
              endpoint_string = endpoint_address(endpoint)
              sep_chain = Iptables.endpoint_chain(name, svc.protocol, endpoint_string)
              body_chains&.push(":#{sep_chain} - [0:0]")
              active_chains << sep_chain
              write.call("-A #{sep_chain} -m comment --comment #{name} -s #{endpoint.address} -j KUBE-MARK-MASQ")
              recent = svc.session_affinity == "ClientIP" ? " -m recent --name #{sep_chain} --set" : ""
              write.call("-A #{sep_chain} -m comment --comment #{name}#{recent} -m #{protocol} -p #{protocol} -j DNAT --to-destination #{endpoint_string}")
            end
          end
          deleted = 0
          (existing_chains - active_chains).each do |chain|
            next unless Iptables.service_chain?(chain)

            nat_chains << ":#{chain} - [0:0]"
            nat_rules << "-X #{chain}"
            deleted += 1
          end
          destinations = "-m addrtype --dst-type LOCAL"
          destinations += if ipv6?
                            " ! -d ::1/128"
                          else
                            (@localhost_node_ports ? "" : " ! -d 127.0.0.0/8")
                          end
          nat_rules << "-A KUBE-SERVICES -m comment --comment \"kubernetes service nodeports; NOTE: this must be the last rule in this chain\" #{destinations} -j KUBE-NODEPORTS"
          unless @conntrack_tcp_liberal
            nfacct = @nfacct_counters[CT_STATE_INVALID_COUNTER] ? " -m nfacct --nfacct-name #{CT_STATE_INVALID_COUNTER}" : ""
            filter_rules << "-A KUBE-FORWARD -m conntrack --ctstate INVALID#{nfacct} -j DROP"
          end
          filter_rules << "-A KUBE-FORWARD -m comment --comment \"kubernetes forwarding rules\" -m mark --mark #{MASQUERADE_MARK}/#{MASQUERADE_MARK} -j ACCEPT"
          filter_rules << "-A KUBE-FORWARD -m comment --comment \"kubernetes forwarding conntrack rule\" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
          text = +"*filter\n"
          text << filter_chains.join("\n") << "\n" << filter_rules.join("\n") << "\nCOMMIT\n*nat\n"
          text << nat_chains.join("\n") << "\n" << nat_rules.join("\n") << "\nCOMMIT\n"
          Program.new(text: text, filter_rules: filter_rules.length, nat_rules: nat_rules.length - deleted, active_chains: active_chains,
                      skipped_nat_rules: skipped_nat_rules, no_local_internal: no_local_internal, no_local_external: no_local_external)
        end

        private

        def endpoint_address(endpoint)
          ip = endpoint.address.to_s
          ip.include?(":") ? "[#{ip}]:#{endpoint.port}" : "#{ip}:#{endpoint.port}"
        end

        # writeServiceToEndpointRules.
        def write_endpoint_rules(write, name, svc, chain, endpoints)
          protocol = svc.protocol
          if svc.session_affinity == "ClientIP"
            endpoints.each do |endpoint|
              sep_chain = Iptables.endpoint_chain(name, protocol, endpoint_address(endpoint))
              write.call("-A #{chain} -m comment --comment \"#{name} -> #{endpoint_address(endpoint)}\" -m recent --name #{sep_chain} --rcheck --seconds #{svc.affinity_timeout} --reap -j #{sep_chain}")
            end
          end
          endpoints.each_with_index do |endpoint, index|
            sep_chain = Iptables.endpoint_chain(name, protocol, endpoint_address(endpoint))
            statistic = index < endpoints.length - 1 ? " -m statistic --mode random --probability #{Iptables.probability(endpoints.length - index)}" : ""
            write.call("-A #{chain} -m comment --comment \"#{name} -> #{endpoint_address(endpoint)}\"#{statistic} -j #{sep_chain}")
          end
        end
      end

      # nfnetlink_acct: the packet counters kube-proxy's nfacct matches feed
      # (ct_state_invalid_dropped_pkts, localhost_nps_accepted_pkts).
      class Nfacct
        NETLINK_NETFILTER = 12
        NFNL_SUBSYS_ACCT = 7
        NFNL_MSG_ACCT_NEW = 0
        NFNL_MSG_ACCT_GET = 1
        NFNL_MSG_ACCT_DEL = 3
        NLM_F_REQUEST = 0x01
        NLM_F_ACK = 0x04
        NLM_F_CREATE = 0x400
        NLM_F_DUMP = 0x300
        NLMSG_ERROR = 2
        NLMSG_DONE = 3
        NFACCT_NAME = 1
        NFACCT_PKTS = 2
        NFACCT_BYTES = 3

        def initialize(timeout: 2.0)
          @timeout = timeout
          @sequence = 0
        end

        # Create the counter if it does not exist; false when nfacct is not available.
        def ensure(name)
          request(NFNL_MSG_ACCT_NEW, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, attribute(NFACCT_NAME, "#{name}\0"))
          true
        rescue SystemCallError, IOError, RuntimeError
          false
        end

        def delete(name)
          request(NFNL_MSG_ACCT_DEL, NLM_F_REQUEST | NLM_F_ACK, attribute(NFACCT_NAME, "#{name}\0"))
          true
        rescue SystemCallError, IOError, RuntimeError
          false
        end

        # {name => [packets, bytes]}.
        def counters
          replies = request(NFNL_MSG_ACCT_GET, NLM_F_REQUEST | NLM_F_DUMP, "", dump: true)
          replies.each_with_object({}) do |payload, result|
            attrs = decode_attributes(payload.byteslice(4..).to_s)
            name = attrs[NFACCT_NAME]&.delete_suffix("\0")
            next if name.nil?

            result[name] = [attrs[NFACCT_PKTS]&.unpack1("Q>").to_i, attrs[NFACCT_BYTES]&.unpack1("Q>").to_i]
          end
        rescue SystemCallError, IOError, RuntimeError
          {}
        end

        private

        def request(type, flags, body, dump: false)
          socket = Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, NETLINK_NETFILTER)
          socket.bind([16, 0, 0, 0].pack("S<S<L<L<"))
          @sequence += 1
          payload = [0, 0, 0].pack("CCn") + body
          length = 16 + payload.bytesize
          socket.send(
            [length, (NFNL_SUBSYS_ACCT << 8) | type, flags, @sequence,
             0].pack("L<S<S<L<L<") + payload + ("\0" * (((length + 3) / 4 * 4) - length)), 0
          )
          replies = []
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise Errno::ETIMEDOUT, "nfacct" if remaining <= 0 || !socket.wait_readable(remaining)

            buffer = socket.recv(65_536)
            offset = 0
            while offset + 16 <= buffer.bytesize
              message_length, message_type, _flags, sequence = buffer.byteslice(offset, 16).unpack("L<S<S<L<")
              message_payload = buffer.byteslice(offset + 16, message_length - 16).to_s
              offset += (message_length + 3) / 4 * 4
              next unless sequence == @sequence

              case message_type
              when NLMSG_ERROR
                code = message_payload.unpack1("l<")
                raise SystemCallError.new("nfacct", code.abs) unless code.zero?
                return replies unless dump
              when NLMSG_DONE then return replies
              else replies << message_payload
              end
            end
          end
        ensure
          socket&.close
        end

        def attribute(type, value)
          length = 4 + value.bytesize
          [length, type].pack("S<S<") + value + ("\0" * (((length + 3) / 4 * 4) - length))
        end

        def decode_attributes(bytes)
          offset = 0
          attrs = {}
          while offset + 4 <= bytes.bytesize
            length, type = bytes.byteslice(offset, 4).unpack("S<S<")
            break if length < 4

            attrs[type & 0x3fff] = bytes.byteslice(offset + 4, length - 4)
            offset += (length + 3) / 4 * 4
          end
          attrs
        end
      end

      # Runs iptables / iptables-restore (ip6tables for IPv6).  +runner+:
      # ->(argv, stdin) -> [status, stdout, stderr], injectable for tests.
      class Adapter
        attr_reader :last_program

        def initialize(runner: nil, test_adapter: false)
          @runner = runner || method(:spawn)
          @test_adapter = test_adapter
          @last_program = {}
          @nfacct = Nfacct.new
        end

        def test_adapter? = @test_adapter

        def binary(name, family) = family == "IPv6" ? name.sub("iptables", "ip6tables") : name

        def production_capable?
          return false if @test_adapter

          status, = @runner.call([binary("iptables-restore", "IPv4"), "--version"], nil)
          status.to_i.zero?
        rescue StandardError
          false
        end

        def mechanically_capable? = production_capable? || @test_adapter

        # EnsureChain + EnsureRule for the jump chains (a full sync).
        def ensure_jump_chains(family, localhost_node_ports: true)
          JUMP_CHAINS.each do |table, chain, hook, comment, extra|
            next if chain == "KUBE-FIREWALL" && !(localhost_node_ports && family == "IPv4")

            run!([binary("iptables", family), "-w", "5", "-t", table, "-N", chain], allow_failure: true)
            args = extra.dup
            args += ["-m", "comment", "--comment", comment] unless comment.empty?
            args += ["-j", chain]
            status, = run!([binary("iptables", family), "-w", "5", "-t", table, "-C", hook, *args], allow_failure: true)
            run!([binary("iptables", family), "-w", "5", "-t", table, "-I", hook, *args]) unless status.zero?
          end
        end

        # RestoreAll(NoFlushTables, RestoreCounters).
        def restore(program, family)
          @last_program[family] = program
          run!([binary("iptables-restore", family), "-w", "5", "--noflush", "--counters"], stdin: program)
          true
        end

        # The KUBE-* chains in the nat table (iptables-save).
        def nat_chains(family)
          _status, output, = run!([binary("iptables-save", family), "-t", "nat"], allow_failure: true)
          output.to_s.lines.filter_map { |line| line[/\A:(KUBE-[A-Z0-9-]+) /, 1] }
        end

        def ensure_nfacct(name) = @nfacct.ensure(name)
        def nfacct_counters = @nfacct.counters

        # Tear the proxier out: jump rules, then the KUBE-* chains.
        def cleanup(family)
          JUMP_CHAINS.each do |table, chain, hook, comment, extra|
            args = extra.dup
            args += ["-m", "comment", "--comment", comment] unless comment.empty?
            args += ["-j", chain]
            loop do
              status, = run!([binary("iptables", family), "-w", "5", "-t", table, "-D", hook, *args], allow_failure: true)
              break unless status.zero?
            end
          end
          %w[filter nat].each do |table|
            chains = run!([binary("iptables-save", family), "-t", table], allow_failure: true)[1].to_s.lines.filter_map do |line|
              line[/\A:(KUBE-[A-Z0-9-]+) /, 1]
            end
            chains.each do |chain|
              run!([binary("iptables", family), "-w", "5", "-t", table, "-F", chain], allow_failure: true)
              run!([binary("iptables", family), "-w", "5", "-t", table, "-X", chain], allow_failure: true)
            end
          end
        end

        private

        def run!(argv, stdin: nil, allow_failure: false)
          status, stdout, stderr = @runner.call(argv, stdin)
          unless allow_failure || status.to_i.zero?
            raise BackendError,
                  "#{argv.first(4).join(" ")} failed (#{status}): #{stderr.to_s.strip[0, 300]}"
          end

          [status.to_i, stdout, stderr]
        end

        def spawn(argv, stdin)
          stdout, stderr, status = Open3.capture3({"XTABLES_LOCKFILE" => "/run/xtables.lock"}, *argv, stdin_data: stdin.to_s)
          [status.exitstatus.to_i, stdout, stderr]
        rescue Errno::ENOENT => error
          [127, "", error.message]
        end
      end

      # The iptables proxier as a Proxy backend.
      class Backend < Proxy::Backend
        attr_accessor :node_name, :node_addresses, :node_zone, :cluster_cidr, :masquerade_all, :localhost_node_ports, :metrics
        attr_reader :adapter, :last_programs

        def initialize(adapter: nil, metrics: nil, families: nil, clock: -> { Time.now.utc }, node_name: nil, node_addresses: [],
                       masquerade_all: false, localhost_node_ports: true, cluster_cidr: nil, test_adapter: false, **)
          @adapter = adapter || Adapter.new(test_adapter: test_adapter)
          super(name: "iptables", clock: clock, syscall_adapter: @adapter, test_adapter: test_adapter, **)
          @metrics = metrics
          @families = families
          @node_name = node_name
          @node_addresses = Array(node_addresses)
          @masquerade_all = masquerade_all
          @localhost_node_ports = localhost_node_ports
          @cluster_cidr = cluster_cidr
          @node_zone = nil
          @last_full_sync = {}
          @need_full_sync = Hash.new(true)
          @nfacct_counters = {}
          @last_programs = {}
          @attached = false
          @pending_services = Hash.new { |hash, family| hash[family] = Set.new }
        end

        def families
          @families || begin
            detected = @node_addresses.filter_map do |ip|
              IPAddr.new(ip.to_s).ipv6? ? "IPv6" : "IPv4"
            rescue StandardError
              nil
            end.uniq
            detected.empty? ? ["IPv4"] : detected
          end
        end

        def attachable?
          @adapter.respond_to?(:mechanically_capable?) && @adapter.mechanically_capable?
        end

        def available? = attachable?
        def production_capable? = @adapter.respond_to?(:production_capable?) && @adapter.production_capable? == true
        def attached? = @mutex.synchronize { @attach_state == :attached }

        def kernel_identity
          {"backend" => "iptables", "families" => families, "chains" => CHAINS.values}
        end

        # Attach: ensure the jump chains and program the current rules.
        def attach(**_options)
          @apply_mutex.synchronize do
            set_attach_state(:attaching)
            raise BackendError, "iptables attach requires iptables-restore on this node" unless attachable?

            @need_full_sync.clear
            families.each { |family| @need_full_sync[family] = true }
            sync_all!
            @mutex.synchronize do
              @attach_state = :attached
              @last_error = nil
            end
          end
          true
        rescue BackendError => error
          fail_attach_state(error)
          raise
        rescue StandardError => error
          wrapped = BackendError.new("iptables attach failed: #{error.message}")
          fail_attach_state(wrapped)
          raise wrapped
        end

        def detach(**_options)
          @apply_mutex.synchronize do
            families.each { |family| @adapter.cleanup(family) } if attached? && @adapter.respond_to?(:cleanup)
            @mutex.synchronize do
              @attach_state = :detached
              @last_error = nil
            end
          end
          true
        end

        def apply_diff(diff)
          @apply_mutex.synchronize do
            previous = backend_state_snapshot
            begin
              result = super
              remember_changed(result)
              sync_all! if attached?
              result
            rescue StandardError
              restore_backend_state(previous)
              raise
            end
          end
        end

        def apply_compiled(compiled)
          @apply_mutex.synchronize do
            previous = backend_state_snapshot
            begin
              result = super
              remember_changed(result)
              sync_all! if attached?
              result
            rescue StandardError
              restore_backend_state(previous)
              raise
            end
          end
        end

        # One syncProxyRules per family.  Public for tests and the service's
        # periodic resync.
        def sync_all!(now: @clock.call)
          families.each { |family| sync_family!(family, now: now) }
        end

        def sync_family!(family, now: @clock.call)
          full = @need_full_sync[family] || @last_full_sync[family].nil? || (now.to_f - @last_full_sync[family].to_f) > FULL_SYNC_PERIOD_SECONDS
          if full
            @adapter.ensure_jump_chains(family, localhost_node_ports: @localhost_node_ports) if @adapter.respond_to?(:ensure_jump_chains)
            if @adapter.respond_to?(:ensure_nfacct)
              [CT_STATE_INVALID_COUNTER, LOCALHOST_NODEPORTS_COUNTER].each do |counter|
                @nfacct_counters[counter] = @adapter.ensure_nfacct(counter)
              end
            end
          end
          renderer = Renderer.new(family: family, node_name: @node_name, node_ips: @node_addresses, masquerade_all: @masquerade_all,
                                  localhost_node_ports: @localhost_node_ports, nfacct_counters: @nfacct_counters, node_zone: @node_zone,
                                  cluster_cidr: @cluster_cidr)
          existing = full && @adapter.respond_to?(:nat_chains) ? @adapter.nat_chains(family) : []
          changed = full ? nil : @pending_services[family].dup
          program = renderer.render(rules, changed_services: changed, existing_chains: existing)
          @last_programs[family] = program
          begin
            @adapter.restore(program.text, family)
          rescue StandardError => error
            @metrics&.iptables_restore_failed(family, partial: !full)
            @need_full_sync[family] = true
            raise BackendError, "iptables-restore failed (#{family}): #{error.message}"
          end
          @need_full_sync[family] = false
          @pending_services[family].clear
          @last_full_sync[family] = now if full
          @metrics&.iptables_synced(family, filter_last: program.filter_rules, filter_total: program.filter_rules,
                                            nat_last: program.nat_rules, nat_total: program.nat_rules + program.skipped_nat_rules)
          program
        end

        # The nfacct packet counters (the two Custom metrics).
        def nfacct_counters
          return {} unless @adapter.respond_to?(:nfacct_counters)

          @adapter.nfacct_counters
        end

        private

        def remember_changed(diff)
          services = (diff.added + diff.deleted + diff.updated.flatten).filter_map do |rule|
            rule.respond_to?(:service_key) ? rule.service_key : nil
          end
          families.each { |family| @pending_services[family].merge(services) }
        end

        def set_attach_state(state)
          @mutex.synchronize { @attach_state = state }
        end

        def fail_attach_state(error)
          @mutex.synchronize do
            @attach_state = :failed
            @last_error = error
          end
        end
      end
    end

    IptablesBackend = Iptables::Backend
  end
end
