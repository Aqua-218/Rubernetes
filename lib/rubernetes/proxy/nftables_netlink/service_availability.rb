# frozen_string_literal: true

module Rubernetes
  module Proxy
    class NftablesNetlinkAdapter
      module ServiceAvailability
        Route = Data.define(:family, :endpoints, :verdict, :host_only)

        SERVICE_FILTER_CHAIN = "service_endpoints_check"
        NODE_PORT_FILTER_CHAIN = "nodeport_endpoints_check"
        FILTER_HOOKS = {"filter_input" => 1, "filter_forward" => 2, "filter_output" => 3}.freeze
        FILTER_CHAINS = {NODE_PORT_FILTER_CHAIN => ["filter_input"].freeze, SERVICE_FILTER_CHAIN => FILTER_HOOKS.keys.freeze}.freeze

        NFT_CT_STATE = 0
        CT_STATE_NEW = 1 << 3
        NFT_DROP = 0
        NFT_REJECT_ICMPX_PORT_UNREACH = 1
        NFTA_FIB_DREG = 1
        NFTA_FIB_RESULT = 2
        NFTA_FIB_FLAGS = 3
        NFT_FIB_RESULT_ADDRTYPE = 3
        NFTA_FIB_F_SADDR = 1
        RTN_LOCAL = 2

        private

        def endpoint_routes(rule)
          endpoints = normalized_endpoints(rule).group_by { |endpoint| family_for_address(endpoint.fetch("address")) }
          endpoint_families(rule, endpoints.keys).map do |family|
            route_for_family(rule, family, endpoints.fetch(family, []))
          end
        end

        def route_for_family(rule, family, endpoints)
          local_node = rule.metadata["node"] || rule.metadata[:node]
          local = endpoints.select { |endpoint| endpoint.fetch("local") }
          if rule.health_check
            health = (local_node.to_s.empty? ? endpoints : local).select { |endpoint| endpoint.fetch("healthy") }
            return Route.new(family: family, endpoints: health, verdict: nil, host_only: false)
          end

          cluster = available_endpoints(endpoints) { |ready| apply_topology_hints(rule, ready) }
          return Route.new(family: family, endpoints: [], verdict: :reject, host_only: false) if cluster.empty?

          policy = external_rule?(rule) ? rule.external_traffic_policy : rule.internal_traffic_policy
          if policy == "Local"
            local = available_endpoints(local)
            return Route.new(family: family, endpoints: local, verdict: nil, host_only: false) unless local.empty?

            # External Local traffic from the host still uses Cluster
            # endpoints. The post-DNAT filter drops the remaining traffic.
            external = external_rule?(rule)
            return Route.new(family: family, endpoints: external ? cluster : [], verdict: :drop, host_only: external)
          end

          Route.new(family: family, endpoints: cluster, verdict: nil, host_only: false)
        end

        def unavailable_service_rules(rule, route)
          chain = rule.virtual_ip ? SERVICE_FILTER_CHAIN : NODE_PORT_FILTER_CHAIN
          terminal = route.verdict == :reject ? reject_expression(NFT_REJECT_ICMPX_PORT_UNREACH) : verdict_expression(NFT_DROP)
          destination_addresses_for(rule, route.family).map do |address|
            id = "availability:#{rule_identity(rule)}:#{route.family}:#{address}:#{route.verdict}"
            rule_marker = marker("rule", id)
            expressions = service_match_expressions(rule, family: route.family, destination_address: address) + [terminal]
            {"chain" => chain, "marker" => rule_marker, "action" => route.verdict.to_s,
             "message" => new_rule_message(chain_name: chain, marker: rule_marker, expressions: expressions)}
          end
        end

        def availability_chains_and_jumps(filter_rules)
          return [[], []] if filter_rules.empty?

          base = FILTER_HOOKS.map do |name, hook|
            chain_marker = marker("chain", "base:#{name}")
            {"name" => name, "marker" => chain_marker, "base" => true,
             "message" => new_chain_message(name: name, marker: chain_marker, hook: {hook: hook, priority: 0, type: "filter"})}
          end
          checks = FILTER_CHAINS.keys.map do |name|
            chain_marker = marker("chain", "availability:#{name}")
            {"name" => name, "marker" => chain_marker, "base" => false, "message" => new_chain_message(name: name, marker: chain_marker)}
          end
          jumps = FILTER_CHAINS.flat_map do |target, sources|
            sources.map do |from|
              jump_marker = marker("rule", "jump:#{from}:#{target}")
              {"chain" => from, "marker" => jump_marker,
               "message" => new_jump_rule_message(from, target, jump_marker, prefix: new_connection_expressions)}
            end
          end
          [base + checks, jumps]
        end

        def new_connection_expressions
          [expression("ct", attributes(attribute(NFTA_CT_DREG, u32(1)), attribute(NFTA_CT_KEY, u32(NFT_CT_STATE)))), compare_expression(1, CT_STATE_NEW)]
        end

        def local_source_expressions
          [expression("fib", attributes(attribute(NFTA_FIB_DREG, u32(1)), attribute(NFTA_FIB_RESULT, u32(NFT_FIB_RESULT_ADDRTYPE)),
                                        attribute(NFTA_FIB_FLAGS, u32(NFTA_FIB_F_SADDR)))), compare_expression(1, RTN_LOCAL)]
        end
      end
    end
  end
end
