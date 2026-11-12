# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class NodeController < BaseController
        # nodetopology.GetZoneKey.
        def self.zone_key(node)
          labels = Support.labels(node)
          zone = labels.fetch("failure-domain.beta.kubernetes.io/zone") { labels["topology.kubernetes.io/zone"] }.to_s
          region = labels.fetch("failure-domain.beta.kubernetes.io/region") { labels["topology.kubernetes.io/region"] }.to_s
          region.empty? && zone.empty? ? "" : "#{region}:\u0000:#{zone}"
        end

        def self.eviction_tainted?(node)
          Array(Support.value(Support.spec(node), "taints", [])).any? do |taint|
            %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].include?(Support.value(taint, "key", "").to_s) &&
              Support.value(taint, "effect", "") == "NoExecute"
          end
        end

        # handleDisruption / addPodEvictorForNewZone: per zone its size, the
        # nodes whose Ready condition is not True, and the healthy share; a
        # zone left without nodes reads 0 / 100 / 0 once.
        # The zones are the process's (the plan and orphan paths use separate
        # instances of this controller).
        ZONE_MUTEX = Mutex.new
        ZONE_NODES = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache)

        def record_zone_health(name, zone, ready)
          ZONE_MUTEX.synchronize do
            previous = ZONE_NODES[name]
            ControllerMetrics.increment("node_collector_evictions_total", {"zone" => zone}, by: 0) unless ZONE_NODES.values.any? do |entry|
              entry[0] == zone
            end
            ZONE_NODES[name] = [zone, ready]
            publish_zones([zone, previous&.first].compact.uniq)
          end
        end

        # classifyNodes: a Node that is gone leaves its zone's metrics.
        def orphan_cleanup? = true

        def plan_orphans(key, store: nil)
          # A Node's key is its bare name; a namespaced key is some other kind.
          forget_zone_node(key.to_s) unless key.to_s.include?("/")
          nil
        end

        def forget_zone_node(name)
          ZONE_MUTEX.synchronize do
            previous = ZONE_NODES.delete(name)
            publish_zones([previous.first]) if previous
          end
        end

        def publish_zones(zones)
          zones.each do |zone|
            members = ZONE_NODES.values.select { |entry| entry[0] == zone }
            labels = {"zone" => zone}
            if members.empty?
              ControllerMetrics.set("node_collector_zone_size", 0, labels)
              ControllerMetrics.set("node_collector_zone_health", 100, labels)
              ControllerMetrics.set("node_collector_unhealthy_nodes_in_zone", 0, labels)
              next
            end
            unhealthy = members.count { |entry| !entry[1] }
            ControllerMetrics.set("node_collector_zone_size", members.length, labels)
            ControllerMetrics.set("node_collector_zone_health", 100.0 * (members.length - unhealthy) / members.length, labels)
            ControllerMetrics.set("node_collector_unhealthy_nodes_in_zone", unhealthy, labels)
          end
        end
        private :record_zone_health, :publish_zones
      end
    end
  end
end
