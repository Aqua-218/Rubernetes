# frozen_string_literal: true

module Rubernetes
  module Scheduler
    module Filters
      class PodTopologySpread
        # matchNodeInclusionPolicies applies per constraint in both PreFilter
        # and PreScore. An omitted affinity policy is Honor, taints are Ignore.
        def self.includes_node?(constraint, pod, node, context)
          return false if constraint["nodeAffinityPolicy"] != "Ignore" && NodeAffinity.new.call(pod, node) != true

          constraint["nodeTaintsPolicy"] != "Honor" || TaintToleration.new.call(pod, node, context) == true
        end

        def call(pod, node, context = nil)
          constraints = pod.topology_spread_constraints.select { |entry| entry.fetch("whenUnsatisfiable", "DoNotSchedule") == "DoNotSchedule" }
          return true if constraints.empty?

          nodes = Helpers.context_nodes(context)
          if context.is_a?(CycleContext) && !nodes.empty?
            counts_by_constraint = context.topology_spread_for(pod) { {}.compare_by_identity }
          else
            counts_by_constraint = {}.compare_by_identity
            nodes = [node] if nodes.empty?
          end
          constraints.each do |constraint|
            key = constraint["topologyKey"]
            next if key.to_s.empty?

            domain = node.labels[key]
            return Helpers.reject("node lacks topology key #{key.inspect}", code: "PodTopologySpread") if domain.nil?

            counts, adjustment = counts_by_constraint[constraint] ||= domain_counts(nodes, constraints, constraint, pod, context)
            skew = counts.fetch(domain, 0) + adjustment
            max_skew = Integer(constraint.fetch("maxSkew", 1))
            if skew > max_skew
              details = {"topologyKey" => key, "domain" => domain, "skew" => skew, "maxSkew" => max_skew}
              return Helpers.reject("node would violate topology spread maxSkew", code: "PodTopologySpread", details: details)
            end
          rescue ArgumentError, TypeError
            return Helpers.reject("pod topology spread constraint is invalid", code: "PodTopologySpread")
          end
          true
        end

        alias filter call

        private

        def domain_counts(nodes, constraints, constraint, pod, context)
          keys = constraints.filter_map { |entry| entry["topologyKey"] }
          eligible = nodes.select { |node| keys.all? { |key| node.labels.key?(key) } }
          selector = Helpers.effective_selector(constraint, pod)
          counts = matching_counts(eligible, constraint, pod, context, selector, constraint.fetch("topologyKey"))
          minimum = counts.size < Integer(constraint.fetch("minDomains", 1)) ? 0 : counts.values.min.to_i
          [counts, (Helpers.selector_matches?(pod, selector) ? 1 : 0) - minimum]
        end

        def matching_counts(nodes, constraint, pod, context, selector, key)
          eligible = nodes.select { |candidate| self.class.includes_node?(constraint, pod, candidate, context) }
          domains = eligible.to_h { |candidate| [candidate.name, candidate.labels.fetch(key)] }
          counts = domains.values.to_h { |domain| [domain, 0] }
          Helpers.context_pods(context).each do |existing|
            domain = domains[existing.node_name]
            next unless domain && existing.namespace == pod.namespace
            next if existing.uid == pod.uid && !pod.uid.empty?

            counts[domain] += 1 if Helpers.selector_matches?(existing, selector)
          end
          counts
        end
      end
    end
  end
end
