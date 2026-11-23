# frozen_string_literal: true

module Rubernetes
  module Controller
    # Aggregates rules into ClusterRoles selected by aggregationRule. Only the
    # selected target is updated; canonical rule de-duplication is replay safe.
    class ClusterRoleAggregationController < BaseController
      include InfrastructureStorageSupport

      CLUSTER_ROLE = ResourceDescriptor.parse("ClusterRole")

      def plan(target, store: nil, cluster_roles: nil, roles: nil, **_options)
        return empty_result(target) unless Support.kind(target) == "ClusterRole"

        adapter = adapter_for(store)
        cluster_roles ||= roles || list_storage_objects(adapter, CLUSTER_ROLE, namespace: :all)
        selectors = Array(Support.value(Support.value(target, "aggregationRule", {}), "clusterRoleSelectors", nil))
        return empty_result(target) if selectors.empty?

        predicates = selectors.map { |selector| Support.selector_predicate(selector) }
        selected = Array(cluster_roles).select do |role|
          Support.kind(role) == "ClusterRole" && Support.name(role) != Support.name(target) &&
            predicates.any? { |matches| matches.call(role) }
        end.sort_by { |role| Support.name(role) }
        rules = []
        seen = {}
        selected.each do |role|
          Array(Support.value(role, "rules", [])).each do |rule|
            key = canonical_rule(rule)
            next if seen[key]

            seen[key] = true
            rules << Support.deep_copy(rule)
          end
        end
        candidate = Support.deep_copy(target)
        candidate["rules"] = rules
        update = operation_update(target, candidate, descriptor: CLUSTER_ROLE, reason: "cluster role aggregation")
        events = if update
                   [{"type" => "Normal", "reason" => "ClusterRoleAggregated",
                     "message" => "cluster role #{Support.name(target)} aggregated #{rules.length} rule(s)"}]
                 else
                   []
                 end
        ReconcileResult.new(operations: [update].compact, status: Support.status(target), events: events,
                            controller: name, key: Support.name(target))
      end

      private

      def empty_result(target)
        ReconcileResult.new(operations: [], status: Support.status(target), controller: name,
                            key: Support.name(target))
      end
    end
  end
end
