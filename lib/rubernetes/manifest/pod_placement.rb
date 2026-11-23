# frozen_string_literal: true

module Rubernetes
  module Manifest
    module PodPlacement
      UNSATISFIABLE = {do_not_schedule: "DoNotSchedule", schedule_anyway: "ScheduleAnyway"}.freeze
      private_constant :UNSATISFIABLE

      def anti_affinity(on:)
        key = topology_key(on)
        @anti_affinity_location ||= caller(1, 1)
        (@anti_affinity_keys ||= []) << key
      end

      def spread_across(key, max_skew: 1, when_unsatisfiable: :do_not_schedule)
        key = topology_key(key)
        raise Error, "spread_across max_skew must be an integer from 1 to 2147483647" unless max_skew.is_a?(Integer) && max_skew.between?(1, 2_147_483_647)

        action = UNSATISFIABLE.fetch(when_unsatisfiable) do
          raise Error, "spread_across when_unsatisfiable must be :do_not_schedule or :schedule_anyway"
        end
        constraint = {"topologyKey" => key, "maxSkew" => max_skew, "whenUnsatisfiable" => action}
        (@spread_constraints ||= []) << [constraint, caller(1, 1)]
        nil
      end

      private

      def topology_key(value)
        key = String(value)
        errors = Rubernetes::Schema::KubernetesValidator.qualified_name_messages(key, label_key: true)
        raise Error, "invalid topology key #{key.inspect}: #{errors.join(", ")}" unless errors.empty?

        key
      end

      def complete_placement(template)
        return unless @anti_affinity_keys || @spread_constraints

        selector = workload_selector(template)
        if selector["matchLabels"].to_h.empty? && Array(selector["matchExpressions"]).empty?
          helper, location = @anti_affinity_keys ? ["anti_affinity", @anti_affinity_location] : ["spread_across", @spread_constraints.first.last]
          raise Error, "#{helper} needs labels on the Pods to tell them apart", location
        end

        if @anti_affinity_keys
          terms = pod_spec["affinity"] ||= {}
          terms = (terms["podAntiAffinity"] ||= {})["requiredDuringSchedulingIgnoredDuringExecution"] ||= []
          @anti_affinity_keys.each { |key| terms << {"labelSelector" => selector, "topologyKey" => key} }
        end
        return unless @spread_constraints

        constraints = pod_spec["topologySpreadConstraints"] ||= []
        @spread_constraints.each do |entry, location|
          key, action = entry.values_at("topologyKey", "whenUnsatisfiable")
          if constraints.any? { |other| other && other["topologyKey"] == key && other["whenUnsatisfiable"] == action }
            raise Error, "duplicate topology spread constraint for #{key.inspect} and #{action}", location
          end

          constraints << entry.merge("labelSelector" => selector)
        end
      end

      def workload_selector(template)
        labels = (template || @workload).dig("metadata", "labels")
        if @pod_spec_path.length > 2
          selector = @workload.dig(*@pod_spec_path[0...-2], "selector")
          if @workload["kind"] == "ReplicationController"
            return {"matchLabels" => selector} unless selector.to_h.empty?
          elsif selector
            return selector
          end
        end
        {"matchLabels" => labels}
      end
    end
  end
end
