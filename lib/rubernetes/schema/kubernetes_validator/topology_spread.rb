# frozen_string_literal: true

module Rubernetes
  module Schema
    module KubernetesValidator
      TOPOLOGY_SPREAD_MATCH_KEYS = "MatchLabelKeysInPodTopologySpread"
      TOPOLOGY_SPREAD_SELECTOR_MERGE = "MatchLabelKeysInPodTopologySpreadSelectorMerge"
      TOPOLOGY_SPREAD_GATES = [TOPOLOGY_SPREAD_MATCH_KEYS, TOPOLOGY_SPREAD_SELECTOR_MERGE].freeze
      TOPOLOGY_SPREAD_ACTIONS = %w[DoNotSchedule ScheduleAnyway].freeze
      TOPOLOGY_SPREAD_NODE_POLICIES = %w[Honor Ignore].freeze

      module_function

      def prepare_topology_spread(root, old, kind, disabled_gates)
        path = topology_spread_path(kind)
        return root unless path

        constraints = dig_path(root, path)
        return root unless constraints.is_a?(Array) && !constraints.empty?

        keys_enabled = !disabled_gates.include?(TOPOLOGY_SPREAD_MATCH_KEYS)
        # A disabled feature retains requests for a field already in use.
        drop_keys = !keys_enabled && Array(dig_path(old, path)).none? { |entry| !Array(fetch(entry, "matchLabelKeys")).empty? }
        merge = keys_enabled && old.nil? && kind == "Pod" && !disabled_gates.include?(TOPOLOGY_SPREAD_SELECTOR_MERGE)
        return root unless drop_keys || merge

        labels = fetch(fetch(root, "metadata"), "labels")
        revised = constraints.map do |entry|
          next entry unless entry.is_a?(Hash)
          next entry.except("matchLabelKeys") if drop_keys

          merge_topology_spread_keys(entry, labels)
        end
        return root if revised == constraints

        copy = deep_copy_value(root)
        dig_path(copy, path[0...-1])[path.last] = revised
        copy
      end

      def merge_topology_spread_keys(entry, labels)
        selector = fetch(entry, "labelSelector")
        return entry unless selector.is_a?(Hash) && labels.is_a?(Hash)

        additions = Array(fetch(entry, "matchLabelKeys")).filter_map do |key|
          {"key" => key, "operator" => "In", "values" => [labels[key]]} if labels.key?(key)
        end
        return entry if additions.empty?

        entry.merge("labelSelector" => selector.merge("matchExpressions" => Array(fetch(selector, "matchExpressions")) + additions))
      end

      def topology_spread_errors(root, old, kind, declarative_options)
        path = topology_spread_path(kind)
        return [] unless path

        constraints = Array(dig_path(root, path))
        return [] if constraints.empty?

        disabled_gates = TOPOLOGY_SPREAD_GATES.select { |gate| declarative_options.include?("#{gate}=false") }
        previous = Array(dig_path(old, path))
        preferred = topology_spread_preferred_keys?(previous, disabled_gates)
        validate_selectors = previous.none? { |entry| !label_selector_errors(fetch(entry, "labelSelector"), [], wire_values: true).empty? }
        remaining = constraints.grep(Hash).map { |entry| topology_spread_identity(entry) }.tally
        constraints.each_with_index.flat_map do |entry, index|
          next [] unless entry.is_a?(Hash)

          tuple = topology_spread_identity(entry)
          remaining[tuple] -= 1
          field = path + [index.to_s]
          issues = topology_spread_scalar_errors(entry, field, tuple, repeated: remaining[tuple].positive?)
          selector = fetch(entry, "labelSelector")
          issues.concat(topology_spread_key_errors(entry, field, preferred))
          issues.concat(label_selector_errors(selector, field + ["labelSelector"], wire_values: true)) if validate_selectors
          issues
        end
      end

      def topology_spread_path(kind)
        template = kind == "Pod" ? [] : POD_TEMPLATE_PATHS[kind]
        template && (template + %w[spec topologySpreadConstraints])
      end

      def topology_spread_identity(entry)
        [fetch(entry, "topologyKey").to_s, fetch(entry, "whenUnsatisfiable").to_s]
      end

      def topology_spread_scalar_errors(entry, field, tuple, repeated:)
        topology_key, action = tuple
        skew = fetch(entry, "maxSkew") || 0
        issues = topology_spread_positive_errors(skew, field + ["maxSkew"])
        issues << issue(field + ["topologyKey"], :required, "can not be empty") if topology_key.empty?
        issues << topology_spread_unsupported(field + ["whenUnsatisfiable"], action, TOPOLOGY_SPREAD_ACTIONS) unless TOPOLOGY_SPREAD_ACTIONS.include?(action)
        if repeated
          issues << ValidationIssue.new(path: field + ["{topologyKey, whenUnsatisfiable}"], code: :duplicate,
                                        value: "{#{topology_key}, #{action}}", message: "", kubernetes_type: "Duplicate value")
        end
        issues.concat(topology_spread_min_domains_errors(entry, field, action))
        %w[nodeAffinityPolicy nodeTaintsPolicy].each do |name|
          policy = fetch(entry, name)
          next if policy.nil? || TOPOLOGY_SPREAD_NODE_POLICIES.include?(policy)

          issues << topology_spread_unsupported(field + [name], policy, TOPOLOGY_SPREAD_NODE_POLICIES)
        end
        issues
      end

      def topology_spread_positive_errors(value, path)
        return [] unless value.is_a?(Integer) && value <= 0

        [valued_issue(path, value, "must be greater than zero")]
      end

      def topology_spread_min_domains_errors(entry, field, action)
        value = fetch(entry, "minDomains")
        return [] if value.nil?

        path = field + ["minDomains"]
        issues = topology_spread_positive_errors(value, path)
        issues << valued_issue(path, value, "can only use minDomains if whenUnsatisfiable=DoNotSchedule, not #{action}") unless action == "DoNotSchedule"
        issues
      end

      def topology_spread_unsupported(field, value, supported)
        ValidationIssue.new(path: field, code: :unsupported, value: value, message: unsupported_detail(supported), kubernetes_type: "Unsupported value")
      end

      def topology_spread_preferred_keys?(previous, disabled_gates)
        return false if disabled_gates.include?(TOPOLOGY_SPREAD_MATCH_KEYS)

        preferred = !disabled_gates.include?(TOPOLOGY_SPREAD_SELECTOR_MERGE)
        previous.any? { |entry| !topology_spread_key_errors(entry, [], preferred).empty? } ? !preferred : preferred
      end

      def topology_spread_key_errors(entry, field, preferred)
        keys = fetch(entry, "matchLabelKeys")
        selector = fetch(entry, "labelSelector")
        if preferred
          preferred_label_key_errors(field, keys, nil, selector)
        else
          legacy_spread_label_key_errors(field + ["matchLabelKeys"], keys, selector)
        end
      end
    end
  end
end
