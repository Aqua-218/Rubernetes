# frozen_string_literal: true

module Rubernetes
  module Schema
    # pkg/apis/core/validation (v1.36.2) ValidateMatchLabelKeysAndMismatchLabelKeys
    # and ValidateMatchLabelKeysInTopologySpread, for Pods and pod templates.
    # With MatchLabelKeysInPodAffinity and MatchLabelKeysInPodTopologySpread-
    # SelectorMerge (on) the API server merges the keys into the selectors
    # when a Pod is created (API::Server#merge_label_keys!, before
    # validation, as the strategy's PrepareForCreate does), and a key named
    # both in matchLabelKeys and in the selector is reported once the merged
    # requirement meets the user's own.  A topology spread constraint of an
    # updated Pod whose old spec only passes the legacy rule keeps the legacy
    # rule (OldPodViolatesMatchLabelKeysValidation).
    module KubernetesValidator
      module_function

      POD_TEMPLATE_PATHS = {
        "Deployment" => %w[spec template], "ReplicaSet" => %w[spec template], "StatefulSet" => %w[spec template],
        "DaemonSet" => %w[spec template], "Job" => %w[spec template], "ReplicationController" => %w[spec template],
        "PodTemplate" => %w[template], "CronJob" => %w[spec jobTemplate spec template]
      }.freeze

      def label_keys_errors(root, kind, operation, old)
        base = if kind == "Pod"
                 []
               elsif (template = POD_TEMPLATE_PATHS[kind])
                 template
               end
        return [] if base.nil?

        spec = dig_path(root, base + ["spec"])
        return [] unless spec.is_a?(Hash)

        old_spec = old && operation == :update ? dig_path(old, base + ["spec"]) : nil
        old_violates = old_spec.is_a?(Hash) && Array(fetch(old_spec, "topologySpreadConstraints")).any? do |constraint|
          constraint.is_a?(Hash) && !preferred_label_key_errors([], fetch(constraint, "matchLabelKeys"), nil,
                                                                fetch(constraint, "labelSelector")).empty?
        end
        path = base + ["spec"]
        issues = []
        affinity = fetch(spec, "affinity")
        if affinity.is_a?(Hash)
          %w[podAffinity podAntiAffinity].each do |section|
            terms = fetch(affinity, section)
            next unless terms.is_a?(Hash)

            Array(fetch(terms, "requiredDuringSchedulingIgnoredDuringExecution")).each_with_index do |term, index|
              next unless term.is_a?(Hash)

              issues.concat(preferred_label_key_errors(path + ["affinity", section, "requiredDuringSchedulingIgnoredDuringExecution", index.to_s],
                                                       fetch(term, "matchLabelKeys"), fetch(term, "mismatchLabelKeys"), fetch(term, "labelSelector")))
            end
            Array(fetch(terms, "preferredDuringSchedulingIgnoredDuringExecution")).each_with_index do |weighted, index|
              term = weighted.is_a?(Hash) ? fetch(weighted, "podAffinityTerm") : nil
              next unless term.is_a?(Hash)

              issues.concat(preferred_label_key_errors(path + ["affinity", section, "preferredDuringSchedulingIgnoredDuringExecution", index.to_s, "podAffinityTerm"],
                                                       fetch(term, "matchLabelKeys"), fetch(term, "mismatchLabelKeys"), fetch(term, "labelSelector")))
            end
          end
        end
        Array(fetch(spec, "topologySpreadConstraints")).each_with_index do |constraint, index|
          next unless constraint.is_a?(Hash)

          constraint_path = path + ["topologySpreadConstraints", index.to_s]
          keys = fetch(constraint, "matchLabelKeys")
          selector = fetch(constraint, "labelSelector")
          issues.concat(old_violates ? legacy_spread_label_key_errors(constraint_path + ["matchLabelKeys"], keys,
                                                                      selector) : preferred_label_key_errors(constraint_path, keys, nil,
                                                                                                             selector))
        end
        issues
      end

      # ValidateMatchLabelKeysAndMismatchLabelKeys.
      def preferred_label_key_errors(path, match_keys, mismatch_keys, selector)
        match_keys = Array(match_keys).map(&:to_s)
        mismatch_keys = Array(mismatch_keys).map(&:to_s)
        issues = label_key_name_errors(path + ["matchLabelKeys"], match_keys, selector)
        issues.concat(label_key_name_errors(path + ["mismatchLabelKeys"], mismatch_keys, selector))
        if selector.is_a?(Hash)
          positions = {}
          match_keys.each_with_index { |key, index| positions[key] = index }
          seen = (fetch(selector, "matchLabels") || {}).keys.map(&:to_s)
          Array(fetch(selector, "matchExpressions")).each do |expression|
            key = fetch(expression, "key").to_s
            if positions.key?(key) && seen.include?(key)
              issues << valued_issue(path + [positions[key].to_s], key, "exists in both matchLabelKeys and labelSelector")
            end
            seen << key
          end
        end
        match_keys.each_with_index do |key, index|
          next unless mismatch_keys.include?(key)

          issues << valued_issue(path + ["matchLabelKeys", index.to_s], key, "exists in both matchLabelKeys and mismatchLabelKeys")
        end
        issues
      end

      # ValidateMatchLabelKeysInTopologySpread (the legacy rule).
      def legacy_spread_label_key_errors(path, match_keys, selector)
        match_keys = Array(match_keys).map(&:to_s)
        return [] if match_keys.empty?

        issues = []
        keys = []
        if selector.is_a?(Hash)
          keys.concat((fetch(selector, "matchLabels") || {}).keys.map(&:to_s))
          keys.concat(Array(fetch(selector, "matchExpressions")).map { |expression| fetch(expression, "key").to_s })
        else
          issues << issue(path, :forbidden, "must not be specified when labelSelector is not set")
        end
        match_keys.each_with_index do |key, index|
          qualified_name_messages(key).each { |message| issues << valued_issue(path + [index.to_s], key, message) }
          issues << valued_issue(path + [index.to_s], key, "exists in both matchLabelKeys and labelSelector") if keys.include?(key)
        end
        issues
      end

      # validateLabelKeys.
      def label_key_name_errors(path, keys, selector)
        return [] if keys.empty?
        return [issue(path, :forbidden, "must not be specified when labelSelector is not set")] unless selector.is_a?(Hash)

        keys.each_with_index.flat_map do |key, index|
          qualified_name_messages(key).map { |message| valued_issue(path + [index.to_s], key, message) }
        end
      end

      def dig_path(object, path)
        path.reduce(object) { |current, key| current.is_a?(Hash) ? fetch(current, key) : nil }
      end
    end
  end
end
