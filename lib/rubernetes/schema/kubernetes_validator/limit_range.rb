# frozen_string_literal: true

module Rubernetes
  module Schema
    # LimitRange: limit types and the consistency of each resource's
    # min/max/default/defaultRequest (ValidateLimitRange).
    module KubernetesValidator
      module_function

      LIMIT_BOUND_SECTIONS = %w[min max default defaultRequest].freeze

      def limit_range_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        limits = fetch(spec, "limits")
        return [] unless limits.is_a?(Array)

        standard = %w[Pod Container PersistentVolumeClaim]
        limits.each_with_index.filter_map do |limit, index|
          next unless limit.is_a?(Hash)

          type = fetch(limit, "type")
          qualified = type.is_a?(String) && type.match?(%r{\A[a-z0-9]([-a-z0-9]*[a-z0-9])?/[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?\z})
          next if standard.include?(type.to_s) || qualified

          issue(["spec", "limits", index.to_s, "type"], :invalid,
                "must be a standard limit type or fully qualified")
        end.concat(limit_range_consistency_errors(root))
      end

      # ValidateLimitRange (validation.go:7636-7720): a type appears once and
      # the min/max/default/defaultRequest of one resource must be internally
      # consistent.  None of it was checked, so a LimitRange could be stored
      # that rejects every Pod it defaults -- min above max, or a default
      # outside its own bounds.
      def limit_range_consistency_errors(root)
        limits = fetch(fetch(root, "spec"), "limits")
        return [] unless limits.is_a?(Array)
        # A bound section that is not a map cannot be compared at all, and
        # then nothing is reported for the whole LimitRange: the structural
        # validator already names the mistyped field.
        return [] unless limits.all? { |limit| !limit.is_a?(Hash) || limit_bounds_readable?(limit) }

        issues = []
        seen_types = {}
        limits.each_with_index do |limit, index|
          next unless limit.is_a?(Hash)

          path = ["spec", "limits", index.to_s]
          type = fetch(limit, "type").to_s
          if seen_types.key?(type)
            issues << issue(path + ["type"], :duplicate, type)
          else
            seen_types[type] = true
          end
          if type == "Pod" && fetch(limit, "default").is_a?(Hash) && !fetch(limit, "default").empty?
            issues << issue(path + ["default"], :forbidden, "may not be specified when `type` is 'Pod'")
          end
          limit_bound_errors(limit, path, issues)
          limit_ratio_errors(limit, path, issues)
        end
        issues
      end

      def limit_bounds_readable?(limit)
        LIMIT_BOUND_SECTIONS.all? do |section|
          value = fetch(limit, section)
          !value || value.is_a?(Hash)
        end
      end

      # The four bounds of each resource, compared pairwise.  A bound that is
      # absent or not a quantity takes part in no comparison.
      def limit_bound_errors(limit, path, issues)
        min, max, default, default_request = LIMIT_BOUND_SECTIONS.map { |section| fetch(limit, section) || {} }
        (min.keys | max.keys | default.keys | default_request.keys).each do |resource|
          minimum = limit_bound(min, resource)
          maximum = limit_bound(max, resource)
          default_limit = limit_bound(default, resource)
          default_req = limit_bound(default_request, resource)
          if minimum && maximum && minimum > maximum
            issues << issue(path + ["min", resource], :invalid,
                            "min value #{min[resource]} is greater than max value #{max[resource]}")
          end
          if minimum && default_limit && minimum > default_limit
            issues << issue(path + ["default", resource], :invalid,
                            "min value #{min[resource]} is greater than default value #{default[resource]}")
          end
          if maximum && default_limit && default_limit > maximum
            issues << issue(path + ["default", resource], :invalid,
                            "default value #{default[resource]} is greater than max value #{max[resource]}")
          end
          if minimum && default_req && minimum > default_req
            issues << issue(path + ["defaultRequest", resource], :invalid,
                            "min value #{min[resource]} is greater than default request value #{default_request[resource]}")
          end
          if maximum && default_req && default_req > maximum
            issues << issue(path + ["defaultRequest", resource], :invalid,
                            "default request value #{default_request[resource]} is greater than max value #{max[resource]}")
          end
          if default_limit && default_req && default_req > default_limit
            issues << issue(path + ["defaultRequest", resource], :invalid,
                            "default request value #{default_request[resource]} is greater than default limit value #{default[resource]}")
          end
        end
      end

      def limit_ratio_errors(limit, path, issues)
        ratios = fetch(limit, "maxLimitRequestRatio") || {}
        return unless ratios.is_a?(Hash)

        ratios.each do |resource, value|
          ratio = limit_quantity(value)
          next if ratio.nil?

          issues << issue(path + ["maxLimitRequestRatio", resource], :invalid, "ratio #{value} is less than 1") if ratio < 1
        end
      end

      def limit_bound(section, resource)
        section.key?(resource) ? limit_quantity(section[resource]) : nil
      end

      # The value of a quantity, or nil for text that is not one (every
      # Quantity parse failure is an ArgumentError).
      def limit_quantity(value)
        Quantity.parse(value.to_s).value
      rescue ArgumentError
        nil
      end

      private_class_method :limit_bounds_readable?, :limit_bound_errors, :limit_ratio_errors, :limit_bound, :limit_quantity
    end
  end
end
