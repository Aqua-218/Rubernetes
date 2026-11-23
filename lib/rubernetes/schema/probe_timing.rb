# frozen_string_literal: true

module Rubernetes
  module Schema
    module ProbeTiming
      FIELDS = %w[livenessProbe readinessProbe startupProbe].freeze
      NONNEGATIVE_FIELDS = %w[initialDelaySeconds timeoutSeconds periodSeconds successThreshold failureThreshold].freeze
      INIT_CONTAINER_DETAIL = "may not be set for init containers without restartPolicy=Always"
      Issue = Data.define(:path, :value, :message)

      module_function

      def errors(probe, path)
        return [] unless probe.is_a?(Hash)

        issues = NONNEGATIVE_FIELDS.filter_map do |field|
          value = probe.fetch(field) { probe[field.to_sym] }
          Issue.new(path + [field], value, "must be greater than or equal to 0") if value.is_a?(Integer) && value.negative?
        end
        grace = probe.fetch("terminationGracePeriodSeconds") { probe[:terminationGracePeriodSeconds] }
        grace_path = path + ["terminationGracePeriodSeconds"]
        issues << Issue.new(grace_path, grace, "must be greater than 0") if grace.is_a?(Integer) && grace <= 0
        if path.last == "readinessProbe"
          issues << Issue.new(grace_path, grace, "must not be set for readinessProbes") unless grace.nil?
        elsif %w[livenessProbe startupProbe].include?(path.last)
          # The apiserver defaults a missing or zero success threshold to 1.
          success = probe.fetch("successThreshold") { probe[:successThreshold] }
          issues << Issue.new(path + ["successThreshold"], success, "must be 1") if success.is_a?(Integer) && ![0, 1].include?(success)
        end
        issues
      end
    end
  end
end
