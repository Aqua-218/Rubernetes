# frozen_string_literal: true

require_relative "apply_failures"
require_relative "support"

module Rubernetes
  module Controller
    # ReplicaSet and ReplicationController both use calculateStatus after
    # managing their Pods. Keep the first failure and its transition time
    # until replica management succeeds or the observed count reaches target.
    module ReplicaFailureStatus
      private

      def apply_replica_failure_condition(status, resource, diff, now: Time.now.utc)
        conditions = Array(Support.value(status, "conditions", []))
        index = conditions.index { |condition| Support.value(condition, "type", "").to_s == "ReplicaFailure" }
        key = [Support.namespace(resource), Support.name(resource)].compact.join("/")
        failure = ApplyFailures[name, key] unless diff.zero?
        if failure.to_s.empty?
          if index
            remaining = conditions.dup
            remaining.delete_at(index)
            remaining.empty? ? status.delete("conditions") : status["conditions"] = remaining
          end
          return false
        end
        return true if index

        reason = diff.negative? ? "FailedCreate" : "FailedDelete"
        status["conditions"] = conditions + [{"type" => "ReplicaFailure", "status" => "True", "reason" => reason,
                                              "message" => failure.to_s, "lastTransitionTime" => now.utc.iso8601(0)}]
        true
      end
    end
  end
end
