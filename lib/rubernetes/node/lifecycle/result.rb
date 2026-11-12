# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # What a lifecycle operation answers with: the record's state and phase,
      # the published status, the event trail, and what the Pod still owns.
      Result = Data.define(
        :pod_uid, :state, :phase, :status, :events, :resources,
        :error, :cleanup_errors
      ) do
        def success?
          error.nil? && %w[Running Succeeded].include?(phase)
        end

        def failed?
          !error.nil? || phase == "Failed"
        end

        def to_h
          {
            "podUID" => pod_uid,
            "state" => state,
            "phase" => phase,
            "status" => Helpers.deep_copy(status),
            "events" => Helpers.deep_copy(events),
            "resources" => Helpers.deep_copy(resources),
            "error" => error,
            "cleanupErrors" => Helpers.deep_copy(cleanup_errors)
          }
        end
      end
    end
  end
end
