# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Startup recovery: reconciles the runtime's durable state with the
      # node's records before the sync loop accepts a Pod.
      module Recovery
        # Reconcile durable runtime and Node lifecycle state before the sync loop
        # can accept a Pod. A pending/unknown record is never treated as a fresh
        # start: it is stopped and cleaned only after the runtime has completed
        # its own identity-based observation. Failed cleanup keeps the original
        # ownership record and leaves the agent unready for a later retry.
        def recover(observer: nil, cleaner: nil, force: false)
          @mutex.synchronize do
            return Helpers.deep_copy(@recovery_report) if @recovery_done && !force
          end

          runtime_report = recover_runtime(observer: observer, cleaner: cleaner)
          runtime_hash = normalize_recovery_report(runtime_report)
          errors = runtime_recovery_errors(runtime_hash)
          recovered, blocked, pod_errors = recover_pending_records(runtime_hash)
          report = {
            "runtime" => runtime_hash,
            "recovered" => recovered.uniq,
            "blocked" => blocked.uniq,
            "errors" => errors.uniq,
            "pod_errors" => pod_errors,
            "ready" => errors.empty?
          }
          # kubelet_orphan_pod_cleaned_volumes: the Pods this sweep tore down
          # (their volumes with them) and the ones it could not.
          metrics_call(:orphan_pod_volumes, recovered.uniq.length, blocked.uniq.length)
          @mutex.synchronize do
            @recovery_report = Helpers.deep_copy(report).freeze
            @recovery_done = true
          end
          persist_state!
          Helpers.deep_copy(report)
        rescue StandardError
          @mutex.synchronize { @recovery_done = false }
          raise
        end

        private

        # What keeps the node from coming up: the runtime's own errors,
        # resources whose identity no longer matches, and orphans it could
        # not clean.
        def runtime_recovery_errors(runtime_hash)
          errors = Array(runtime_hash["errors"]).map(&:to_s)
          errors.concat(Array(runtime_hash["identity_mismatch"]).map do |entry|
            "resource identity mismatch: #{recovery_resource_key(entry)}"
          end)
          cleaned_orphans = Array(runtime_hash["cleaned_orphans"]).map(&:to_s)
          unresolved_orphans = Array(runtime_hash["orphans"]).filter_map do |entry|
            key = recovery_resource_key(entry)
            key unless cleaned_orphans.include?(key)
          end
          errors.concat(unresolved_orphans.map { |key| "unresolved orphan resource: #{key}" })
        end

        # Terminates every record a crash left half way.  Answers the uids
        # recovered, the uids blocked, and the blocked Pods' errors.
        #
        # One Pod's leftover is that Pod's problem (kubelet never refuses to
        # start over one): its cleanup errors are reported per Pod, the
        # record stays CleanupPending for the periodic retry, and the node
        # comes up.  Only runtime-level errors keep the node down.
        def recover_pending_records(runtime_hash)
          recovered = []
          blocked = []
          pod_errors = {}
          pending_records.each do |record|
            uid = record.fetch(:uid)
            if record.fetch(:state) == "StateUnknown" && !recovery_record_observed?(record, runtime_hash)
              blocked << uid
              next
            end

            begin
              result = terminate(record[:pod], request_id: record[:request_id], reason: "StartupRecovery")
              if result && result.state == "Removed"
                recovered << uid
              else
                blocked << uid
                pod_errors[uid] = Array(result&.cleanup_errors).map(&:to_s)
              end
            rescue StandardError => error
              blocked << uid
              pod_errors[uid] = ["Pod #{uid} recovery failed: #{Helpers.failure_message(error)}"]
            end
          end
          [recovered, blocked, pod_errors]
        end

        def pending_records
          @mutex.synchronize do
            @records.values.select { |record| %w[RollingBack CleanupPending StateUnknown].include?(record[:state]) }
          end
        end

        def recover_runtime(observer:, cleaner:)
          return {"status" => "NOT_APPLICABLE", "errors" => []} unless runtime_supports?(:recover)

          observer ||= @recovery_observer
          cleaner ||= @recovery_cleaner
          callable = @runtime.method(:recover)
          options = {observer: observer, cleaner: cleaner}
          if callable.parameters.any? { |kind, _| kind == :keyrest }
            value = callable.call(**options.compact)
          else
            accepted = callable.parameters.filter_map { |kind, name| name if %i[key keyreq].include?(kind) }
            value = callable.call(**options.select { |key, _| accepted.include?(key) })
          end
          normalize_recovery_report(value)
        rescue ArgumentError => error
          raise unless error.message.include?("wrong number") || error.message.include?("unknown keyword")

          normalize_recovery_report(@runtime.recover)
        end

        def normalize_recovery_report(value)
          hash = if hash_convertible?(value)
                   value.to_h
                 elsif value.is_a?(Hash)
                   value
                 elsif value == true
                   {"status" => "PASS", "errors" => []}
                 elsif value == false
                   {"status" => "INCOMPLETE", "errors" => ["runtime recovery returned false"]}
                 elsif value.nil?
                   {"status" => "INCOMPLETE", "errors" => ["runtime recovery returned no report"]}
                 else
                   {"status" => "INCOMPLETE", "value" => value, "errors" => ["runtime recovery returned an invalid report"]}
                 end
          Helpers.string_keys(hash || {})
        end

        def recovery_record_observed?(record, runtime_report)
          # An inventory the runtime cannot produce proves nothing: the record
          # stays blocked.
          best_effort(false) { resources_observed?(record, runtime_report) }
        end

        def resources_observed?(record, runtime_report)
          return true unless record.fetch(:state) == "StateUnknown"
          return true if runtime_report["state_unknown_observed"] == true
          return false unless runtime_supports?(:resource_inventory)

          observed = Array(@runtime.resource_inventory)
          owned = Array(record[:resources]).filter_map do |resource|
            resource = Helpers.string_keys(resource)
            [resource["kind"].to_s, resource["id"].to_s, resource["identity"].to_s]
          end
          return false if owned.empty?

          owned.all? do |kind, id, identity|
            observed.any? do |entry|
              value = Helpers.string_keys(hash_convertible?(entry) ? entry.to_h : entry)
              value["kind"].to_s == kind && value["id"].to_s == id && value["identity"].to_s == identity
            end
          end
        end

        def recovery_resource_key(entry)
          return entry.to_s unless entry.is_a?(Hash)

          kind = entry["kind"] || entry[:kind]
          id = entry["id"] || entry[:id]
          return entry.to_s if kind.nil? || id.nil?

          "#{kind}:#{id}"
        end
      end
    end
  end
end
