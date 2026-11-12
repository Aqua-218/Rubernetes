# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # The startup barrier: the lifecycle reconciles its durable records with
      # the runtime before the node registers, and a recovery that is not
      # clean keeps the node NotReady.
      module Recovery
        def recover(observer: nil, cleaner: nil, force: false)
          report = Helpers.string_keys(@lifecycle.recover(observer: observer, cleaner: cleaner, force: force))
          errors = recovery_errors(report)
          blocked = Array(report["blocked"]).map(&:to_s)
          unless errors.empty? && report.fetch("ready", true) == true
            reason = (errors + blocked.map { |uid| "Pod #{uid} recovery is pending" }).join("; ")
            set_ready(false, reason: "RecoveryRequired", message: reason, persist: false)
            raise Runtime::RecoveryRequired, reason
          end
          report_pending_recoveries(blocked, report["pod_errors"])
          @mutex.synchronize do
            @recovery_report = Helpers.deep_copy(report).freeze
            @recovered = true
            @ready = false
          end
          Helpers.deep_copy(report)
        rescue StandardError => error
          @mutex.synchronize do
            @recovered = false
            @recovery_report = {"ready" => false, "errors" => [error.message], "blocked" => []}.freeze
            @ready = false
          end
          raise
        end

        private

        def ensure_recovered!
          return if @mutex.synchronize { @recovered }

          perform_recovery!
        end

        def perform_recovery!
          return @recovery_report if @mutex.synchronize { @recovered }

          recover
        end

        # What keeps the node down: the report's own errors, resources whose
        # identity no longer matches, and orphans nobody cleaned.
        def recovery_errors(report)
          errors = Array(report["errors"]).map(&:to_s)
          errors.concat(Array(report["identity_mismatch"]).map do |entry|
            "resource identity mismatch: #{recovery_resource_key(entry)}"
          end)
          cleaned_orphans = Array(report["cleaned_orphans"]).map(&:to_s)
          unresolved_orphans = Array(report["orphans"]).filter_map do |entry|
            key = recovery_resource_key(entry)
            key unless cleaned_orphans.include?(key)
          end
          # HandlePodCleanups: runtime Pods no worker knew of (orphaned).
          orphaned = Array(report["orphans"]).length
          @kubelet_metrics&.orphaned_runtime_pod(orphaned) if orphaned.positive?
          errors.concat(unresolved_orphans.map { |key| "unresolved orphan resource: #{key}" })
        end

        # A Pod whose cleanup is still pending is reported and retried by the
        # lifecycle (retry_pending_cleanups); it does not keep the node down.
        def report_pending_recoveries(blocked, pod_errors)
          pod_errors = {} unless pod_errors.is_a?(Hash)
          blocked.each do |uid|
            detail = Array(pod_errors[uid]).join("; ")
            @error_handler&.call(Runtime::RecoveryRequired.new("Pod #{uid} recovery is pending#{": #{detail}" unless detail.empty?}"),
                                 :pod_recovery_pending, uid)
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
