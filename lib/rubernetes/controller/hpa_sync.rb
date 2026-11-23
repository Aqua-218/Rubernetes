# frozen_string_literal: true

module Rubernetes
  module Controller
    # The upstream HPA queue uses a fixed per-object interval for additions,
    # updates and subsequent checks. The shared manager queue can receive the
    # same key from status writes and from unrelated controllers.
    module HPASync
      INTERVAL = 15.0

      private

      def initialize_hpa_sync
        return unless name == "horizontal-pod-autoscaler-controller"

        @hpa_sync_mutex = Mutex.new
        @hpa_sync_deadlines = {}
      end

      def delayed_hpa_plan(resource)
        return unless @hpa_sync_mutex

        key = "#{Support.namespace(resource)}/#{Support.name(resource)}"
        delay = hpa_sync_delay(key, Support.uid(resource))
        ReconcileResult.new(controller: name, key: key, requeue_after: delay) if delay
      end

      def hpa_sync_delay(key, uid)
        now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @hpa_sync_mutex.synchronize do
          prior_uid, deadline = @hpa_sync_deadlines[key]
          if deadline.nil? || prior_uid != uid
            @hpa_sync_deadlines[key] = [uid, now + INTERVAL]
            return INTERVAL
          end
          return deadline - now if deadline > now

          @hpa_sync_deadlines[key] = [uid, now + INTERVAL]
          nil
        end
      end

      def forget_hpa_sync(key)
        @hpa_sync_mutex&.synchronize { @hpa_sync_deadlines.delete(key.to_s) }
      end
    end
  end
end
