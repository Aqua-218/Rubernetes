# frozen_string_literal: true

module Rubernetes
  module Controller
    # Evicts Pods after NoExecute tolerations expire. NodeController publishes
    # Node.spec.taints; this controller owns only the eviction side.
    class TaintEvictionController < BaseController
      include InfrastructureStorageSupport

      # float64(time.Since(fireAt) * time.Second): upstream multiplies the
      # nanosecond Duration by another 1e9 (wrapping as int64), and that is
      # what the histogram holds.
      def self.go_duration_times_second(seconds)
        value = (seconds * 1_000_000_000).to_i * 1_000_000_000
        value = ((value + (2**63)) % (2**64)) - (2**63)
        value.to_f
      end

      NODE = ResourceDescriptor.parse("Node")
      POD = ResourceDescriptor.parse("Pod")

      def initialize(clock: nil, **)
        @clock = clock || -> { Time.now.utc }
        # When a taint carries no timeAdded (kubectl taint sets none), the
        # toleration clock starts when this controller first saw the taint,
        # as upstream's taint manager does.  Falling back to the Node's Ready
        # transition started it long ago, so every tolerationSeconds had
        # already elapsed and each tolerating Pod was evicted at once.
        @taint_first_seen = {}
        @taint_mutex = Mutex.new
        super(**)
      end

      def plan(node, store: nil, pods: nil, now: nil, **_options)
        adapter = adapter_for_storage(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        timestamp = normalize_time(now || @clock.call)
        taints = eviction_taints(node)
        remember_taints(node, taints, timestamp)
        operations = []
        events = []
        next_deadline = nil
        Array(pods).select { |pod| pod_on_node?(pod, node) }.each do |pod|
          due_taint = taints.find { |taint| eviction_due?(pod, taint, timestamp, node) }
          unless due_taint
            deadline = taints.filter_map { |taint| eviction_deadline(pod, taint, node) }.min
            next_deadline = [next_deadline, deadline].compact.min if deadline
            next
          end

          # addConditionAndDeletePod, and emitPodDeletionEvent on the Pod;
          # deletePodHandler counts each delete that went through.
          fired = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          deletions = disruption_and_delete(pod, timestamp, reason: "DeletionByTaintManager",
                                                            message: "Taint manager: deleting due to NoExecute taint")
          observed = deletions.map do |operation|
            next operation unless operation.delete?

            operation.observed do |succeeded, _|
              next unless succeeded

              ControllerMetrics.increment("taint_eviction_controller_pod_deletions_total")
              ControllerMetrics.observe("taint_eviction_controller_pod_deletion_duration_seconds",
                                        self.class.go_duration_times_second(Process.clock_gettime(Process::CLOCK_MONOTONIC) - fired))
            end
          end
          operations.concat(observed)
          events << {"type" => "Normal", "reason" => "TaintManagerEviction",
                     "message" => "Marking for deletion Pod #{name_key(pod)}", "involvedObject" => pod_reference(pod)}
        end
        # Upstream's taint manager fires each eviction from a timer at its
        # deadline.  Returning nothing made the eviction wait for whatever
        # next happened to touch the Node.
        requeue_after = next_deadline && [next_deadline - timestamp, 0.5].max
        ReconcileResult.new(operations: operations, status: Support.status(node), events: events,
                            controller: name, key: Support.name(node), requeue_after: requeue_after)
      end

      private

      # apipod.UpdatePodCondition on a copy of the status (lastTransitionTime
      # kept when the status is unchanged), patched only when it changed.
      def disruption_and_delete(pod, now, reason:, message:, uid_precondition: false)
        operations = []
        status = Support.deep_copy(Support.status(pod))
        conditions = Array(status["conditions"]).map { |entry| Support.deep_copy(entry) }
        wanted = {"type" => "DisruptionTarget", "status" => "True", "reason" => reason, "message" => message}
        generation = Support.value(Support.metadata(pod), "generation", nil)
        wanted["observedGeneration"] = generation unless generation.nil?
        stamp = now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        existing = conditions.find { |entry| entry["type"] == "DisruptionTarget" }
        changed = if existing.nil?
                    conditions << wanted.merge("lastProbeTime" => nil, "lastTransitionTime" => stamp)
                    true
                  elsif wanted.any? { |key, value| existing[key] != value }
                    existing["lastTransitionTime"] = stamp if existing["status"] != "True"
                    existing.merge!(wanted)
                    true
                  else
                    false
                  end
        if changed
          status["conditions"] = conditions
          operations << operation_status(pod, status, descriptor: POD, reason: "taint eviction DisruptionTarget", force: true)
        end
        options = nil
        uid = Support.uid(pod).to_s
        options = {"preconditions" => {"uid" => uid}} if uid_precondition && !uid.empty?
        operations << operation_delete(pod, descriptor: POD, reason: "taint eviction", options: options)
        operations
      end

      def pod_reference(pod)
        {"apiVersion" => "v1", "kind" => "Pod", "namespace" => Support.namespace(pod), "name" => Support.name(pod),
         "uid" => Support.uid(pod)}.compact
      end

      def pod_on_node?(pod, node)
        workload_pod?(pod) && Support.value(Support.spec(pod), "nodeName", "").to_s == Support.name(node)
      end

      def eviction_taints(node)
        Array(Support.value(Support.spec(node), "taints", [])).filter_map do |taint|
          copy = Support.deep_copy(taint)
          copy if Support.value(copy, "effect", "").to_s == "NoExecute"
        end
      end

      def taint_key(taint)
        key = Support.value(taint, "key", "").to_s
        value = Support.value(taint, "value", nil)
        value.to_s.empty? ? key : "#{key}=#{value}"
      end

      def eviction_due?(pod, taint, now, node = nil)
        toleration_expired?(matching_tolerations(pod, taint), taint_added_at(taint, node), now)
      end

      # When a tolerating Pod's eviction falls due, or nil if it never does.
      def eviction_deadline(pod, taint, node)
        matching = matching_tolerations(pod, taint)
        return nil if matching.empty? || tolerated_forever?(matching)

        seconds = longest_toleration_seconds(matching)
        added_at = taint_added_at(taint, node)
        seconds && added_at ? added_at + seconds : nil
      end

      # Whether the tolerations +matching+ a taint that took effect at
      # +added_at+ have run out by +now+.  No toleration at all is no grace;
      # one without tolerationSeconds tolerates the taint for good.
      def toleration_expired?(matching, added_at, now)
        return true if matching.empty?
        return false if tolerated_forever?(matching)

        seconds = longest_toleration_seconds(matching)
        return false unless seconds
        return seconds.zero? unless added_at

        now >= added_at + seconds
      end

      def tolerated_forever?(matching)
        matching.any? { |toleration| Support.value(toleration, "tolerationSeconds", nil).nil? }
      end

      def longest_toleration_seconds(matching)
        matching.filter_map do |toleration|
          parsed = Support.integer(Support.value(toleration, "tolerationSeconds", nil), -1)
          parsed if parsed >= 0
        end.max
      end

      def taint_added_at(taint, node = nil)
        Support.parse_time(Support.value(taint, "timeAdded", nil)) ||
          Support.parse_time(Support.value(taint, "addedAt", nil)) ||
          Support.parse_time(Support.value(taint, "lastTransitionTime", nil)) ||
          first_seen(node, taint)
      end

      def taint_identity(node, taint)
        [Support.name(node || {}).to_s, Support.value(taint, "key", "").to_s,
         Support.value(taint, "value", "").to_s, Support.value(taint, "effect", "").to_s]
      end

      def first_seen(node, taint)
        @taint_mutex.synchronize { @taint_first_seen[taint_identity(node, taint)] }
      end

      # Record when each of this Node's NoExecute taints was first observed,
      # and forget the ones that are gone so a re-added taint starts afresh.
      def remember_taints(node, taints, now)
        name = Support.name(node).to_s
        current = taints.map { |taint| taint_identity(node, taint) }
        @taint_mutex.synchronize do
          @taint_first_seen.delete_if { |identity, _| identity.first == name && !current.include?(identity) }
          current.each { |identity| @taint_first_seen[identity] ||= now }
        end
      end

      def matching_tolerations(pod, taint)
        Array(Support.value(Support.spec(pod), "tolerations", [])).select do |toleration|
          toleration_matches?(toleration, taint)
        end
      end

      def toleration_matches?(toleration, taint)
        effect = Support.value(toleration, "effect", "").to_s
        taint_effect = Support.value(taint, "effect", "").to_s
        return false unless effect.empty? || effect == taint_effect

        key = Support.value(toleration, "key", "").to_s
        taint_key_value = Support.value(taint, "key", "").to_s
        operator = Support.value(toleration, "operator", "Equal").to_s
        return true if operator == "Exists" && (key.empty? || key == taint_key_value)

        return false unless operator == "Equal" && key == taint_key_value

        Support.value(toleration, "value", "").to_s == Support.value(taint, "value", "").to_s
      end
    end

    # DRA device taints are sourced separately from ordinary Node taints while
    # retaining the NoExecute toleration timing contract.
    class DeviceTaintEvictionController < TaintEvictionController
      DEVICE_TAINT_PREFIXES = %w[resource.kubernetes.io/ device.kubernetes.io/ dra.kubernetes.io/].freeze

      def plan(node, store: nil, pods: nil, device_taints: nil, now: nil, **_options)
        adapter = adapter_for_storage(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        timestamp = normalize_time(now || @clock.call)
        taints = Array(device_taints || discovered_device_taints(node)).select do |taint|
          Support.value(taint, "effect", "").to_s == "NoExecute"
        end
        remember_taints(node, taints, timestamp)
        operations = []
        events = []
        Array(pods).select { |pod| pod_on_device_node?(pod, node) }.each do |pod|
          due_taint = taints.find { |taint| device_eviction_due?(pod, taint, timestamp, node) }
          next unless due_taint

          # deletePod: the condition, then a delete with a UID precondition;
          # a delete that went through is counted with the time since the
          # taint's effect became active (a Pod already gone is not).
          effective = device_eviction_time(pod, due_taint, node) || timestamp
          deletions = disruption_and_delete(pod, timestamp, reason: "DeletionByDeviceTaintManager",
                                                            message: "Device Taint manager: deleting due to NoExecute taint", uid_precondition: true)
          observed = deletions.map do |operation|
            next operation unless operation.delete?

            operation.observed do |succeeded, _|
              next unless succeeded

              ControllerMetrics.increment("device_taint_eviction_controller_pod_deletions_total")
              ControllerMetrics.observe("device_taint_eviction_controller_pod_deletion_duration_seconds",
                                        [normalize_time(@clock.call) - effective, 0.0].max)
            end
          end
          operations.concat(observed)
          events << {"type" => "Normal", "reason" => "DeviceTaintManagerEviction", "message" => "Marking for deletion",
                     "involvedObject" => pod_reference(pod)}
        end
        ReconcileResult.new(operations: operations, status: Support.status(node), events: events,
                            controller: name, key: Support.name(node))
      end

      private

      def discovered_device_taints(node)
        status = Support.status(node)
        spec = Support.spec(node)
        candidates = Array(Support.value(status, "deviceTaints", nil))
        candidates += Array(Support.value(spec, "deviceTaints", nil))
        candidates += Array(Support.value(spec, "resourceTaints", nil))
        candidates += Array(Support.value(spec, "taints", [])).select do |taint|
          DEVICE_TAINT_PREFIXES.any? { |prefix| Support.value(taint, "key", "").to_s.start_with?(prefix) }
        end
        candidates.filter_map { |taint| taint.is_a?(Hash) ? Support.deep_copy(taint) : nil }
      end

      def pod_on_device_node?(pod, node) = pod_on_node?(pod, node)

      # A device taint without timeAdded took effect when the Node last
      # changed readiness.
      def device_taint_added_at(taint, node)
        Support.parse_time(Support.value(taint, "timeAdded", nil)) ||
          Support.parse_time(Support.value(Support.condition(node || {}, "Ready") || {}, "lastTransitionTime", nil))
      end

      # eviction.when: the taint's timeAdded plus the longest matching
      # tolerationSeconds.
      def device_eviction_time(pod, taint, node)
        added_at = device_taint_added_at(taint, node)
        return nil unless added_at

        seconds = matching_tolerations(pod, taint)
          .filter_map { |toleration| Support.integer(Support.value(toleration, "tolerationSeconds", nil), -1) }
          .select(&:positive?).max
        added_at + seconds.to_i
      end

      def device_eviction_due?(pod, taint, now, node = nil)
        toleration_expired?(matching_tolerations(pod, taint), device_taint_added_at(taint, node), now)
      end

      def device_toleration_matches?(toleration, taint) = toleration_matches?(toleration, taint)
    end
  end
end
