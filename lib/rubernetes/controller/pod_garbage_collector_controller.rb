# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # pkg/controller/podgc (v1.36.2), every gcCheckPeriod (20 s):
    # terminated Pods over the threshold (evicted first, then oldest),
    # terminating Pods on a NotReady node tainted out-of-service, Pods bound
    # to a node that is gone (after a 40 s quarantine and a live check;
    # DisruptionTarget DeletionByPodGC), and terminating Pods that were never
    # scheduled.  Each is marked Failed unless already terminal, then force
    # deleted (grace period 0).
    class PodGarbageCollectorController < BaseController
      POD = ResourceDescriptor.parse("Pod")
      NODE = ResourceDescriptor.parse("Node")
      DEFAULT_TERMINATED_POD_GC_THRESHOLD = 12_500
      GC_CHECK_PERIOD = 20.0
      QUARANTINE_TIME = 40.0
      OUT_OF_SERVICE_TAINT = "node.kubernetes.io/out-of-service"

      include SecondarySupport

      def initialize(*, clock: -> { Time.now.utc }, **)
        super(*, **)
        @clock = clock
        @missing_nodes = {}
        @mutex = Mutex.new
      end

      def plan(resource = nil, store: nil, pods: nil, nodes: nil, terminated_pod_gc_threshold: nil, threshold: nil,
               delete_orphaned: true, **_options)
        adapter = adapter_for(store)
        pods ||= list_for(adapter, POD, namespace: :all)
        nodes ||= list_for(adapter, NODE, namespace: :all)
        threshold = terminated_pod_gc_threshold if threshold.nil?
        threshold = DEFAULT_TERMINATED_POD_GC_THRESHOLD if threshold.nil?
        threshold = Integer(threshold)
        raise ArgumentError, "terminated pod GC threshold must be non-negative" if threshold.negative?

        operations = []
        handled = {}
        collect = lambda do |pod, reason, condition = nil|
          next if handled[Support.uid(pod).to_s]

          handled[Support.uid(pod).to_s] = true
          operations.concat(counted(pod, reason, mark_failed_and_delete(pod, condition)))
        end
        pods = Array(pods)
        gc_terminated(pods, threshold).each { |pod| collect.call(pod, "terminated") } if threshold.positive?
        gc_terminating(pods, nodes).each { |pod| collect.call(pod, "out-of-service") }
        if delete_orphaned
          orphans(pods, nodes, adapter).each do |pod|
            collect.call(pod, "orphaned", {"type" => "DisruptionTarget", "status" => "True", "reason" => "DeletionByPodGC",
                                           "message" => "PodGC: node no longer exists"})
          end
        end
        pods.each do |pod|
          next if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?
          next unless Support.value(Support.spec(pod), "nodeName", "").to_s.empty?

          collect.call(pod, "unscheduled")
        end
        ReconcileResult.new(operations: operations, events: [], controller: name, key: resource && object_key_for(resource),
                            requeue_after: GC_CHECK_PERIOD)
      end

      private

      def terminated?(pod) = !%w[Pending Running Unknown].include?(Support.value(Support.status(pod), "phase", "").to_s)

      def evicted?(pod)
        status = Support.status(pod)
        Support.value(status, "phase", "") == "Failed" && Support.value(status, "reason", "") == "Evicted"
      end

      # byEvictionAndCreationTimestamp.
      def sorted(pods)
        pods.sort_by { |pod| [evicted?(pod) ? 0 : 1, Support.creation_time(pod).to_f, Support.name(pod)] }
      end

      def gc_terminated(pods, threshold)
        terminated = pods.select { |pod| terminated?(pod) }
        count = terminated.length - threshold
        count.positive? ? sorted(terminated).first(count) : []
      end

      # gcTerminating: a node that is NotReady and tainted out-of-service.
      def gc_terminating(pods, nodes)
        by_name = Array(nodes).to_h { |node| [Support.name(node), node] }
        candidates = pods.select do |pod|
          next false if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

          node = by_name[Support.value(Support.spec(pod), "nodeName", "").to_s]
          node && !node_ready?(node) &&
            Array(Support.value(Support.spec(node), "taints", [])).any? { |taint| Support.value(taint, "key", "") == OUT_OF_SERVICE_TAINT }
        end
        sorted(candidates)
      end

      def node_ready?(node)
        Array(Support.value(Support.status(node), "conditions", [])).any? do |condition|
          Support.value(condition, "type", "") == "Ready" && Support.value(condition, "status", "") == "True"
        end
      end

      # gcOrphaned with the node quarantine (nodeQueue.AddAfter).
      def orphans(pods, nodes, adapter)
        existing = Array(nodes).to_h { |node| [Support.name(node), true] }
        now = @clock.call
        missing = pods.map do |pod|
          Support.value(Support.spec(pod), "nodeName", "").to_s
        end.reject { |name| name.empty? || existing[name] }.uniq
        deleted = @mutex.synchronize do
          @missing_nodes.delete_if { |name, _| existing[name] }
          missing.each { |name| @missing_nodes[name] ||= now }
          @missing_nodes.select { |name, since| now - since >= QUARANTINE_TIME && missing.include?(name) }.keys
        end
        deleted.reject! { |name| node_exists?(adapter, name) }
        pods.select { |pod| deleted.include?(Support.value(Support.spec(pod), "nodeName", "").to_s) }
      end

      # checkIfNodeExists: the API server, not the cache.
      def node_exists?(adapter, name)
        return false unless adapter.respond_to?(:find_live)

        !adapter.find_live(NODE, name: name).nil?
      rescue StandardError
        true
      end

      # pod_gc_collector_force_delete_pods_total / _errors_total by
      # namespace and reason: one per Pod, and an error when its status write
      # or its delete failed.
      def counted(pod, reason, operations)
        labels = {"namespace" => Support.namespace(pod).to_s, "reason" => reason}
        counted = false
        lock = Mutex.new
        operations.map.with_index do |operation, index|
          last = index == operations.length - 1
          operation.observed do |succeeded, _error|
            first = lock.synchronize do
              next false if counted

              counted = !succeeded || last
            end
            next unless first

            ControllerMetrics.increment("pod_gc_collector_force_delete_pod_errors_total", labels) unless succeeded
            ControllerMetrics.increment("pod_gc_collector_force_delete_pods_total", labels)
          end
        end
      end

      # markFailedAndDeletePodWithCondition.
      def mark_failed_and_delete(pod, condition)
        operations = []
        unless %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
          status = Support.deep_copy(Support.status(pod))
          status["phase"] = "Failed"
          generation = Support.value(Support.metadata(pod), "generation", nil)
          status["observedGeneration"] = generation unless generation.nil?
          if condition
            conditions = Array(status["conditions"]).map { |entry| Support.deep_copy(entry) }
            existing = conditions.find { |entry| entry["type"] == condition["type"] }
            stamp = @clock.call.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            if existing
              existing["lastTransitionTime"] = stamp if existing["status"] != condition["status"]
              existing.merge!(condition)
            else
              conditions << condition.merge("lastProbeTime" => nil, "lastTransitionTime" => stamp)
            end
            status["conditions"] = conditions
          end
          operations << operation_status(pod, status, descriptor: POD, reason: "PodGC marks the Pod failed", force: true)
        end
        operations << operation_delete(pod, descriptor: POD, reason: "PodGC force deletion", options: {"gracePeriodSeconds" => 0})
        operations
      end
    end
  end
end
