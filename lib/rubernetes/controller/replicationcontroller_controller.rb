# frozen_string_literal: true

require "time"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "apply_failures"
require_relative "pod_deletion_ranking"

module Rubernetes
  module Controller
    # Maintains the Pod population selected by a legacy
    # core/v1 ReplicationController.  Matching orphan Pods are adopted only
    # when they have no competing controller owner; all later changes are
    # restricted to Pods whose controller owner reference matches the RC UID.
    class ReplicationControllerController < BaseController
      REPLICATION_CONTROLLER = ResourceDescriptor.parse("ReplicationController")
      POD = ResourceDescriptor.parse("Pod")
      POD_CAP = 500

      include SecondarySupport


      # PodControllerRefManager canAdoptFunc / RecheckDeletionTimestamp: a
      # controller adopts only after a fresh read shows the same object, not
      # being deleted.  Adopting from the informer cache re-owned the Pods an
      # orphaning delete had just released; the garbage collector then found
      # their owner gone and deleted them ("[sig-api-machinery] Garbage
      # collector should orphan pods created by rc if delete options say so"
      # kept 27 of 100).
      def adoption_allowed?(adapter, controller, descriptor)
        return true unless adapter.respond_to?(:find_live)

        fresh = adapter.find_live(descriptor, name: Support.name(controller), namespace: Support.namespace(controller))
        !fresh.nil? && Support.uid(fresh).to_s == Support.uid(controller).to_s &&
          Support.value(Support.metadata(fresh), "deletionTimestamp", nil).nil?
      rescue StandardError
        false
      end

      def plan(replication_controller, store: nil, pods: nil, **_options)
        adapter = adapter_for(store)
        namespace = Support.namespace(replication_controller)
        pods ||= list_for(adapter, POD, namespace: namespace)
        selector = selector_for(replication_controller)
        owned_pods = Array(pods).select do |pod|
          namespace_matches?(replication_controller, pod) &&
            owner_matches?(replication_controller, pod, controller: true)
        end
        adoptable = Array(pods).select do |pod|
          namespace_matches?(replication_controller, pod) &&
            Support.selector_matches?(selector, pod) &&
            !controller_owner_reference?(pod)
        end
        operations = []
        # ReleasePod: an owned Pod whose labels no longer match the selector
        # loses this controller's owner reference and stops counting.
        released = owned_pods.reject do |pod|
          Support.selector_matches?(selector, pod) || !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?
        end
        owned_pods -= released
        released.each do |pod|
          candidate = Support.deep_copy(pod)
          candidate["metadata"] ||= {}
          candidate["metadata"]["ownerReferences"] = Support.owner_references(pod).map { |reference| Support.deep_copy(reference) }.reject do |reference|
            Support.value(reference, "uid", nil).to_s == Support.uid(replication_controller).to_s
          end
          update = operation_update(pod, candidate, descriptor: POD, reason: "replicationcontroller pod release")
          operations << update if update
        end
        adoptable = [] unless adoptable.empty? || adoption_allowed?(adapter, replication_controller, REPLICATION_CONTROLLER)
        adoptable.each do |pod|
          candidate = ensure_owner_reference(pod, replication_controller)
          update = operation_update(pod, candidate, descriptor: POD, reason: "replicationcontroller pod adoption")
          operations << update if update
        end
        managed = (owned_pods + adoptable).uniq { |pod| [Support.name(pod), Support.uid(pod)] }
        alive = managed.reject { |pod| terminal_pod?(pod) || !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil? }
        desired = replica_count(replication_controller)
        # replica_set.go syncReplicaSet: a controller that is being deleted
        # does not manage its replicas any more.  Recreating the Pods its
        # deletion was removing left them behind once it was gone.
        being_deleted = !Support.value(Support.metadata(replication_controller), "deletionTimestamp", nil).nil?
        if alive.length < desired && !being_deleted
          create_count = [desired - alive.length, POD_CAP].min
          operations.concat(create_pods(replication_controller, managed, create_count, selector))
        elsif alive.length > desired
          operations.concat(delete_pods(alive, alive.length - desired))
        end
        deleted_names = operations.select(&:delete?).map { |operation| Support.name(operation.object) }
        surviving = alive.reject { |pod| deleted_names.include?(Support.name(pod)) }
        status = Support.deep_copy(Support.status(replication_controller))
        # replica_set_utils.go calculateStatus counts the Pods this sync
        # OBSERVED, never the ones it is about to create: creates go out in
        # slow-start batches over later syncs, and a status that already
        # counted them claimed replicas that did not exist yet.  "[sig-api-
        # machinery] Garbage collector should orphan pods created by rc if
        # delete options say so" waits for status.replicas == 100 before
        # deleting the rc, read 100 two seconds in, and found 60 Pods.
        observed_fully_labeled = alive.count { |pod| Support.selector_matches?(selector, pod) }
        status["replicas"] = alive.length
        status["fullyLabeledReplicas"] = observed_fully_labeled
        # replica_set_utils.go calculateStatus also publishes readiness and the
        # generation it acted on.  Without observedGeneration every client that
        # waits for the controller to catch up -- "[sig-apps]
        # ReplicationController should surface a failure condition on a common
        # issue like exceeded quota" polls `generation > status.observedGeneration`
        # before it even looks at the conditions -- waits for ever on a status
        # that is already correct.
        # Everything but `replicas` is omitempty in ReplicationControllerStatus
        # (core/v1 types.go), so a zero is an ABSENT field, not a written one.
        # Writing explicit zeros makes every sync differ from the stored object
        # by exactly the fields it just wrote, and the controller re-writes the
        # status for ever.
        ready = surviving.count { |pod| pod_ready?(pod) }
        available = surviving.count { |pod| pod_available?(pod, min_ready_seconds(replication_controller)) }
        generation = Integer(Support.value(Support.metadata(replication_controller), "generation", 0) || 0)
        # Zero counters are written, not omitted (a status apply that leaves a
        # counter out does not clear the stored value); the perpetual rewrite
        # this comment once warned about is prevented by the store adapter
        # comparing statuses with absent-equals-zero.
        status["readyReplicas"] = ready
        status["availableReplicas"] = available
        generation.zero? ? status.delete("observedGeneration") : status["observedGeneration"] = generation
        apply_replica_failure_condition(status, replication_controller, alive.length - desired)
        events = []
        events << {"type" => "Normal", "reason" => "SuccessfulCreate",
                   "message" => "ReplicationController #{Support.name(replication_controller)} created Pods"} if operations.any?(&:create?)
        events << {"type" => "Normal", "reason" => "SuccessfulDelete",
                   "message" => "ReplicationController #{Support.name(replication_controller)} deleted excess Pods"} if operations.any?(&:delete?)
        observed = result_for(replication_controller, operations, status: status, events: events, status_first: true)
        settle_status_after_changes(replication_controller, observed, operations, status, alive, selector)
      end

      # The status above counts only what this sync OBSERVED, and goes out
      # first so that a ReplicaFailure condition reaches the API even when the
      # create it explains is refused.  Once this sync's creates and deletes
      # have landed, the count they produced is real, so it is written in a
      # final batch -- one that runs only if every change before it
      # succeeded.  A single pass therefore still reaches a fixed point, and
      # the count is never ahead of the Pods that exist.
      def settle_status_after_changes(replication_controller, observed, operations, status, alive, selector)
        creates = operations.select(&:create?)
        deletes = operations.select(&:delete?)
        return observed if creates.empty? && deletes.empty?

        deleted_names = deletes.map { |operation| Support.name(operation.object) }
        remaining = alive.reject { |pod| deleted_names.include?(Support.name(pod)) }
        settled = Support.deep_copy(status)
        settled["replicas"] = remaining.length + creates.length
        fully_labeled = remaining.count { |pod| Support.selector_matches?(selector, pod) } +
                        creates.count { |operation| Support.selector_matches?(selector, operation.object) }
        fully_labeled.zero? ? settled.delete("fullyLabeledReplicas") : settled["fullyLabeledReplicas"] = fully_labeled
        apply_replica_failure_condition(settled, replication_controller, settled["replicas"] - replica_count(replication_controller))
        final = operation_status(replication_controller, settled, descriptor: REPLICATION_CONTROLLER,
                                                                 reason: "controller status after replica changes", force: true)
        batches = Array(observed.batches) + [[final]]
        ReconcileResult.new(operations: observed.operations + [final], batches: batches, status: settled,
                            events: observed.events, controller: observed.controller, key: observed.key)
      end

      def scale(replication_controller, replicas, pods: nil, store: nil)
        candidate = Support.deep_copy(replication_controller)
        candidate["spec"] ||= {}
        candidate["spec"]["replicas"] = Integer(replicas)
        plan(candidate, pods: pods, store: store)
      end

      def delete(replication_controller, pods: nil, store: nil, orphan: false)
        adapter = adapter_for(store)
        pods ||= list_for(adapter, POD, namespace: Support.namespace(replication_controller))
        operations = if orphan
                       []
                     else
                       Array(pods).select { |pod| owner_matches?(replication_controller, pod, controller: true) }
                                .map { |pod| operation_delete(pod, descriptor: POD, reason: "replicationcontroller deletion") }
                     end
        operations << operation_delete(replication_controller, descriptor: REPLICATION_CONTROLLER,
                                       reason: "replicationcontroller deletion")
        ReconcileResult.new(operations: operations, controller: name,
                            key: object_key_for(replication_controller))
      end

      private

      # replica_set_utils.go calculateStatus: the condition is added when the
      # last attempt to reach the desired count failed and is removed as soon
      # as one succeeds.  An existing condition is left alone rather than
      # restamped, so its lastTransitionTime keeps meaning what it says.
      def apply_replica_failure_condition(status, replication_controller, diff)
        conditions = Array(Support.value(status, "conditions", [])).map { |condition| Support.deep_copy(condition) }
        existing = conditions.find { |condition| Support.value(condition, "type", "").to_s == "ReplicaFailure" }
        message = ApplyFailures[name, object_key_for(replication_controller)]
        if message.nil? || message.to_s.empty?
          return if existing.nil?

          status["conditions"] = conditions.reject do |condition|
            Support.value(condition, "type", "").to_s == "ReplicaFailure"
          end
          status.delete("conditions") if status["conditions"].empty?
          return
        end
        return if existing

        reason = if diff.negative?
                   "FailedCreate"
                 elsif diff.positive?
                   "FailedDelete"
                 else
                   ""
                 end
        stamp = Time.now.utc.iso8601(0)
        conditions << {"type" => "ReplicaFailure", "status" => "True", "lastTransitionTime" => stamp,
                       "reason" => reason, "message" => message.to_s}
        status["conditions"] = conditions
      end

      def min_ready_seconds(replication_controller)
        Integer(Support.value(Support.spec(replication_controller), "minReadySeconds", 0) || 0)
      rescue ArgumentError, TypeError
        0
      end

      def pod_ready?(pod)
        Array(Support.value(Support.status(pod), "conditions", [])).any? do |condition|
          Support.value(condition, "type", "").to_s == "Ready" && Support.value(condition, "status", "").to_s == "True"
        end
      end

      # v1/pod/util.go IsPodAvailable: ready, and ready for at least
      # minReadySeconds.
      def pod_available?(pod, min_ready_seconds)
        return false unless pod_ready?(pod)
        return true if min_ready_seconds.zero?

        condition = Array(Support.value(Support.status(pod), "conditions", [])).find do |value|
          Support.value(value, "type", "").to_s == "Ready"
        end
        stamp = Support.value(condition, "lastTransitionTime", nil)
        return false if stamp.nil? || stamp.to_s.empty?

        Time.now.utc - Time.parse(stamp.to_s) >= min_ready_seconds
      rescue ArgumentError, TypeError
        false
      end

      def namespace_matches?(owner, dependent)
        Support.namespace(owner).to_s == Support.namespace(dependent).to_s
      end

      def selector_for(replication_controller)
        selector = Support.value(Support.spec(replication_controller), "selector", nil)
        selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
        selector = Support.labels(replication_controller) if selector.nil? || selector == {}
        selector || {}
      end

      def controller_owner_reference?(pod)
        Support.owner_references(pod).any? do |reference|
          value = Support.value(reference, "controller", false)
          value == true || value.to_s.casecmp("true").zero?
        end
      end

      def replica_count(resource)
        replicas = Support.integer(Support.value(Support.spec(resource), "replicas", 1), 1)
        raise ArgumentError, "replicas must be non-negative" if replicas.negative?

        replicas
      end

      def create_pods(owner, existing_pods, count, selector)
        names = Array(existing_pods).map { |pod| Support.name(pod) }
        template = Support.value(Support.spec(owner), "template", {})
        operations = []
        Integer(count).times do
          # GenerateName semantics: a random 5-character suffix, never a
          # counter -- "<rc>-0" collided with Pods the controller does not own.
          name = nil
          loop do
            name = "#{Support.name(owner)}-#{Support.random_suffix}"
            break unless names.include?(name)
          end
          names << name
          metadata = Support.deep_copy(Support.value(template, "metadata", {}))
          metadata = {} unless metadata.is_a?(Hash)
          metadata["name"] = name
          metadata["namespace"] ||= Support.namespace(owner)
          labels = Support.deep_copy(Support.value(metadata, "labels", {}))
          labels = {} unless labels.is_a?(Hash)
          metadata["labels"] = labels.merge(selector || {})
          spec = Support.deep_copy(Support.value(template, "spec", {}))
          spec = {} unless spec.is_a?(Hash)
          pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => spec}
          operations << operation_create(pod, owner: owner, descriptor: POD,
                                          reason: "replicationcontroller scale up")
          names << name
        end
        operations
      end

      # getPodsToDelete (the ReplicationManager is the ReplicaSet
      # controller): ActivePodsWithRanks over the controller's own Pods.
      def delete_pods(pods, count)
        now = @clock ? Support.parse_time(@clock.call) : nil
        selected = PodDeletionRanking.pods_to_delete(pods, count, related: pods, now: now || Time.now)
        selected.map { |pod| operation_delete(pod, descriptor: POD, reason: "replicationcontroller scale down") }
      end
    end
  end
end
