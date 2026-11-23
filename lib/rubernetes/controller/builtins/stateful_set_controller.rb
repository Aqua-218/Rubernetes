# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class StatefulSetController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("StatefulSet")
        CONTROLLER_REVISION = ResourceDescriptor.parse("ControllerRevision")
        PERSISTENT_VOLUME_CLAIM = ResourceDescriptor.parse("PersistentVolumeClaim")
        REVISION_LABEL = "controller-revision-hash"
        POD_NAME_LABEL = "statefulset.kubernetes.io/pod-name"
        POD_INDEX_LABEL = "apps.kubernetes.io/pod-index"

        # +max_unavailable_stateful_set+: the MaxUnavailableStatefulSet gate
        # (Beta, off by default); off, a rolling update replaces one Pod at a
        # time whatever rollingUpdate.maxUnavailable says.
        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          @max_unavailable_stateful_set = options.delete(:max_unavailable_stateful_set) == true
          super
        end

        # What one pass over a StatefulSet knows and has decided so far: the
        # set with its revisions applied, the Pods by role, and the writes,
        # events and status the pass is accumulating.
        Sync = Struct.new(:working_set, :desired, :start, :now, :operations, :events, :status,
                          :current_revision, :update_revision, :current_set, :update_set,
                          :min_ready_seconds, :monotonic, :strategy, :strategy_type, :max_unavailable_gate,
                          :existing_by_ordinal, :replicas, :condemned, :first_unavailable, :claim_templates,
                          keyword_init: true)

        # pkg/controller/statefulset/stateful_set_control.go updateStatefulSet.
        def plan(stateful_set, store: nil, pods: nil, revisions: nil, controller_revisions: nil,
                 pvcs: nil, claims: nil, now: nil, max_unavailable_stateful_set: nil, **_options)
          max_unavailable_gate = max_unavailable_stateful_set.nil? ? @max_unavailable_stateful_set : max_unavailable_stateful_set == true
          adapter = adapter_for(store)
          pods ||= list_children(adapter, POD, Support.namespace(stateful_set))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          owned_pods, ownership_operations = claim_pods(stateful_set, pods, adapter)

          revisions = controller_revisions unless controller_revisions.nil?
          revisions = list_children(adapter, CONTROLLER_REVISION, Support.namespace(stateful_set)) if revisions.nil? && adapter
          pvcs = claims unless claims.nil?
          pvcs = list_children(adapter, PERSISTENT_VOLUME_CLAIM, Support.namespace(stateful_set)) if pvcs.nil? && adapter

          sync = begin_sync(stateful_set, revisions, owned_pods, now, max_unavailable_gate)
          sync.operations.unshift(*ownership_operations)
          if Support.metadata(stateful_set).key?("deletionTimestamp")
            observe_replicas(sync)
          else
            reconcile_storage(sync, pvcs)
            exited = process_replicas(sync) || process_condemned(sync)
            observe_replicas(sync)
            rolling_update(sync) if !exited && sync.strategy_type == "RollingUpdate"
            complete_rolling_update!(sync.working_set, sync.status, sync.strategy_type, sync.desired)
          end
          planned = result(stateful_set, sync.operations, status: compact_stateful_status(sync.status), events: sync.events)
          with_requeue(planned, availability_requeue(sync, owned_pods))
        end

        def scale(stateful_set, replicas, pods: nil, store: nil)
          candidate = Support.deep_copy(stateful_set)
          candidate["spec"] ||= {}
          candidate["spec"]["replicas"] = Integer(replicas)
          plan(candidate, pods: pods, store: store)
        end

        def rollback(stateful_set, revision:, pods: nil, store: nil, revisions: nil, controller_revisions: nil)
          adapter = adapter_for(store)
          revisions = controller_revisions unless controller_revisions.nil?
          revisions = list_children(adapter, CONTROLLER_REVISION, Support.namespace(stateful_set)) if revisions.nil? && adapter
          selected = find_revision(revisions, revision)
          raise ArgumentError, "StatefulSet revision #{revision.inspect} was not found" unless selected

          candidate = apply_revision(stateful_set, selected)
          annotations = Support.annotations(candidate).dup
          annotations.delete("statefulset.kubernetes.io/rollback-to")
          candidate["metadata"] ||= {}
          candidate["metadata"]["annotations"] = annotations unless annotations.empty?
          candidate["metadata"].delete("annotations") if annotations.empty?
          operation = operation_update(stateful_set, candidate, descriptor: DESCRIPTOR, reason: "statefulset rollback")
          result(stateful_set, [operation].compact)
        end

        def delete(stateful_set, pods: nil, store: nil, orphan: false)
          adapter = store || @adapter
          pods ||= list_children(adapter, POD, Support.namespace(stateful_set))
          operations = if orphan
                         []
                       else
                         owned(stateful_set, pods).map do |pod|
                           operation_delete(pod, descriptor: POD, reason: "statefulset deletion")
                         end
                       end
          operations << operation_delete(stateful_set, descriptor: DESCRIPTOR, reason: "statefulset deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        private

        def claim_pods(stateful_set, pods, adapter)
          matches = Support.selector_predicate(Support.value(Support.spec(stateful_set), "selector", {}))
          namespace = Support.namespace(stateful_set)
          name = Support.name(stateful_set)
          matching = pods.select do |pod|
            Support.namespace(pod) == namespace && ordinal_for(pod, name) && matches.call(pod)
          end
          registered = owned(stateful_set, pods)
          retained = registered & matching
          return [retained, []] if terminating?(stateful_set)

          orphans = matching.reject { |pod| terminating?(pod) || Support.controller_owner_reference(pod) }
          orphans = [] unless orphans.empty? || Support.adoption_allowed?(adapter, stateful_set, DESCRIPTOR)
          releases = (registered - matching).map { |pod| update_pod_owner(pod, stateful_set, adopt: false) }
          adoptions = orphans.map { |pod| update_pod_owner(pod, stateful_set, adopt: true) }
          [retained + orphans, releases + adoptions]
        end

        def update_pod_owner(pod, stateful_set, adopt:)
          candidate = Support.deep_copy(pod)
          uid = Support.uid(stateful_set).to_s
          references = Support.owner_references(candidate).reject { |ref| Support.ref_value(ref, "uid", nil).to_s == uid }
          references << Support.owner_reference(stateful_set) if adopt
          candidate.fetch("metadata")["ownerReferences"] = references
          operation_update(pod, candidate, descriptor: POD, reason: adopt ? "statefulset pod adoption" : "statefulset pod release")
        end

        def start_ordinal(resource)
          ordinals = Support.value(Support.spec(resource), "ordinals", {})
          ordinals = {} unless ordinals.is_a?(Hash)
          Support.integer(Support.value(ordinals, "start", 0), 0)
        end

        # Everything the pass derives before it acts: revisions (their writes
        # are the first operations), the Pods split into wanted replicas and
        # condemned ones, and the status header.
        def begin_sync(stateful_set, revisions, owned_pods, now, max_unavailable_gate)
          working_set = apply_rollback_annotation(stateful_set, revisions)
          sync = Sync.new(working_set: working_set, desired: replica_count(working_set), start: start_ordinal(working_set),
                          now: now, events: [], max_unavailable_gate: max_unavailable_gate)
          collision_count = Support.integer(Support.value(Support.status(stateful_set), "collisionCount", 0), 0)
          revision_state = reconcile_revisions(working_set, revisions, owned_pods, collision_count)
          sync.operations = [].concat(revision_state.fetch(:operations))
          sync.update_revision = revision_state.fetch(:update)
          sync.current_revision = revision_state.fetch(:current)
          sync.current_set = apply_revision(working_set, sync.current_revision)
          sync.update_set = apply_revision(working_set, sync.update_revision)
          sync.min_ready_seconds = Support.integer(Support.value(Support.spec(working_set), "minReadySeconds", 0), 0)
          sync.existing_by_ordinal = owned_pods.each_with_object({}) do |pod, result|
            ordinal = ordinal_for(pod, Support.name(working_set))
            result[ordinal] = pod if ordinal
          end
          sync.monotonic = pod_management_policy(working_set) == "OrderedReady"
          sync.strategy, sync.strategy_type = update_strategy(working_set)
          partition_pods(sync)
          sync.status = status_header(stateful_set, sync, revision_state.fetch(:collision_count))
          sync
        end

        def pod_management_policy(working_set)
          pod_policy = Support.value(Support.spec(working_set), "podManagementPolicy", "OrderedReady").to_s
          raise ArgumentError, "unsupported StatefulSet podManagementPolicy #{pod_policy.inspect}" unless %w[OrderedReady Parallel].include?(pod_policy)

          pod_policy
        end

        # [spec.updateStrategy as a Hash, its type].
        def update_strategy(working_set)
          strategy = Support.value(Support.spec(working_set), "updateStrategy", {})
          strategy = {} unless strategy.is_a?(Hash)
          strategy_type = Support.value(strategy, "type", "RollingUpdate").to_s
          raise ArgumentError, "unsupported StatefulSet updateStrategy #{strategy_type.inspect}" unless %w[RollingUpdate OnDelete].include?(strategy_type)

          [strategy, strategy_type]
        end

        # replicas: the Pod (or nil) at each wanted ordinal; condemned: the
        # Pods outside the range, highest ordinal first.
        def partition_pods(sync)
          wanted = sync.start...(sync.start + sync.desired)
          sync.replicas = wanted.map { |ordinal| sync.existing_by_ordinal[ordinal] }
          sync.condemned = sync.existing_by_ordinal.reject { |ordinal, _pod| wanted.cover?(ordinal) }
            .sort_by { |ordinal, _pod| -ordinal }.map { |_ordinal, pod| pod }
          sync.first_unavailable = sync.replicas.compact.find { |pod| unavailable?(sync, pod) } ||
                                   sync.condemned.reverse.find { |pod| unavailable?(sync, pod) }
        end

        def unavailable?(sync, pod)
          !Support.pod_available?(pod, sync.min_ready_seconds, sync.now) || terminating?(pod)
        end

        def availability_requeue(sync, pods)
          minimum = sync.min_ready_seconds
          return unless minimum.positive? && sync.status["readyReplicas"] != sync.status["availableReplicas"]

          # A ready Pod can become available without generating another Pod
          # event. Schedule the first upcoming availability transition.
          delays = pods.filter_map do |pod|
            next unless running_and_ready?(pod)

            transition = Support.parse_time(Support.value(Support.condition(pod, "Ready"), "lastTransitionTime", nil))
            delay = transition + minimum - sync.now if transition
            delay if delay&.positive?
          end
          delays.min || minimum
        end

        def status_header(stateful_set, sync, collision_count)
          status = Support.deep_copy(Support.status(stateful_set))
          status["observedGeneration"] = Support.integer(Support.metadata(stateful_set)["generation"],
                                                         Support.integer(status["observedGeneration"], 0))
          status["currentRevision"] = Support.name(sync.current_revision)
          status["updateRevision"] = Support.name(sync.update_revision)
          status["collisionCount"] = collision_count
          status
        end

        def reconcile_storage(sync, pvcs)
          sync.claim_templates = volume_claim_templates_for(sync.working_set)
          # A direct planner invocation has no informer to list from.  An
          # explicitly omitted claim list still means the declared templates
          # must be materialized; an adapter-backed reconcile already supplied
          # the authoritative snapshot above.
          pvcs = [] if pvcs.nil? && sync.claim_templates.any?
          blocked = sync.replicas.index { |pod| pod.nil? || ordered_replica_blocked?(sync, pod) } if sync.monotonic
          create_through = sync.start + (blocked || sync.desired)
          sync.operations.concat(reconcile_claims(sync.working_set, sync.claim_templates, pvcs, sync.desired, sync.start,
                                                  sync.existing_by_ordinal, create_through: create_through))
        end

        def ordered_replica_blocked?(sync, pod)
          !running_and_ready?(pod) || unavailable?(sync, pod)
        end

        # processReplica: create missing ordinals, restart terminal Pods, and
        # in OrderedReady mode stop at the first Pod that is not yet
        # Running, Ready, and Available.  True when the pass must stop here.
        def process_replicas(sync)
          sync.replicas.each_with_index do |pod, index|
            ordinal = sync.start + index
            if pod.nil?
              create_replica(sync, ordinal)
              return true if sync.monotonic

              next
            end
            if %w[Failed Succeeded].include?(Support.value(Support.status(pod), "phase", "").to_s)
              restart_terminal_pod(sync, pod)
              return true
            end
            return true if sync.monotonic && ordered_replica_blocked?(sync, pod)
            next if sync.claim_templates.empty?

            reconcile_pod_volumes(sync, pod, ordinal)
          end
          false
        end

        def create_replica(sync, ordinal)
          working_set = sync.working_set
          source_set, revision_name = versioned_source(sync.current_set, sync.update_set, sync.current_revision, sync.update_revision,
                                                       ordinal, sync.start)
          candidate = stateful_pod_for(source_set, name: "#{Support.name(working_set)}-#{ordinal}",
                                                   template_value: template(source_set), revision_hash: revision_name,
                                                   ordinal: ordinal, claim_templates: sync.claim_templates)
          sync.operations << operation_create(candidate, owner: working_set, descriptor: POD, reason: "statefulset scale up")
          sync.events << {"type" => "Normal", "reason" => "SuccessfulCreate",
                          "message" => "Create Pod #{Support.name(candidate)} in StatefulSet #{Support.name(working_set)} successful"}
        end

        def restart_terminal_pod(sync, pod)
          return if terminating?(pod)

          sync.operations << operation_delete(pod, descriptor: POD, reason: "statefulset terminal pod restart")
          sync.events << successful_delete_event(sync, pod)
        end

        def successful_delete_event(sync, pod)
          {"type" => "Normal", "reason" => "SuccessfulDelete",
           "message" => "delete Pod #{Support.name(pod)} in StatefulSet #{Support.name(sync.working_set)} successful"}
        end

        def reconcile_pod_volumes(sync, pod, ordinal)
          candidate = stateful_pod_for(sync.update_set, name: Support.name(pod), template_value: template(sync.update_set),
                                                        revision_hash: Support.labels(pod)[REVISION_LABEL].to_s,
                                                        ordinal: ordinal, claim_templates: sync.claim_templates, existing: pod)
          storage_update = operation_update(pod, candidate, descriptor: POD, reason: "statefulset volume claim reconciliation")
          sync.operations << storage_update if storage_update
        end

        # processCondemned: scale down from the highest ordinal, one Pod at a
        # time in OrderedReady mode, waiting for predecessors to be available.
        # True when a Pod was deleted, which ends the pass.
        def process_condemned(sync)
          sync.condemned.each do |pod|
            if terminating?(pod)
              break if sync.monotonic

              next
            end
            if sync.monotonic && pod != sync.first_unavailable &&
               (!running_and_ready?(pod) || !Support.pod_available?(pod, sync.min_ready_seconds, sync.now))
              break
            end

            sync.operations << operation_delete(pod, descriptor: POD, reason: "statefulset scale down")
            sync.events << successful_delete_event(sync, pod)
            return true
          end
          false
        end

        # Deletes Pods of an older revision from the highest ordinal down to
        # the partition; each is recreated from the update revision next pass.
        def rolling_update(sync)
          rolling = Support.value(sync.strategy, "rollingUpdate", {})
          rolling = {} unless rolling.is_a?(Hash)
          update_min = Support.integer(Support.value(rolling, "partition", 0), 0)
          targets = sync.replicas.compact
          return rolling_update_within_budget(sync, rolling, targets, update_min) if sync.max_unavailable_gate

          targets.each_with_index.to_a.reverse_each do |pod, index|
            break if index < update_min

            if outdated?(sync, pod)
              delete_for_rolling_update(sync, pod)
              break
            end
            break if unavailable?(sync, pod)
          end
        end

        # MaxUnavailableStatefulSet semantics (updateStatefulSetAfterInvariantEstablished).
        def rolling_update_within_budget(sync, rolling, targets, update_min)
          max_unavailable = [Support.quantity(Support.value(rolling, "maxUnavailable", 1), sync.desired, mode: :floor, default: 1), 1].max
          unavailable_pods = targets.count { |pod| unavailable?(sync, pod) }
          record_max_unavailable(sync.working_set, max_unavailable, unavailable_pods)
          return unless unavailable_pods < max_unavailable

          budget = max_unavailable - unavailable_pods
          deleted = 0
          targets.each_with_index.to_a.reverse_each do |pod, index|
            break if index < update_min || deleted >= budget
            next unless outdated?(sync, pod)

            delete_for_rolling_update(sync, pod)
            deleted += 1
          end
        end

        # statefulset_controller_statefulset_{max_unavailable,unavailable_replicas}:
        # recorded, as upstream, only with the MaxUnavailableStatefulSet gate on.
        def record_max_unavailable(working_set, max_unavailable, unavailable_pods)
          gauge_labels = {"pod_management_policy" => Support.value(Support.spec(working_set), "podManagementPolicy", "OrderedReady").to_s,
                          "statefulset_name" => Support.name(working_set).to_s, "statefulset_namespace" => Support.namespace(working_set).to_s}
          ControllerMetrics.set("statefulset_controller_statefulset_max_unavailable", max_unavailable, gauge_labels)
          ControllerMetrics.set("statefulset_controller_statefulset_unavailable_replicas", unavailable_pods, gauge_labels)
        end

        def outdated?(sync, pod)
          Support.labels(pod)[REVISION_LABEL].to_s != Support.name(sync.update_revision) && !terminating?(pod)
        end

        def delete_for_rolling_update(sync, pod)
          sync.operations << operation_delete(pod, descriptor: POD, reason: "statefulset rolling update")
          sync.status["currentReplicas"] = Support.integer(sync.status["currentReplicas"], 0) - 1
        end

        def observe_replicas(sync)
          compute_replica_status!(sync.status, sync.replicas.compact + sync.condemned, sync.min_ready_seconds,
                                  sync.current_revision, sync.update_revision, sync.now)
        end

        def terminating?(pod)
          !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?
        end

        def running_and_ready?(pod)
          Support.value(Support.status(pod), "phase", "").to_s == "Running" && Support.ready?(pod)
        end

        # newVersionedStatefulSetPod: ordinals below the partition are created
        # from the current revision, the rest from the update revision.
        def versioned_source(current_set, update_set, current_revision, update_revision, ordinal, start)
          strategy = Support.value(Support.spec(current_set), "updateStrategy", {})
          strategy = {} unless strategy.is_a?(Hash)
          rolling = Support.value(strategy, "rollingUpdate", nil)
          if Support.value(strategy, "type", "RollingUpdate").to_s == "RollingUpdate"
            boundary = if rolling.is_a?(Hash)
                         start + Support.integer(Support.value(rolling, "partition", 0), 0)
                       else
                         start + Support.integer(Support.value(Support.status(current_set), "currentReplicas", 0), 0)
                       end
            return [current_set, Support.name(current_revision)] if ordinal < boundary
          end
          [update_set, Support.name(update_revision)]
        end

        # computeReplicaStatus over every observed replica and condemned Pod.
        def compute_replica_status!(status, pods, min_ready_seconds, current_revision, update_revision, now)
          status["replicas"] = pods.length
          status["readyReplicas"] = pods.count { |pod| running_and_ready?(pod) }
          status["availableReplicas"] = pods.count { |pod| running_and_ready?(pod) && Support.pod_available?(pod, min_ready_seconds, now) }
          live = pods.reject { |pod| terminating?(pod) }
          status["currentReplicas"] = live.count { |pod| Support.labels(pod)[REVISION_LABEL].to_s == Support.name(current_revision) }
          status["updatedReplicas"] = live.count { |pod| Support.labels(pod)[REVISION_LABEL].to_s == Support.name(update_revision) }
          status
        end

        def complete_rolling_update!(_set, status, strategy_type, desired)
          return unless strategy_type == "RollingUpdate" &&
                        Support.integer(status["updatedReplicas"], 0) == desired &&
                        Support.integer(status["readyReplicas"], 0) == desired &&
                        Support.integer(status["replicas"], 0) == desired

          status["currentReplicas"] = status["updatedReplicas"]
          status["currentRevision"] = status["updateRevision"]
        end

        # StatefulSetStatus JSON: readyReplicas, currentReplicas and
        # updatedReplicas are omitempty; replicas, availableReplicas and the
        # revisions are always serialized.
        def compact_stateful_status(status)
          candidate = Support.deep_copy(status)
          %w[readyReplicas currentReplicas updatedReplicas].each do |key|
            candidate.delete(key) if Support.integer(candidate[key], 0) <= 0
          end
          candidate
        end

        def ordinal_for(pod, prefix)
          match = Support.name(pod).match(/\A#{Regexp.escape(prefix)}-(\d+)\z/)
          match && Integer(match[1])
        rescue ArgumentError
          nil
        end
      end
    end
  end
end
