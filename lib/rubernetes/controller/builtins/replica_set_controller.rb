# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class ReplicaSetController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("ReplicaSet")

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          super
        end

        # PodControllerRefManager canAdoptFunc / RecheckDeletionTimestamp: a
        # controller adopts only after a fresh read shows the same object, not
        # being deleted.  Adopting from the informer cache re-owned the Pods an
        # orphaning delete had just released; the garbage collector then found
        # their owner gone and deleted them ("[sig-api-machinery] Garbage
        # collector should orphan pods created by rc if delete options say so"
        # kept 27 of 100).
        def adoption_allowed?(adapter, controller, descriptor)
          return true unless AdapterCapability.live_reads?(adapter)

          fresh = adapter.find_live(descriptor, name: Support.name(controller), namespace: Support.namespace(controller))
          !fresh.nil? && Support.uid(fresh).to_s == Support.uid(controller).to_s &&
            Support.value(Support.metadata(fresh), "deletionTimestamp", nil).nil?
        end

        def plan(replica_set, store: nil, pods: nil, now: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(replica_set))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          all_pods = Array(pods)
          claimed = claim_pods(replica_set, all_pods, adapter)
          owned_pods = claimed.fetch(:owned)
          alive = owned_pods.select { |pod| pod_alive?(pod) }
          desired = replica_count(replica_set)
          scaling, creation_batches = manage_replicas(replica_set, all_pods, alive, desired, adapter, now)
          status = replica_status(replica_set, owned_pods, alive, now)
          planned = result(replica_set, claimed.fetch(:operations) + scaling, status: status, batches: creation_batches)
          with_requeue(planned, availability_requeue(replica_set, status, desired))
        end

        def scale(replica_set, replicas, pods: nil, store: nil)
          candidate = Support.deep_copy(replica_set)
          candidate["spec"] ||= {}
          candidate["spec"]["replicas"] = Integer(replicas)
          plan(candidate, pods: pods, store: store)
        end

        def delete(replica_set, pods: nil, store: nil)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(replica_set))
          operations = owned(replica_set, pods).map { |pod| operation_delete(pod, descriptor: POD, reason: "replicaset deletion") }
          operations << operation_delete(replica_set, descriptor: DESCRIPTOR, reason: "replicaset deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        def create_pods(replica_set, existing_pods, count)
          existing_names = Array(existing_pods).map { |pod| Support.name(pod) }
          template_value = Support.value(Support.spec(replica_set), "template", {})
          labels = selector_for(replica_set)
          operations = []
          Integer(count).times do
            loop do
              # GenerateName semantics (random suffix), as upstream: a counter
              # collided with Pods that exist but are not owned by this set.
              candidate_name = "#{Support.name(replica_set)}-#{Support.random_suffix}"
              next if existing_names.include?(candidate_name)

              pod = pod_for(replica_set, name: candidate_name, template_value: template_value, labels: labels)
              operations << operation_create(pod, owner: replica_set, descriptor: POD, reason: "replicaset scale up")
              existing_names << candidate_name
              break
            end
          end
          operations
        end

        def selector_matches?(replica_set, pod)
          selector = Support.value(Support.spec(replica_set), "selector", {})
          Support.selector_matches?(selector, pod)
        end

        def namespace_matches?(replica_set, pod)
          Support.namespace(replica_set).to_s == Support.namespace(pod).to_s
        end

        def controlling_owner_reference?(pod)
          Support.owner_references(pod).any? do |reference|
            value = Support.ref_value(reference, "controller", false)
            value == true || value.to_s.casecmp("true").zero?
          end
        end

        def slow_start_batches(operations)
          batches = []
          cursor = 0
          batch_size = 1
          while cursor < operations.length
            batch = operations.slice(cursor, batch_size)
            batches << batch
            cursor += batch.length
            batch_size *= 2
          end
          batches
        end

        # getPodsToDelete: ActivePodsWithRanks (PodDeletionRanking).
        def delete_pods(pods, count, related: nil, now: Time.now)
          selected = PodDeletionRanking.pods_to_delete(pods, count, related: related, now: now)
          selected.map { |pod| operation_delete(pod, descriptor: POD, reason: "replicaset scale down") }
        end

        # getIndirectlyRelatedPods: the Pods of every ReplicaSet with this
        # one's controller (a Deployment's old and new sets), or this set's
        # own when it has no controller.
        def related_pods(adapter, replica_set, all_pods)
          controller = Support.owner_references(replica_set).find do |reference|
            Support.ref_value(reference, "controller", false).to_s.casecmp("true").zero?
          end
          uids = [Support.uid(replica_set).to_s]
          if controller
            owner_uid = Support.ref_value(controller, "uid", nil).to_s
            Array(list_children(adapter, DESCRIPTOR, Support.namespace(replica_set))).each do |sibling|
              next unless Support.owner_references(sibling).any? do |reference|
                Support.ref_value(reference, "controller", false).to_s.casecmp("true").zero? &&
                Support.ref_value(reference, "uid", nil).to_s == owner_uid
              end

              uids << Support.uid(sibling).to_s
            end
          end
          Array(all_pods).select do |pod|
            namespace_matches?(replica_set, pod) && Support.owner_references(pod).any? do |reference|
              Support.ref_value(reference, "controller", false).to_s.casecmp("true").zero? &&
                uids.include?(Support.ref_value(reference, "uid", nil).to_s)
            end
          end
        end

        private

        # ClaimPods: the Pods this set owns once matching orphans are adopted
        # and owned Pods whose labels stopped matching are released, with the
        # writes that record both.
        def claim_pods(replica_set, all_pods, adapter)
          owned_pods = owned(replica_set, all_pods).select { |pod| controlled_by?(pod, replica_set) }
          adoptable = adoptable_pods(replica_set, all_pods)
          adoptable = [] unless adoptable.empty? || adoption_allowed?(adapter, replica_set, DESCRIPTOR)
          adoption_operations = adoptable.filter_map { |pod| adoption_operation(replica_set, pod) }
          owned_pods += adoptable
          # ClaimPods/ReleasePod: an owned Pod whose labels stopped matching
          # the selector is released (its controller reference removed) so
          # another owner may adopt it, and it no longer counts as a replica.
          released = owned_pods.reject do |pod|
            selector_matches?(replica_set, pod) || Support.value(Support.metadata(pod), "deletionTimestamp", nil)
          end
          release_operations = released.map { |pod| release_operation(replica_set, pod) }
          {owned: owned_pods - released, operations: adoption_operations + release_operations}
        end

        def controlled_by?(pod, replica_set)
          Support.owner_references(pod).any? do |reference|
            Support.ref_value(reference, "controller", false).to_s.casecmp("true").zero? &&
              Support.ref_value(reference, "apiVersion", nil).to_s == DESCRIPTOR.api_version &&
              Support.ref_value(reference, "kind", "").to_s == DESCRIPTOR.kind &&
              Support.ref_value(reference, "name", "").to_s == Support.name(replica_set) &&
              Support.ref_value(reference, "uid", nil).to_s == Support.uid(replica_set).to_s
          end
        end

        # ReplicaSet adopts selector-matching Pods that have no controlling
        # owner. A Pod with another controller is never adopted, even when
        # its labels and generated name happen to collide with this set.
        def adoptable_pods(replica_set, all_pods)
          all_pods.select do |pod|
            next false unless namespace_matches?(replica_set, pod)
            next false if Support.value(Support.metadata(pod), "deletionTimestamp", nil)
            next false unless selector_matches?(replica_set, pod)

            !controlling_owner_reference?(pod)
          end
        end

        def adoption_operation(replica_set, pod)
          candidate = Support.deep_copy(pod)
          candidate["metadata"] ||= {}
          references = Array(Support.value(candidate["metadata"], "ownerReferences", [])).map { |reference| Support.deep_copy(reference) }
          references << Support.owner_reference(replica_set)
          candidate["metadata"]["ownerReferences"] = references
          operation_update(pod, candidate, descriptor: POD, reason: "replicaset pod adoption")
        end

        def release_operation(replica_set, pod)
          candidate = Support.deep_copy(pod)
          candidate["metadata"] ||= {}
          candidate["metadata"]["ownerReferences"] = Array(Support.value(candidate["metadata"], "ownerReferences", [])).reject do |reference|
            Support.ref_value(reference, "uid", nil).to_s == Support.uid(replica_set).to_s
          end
          operation_update(pod, candidate, descriptor: POD, reason: "replicaset pod release")
        end

        # Creates the missing replicas (at most 500 a pass, in slow-start
        # batches) or deletes the surplus: [operations, creation batches].
        def manage_replicas(replica_set, all_pods, alive, desired, adapter, now)
          # replica_set.go syncReplicaSet: a ReplicaSet that is being deleted
          # does not manage its replicas any more (it would recreate the Pods
          # its own deletion is removing).
          being_deleted = !Support.value(Support.metadata(replica_set), "deletionTimestamp", nil).nil?
          if alive.length < desired && !being_deleted
            create_count = [desired - alive.length, 500].min
            # Include every Pod in the namespace in the name reservation.
            # Kubernetes rejects a create when a foreign controller already
            # owns the generated name; reserving only our Pods would repeat
            # an AlreadyExists conflict on every retry.
            namespace_pods = all_pods.select { |pod| namespace_matches?(replica_set, pod) }
            create_operations = create_pods(replica_set, namespace_pods, create_count)
            [create_operations, slow_start_batches(create_operations)]
          elsif alive.length > desired
            [delete_pods(alive, alive.length - desired, related: related_pods(adapter, replica_set, all_pods), now: now), []]
          else
            [[], []]
          end
        end

        # replica_set_utils.go calculateStatus: readiness is the Ready
        # condition, availability additionally honours minReadySeconds, and
        # both counters are omitempty in the API.
        def replica_status(replica_set, owned_pods, alive, now)
          min_ready_seconds = Support.integer(Support.value(Support.spec(replica_set), "minReadySeconds", 0), 0)
          status = Support.deep_copy(Support.status(replica_set))
          status["replicas"] = alive.length
          status["fullyLabeledReplicas"] = alive.count do |pod|
            selector_for(replica_set).all? do |key, value|
              Support.labels(pod)[key.to_s] == value.to_s
            end
          end
          # Zero counters are written, not omitted: a status apply that leaves
          # a counter out does not clear the stored value (see
          # DeploymentController#compact_status).
          status["readyReplicas"] = alive.count { |pod| Support.ready?(pod) }
          status["availableReplicas"] = alive.count { |pod| Support.pod_available?(pod, min_ready_seconds, now) }
          status["observedGeneration"] =
            Support.integer(Support.metadata(replica_set)["generation"], Support.integer(status["observedGeneration"], 0))
          status["terminatingReplicas"] = owned_pods.count do |pod|
            Support.value(Support.metadata(pod), "deletionTimestamp", nil) &&
              !%w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
          end
          status
        end

        # Upstream re-syncs after minReadySeconds so availability catches up
        # without a Pod event (replica_set.go syncReplicaSet).
        def availability_requeue(replica_set, status, desired)
          min_ready_seconds = Support.integer(Support.value(Support.spec(replica_set), "minReadySeconds", 0), 0)
          return nil unless min_ready_seconds.positive? && status["readyReplicas"] == desired && status["availableReplicas"] != desired

          min_ready_seconds.to_f
        end
      end
    end
  end
end
