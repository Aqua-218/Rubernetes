# frozen_string_literal: true

require "json"
require "time"

require "digest"
require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "runtime"
require_relative "ownership"
require_relative "pod_deletion_ranking"

module Rubernetes
  module Controller
    module Builtins
      class WorkloadController < BaseController
        POD = ResourceDescriptor.parse("Pod")

        protected

        def descriptor_for(value)
          ResourceDescriptor.parse(value)
        end

        def list_children(adapter, descriptor, namespace)
          return [] unless adapter

          adapter.list(descriptor, namespace: namespace || :all)
        end

        def owner_pods(resource, adapter)
          owned(resource, list_children(adapter, POD, Support.namespace(resource)))
        end

        def template(resource)
          candidate = Support.value(Support.spec(resource), "template", {})
          candidate.is_a?(Hash) ? Support.deep_copy(candidate) : {}
        end

        def template_hash(resource_or_template)
          candidate = resource_or_template.is_a?(Hash) && Support.kind(resource_or_template).to_s.empty? ? resource_or_template : template(resource_or_template)
          Digest::SHA256.hexdigest(JSON.generate(Support.canonical(candidate)))[0, 10]
        end

        def owner_ref?(owner, dependent)
          Support.owner_reference_matches?(owner, dependent, controller: true)
        end

        def pod_for(owner, name:, template_value: nil, labels: nil, node_name: nil, ordinal: nil)
          source = Support.deep_copy(template_value || template(owner))
          metadata = Support.value(source, "metadata", {})
          metadata = {} unless metadata.is_a?(Hash)
          spec = Support.value(source, "spec", {})
          spec = {} unless spec.is_a?(Hash)
          metadata["name"] = name
          metadata["namespace"] ||= Support.namespace(owner) if Support.namespace(owner)
          merged_labels = Support.value(metadata, "labels", {})
          merged_labels = {} unless merged_labels.is_a?(Hash)
          merged_labels = merged_labels.merge(labels || {})
          metadata["labels"] = merged_labels unless merged_labels.empty?
          source_annotations = Support.value(source, "metadata", {})["annotations"] if Support.value(source, "metadata", {}).is_a?(Hash)
          metadata["annotations"] = Support.deep_copy(source_annotations) if source_annotations.is_a?(Hash) && !source_annotations.empty?
          object = {
            "apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata,
            "spec" => spec
          }
          object["spec"]["nodeName"] = node_name if node_name
          object
        end

        def available_count(objects)
          Array(objects).count { |object| Support.ready?(object) || Support.integer(Support.status(object)["readyReplicas"], 0).positive? }
        end

        def pod_alive?(pod)
          phase = Support.value(Support.status(pod), "phase", "").to_s
          !Support.value(Support.metadata(pod), "deletionTimestamp", nil) && !%w[Succeeded Failed].include?(phase)
        end

        def status_candidate(resource, status)
          candidate = Support.deep_copy(resource)
          candidate["status"] = status
          candidate
        end

        def result(resource, operations, status: nil, events: [], batches: nil, force_status: false)
          status ||= Support.status(resource)
          status_operation = operation_status(resource, status, descriptor: descriptor_for(resource), force: force_status)
          operations = Array(operations).compact
          operations << status_operation if status_operation
          ReconcileResult.new(operations: operations, status: status,
                              batches: batches, events: events, controller: name,
                              key: [Support.namespace(resource), Support.name(resource)].compact.join("/"))
        end

        def replica_count(resource, field = "replicas", default: 1)
          count = Support.integer(Support.value(Support.spec(resource), field, default), default)
          raise ArgumentError, "#{field} must be non-negative" if count.negative?

          count
        end

        def selector_for(resource)
          selector = Support.value(Support.spec(resource), "selector", {})
          selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
          selector || {}
        end

        def revision(object)
          annotations = Support.annotations(object)
          Support.integer(annotations["deployment.kubernetes.io/revision"] || annotations["controller.kubernetes.io/revision"], 0)
        end

        def with_owner_metadata(object, owner)
          candidate = Support.deep_copy(object)
          candidate["metadata"] ||= {}
          candidate["metadata"]["ownerReferences"] = [Support.owner_reference(owner)]
          candidate
        end
      end

      # Deployment lives in its own file; it depends on the shared
      # WorkloadController helpers defined above.
      require_relative "deployment_controller"

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
          return true unless adapter.respond_to?(:find_live)

          fresh = adapter.find_live(descriptor, name: Support.name(controller), namespace: Support.namespace(controller))
          !fresh.nil? && Support.uid(fresh).to_s == Support.uid(controller).to_s &&
            Support.value(Support.metadata(fresh), "deletionTimestamp", nil).nil?
        rescue StandardError
          false
        end

        def plan(replica_set, store: nil, pods: nil, now: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(replica_set))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          all_pods = Array(pods)
          owned_pods = owned(replica_set, all_pods).select do |pod|
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
          adoptable_pods = all_pods.select do |pod|
            next false unless namespace_matches?(replica_set, pod)
            next false if Support.value(Support.metadata(pod), "deletionTimestamp", nil)
            next false unless selector_matches?(replica_set, pod)

            !controlling_owner_reference?(pod)
          end
          adoptable_pods = [] unless adoptable_pods.empty? || adoption_allowed?(adapter, replica_set, DESCRIPTOR)
          adoption_operations = adoptable_pods.filter_map do |pod|
            candidate = Support.deep_copy(pod)
            candidate["metadata"] ||= {}
            references = Array(Support.value(candidate["metadata"], "ownerReferences", [])).map { |reference| Support.deep_copy(reference) }
            references << Support.owner_reference(replica_set)
            candidate["metadata"]["ownerReferences"] = references
            operation_update(pod, candidate, descriptor: POD, reason: "replicaset pod adoption")
          end
          owned_pods += adoptable_pods
          # ClaimPods/ReleasePod: an owned Pod whose labels stopped matching
          # the selector is released (its controller reference removed) so
          # another owner may adopt it, and it no longer counts as a replica.
          released_pods = owned_pods.reject do |pod|
            selector_matches?(replica_set, pod) || Support.value(Support.metadata(pod), "deletionTimestamp", nil)
          end
          release_operations = released_pods.map do |pod|
            candidate = Support.deep_copy(pod)
            candidate["metadata"] ||= {}
            candidate["metadata"]["ownerReferences"] = Array(Support.value(candidate["metadata"], "ownerReferences", [])).reject do |reference|
              Support.ref_value(reference, "uid", nil).to_s == Support.uid(replica_set).to_s
            end
            operation_update(pod, candidate, descriptor: POD, reason: "replicaset pod release")
          end
          owned_pods -= released_pods
          alive = owned_pods.select { |pod| pod_alive?(pod) }
          desired = replica_count(replica_set)
          operations = adoption_operations + release_operations
          creation_batches = []
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
            operations.concat(create_operations)
            creation_batches = slow_start_batches(create_operations)
          elsif alive.length > desired
            delete_count = alive.length - desired
            operations.concat(delete_pods(alive, delete_count, related: related_pods(adapter, replica_set, all_pods), now: now))
          end
          # replica_set_utils.go calculateStatus: readiness is the Ready
          # condition, availability additionally honours minReadySeconds, and
          # both counters are omitempty in the API.
          min_ready_seconds = Support.integer(Support.value(Support.spec(replica_set), "minReadySeconds", 0), 0)
          ready_count = alive.count { |pod| Support.ready?(pod) }
          available = alive.count { |pod| Support.pod_available?(pod, min_ready_seconds, now) }
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
          status["readyReplicas"] = ready_count
          status["availableReplicas"] = available
          status["observedGeneration"] =
            Support.integer(Support.metadata(replica_set)["generation"], Support.integer(status["observedGeneration"], 0))
          status["terminatingReplicas"] = owned_pods.count do |pod|
            Support.value(Support.metadata(pod), "deletionTimestamp", nil) &&
              !%w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
          end
          # Upstream re-syncs after minReadySeconds so availability catches up
          # without a Pod event (replica_set.go syncReplicaSet).
          requeue_after = (min_ready_seconds.to_f if min_ready_seconds.positive? && ready_count == desired && available != desired)
          planned = result(replica_set, operations, status: status, batches: creation_batches)
          return planned if requeue_after.nil?

          ReconcileResult.new(operations: planned.operations, batches: planned.batches, status: planned.status,
                              events: planned.events, controller: planned.controller, key: planned.key,
                              requeue_after: requeue_after)
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
            siblings = begin
              list_children(adapter, DESCRIPTOR, Support.namespace(replica_set))
            rescue StandardError
              []
            end
            Array(siblings).each do |sibling|
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
      end

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

        # pkg/controller/statefulset/stateful_set_control.go updateStatefulSet.
        def plan(stateful_set, store: nil, pods: nil, revisions: nil, controller_revisions: nil,
                 pvcs: nil, claims: nil, now: nil, max_unavailable_stateful_set: nil, **_options)
          max_unavailable_gate = max_unavailable_stateful_set.nil? ? @max_unavailable_stateful_set : max_unavailable_stateful_set == true
          adapter = controller_adapter(store)
          pods ||= list_children(adapter, POD, Support.namespace(stateful_set))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          owned_pods = owned(stateful_set, pods)

          revisions = controller_revisions unless controller_revisions.nil?
          revisions = list_children(adapter, CONTROLLER_REVISION, Support.namespace(stateful_set)) if revisions.nil? && adapter
          pvcs = claims unless claims.nil?
          pvcs = list_children(adapter, PERSISTENT_VOLUME_CLAIM, Support.namespace(stateful_set)) if pvcs.nil? && adapter

          working_set = apply_rollback_annotation(stateful_set, revisions)
          desired = replica_count(working_set)
          start = start_ordinal(working_set)
          collision_count = Support.integer(Support.value(Support.status(stateful_set), "collisionCount", 0), 0)
          operations = []
          events = []
          revision_state = reconcile_revisions(working_set, revisions, owned_pods, collision_count)
          operations.concat(revision_state.fetch(:operations))
          update_revision = revision_state.fetch(:update)
          current_revision = revision_state.fetch(:current)
          collision_count = revision_state.fetch(:collision_count)
          current_set = apply_revision(working_set, current_revision)
          update_set = apply_revision(working_set, update_revision)
          min_ready_seconds = Support.integer(Support.value(Support.spec(working_set), "minReadySeconds", 0), 0)

          existing_by_ordinal = owned_pods.each_with_object({}) do |pod, result|
            ordinal = ordinal_for(pod, Support.name(working_set))
            result[ordinal] = pod if ordinal
          end
          pod_policy = Support.value(Support.spec(working_set), "podManagementPolicy", "OrderedReady").to_s
          raise ArgumentError, "unsupported StatefulSet podManagementPolicy #{pod_policy.inspect}" unless %w[OrderedReady Parallel].include?(pod_policy)

          monotonic = pod_policy == "OrderedReady"
          strategy = Support.value(Support.spec(working_set), "updateStrategy", {})
          strategy = {} unless strategy.is_a?(Hash)
          strategy_type = Support.value(strategy, "type", "RollingUpdate").to_s
          raise ArgumentError, "unsupported StatefulSet updateStrategy #{strategy_type.inspect}" unless %w[RollingUpdate OnDelete].include?(strategy_type)

          replicas = (start...(start + desired)).map { |ordinal| existing_by_ordinal[ordinal] }
          condemned = existing_by_ordinal.select { |ordinal, _pod| ordinal < start || ordinal >= start + desired }
            .sort_by { |ordinal, _pod| -ordinal }.map { |_ordinal, pod| pod }
          unavailable = ->(pod) { !Support.pod_available?(pod, min_ready_seconds, now) || terminating?(pod) }
          first_unavailable = replicas.compact.find { |pod| unavailable.call(pod) } ||
                              condemned.reverse.find { |pod| unavailable.call(pod) }

          status = Support.deep_copy(Support.status(stateful_set))
          status["observedGeneration"] = Support.integer(Support.metadata(stateful_set)["generation"],
                                                         Support.integer(status["observedGeneration"], 0))
          status["currentRevision"] = Support.name(current_revision)
          status["updateRevision"] = Support.name(update_revision)
          status["collisionCount"] = collision_count
          if Support.metadata(stateful_set).key?("deletionTimestamp")
            compute_replica_status!(status, replicas.compact + condemned, min_ready_seconds, current_revision, update_revision, now)
            return result(stateful_set, operations, status: compact_stateful_status(status), events: events)
          end

          volume_claim_templates = volume_claim_templates_for(working_set)
          # A direct planner invocation has no informer to list from.  An
          # explicitly omitted claim list still means the declared templates
          # must be materialized; an adapter-backed reconcile already supplied
          # the authoritative snapshot above.
          pvcs = [] if pvcs.nil? && volume_claim_templates.any?
          operations.concat(reconcile_claims(working_set, volume_claim_templates, pvcs, desired, start,
                                             existing_by_ordinal))

          # processReplica: create missing ordinals, restart terminal Pods, and
          # in OrderedReady mode stop at the first Pod that is not yet
          # Running, Ready, and Available.
          exited = false
          replicas.each_with_index do |pod, index|
            ordinal = start + index
            if pod.nil?
              source_set, revision_name = versioned_source(current_set, update_set, current_revision, update_revision, ordinal, start)
              candidate = stateful_pod_for(source_set, name: "#{Support.name(working_set)}-#{ordinal}",
                                                       template_value: template(source_set), revision_hash: revision_name,
                                                       ordinal: ordinal, claim_templates: volume_claim_templates)
              operations << operation_create(candidate, owner: working_set, descriptor: POD, reason: "statefulset scale up")
              events << {"type" => "Normal", "reason" => "SuccessfulCreate",
                         "message" => "Create Pod #{Support.name(candidate)} in StatefulSet #{Support.name(working_set)} successful"}
              if monotonic
                exited = true
                break
              end
              next
            end
            phase = Support.value(Support.status(pod), "phase", "").to_s
            if %w[Failed Succeeded].include?(phase)
              unless terminating?(pod)
                operations << operation_delete(pod, descriptor: POD, reason: "statefulset terminal pod restart")
                events << {"type" => "Normal", "reason" => "SuccessfulDelete",
                           "message" => "delete Pod #{Support.name(pod)} in StatefulSet #{Support.name(working_set)} successful"}
              end
              exited = true
              break
            end
            if monotonic && (terminating?(pod) || !running_and_ready?(pod) || !Support.pod_available?(pod, min_ready_seconds, now))
              exited = true
              break
            end
            next if volume_claim_templates.empty?

            candidate = stateful_pod_for(update_set, name: Support.name(pod), template_value: template(update_set),
                                                     revision_hash: Support.labels(pod)[REVISION_LABEL].to_s,
                                                     ordinal: ordinal, claim_templates: volume_claim_templates, existing: pod)
            storage_update = operation_update(pod, candidate, descriptor: POD, reason: "statefulset volume claim reconciliation")
            operations << storage_update if storage_update
          end

          # processCondemned: scale down from the highest ordinal, one Pod at a
          # time in OrderedReady mode, waiting for predecessors to be available.
          unless exited
            condemned.each do |pod|
              if terminating?(pod)
                break if monotonic

                next
              end
              if monotonic && pod != first_unavailable &&
                 (!running_and_ready?(pod) || !Support.pod_available?(pod, min_ready_seconds, now))
                break
              end

              operations << operation_delete(pod, descriptor: POD, reason: "statefulset scale down")
              events << {"type" => "Normal", "reason" => "SuccessfulDelete",
                         "message" => "delete Pod #{Support.name(pod)} in StatefulSet #{Support.name(working_set)} successful"}
              exited = true
              break
            end
          end

          compute_replica_status!(status, replicas.compact + condemned, min_ready_seconds, current_revision, update_revision, now)
          if !exited && strategy_type == "RollingUpdate"
            rolling = Support.value(strategy, "rollingUpdate", {})
            rolling = {} unless rolling.is_a?(Hash)
            partition = Support.integer(Support.value(rolling, "partition", 0), 0)
            update_min = partition
            targets = replicas.compact
            if max_unavailable_gate
              # MaxUnavailableStatefulSet semantics (updateStatefulSetAfterInvariantEstablished).
              max_unavailable = [Support.quantity(Support.value(rolling, "maxUnavailable", 1), desired, mode: :floor, default: 1), 1].max
              unavailable_pods = targets.count { |pod| unavailable.call(pod) }
              # statefulset_controller_statefulset_{max_unavailable,unavailable_replicas}:
              # recorded, as upstream, only with the MaxUnavailableStatefulSet gate on.
              gauge_labels = {"pod_management_policy" => Support.value(Support.spec(working_set), "podManagementPolicy", "OrderedReady").to_s,
                              "statefulset_name" => Support.name(working_set).to_s, "statefulset_namespace" => Support.namespace(working_set).to_s}
              ControllerMetrics.set("statefulset_controller_statefulset_max_unavailable", max_unavailable, gauge_labels)
              ControllerMetrics.set("statefulset_controller_statefulset_unavailable_replicas", unavailable_pods, gauge_labels)
              if unavailable_pods < max_unavailable
                budget = max_unavailable - unavailable_pods
                deleted = 0
                targets.each_with_index.to_a.reverse_each do |pod, index|
                  break if index < update_min || deleted >= budget
                  next unless Support.labels(pod)[REVISION_LABEL].to_s != Support.name(update_revision) && !terminating?(pod)

                  operations << operation_delete(pod, descriptor: POD, reason: "statefulset rolling update")
                  deleted += 1
                  status["currentReplicas"] = Support.integer(status["currentReplicas"], 0) - 1
                end
              end
            else
              targets.each_with_index.to_a.reverse_each do |pod, index|
                break if index < update_min

                if Support.labels(pod)[REVISION_LABEL].to_s != Support.name(update_revision) && !terminating?(pod)
                  operations << operation_delete(pod, descriptor: POD, reason: "statefulset rolling update")
                  status["currentReplicas"] = Support.integer(status["currentReplicas"], 0) - 1
                  break
                end
                break if unavailable.call(pod)
              end
            end
          end
          complete_rolling_update!(working_set, status, strategy_type, desired)
          result(stateful_set, operations, status: compact_stateful_status(status), events: events)
        end

        def scale(stateful_set, replicas, pods: nil, store: nil)
          candidate = Support.deep_copy(stateful_set)
          candidate["spec"] ||= {}
          candidate["spec"]["replicas"] = Integer(replicas)
          plan(candidate, pods: pods, store: store)
        end

        def rollback(stateful_set, revision:, pods: nil, store: nil, revisions: nil, controller_revisions: nil)
          adapter = controller_adapter(store)
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
          adapter = store || (self.store && StoreAdapter.new(self.store))
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

        def controller_adapter(store)
          candidate = store || self.store
          return nil unless candidate

          candidate.is_a?(StoreAdapter) ? candidate : StoreAdapter.new(candidate)
        end

        def start_ordinal(resource)
          ordinals = Support.value(Support.spec(resource), "ordinals", {})
          ordinals = {} unless ordinals.is_a?(Hash)
          Support.integer(Support.value(ordinals, "start", 0), 0)
        end

        def volume_claim_templates_for(resource)
          Array(Support.value(Support.spec(resource), "volumeClaimTemplates", [])).filter_map do |claim|
            next unless claim.is_a?(Hash)

            name = Support.name(claim)
            raise ArgumentError, "StatefulSet volumeClaimTemplates entries require metadata.name" if name.empty?

            Support.deep_copy(claim)
          end
        end

        def stateful_pod_for(owner, name:, template_value:, revision_hash:, ordinal:, claim_templates:, existing: nil)
          labels = {REVISION_LABEL => revision_hash.to_s, POD_NAME_LABEL => name.to_s,
                    POD_INDEX_LABEL => ordinal.to_s}
          candidate = if existing
                        Support.deep_copy(existing)
                      else
                        pod_for(owner, name: name, template_value: template_value, labels: labels)
                      end
          candidate["metadata"] ||= {}
          candidate["metadata"]["name"] = name
          candidate["metadata"]["namespace"] ||= Support.namespace(owner) if Support.namespace(owner)
          candidate["metadata"]["labels"] = Support.labels(candidate).merge(labels)
          candidate["spec"] ||= {}
          candidate["spec"]["hostname"] ||= name unless existing
          candidate["spec"]["subdomain"] ||= Support.value(Support.spec(owner), "serviceName", nil) unless existing
          update_storage_volumes(candidate, owner, claim_templates, ordinal)
          candidate
        end

        def update_storage_volumes(pod, owner, claim_templates, ordinal)
          return pod if claim_templates.empty?

          desired = claim_templates.map do |claim|
            {"name" => Support.name(claim), "persistentVolumeClaim" => {
              "claimName" => "#{Support.name(claim)}-#{Support.name(owner)}-#{ordinal}"
            }}
          end
          names = desired.map { |volume| volume["name"] }
          existing = Array(Support.value(Support.spec(pod), "volumes", [])).filter_map do |volume|
            next unless volume.is_a?(Hash)
            next if names.include?(Support.value(volume, "name", "").to_s)

            Support.deep_copy(volume)
          end
          pod["spec"]["volumes"] = desired + existing
          pod
        end

        def reconcile_claims(owner, templates, claims, desired, start, existing_by_ordinal)
          return [] if templates.empty? || claims.nil?

          existing = Array(claims).each_with_object({}) do |claim, result|
            result[Support.name(claim)] = claim if Support.kind(claim) == "PersistentVolumeClaim"
          end
          operations = []
          (start...(start + desired)).each do |ordinal|
            templates.each do |template_value|
              name = "#{Support.name(template_value)}-#{Support.name(owner)}-#{ordinal}"
              desired_claim = claim_for(owner, template_value, name, ordinal, scaled_down: false)
              current = existing[name]
              if current.nil?
                operations << operation_create(desired_claim, descriptor: PERSISTENT_VOLUME_CLAIM,
                                                              reason: "statefulset volume claim")
                next
              end

              candidate = claim_metadata_update(current, desired_claim, owner: owner)
              update = operation_update(current, candidate, descriptor: PERSISTENT_VOLUME_CLAIM,
                                                            reason: "statefulset volume claim retention policy")
              operations << update if update
            end
          end

          policy = pvc_retention_policy(owner)
          if policy.fetch(:when_scaled) == "Delete"
            existing.each_value do |claim|
              ordinal = ordinal_for_claim(claim, owner)
              next unless ordinal && (ordinal < start || ordinal >= start + desired)
              next unless existing_by_ordinal[ordinal]

              desired_claim = claim_for(owner, claim, Support.name(claim), ordinal, scaled_down: true,
                                                                                    pod: existing_by_ordinal[ordinal])
              candidate = claim_metadata_update(claim, desired_claim, owner: owner,
                                                                      pod: existing_by_ordinal[ordinal])
              update = operation_update(claim, candidate, descriptor: PERSISTENT_VOLUME_CLAIM,
                                                          reason: "statefulset scaled volume claim retention policy")
              operations << update if update
            end
          end
          operations
        end

        def claim_for(owner, template_value, name, _ordinal, scaled_down:, pod: nil)
          candidate = Support.deep_copy(template_value)
          candidate["apiVersion"] ||= "v1"
          candidate["kind"] = "PersistentVolumeClaim"
          candidate["metadata"] ||= {}
          candidate["metadata"]["name"] = name
          candidate["metadata"]["namespace"] ||= Support.namespace(owner) if Support.namespace(owner)
          selector = Support.value(Support.spec(owner), "selector", {})
          selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && selector.key?("matchLabels")
          labels = Support.value(candidate["metadata"], "labels", {})
          labels = {} unless labels.is_a?(Hash)
          candidate["metadata"]["labels"] = labels.merge(selector.is_a?(Hash) ? selector : {})
          candidate["metadata"]["ownerReferences"] = desired_claim_owner_references(
            owner, candidate, scaled_down: scaled_down, pod: pod
          )
          candidate
        end

        def claim_metadata_update(current, desired, owner:, pod: nil)
          candidate = Support.deep_copy(current)
          candidate["metadata"] ||= {}
          desired_metadata = Support.metadata(desired)
          candidate["metadata"]["labels"] = Support.deep_copy(Support.value(desired_metadata, "labels", {}))
          desired_refs = Array(Support.value(desired_metadata, "ownerReferences", []))
          managed = [[Support.kind(owner), Support.name(owner)], ["Pod", Support.name(pod)]]
          existing_refs = Support.owner_references(current)
          retained_refs = existing_refs.reject do |reference|
            managed.include?([Support.ref_value(reference, "kind", ""),
                              Support.ref_value(reference, "name", "")])
          end
          candidate["metadata"]["ownerReferences"] = retained_refs + Support.deep_copy(desired_refs)
          candidate
        end

        def desired_claim_owner_references(owner, _claim, scaled_down:, pod: nil)
          policy = pvc_retention_policy(owner)
          retain = []
          return retain if policy.fetch(:when_deleted) == "Retain" && policy.fetch(:when_scaled) == "Retain"

          return [Support.owner_reference(pod)] if scaled_down && policy.fetch(:when_scaled) == "Delete" && pod
          return [Support.owner_reference(owner)] if policy.fetch(:when_deleted) == "Delete"

          retain
        end

        def pvc_retention_policy(resource)
          raw = Support.value(Support.spec(resource), "persistentVolumeClaimRetentionPolicy", {})
          raw = {} unless raw.is_a?(Hash)
          when_deleted = Support.value(raw, "whenDeleted", "Retain").to_s
          when_scaled = Support.value(raw, "whenScaled", "Retain").to_s
          unless %w[Retain Delete].include?(when_deleted) && %w[Retain Delete].include?(when_scaled)
            raise ArgumentError, "StatefulSet PVC retention policy must use Retain or Delete"
          end

          {when_deleted: when_deleted, when_scaled: when_scaled}
        end

        def ordinal_for_claim(claim, owner)
          prefix = "-#{Support.name(owner)}-"
          match = Support.name(claim).match(/#{Regexp.escape(prefix)}(\d+)\z/)
          match && Integer(match[1])
        rescue ArgumentError
          nil
        end

        def revision_data_for(resource)
          spec = Support.spec(resource)
          template_value = Support.deep_copy(Support.value(spec, "template", {}))
          template_value["$patch"] = "replace" if template_value.is_a?(Hash)
          {"spec" => {"template" => template_value}}
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

        # getStatefulSetRevisions + truncateHistory.
        def reconcile_revisions(owner, revisions, pods, collision_count)
          data = revision_data_for(owner)
          if revisions.nil?
            update = revision_for(owner, data, Support.controller_revision_hash(data, collision_count), 1)
            return {current: update, update: update, operations: [], collision_count: collision_count}
          end

          owned_revisions = Array(revisions).select do |revision|
            next false unless Support.kind(revision) == "ControllerRevision"
            next true if Support.owner_reference_matches?(owner, revision, controller: true)

            Support.namespace(revision) == Support.namespace(owner) &&
              Support.name(revision).start_with?("#{Support.name(owner)}-")
          end.sort_by { |revision| [revision_number(revision), Support.creation_time(revision).to_f, Support.name(revision)] }
          next_number = owned_revisions.empty? ? 1 : revision_number(owned_revisions.last) + 1
          operations = []
          equivalent = owned_revisions.select { |revision| revision_data_equal?(revision, data) }
          if equivalent.any? && Support.name(equivalent.last) == Support.name(owned_revisions.last)
            update_revision = owned_revisions.last
          elsif equivalent.any?
            # Rolling back: the equivalent revision becomes the newest one.
            update_revision = Support.deep_copy(equivalent.last)
            update_revision["revision"] = next_number
            operations << operation_update(equivalent.last, update_revision, descriptor: CONTROLLER_REVISION,
                                                                             reason: "statefulset controller revision rollback")
          elsif owned_revisions.any? && set_matches_latest_revision?(owner, data, owned_revisions.last)
            # StatefulSetSemanticRevisionComparison: the latest revision, once
            # restored and defaulted, is this spec -- only its stored form
            # differs (a field defaulted since it was written).
            update_revision = owned_revisions.last
          else
            loop do
              hash = Support.controller_revision_hash(data, collision_count)
              update_revision = revision_for(owner, data, hash, next_number)
              colliding = owned_revisions.find { |revision| Support.name(revision) == Support.name(update_revision) }
              break if colliding.nil?

              # Name collision with different content: bump the probe, as
              # history.CreateControllerRevision does.
              collision_count += 1
            end
            operations << operation_create(update_revision, descriptor: CONTROLLER_REVISION, owner: owner,
                                                            reason: "statefulset controller revision")
            owned_revisions << update_revision
          end

          current_name = Support.value(Support.status(owner), "currentRevision", nil).to_s
          current = owned_revisions.find { |revision| Support.name(revision) == current_name } || update_revision
          history_limit = Support.integer(Support.value(Support.spec(owner), "revisionHistoryLimit", 10), 10)
          live = [Support.name(current), Support.name(update_revision)] + pods.map { |pod| Support.labels(pod)[REVISION_LABEL].to_s }
          history = owned_revisions.reject { |revision| live.include?(Support.name(revision)) }
          if history_limit >= 0 && history.length > history_limit
            history.first(history.length - history_limit).each do |revision|
              operations << operation_delete(revision, descriptor: CONTROLLER_REVISION, reason: "statefulset revision history limit")
            end
          end
          {current: current, update: update_revision, operations: operations, collision_count: collision_count}
        end

        # setMatchesLatestExistingRevision (StatefulSetSemanticRevisionComparison,
        # Beta on): would restoring +latest+ into the set, with defaults
        # applied, produce +data+?  A positive answer is remembered per set
        # UID, generation and revision resourceVersion.
        REVISION_EQUALITY_CACHE_SIZE = 10_000

        def set_matches_latest_revision?(owner, data, latest)
          key = [Support.uid(owner), Support.value(Support.metadata(owner), "generation", nil),
                 Support.value(Support.metadata(latest), "resourceVersion", nil)]
          @revision_equality ||= {}
          return true if @revision_equality.key?(key)

          restored = apply_revision(owner, latest)
          restored = default_stateful_set(restored)
          return false unless Support.canonical(revision_data_for(restored)) == Support.canonical(data)

          @revision_equality.delete(@revision_equality.keys.first) while @revision_equality.size >= REVISION_EQUALITY_CACHE_SIZE
          @revision_equality[key] = true
          true
        rescue StandardError
          false
        end

        # legacyscheme.Scheme.Default for apps/v1 StatefulSet.
        def default_stateful_set(object)
          @stateful_set_definition ||= begin
            require File.expand_path("../../../generated/ruby/kubernetes_types", __dir__)
            Rubernetes::Generated.definition_for("io.k8s.api.apps.v1.StatefulSet")
          rescue LoadError, StandardError
            false
          end
          return object unless @stateful_set_definition

          defaulting = @stateful_set_definition.respond_to?(:defaulting) ? @stateful_set_definition.defaulting : nil
          defaulted = if defaulting.respond_to?(:apply_hash)
                        defaulting.apply_hash(object, kubernetes_admission_defaults: true)
                      else
                        Schema::Defaulting.apply(@stateful_set_definition, object, kubernetes_admission_defaults: true)
                      end
          Support.deep_copy(defaulted)
        rescue StandardError
          object
        end

        # history.NewControllerRevision with the StatefulSet annotations copied.
        def revision_for(owner, data, revision_hash, number)
          template_labels = Support.value(Support.value(Support.value(data, "spec", {}), "template", {}), "metadata", {})
          template_labels = Support.value(template_labels, "labels", {})
          template_labels = {} unless template_labels.is_a?(Hash)
          revision = {
            "apiVersion" => "apps/v1", "kind" => "ControllerRevision",
            "metadata" => {"name" => "#{Support.name(owner)}-#{revision_hash}",
                           "namespace" => Support.namespace(owner),
                           "labels" => Support.deep_copy(template_labels).merge("controller.kubernetes.io/hash" => revision_hash),
                           "ownerReferences" => [Support.owner_reference(owner)]},
            "revision" => number,
            "data" => Support.deep_copy(data)
          }
          annotations = Support.annotations(owner)
          revision["metadata"]["annotations"] = Support.deep_copy(annotations) unless annotations.empty?
          revision
        end

        def revision_data_equal?(revision, data)
          Support.canonical(revision_data(revision)) == Support.canonical(data)
        end

        def revision_data(revision)
          raw = Support.value(revision, "data", nil)
          raw = JSON.parse(raw) if raw.is_a?(String)
          return raw if raw.is_a?(Hash)

          spec = Support.value(revision, "spec", nil)
          spec.is_a?(Hash) ? {"spec" => Support.deep_copy(spec)} : {}
        rescue JSON::ParserError
          {}
        end

        def revision_number(revision)
          Support.integer(Support.value(revision, "revision", nil),
                          Support.integer(Support.annotations(revision)["controller.kubernetes.io/revision"], 0))
        end

        def ensure_revision_owner(revision, owner)
          candidate = Support.deep_copy(revision)
          candidate["metadata"] ||= {}
          candidate["metadata"]["ownerReferences"] = [Support.owner_reference(owner)]
          candidate
        end

        def find_revision(revisions, revision)
          text = revision.to_s
          Array(revisions).select { |candidate| Support.kind(candidate) == "ControllerRevision" }.find do |candidate|
            Support.name(candidate) == text || revision_number(candidate).to_s == text ||
              Support.labels(candidate)[REVISION_LABEL].to_s == text ||
              Support.name(candidate).end_with?("-#{text}")
          end
        end

        def apply_revision(resource, revision)
          data = revision_data(revision)
          revision_spec = Support.value(data, "spec", data)
          return Support.deep_copy(resource) unless revision_spec.is_a?(Hash)

          candidate = Support.deep_copy(resource)
          candidate["spec"] ||= {}
          %w[template updateStrategy podManagementPolicy ordinals volumeClaimTemplates].each do |field|
            next unless revision_spec.key?(field)

            candidate["spec"][field] = Support.deep_copy(revision_spec[field])
          end
          candidate
        end

        def apply_rollback_annotation(resource, revisions)
          annotation = Support.annotations(resource)["statefulset.kubernetes.io/rollback-to"]
          return resource if annotation.to_s.empty? || revisions.nil?

          revision = find_revision(revisions, annotation)
          raise ArgumentError, "StatefulSet revision #{annotation.inspect} was not found" unless revision

          candidate = apply_revision(resource, revision)
          candidate["metadata"] ||= {}
          candidate["metadata"]["annotations"] = Support.annotations(candidate).dup
          candidate["metadata"]["annotations"].delete("statefulset.kubernetes.io/rollback-to")
          candidate
        end

        def ordinal_for(pod, prefix)
          label = Support.labels(pod)["controller.kubernetes.io/ordinal"]
          return Integer(label) if label && label.to_s.match?(/\A\d+\z/)

          match = Support.name(pod).match(/\A#{Regexp.escape(prefix)}-(\d+)\z/)
          match && Integer(match[1])
        rescue ArgumentError
          nil
        end
      end

      # DaemonSet lives in its own file; it depends on the shared
      # WorkloadController helpers defined above.
      require_relative "daemonset_controller"

      # The Job controller lives in its own file; it depends on the shared
      # WorkloadController helpers defined above.
      require_relative "job_controller"

      class CronJobController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("CronJob")
        JOB = ResourceDescriptor.parse("Job")

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          super
        end

        SCHEDULED_TIMESTAMP_ANNOTATION = "batch.kubernetes.io/cronjob-scheduled-timestamp"
        DEFAULT_SUCCESSFUL_JOBS_HISTORY_LIMIT = 3
        DEFAULT_FAILED_JOBS_HISTORY_LIMIT = 1
        NEXT_SCHEDULE_DELAY_SECONDS = 0.1

        # pkg/controller/cronjob/cronjob_controllerv2.go sync: history cleanup,
        # then syncCronJob for the most recent unmet schedule time.
        def plan(cron_job, store: nil, jobs: nil, now: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          jobs ||= list_children(adapter, JOB, Support.namespace(cron_job))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          owned_jobs = owned(cron_job, jobs)
          spec_value = Support.spec(cron_job)
          status = Support.deep_copy(Support.status(cron_job))
          # The stored list is what the previous sync saw; it is used to decide
          # which transitions to report.  The list this sync publishes is
          # rebuilt from the Jobs actually observed, because a pure planner
          # cannot know the uid of a Job it has only asked to create: writing
          # a uid-less placeholder and then matching on uid dropped every
          # reference on the following sync, leaving status.active empty for
          # good -- which also disabled the Forbid concurrency policy.
          previous_active = Array(status["active"]).grep(Hash)
            .map { |reference| Support.deep_copy(reference) }
          active = previous_active.map { |reference| Support.deep_copy(reference) }
          operations = []
          events = []
          requeue_after = nil

          deleted_uids = cleanup_finished_jobs(cron_job, owned_jobs, active, operations, events)
          owned_jobs = owned_jobs.reject { |job| deleted_uids.include?(Support.uid(job)) }

          # syncCronJob: reconcile the active list against the observed Jobs.
          children = owned_jobs.to_h { |job| [Support.uid(job), job] }
          active = owned_jobs.reject { |job| job_finished_type(job) }.map { |job| job_reference(job) }
          owned_jobs.each do |job|
            # A reference this planner wrote before the Job existed carries no
            # uid, so a Job it did create is recognised by name as well.
            in_active = previous_active.any? do |reference|
              uid = Support.ref_value(reference, "uid", nil).to_s
              uid.empty? ? Support.ref_value(reference, "name", "").to_s == Support.name(job) : uid == Support.uid(job)
            end
            finished_type = job_finished_type(job)
            if !in_active && finished_type.nil?
              events << {"type" => "Warning", "reason" => "UnexpectedJob",
                         "message" => "Saw a job that the controller did not create or forgot: #{Support.name(job)}"}
            elsif finished_type
              if in_active
                events << {"type" => "Normal", "reason" => "SawCompletedJob",
                           "message" => "Saw completed job: #{Support.name(job)}, condition: #{finished_type}"}
              end
              if finished_type == "Complete"
                completion_time = Support.parse_time(Support.value(Support.status(job), "completionTime", nil))
                last_successful = Support.parse_time(status["lastSuccessfulTime"])
                if completion_time && (last_successful.nil? || completion_time > last_successful)
                  status["lastSuccessfulTime"] = Support.value(Support.status(job), "completionTime", nil)
                end
              end
            end
          end
          # A Job the previous sync listed as active that no longer exists is
          # reported once; the rebuilt list already excludes it.
          previous_active.each do |reference|
            uid = Support.ref_value(reference, "uid", nil).to_s
            next if uid.empty? || children.key?(uid)

            events << {"type" => "Normal", "reason" => "MissingJob",
                       "message" => "Active job went missing: #{Support.ref_value(reference, "name", "")}"}
          end

          unless Support.metadata(cron_job).key?("deletionTimestamp") || Support.value(spec_value, "suspend", false) == true
            time_zone = Support.value(spec_value, "timeZone", nil)
            if !time_zone.nil? && !supported_time_zone?(time_zone)
              events << {"type" => "Warning", "reason" => "UnknownTimeZone", "message" => "invalid timeZone: #{time_zone.to_s.inspect}"}
            else
              fields = cron_fields(Support.value(spec_value, "schedule", ""))
              if fields.nil?
                events << {"type" => "Warning", "reason" => "UnparseableSchedule",
                           "message" => "unparseable schedule: #{Support.value(spec_value, "schedule", "").to_s.inspect}"}
              else
                offset = time_zone_offset(time_zone)
                scheduled_at, missed = next_schedule_time(cron_job, status, now, fields, offset, events)
                policy = Support.value(spec_value, "concurrencyPolicy", "Allow").to_s
                raise ArgumentError, "unsupported CronJob concurrencyPolicy #{policy.inspect}" unless %w[Allow Forbid
                                                                                                         Replace].include?(policy)

                requeue_after = next_schedule_delay(cron_job, status, now, fields, offset)
                starting_deadline = Support.value(spec_value, "startingDeadlineSeconds", nil)
                if scheduled_at.nil?
                  # No unmet start time.
                elsif !starting_deadline.nil? && scheduled_at + Support.integer(starting_deadline, 0) < now
                  events << {"type" => "Warning", "reason" => "MissSchedule",
                             "message" => "Missed scheduled time to start a job: #{scheduled_at.utc.strftime("%a, %d %b %Y %H:%M:%S %z")}"}
                elsif active.any? { |reference| Support.ref_value(reference, "name", "") == job_name(cron_job, scheduled_at) } ||
                      Support.parse_time(status["lastScheduleTime"]) == scheduled_at
                  # This scheduled time was already processed.
                elsif policy == "Forbid" && active.any?
                  events << {"type" => "Normal", "reason" => "JobAlreadyActive",
                             "message" => "Not starting job because prior execution is running and concurrency policy is Forbid"}
                else
                  if policy == "Replace"
                    active.each do |reference|
                      job = children[Support.ref_value(reference, "uid", nil).to_s]
                      next unless job

                      operations << operation_delete(job, descriptor: JOB, reason: "cronjob replace")
                      events << {"type" => "Normal", "reason" => "SuccessfulDelete", "message" => "Deleted job #{Support.name(job)}"}
                    end
                    active = []
                  end
                  candidate = job_from_template(cron_job, scheduled_at, offset)
                  existing = owned_jobs.find { |job| Support.name(job) == Support.name(candidate) }
                  if existing
                    active << job_reference(existing) unless active.any? do |reference|
                      Support.ref_value(reference, "uid", nil).to_s == Support.uid(existing)
                    end
                  else
                    # metrics.CronJobCreationSkew: the new Job's creationTimestamp
                    # (whole seconds) less the time it was scheduled for.
                    scheduled_for = scheduled_at
                    operations << operation_create(candidate, owner: cron_job, descriptor: JOB,
                                                              reason: "cron schedule").observed do |succeeded, _|
                      next unless succeeded

                      ControllerMetrics.observe("cronjob_controller_job_creation_skew_duration_seconds",
                                                Time.at(Time.now.to_i).utc - scheduled_for)
                    end
                    events << {"type" => "Normal", "reason" => "SuccessfulCreate", "message" => "Created job #{Support.name(candidate)}"}
                    active << job_reference(candidate)
                  end
                  status["lastScheduleTime"] = scheduled_at.utc.iso8601(6)
                  _unused = missed
                end
              end
            end
          end

          if active.empty?
            status.delete("active")
          else
            status["active"] = active
          end
          planned = result(cron_job, operations, status: status, events: events, force_status: !cron_job.key?("status"))
          return planned if requeue_after.nil?

          ReconcileResult.new(operations: planned.operations, batches: planned.batches, status: planned.status,
                              events: planned.events, controller: planned.controller, key: planned.key,
                              requeue_after: requeue_after)
        end

        def scale(cron_job, _replicas, **)
          plan(cron_job, **)
        end

        def delete(cron_job, jobs: nil, store: nil, orphan: false)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          jobs ||= list_children(adapter, JOB, Support.namespace(cron_job))
          operations = orphan ? [] : owned(cron_job, jobs).map { |job| operation_delete(job, descriptor: JOB, reason: "cronjob deletion") }
          operations << operation_delete(cron_job, descriptor: DESCRIPTOR, reason: "cronjob deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        private

        # cleanupFinishedJobs / removeOldestJobs: finished Jobs beyond the
        # history limits are deleted oldest-first by status.startTime.
        def cleanup_finished_jobs(cron_job, jobs, active, operations, events)
          spec_value = Support.spec(cron_job)
          successful_limit = Support.integer(Support.value(spec_value, "successfulJobsHistoryLimit", DEFAULT_SUCCESSFUL_JOBS_HISTORY_LIMIT),
                                             DEFAULT_SUCCESSFUL_JOBS_HISTORY_LIMIT)
          failed_limit = Support.integer(Support.value(spec_value, "failedJobsHistoryLimit", DEFAULT_FAILED_JOBS_HISTORY_LIMIT),
                                         DEFAULT_FAILED_JOBS_HISTORY_LIMIT)
          successful = jobs.select { |job| job_finished_type(job) == "Complete" }
          failed = jobs.select { |job| job_finished_type(job) == "Failed" }
          deleted = []
          [[successful, successful_limit], [failed, failed_limit]].each do |group, limit|
            to_delete = group.length - limit
            next if to_delete <= 0

            group.sort_by { |job| job_start_sort_key(job) }.first(to_delete).each do |job|
              operations << operation_delete(job, descriptor: JOB, reason: "cronjob history limit")
              events << {"type" => "Normal", "reason" => "SuccessfulDelete", "message" => "Deleted job #{Support.name(job)}"}
              active.reject! { |reference| Support.ref_value(reference, "uid", nil).to_s == Support.uid(job) }
              deleted << Support.uid(job)
            end
          end
          deleted
        end

        def job_start_sort_key(job)
          start = Support.parse_time(Support.value(Support.status(job), "startTime", nil))
          [start ? 0 : 1, start ? start.to_f : 0.0, Support.name(job)]
        end

        def job_finished_type(job)
          condition = Array(Support.value(Support.status(job), "conditions", [])).find do |value|
            %w[Complete Failed].include?(Support.value(value, "type", "").to_s) && Support.value(value, "status", "").to_s == "True"
          end
          condition && Support.value(condition, "type", "").to_s
        end

        # getJobName: the schedule time in minutes since the epoch keeps the
        # name deterministic for one nominal start time.
        def job_name(cron_job, scheduled_at)
          "#{Support.name(cron_job)}-#{scheduled_at.to_i / 60}"
        end

        # getJobFromTemplate2
        def job_from_template(cron_job, scheduled_at, offset)
          job_template = Support.value(Support.spec(cron_job), "jobTemplate", {})
          job_template = {} unless job_template.is_a?(Hash)
          job_metadata = Support.value(job_template, "metadata", {})
          job_metadata = {} unless job_metadata.is_a?(Hash)
          labels = Support.value(job_metadata, "labels", {})
          annotations = Support.value(job_metadata, "annotations", {})
          metadata = {"name" => job_name(cron_job, scheduled_at), "namespace" => Support.namespace(cron_job),
                      "annotations" => (annotations.is_a?(Hash) ? Support.deep_copy(annotations) : {}).merge(
                        SCHEDULED_TIMESTAMP_ANNOTATION => (offset == "+00:00" ? scheduled_at.utc.iso8601 : scheduled_at.getlocal(offset).iso8601)
                      )}
          metadata["labels"] = Support.deep_copy(labels) if labels.is_a?(Hash) && !labels.empty?
          job_spec = Support.value(job_template, "spec", {})
          candidate = {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => metadata,
                       "spec" => job_spec.is_a?(Hash) ? Support.deep_copy(job_spec) : {}}
          with_owner_metadata(candidate, cron_job)
        end

        def job_reference(job)
          reference = {"apiVersion" => "batch/v1", "kind" => "Job", "name" => Support.name(job),
                       "namespace" => Support.namespace(job), "uid" => Support.uid(job),
                       "resourceVersion" => Support.value(Support.metadata(job), "resourceVersion", nil)}
          reference.reject { |_key, value| value.nil? || value.to_s.empty? }
        end

        def supported_time_zone?(value)
          text = value.to_s
          text.empty? || %w[UTC Etc/UTC Z].include?(text) || text.match?(/\A[+-]\d{2}:\d{2}\z/)
        end

        def time_zone_offset(value)
          text = value.to_s
          text.match?(/\A[+-]\d{2}:\d{2}\z/) ? text : "+00:00"
        end

        def cron_fields(schedule)
          expression = schedule.to_s.strip
          case expression
          when "@hourly" then expression = "0 * * * *"
          when "@daily", "@midnight" then expression = "0 0 * * *"
          when "@weekly" then expression = "0 0 * * 0"
          when "@monthly" then expression = "0 0 1 * *"
          when "@yearly", "@annually" then expression = "0 0 1 1 *"
          end
          fields = expression.split(/\s+/)
          return nil unless fields.length == 5
          return nil unless [[0, 0..59], [1, 0..23], [2, 1..31], [3, 1..12], [4, 0..6]].all? do |index, range|
            cron_field_valid?(fields[index], range)
          end

          fields
        end

        def cron_field_valid?(field, range)
          return true if ["*", "?"].include?(field)

          field.split(",").all? do |part|
            base, step = part.split("/", 2)
            next false if step && !step.match?(/\A\d+\z/)
            next true if base == "*"

            first, last = base.split("-", 2)
            [first, last].compact.all? { |value| value.match?(/\A\d+\z/) && range.cover?(Integer(value)) }
          end
        end

        # cron.Schedule.Next: the first minute strictly after `after` that
        # matches every field.  Day-of-month and day-of-week are OR-ed when
        # both are restricted, as in robfig/cron's standard parser.
        def cron_next(fields, after, offset, limit_days: 366)
          minute, hour, day, month, weekday = fields
          cursor = after.getlocal(offset)
          cursor = Time.new(cursor.year, cursor.month, cursor.day, cursor.hour, cursor.min, 0, offset) + 60
          deadline = cursor + (limit_days * 86_400)
          while cursor <= deadline
            day_match = cron_field_match?(day, cursor.day, 1..31)
            weekday_match = cron_field_match?(weekday, cursor.wday, 0..6)
            day_restricted = day != "*" && day != "?"
            weekday_restricted = weekday != "*" && weekday != "?"
            calendar_match = day_restricted && weekday_restricted ? (day_match || weekday_match) : (day_match && weekday_match)
            if calendar_match && cron_field_match?(month, cursor.month, 1..12) &&
               cron_field_match?(hour, cursor.hour, 0..23) && cron_field_match?(minute, cursor.min, 0..59)
              return cursor.utc
            end

            cursor += 60
          end
          nil
        end

        # utils.go mostRecentScheduleTime + nextScheduleTime: the single most
        # recent unmet schedule, with a TooManyMissedTimes warning past 100.
        def next_schedule_time(cron_job, status, now, fields, offset, events)
          earliest = Support.parse_time(status["lastScheduleTime"]) || Support.creation_time(cron_job) || Time.at(0).utc
          starting_deadline = Support.value(Support.spec(cron_job), "startingDeadlineSeconds", nil)
          unless starting_deadline.nil?
            deadline = now - Support.integer(starting_deadline, 0)
            earliest = deadline if deadline > earliest
          end
          t1 = cron_next(fields, earliest, offset)
          return [nil, 0] if t1.nil? || now < t1

          t2 = cron_next(fields, t1, offset)
          return [t1, 0] if t2.nil? || now < t2

          between = (t2 - t1).round
          raise ArgumentError, "time difference between two schedules is less than 1 second" if between < 1

          missed = ((now - t1).to_i / between) + 1
          potential_earliest = t1 + ((missed - 2) * between)
          most_recent = nil
          cursor = cron_next(fields, potential_earliest, offset)
          while cursor && cursor <= now
            most_recent = cursor
            cursor = cron_next(fields, cursor, offset)
          end
          if missed > 100
            events << {"type" => "Warning", "reason" => "TooManyMissedTimes",
                       "message" => "too many missed start times. Set or decrease .spec.startingDeadlineSeconds or check clock skew"}
          end
          [most_recent, missed]
        end

        # utils.go nextScheduleTimeDuration
        def next_schedule_delay(cron_job, status, now, fields, offset)
          earliest = Support.parse_time(status["lastScheduleTime"]) || Support.creation_time(cron_job) || Time.at(0).utc
          starting_deadline = Support.value(Support.spec(cron_job), "startingDeadlineSeconds", nil)
          unless starting_deadline.nil?
            deadline = now - Support.integer(starting_deadline, 0)
            earliest = deadline if deadline > earliest
          end
          next_time = cron_next(fields, [earliest, now].max, offset)
          return nil if next_time.nil?

          [(next_time - now) + NEXT_SCHEDULE_DELAY_SECONDS, 0.0].max
        end

        def cron_field_match?(field, value, range)
          return true if ["*", "?"].include?(field)

          field.split(",").any? do |part|
            if part.include?("/")
              base, raw_step = part.split("/", 2)
              step = Integer(raw_step)
              next false unless step.positive?

              first, last = if base == "*"
                              [range.begin, range.end]
                            elsif base.include?("-")
                              base.split("-", 2).map(&:to_i)
                            else
                              [Integer(base), Integer(base)]
                            end
              value.between?(first, last) && ((value - first) % step).zero?
            elsif part.include?("-")
              first, last = part.split("-", 2).map(&:to_i)
              value.between?(first, last)
            else
              Integer(part) == value
            end
          end
        rescue ArgumentError
          false
        end
      end

      class NodeController < BaseController
        DESCRIPTOR = ResourceDescriptor.parse("Node")
        POD = ResourceDescriptor.parse("Pod")
        LEASE = ResourceDescriptor.parse("Lease")
        NODE_LEASE_NAMESPACE = "kube-node-lease"
        HEARTBEAT_GRACE_SECONDS = 40.0
        NOT_READY_TAINT_DELAY_SECONDS = 5 * 60.0

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          @heartbeat_grace_seconds = options.delete(:heartbeat_grace_seconds) || HEARTBEAT_GRACE_SECONDS
          @taint_delay_seconds = options.delete(:taint_delay_seconds) || NOT_READY_TAINT_DELAY_SECONDS
          super
        end

        def plan(node, store: nil, pods: nil, now: nil, lease: nil, **_options)
          health_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= adapter ? adapter.list(POD, namespace: :all) : []
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          ready_condition = Support.condition(node, "Ready") || {}
          # The node lease is the primary heartbeat (monitorNodeHealth observes
          # the lease's renewTime and only falls back to the condition stamp).
          # Reading the condition alone declares a healthy node stale as soon as
          # its status stops changing, which taints it out of the scheduler.
          heartbeat = [Support.parse_time(Support.value(ready_condition, "lastHeartbeatTime", nil)),
                       Support.parse_time(Support.value(ready_condition, "lastTransitionTime", nil)),
                       node_lease_renewal(node, adapter, lease)].compact.max
          ready_status = Support.value(ready_condition, "status", "Unknown").to_s
          stale = heartbeat.nil? || (now - heartbeat) > @heartbeat_grace_seconds
          desired_status = stale ? "Unknown" : ready_status
          operations = []
          candidate = Support.deep_copy(node)
          candidate["status"] ||= {}
          conditions = Array(candidate["status"]["conditions"]).map { |condition| Support.deep_copy(condition) }
          desired = conditions.find { |condition| Support.value(condition, "type", "") == "Ready" }
          if desired
            desired["status"] = desired_status
            desired["reason"] = stale ? "NodeStatusUnknown" : Support.value(desired, "reason", "")
          else
            conditions << {"type" => "Ready", "status" => desired_status,
                           "reason" => stale ? "NodeStatusUnknown" : "NodeReady"}
          end
          candidate["status"]["conditions"] = conditions
          unhealthy_since = Support.parse_time(Support.value(ready_condition, "lastTransitionTime", nil)) || heartbeat || now
          unhealthy = %w[Unknown False].include?(desired_status) && (now - unhealthy_since) >= @taint_delay_seconds
          controller_taint_keys = ["node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"]
          taints = Array(Support.value(Support.spec(candidate), "taints", [])).map { |taint| Support.deep_copy(taint) }
          taints.reject! do |taint|
            controller_taint_keys.include?(Support.value(taint, "key", "").to_s) &&
              Support.value(taint, "effect", "") == "NoExecute"
          end
          if unhealthy
            candidate["spec"] ||= {}
            key = desired_status == "False" ? "node.kubernetes.io/not-ready" : "node.kubernetes.io/unreachable"
            unless taints.any? { |taint| Support.value(taint, "key", "") == key && Support.value(taint, "effect", "") == "NoExecute" }
              taints << {"key" => key, "effect" => "NoExecute"}
            end
            candidate["spec"]["taints"] = taints
            eviction_taint = taints.find do |taint|
              Support.value(taint, "key", "") == key && Support.value(taint, "effect", "") == "NoExecute"
            end
          elsif !Array(Support.value(Support.spec(candidate), "taints", [])).empty?
            candidate["spec"] ||= {}
            candidate["spec"]["taints"] = taints
          end
          # doNoScheduleTaintingPass: the NoSchedule condition taints are a pure
          # function of the node's conditions plus spec.unschedulable.  Without
          # this the not-ready:NoSchedule taint that admission stamps on a new
          # node is never removed once it becomes Ready, and nothing can ever be
          # scheduled onto it.
          candidate["spec"] ||= {}
          candidate["spec"]["taints"] = reconcile_no_schedule_taints(candidate,
                                                                     Array(Support.value(Support.spec(candidate), "taints", [])))
          candidate["spec"].delete("taints") if candidate["spec"]["taints"].empty? &&
                                                Array(Support.value(Support.spec(node), "taints", [])).empty?
          # Two writes, as upstream issues them: the Ready condition through
          # the status subresource (tryUpdateNodeHealth -> UpdateStatus) and
          # the taints through the primary resource (AddOrUpdateTaintOnNode).
          # A single PUT of the whole object would carry both, but the API
          # server ignores status on the primary URL: the taint landed and the
          # node stayed "Ready", so the unreachable:NoSchedule taint was never
          # derived and the scheduler kept placing Pods that the NoExecute
          # taint then evicted, over and over.
          status_update = operation_status(node, Support.status(candidate), descriptor: DESCRIPTOR, reason: "node heartbeat/status")
          operations << status_update if status_update
          # The taint write is issued only when spec/metadata changed; it
          # carries the new status too, so an in-memory store (which honours
          # status on a primary write) ends up identical to the API server's
          # view and a second pass over the result is a no-op.
          spec_candidate = Support.deep_copy(candidate)
          spec_candidate["status"] = Support.deep_copy(Support.status(node))
          update = spec_candidate == node ? nil : operation_update(node, candidate, descriptor: DESCRIPTOR, reason: "node taints")
          zone = self.class.zone_key(node)
          if update && unhealthy && !self.class.eviction_tainted?(node)
            # doNoExecuteTaintingPass: a node newly tainted for eviction.
            update = update.observed do |succeeded, _|
              ControllerMetrics.increment("node_collector_evictions_total", {"zone" => zone}) if succeeded
            end
          end
          operations << update if update
          record_zone_health(Support.name(node), zone, desired_status == "True")
          ControllerMetrics.observe("node_collector_update_node_health_duration_seconds",
                                    Process.clock_gettime(Process::CLOCK_MONOTONIC) - health_started)
          if unhealthy
            owned_pods = Array(pods).select { |pod| Support.value(Support.spec(pod), "nodeName", nil).to_s == Support.name(node) }
            owned_pods.reject { |pod| tolerates_taint?(pod, eviction_taint) }.each do |pod|
              operations << operation_delete(pod, descriptor: POD, reason: "node taint eviction")
            end
          end
          ReconcileResult.new(operations: operations, status: Support.status(candidate),
                              events: unhealthy ? [{"type" => "Warning", "reason" => "NodeNotReady", "message" => "node #{Support.name(node)} is not ready"}] : [],
                              controller: name, key: Support.name(node))
        end

        # nodetopology.GetZoneKey.
        def self.zone_key(node)
          labels = Support.labels(node)
          zone = labels.fetch("failure-domain.beta.kubernetes.io/zone") { labels["topology.kubernetes.io/zone"] }.to_s
          region = labels.fetch("failure-domain.beta.kubernetes.io/region") { labels["topology.kubernetes.io/region"] }.to_s
          region.empty? && zone.empty? ? "" : "#{region}:\u0000:#{zone}"
        end

        def self.eviction_tainted?(node)
          Array(Support.value(Support.spec(node), "taints", [])).any? do |taint|
            %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].include?(Support.value(taint, "key", "").to_s) &&
              Support.value(taint, "effect", "") == "NoExecute"
          end
        end

        # handleDisruption / addPodEvictorForNewZone: per zone its size, the
        # nodes whose Ready condition is not True, and the healthy share; a
        # zone left without nodes reads 0 / 100 / 0 once.
        # The zones are the process's (the plan and orphan paths use separate
        # instances of this controller).
        ZONE_MUTEX = Mutex.new
        ZONE_NODES = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache)

        def record_zone_health(name, zone, ready)
          ZONE_MUTEX.synchronize do
            previous = ZONE_NODES[name]
            ControllerMetrics.increment("node_collector_evictions_total", {"zone" => zone}, by: 0) unless ZONE_NODES.values.any? do |entry|
              entry[0] == zone
            end
            ZONE_NODES[name] = [zone, ready]
            publish_zones([zone, previous&.first].compact.uniq)
          end
        end

        # classifyNodes: a Node that is gone leaves its zone's metrics.
        def orphan_cleanup? = true

        def plan_orphans(key, store: nil)
          # A Node's key is its bare name; a namespaced key is some other kind.
          forget_zone_node(key.to_s) unless key.to_s.include?("/")
          nil
        end

        def forget_zone_node(name)
          ZONE_MUTEX.synchronize do
            previous = ZONE_NODES.delete(name)
            publish_zones([previous.first]) if previous
          end
        end

        def publish_zones(zones)
          zones.each do |zone|
            members = ZONE_NODES.values.select { |entry| entry[0] == zone }
            labels = {"zone" => zone}
            if members.empty?
              ControllerMetrics.set("node_collector_zone_size", 0, labels)
              ControllerMetrics.set("node_collector_zone_health", 100, labels)
              ControllerMetrics.set("node_collector_unhealthy_nodes_in_zone", 0, labels)
              next
            end
            unhealthy = members.count { |entry| !entry[1] }
            ControllerMetrics.set("node_collector_zone_size", members.length, labels)
            ControllerMetrics.set("node_collector_zone_health", 100.0 * (members.length - unhealthy) / members.length, labels)
            ControllerMetrics.set("node_collector_unhealthy_nodes_in_zone", unhealthy, labels)
          end
        end
        private :record_zone_health, :publish_zones

        def heartbeat(node, now: nil, store: nil)
          plan(node, now: now, store: store)
        end

        def delete(node, pods: nil, store: nil, orphan: false)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= adapter ? adapter.list(POD, namespace: :all) : []
          operations = if orphan
                         []
                       else
                         Array(pods).select do |pod|
                           Support.value(Support.spec(pod), "nodeName",
                                         nil).to_s == Support.name(node)
                         end.map { |pod| operation_delete(pod, descriptor: POD, reason: "node deletion") }
                       end
          operations << operation_delete(node, descriptor: DESCRIPTOR, reason: "node deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        private

        # The lease in kube-node-lease named after the node; absent for a node
        # that has not started reporting yet, which stays a stale node.
        def node_lease_renewal(node, adapter, injected)
          lease = injected
          lease ||= begin
            Array(adapter&.list(LEASE, namespace: NODE_LEASE_NAMESPACE)).find do |candidate|
              Support.name(candidate) == Support.name(node)
            end
          rescue StandardError
            nil
          end
          return nil unless lease

          Support.parse_time(Support.value(Support.spec(lease), "renewTime", nil))
        end

        # {NodeConditionType => {ConditionStatus => taint key}} and the reverse
        # index, from pkg/controller/nodelifecycle.
        NODE_CONDITION_TAINTS = {
          "Ready" => {"False" => "node.kubernetes.io/not-ready", "Unknown" => "node.kubernetes.io/unreachable"},
          "MemoryPressure" => {"True" => "node.kubernetes.io/memory-pressure"},
          "DiskPressure" => {"True" => "node.kubernetes.io/disk-pressure"},
          "NetworkUnavailable" => {"True" => "node.kubernetes.io/network-unavailable"},
          "PIDPressure" => {"True" => "node.kubernetes.io/pid-pressure"}
        }.freeze
        UNSCHEDULABLE_TAINT_KEY = "node.kubernetes.io/unschedulable"
        CONDITION_TAINT_KEYS = (NODE_CONDITION_TAINTS.values.flat_map(&:values) + [UNSCHEDULABLE_TAINT_KEY]).freeze

        def reconcile_no_schedule_taints(node, taints)
          desired = Array(Support.value(Support.status(node), "conditions", [])).filter_map do |condition|
            mapping = NODE_CONDITION_TAINTS[Support.value(condition, "type", "").to_s]
            key = mapping && mapping[Support.value(condition, "status", "").to_s]
            {"key" => key, "effect" => "NoSchedule"} if key
          end
          desired << {"key" => UNSCHEDULABLE_TAINT_KEY, "effect" => "NoSchedule"} if
            Support.value(Support.spec(node), "unschedulable", false) == true

          # Only this controller's NoSchedule condition taints are replaced;
          # every other taint on the node is left exactly as it was.
          retained = taints.reject do |taint|
            Support.value(taint, "effect", "").to_s == "NoSchedule" &&
              CONDITION_TAINT_KEYS.include?(Support.value(taint, "key", "").to_s)
          end
          # A taint is its key AND effect: the unreachable:NoExecute eviction
          # taint must not suppress the unreachable:NoSchedule condition taint,
          # or a dead node keeps receiving new Pods that are then evicted.
          retained + desired.reject do |taint|
            retained.any? do |existing|
              Support.value(existing, "key", "") == taint["key"] && Support.value(existing, "effect", "") == taint["effect"]
            end
          end
        end

        def tolerates_taint?(pod, taint)
          tolerations = Array(Support.value(Support.spec(pod), "tolerations", []))
          tolerations.any? do |toleration|
            key = Support.value(toleration, "key", "").to_s
            effect = Support.value(toleration, "effect", "").to_s
            operator = Support.value(toleration, "operator", "Equal").to_s
            value = Support.value(toleration, "value", "").to_s
            next false unless effect.empty? || effect == Support.value(taint, "effect", "").to_s
            next true if operator == "Exists" && (key.empty? || key == Support.value(taint, "key", "").to_s)

            key == Support.value(taint, "key", "").to_s && value == Support.value(taint, "value", "").to_s
          end
        end
      end

      class EndpointController < BaseController
        SERVICE = ResourceDescriptor.parse("Service")
        POD = ResourceDescriptor.parse("Pod")
        ENDPOINTS = ResourceDescriptor.parse("Endpoints")

        def plan(resource, store: nil, pods: nil, endpoints: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          # This controller's declared kind is Endpoints, so the reconcile
          # loop resolves a queue key to the Endpoints object -- but the
          # desired state is derived from the *Service*: its selector picks
          # the Pods and its ports shape the subsets.  Planning from an
          # Endpoints object silently produced an empty selector, so every
          # Service ended up with an Endpoints that was created once, empty,
          # and never updated again.
          service = resource
          if Support.kind(resource).to_s == "Endpoints"
            endpoints ||= resource
            service = adapter&.find(SERVICE, name: Support.name(resource), namespace: Support.namespace(resource))
            if service.nil?
              # "Delete the corresponding endpoints, as the service has been
              # deleted" (pkg/controller/endpoint/endpoints_controller.go:370).
              # Returning an empty plan left the Endpoints object behind for
              # ever, which is what "[sig-network] EndpointsController should
              # create and delete Endpoints for a Service" checks after it
              # deletes the Service.
              return ReconcileResult.new(
                operations: [operation_delete(resource, descriptor: ENDPOINTS,
                                                        reason: "service deleted")],
                status: {}, controller: name,
                key: [Support.namespace(resource), Support.name(resource)].compact.join("/")
              )
            end
          end
          pods ||= adapter ? adapter.list(POD, namespace: Support.namespace(service)) : []
          endpoints ||= adapter ? adapter.find(ENDPOINTS, name: Support.name(service), namespace: Support.namespace(service)) : nil
          selector = Support.value(Support.spec(service), "selector", {})
          selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
          selector_present = selector.is_a?(Hash) ? !selector.empty? : !selector.nil? && !selector.to_s.empty?
          # endpoints_controller.go syncService: "services without a selector
          # receive no endpoints from this controller; the user is responsible
          # for the Endpoints object".  Creating an empty one raced the user:
          # "[sig-network] EndpointSliceMirroring should mirror a custom
          # Endpoints resource" got AlreadyExists on its own Endpoints.
          unless selector_present
            return ReconcileResult.new(operations: [], status: {}, controller: name,
                                       key: [Support.namespace(service), Support.name(service)].compact.join("/"))
          end
          selected = if selector_present
                       Array(pods).select do |pod|
                         namespace_matches?(service, pod) &&
                           !Support.metadata(pod).key?("deletionTimestamp") &&
                           Support.selector_matches?(selector, pod)
                       end
                     else
                       []
                     end
          selected.select { |pod| Support.ready?(pod) }.filter_map { |pod| address_for(pod, service) }
          selected.reject { |pod| Support.ready?(pod) }.filter_map { |pod| address_for(pod, service) }
          # v1.EndpointPort carries the port *on the Pod*, not the Service
          # port: a subset describes where traffic actually lands.  Copying
          # the ServicePort verbatim published the Service port (and its
          # nodePort), which is not a field EndpointPort even has.
          # v1.EndpointPort carries the port *on the Pod*.  A named targetPort
          # resolves per Pod (podutil.FindPort), so Pods whose container ports
          # differ land in different subsets, exactly as upstream's
          # endpoints controller groups them.
          resolve_ports = lambda do |pod|
            container_ports = if pod
                                Array(Support.value(Support.spec(pod), "containers", [])).flat_map do |container|
                                  Array(Support.value(container, "ports", []))
                                end
                              else
                                []
                              end
            Array(Support.value(Support.spec(service), "ports", [])).map do |port|
              target = Support.value(port, "targetPort", nil)
              target = Support.value(port, "port", nil) if target.nil? || target.to_s.empty?
              protocol = Support.value(port, "protocol", "TCP").to_s
              unless target.to_s.match?(/\A\d+\z/)
                match = container_ports.find do |candidate|
                  Support.value(candidate, "name", "").to_s == target.to_s &&
                    Support.value(candidate, "protocol", "TCP").to_s == protocol
                end
                target = match ? Support.value(match, "containerPort", nil) : Support.value(port, "port", nil)
              end
              entry = {"port" => Support.integer(target, Support.integer(Support.value(port, "port", 0), 0)),
                       "protocol" => protocol}
              name = Support.value(port, "name", nil).to_s
              entry["name"] = name unless name.empty?
              app_protocol = Support.value(port, "appProtocol", nil)
              entry["appProtocol"] = app_protocol.to_s unless app_protocol.nil? || app_protocol.to_s.empty?
              entry
            end
          end
          groups = {}
          selected.each do |pod|
            address = address_for(pod, service)
            next if address.nil?

            ports = resolve_ports.call(pod)
            group = (groups[ports] ||= {"ports" => ports, "addresses" => [], "notReadyAddresses" => []})
            (Support.ready?(pod) ? group["addresses"] : group["notReadyAddresses"]) << address
          end
          resolve_ports.call(selected.first)
          groups.values.flat_map { |group| group["addresses"] }
          groups.values.flat_map { |group| group["notReadyAddresses"] }
          subsets = groups.values.sort_by { |group| group["ports"].map { |entry| entry["port"].to_i } }.map do |group|
            subset = {"ports" => group["ports"]}
            subset["addresses"] = group["addresses"] unless group["addresses"].empty?
            subset["notReadyAddresses"] = group["notReadyAddresses"] unless group["notReadyAddresses"].empty?
            subset
          end
          candidate = if endpoints
                        Support.deep_copy(endpoints)
                      else
                        {"apiVersion" => "v1", "kind" => "Endpoints",
                         "metadata" => {"name" => Support.name(service), "namespace" => Support.namespace(service)}}
                      end
          candidate["subsets"] = subsets
          candidate["metadata"] ||= {}
          candidate["metadata"]["labels"] ||= {}
          # pkg/controller/endpoint/endpoints_controller.go ControllerName.
          candidate["metadata"]["labels"]["endpoints.kubernetes.io/managed-by"] = "endpoint-controller"
          operations = []
          if endpoints.nil?
            operations << operation_create(candidate, owner: service, descriptor: ENDPOINTS, reason: "service selector update")
          elsif Support.owner_reference_matches?(service, endpoints)
            update = operation_update(endpoints, candidate, descriptor: ENDPOINTS, reason: "service selector update")
            operations << update if update
          end
          # Same self-heal as the EndpointSlice controller: a Pod readiness
          # event that raced the Service into the cache is re-planned 15 s on.
          ReconcileResult.new(operations: operations, status: {}, controller: name,
                              key: [Support.namespace(service), Support.name(service)].compact.join("/"),
                              requeue_after: 15.0)
        end

        alias reconcile_service plan

        def delete(service, endpoints: nil, store: nil)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          endpoints ||= adapter&.find(ENDPOINTS, name: Support.name(service), namespace: Support.namespace(service))
          operations = endpoints ? [operation_delete(endpoints, descriptor: ENDPOINTS, reason: "service deletion")] : []
          ReconcileResult.new(operations: operations, controller: name)
        end

        private

        def namespace_matches?(service, pod)
          service_namespace = Support.namespace(service)
          pod_namespace = Support.namespace(pod)
          service_namespace.nil? || service_namespace == pod_namespace
        end

        # pkg/controller/endpoint/endpoints_controller.go addressAndPort: the
        # Pod IP of the Service's primary family (ipFamilies[0], else the
        # family of its clusterIP, else the Pod's own primary), so an IPv6
        # Service in a dual-stack cluster is not published at the Pod's IPv4.
        def address_for(pod, service = nil)
          status = Support.status(pod)
          ips = Array(Support.value(status, "podIPs", [])).filter_map { |entry| Support.value(entry, "ip", nil).to_s }.reject(&:empty?)
          primary = Support.value(status, "podIP", nil) || Support.value(status, "podIp", nil)
          ips = [primary.to_s] if ips.empty? && !primary.to_s.empty?
          family = Array(Support.value(Support.spec(service || {}), "ipFamilies", [])).first.to_s
          if family.empty?
            cluster_ip = Support.value(Support.spec(service || {}), "clusterIP", "").to_s
            family = if !cluster_ip.empty? && cluster_ip != "None" then cluster_ip.include?(":") ? "IPv6" : "IPv4"
                     else ips.first.to_s.include?(":") ? "IPv6" : "IPv4"
                     end
          end
          ip = ips.find { |candidate| (family == "IPv6") == candidate.include?(":") }
          return nil if ip.nil? || ip.to_s.empty?

          # v1.ObjectReference: a targetRef without its namespace does not
          # identify the Pod, and the EndpointSlice conformance spec checks
          # the field explicitly.
          target = {"kind" => "Pod", "namespace" => Support.namespace(pod).to_s,
                    "name" => Support.name(pod), "uid" => Support.uid(pod)}
          target.delete("namespace") if target["namespace"].empty?
          target.delete("uid") if target["uid"].to_s.empty?
          {"ip" => ip.to_s, "targetRef" => target}
        end
      end

      class GarbageCollectorController < BaseController
        def initialize(**options)
          @event_sink = options[:event_sink]
          @gc = GarbageCollector.new(store: options[:store], event_sink: @event_sink)
          @sweep_mutex = Mutex.new
          @collector_mutex = Mutex.new
          @last_sweep_at = nil
          super
        end

        def plan(resource = nil, store: nil, objects: nil, deleted: [], propagation_policy: :background, **_options)
          expedite_sweeps! if resource.is_a?(Hash) && foreground_owner?(resource)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          objects ||= adapter ? adapter.all : []
          objects = Array(objects)
          objects << resource if resource && !objects.include?(resource)
          collector(adapter).plan(objects, deleted: deleted, propagation_policy: propagation_policy)
        end

        # The planner is told which kinds the scan actually covered and how to
        # re-read an owner, so "I did not see it" can never be mistaken for "it
        # is gone".  An adapter that cannot say -- an in-memory store holding
        # the whole corpus -- keeps the unrestricted planner.
        def collector(adapter)
          return @gc unless adapter.respond_to?(:resource_descriptors)

          @collector_mutex.synchronize do
            unless @collector && @collector_adapter.equal?(adapter)
              @collector_adapter = adapter
              @collector = GarbageCollector.new(
                store: adapter, event_sink: @event_sink,
                known_kinds: adapter.resource_descriptors,
                owner_lookup: owner_lookup_for(adapter),
                dependent_lookup: dependent_lookup_for(adapter)
              )
            end
            @collector
          end
        end

        # true (the owner is there), false (the API server says it is gone) or
        # nil (this collector cannot tell, so the dependent stays).  Only kinds
        # the adapter already knows are looked up: guessing a plural resource
        # path for an unknown kind would turn a 404 on the path itself into a
        # verdict of "owner deleted".
        # The live copy of a dependent the sweep is about to collect, nil if it
        # is gone, or the swept copy itself when this adapter cannot read live.
        def dependent_lookup_for(adapter)
          lambda do |object|
            descriptor = ResourceDescriptor.parse(object)
            scope = descriptor.cluster_scoped? ? nil : Support.namespace(object)
            if adapter.respond_to?(:find_live)
              adapter.find_live(descriptor, name: Support.name(object), namespace: scope)
            else
              object
            end
          end
        end

        def owner_lookup_for(adapter)
          by_kind = {}
          Array(adapter.resource_descriptors).each do |descriptor|
            by_kind["#{descriptor.api_version}/#{descriptor.kind}"] ||= descriptor
            by_kind[descriptor.kind.to_s] ||= descriptor
          end
          lambda do |reference, namespace|
            kind = Support.ref_value(reference, "kind", "").to_s
            api_version = Support.ref_value(reference, "apiVersion", "").to_s
            descriptor = by_kind["#{api_version}/#{kind}"] || by_kind[kind]
            name = Support.ref_value(reference, "name", "").to_s
            next nil if descriptor.nil? || name.empty?

            scope = descriptor.cluster_scoped? ? nil : namespace
            object = if adapter.respond_to?(:find_live)
                       adapter.find_live(descriptor, name: name, namespace: scope)
                     else
                       adapter.find(descriptor, name: name, namespace: scope)
                     end
            next false if object.nil?

            uid = Support.ref_value(reference, "uid", "").to_s
            Support.uid(object).to_s == uid
          end
        end

        alias reconcile plan

        # A Background/Foreground delete removes the owner immediately, so the
        # dependents' reconcile key resolves to nothing and the normal
        # reconcile above never runs.  The manager invokes plan_orphans for
        # every key regardless, so the missing-owner sweep runs here and
        # deletes dependents whose owner UID no longer exists.
        # The sweep reads EVERY object in the cluster, so running it once per
        # orphaned key -- and there is one for every deleted object -- made the
        # controller manager spend most of its time re-reading the same corpus.
        # It is a periodic sweep by nature.
        #
        # Upstream's garbage collector does not sweep at all: it keeps a graph
        # built from watch events and only re-lists when discovery changes
        # (pkg/controller/garbagecollector/graph_builder.go).  A sweep is our
        # simplification, and at a five-second period it was costing HALF of
        # all the controller manager's worker time -- measured at 59 seconds of
        # work per 30 seconds of wall clock across four workers -- which pushed
        # the average wait for every other key to 40 seconds.  Once the orphan
        # pass itself was routed rather than asked of every controller, one
        # sweep every ten seconds costs a few percent of one worker -- and ten
        # seconds is what the specs that wait for a collection allow for.
        SWEEP_INTERVAL_SECONDS = 10.0

        def plan_orphans(_key, store: nil)
          return nil unless sweep_due?

          adapter = store || (self.store && StoreAdapter.new(self.store))
          objects = begin
            adapter ? adapter.all : []
          rescue StandardError
            # GarbageCollector.Sync: the resources could not be read.
            ControllerMetrics.increment("garbagecollector_controller_resources_sync_error_total")
            raise
          end
          result = collector(adapter).plan(Array(objects), deleted: [])
          result = with_foreground_operations(result, Array(objects), live: dependent_lookup_for(adapter))
          # An owner still waiting on dependents needs the next pass soon: the
          # foreground protocol takes three (delete or release the
          # dependents, see them gone, drop the finalizer), and ten seconds
          # apart that was half a minute per foreground delete where the
          # kube-controller-manager reacts to each watch event.
          expedite_sweeps! if Array(objects).any? { |object| foreground_owner?(object) }
          # kube-controller-manager logs every collection; a sweep that finds
          # nothing is the only evidence the sweep ran at all.
          log_sweep(objects.length, result)
          result
        end

        # garbagecollector.go processDeletingDependentsItem: an owner deleted
        # with propagationPolicy=Foreground keeps the foregroundDeletion
        # finalizer while it has dependents.  Each sweep deletes the ones not
        # yet going, releases the ones another live owner still holds, and
        # once none is left removes the finalizer, which lets the API server
        # finish the removal.  A creation batch its controller had already
        # started when the owner was marked can still land Pods for a moment,
        # so an owner marked less than FOREGROUND_SETTLE_SECONDS ago is not
        # released even when it looks empty.
        FOREGROUND_FINALIZER = "foregroundDeletion"
        FOREGROUND_SETTLE_SECONDS = 5.0

        def with_foreground_operations(result, objects, now: Time.now.utc, live: nil)
          operations = foreground_operations(objects, now, live: live)
          return result if operations.empty?

          ReconcileResult.new(operations: Array(result.operations) + operations,
                              batches: Array(result.batches) + operations.map { |operation| [operation] },
                              status: result.status, events: result.events,
                              controller: result.controller, key: result.key)
        end

        # `live` re-reads a dependent from the API before it is acted on, as
        # attemptToDeleteItem does (garbagecollector.go: "the latest object
        # is fetched").  The sweep works from informer caches, and the copy
        # of a Pod patched with a second owner a moment ago still named only
        # the owner being deleted: ten of fifty such Pods were deleted
        # ("Garbage collector should not delete dependents that have both
        # valid owner and owner that's waiting for dependents to be deleted"
        # expected 50 pods, got 40).

        def foreground_operations(objects, now, live: nil)
          owners = objects.select { |object| foreground_owner?(object) }
          return [] if owners.empty?

          by_uid = objects.to_h { |object| [Support.uid(object).to_s, object] }
          dependents_of = Hash.new { |hash, key| hash[key] = [] }
          objects.each do |object|
            Support.owner_references(object).each do |reference|
              dependents_of[Support.ref_value(reference, "uid", "").to_s] << object
            end
          end
          owners.flat_map do |owner|
            uid = Support.uid(owner).to_s
            dependents = dependents_of[uid].select { |dependent| same_scope?(owner, dependent) }
            dependents = current_dependents(dependents, live, uid)
            if dependents.empty?
              next [] if marked_seconds_ago(owner, now) < FOREGROUND_SETTLE_SECONDS

              candidate = Support.deep_copy(owner)
              candidate["metadata"]["finalizers"] = Array(candidate["metadata"]["finalizers"]) - [FOREGROUND_FINALIZER]
              next [operation_update(owner, candidate, descriptor: ResourceDescriptor.parse(owner),
                                                       reason: "foreground deletion: dependents gone")]
            end

            dependents.filter_map do |dependent|
              next nil if Support.value(Support.metadata(dependent), "deletionTimestamp", nil)

              if other_live_owner?(dependent, uid, by_uid)
                candidate = Support.deep_copy(dependent)
                candidate["metadata"]["ownerReferences"] = Support.owner_references(dependent).reject do |reference|
                  Support.ref_value(reference, "uid", "").to_s == uid
                end
                operation_update(dependent, candidate, descriptor: ResourceDescriptor.parse(dependent),
                                                       reason: "foreground deletion: released to its other owner")
              else
                operation_delete(dependent, descriptor: ResourceDescriptor.parse(dependent),
                                            reason: "foreground deletion of #{Support.name(owner)}")
              end
            end
          end
        end

        # The live copies of the owner's dependents: one the API no longer has,
        # or that no longer names the owner (already released), drops out, so
        # an owner whose dependents are all gone or released is seen as empty
        # and its finalizer removed.  A read that fails keeps the cached copy
        # rather than dropping the dependent: dropping it left the owner with
        # dependents in the cache and none to act on, so no operation and no
        # finalizer removal for the whole 90 s the GC spec allows.  The reads
        # run on this thread (they reuse its kept-alive connection); a
        # thread per read opened a hundred TLS connections per sweep.
        def current_dependents(dependents, live, owner_uid)
          return dependents if live.nil?

          dependents.filter_map do |dependent|
            next dependent if Support.value(Support.metadata(dependent), "deletionTimestamp", nil)

            current = begin
              live.call(dependent)
            rescue StandardError
              dependent
            end
            next nil unless current.is_a?(Hash)
            next nil unless Support.owner_references(current).any? { |reference| Support.ref_value(reference, "uid", "").to_s == owner_uid }

            current
          end
        end

        def foreground_owner?(object)
          metadata = Support.metadata(object)
          !Support.value(metadata, "deletionTimestamp", nil).nil? &&
            Array(Support.value(metadata, "finalizers", [])).include?(FOREGROUND_FINALIZER)
        end

        def same_scope?(owner, dependent)
          owner_namespace = Support.namespace(owner).to_s
          owner_namespace.empty? || Support.namespace(dependent).to_s == owner_namespace
        end

        def other_live_owner?(dependent, uid, by_uid)
          Support.owner_references(dependent).any? do |reference|
            other = Support.ref_value(reference, "uid", "").to_s
            next false if other == uid

            owner = by_uid[other]
            owner && Support.value(Support.metadata(owner), "deletionTimestamp", nil).nil?
          end
        end

        def marked_seconds_ago(owner, now)
          marked = Support.parse_time(Support.value(Support.metadata(owner), "deletionTimestamp", nil))
          marked ? now - marked : Float::INFINITY
        end

        def log_sweep(scanned, result)
          targets = result.respond_to?(:operations) ? Array(result.operations).length : 0
          line = {"timestamp" => Time.now.utc.iso8601(6), "level" => "info", "event" => "garbage_collector.sweep",
                  "scanned" => scanned, "targets" => targets}
          $stderr.write(JSON.generate(line) << "\n")
        rescue StandardError
          nil
        end

        # While a foreground deletion is in progress sweeps run this often.
        FOREGROUND_SWEEP_SECONDS = 1.0
        EXPEDITE_WINDOW_SECONDS = 15.0

        def expedite_sweeps!
          @sweep_mutex ||= Mutex.new
          @sweep_mutex.synchronize { @expedite_until = Process.clock_gettime(Process::CLOCK_MONOTONIC) + EXPEDITE_WINDOW_SECONDS }
        end

        def sweep_due?
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          @sweep_mutex ||= Mutex.new
          @sweep_mutex.synchronize do
            interval = @expedite_until && now < @expedite_until ? FOREGROUND_SWEEP_SECONDS : SWEEP_INTERVAL_SECONDS
            return false if @last_sweep_at && (now - @last_sweep_at) < interval

            @last_sweep_at = now
            true
          end
        end
      end
    end

    DeploymentController = Builtins::DeploymentController
    ReplicaSetController = Builtins::ReplicaSetController
    StatefulSetController = Builtins::StatefulSetController
    DaemonSetController = Builtins::DaemonSetController
    JobController = Builtins::JobController
    CronJobController = Builtins::CronJobController
    NodeController = Builtins::NodeController
    EndpointController = Builtins::EndpointController
    EndpointsController = Builtins::EndpointController
    GarbageCollectorController = Builtins::GarbageCollectorController
  end
end
