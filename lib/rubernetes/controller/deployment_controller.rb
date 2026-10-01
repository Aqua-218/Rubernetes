# frozen_string_literal: true

require "time"
require_relative "support"
require_relative "types"

module Rubernetes
  module Controller
    module Builtins
      # Deployment controller following pkg/controller/deployment at Kubernetes
      # v1.36.2: revision-annotated ReplicaSets addressed by the pod-template
      # hash, proportional scaling, rolling/recreate rollouts, rollback,
      # progress deadline tracking, paused handling, and hash collisions.
      class DeploymentController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("Deployment")
        REPLICA_SET = ResourceDescriptor.parse("ReplicaSet")
        POD = WorkloadController::POD
        HASH_LABEL = "pod-template-hash"
        REVISION_ANNOTATION = "deployment.kubernetes.io/revision"
        REVISION_HISTORY_ANNOTATION = "deployment.kubernetes.io/revision-history"
        DESIRED_REPLICAS_ANNOTATION = "deployment.kubernetes.io/desired-replicas"
        MAX_REPLICAS_ANNOTATION = "deployment.kubernetes.io/max-replicas"
        ROLLBACK_TO_ANNOTATION = "deprecated.deployment.rollback.to"
        LAST_APPLIED_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"
        # pkg/controller/deployment/util/deployment_util.go:295
        ANNOTATIONS_TO_SKIP = [LAST_APPLIED_ANNOTATION, REVISION_ANNOTATION, REVISION_HISTORY_ANNOTATION,
                               DESIRED_REPLICAS_ANNOTATION, MAX_REPLICAS_ANNOTATION, ROLLBACK_TO_ANNOTATION].freeze
        MAX_REV_HISTORY_LENGTH_IN_CHARS = 2000
        MAX_INT32 = (2**31) - 1
        # apps/v1 API defaults (pkg/apis/apps/v1/defaults.go).
        DEFAULT_PROGRESS_DEADLINE_SECONDS = 600
        DEFAULT_REVISION_HISTORY_LIMIT = 10
        DEFAULT_ROLLING_PERCENT = "25%"
        # Condition reasons (deployment_util.go:71-92).
        REASON_REPLICA_SET_UPDATED = "ReplicaSetUpdated"
        REASON_FAILED_RS_CREATE = "ReplicaSetCreateError"
        REASON_NEW_REPLICA_SET = "NewReplicaSetCreated"
        REASON_FOUND_NEW_RS = "FoundNewReplicaSet"
        REASON_NEW_RS_AVAILABLE = "NewReplicaSetAvailable"
        REASON_TIMED_OUT = "ProgressDeadlineExceeded"
        REASON_PAUSED = "DeploymentPaused"
        REASON_RESUMED = "DeploymentResumed"
        REASON_MIN_AVAILABLE = "MinimumReplicasAvailable"
        REASON_MIN_UNAVAILABLE = "MinimumReplicasUnavailable"
        REASON_ROLLBACK_REVISION_NOT_FOUND = "DeploymentRollbackRevisionNotFound"
        REASON_ROLLBACK_TEMPLATE_UNCHANGED = "DeploymentRollbackTemplateUnchanged"
        REASON_ROLLBACK_DONE = "DeploymentRollback"

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          super
        end

        def plan(deployment, store: nil, replicasets: nil, pods: nil, now: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          replicasets ||= list_children(adapter, REPLICA_SET, Support.namespace(deployment))
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          all_replica_sets = Array(replicasets).select { |rs| Support.namespace(rs).to_s == Support.namespace(deployment).to_s }
          adoption = adoption_operations(deployment, all_replica_sets, adapter)
          all_replica_sets = all_replica_sets.map { |rs| adoption[:by_name][Support.name(rs).to_s] || rs }
          owned_sets = owned(deployment, all_replica_sets)
          pods = if pods.nil? && adapter && strategy_type(deployment) == "Recreate"
                   list_children(adapter, POD, Support.namespace(deployment))
                 else
                   Array(pods)
                 end
          result = Sync.new(self, deployment, owned_sets, all_replica_sets, pods, now).run
          return result if adoption[:operations].empty?

          ReconcileResult.new(operations: adoption[:operations] + result.operations, status: result.status,
                              events: result.events, controller: name, key: result.key,
                              requeue_after: result.requeue_after)
        end

        # replica_set_utils.go getReplicaSetsForDeployment / ClaimReplicaSets.
        # A ReplicaSet whose labels match the selector and that no controller
        # owns is adopted.  Taking only the ReplicaSets that already carried an
        # owner reference meant a Deployment created over an existing
        # ReplicaSet never saw it: it counted no old revisions, numbered its
        # new ReplicaSet 1 instead of the adopted one's revision plus one, and
        # left the old Pods running ("[sig-apps] Deployment RollingUpdateDeployment
        # should delete old pods and create new ones" and "deployment should
        # support rollover").
        def adoption_operations(deployment, replica_sets, adapter)
          empty = {by_name: {}, operations: []}
          return empty unless Support.value(Support.metadata(deployment), "deletionTimestamp", nil).nil?

          selector = Support.value(Support.spec(deployment), "selector", nil)
          return empty if selector.nil? || (selector.is_a?(Hash) && selector.empty?)

          adoptable = replica_sets.select do |rs|
            Support.value(Support.metadata(rs), "deletionTimestamp", nil).nil? &&
              Support.selector_matches?(selector, rs) &&
              Support.owner_references(rs).none? do |reference|
                flag = Support.ref_value(reference, "controller", false)
                flag == true || flag.to_s.casecmp("true").zero?
              end
          end
          return empty if adoptable.empty?
          return empty unless adoption_allowed?(adapter, deployment, DESCRIPTOR)

          by_name = {}
          operations = adoptable.filter_map do |rs|
            candidate = Support.deep_copy(rs)
            candidate["metadata"] ||= {}
            candidate["metadata"]["ownerReferences"] =
              Support.owner_references(candidate).map { |reference| Support.deep_copy(reference) } +
              [Support.owner_reference(deployment)]
            by_name[Support.name(rs).to_s] = candidate
            operation_update(rs, candidate, descriptor: REPLICA_SET, reason: "deployment replica set adoption")
          end
          {by_name: by_name, operations: operations}
        end

        # PodControllerRefManager canAdoptFunc: adopt only after a fresh read
        # shows the same Deployment, not being deleted.
        def adoption_allowed?(adapter, deployment, descriptor)
          return true unless adapter.respond_to?(:find_live)

          fresh = adapter.find_live(descriptor, name: Support.name(deployment), namespace: Support.namespace(deployment))
          !fresh.nil? && Support.uid(fresh).to_s == Support.uid(deployment).to_s &&
            Support.value(Support.metadata(fresh), "deletionTimestamp", nil).nil?
        rescue StandardError
          false
        end

        def rollout(deployment, replicasets: nil, store: nil, **)
          plan(deployment, replicasets: replicasets, store: store, **)
        end

        def scale(deployment, replicas, replicasets: nil, store: nil, **)
          candidate = Support.deep_copy(deployment)
          candidate["spec"] ||= {}
          candidate["spec"]["replicas"] = Integer(replicas)
          plan(candidate, replicasets: replicasets, store: store, **)
        end

        # A controller-side rollback request is the deprecated rollback
        # annotation; kubectl rollout undo patches the template directly and
        # is served by the ordinary rollout path.
        def rollback(deployment, revision: nil, replicasets: nil, store: nil, **)
          candidate = Support.deep_copy(deployment)
          candidate["metadata"] ||= {}
          candidate["metadata"]["annotations"] = Support.annotations(candidate).merge(ROLLBACK_TO_ANNOTATION => (revision || 0).to_s)
          plan(candidate, replicasets: replicasets, store: store, **)
        end

        def delete(deployment, replicasets: nil, store: nil, propagation_policy: :background)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          replicasets ||= list_children(adapter, REPLICA_SET, Support.namespace(deployment))
          owned_sets = owned(deployment, replicasets)
          operations = if propagation_policy.to_sym == :orphan
                         []
                       else
                         owned_sets.map { |rs| operation_delete(rs, descriptor: REPLICA_SET, reason: "deployment deletion") }
                       end
          operations << operation_delete(deployment, descriptor: DESCRIPTOR, reason: "deployment deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        # ---- spec accessors shared with Sync ------------------------------------

        def strategy_type(deployment)
          strategy = Support.value(Support.spec(deployment), "strategy", {})
          strategy = {} unless strategy.is_a?(Hash)
          type = Support.value(strategy, "type", "RollingUpdate").to_s
          raise ArgumentError, "unsupported Deployment strategy #{type.inspect}" unless %w[RollingUpdate Recreate].include?(type)

          type
        end

        def rolling_update?(deployment)
          strategy_type(deployment) == "RollingUpdate"
        end

        def rolling_update_params(deployment)
          strategy = Support.value(Support.spec(deployment), "strategy", {})
          strategy = {} unless strategy.is_a?(Hash)
          rolling = Support.value(strategy, "rollingUpdate", {})
          rolling.is_a?(Hash) ? rolling : {}
        end

        def replicas(deployment)
          replica_count(deployment, default: 1)
        end

        # deployment_util.go ResolveFenceposts: surge rounds up, unavailable
        # rounds down, and both-zero resolves to one unavailable replica.
        def resolve_fenceposts(deployment)
          desired = replicas(deployment)
          rolling = rolling_update_params(deployment)
          surge = Support.quantity(Support.value(rolling, "maxSurge", DEFAULT_ROLLING_PERCENT), desired, mode: :ceil, default: 0)
          unavailable = Support.quantity(Support.value(rolling, "maxUnavailable", DEFAULT_ROLLING_PERCENT), desired, mode: :floor,
                                                                                                                     default: 0)
          unavailable = 1 if surge.zero? && unavailable.zero?
          [surge, unavailable]
        end

        def max_unavailable(deployment)
          return 0 if !rolling_update?(deployment) || replicas(deployment).zero?

          _surge, unavailable = resolve_fenceposts(deployment)
          [unavailable, replicas(deployment)].min
        end

        def max_surge(deployment)
          return 0 unless rolling_update?(deployment)

          resolve_fenceposts(deployment).first
        end

        def progress_deadline_seconds(deployment)
          raw = Support.value(Support.spec(deployment), "progressDeadlineSeconds", nil)
          raw.nil? ? DEFAULT_PROGRESS_DEADLINE_SECONDS : Support.integer(raw, DEFAULT_PROGRESS_DEADLINE_SECONDS)
        end

        def progress_deadline?(deployment)
          progress_deadline_seconds(deployment) != MAX_INT32
        end

        def revision_history_limit(deployment)
          raw = Support.value(Support.spec(deployment), "revisionHistoryLimit", nil)
          raw.nil? ? DEFAULT_REVISION_HISTORY_LIMIT : Support.integer(raw, DEFAULT_REVISION_HISTORY_LIMIT)
        end

        def revision_history_limit?(deployment)
          revision_history_limit(deployment) != MAX_INT32
        end

        def paused?(deployment)
          Support.value(Support.spec(deployment), "paused", false) == true
        end

        def min_ready_seconds(deployment)
          Support.integer(Support.value(Support.spec(deployment), "minReadySeconds", 0), 0)
        end

        def rollback_to(deployment)
          raw = Support.annotations(deployment)[ROLLBACK_TO_ANNOTATION]
          return nil if raw.nil? || raw.to_s.empty?

          Integer(raw.to_s, 10)
        rescue ArgumentError, TypeError
          nil
        end

        def rs_replicas(rs)
          replica_count(rs, default: 0)
        end

        def rs_status_int(rs, key)
          Support.integer(Support.status(rs)[key], 0)
        end

        def revision_of(rs)
          raw = Support.annotations(rs)[REVISION_ANNOTATION]
          return 0 if raw.nil? || raw.to_s.empty?

          Integer(raw.to_s, 10)
        rescue ArgumentError, TypeError
          nil
        end

        def template_without_hash(template)
          candidate = Support.deep_copy(template.is_a?(Hash) ? template : {})
          metadata = candidate["metadata"]
          if metadata.is_a?(Hash) && metadata["labels"].is_a?(Hash)
            labels = metadata["labels"].reject { |key, _| key.to_s == HASH_LABEL }
            if labels.empty?
              metadata.delete("labels")
            else
              metadata["labels"] = labels
            end
            candidate.delete("metadata") if metadata.empty?
          end
          candidate
        end

        # deployment_util.go EqualIgnoreHash
        def equal_ignore_hash?(left, right)
          Support.canonical(template_without_hash(left)) == Support.canonical(template_without_hash(right))
        end

        def creation_sort_key(rs)
          created = Support.creation_time(rs)
          [created ? 1 : 0, created ? created.to_f : 0.0, Support.name(rs)]
        end

        def event(type, reason, message)
          {"type" => type, "reason" => reason, "message" => message}
        end

        def new_condition(type, status, reason, message, now)
          stamp = now.utc.iso8601(6)
          {"type" => type, "status" => status, "lastUpdateTime" => stamp, "lastTransitionTime" => stamp,
           "reason" => reason, "message" => message}
        end

        def find_condition(status, type)
          Array(Support.value(status, "conditions", [])).find { |condition| Support.value(condition, "type", "").to_s == type }
        end

        # deployment_util.go SetDeploymentCondition
        def set_condition!(status, condition)
          current = find_condition(status, condition.fetch("type"))
          if current && Support.value(current, "status", "") == condition.fetch("status") &&
             Support.value(current, "reason", "") == condition.fetch("reason")
            return status
          end

          condition = condition.merge("lastTransitionTime" => current.fetch("lastTransitionTime")) if current &&
                                                                                                      Support.value(current, "status",
                                                                                                                    "") == condition.fetch("status") &&
                                                                                                      current.key?("lastTransitionTime")
          status["conditions"] = filter_out_condition(status["conditions"], condition.fetch("type")) + [condition]
          status
        end

        def remove_condition!(status, type)
          status["conditions"] = filter_out_condition(status["conditions"], type)
          status.delete("conditions") if status["conditions"].empty?
          status
        end

        def filter_out_condition(conditions, type)
          Array(conditions).reject do |condition|
            Support.value(condition, "type", "").to_s == type
          end.map { |condition| Support.deep_copy(condition) }
        end

        public :operation_create, :operation_delete, :operation_update, :operation_status

        # One syncDeployment pass.
        class Sync
          def initialize(controller, deployment, owned_sets, all_replica_sets, pods, now)
            @c = controller
            @deployment = deployment
            @d = Support.deep_copy(deployment)
            @status = Support.deep_copy(Support.status(deployment))
            @original_status = Support.deep_copy(@status)
            @rs_list = owned_sets.map { |rs| Support.deep_copy(rs) }
            @all_replica_sets = all_replica_sets
            @pods = pods
            @now = now
            @operations = []
            @events = []
            @requeue_after = nil
            @deployment_metadata_dirty = false
            @spec_dirty = false
          end

          def run
            d = @d
            selector = Support.value(Support.spec(d), "selector", {})
            if selector.nil? || (selector.is_a?(Hash) && selector.empty?)
              @events << @c.event("Warning", "SelectingAll", "This deployment is selecting all pods. A non-empty selector is required.")
              generation = Support.integer(Support.metadata(d)["generation"], 0)
              @status["observedGeneration"] = generation if Support.integer(@status["observedGeneration"], 0) < generation
              return finish
            end

            return sync_status_only if Support.metadata(d).key?("deletionTimestamp")

            check_paused_conditions
            return sync if @c.paused?(d)
            return rollback unless @c.rollback_to(d).nil?
            return sync if scaling_event?

            case @c.strategy_type(d)
            when "Recreate" then rollout_recreate
            else rollout_rolling
            end
          end

          private

          # ---- ReplicaSet discovery ------------------------------------------------

          def find_new_replica_set(rs_list)
            rs_list.sort_by { |rs| @c.creation_sort_key(rs) }.find do |rs|
              @c.equal_ignore_hash?(Support.value(Support.spec(rs), "template", {}), Support.value(Support.spec(@d), "template", {}))
            end
          end

          def find_old_replica_sets(rs_list)
            new_rs = find_new_replica_set(rs_list)
            all_old = rs_list.reject { |rs| new_rs && Support.uid(rs) == Support.uid(new_rs) && Support.name(rs) == Support.name(new_rs) }
            required = all_old.select { |rs| @c.rs_replicas(rs).positive? }
            [required, all_old]
          end

          def active_replica_sets(rs_list)
            rs_list.compact.select { |rs| @c.rs_replicas(rs).positive? }
          end

          def max_revision(rs_list)
            rs_list.filter_map { |rs| @c.revision_of(rs) }.max.to_i
          end

          def last_revision(rs_list)
            max = 0
            second = 0
            rs_list.each do |rs|
              revision = @c.revision_of(rs)
              next if revision.nil?

              if revision >= max
                second = max
                max = revision
              elsif revision > second
                second = revision
              end
            end
            second
          end

          # sync.go getAllReplicaSetsAndSyncRevision.  Returns [new_rs, old_rss]
          # or :collision when a hash collision was recorded.
          def all_replica_sets_and_sync_revision(create_if_not_existed)
            _required, all_old = find_old_replica_sets(@rs_list)
            new_rs = new_replica_set(all_old, create_if_not_existed)
            return :collision if new_rs == :collision

            [new_rs, all_old]
          end

          # sync.go getNewReplicaSet
          def new_replica_set(old_rss, create_if_not_existed)
            d = @d
            existing = find_new_replica_set(@rs_list)
            new_revision = (max_revision(old_rss) + 1).to_s
            if existing
              rs_copy = Support.deep_copy(existing)
              annotations_updated = set_new_replica_set_annotations!(rs_copy, new_revision, exists: true)
              rs_copy["spec"] ||= {}
              min_ready_needs_update = Support.integer(rs_copy["spec"]["minReadySeconds"], 0) != @c.min_ready_seconds(d)
              if annotations_updated || min_ready_needs_update
                rs_copy["spec"]["minReadySeconds"] = @c.min_ready_seconds(d)
                rs_copy["spec"].delete("minReadySeconds") if @c.min_ready_seconds(d).zero? && !Support.spec(existing).key?("minReadySeconds")
                @operations << @c.operation_update(existing, rs_copy, descriptor: REPLICA_SET, reason: "deployment replica set annotations")
                replace_replica_set!(rs_copy)
                return rs_copy
              end

              needs_update = set_deployment_revision!(Support.annotations(rs_copy)[REVISION_ANNOTATION].to_s)
              if @c.progress_deadline?(d) && @c.find_condition(@status, "Progressing").nil?
                @c.set_condition!(@status, @c.new_condition("Progressing", "True", REASON_FOUND_NEW_RS,
                                                            "Found new replica set \"#{Support.name(rs_copy)}\"", @now))
                needs_update = true
              end
              @deployment_metadata_dirty ||= needs_update
              return rs_copy
            end
            return nil unless create_if_not_existed

            template = Support.deep_copy(Support.value(Support.spec(d), "template", {}))
            collision_count = @status.key?("collisionCount") ? Support.integer(@status["collisionCount"], 0) : nil
            hash = Support.pod_template_hash(template, collision_count)
            template["metadata"] ||= {}
            template_labels = Support.value(template["metadata"], "labels", {})
            template_labels = {} unless template_labels.is_a?(Hash)
            template["metadata"]["labels"] = template_labels.merge(HASH_LABEL => hash)
            selector = Support.deep_copy(Support.value(Support.spec(d), "selector", {}))
            selector["matchLabels"] = (selector["matchLabels"].is_a?(Hash) ? selector["matchLabels"] : {}).merge(HASH_LABEL => hash)
            new_rs = {
              "apiVersion" => "apps/v1", "kind" => "ReplicaSet",
              "metadata" => {"name" => "#{Support.name(d)}-#{hash}", "namespace" => Support.namespace(d),
                             "labels" => Support.deep_copy(template["metadata"]["labels"]),
                             "ownerReferences" => [Support.owner_reference(d)]},
              "spec" => {"replicas" => 0, "selector" => selector, "template" => template}
            }
            new_rs["spec"]["minReadySeconds"] = @c.min_ready_seconds(d) if @c.min_ready_seconds(d).positive?
            new_rs["spec"]["replicas"] = new_rs_new_replicas(old_rss + [new_rs], new_rs)
            set_new_replica_set_annotations!(new_rs, new_revision, exists: false)

            colliding = @all_replica_sets.find { |rs| Support.name(rs) == Support.name(new_rs) }
            if colliding
              controlled = Support.owner_reference_matches?(d, colliding, controller: true)
              if controlled && @c.equal_ignore_hash?(Support.value(Support.spec(d), "template", {}),
                                                     Support.value(Support.spec(colliding), "template", {}))
                created = Support.deep_copy(colliding)
              else
                # A different template already owns this name: bump the
                # collision count so the next sync derives a fresh hash.
                @status["collisionCount"] = Support.integer(@status["collisionCount"], 0) + 1
                @requeue_after = 0.0
                return :collision
              end
            else
              created = new_rs
              @operations << @c.operation_create(new_rs, owner: d, descriptor: REPLICA_SET, reason: "new deployment revision")
              @rs_list << new_rs
              count = @c.rs_replicas(new_rs)
              if count.positive?
                @events << @c.event("Normal", "ScalingReplicaSet",
                                    "Scaled up replica set #{Support.name(new_rs)} from 0 to #{count}")
              end
            end
            needs_update = set_deployment_revision!(new_revision)
            if colliding.nil? && @c.progress_deadline?(d)
              @c.set_condition!(@status, @c.new_condition("Progressing", "True", REASON_NEW_REPLICA_SET,
                                                          "Created new replica set \"#{Support.name(created)}\"", @now))
              needs_update = true
            end
            @deployment_metadata_dirty ||= needs_update
            created
          end

          def replace_replica_set!(rs)
            index = @rs_list.index { |candidate| Support.name(candidate) == Support.name(rs) }
            index.nil? ? @rs_list << rs : @rs_list[index] = rs
          end

          # deployment_util.go SetNewReplicaSetAnnotations
          def set_new_replica_set_annotations!(rs, new_revision, exists:)
            changed = copy_deployment_annotations!(rs)
            rs["metadata"] ||= {}
            annotations = rs["metadata"]["annotations"] = (rs["metadata"]["annotations"] || {}).dup
            old_revision = annotations[REVISION_ANNOTATION]
            old_revision_int = if old_revision.nil? || old_revision.to_s.empty?
                                 0
                               else
                                 begin
                                   Integer(old_revision.to_s, 10)
                                 rescue ArgumentError
                                   return false
                                 end
                               end
            new_revision_int = Integer(new_revision, 10)
            if old_revision_int < new_revision_int
              annotations[REVISION_ANNOTATION] = new_revision
              changed = true
            end
            if !old_revision.nil? && old_revision_int < new_revision_int
              history = annotations[REVISION_HISTORY_ANNOTATION].to_s
              old_revisions = history.split(",")
              if old_revisions.empty? || old_revisions.first.empty?
                annotations[REVISION_HISTORY_ANNOTATION] = old_revision.to_s
              else
                total = history.length + old_revision.to_s.length + 1
                start = 0
                while total > MAX_REV_HISTORY_LENGTH_IN_CHARS && start < old_revisions.length
                  total -= old_revisions[start].length + 1
                  start += 1
                end
                if total <= MAX_REV_HISTORY_LENGTH_IN_CHARS
                  annotations[REVISION_HISTORY_ANNOTATION] =
                    (old_revisions[start..] + [old_revision.to_s]).join(",")
                end
              end
            end
            changed = true if !exists && set_replicas_annotations!(rs, @c.replicas(@d), @c.replicas(@d) + @c.max_surge(@d))
            changed
          end

          def copy_deployment_annotations!(rs)
            rs["metadata"] ||= {}
            annotations = rs["metadata"]["annotations"] = (rs["metadata"]["annotations"] || {}).dup
            changed = false
            Support.annotations(@d).each do |key, value|
              next if ANNOTATIONS_TO_SKIP.include?(key.to_s) || (annotations.key?(key.to_s) && annotations[key.to_s] == value)

              annotations[key.to_s] = value
              changed = true
            end
            changed
          end

          def set_replicas_annotations!(rs, desired, maximum)
            rs["metadata"] ||= {}
            annotations = rs["metadata"]["annotations"] = (rs["metadata"]["annotations"] || {}).dup
            changed = false
            if annotations[DESIRED_REPLICAS_ANNOTATION] != desired.to_s
              annotations[DESIRED_REPLICAS_ANNOTATION] = desired.to_s
              changed = true
            end
            if annotations[MAX_REPLICAS_ANNOTATION] != maximum.to_s
              annotations[MAX_REPLICAS_ANNOTATION] = maximum.to_s
              changed = true
            end
            changed
          end

          def replicas_annotations_need_update?(rs, desired, maximum)
            annotations = Support.annotations(rs)
            annotations[DESIRED_REPLICAS_ANNOTATION] != desired.to_s || annotations[MAX_REPLICAS_ANNOTATION] != maximum.to_s
          end

          def set_deployment_revision!(revision)
            @d["metadata"] ||= {}
            annotations = @d["metadata"]["annotations"] = (@d["metadata"]["annotations"] || {}).dup
            return false if annotations[REVISION_ANNOTATION] == revision

            annotations[REVISION_ANNOTATION] = revision
            true
          end

          # deployment_util.go NewRSNewReplicas
          def new_rs_new_replicas(all_rss, new_rs)
            d = @d
            case @c.strategy_type(d)
            when "RollingUpdate"
              rolling = @c.rolling_update_params(d)
              surge = Support.quantity(Support.value(rolling, "maxSurge", DEFAULT_ROLLING_PERCENT), @c.replicas(d), mode: :ceil, default: 0)
              current = all_rss.sum { |rs| @c.rs_replicas(rs) }
              max_total = @c.replicas(d) + surge
              return @c.rs_replicas(new_rs) if current >= max_total

              scale_up = [max_total - current, @c.replicas(d) - @c.rs_replicas(new_rs)].min
              @c.rs_replicas(new_rs) + scale_up
            else
              @c.replicas(d)
            end
          end

          # ---- scaling -----------------------------------------------------------

          # sync.go scaleReplicaSet.  Returns [scaled, rs].
          def scale_replica_set(rs, new_scale, force_update: false)
            current = @c.rs_replicas(rs)
            return [false, rs] if !force_update && current == new_scale

            desired = @c.replicas(@d)
            maximum = desired + @c.max_surge(@d)
            size_needs_update = current != new_scale
            annotations_need_update = replicas_annotations_need_update?(rs, desired, maximum)
            return [false, rs] unless size_needs_update || annotations_need_update

            rs_copy = Support.deep_copy(rs)
            rs_copy["spec"] ||= {}
            rs_copy["spec"]["replicas"] = new_scale
            set_replicas_annotations!(rs_copy, desired, maximum)
            operation = @c.operation_update(rs, rs_copy, descriptor: REPLICA_SET, reason: "deployment scaling")
            @operations << operation if operation
            replace_replica_set!(rs_copy)
            if size_needs_update
              direction = current < new_scale ? "up" : "down"
              @events << @c.event("Normal", "ScalingReplicaSet",
                                  "Scaled #{direction} replica set #{Support.name(rs)} from #{current} to #{new_scale}")
            end
            [size_needs_update, rs_copy]
          end

          # sync.go isScalingEvent
          def scaling_event?
            result = all_replica_sets_and_sync_revision(false)
            return false if result == :collision

            new_rs, old_rss = result
            active_replica_sets(old_rss + [new_rs]).any? do |rs|
              raw = Support.annotations(rs)[DESIRED_REPLICAS_ANNOTATION]
              next false if raw.nil?

              desired = Integer(raw.to_s, 10)
              desired >= 0 && desired != @c.replicas(@d)
            rescue ArgumentError
              false
            end
          end

          # sync.go sync
          def sync
            result = all_replica_sets_and_sync_revision(false)
            return finish if result == :collision

            new_rs, old_rss = result
            scale(new_rs, old_rss)
            cleanup_deployment(old_rss) if @c.paused?(@d) && @c.rollback_to(@d).nil?
            sync_deployment_status(old_rss + [new_rs], new_rs)
          end

          def sync_status_only
            result = all_replica_sets_and_sync_revision(false)
            return finish if result == :collision

            new_rs, old_rss = result
            sync_deployment_status(old_rss + [new_rs], new_rs)
          end

          # sync.go scale: proportional scaling of every active ReplicaSet.
          def scale(new_rs, old_rss)
            d = @d
            active_or_latest = find_active_or_latest(new_rs, old_rss)
            if active_or_latest
              return if @c.rs_replicas(active_or_latest) == @c.replicas(d)

              scale_replica_set(active_or_latest, @c.replicas(d))
              return
            end

            if saturated?(new_rs)
              active_replica_sets(old_rss).each { |rs| scale_replica_set(rs, 0) }
              return
            end

            return unless @c.rolling_update?(d)

            all_rss = active_replica_sets(old_rss + [new_rs])
            all_replicas = all_rss.sum { |rs| @c.rs_replicas(rs) }
            allowed = @c.replicas(d).positive? ? @c.replicas(d) + @c.max_surge(d) : 0
            to_add = allowed - all_replicas
            if to_add.positive?
              all_rss = all_rss.sort_by { |rs| [-@c.rs_replicas(rs), invert_key(@c.creation_sort_key(rs))] }
            elsif to_add.negative?
              all_rss = all_rss.sort_by { |rs| [-@c.rs_replicas(rs), @c.creation_sort_key(rs)] }
            end
            added = 0
            sizes = {}
            all_rss.each do |rs|
              if to_add.zero?
                sizes[Support.name(rs)] = @c.rs_replicas(rs)
              else
                proportion = replica_set_proportion(rs, to_add, added)
                sizes[Support.name(rs)] = @c.rs_replicas(rs) + proportion
                added += proportion
              end
            end
            all_rss.each_with_index do |rs, index|
              if index.zero? && !to_add.zero?
                leftover = to_add - added
                sizes[Support.name(rs)] = [sizes[Support.name(rs)] + leftover, 0].max
              end
              scale_replica_set(rs, sizes[Support.name(rs)], force_update: true)
            end
          end

          # Sorting newest-first for scale-up needs the creation key inverted;
          # names cannot be negated, so compare on the mirrored components.
          def invert_key(key)
            present, seconds, name = key
            [-present, -seconds, name.each_char.map { |char| 255 - char.ord }]
          end

          def find_active_or_latest(new_rs, old_rss)
            return nil if new_rs.nil? && old_rss.empty?

            sorted_old = old_rss.sort_by { |rs| @c.creation_sort_key(rs) }.reverse
            active = active_replica_sets(sorted_old + [new_rs])
            case active.length
            when 0 then new_rs || sorted_old.first
            when 1 then active.first
            end
          end

          def saturated?(rs)
            return false if rs.nil?

            desired = Support.annotations(rs)[DESIRED_REPLICAS_ANNOTATION]
            return false if desired.nil?

            replicas = @c.replicas(@d)
            @c.rs_replicas(rs) == replicas && Integer(desired.to_s, 10) == replicas && @c.rs_status_int(rs, "availableReplicas") == replicas
          rescue ArgumentError
            false
          end

          # deployment_util.go GetReplicaSetProportion / getReplicaSetFraction
          def replica_set_proportion(rs, to_add, added)
            return 0 if rs.nil? || @c.rs_replicas(rs).zero? || to_add.zero? || to_add == added

            fraction = replica_set_fraction(rs)
            allowed = to_add - added
            to_add.positive? ? [fraction, allowed].min : [fraction, allowed].max
          end

          def replica_set_fraction(rs)
            d = @d
            return -@c.rs_replicas(rs) if @c.replicas(d).zero?

            max_replicas = @c.replicas(d) + @c.max_surge(d)
            before = begin
              Integer(Support.annotations(rs)[MAX_REPLICAS_ANNOTATION].to_s, 10)
            rescue ArgumentError
              0
            end
            if before.zero?
              before = Support.integer(@status["replicas"], 0)
              return 0 if before.zero?
            end
            scale_base = @c.rs_replicas(rs)
            (scale_base * max_replicas).to_f.fdiv(before).round - scale_base
          end

          # ---- rolling update ----------------------------------------------------

          def rollout_rolling
            result = all_replica_sets_and_sync_revision(true)
            return finish if result == :collision

            new_rs, old_rss = result
            all_rss = old_rss + [new_rs]
            scaled_up = reconcile_new_replica_set(all_rss, new_rs)
            return sync_rollout_status(all_rss, new_rs) if scaled_up

            scaled_down = reconcile_old_replica_sets(all_rss, active_replica_sets(old_rss), new_rs)
            return sync_rollout_status(all_rss, new_rs) if scaled_down

            cleanup_deployment(old_rss) if deployment_complete?(@original_status)
            sync_rollout_status(all_rss, new_rs)
          end

          def reconcile_new_replica_set(all_rss, new_rs)
            return false if @c.rs_replicas(new_rs) == @c.replicas(@d)

            if @c.rs_replicas(new_rs) > @c.replicas(@d)
              scaled, = scale_replica_set(new_rs, @c.replicas(@d))
              return scaled
            end
            count = new_rs_new_replicas(all_rss, new_rs)
            scaled, = scale_replica_set(new_rs, count)
            scaled
          end

          def reconcile_old_replica_sets(all_rss, old_rss, new_rs)
            old_pods = old_rss.sum { |rs| @c.rs_replicas(rs) }
            return false if old_pods.zero?

            all_pods = all_rss.sum { |rs| @c.rs_replicas(rs) }
            min_available = @c.replicas(@d) - @c.max_unavailable(@d)
            new_unavailable = @c.rs_replicas(new_rs) - @c.rs_status_int(new_rs, "availableReplicas")
            max_scaled_down = all_pods - min_available - new_unavailable
            return false if max_scaled_down <= 0

            old_rss, cleanup_count = cleanup_unhealthy_replicas(old_rss, max_scaled_down)
            scaled_down_count = scale_down_old_replica_sets_for_rolling_update(old_rss + [new_rs], old_rss)
            (cleanup_count + scaled_down_count).positive?
          end

          def cleanup_unhealthy_replicas(old_rss, max_cleanup)
            sorted = old_rss.sort_by { |rs| @c.creation_sort_key(rs) }
            total = 0
            updated = sorted.map do |rs|
              next rs if total >= max_cleanup
              next rs if @c.rs_replicas(rs).zero?
              next rs if @c.rs_replicas(rs) == @c.rs_status_int(rs, "availableReplicas")

              count = [max_cleanup - total, @c.rs_replicas(rs) - @c.rs_status_int(rs, "availableReplicas")].min
              _scaled, scaled_rs = scale_replica_set(rs, @c.rs_replicas(rs) - count)
              total += count
              scaled_rs
            end
            [updated, total]
          end

          def scale_down_old_replica_sets_for_rolling_update(all_rss, old_rss)
            min_available = @c.replicas(@d) - @c.max_unavailable(@d)
            available = all_rss.sum { |rs| @c.rs_status_int(rs, "availableReplicas") }
            return 0 if available <= min_available

            total = 0
            budget = available - min_available
            old_rss.sort_by { |rs| @c.creation_sort_key(rs) }.each do |rs|
              break if total >= budget
              next if @c.rs_replicas(rs).zero?

              count = [@c.rs_replicas(rs), budget - total].min
              scale_replica_set(rs, @c.rs_replicas(rs) - count)
              total += count
            end
            total
          end

          # ---- recreate ----------------------------------------------------------

          def rollout_recreate
            result = all_replica_sets_and_sync_revision(false)
            return finish if result == :collision

            new_rs, old_rss = result
            all_rss = old_rss + [new_rs]
            scaled_down = active_replica_sets(old_rss).map { |rs| scale_replica_set(rs, 0).first }.any?
            return sync_rollout_status(all_rss, new_rs) if scaled_down
            return sync_rollout_status(all_rss, new_rs) if old_pods_running?(new_rs, old_rss)

            if new_rs.nil?
              result = all_replica_sets_and_sync_revision(true)
              return finish if result == :collision

              new_rs, old_rss = result
              all_rss = old_rss + [new_rs]
            end
            scale_replica_set(new_rs, @c.replicas(@d))
            cleanup_deployment(old_rss) if deployment_complete?(@original_status)
            sync_rollout_status(all_rss, new_rs)
          end

          def old_pods_running?(new_rs, old_rss)
            return true if old_rss.sum { |rs| @c.rs_status_int(rs, "replicas") }.positive?

            old_uids = old_rss.filter_map { |rs| Support.uid(rs) }
            @pods.any? do |pod|
              owner = Support.owner_references(pod).find { |reference| Support.ref_value(reference, "kind", "") == "ReplicaSet" }
              next false unless owner && old_uids.include?(Support.ref_value(owner, "uid", nil).to_s)
              next false if new_rs && Support.ref_value(owner, "uid", nil).to_s == Support.uid(new_rs)

              !%w[Failed Succeeded].include?(Support.value(Support.status(pod), "phase", "").to_s)
            end
          end

          # ---- rollback (deprecated annotation path) ------------------------------

          def rollback
            result = all_replica_sets_and_sync_revision(true)
            return finish if result == :collision

            new_rs, old_rss = result
            all_rss = old_rss + [new_rs]
            revision = @c.rollback_to(@d)
            if revision.zero?
              revision = last_revision(all_rss)
              if revision.zero?
                @events << @c.event("Warning", REASON_ROLLBACK_REVISION_NOT_FOUND, "Unable to find last revision.")
                return clear_rollback_to
              end
            end
            target = all_rss.compact.find { |rs| @c.revision_of(rs) == revision }
            unless target
              @events << @c.event("Warning", REASON_ROLLBACK_REVISION_NOT_FOUND, "Unable to find the revision to rollback to.")
              return clear_rollback_to
            end

            if @c.equal_ignore_hash?(Support.value(Support.spec(@d), "template", {}), Support.value(Support.spec(target), "template", {}))
              @events << @c.event("Warning", REASON_ROLLBACK_TEMPLATE_UNCHANGED,
                                  "The rollback revision contains the same template as current deployment \"#{Support.name(@d)}\"")
            else
              @d["spec"]["template"] = @c.template_without_hash(Support.value(Support.spec(target), "template", {}))
              skipped = Support.annotations(@d).select { |key, _| ANNOTATIONS_TO_SKIP.include?(key.to_s) }
              copied = Support.annotations(target).reject { |key, _| ANNOTATIONS_TO_SKIP.include?(key.to_s) }
              @d["metadata"]["annotations"] = skipped.merge(copied)
              @spec_dirty = true
              @events << @c.event("Normal", REASON_ROLLBACK_DONE, "Rolled back deployment \"#{Support.name(@d)}\" to revision #{revision}")
            end
            clear_rollback_to
          end

          def clear_rollback_to
            @d["metadata"]["annotations"] = Support.annotations(@d).reject { |key, _| key.to_s == ROLLBACK_TO_ANNOTATION }
            @d["metadata"].delete("annotations") if @d["metadata"]["annotations"].empty?
            @spec_dirty = true
            finish
          end

          # ---- history -----------------------------------------------------------

          def cleanup_deployment(old_rss)
            return unless @c.revision_history_limit?(@d)

            cleanable = old_rss.compact.reject { |rs| Support.metadata(rs).key?("deletionTimestamp") }
            diff = cleanable.length - @c.revision_history_limit(@d)
            return if diff <= 0

            sorted = cleanable.sort_by do |rs|
              revision = @c.revision_of(rs)
              [revision.nil? ? -1 : revision, @c.creation_sort_key(rs)]
            end
            sorted.first(diff).each do |rs|
              next if @c.rs_status_int(rs, "replicas") != 0 || @c.rs_replicas(rs) != 0
              next if Support.integer(Support.metadata(rs)["generation"], 0) > @c.rs_status_int(rs, "observedGeneration")

              @operations << @c.operation_delete(rs, descriptor: REPLICA_SET, reason: "revision history limit")
            end
          end

          # ---- status ------------------------------------------------------------

          def check_paused_conditions
            d = @d
            return unless @c.progress_deadline?(d)

            condition = @c.find_condition(@status, "Progressing")
            return if condition && Support.value(condition, "reason", "") == REASON_TIMED_OUT

            paused_exists = condition && Support.value(condition, "reason", "") == REASON_PAUSED
            if @c.paused?(d) && !paused_exists
              @c.set_condition!(@status, @c.new_condition("Progressing", "Unknown", REASON_PAUSED, "Deployment is paused", @now))
            elsif !@c.paused?(d) && paused_exists
              @c.set_condition!(@status, @c.new_condition("Progressing", "Unknown", REASON_RESUMED, "Deployment is resumed", @now))
            end
          end

          # sync.go calculateStatus
          def calculate_status(all_rss, new_rs)
            rss = all_rss.compact
            available = rss.sum { |rs| @c.rs_status_int(rs, "availableReplicas") }
            total = rss.sum { |rs| @c.rs_replicas(rs) }
            unavailable = [total - available, 0].max
            status = {
              "observedGeneration" => Support.integer(Support.metadata(@d)["generation"], 0),
              "replicas" => rss.sum { |rs| @c.rs_status_int(rs, "replicas") },
              "updatedReplicas" => new_rs ? @c.rs_status_int(new_rs, "replicas") : 0,
              "readyReplicas" => rss.sum { |rs| @c.rs_status_int(rs, "readyReplicas") },
              "availableReplicas" => available,
              "unavailableReplicas" => unavailable
            }
            status["collisionCount"] = @status["collisionCount"] if @status.key?("collisionCount")
            terminating = terminating_replica_count(rss)
            status["terminatingReplicas"] = terminating unless terminating.nil?
            status["conditions"] = Array(@status["conditions"]).map { |condition| Support.deep_copy(condition) }
            if available >= @c.replicas(@d) - @c.max_unavailable(@d)
              @c.set_condition!(status,
                                @c.new_condition("Available", "True", REASON_MIN_AVAILABLE, "Deployment has minimum availability.", @now))
            else
              @c.set_condition!(status,
                                @c.new_condition("Available", "False", REASON_MIN_UNAVAILABLE,
                                                 "Deployment does not have minimum availability.", @now))
            end
            status
          end

          # deployment_util.go GetTerminatingReplicaCountForReplicaSets
          def terminating_replica_count(rss)
            total = 0
            rss.each do |rs|
              status = Support.status(rs)
              next if @c.rs_status_int(rs, "observedGeneration").zero? && !status.key?("terminatingReplicas")
              return nil unless status.key?("terminatingReplicas")

              total += Support.integer(status["terminatingReplicas"], 0)
            end
            total
          end

          def sync_deployment_status(all_rss, new_rs)
            @status = calculate_status(all_rss, new_rs)
            finish
          end

          # progress.go syncRolloutStatus
          def sync_rollout_status(all_rss, new_rs)
            d = @d
            new_status = calculate_status(all_rss, new_rs)
            @c.remove_condition!(new_status, "Progressing") unless @c.progress_deadline?(d)
            current = @c.find_condition(@status, "Progressing")
            complete_deployment = new_status["replicas"] == new_status["updatedReplicas"] && current &&
                                  Support.value(current, "reason", "") == REASON_NEW_RS_AVAILABLE
            if @c.progress_deadline?(d) && !complete_deployment
              if deployment_complete?(new_status)
                message = if new_rs
                            "ReplicaSet \"#{Support.name(new_rs)}\" has successfully progressed."
                          else
                            "Deployment \"#{Support.name(d)}\" has " \
                              "successfully progressed."
                          end
                @c.set_condition!(new_status, @c.new_condition("Progressing", "True", REASON_NEW_RS_AVAILABLE, message, @now))
              elsif deployment_progressing?(new_status)
                message = new_rs ? "ReplicaSet \"#{Support.name(new_rs)}\" is progressing." : "Deployment \"#{Support.name(d)}\" is progressing."
                condition = @c.new_condition("Progressing", "True", REASON_REPLICA_SET_UPDATED, message, @now)
                if current
                  condition["lastTransitionTime"] = current["lastTransitionTime"] if Support.value(current, "status",
                                                                                                   "") == "True" && current.key?("lastTransitionTime")
                  @c.remove_condition!(new_status, "Progressing")
                end
                @c.set_condition!(new_status, condition)
              elsif deployment_timed_out?(new_status)
                message = new_rs ? "ReplicaSet \"#{Support.name(new_rs)}\" has timed out progressing." : "Deployment \"#{Support.name(d)}\" has timed out progressing."
                @c.set_condition!(new_status, @c.new_condition("Progressing", "False", REASON_TIMED_OUT, message, @now))
              end
            end

            failure = replica_failure_condition(all_rss, new_rs)
            if failure
              @c.set_condition!(new_status, failure)
            else
              @c.remove_condition!(new_status, "ReplicaFailure")
            end
            new_status.delete("conditions") if Array(new_status["conditions"]).empty?

            requeue_stuck_deployment(new_status) if Support.canonical(compact_status(@status)) == Support.canonical(compact_status(new_status))
            @status = new_status
            finish
          end

          def replica_failure_condition(all_rss, new_rs)
            candidates = [new_rs] + all_rss.compact.reject { |rs| new_rs && Support.name(rs) == Support.name(new_rs) }
            candidates.compact.each do |rs|
              condition = Array(Support.value(Support.status(rs), "conditions", [])).find do |value|
                Support.value(value, "type", "").to_s == "ReplicaFailure"
              end
              next unless condition

              return {"type" => "ReplicaFailure", "status" => Support.value(condition, "status", ""),
                      "lastUpdateTime" => Support.value(condition, "lastTransitionTime", @now.utc.iso8601(6)),
                      "lastTransitionTime" => Support.value(condition, "lastTransitionTime", @now.utc.iso8601(6)),
                      "reason" => Support.value(condition, "reason", ""), "message" => Support.value(condition, "message", "")}
            end
            nil
          end

          # deployment_util.go DeploymentComplete
          def deployment_complete?(status)
            replicas = @c.replicas(@d)
            Support.integer(status["updatedReplicas"], 0) == replicas &&
              Support.integer(status["replicas"], 0) == replicas &&
              Support.integer(status["availableReplicas"], 0) == replicas &&
              Support.integer(status["observedGeneration"], 0) >= Support.integer(Support.metadata(@d)["generation"], 0)
          end

          # deployment_util.go DeploymentProgressing
          def deployment_progressing?(new_status)
            old = @original_status
            old_old_replicas = Support.integer(old["replicas"], 0) - Support.integer(old["updatedReplicas"], 0)
            new_old_replicas = Support.integer(new_status["replicas"], 0) - Support.integer(new_status["updatedReplicas"], 0)
            Support.integer(new_status["updatedReplicas"], 0) > Support.integer(old["updatedReplicas"], 0) ||
              new_old_replicas < old_old_replicas ||
              Support.integer(new_status["readyReplicas"], 0) > Support.integer(old["readyReplicas"], 0) ||
              Support.integer(new_status["availableReplicas"], 0) > Support.integer(old["availableReplicas"], 0)
          end

          # deployment_util.go DeploymentTimedOut
          def deployment_timed_out?(new_status)
            return false unless @c.progress_deadline?(@d)

            condition = @c.find_condition(new_status, "Progressing")
            return false if condition.nil?
            return false if Support.value(condition, "reason", "") == REASON_NEW_RS_AVAILABLE
            return true if Support.value(condition, "reason", "") == REASON_TIMED_OUT

            from = Support.parse_time(Support.value(condition, "lastUpdateTime", nil))
            return false if from.nil?

            from + @c.progress_deadline_seconds(@d) < @now
          end

          # progress.go requeueStuckDeployment
          def requeue_stuck_deployment(new_status)
            current = @c.find_condition(@original_status, "Progressing")
            return unless @c.progress_deadline?(@d) && current
            return if deployment_complete?(new_status) || Support.value(current, "reason", "") == REASON_TIMED_OUT

            from = Support.parse_time(Support.value(current, "lastUpdateTime", nil))
            return if from.nil?

            after = (from + @c.progress_deadline_seconds(@d)) - @now
            # Below one second upstream uses the rate-limited queue; a bounded
            # short delay keeps the check from hot-looping on the same status.
            @requeue_after = after < 1.0 ? 1.0 : after + 1.0
          end

          # Every counter is written, zero included.  Upstream's UpdateStatus
          # replaces the whole status, so a counter that dropped to zero is
          # gone from the stored object; our status write is an apply, and a
          # counter simply left out of it kept its previous value when the
          # deployment's own full update had come to own the field.  A rollover
          # thus published replicas 1 / updatedReplicas 1 (stale) / available 1
          # for a moment -- "complete" to the e2e's check -- while the old
          # ReplicaSet still had its Pod ("deployment should support rollover").
          def compact_status(status)
            candidate = Support.deep_copy(status)
            %w[replicas updatedReplicas readyReplicas availableReplicas unavailableReplicas].each do |key|
              candidate[key] = Support.integer(candidate[key], 0)
            end
            candidate.delete("conditions") if Array(candidate["conditions"]).empty?
            candidate
          end

          def finish
            deployment = @deployment
            final_status = compact_status(@status)
            if @spec_dirty || @deployment_metadata_dirty
              candidate = Support.deep_copy(@d)
              candidate["status"] = Support.deep_copy(Support.status(deployment))
              update = @c.operation_update(deployment, candidate, descriptor: DESCRIPTOR,
                                                                  reason: @spec_dirty ? "deployment rollback" : "deployment revision")
              @operations << update if update
            end
            status_operation = @c.operation_status(deployment, final_status, descriptor: DESCRIPTOR)
            @operations << status_operation if status_operation
            ReconcileResult.new(operations: @operations, status: final_status, events: @events, controller: @c.name,
                                key: [Support.namespace(deployment), Support.name(deployment)].compact.join("/"),
                                requeue_after: @requeue_after)
          end
        end
      end
    end
  end
end
