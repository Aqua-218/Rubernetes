# frozen_string_literal: true

require "time"
require_relative "support"
require_relative "types"

module Rubernetes
  module Controller
    module Builtins
      # DaemonSet controller following pkg/controller/daemon at Kubernetes
      # v1.36.2: ControllerRevision history keyed by the template hash, per-node
      # placement through the node-affinity contract, RollingUpdate with
      # maxUnavailable/maxSurge, OnDelete, and the upstream status counters.
      class DaemonSetController < WorkloadController
        DESCRIPTOR = ResourceDescriptor.parse("DaemonSet")
        NODE = ResourceDescriptor.parse("Node")
        CONTROLLER_REVISION = ResourceDescriptor.parse("ControllerRevision")
        POD = WorkloadController::POD
        HASH_LABEL = "controller-revision-hash"
        TEMPLATE_GENERATION_LABEL = "pod-template-generation"
        TEMPLATE_GENERATION_ANNOTATION = "deprecated.daemonset.template.generation"
        DEFAULT_REVISION_HISTORY_LIMIT = 10
        DEFAULT_MAX_UNAVAILABLE = 1
        BURST_REPLICAS = 250
        # daemonset_util.go AddOrUpdateDaemonPodTolerations
        NO_EXECUTE_TOLERATIONS = %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].freeze
        NO_SCHEDULE_TOLERATIONS = %w[node.kubernetes.io/disk-pressure node.kubernetes.io/memory-pressure
                                     node.kubernetes.io/pid-pressure node.kubernetes.io/unschedulable].freeze

        def initialize(**options)
          @clock = options.delete(:clock) || -> { Time.now.utc }
          super
        end

        def plan(daemon_set, store: nil, pods: nil, nodes: nil, revisions: nil, controller_revisions: nil, now: nil, **_options)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(daemon_set))
          nodes ||= list_children(adapter, NODE, nil)
          revisions = controller_revisions unless controller_revisions.nil?
          revisions = list_children(adapter, CONTROLLER_REVISION, Support.namespace(daemon_set)) if revisions.nil? && adapter
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          Sync.new(self, daemon_set, owned(daemon_set, pods), Array(nodes), revisions, now).run
        end

        # The live copy of a Pod, or nil when this controller cannot read live.
        def live_pod(pod)
          adapter = store.is_a?(StoreAdapter) ? store : (store && StoreAdapter.new(store))
          return nil unless adapter.respond_to?(:find_live)

          adapter.find_live(POD, name: Support.name(pod), namespace: Support.namespace(pod))
        rescue StandardError
          nil
        end

        def scale(daemon_set, _replicas = nil, **)
          plan(daemon_set, **)
        end

        def delete(daemon_set, pods: nil, store: nil, orphan: false)
          adapter = store || (self.store && StoreAdapter.new(self.store))
          pods ||= list_children(adapter, POD, Support.namespace(daemon_set))
          operations = if orphan
                         []
                       else
                         owned(daemon_set, pods).map do |pod|
                           operation_delete(pod, descriptor: POD, reason: "daemonset deletion")
                         end
                       end
          operations << operation_delete(daemon_set, descriptor: DESCRIPTOR, reason: "daemonset deletion")
          ReconcileResult.new(operations: operations, controller: name)
        end

        def update_strategy(daemon_set)
          strategy = Support.value(Support.spec(daemon_set), "updateStrategy", {})
          strategy = {} unless strategy.is_a?(Hash)
          type = Support.value(strategy, "type", "RollingUpdate").to_s
          raise ArgumentError, "unsupported DaemonSet updateStrategy #{type.inspect}" unless %w[RollingUpdate OnDelete].include?(type)

          rolling = Support.value(strategy, "rollingUpdate", {})
          [type, rolling.is_a?(Hash) ? rolling : {}]
        end

        # daemonset_util.go SurgeCount / UnavailableCount
        def surge_count(daemon_set, number_to_schedule)
          type, rolling = update_strategy(daemon_set)
          return 0 unless type == "RollingUpdate"
          return 0 if Support.value(rolling, "maxSurge", nil).nil?

          Support.quantity(Support.value(rolling, "maxSurge", 0), number_to_schedule, mode: :ceil, default: 0)
        end

        def unavailable_count(daemon_set, number_to_schedule)
          type, rolling = update_strategy(daemon_set)
          return 0 unless type == "RollingUpdate"

          Support.quantity(Support.value(rolling, "maxUnavailable", DEFAULT_MAX_UNAVAILABLE), number_to_schedule, mode: :ceil, default: 0)
        end

        def allows_surge?(daemon_set)
          surge_count(daemon_set, 1).positive?
        end

        def min_ready_seconds(daemon_set)
          Support.integer(Support.value(Support.spec(daemon_set), "minReadySeconds", 0), 0)
        end

        def revision_history_limit(daemon_set)
          raw = Support.value(Support.spec(daemon_set), "revisionHistoryLimit", nil)
          raw.nil? ? DEFAULT_REVISION_HISTORY_LIMIT : Support.integer(raw, DEFAULT_REVISION_HISTORY_LIMIT)
        end

        # The apps registry stamps deprecated.daemonset.template.generation on
        # every create/update; metadata.generation is the same value for an
        # API server that has not stamped the annotation yet.
        def template_generation(daemon_set)
          raw = Support.annotations(daemon_set)[TEMPLATE_GENERATION_ANNOTATION]
          raw = Support.metadata(daemon_set)["generation"] if raw.nil?
          return nil if raw.nil?

          Integer(raw.to_s, 10)
        rescue ArgumentError, TypeError
          nil
        end

        # daemonset_util.go IsPodUpdated
        def pod_updated?(pod, hash, generation)
          labels = Support.labels(pod)
          (!generation.nil? && labels[TEMPLATE_GENERATION_LABEL].to_s == generation.to_s) ||
            (!hash.to_s.empty? && labels[HASH_LABEL].to_s == hash.to_s)
        end

        # daemonset_util.go GetTargetNodeName: spec.nodeName, else the
        # required node-affinity metadata.name term.
        def target_node_name(pod)
          node_name = Support.value(Support.spec(pod), "nodeName", nil).to_s
          return node_name unless node_name.empty?

          terms = Support.value(Support.value(Support.value(Support.value(Support.spec(pod), "affinity", {}), "nodeAffinity", {}),
                                              "requiredDuringSchedulingIgnoredDuringExecution", {}), "nodeSelectorTerms", [])
          Array(terms).each do |term|
            Array(Support.value(term, "matchFields", [])).each do |field|
              next unless Support.value(field, "key", "").to_s == "metadata.name" && Support.value(field, "operator", "").to_s == "In"

              values = Array(Support.value(field, "values", []))
              return values.first.to_s if values.length == 1 && !values.first.to_s.empty?
            end
          end
          nil
        end

        # daemon_controller.go getPatch: the strategic-merge patch replacing
        # spec.template is the ControllerRevision payload.
        def revision_data_for(daemon_set)
          template = Support.deep_copy(Support.value(Support.spec(daemon_set), "template", {}))
          template["$patch"] = "replace" if template.is_a?(Hash)
          {"spec" => {"template" => template}}
        end

        def revision_data(revision)
          raw = Support.value(revision, "data", nil)
          raw = JSON.parse(raw) if raw.is_a?(String)
          raw.is_a?(Hash) ? raw : {}
        rescue JSON::ParserError
          {}
        end

        def revision_number(revision)
          Support.integer(Support.value(revision, "revision", nil), 0)
        end

        def pod_terminal?(pod)
          %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
        end

        def pod_deleting?(pod)
          !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?
        end

        def event(type, reason, message)
          {"type" => type, "reason" => reason, "message" => message}
        end

        public :operation_create, :operation_delete, :operation_update, :operation_status, :pod_for, :template

        class Sync
          def initialize(controller, daemon_set, pods, nodes, revisions, now)
            @c = controller
            @ds = daemon_set
            @pods = pods
            @nodes = nodes
            @revisions = revisions
            @now = now
            @operations = []
            @events = []
            @status = Support.deep_copy(Support.status(daemon_set))
          end

          def run
            ds = @ds
            selector = Support.value(Support.spec(ds), "selector", {})
            if selector.nil? || (selector.is_a?(Hash) && selector.empty?)
              @events << @c.event("Warning", "SelectingAll", "This daemon set is selecting all pods. A non-empty selector is required.")
              return finish(status: nil)
            end
            return finish(status: nil) if Support.metadata(ds).key?("deletionTimestamp")

            current, old = construct_history
            hash = Support.labels(current)[HASH_LABEL].to_s
            pod_operations_before = pod_operation_count
            manage(hash)
            type, = @c.update_strategy(ds)
            # daemon_controller.go syncDaemonSet: the rolling update runs only
            # while the controller's create/delete expectations are satisfied.
            # Operations issued by manage() are exactly those expectations, so
            # the update waits for the next sync instead of planning a second
            # delete for the pod manage() already removes.
            rolling_update(hash) if type == "RollingUpdate" && pod_operation_count == pod_operations_before
            cleanup_history(old)
            finish(status: calculate_status(hash))
          end

          private

          def pod_operation_count
            @operations.count { |operation| operation.respond_to?(:resource) && operation.resource.kind == "Pod" }
          end

          # ---- history ------------------------------------------------------------

          def owned_revisions
            return nil if @revisions.nil?

            Array(@revisions).select do |revision|
              Support.kind(revision) == "ControllerRevision" && Support.owner_reference_matches?(@ds, revision, controller: true)
            end
          end

          # update.go constructHistory
          def construct_history
            data = @c.revision_data_for(@ds)
            histories = owned_revisions
            collision_count = @status.key?("collisionCount") ? Support.integer(@status["collisionCount"], 0) : nil
            hash = Support.pod_template_hash(Support.value(Support.spec(@ds), "template", {}), collision_count)
            if histories.nil?
              # Direct planner invocation without a history lister: the
              # revision identity is still needed to label Pods.
              return [snapshot_object(data, hash, 1), []]
            end

            current_histories = []
            old = []
            histories.each do |history|
              candidate = history
              unless Support.labels(history).key?(HASH_LABEL)
                candidate = Support.deep_copy(history)
                candidate["metadata"]["labels"] = Support.labels(candidate).merge(HASH_LABEL => Support.name(candidate))
                @operations << @c.operation_update(history, candidate, descriptor: CONTROLLER_REVISION, reason: "daemonset history label")
              end
              if Support.canonical(@c.revision_data(candidate)) == Support.canonical(data)
                current_histories << candidate
              else
                old << candidate
              end
            end
            current_revision_number = old.map { |history| @c.revision_number(history) }.max.to_i + 1
            if current_histories.empty?
              current = snapshot(data, hash, current_revision_number, histories)
              return [current, old] if current

              # A name collision with a different template bumps the
              # collision count; the next sync computes a fresh hash.
              @status["collisionCount"] = Support.integer(@status["collisionCount"], 0) + 1
              return [snapshot_object(data, hash, current_revision_number), old]
            end

            current = dedup_current_histories(current_histories)
            if @c.revision_number(current) < current_revision_number
              bumped = Support.deep_copy(current)
              bumped["revision"] = current_revision_number
              @operations << @c.operation_update(current, bumped, descriptor: CONTROLLER_REVISION, reason: "daemonset history revision")
              current = bumped
            end
            [current, old]
          end

          def snapshot_object(data, hash, revision)
            ds = @ds
            template_labels = Support.value(Support.value(Support.value(Support.spec(ds), "template", {}), "metadata", {}), "labels", {})
            template_labels = {} unless template_labels.is_a?(Hash)
            object = {
              "apiVersion" => "apps/v1", "kind" => "ControllerRevision",
              "metadata" => {"name" => "#{Support.name(ds)}-#{hash}", "namespace" => Support.namespace(ds),
                             "labels" => Support.deep_copy(template_labels).merge(HASH_LABEL => hash),
                             "ownerReferences" => [Support.owner_reference(ds)]},
              "data" => Support.deep_copy(data),
              "revision" => revision
            }
            annotations = Support.annotations(ds)
            object["metadata"]["annotations"] = Support.deep_copy(annotations) unless annotations.empty?
            object
          end

          # update.go snapshot
          def snapshot(data, hash, revision, histories)
            object = snapshot_object(data, hash, revision)
            existing = histories.find { |history| Support.name(history) == Support.name(object) }
            if existing
              return existing if Support.canonical(@c.revision_data(existing)) == Support.canonical(data)

              return nil
            end
            @operations << @c.operation_create(object, owner: @ds, descriptor: CONTROLLER_REVISION, reason: "daemonset history")
            object
          end

          # update.go dedupCurHistories
          def dedup_current_histories(current_histories)
            return current_histories.first if current_histories.length == 1

            keep = current_histories.max_by { |history| [@c.revision_number(history), Support.name(history)] }
            keep_hash = Support.labels(keep)[HASH_LABEL]
            @pods.each do |pod|
              next if Support.labels(pod)[HASH_LABEL] == keep_hash

              candidate = Support.deep_copy(pod)
              candidate["metadata"]["labels"] = Support.labels(candidate).merge(HASH_LABEL => keep_hash)
              @operations << @c.operation_update(pod, candidate, descriptor: POD, reason: "daemonset history dedup")
            end
            current_histories.each do |history|
              next if Support.name(history) == Support.name(keep)

              @operations << @c.operation_delete(history, descriptor: CONTROLLER_REVISION, reason: "daemonset history dedup")
            end
            keep
          end

          # update.go cleanupHistory
          def cleanup_history(old)
            to_kill = old.length - @c.revision_history_limit(@ds)
            return if to_kill <= 0

            live = @pods.filter_map { |pod| Support.labels(pod)[HASH_LABEL] }.reject(&:empty?)
            old.sort_by { |history| [@c.revision_number(history), Support.name(history)] }.each do |history|
              break if to_kill <= 0
              next if live.include?(Support.labels(history)[HASH_LABEL].to_s)

              @operations << @c.operation_delete(history, descriptor: CONTROLLER_REVISION, reason: "daemonset revision history limit")
              to_kill -= 1
            end
          end

          # ---- placement ------------------------------------------------------------

          def daemon_pod_template
            template = @c.template(@ds)
            template["spec"] ||= {}
            template["spec"]["tolerations"] = daemon_tolerations(Array(template["spec"]["tolerations"]),
                                                                 host_network: Support.value(template["spec"], "hostNetwork",
                                                                                             false) == true)
            template
          end

          def daemon_tolerations(tolerations, host_network:)
            values = tolerations.map { |entry| Support.deep_copy(entry) }
            desired = NO_EXECUTE_TOLERATIONS.map { |key| {"key" => key, "operator" => "Exists", "effect" => "NoExecute"} }
            desired += NO_SCHEDULE_TOLERATIONS.map { |key| {"key" => key, "operator" => "Exists", "effect" => "NoSchedule"} }
            desired << {"key" => "node.kubernetes.io/network-unavailable", "operator" => "Exists", "effect" => "NoSchedule"} if host_network
            desired.each do |toleration|
              index = values.index do |entry|
                Support.value(entry, "key", "").to_s == toleration["key"] && Support.value(entry, "effect", "").to_s == toleration["effect"]
              end
              index.nil? ? values << toleration : values[index] = toleration
            end
            values
          end

          # daemon_controller.go NodeShouldRunDaemonPod: [should_run, should_continue_running]
          def node_should_run?(node)
            template = daemon_pod_template
            spec = template["spec"]
            node_name = Support.value(spec, "nodeName", "").to_s
            return [false, false] unless node_name.empty? || node_name == Support.name(node)
            return [false, false] unless required_node_affinity_matches?(spec, node)

            taints = Array(Support.value(Support.spec(node), "taints", []))
            tolerations = Array(spec["tolerations"])
            untolerated = taints.select do |taint|
              effect = Support.value(taint, "effect", "").to_s
              %w[NoExecute NoSchedule].include?(effect) && tolerations.none? { |toleration| tolerates?(toleration, taint) }
            end
            return [true, true] if untolerated.empty?

            untolerated_no_execute = untolerated.any? { |taint| Support.value(taint, "effect", "").to_s == "NoExecute" }
            [false, !untolerated_no_execute]
          end

          def required_node_affinity_matches?(spec, node)
            labels = Support.labels(node)
            selector = Support.value(spec, "nodeSelector", {})
            selector = {} unless selector.is_a?(Hash)
            return false unless selector.all? { |key, value| labels[key.to_s].to_s == value.to_s }

            required = Support.value(Support.value(Support.value(spec, "affinity", {}), "nodeAffinity", {}),
                                     "requiredDuringSchedulingIgnoredDuringExecution", nil)
            return true if required.nil?

            terms = Array(Support.value(required, "nodeSelectorTerms", []))
            return true if terms.empty?

            terms.any? do |term|
              Array(Support.value(term, "matchExpressions", [])).all? { |expression| requirement_matches?(expression, labels) } &&
                Array(Support.value(term, "matchFields", [])).all? do |expression|
                  requirement_matches?(expression, {"metadata.name" => Support.name(node)})
                end
            end
          end

          def requirement_matches?(expression, labels)
            key = Support.value(expression, "key", "").to_s
            values = Array(Support.value(expression, "values", [])).map(&:to_s)
            present = labels.key?(key)
            actual = labels[key].to_s
            case Support.value(expression, "operator", "In").to_s
            when "In" then present && values.include?(actual)
            when "NotIn" then !present || !values.include?(actual)
            when "Exists" then present
            when "DoesNotExist" then !present
            when "Gt" then present && Integer(actual, 10) > Integer(values.first.to_s, 10)
            when "Lt" then present && Integer(actual, 10) < Integer(values.first.to_s, 10)
            else false
            end
          rescue ArgumentError, TypeError
            false
          end

          def tolerates?(toleration, taint)
            effect = Support.value(toleration, "effect", "").to_s
            return false unless effect.empty? || effect == Support.value(taint, "effect", "").to_s

            key = Support.value(toleration, "key", "").to_s
            operator = Support.value(toleration, "operator", "Equal").to_s
            case operator
            when "Exists" then key.empty? || key == Support.value(taint, "key", "").to_s
            else key == Support.value(taint, "key",
                                      "").to_s && Support.value(toleration, "value", "").to_s == Support.value(taint, "value", "").to_s
            end
          end

          # daemon_controller.go getNodesToDaemonPods
          def nodes_to_daemon_pods(include_deleted_terminal: false)
            @pods.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |pod, result|
              next if !include_deleted_terminal && @c.pod_terminal?(pod) && @c.pod_deleting?(pod)

              node_name = @c.target_node_name(pod)
              next if node_name.nil? || node_name.empty?

              result[node_name] << pod
            end
          end

          # An old Pod the cache reports unavailable is replaced without
          # counting against maxUnavailable, so the cache must not be behind:
          # a DaemonSet updated the moment its Pods turned Ready had every
          # one of them deleted at once ("number of unavailable pods: 3 is
          # greater than maxUnavailable: 1") because the informer had not yet
          # seen them Ready.  The live object decides.
          def old_pod_available?(pod)
            return true if pod_available?(pod)

            live = @c.live_pod(pod)
            !live.nil? && pod_available?(live)
          end

          def pod_available?(pod)
            Support.pod_available?(pod, @c.min_ready_seconds(@ds), @now)
          end

          def pod_sort_key(pod)
            created = Support.creation_time(pod)
            [Support.value(Support.spec(pod), "nodeName", "").to_s.empty? ? 1 : 0, created ? created.to_f : 0.0, Support.name(pod)]
          end

          # daemon_controller.go manage + podsShouldBeOnNode
          def manage(hash)
            node_to_pods = nodes_to_daemon_pods
            nodes_needing = []
            to_delete = []
            @nodes.sort_by { |node| Support.name(node) }.each do |node|
              should_run, should_continue = node_should_run?(node)
              daemon_pods = node_to_pods.fetch(Support.name(node), nil)
              if should_run && daemon_pods.nil?
                nodes_needing << Support.name(node)
              elsif should_continue
                running = []
                Array(daemon_pods).each do |pod|
                  next if @c.pod_deleting?(pod)

                  phase = Support.value(Support.status(pod), "phase", "").to_s
                  if phase == "Failed"
                    @events << @c.event("Warning", "FailedDaemonPod",
                                        "Found failed daemon pod #{Support.namespace(pod)}/#{Support.name(pod)} on node #{Support.name(node)}, will try to " \
                                        "kill it")
                    to_delete << pod
                  elsif phase == "Succeeded"
                    @events << @c.event("Normal", "SucceededDaemonPod",
                                        "Found succeeded daemon pod #{Support.namespace(pod)}/#{Support.name(pod)} on node #{Support.name(node)}, will try to delete it")
                    to_delete << pod
                  else
                    running << pod
                  end
                end
                unless @c.allows_surge?(@ds)
                  next if running.length <= 1

                  running.sort_by { |pod| pod_sort_key(pod) }.drop(1).each { |pod| to_delete << pod }
                  next
                end
                if running.length <= 1
                  nodes_needing << Support.name(node) if running.empty? && should_run
                  next
                end
                oldest_new = nil
                oldest_old = nil
                running.sort_by { |pod| pod_sort_key(pod) }.each do |pod|
                  if Support.labels(pod)[HASH_LABEL] == hash
                    if oldest_new.nil?
                      oldest_new = pod
                      next
                    end
                  elsif oldest_old.nil?
                    oldest_old = pod
                    next
                  end
                  to_delete << pod
                end
                to_delete << oldest_old if oldest_new && oldest_old && (!Support.ready?(oldest_old) || pod_available?(oldest_new))
              elsif !should_continue && daemon_pods
                daemon_pods.each { |pod| to_delete << pod unless @c.pod_deleting?(pod) }
              end
            end
            node_names = @nodes.map { |node| Support.name(node) }
            node_to_pods.each do |node_name, pods|
              next if node_names.include?(node_name)

              pods.each do |pod|
                to_delete << pod if Support.value(Support.spec(pod), "nodeName", "").to_s.empty? && !@c.pod_deleting?(pod)
              end
            end
            sync_nodes(to_delete, nodes_needing, hash)
          end

          # daemon_controller.go syncNodes
          def sync_nodes(pods_to_delete, nodes_needing, hash)
            ds = @ds
            template = daemon_pod_template
            generation = @c.template_generation(ds)
            labels = {HASH_LABEL => hash}
            labels[TEMPLATE_GENERATION_LABEL] = generation.to_s unless generation.nil?
            nodes_needing.uniq.first(BURST_REPLICAS).each do |node_name|
              candidate = @c.pod_for(ds, name: nil, template_value: template, labels: labels)
              candidate["metadata"].delete("name")
              candidate["metadata"]["generateName"] = "#{Support.name(ds)}-"
              candidate["spec"]["affinity"] = replace_node_name_affinity(Support.value(candidate["spec"], "affinity", nil), node_name)
              @operations << @c.operation_create(candidate, owner: ds, descriptor: POD, reason: "daemonset node assignment",
                                                            operation_key: "registry/v1/pods/#{Support.namespace(ds)}/#{Support.uid(ds)}:#{node_name}:#{hash}")
              @events << @c.event("Normal", "SuccessfulCreate", "Created pod: #{Support.name(ds)}-#{node_name}-#{hash}")
            end
            pods_to_delete.uniq { |pod| Support.uid(pod) || Support.name(pod) }.first(BURST_REPLICAS).each do |pod|
              @operations << @c.operation_delete(pod, descriptor: POD, reason: "daemonset pod removal")
              @events << @c.event("Normal", "SuccessfulDelete", "Deleted pod: #{Support.name(pod)}")
            end
          end

          # daemonset_util.go ReplaceDaemonSetPodNodeNameNodeAffinity
          def replace_node_name_affinity(affinity, node_name)
            term = {"matchFields" => [{"key" => "metadata.name", "operator" => "In", "values" => [node_name]}]}
            result = affinity.is_a?(Hash) ? Support.deep_copy(affinity) : {}
            node_affinity = result["nodeAffinity"].is_a?(Hash) ? result["nodeAffinity"] : {}
            node_affinity["requiredDuringSchedulingIgnoredDuringExecution"] = {"nodeSelectorTerms" => [term]}
            result["nodeAffinity"] = node_affinity
            result
          end

          # ---- rolling update ----------------------------------------------------

          # update.go findUpdatedPodsOnNode: [new_pod, old_pod, ok]
          def updated_pods_on_node(pods, hash, generation)
            new_pod = nil
            old_pod = nil
            pods.each do |pod|
              next if @c.pod_deleting?(pod)

              if @c.pod_updated?(pod, hash, generation)
                return [nil, nil, false] if new_pod

                new_pod = pod
              else
                return [nil, nil, false] if old_pod

                old_pod = pod
              end
            end
            [new_pod, old_pod, true]
          end

          # update.go rollingUpdate
          def rolling_update(hash)
            ds = @ds
            node_to_pods = nodes_to_daemon_pods
            generation = @c.template_generation(ds)
            desired = 0
            @nodes.each do |node|
              should_run, = node_should_run?(node)
              next unless should_run

              desired += 1
              node_to_pods[Support.name(node)] = [] unless node_to_pods.key?(Support.name(node))
            end
            max_unavailable = @c.unavailable_count(ds, desired)
            max_surge = @c.surge_count(ds, desired)
            max_unavailable = 1 if desired.positive? && max_unavailable.zero? && max_surge.zero?

            if max_surge.zero?
              num_unavailable = 0
              allowed_replacements = []
              candidates = []
              node_to_pods.sort_by { |node_name, _| node_name }.each do |_node_name, pods|
                new_pod, old_pod, ok = updated_pods_on_node(pods, hash, generation)
                unless ok
                  num_unavailable += 1
                  next
                end
                if (old_pod.nil? && new_pod.nil?) || (old_pod && new_pod)
                  num_unavailable += 1
                elsif new_pod
                  num_unavailable += 1 unless pod_available?(new_pod)
                elsif !old_pod_available?(old_pod)
                  allowed_replacements << old_pod
                  num_unavailable += 1
                elsif num_unavailable >= max_unavailable
                  next
                else
                  candidates << old_pod
                end
              end
              remaining = [max_unavailable - num_unavailable, 0].max
              remaining = [remaining, candidates.length].min
              sync_nodes(allowed_replacements + candidates.first(remaining), [], hash)
              return
            end

            old_pods_to_delete = []
            should_not_run_pods = []
            candidate_nodes = []
            allowed_nodes = []
            num_surge = 0
            num_available = 0
            nodes_by_name = @nodes.to_h { |node| [Support.name(node), node] }
            node_to_pods.sort_by { |node_name, _| node_name }.each do |node_name, pods|
              new_pod, old_pod, ok = updated_pods_on_node(pods, hash, generation)
              unless ok
                num_surge += 1
                next
              end
              if old_pod
                num_available += 1 if pod_available?(old_pod)
              elsif new_pod
                num_available += 1 if pod_available?(new_pod)
              end
              if old_pod.nil?
                next
              elsif new_pod.nil?
                node = nodes_by_name[node_name]
                should_run = node ? node_should_run?(node).first : false
                if pod_available?(old_pod)
                  unless should_run
                    should_not_run_pods << old_pod
                    next
                  end
                  next if num_surge >= max_surge

                  candidate_nodes << node_name
                else
                  unless should_run
                    old_pods_to_delete << old_pod
                    next
                  end
                  allowed_nodes << node_name
                end
              elsif !pod_available?(new_pod)
                num_surge += 1
              else
                old_pods_to_delete << old_pod
              end
            end
            remaining_surge = max_surge - num_surge
            deletable = num_available - desired
            if deletable.positive?
              deletable = [deletable, should_not_run_pods.length].min
              old_pods_to_delete.concat(should_not_run_pods.first(deletable))
            end
            remaining_surge = [[remaining_surge, 0].max, candidate_nodes.length].min
            sync_nodes(old_pods_to_delete, allowed_nodes + candidate_nodes.first(remaining_surge), hash)
          end

          # ---- status ------------------------------------------------------------

          # daemon_controller.go updateDaemonSetStatus
          def calculate_status(hash)
            ds = @ds
            node_to_pods = nodes_to_daemon_pods
            generation = @c.template_generation(ds)
            desired = current = misscheduled = ready = updated = available = 0
            @nodes.each do |node|
              should_run, = node_should_run?(node)
              pods = node_to_pods.fetch(Support.name(node), [])
              scheduled = pods.any?
              if should_run
                desired += 1
                next unless scheduled

                current += 1
                pod = pods.min_by { |candidate| pod_sort_key(candidate) }
                if Support.ready?(pod)
                  ready += 1
                  available += 1 if pod_available?(pod)
                end
                updated += 1 if @c.pod_updated?(pod, hash, generation)
              elsif scheduled
                misscheduled += 1
              end
            end
            status = Support.deep_copy(@status)
            status["desiredNumberScheduled"] = desired
            status["currentNumberScheduled"] = current
            status["numberMisscheduled"] = misscheduled
            status["numberReady"] = ready
            # Zero counters are written, not omitted: a status apply that
            # leaves a counter out does not clear the stored value.
            status["updatedNumberScheduled"] = updated
            status["numberAvailable"] = available
            unavailable = desired - available
            status["numberUnavailable"] = unavailable
            status.delete("numberScheduled")
            status["observedGeneration"] =
              Support.integer(Support.metadata(ds)["generation"], Support.integer(status["observedGeneration"], 0))
            status
          end

          def finish(status:)
            ds = @ds
            if status
              template_generation = status["observedGeneration"].to_i
              current_annotation = Support.annotations(ds)[TEMPLATE_GENERATION_ANNOTATION].to_s
              if template_generation.positive? && current_annotation != template_generation.to_s
                candidate = Support.deep_copy(ds)
                candidate["metadata"] ||= {}
                candidate["metadata"]["annotations"] =
                  Support.annotations(candidate).merge(TEMPLATE_GENERATION_ANNOTATION => template_generation.to_s)
                @operations.unshift(@c.operation_update(ds, candidate, descriptor: DESCRIPTOR, reason: "daemonset template generation"))
              end
              status_operation = @c.operation_status(ds, status, descriptor: DESCRIPTOR)
              @operations << status_operation if status_operation
            end
            ReconcileResult.new(operations: @operations.compact, status: status || Support.status(ds), events: @events,
                                controller: @c.name, key: [Support.namespace(ds), Support.name(ds)].compact.join("/"))
          end
        end
      end
    end
  end
end
