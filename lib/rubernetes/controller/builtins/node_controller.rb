# frozen_string_literal: true

require_relative "../../taint_toleration"

module Rubernetes
  module Controller
    module Builtins
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
          adapter = store || @adapter
          pods ||= adapter ? adapter.list(POD, namespace: :all) : []
          now = Support.parse_time(now) || Support.parse_time(@clock.call)
          raise ArgumentError, "clock must return Time or RFC3339 value" unless now

          stale, desired_status, unhealthy = node_health(node, adapter, lease, now)
          candidate = Support.deep_copy(node)
          candidate["status"] ||= {}
          candidate["status"]["conditions"] = ready_conditions(candidate, desired_status, stale)
          eviction_taint = apply_no_execute_taint(candidate, desired_status, unhealthy)
          apply_no_schedule_taints(candidate, node)
          zone = self.class.zone_key(node)
          operations = node_writes(node, candidate, unhealthy, zone)
          record_zone_health(Support.name(node), zone, desired_status == "True")
          ControllerMetrics.observe("node_collector_update_node_health_duration_seconds",
                                    Process.clock_gettime(Process::CLOCK_MONOTONIC) - health_started)
          operations.concat(eviction_operations(node, pods, eviction_taint)) if unhealthy
          events = unhealthy ? [{"type" => "Warning", "reason" => "NodeNotReady", "message" => "node #{Support.name(node)} is not ready"}] : []
          ReconcileResult.new(operations: operations, status: Support.status(candidate), events: events,
                              controller: name, key: Support.name(node))
        end

        def heartbeat(node, now: nil, store: nil)
          plan(node, now: now, store: store)
        end

        def delete(node, pods: nil, store: nil, orphan: false)
          adapter = store || @adapter
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

        # monitorNodeHealth: [stale, the Ready status to publish, unhealthy for
        # long enough to be tainted for eviction].
        def node_health(node, adapter, lease, now)
          ready_condition = Support.condition(node, "Ready") || {}
          # The node lease is the primary heartbeat (monitorNodeHealth observes
          # the lease's renewTime and only falls back to the condition stamp).
          # Reading the condition alone declares a healthy node stale as soon as
          # its status stops changing, which taints it out of the scheduler.
          heartbeat = [Support.parse_time(Support.value(ready_condition, "lastHeartbeatTime", nil)),
                       Support.parse_time(Support.value(ready_condition, "lastTransitionTime", nil)),
                       node_lease_renewal(node, adapter, lease)].compact.max
          stale = heartbeat.nil? || (now - heartbeat) > @heartbeat_grace_seconds
          desired_status = stale ? "Unknown" : Support.value(ready_condition, "status", "Unknown").to_s
          unhealthy_since = Support.parse_time(Support.value(ready_condition, "lastTransitionTime", nil)) || heartbeat || now
          unhealthy = %w[Unknown False].include?(desired_status) && (now - unhealthy_since) >= @taint_delay_seconds
          [stale, desired_status, unhealthy]
        end

        # The candidate's conditions with Ready set to +desired_status+.
        def ready_conditions(candidate, desired_status, stale)
          conditions = Array(candidate["status"]["conditions"]).map { |condition| Support.deep_copy(condition) }
          desired = conditions.find { |condition| Support.value(condition, "type", "") == "Ready" }
          if desired
            desired["status"] = desired_status
            desired["reason"] = stale ? "NodeStatusUnknown" : Support.value(desired, "reason", "")
          else
            conditions << {"type" => "Ready", "status" => desired_status,
                           "reason" => stale ? "NodeStatusUnknown" : "NodeReady"}
          end
          conditions
        end

        # doNoExecuteTaintingPass: replaces this controller's NoExecute taints
        # on the candidate with the one its health calls for, and returns that
        # taint (nil for a node that is not to be evicted).
        def apply_no_execute_taint(candidate, desired_status, unhealthy)
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
            return taints.find { |taint| Support.value(taint, "key", "") == key && Support.value(taint, "effect", "") == "NoExecute" }
          end

          unless Array(Support.value(Support.spec(candidate), "taints", [])).empty?
            candidate["spec"] ||= {}
            candidate["spec"]["taints"] = taints
          end
          nil
        end

        # doNoScheduleTaintingPass: the NoSchedule condition taints are a pure
        # function of the node's conditions plus spec.unschedulable.  Without
        # this the not-ready:NoSchedule taint that admission stamps on a new
        # node is never removed once it becomes Ready, and nothing can ever be
        # scheduled onto it.
        def apply_no_schedule_taints(candidate, node)
          candidate["spec"] ||= {}
          candidate["spec"]["taints"] = reconcile_no_schedule_taints(candidate,
                                                                     Array(Support.value(Support.spec(candidate), "taints", [])))
          candidate["spec"].delete("taints") if candidate["spec"]["taints"].empty? &&
                                                Array(Support.value(Support.spec(node), "taints", [])).empty?
        end

        # Two writes, as upstream issues them: the Ready condition through
        # the status subresource (tryUpdateNodeHealth -> UpdateStatus) and
        # the taints through the primary resource (AddOrUpdateTaintOnNode).
        # A single PUT of the whole object would carry both, but the API
        # server ignores status on the primary URL: the taint landed and the
        # node stayed "Ready", so the unreachable:NoSchedule taint was never
        # derived and the scheduler kept placing Pods that the NoExecute
        # taint then evicted, over and over.
        def node_writes(node, candidate, unhealthy, zone)
          status_update = operation_status(node, Support.status(candidate), descriptor: DESCRIPTOR, reason: "node heartbeat/status")
          # The taint write is issued only when spec/metadata changed; it
          # carries the new status too, so an in-memory store (which honours
          # status on a primary write) ends up identical to the API server's
          # view and a second pass over the result is a no-op.
          spec_candidate = Support.deep_copy(candidate)
          spec_candidate["status"] = Support.deep_copy(Support.status(node))
          update = spec_candidate == node ? nil : operation_update(node, candidate, descriptor: DESCRIPTOR, reason: "node taints")
          if update && unhealthy && !self.class.eviction_tainted?(node)
            # doNoExecuteTaintingPass: a node newly tainted for eviction.
            update = update.observed do |succeeded, _|
              ControllerMetrics.increment("node_collector_evictions_total", {"zone" => zone}) if succeeded
            end
          end
          [status_update, update].compact
        end

        # The node's Pods that do not tolerate the eviction taint are deleted.
        def eviction_operations(node, pods, eviction_taint)
          owned_pods = Array(pods).select { |pod| Support.value(Support.spec(pod), "nodeName", nil).to_s == Support.name(node) }
          owned_pods.reject { |pod| tolerates_taint?(pod, eviction_taint) }.map do |pod|
            operation_delete(pod, descriptor: POD, reason: "node taint eviction")
          end
        end

        # The lease in kube-node-lease named after the node; absent for a node
        # that has not started reporting yet, which stays a stale node.
        def node_lease_renewal(node, adapter, injected)
          lease = injected
          lease ||= Array(adapter&.list(LEASE, namespace: NODE_LEASE_NAMESPACE)).find do |candidate|
            Support.name(candidate) == Support.name(node)
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
          Array(Support.value(Support.spec(pod), "tolerations", [])).any? { |entry| TaintToleration.matches?(entry, taint) }
        end
      end
    end
  end
end
