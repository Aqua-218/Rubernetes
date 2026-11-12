# frozen_string_literal: true

module Rubernetes
  module Node
    class Agent
      # Sending the Node's status to the API: on a change, on the report
      # frequency, and at once when a device plugin or the volumes in use
      # changed.
      module StatusReporting
        def set_ready(value, reason: nil, message: nil, persist: true)
          @mutex.synchronize { @ready = !!value }
          return unless persist

          persist_node(build_node(ready: value, reason: reason, message: message))
        end

        # kubelet syncNodeStatus / tryUpdateNodeStatus: the status is rebuilt
        # and patched when it differs from the last one reported (heartbeat
        # times aside) or when the report frequency has elapsed; either way
        # the volumes the Node carries are marked reported in use.  Public for
        # a deterministic tick.
        def sync_node_status(force: false)
          return false unless registered?

          node = build_node(ready: ready?)
          last, last_at = @mutex.synchronize { [@last_reported_status, @last_status_report_at] }
          due = last_at.nil? || Process.clock_gettime(Process::CLOCK_MONOTONIC) - last_at >= @node_status_report_frequency
          if force || due || self.class.node_status_changed?(last, node["status"])
            persist_node(node)
            true
          else
            mark_volumes_from_status(last)
            false
          end
        end

        # A pending desired-state change: the status thread wakes at once.
        def request_node_status_sync
          @mutex.synchronize do
            @node_status_requested = true
            @node_status_condition.broadcast
          end
          true
        end

        private

        def persist_node(object)
          status = object.is_a?(Hash) ? object["status"] : nil
          persisted = write_node(with_status_tombstones(object, status))
          @kubelet_metrics&.node_registered if api_created_node?
          node_status_persisted(persisted)
          @mutex.synchronize do
            @last_reported_status = status
            @last_status_report_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          end
          mark_volumes_from_status(status)
          persisted
        end

        # updateNodeStatus: a status the API server took with Ready=True
        # (RecordNodeReady).
        def node_status_persisted(response)
          conditions = response.is_a?(Hash) ? Array(response.dig("status", "conditions")) : []
          ready = conditions.any? { |condition| condition.is_a?(Hash) && condition["type"] == "Ready" && condition["status"] == "True" }
          @kubelet_metrics&.node_ready if ready
        end

        # nodeutil.PatchNodeStatus sends the difference between the last Node
        # and this one, so a status field that went away (the last volume in
        # use, a condition) arrives as null and is removed.  The built status
        # is compacted; the keys the last report had and this one lacks are
        # sent as null (a merge patch deletes them).
        def with_status_tombstones(object, status)
          previous = @mutex.synchronize { @last_reported_status }
          return object unless object.is_a?(Hash) && previous.is_a?(Hash) && status.is_a?(Hash)

          gone = previous.keys.map(&:to_s) - status.keys.map(&:to_s)
          return object if gone.empty?

          object.merge("status" => status.merge(gone.to_h { |key| [key, nil] }))
        end

        def persist_pressure_conditions
          return unless registered?

          persist_node(build_node(ready: ready?))
        end

        def mark_volumes_from_status(status)
          names = status.is_a?(Hash) ? Array(status["volumesInUse"]) : []
          @lifecycle.mark_volumes_reported_in_use(names)
        rescue StandardError => error
          @error_handler&.call(error)
        end

        def start_node_status_thread
          return unless wall_clock?

          @mutex.synchronize do
            return if @node_status_thread&.alive?

            @node_status_thread = Thread.new { node_status_loop }
          end
        end

        def node_status_loop
          until @mutex.synchronize { @stop_requested }
            begin
              sync_node_status
            rescue StandardError => error
              @error_handler&.call(error)
            end
            wait_for_node_status_interval
          end
        end

        def wait_for_node_status_interval
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @node_status_update_frequency
          @mutex.synchronize do
            until @stop_requested || @node_status_requested
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              break if remaining <= 0

              @node_status_condition.wait(@mutex, remaining)
            end
            @node_status_requested = false
          end
        end

        # kubelet nodestatus MachineInfo: every resource in the Node's capacity is
        # carried into allocatable on each status sync, including extended
        # resources this agent does not manage itself, and extended resources
        # gone from capacity leave allocatable.  The agent never did this, so a
        # resource a client wrote into capacity never became allocatable, the
        # scheduler could place nothing that requested it, and the agent's own
        # admission rejected it anyway -- "[sig-scheduling] SchedulerPreemption
        # PreemptionExecutionPath runs ReplicaSets to verify preemption running
        # path" adds "example.com/fakecpu" and its ReplicaSets never ran.
        def sync_extended_resources
          return unless node_adapter?

          node = @api.read_object("nodes", @node_name)
          status = node.is_a?(Hash) ? (node["status"] || {}) : {}
          capacity = status["capacity"].is_a?(Hash) ? status["capacity"] : {}
          allocatable = status["allocatable"].is_a?(Hash) ? status["allocatable"] : {}
          # Device plugin resources are this agent's own (allocatable = the
          # healthy devices); only the others are carried over from capacity.
          managed = @device_plugins ? @device_plugins.resource_names : []
          extended = capacity.select do |name, _|
            ResourceManager.extended_resource?(name) && !@capacity.key?(name.to_s) && !managed.include?(name.to_s)
          end
          patch = extended.reject { |name, value| allocatable[name] == value }
          allocatable.each_key do |name|
            next if managed.include?(name.to_s)

            patch[name] = nil if ResourceManager.extended_resource?(name) && !@capacity.key?(name.to_s) && !capacity.key?(name)
          end
          @api.patch_node_status(@node_name, {"allocatable" => patch}) unless patch.empty?
          @admission.resource_manager.replace_extended(extended.merge(device_capacity.last))
        rescue StandardError => error
          @error_handler&.call(error)
        end

        # A plugin registered, its devices changed or it went away: the Node
        # status and the admission view follow at once (kubelet updates the
        # node status on the device manager's callback).
        def device_plugins_changed
          return unless registered?

          manager = @admission.resource_manager
          current = manager.allocatable_values.select { |name, _| ResourceManager.extended_resource?(name) }
          managed = @device_plugins.resource_names
          current = current.reject { |name, _| managed.include?(name.to_s) }.transform_values(&:to_s)
          manager.replace_extended(current.merge(device_capacity.last))
          publish_device_resources
        rescue StandardError => error
          @error_handler&.call(error)
        end

        # Status is a subresource: an apply of the Node object does not carry
        # it, so the device counts go out as a merge patch of /status, and a
        # resource whose plugin is gone is removed from both maps.
        def publish_device_resources
          capacity, allocatable = device_capacity
          gone = (@published_device_resources || []) - capacity.keys
          patch = {"capacity" => capacity.merge(gone.to_h { |name| [name, nil] }),
                   "allocatable" => allocatable.merge(gone.to_h { |name| [name, nil] })}
          if node_adapter?
            @api.patch_node_status(@node_name, patch)
          else
            persist_node(build_node(ready: ready?))
          end
          @published_device_resources = capacity.keys
        end
      end
    end
  end
end
