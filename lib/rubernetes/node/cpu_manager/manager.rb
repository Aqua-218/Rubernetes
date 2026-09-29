# frozen_string_literal: true

require "monitor"
require_relative "policy"

module Rubernetes
  module Node
    module CPUManager
      # cpu_manager.go: the policy behind a lock, its checkpointed state, a
      # topology hint provider, and the reconcile loop that keeps each
      # running container's cpuset.cpus equal to its assignment (exclusive
      # CPUs, or the shared pool as it shrinks and grows).
      class Manager
        DEFAULT_RECONCILE_PERIOD = 10.0

        attr_reader :policy, :state, :topology

        # +node_allocatable_reservation+: {"cpu" => quantity} (system + kube
        # reserved); the static policy reserves ceil(cpu) CPUs, or exactly
        # +reserved_cpus+ when given.
        def initialize(policy: POLICY_NONE, options: {}, topology: nil, node_allocatable_reservation: {}, reserved_cpus: nil,
                       state_directory: nil, affinity: nil, reconcile_period: DEFAULT_RECONCILE_PERIOD, alpha_options: false,
                       beta_options: true, sleeper: ->(seconds) { sleep(seconds) }, pod_level: false)
          @pod_level = pod_level
          @mutex = Monitor.new
          @topology = topology || Topology.discover_host
          @state_directory = state_directory
          @reconcile_period = Float(reconcile_period)
          @sleeper = sleeper
          @containers = {}
          @last_update = {}
          @active_pods = -> { [] }
          @container_statuses = ->(_pod) { [] }
          @update_cpuset = nil
          @policy = case policy.to_s
                    when POLICY_NONE then NonePolicy.new(options)
                    when POLICY_STATIC
                      reservation = node_allocatable_reservation.to_h { |name, value| [name.to_s, value] }["cpu"]
                      raise Error, "[cpumanager] unable to determine reserved CPU resources for static policy" if reservation.nil?

                      milli = (ResourceHelpers::Quantity.from_json(reservation).value * 1000).ceil
                      raise Error, "[cpumanager] the static policy requires systemreserved.cpu + kubereserved.cpu to be greater than zero" if milli.zero?

                      specific = reserved_cpus.nil? || reserved_cpus.to_s.empty? ? CPUSet.empty : CPUSet.parse(reserved_cpus.to_s)
                      StaticPolicy.new(topology: @topology, num_reserved: (milli / 1000.0).ceil, reserved_cpus: specific,
                                       affinity: affinity, options: options, alpha_options: alpha_options, beta_options: beta_options,
                                       pod_level: pod_level)
                    else raise Error, "unknown policy: \"#{policy}\""
                    end
        end

        # Start: +active_pods+ lists the admitted, not yet terminated Pods;
        # +container_statuses+ gives a Pod's runtime containers
        # ([{name:, id:, state:}]); +update_cpuset+ applies a cpuset.cpus.
        def start(active_pods: nil, container_statuses: nil, update_cpuset: nil, reconcile: true, sources_ready: nil)
          @active_pods = active_pods if active_pods
          # sourcesReady: stale state is removed only once every Pod source
          # has been seen (after recovery), or a restart would drop the
          # restored assignments of Pods not yet listed again.
          @sources_ready = sources_ready if sources_ready
          @container_statuses = container_statuses if container_statuses
          @update_cpuset = update_cpuset
          @state = if @state_directory
                     CheckpointState.new(directory: @state_directory, policy_name: @policy.name, pod_level: @pod_level)
                   else
                     MemoryState.new
                   end
          @policy.start(@state)
          @allocatable = @policy.allocatable_cpus(@state)
          start_reconcile_loop if reconcile
          self
        rescue CheckpointState::Error => error
          raise Error, "could not initialize checkpoint manager, please drain node and remove policy state file: #{error.message}"
        end

        def stop
          thread = @mutex.synchronize do
            @stopped = true
            @thread
          end
          thread&.join(1)
        end

        def allocatable_cpus = @allocatable || CPUSet.empty
        def all_cpus = @topology.cpu_details.cpus

        # Hint provider.
        def topology_hints(pod, container)
          remove_stale_state
          @mutex.synchronize { @policy.topology_hints(@state, pod, container) }
        end

        def pod_topology_hints(pod)
          remove_stale_state
          @mutex.synchronize { @policy.pod_topology_hints(@state, pod) }
        end

        def allocate(pod, container)
          remove_stale_state
          @mutex.synchronize { @policy.allocate(@state, pod, container) }
        end

        # AllocatePod (PodLevelResourceManagers, pod scope).
        def allocate_pod(pod)
          return nil unless @policy.respond_to?(:allocate_pod)

          remove_stale_state
          @mutex.synchronize { @policy.allocate_pod(@state, pod) }
        end

        # AddContainer (PreStartContainer): the container now runs with the
        # cpuset it was created with.
        def add_container(pod, container, container_id)
          @mutex.synchronize do
            uid = PodResources.uid(pod)
            cpus = @state&.cpu_set(uid, container["name"])
            @last_update[[uid, container["name"].to_s]] = cpus if cpus
            @containers[container_id.to_s] = [uid, container["name"].to_s]
          end
        end

        def remove_container(container_id)
          @mutex.synchronize do
            reference = @containers[container_id.to_s]
            remove_by_ref(*reference) if reference
          end
          nil
        end

        # GetCPUAffinity: the container's exclusive CPUs, else the shared pool
        # (empty with the none policy: no cpuset is applied).
        def cpu_affinity(pod_uid, container)
          return CPUSet.empty unless @state

          @state.cpu_set_or_default(pod_uid, container)
        end

        def exclusive_cpus(pod_uid, container) = @state&.cpu_set(pod_uid, container) || CPUSet.empty

        def remove_stale_state
          return unless @state
          return if @sources_ready && !@sources_ready.call

          @mutex.synchronize do
            active = active_containers
            @state.assignments.each do |pod_uid, containers|
              containers.each_key { |name| remove_by_ref(pod_uid, name) unless active.dig(pod_uid, name) }
            end
            @containers.values.each { |pod_uid, name| remove_by_ref(pod_uid, name) unless active.dig(pod_uid, name) }
          end
        end

        # reconcileState: [succeeded, failed] container references.
        def reconcile_state
          remove_stale_state
          success = []
          failure = []
          Array(@active_pods.call).each do |pod|
            uid = PodResources.uid(pod)
            statuses = Array(@container_statuses.call(pod))
            PodResources.containers(pod).each do |container|
              name = container["name"].to_s
              status = statuses.find { |entry| entry[:name].to_s == name }
              if status.nil? || status[:id].to_s.empty? || !%w[running exited].include?(status[:state].to_s)
                failure << [pod.dig("metadata", "name"), name, nil]
                next
              end
              next if status[:state].to_s == "exited"

              @mutex.synchronize { @containers[status[:id].to_s] = [uid, name] }
              cpus = @state.cpu_set_or_default(uid, name)
              if cpus.empty?
                failure << [pod.dig("metadata", "name"), name, status[:id]]
                next
              end
              if @last_update[[uid, name]] != cpus
                begin
                  @update_cpuset&.call(status[:id], cpus)
                rescue StandardError
                  failure << [pod.dig("metadata", "name"), name, status[:id]]
                  next
                end
                @mutex.synchronize { @last_update[[uid, name]] = cpus }
              end
              success << [pod.dig("metadata", "name"), name, status[:id]]
            end
          end
          [success, failure]
        end

        def start_reconcile_loop
          return unless @state && @policy.name != POLICY_NONE && @update_cpuset

          @mutex.synchronize do
            return if @thread&.alive?

            @stopped = false
            @thread = Thread.new do
              until @mutex.synchronize { @stopped }
                begin
                  reconcile_state
                rescue StandardError
                  nil
                end
                @sleeper.call(@reconcile_period)
              end
            end
          end
        end

        private

        def active_containers
          Array(@active_pods.call).to_h do |pod|
            [PodResources.uid(pod), PodResources.containers(pod).to_h { |container| [container["name"].to_s, true] }]
          end
        end

        def remove_by_ref(pod_uid, name)
          @policy.remove_container(@state, pod_uid, name)
          @last_update.delete([pod_uid.to_s, name.to_s])
          @containers.delete_if { |_, reference| reference == [pod_uid.to_s, name.to_s] }
        end
      end
    end
  end
end
