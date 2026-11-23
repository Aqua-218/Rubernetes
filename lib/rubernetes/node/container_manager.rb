# frozen_string_literal: true

require_relative "topology_manager"
require_relative "cpu_manager"
require_relative "memory_manager"
require_relative "node_allocatable"
require_relative "../runtime/cpu_quota"

module Rubernetes
  module Node
    # The resource side of pkg/kubelet/cm's containerManagerImpl: the
    # topology manager (the pod admit handler) with the CPU and memory
    # managers as its hint providers, and the internal container lifecycle
    # (internal_container_lifecycle_linux.go): PreCreateContainer pins
    # cpuset.cpus/cpuset.mems, PreStartContainer registers the container
    # with every manager, PostStopContainer tells the topology manager.
    class ContainerManager
      class Error < StandardError; end

      attr_reader :topology_manager, :cpu_manager, :memory_manager, :reservation

      # +cpu+, +memory+, +topology+: the cpuManager*/memoryManager*/
      # topologyManager* kubelet settings; +reservation+: the node
      # allocatable reservation ({resource => Quantity}).
      def initialize(state_directory:, reservation: {}, cpu: {}, memory: {}, topology: {}, machine: nil, cpu_topology: nil,
                     reserved_system_cpus: nil, sleeper: ->(seconds) { sleep(seconds) }, pod_level_resource_managers: false,
                     feature_gates: {})
        cpu = stringify(cpu)
        memory = stringify(memory)
        topology = stringify(topology)
        @reservation = reservation
        @pod_level_resource_managers = pod_level_resource_managers
        @exclusive_cpu_quota_exemption = feature_gates.fetch(Runtime::CPUQuota::EXCLUSIVE_CPU_GATE, true)
        machine ||= CPUManager::Topology.machine_info
        @topology_manager = TopologyManager::Manager.new(policy: topology.fetch("policy", TopologyManager::POLICY_NONE),
                                                         scope: topology.fetch("scope", TopologyManager::SCOPE_CONTAINER),
                                                         options: topology.fetch("options", {}), topology: machine[:topology],
                                                         pod_level: pod_level_resource_managers)
        cpu_topology ||= CPUManager::Topology.discover(machine)
        @cpu_manager = CPUManager::Manager.new(policy: cpu.fetch("policy", CPUManager::POLICY_NONE), options: cpu.fetch("options", {}),
                                               topology: cpu_topology, node_allocatable_reservation: reservation,
                                               reserved_cpus: reserved_system_cpus, state_directory: state_directory,
                                               affinity: @topology_manager,
                                               alpha_options: feature_gates["CPUManagerPolicyAlphaOptions"] == true,
                                               beta_options: feature_gates.fetch("CPUManagerPolicyBetaOptions", true) != false,
                                               reconcile_period: cpu.fetch("reconcile_period_seconds", CPUManager::Manager::DEFAULT_RECONCILE_PERIOD),
                                               sleeper: sleeper, pod_level: pod_level_resource_managers)
        @memory_manager = MemoryManager::Manager.new(policy: memory.fetch("policy", MemoryManager::POLICY_NONE),
                                                     machine: Array(machine[:topology]), reserved_memory: memory_reservations(memory),
                                                     node_allocatable_reservation: reservation.to_h do |name, quantity|
                                                       [name, quantity.to_s]
                                                     end,
                                                     state_directory: state_directory, affinity: @topology_manager,
                                                     pod_level: pod_level_resource_managers)
        @topology_manager.add_hint_provider(@cpu_manager)
        @topology_manager.add_hint_provider(@memory_manager)
      rescue CPUManager::Error, MemoryManager::Error, TopologyManager::Error => error
        raise Error, error.message
      end

      # Restore the checkpoints and start the policies: before any Pod is
      # admitted (kubelet initializeRuntimeDependentModules).
      def start(active_pods:, container_statuses: nil, update_cpuset: nil, sources_ready: nil)
        @cpu_manager.start(active_pods: active_pods, container_statuses: container_statuses, update_cpuset: update_cpuset,
                           reconcile: false, sources_ready: sources_ready)
        @memory_manager.start(active_pods: active_pods, sources_ready: sources_ready)
        self
      rescue CPUManager::Error, MemoryManager::Error => error
        raise Error, error.message
      end

      # The kubelet registry the resource managers' metrics go to; set before
      # #start (the policies initialise theirs there).
      def metrics=(registry)
        [@cpu_manager.policy, @memory_manager.policy, @topology_manager].each do |component|
          component.metrics = registry if component.respond_to?(:metrics=)
        end
      end

      # GetNodeConfig().CPUManagerPolicy / MemoryManagerPolicy.
      def cpu_manager_policy = @cpu_manager.policy.name
      def memory_manager_policy = @memory_manager.policy.name

      # The CPU manager's reconcile loop (static policy only).
      def start_reconcile = @cpu_manager.start_reconcile_loop

      def stop = @cpu_manager.stop

      # The allocate-resources pod admit handler.
      def admit(pod) = @topology_manager.admit(pod)

      def pod_cpu_quota_exempt?(pod)
        return false unless @exclusive_cpu_quota_exemption

        containers = CPUManager::PodResources.containers(pod)
        if pod_scope_cpu_isolation?(pod)
          containers.all? { |container| container_cpu_quota_exempt?(pod, container) }
        else
          containers.any? { |container| container_cpu_quota_exempt?(pod, container) }
        end
      end

      def container_cpu_quota_exempt?(pod, container)
        return false unless @exclusive_cpu_quota_exemption && pod

        resources = CPUManager::PodResources
        return false if @cpu_manager.exclusive_cpus(resources.uid(pod), container["name"]).empty?
        return true unless pod_scope_cpu_isolation?(pod)

        resources.container_equivalent_guaranteed?(container) && resources.integral_cpus(resources.cpu_request(container)).to_i.positive?
      end

      # PreCreateContainer: the cgroup files to pin, {} when nothing is.
      def container_limits(pod, container)
        limits = {}
        cpus = @cpu_manager.cpu_affinity(pod.dig("metadata", "uid").to_s, container["name"].to_s)
        limits["cpuset.cpus"] = cpus.to_s unless cpus.empty?
        nodes = @memory_manager.memory_numa_nodes(pod, container)
        limits["cpuset.mems"] = nodes.join(",") if nodes
        limits
      end

      # PreStartContainer.
      def pre_start(pod, container, container_id)
        @cpu_manager.add_container(pod, container, container_id)
        @memory_manager.add_container(pod, container, container_id)
        @topology_manager.add_container(pod, container, container_id)
      end

      # PostStopContainer.
      def post_stop(container_id) = @topology_manager.remove_container(container_id)

      private

      def pod_scope_cpu_isolation?(pod)
        @pod_level_resource_managers && CPUManager::PodResources.pod_level_resources?(pod)
      end

      def stringify(value) = (value || {}).to_h { |key, entry| [key.to_s, entry] }

      def memory_reservations(memory)
        Array(memory["reserved_memory"]).map do |entry|
          entry = stringify(entry)
          {numa_node: Integer(entry.fetch("numa_node")), limits: stringify(entry.fetch("limits", {}))}
        end
      end
    end
  end
end
