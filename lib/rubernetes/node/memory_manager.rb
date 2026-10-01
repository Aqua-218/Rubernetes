# frozen_string_literal: true

require "fileutils"
require "json"
require_relative "topology_manager"
require_relative "cpu_manager/state"
require_relative "cpu_manager/policy"
require_relative "../resource_helpers"

module Rubernetes
  module Node
    # pkg/kubelet/cm/memorymanager (v1.36.2): with the Static policy,
    # Guaranteed Pods get their memory and hugepages reserved on specific
    # NUMA nodes (a group of nodes when one is not enough -- a group is then
    # used only by containers of the same group), the reservation is a
    # topology hint provider, and the container's cpuset.mems is pinned to
    # the nodes.  The machine state and assignments persist in
    # memory_manager_state.
    module MemoryManager
      class Error < StandardError; end

      POLICY_NONE = "None"
      POLICY_STATIC = "Static"
      STATE_FILE = "memory_manager_state"
      MEMORY = "memory"
      HUGEPAGES_PREFIX = "hugepages-"

      # state.MemoryTable.
      MemoryTable = Struct.new(:total, :system_reserved, :allocatable, :reserved, :free, keyword_init: true) do
        def to_h
          {"total" => total, "systemReserved" => system_reserved, "allocatable" => allocatable, "reserved" => reserved, "free" => free}
        end

        def self.from_h(value)
          new(total: value["total"].to_i, system_reserved: value["systemReserved"].to_i, allocatable: value["allocatable"].to_i,
              reserved: value["reserved"].to_i, free: value["free"].to_i)
        end
      end

      # state.NUMANodeState.
      NodeState = Struct.new(:assignments, :memory, :cells, keyword_init: true) do
        def deep_dup = NodeState.new(assignments: assignments, memory: memory.transform_values(&:dup), cells: cells.dup)

        def to_h
          {"numberOfAssignments" => assignments, "memoryMap" => memory.sort.to_h { |name, table| [name, table.to_h] }, "cells" => cells}
        end

        def self.from_h(value)
          new(assignments: value["numberOfAssignments"].to_i, cells: Array(value["cells"]).map(&:to_i),
              memory: (value["memoryMap"] || {}).to_h { |name, table| [name, MemoryTable.from_h(table)] })
        end
      end

      # state.Block.
      Block = Struct.new(:numa_affinity, :type, :size, keyword_init: true) do
        def to_h = {"numaAffinity" => numa_affinity, "type" => type, "size" => size}

        def self.from_h(value)
          new(numa_affinity: Array(value["numaAffinity"]).map(&:to_i), type: value["type"].to_s, size: value["size"].to_i)
        end
      end

      module_function

      def hugepage_resource?(name) = name.to_s.start_with?(HUGEPAGES_PREFIX)

      # corehelper.HugePageResourceName for a page size in KiB.
      def hugepage_resource_name(page_size_kib)
        bytes = page_size_kib * 1024
        suffixes = %w[Ki Mi Gi Ti Pi Ei]
        exponent = 0
        exponent += 1 while exponent < suffixes.length && (bytes % (1024**(exponent + 1))).zero?
        exponent.zero? ? "#{HUGEPAGES_PREFIX}#{bytes}" : "#{HUGEPAGES_PREFIX}#{bytes / (1024**exponent)}#{suffixes[exponent - 1]}"
      end

      def clone_machine(machine) = machine.transform_values(&:deep_dup)

      # The in-memory state (state_mem.go).
      class MemoryState
        def initialize
          @mutex = Mutex.new
          @machine = {}
          @assignments = {}
          @pod_blocks = {}
        end

        # PodLevelResourceManagers: the memory a pod-level Pod holds as a whole.
        def pod_memory_blocks(pod_uid) = @mutex.synchronize { @pod_blocks[pod_uid.to_s]&.map(&:dup) }
        def pod_memory_assignments = @mutex.synchronize { @pod_blocks.transform_values { |blocks| blocks.map(&:dup) } }

        def set_pod_memory_blocks(pod_uid, blocks)
          @mutex.synchronize { @pod_blocks[pod_uid.to_s] = blocks.map(&:dup) }
          changed
        end

        def delete_pod(pod_uid)
          @mutex.synchronize do
            @pod_blocks.delete(pod_uid.to_s)
            @assignments.delete(pod_uid.to_s)
          end
          changed
        end

        def machine_state = @mutex.synchronize { MemoryManager.clone_machine(@machine) }

        def machine_state=(value)
          @mutex.synchronize { @machine = MemoryManager.clone_machine(value) }
          changed
        end

        # GetMemoryBlocks: nil when the container has none recorded.
        def memory_blocks(pod_uid, container)
          @mutex.synchronize do
            blocks = @assignments.dig(pod_uid.to_s, container.to_s)
            blocks&.map(&:dup)
          end
        end

        def set_memory_blocks(pod_uid, container, blocks)
          @mutex.synchronize { (@assignments[pod_uid.to_s] ||= {})[container.to_s] = blocks.map(&:dup) }
          changed
        end

        def assignments
          @mutex.synchronize { @assignments.transform_values { |containers| containers.transform_values { |blocks| blocks.map(&:dup) } } }
        end

        def assignments=(value)
          @mutex.synchronize do
            @assignments = value.transform_values do |containers|
              containers.transform_values do |blocks|
                blocks.map(&:dup)
              end
            end
          end
          changed
        end

        def delete(pod_uid, container)
          @mutex.synchronize do
            containers = @assignments[pod_uid.to_s]
            return unless containers

            containers.delete(container.to_s)
            @assignments.delete(pod_uid.to_s) if containers.empty?
          end
          changed
        end

        def clear_state
          @mutex.synchronize do
            @machine = {}
            @assignments = {}
            @pod_blocks = {}
          end
          changed
        end

        private

        def changed = nil
      end

      # state_checkpoint.go with the V1 checkpoint the kubelet writes while
      # PodLevelResourceManagers is off (hashed under the V2 type name).
      class CheckpointState < MemoryState
        attr_reader :path

        # +pod_level+: PodLevelResourceManagers, which stores the V2
        # checkpoint (podEntries).
        def initialize(directory:, policy_name:, file: STATE_FILE, pod_level: false)
          super()
          @path = File.join(directory, file)
          @policy_name = policy_name.to_s
          @pod_level = pod_level
          restore
        end

        def self.encode(policy_name, machine, assignments, pod_blocks: nil)
          body = {"policyName" => policy_name,
                  # encoding/json sorts int map keys by their decimal text.
                  "machineState" => machine.sort_by { |id, _| id.to_s }.to_h { |id, node| [id.to_s, node.to_h] }}
          entries = assignments.sort.to_h do |pod, containers|
            [pod, containers.sort.to_h { |name, blocks| [name, blocks.map(&:to_h)] }]
          end
          body["entries"] = entries unless entries.empty?
          body["podEntries"] = pod_blocks.sort.to_h { |pod, blocks| [pod, {"memoryBlocks" => blocks.map(&:to_h)}] } unless pod_blocks.nil? || pod_blocks.empty?
          body["checksum"] = Checksum.fnv32a(Checksum.for_hash(policy_name, machine, assignments,
                                                               pod_entries: pod_blocks.nil? ? :absent : pod_blocks))
          JSON.generate(body)
        end

        private

        def changed
          FileUtils.mkdir_p(File.dirname(@path))
          temporary = "#{@path}.tmp.#{Process.pid}"
          File.write(temporary, self.class.encode(@policy_name, @machine, @assignments, pod_blocks: @pod_level ? @pod_blocks : nil))
          File.rename(temporary, @path)
        end

        def restore
          unless File.exist?(@path)
            changed
            return
          end

          body = JSON.parse(File.read(@path))
          machine = (body["machineState"] || {}).to_h { |id, node| [Integer(id), NodeState.from_h(node)] }
          assignments = (body["entries"] || {}).to_h do |pod, containers|
            [pod, containers.to_h { |name, blocks| [name, Array(blocks).map { |block| Block.from_h(block) }] }]
          end
          pod_blocks = (body["podEntries"] || {}).to_h do |pod, entry|
            [pod, Array(entry["memoryBlocks"]).map { |block| Block.from_h(block) }]
          end
          accepted = Checksum.accepted(body["policyName"].to_s, machine, assignments, pod_blocks)
          if body["checksum"].to_i.nonzero? && !accepted.include?(body["checksum"].to_i)
            raise Error, "checkpoint is corrupted: checksum #{body["checksum"]} does not match #{accepted.first}"
          end
          if body["policyName"].to_s != @policy_name
            raise Error,
                  "[memorymanager] configured policy \"#{@policy_name}\" differs from state checkpoint policy \"#{body["policyName"]}\""
          end

          @machine = machine
          @assignments = assignments
          @pod_blocks = pod_blocks
        rescue JSON::ParserError, ArgumentError, TypeError => error
          raise Error, "could not restore state from checkpoint: #{error.message}"
        end
      end

      # dump.ForHash of *MemoryManagerCheckpointV1 (renamed to the V2 type
      # name before hashing): pointers inside maps print as their pointee.
      module Checksum
        module_function

        # Fields always carry their type; a map value does not, and a
        # pointer stored in a map prints as <*> before its pointee.
        def for_hash(policy_name, machine, assignments, type_name: "MemoryManagerCheckpoint", pod_entries: :absent)
          nodes = machine.sort.map do |id, node|
            tables = node.memory.sort.map do |name, table|
              "#{name}:<*>{TotalMemSize:(uint64)#{table.total} SystemReserved:(uint64)#{table.system_reserved} " \
                "Allocatable:(uint64)#{table.allocatable} Reserved:(uint64)#{table.reserved} Free:(uint64)#{table.free}}"
            end
            "#{id}:<*>{NumberOfAssignments:(int)#{node.assignments} " \
              "MemoryMap:(map[v1.ResourceName]*state.MemoryTable)map[#{tables.join(" ")}] Cells:([]int)[#{node.cells.join(" ")}]}"
          end
          entries = assignments.sort.map do |pod, containers|
            rendered = containers.sort.map do |name, blocks|
              "#{name}:[#{blocks.map { |block| block_for_hash(block) }.join(" ")}]"
            end
            "#{pod}:map[#{rendered.join(" ")}]"
          end
          pods = ""
          unless pod_entries == :absent
            rendered = (pod_entries || {}).sort.map do |pod, blocks|
              "#{pod}:{MemoryBlocks:([]state.Block)[#{blocks.map { |block| block_for_hash(block) }.join(" ")}]}"
            end
            pods = " PodEntries:(state.PodMemoryAssignments)map[#{rendered.join(" ")}]"
          end
          "(*state.#{type_name}){PolicyName:(string)#{policy_name} MachineState:(state.NUMANodeMap)map[#{nodes.join(" ")}] " \
            "Entries:(state.ContainerMemoryAssignments)map[#{entries.join(" ")}]#{pods} Checksum:(checksum.Checksum)0}"
        end

        def block_for_hash(block)
          "{NUMAAffinity:([]int)[#{block.numa_affinity.join(" ")}] Type:(v1.ResourceName)#{block.type} Size:(uint64)#{block.size}}"
        end

        def accepted(policy_name, machine, assignments, pod_entries = {})
          [for_hash(policy_name, machine, assignments),
           for_hash(policy_name, machine, assignments, type_name: "MemoryManagerCheckpointV1"),
           for_hash(policy_name, machine, assignments, pod_entries: pod_entries || {})].map { |text| fnv32a(text) }
        end

        def fnv32a(text) = CPUManager::Checksum.fnv32a(text)
      end

      # Pod helpers.
      module PodResources
        module_function

        def uid(pod) = pod.dig("metadata", "uid").to_s
        def containers(pod) = Array(pod.dig("spec", "initContainers")) + Array(pod.dig("spec", "containers"))
        def restartable_init?(container) = container["restartPolicy"].to_s == "Always"
        def guaranteed?(pod) = ResourceHelpers.pod_qos(pod) == "Guaranteed"
        def pod_level_resources?(pod) = ResourceHelpers.pod_level_resources_set?(pod)

        def regular_init_container?(pod, container)
          init = Array(pod.dig("spec", "initContainers")).find { |entry| entry["name"] == container["name"] }
          init ? !restartable_init?(init) : false
        end

        # getContainerRequestedResources: memory and hugepages, in bytes.
        def container_requests(container)
          (container.dig("resources", "requests") || {}).each_with_object({}) do |(name, value), result|
            next unless name.to_s == MEMORY || MemoryManager.hugepage_resource?(name)

            amount = ResourceHelpers::Quantity.from_json(value).value
            raise Error, "[memorymanager] failed to represent quantity as int64" unless amount.denominator == 1

            result[name.to_s] = amount.to_i
          end.sort.to_h
        end

        # getPodRequestedResources.
        def pod_requests(pod)
          by_init = {}
          by_sidecars = Hash.new(0)
          Array(pod.dig("spec", "initContainers")).each do |container|
            container_requests(container).each do |name, size|
              by_init[name] ||= 0
              if restartable_init?(container)
                by_sidecars[name] += size
              elsif by_sidecars[name] + size > by_init[name]
                by_init[name] = by_sidecars[name] + size
              end
            end
          end
          by_apps = {}
          Array(pod.dig("spec", "containers")).each do |container|
            container_requests(container).each do |name, size|
              by_apps[name] = (by_apps[name] || 0) + size
            end
          end
          by_apps.keys.sort.to_h do |name|
            long_running = by_apps[name] + by_sidecars[name]
            [name, [long_running, by_init[name] || 0].max]
          end
        end
      end

      # The None policy.
      class NonePolicy
        def name = POLICY_NONE
        def start(_state) = nil
        def allocate(_state, _pod, _container) = nil
        def allocate_pod(_state, _pod) = nil
        def remove_container(_state, _pod_uid, _container) = nil
        def topology_hints(_state, _pod, _container) = nil
        def pod_topology_hints(_state, _pod) = nil
        def allocatable_memory(_state) = []
      end

      # policy_static.go.
      class StaticPolicy
        # +machine+: [{id:, memory: bytes, hugepages: [{page_size: KiB, num_pages:}]}];
        # +system_reserved+: {numa id => {resource => bytes}}.
        # +pod_level+: PodLevelResourceManagers (and PodLevelResources) on.
        def initialize(machine:, system_reserved:, affinity: nil, pod_level: false)
          @pod_level = pod_level
          total = system_reserved.values.sum { |resources| resources.fetch(MEMORY, 0) }
          raise Error, "[memorymanager] you should specify the system reserved memory" unless total.positive?

          @machine = machine
          @system_reserved = system_reserved
          @affinity = affinity
          @reusable = {}
        end

        def name = POLICY_STATIC

        # The kubelet registry for kubelet_memory_manager_pinning_*.
        attr_writer :metrics

        def start(state) = validate_state(state)

        # getDefaultMachineState.
        def default_machine_state
          @machine.to_h do |node|
            id = node[:id]
            memory = {}
            hugepages_total = 0
            Array(node[:hugepages]).each do |page|
              resource = MemoryManager.hugepage_resource_name(page[:page_size])
              reserved = system_reserved(id, resource)
              total = page[:num_pages] * page[:page_size] * 1024
              allocatable = total - reserved
              memory[resource] = MemoryTable.new(total: total, system_reserved: reserved, allocatable: allocatable, reserved: 0,
                                                 free: allocatable)
              hugepages_total += total
            end
            reserved = system_reserved(id, MEMORY)
            allocatable = node[:memory].to_i - reserved - hugepages_total
            memory[MEMORY] = MemoryTable.new(total: node[:memory].to_i, system_reserved: reserved, allocatable: allocatable,
                                             reserved: 0, free: allocatable)
            [id, NodeState.new(assignments: 0, memory: memory, cells: [id])]
          end
        end

        def validate_state(state)
          machine = state.machine_state
          assignments = state.assignments
          if machine.empty?
            raise Error, "[memorymanager] machine state can not be empty when it has memory assignments" unless assignments.empty?

            state.machine_state = default_machine_state
            return
          end

          expected = default_machine_state
          pod_blocks = @pod_level && state.respond_to?(:pod_memory_assignments) ? state.pod_memory_assignments : {}
          assignments.each do |pod, containers|
            # A pod-level Pod is accounted once, by its whole allocation.
            containers = {"" => pod_blocks[pod]} if pod_blocks[pod] && !pod_blocks[pod].empty?
            containers.each do |container, blocks|
              blocks.each do |block|
                remaining = block.size
                block.numa_affinity.each do |id|
                  node = expected[id]
                  unless node
                    raise Error,
                          "[memorymanager] (pod: #{pod}, container: #{container}) the memory assignment uses the NUMA that does not exist"
                  end

                  node.assignments += 1
                  node.cells = block.numa_affinity
                  table = node.memory[block.type]
                  unless table
                    raise Error,
                          "[memorymanager] (pod: #{pod}, container: #{container}) the memory assignment uses memory resource that does not exist"
                  end
                  next if remaining.zero? || table.free <= 0

                  taken = [table.free, remaining].min
                  table.reserved += taken
                  table.free -= taken
                  remaining -= taken
                end
              end
            end
          end
          return if machine_states_equal?(machine, expected)

          raise Error, "[memorymanager] the expected machine state is different from the real one"
        end

        # Allocate.
        def allocate(state, pod, container)
          return nil unless PodResources.guaranteed?(pod)
          return nil if PodResources.pod_level_resources?(pod) && !@pod_level

          pinning(:request)
          begin
            allocate_container(state, pod, container)
          rescue StandardError
            pinning(:error)
            raise
          end
        end

        def pinning(kind)
          name = kind == :request ? "kubelet_memory_manager_pinning_requests_total" : "kubelet_memory_manager_pinning_errors_total"
          @metrics&.increment(name)
        rescue StandardError
          nil
        end

        def allocate_container(state, pod, container)
          pod_uid = PodResources.uid(pod)
          if (blocks = state.memory_blocks(pod_uid, container["name"]))
            update_pod_reusable_memory(pod, container, blocks)
            return nil
          end

          hint = @affinity ? @affinity.affinity(pod_uid, container["name"]) : TopologyManager::Hint.new(nil, false)
          requests = container_requests(pod, container)
          machine = state.machine_state
          best = hint
          if hint.affinity.nil?
            default = default_hint(machine, pod, requests)
            raise Error, "[memorymanager] failed to find the default preferred hint" if !default.preferred && best.preferred

            best = default
          end
          unless affinity_satisfies_request?(machine, best.affinity, requests)
            extended = extend_hint(machine, pod, requests, best.affinity)
            raise Error, "[memorymanager] failed to find the extended preferred hint" if !extended.preferred && best.preferred

            best = extended
          end
          raise Error, "[memorymanager] preferred hint violates NUMA node allocation" if affinity_violates_allocations?(machine,
                                                                                                                        best.affinity)

          bits = best.affinity.bits
          blocks = requests.map do |resource, size|
            reusable = pod_reusable_memory(pod, best.affinity, resource)
            update_machine_state(machine, bits, resource, reusable >= size ? 0 : size - reusable)
            Block.new(numa_affinity: bits, type: resource, size: size)
          end
          update_pod_reusable_memory(pod, container, blocks)
          state.machine_state = machine
          state.set_memory_blocks(pod_uid, container["name"], blocks)
          update_init_containers_memory_blocks(state, pod, container, blocks)
          nil
        end

        def remove_container(state, pod_uid, container_name)
          # A pod-level Pod's memory goes back as a whole, with its last container.
          if @pod_level && state.respond_to?(:pod_memory_blocks) && (pod_blocks = state.pod_memory_blocks(pod_uid))
            state.delete(pod_uid, container_name)
            if (state.assignments[pod_uid.to_s] || {}).empty?
              release_memory(state, pod_blocks)
              state.delete_pod(pod_uid)
            end
            return nil
          end
          blocks = state.memory_blocks(pod_uid, container_name)
          return nil unless blocks

          state.delete(pod_uid, container_name)
          release_memory(state, blocks)
          nil
        end

        # GetTopologyHints.
        def topology_hints(state, pod, container)
          return nil unless PodResources.guaranteed?(pod)

          requests = begin
            container_requests(pod, container)
          rescue Error
            return nil
          end
          return nil if PodResources.pod_level_resources?(pod) && !@pod_level

          blocks = state.memory_blocks(PodResources.uid(pod), container["name"])
          return regenerate_hints(blocks, requests) if blocks

          calculate_hints(state.machine_state, pod, requests)
        end

        # GetPodTopologyHints.
        def pod_topology_hints(state, pod)
          return nil unless PodResources.guaranteed?(pod)

          requests = begin
            pod_requests(pod)
          rescue Error
            return nil
          end
          return nil if PodResources.pod_level_resources?(pod) && !@pod_level

          if @pod_level && PodResources.pod_level_resources?(pod)
            begin
              validate_pod_scope_resources(pod)
            rescue CPUManager::EmptyPodSharedPoolError, Error
              return requests.keys.to_h { |name| [name, []] }
            end
          end
          return nil if requests.empty?

          PodResources.containers(pod).each do |container|
            blocks = state.memory_blocks(PodResources.uid(pod), container["name"])
            return regenerate_hints(blocks, requests) if blocks
          end
          calculate_hints(state.machine_state, pod, requests)
        end

        # getContainerRequestedResources: a container of a pod-level Pod has
        # exclusive memory only when it is Guaranteed on its own terms.
        def container_requests(pod, container)
          return {} if @pod_level && PodResources.pod_level_resources?(pod) && !CPUManager::PodResources.container_equivalent_guaranteed?(container)

          PodResources.container_requests(container)
        end

        # getPodRequestedResources: a pod-level Pod's own memory/hugepages.
        def pod_requests(pod)
          return PodResources.pod_requests(pod) unless @pod_level && PodResources.pod_level_resources?(pod)

          (pod.dig("spec", "resources", "requests") || {}).each_with_object({}) do |(name, value), result|
            next unless name.to_s == MEMORY || MemoryManager.hugepage_resource?(name)

            amount = ResourceHelpers::Quantity.from_json(value).value
            raise Error, "[memorymanager] failed to represent quantity as int64" unless amount.denominator == 1

            result[name.to_s] = amount.to_i if amount.positive?
          end.sort.to_h
        end

        # validatePodScopeResources.
        def validate_pod_scope_resources(pod)
          total = pod_requests(pod)
          shared_long_running = false
          exclusive = Hash.new(0)
          Array(pod.dig("spec", "initContainers")).each do |container|
            requests = container_requests(pod, container)
            if !PodResources.restartable_init?(container)
              next unless requests.empty?

              total.each do |name, size|
                next unless exclusive[name] >= size

                raise CPUManager::EmptyPodSharedPoolError, "pod rejected, pod has shared init containers but no #{name} available for them"
              end
            elsif requests.empty?
              shared_long_running = true
            else
              requests.each { |name, size| exclusive[name] += size }
            end
          end
          Array(pod.dig("spec", "containers")).each do |container|
            requests = container_requests(pod, container)
            requests.empty? ? shared_long_running = true : requests.each { |name, size| exclusive[name] += size }
          end
          return unless shared_long_running

          total.each do |name, size|
            next unless exclusive[name] >= size

            raise CPUManager::EmptyPodSharedPoolError,
                  "pod rejected, sum of exclusive container #{name} requests equals pod budget, leaving no memory for shared containers"
          end
        end

        # AllocatePod: one NUMA-aligned memory "bubble" for the Pod; the
        # eligible containers get exclusive blocks of it, the others share
        # what is left.
        def allocate_pod(state, pod)
          return nil unless PodResources.guaranteed?(pod)

          total = begin
            pod_requests(pod)
          rescue Error
            return nil
          end
          pinning(:request)
          begin
            allocate_pod_bubble(state, pod, total)
          rescue StandardError
            pinning(:error)
            raise
          end
        end

        def allocate_pod_bubble(state, pod, total)
          validate_pod_scope_resources(pod)
          machine = state.machine_state
          pod_uid = PodResources.uid(pod)
          first = PodResources.containers(pod).first
          best = @affinity ? @affinity.affinity(pod_uid, first && first["name"]) : TopologyManager::Hint.new(nil, false)
          if best.affinity.nil?
            default = default_hint(machine, pod, total)
            raise Error, "[memorymanager] failed to find the default preferred hint" if !default.preferred && best.preferred

            best = default
          end
          unless affinity_satisfies_request?(machine, best.affinity, total)
            extended = extend_hint(machine, pod, total, best.affinity)
            raise Error, "[memorymanager] failed to find the extended preferred hint" if !extended.preferred && best.preferred

            best = extended
          end
          raise Error, "[memorymanager] preferred hint violates NUMA node allocation" if affinity_violates_allocations?(machine,
                                                                                                                        best.affinity)

          bits = best.affinity.bits
          blocks_of = lambda { |requests|
            requests.filter_map do |name, size|
              Block.new(numa_affinity: bits, type: name, size: size) if size.positive?
            end
          }
          exclusive = {}
          sidecars = Hash.new(0)
          Array(pod.dig("spec", "initContainers")).each do |container|
            requests = container_requests(pod, container)
            pinning(:request)
            if requests.empty?
              next if PodResources.restartable_init?(container)

              exclusive[container["name"]] = blocks_of.call(total.to_h { |name, size| [name, size - sidecars[name]] })
              next
            end
            exclusive[container["name"]] = blocks_of.call(requests)
            requests.each { |name, size| sidecars[name] += size } if PodResources.restartable_init?(container)
          end
          pool = total.to_h { |name, size| [name, size - sidecars[name]] }
          Array(pod.dig("spec", "containers")).each do |container|
            requests = container_requests(pod, container)
            next if requests.empty?

            pinning(:request)
            exclusive[container["name"]] = blocks_of.call(requests)
            requests.each { |name, size| pool[name] -= size if pool.key?(name) }
          end
          shared = blocks_of.call(pool)
          state.set_pod_memory_blocks(pod_uid, blocks_of.call(total))
          total.each { |name, size| update_machine_state(machine, bits, name, size) }
          PodResources.containers(pod).each do |container|
            state.set_memory_blocks(pod_uid, container["name"], exclusive.fetch(container["name"], shared))
          end
          state.machine_state = machine
          nil
        end

        # GetAllocatableMemory: one block per node and resource.
        def allocatable_memory(state)
          state.machine_state.sort.flat_map do |id, node|
            node.memory.sort.filter_map do |resource, table|
              Block.new(numa_affinity: [id], type: resource, size: table.allocatable) unless table.allocatable.zero?
            end
          end
        end

        # calculateHints.
        def calculate_hints(machine, pod, requests)
          nodes = machine.keys.sort
          min_affinity = nodes.length
          hints = {}
          TopologyManager::BitMask.iterate(nodes) do |mask|
            bits = mask.bits
            single = bits.length == 1
            free = Hash.new(0)
            allocatable = Hash.new(0)
            bits.each do |id|
              requests.each_key do |resource|
                table = machine[id].memory[resource]
                free[resource] += table ? table.free : 0
                allocatable[resource] += table ? table.allocatable : 0
              end
            end
            next if requests.any? { |resource, size| allocatable[resource] < size }

            min_affinity = mask.count if mask.count < min_affinity
            next if single && machine[bits.first].cells.length > 1
            next if bits.any? do |id|
              node = machine[id]
              !single && node.assignments.positive? && (node.cells.length == 1 || node.cells.sort != bits)
            end
            next if requests.any? { |resource, size| free[resource] + pod_reusable_memory(pod, mask, resource) < size }

            requests.each_key { |resource| (hints[resource] ||= []) << TopologyManager::Hint.new(mask, false) }
          end
          requests.each_key do |resource|
            Array(hints[resource]).each { |hint| hint.preferred = hint.affinity.count == min_affinity }
          end
          hints
        end

        private

        def system_reserved(id, resource) = (@system_reserved[id] || {}).fetch(resource, 0)

        def machine_states_equal?(first, second)
          return false unless first.length == second.length

          first.all? do |id, node|
            other = second[id]
            next false unless other
            next false unless node.assignments == other.assignments && node.cells.sort == other.cells.sort
            next false unless node.memory.length == other.memory.length

            node.memory.all? do |resource, table|
              other_table = other.memory[resource]
              next false unless other_table
              next false unless table.total == other_table.total && table.system_reserved == other_table.system_reserved &&
                                table.allocatable == other_table.allocatable

              group_free = node.cells.sum { |cell| first[cell].memory[resource].free }
              group_reserved = node.cells.sum { |cell| first[cell].memory[resource].reserved }
              other_free = node.cells.sum { |cell| second[cell].memory[resource].free }
              other_reserved = node.cells.sum { |cell| second[cell].memory[resource].reserved }
              group_free == other_free && group_reserved == other_reserved
            end
          end
        end

        def update_machine_state(machine, bits, resource, size)
          bits.each do |id|
            node = machine[id]
            node.assignments += 1
            node.cells = bits
            next if size.zero?

            table = node.memory[resource]
            next if table.free <= 0

            taken = [table.free, size].min
            table.reserved += taken
            table.free -= taken
            size -= taken
          end
        end

        def release_memory(state, blocks)
          machine = state.machine_state
          blocks.each do |block|
            released = block.size
            block.numa_affinity.each do |id|
              node = machine[id]
              node.assignments -= 1
              node.cells = [id] if node.assignments.zero?
              next if released.zero?

              table = node.memory[block.type]
              next if table.reserved.zero?

              if table.reserved < released
                released -= table.reserved
                table.free += table.reserved
                table.reserved = 0
                next
              end
              table.free += released
              table.reserved -= released
              released = 0
            end
          end
          state.machine_state = machine
        end

        def regenerate_hints(blocks, requests)
          return nil if blocks.length != requests.length

          hints = requests.keys.to_h { |resource| [resource, []] }
          blocks.each do |block|
            return nil unless requests.key?(block.type) && block.size == requests[block.type]

            hints[block.type] << TopologyManager::Hint.new(TopologyManager::BitMask.of(*block.numa_affinity), true)
          end
          hints
        end

        def default_hint(machine, pod, requests)
          hints = calculate_hints(machine, pod, requests)
          if hints.empty?
            raise Error,
                  "[memorymanager] failed to get the default NUMA affinity, no NUMA nodes with enough memory is available"
          end

          best_hint(Array(hints[MEMORY]))
        end

        def extend_hint(machine, pod, requests, mask)
          filtered = Array(calculate_hints(machine, pod, requests)[MEMORY]).select { |hint| hint_in_group?(mask.bits, hint.affinity.bits) }
          raise Error, "[memorymanager] failed to find NUMA nodes to extend the current topology hint" if filtered.empty?

          best_hint(filtered)
        end

        def hint_in_group?(hint, group)
          (hint - group).empty?
        end

        # findBestHint.
        def best_hint(hints)
          best = TopologyManager::Hint.new(nil, false)
          hints.each do |hint|
            if best.affinity.nil?
              best = hint
            elsif hint.preferred && !best.preferred
              best = hint
            elsif hint.preferred == best.preferred && hint.affinity.narrower_than?(best.affinity)
              best = hint
            end
          end
          best
        end

        def affinity_satisfies_request?(machine, mask, requests)
          requests.all? do |resource, size|
            mask.bits.sum { |id| machine[id].memory[resource]&.free.to_i } >= size
          end
        end

        def affinity_violates_allocations?(machine, mask)
          bits = mask.bits
          return false if bits.length == 1

          bits.any? do |id|
            node = machine[id]
            node.assignments.positive? && (node.cells.length == 1 || node.cells.sort != bits)
          end
        end

        def pod_reusable_memory(pod, mask, resource)
          @reusable.dig(PodResources.uid(pod), mask.to_s, resource) || 0
        end

        # updatePodReusableMemory: a regular init container's memory may be
        # reused by the containers after it.
        def update_pod_reusable_memory(pod, container, blocks)
          pod_uid = PodResources.uid(pod)
          @reusable.delete_if { |uid, _| uid != pod_uid }
          if PodResources.regular_init_container?(pod, container)
            pod_memory = (@reusable[pod_uid] ||= {})
            blocks.each do |block|
              key = TopologyManager::BitMask.of(*block.numa_affinity).to_s
              by_type = (pod_memory[key] ||= {})
              by_type[block.type] = block.size if block.size > (by_type[block.type] || 0)
            end
            return
          end

          blocks.each do |block|
            key = TopologyManager::BitMask.of(*block.numa_affinity).to_s
            reusable = @reusable.dig(pod_uid, key, block.type) || 0
            next if reusable.zero?

            @reusable[pod_uid][key][block.type] = block.size >= reusable ? 0 : reusable - block.size
          end
        end

        # updateInitContainersMemoryBlocks: memory an app container reuses is
        # taken off the init containers' blocks, so it is not released twice.
        def update_init_containers_memory_blocks(state, pod, container, blocks)
          pod_uid = PodResources.uid(pod)
          blocks.each do |block|
            size = block.size
            Array(pod.dig("spec", "initContainers")).each do |init|
              break if init["name"] == container["name"]
              break if size.zero?
              next if PodResources.restartable_init?(init)

              init_blocks = state.memory_blocks(pod_uid, init["name"])
              next if init_blocks.nil? || init_blocks.empty?

              init_blocks.each do |init_block|
                next if init_block.size.zero? || init_block.type != block.type
                next unless init_block.numa_affinity.sort == block.numa_affinity.sort

                if init_block.size > size
                  init_block.size -= size
                  size = 0
                else
                  size -= init_block.size
                  init_block.size = 0
                end
              end
              state.set_memory_blocks(pod_uid, init["name"], init_blocks)
            end
          end
        end
      end

      # memory_manager.go: the policy behind a lock, with stale-state removal
      # against the active Pods, as a topology hint provider.
      class Manager
        attr_reader :policy, :state

        # +reserved_memory+: [{numa_node:, limits: {resource => quantity}}];
        # +node_allocatable_reservation+: {resource => bytes} (system +
        # kube reserved + the hard eviction threshold).
        def initialize(policy: POLICY_NONE, machine: [], reserved_memory: [], node_allocatable_reservation: {}, state_directory: nil,
                       affinity: nil, pod_level: false)
          @mutex = Monitor.new
          @pod_level = pod_level
          @containers = {}
          @active_pods = -> { [] }
          @state_directory = state_directory
          @policy = case policy.to_s
                    when POLICY_NONE then NonePolicy.new
                    when POLICY_STATIC
                      StaticPolicy.new(machine: machine, affinity: affinity, pod_level: pod_level,
                                       system_reserved: system_reserved_memory(machine, node_allocatable_reservation, reserved_memory))
                    else raise Error, "unknown policy: #{policy.to_s.dump}"
                    end
        end

        def start(active_pods: nil, sources_ready: nil)
          @active_pods = active_pods if active_pods
          @sources_ready = sources_ready if sources_ready
          @state = if @state_directory
                     CheckpointState.new(directory: @state_directory, policy_name: @policy.name,
                                         pod_level: @pod_level)
                   else
                     MemoryState.new
                   end
          @policy.start(@state)
          @allocatable = @policy.allocatable_memory(@state)
          self
        end

        def allocatable_memory = @allocatable || []

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

        # AllocatePod: the pod-scope allocation of a pod-level Pod.
        def allocate_pod(pod)
          remove_stale_state
          @mutex.synchronize { @policy.allocate_pod(@state, pod) }
        end

        # AddContainer: a container started, so every regular init container
        # before it is done with its memory.
        def add_container(pod, container, container_id)
          @mutex.synchronize do
            @containers[container_id.to_s] = [PodResources.uid(pod), container["name"].to_s]
            Array(pod.dig("spec", "initContainers")).each do |init|
              break if init["name"] == container["name"]
              next if PodResources.restartable_init?(init)

              remove_by_ref(PodResources.uid(pod), init["name"])
            end
          end
        end

        def remove_container(container_id)
          @mutex.synchronize do
            reference = @containers[container_id.to_s]
            remove_by_ref(*reference) if reference
          end
          nil
        end

        # GetMemoryNUMANodes: the nodes for cpuset.mems, nil when unpinned.
        def memory_numa_nodes(pod, container)
          return nil unless @state

          nodes = Array(@state.memory_blocks(PodResources.uid(pod), container["name"])).flat_map(&:numa_affinity).uniq.sort
          nodes.empty? ? nil : nodes
        end

        def memory(pod_uid, container) = @state&.memory_blocks(pod_uid, container)

        def remove_stale_state
          return unless @state
          return if @sources_ready && !@sources_ready.call

          @mutex.synchronize do
            active = {}
            Array(@active_pods.call).each do |pod|
              active[PodResources.uid(pod)] = PodResources.containers(pod).map { |container| container["name"].to_s }
            end
            @state.assignments.each do |pod_uid, containers|
              containers.each_key { |name| remove_by_ref(pod_uid, name) unless Array(active[pod_uid]).include?(name) }
            end
            @containers.values.each do |pod_uid, name|
              remove_by_ref(pod_uid, name) unless Array(active[pod_uid]).include?(name)
            end
          end
        end

        private

        def remove_by_ref(pod_uid, name)
          @policy.remove_container(@state, pod_uid, name)
          @containers.delete_if { |_, reference| reference == [pod_uid.to_s, name.to_s] }
        end

        # getSystemReservedMemory: the per-NUMA reservations must add up to
        # the node allocatable reservation for every memory type.
        def system_reserved_memory(machine, node_allocatable_reservation, reserved_memory)
          ids = machine.map { |node| node[:id] }
          totals = {}
          reserved_memory.each do |reservation|
            node = Integer(reservation[:numa_node] || reservation["numaNode"])
            unless ids.include?(node)
              raise Error,
                    "the reserved memory configuration references a NUMA node #{node} that does not exist on this machine"
            end

            (reservation[:limits] || reservation["limits"] || {}).each do |resource, quantity|
              totals[resource.to_s] = add(totals[resource.to_s], quantity(quantity))
            end
          end
          reservation = node_allocatable_reservation.to_h { |name, value| [name.to_s, quantity(value)] }
          types = totals.keys | reservation.keys.select { |name| name == MEMORY || MemoryManager.hugepage_resource?(name) }
          types.each do |resource|
            allocatable = add(nil, reservation[resource])
            reserved = add(nil, totals[resource])
            next if allocatable.value == reserved.value

            raise Error, "the total amount #{reserved.to_s.dump} of type #{resource.dump} is not equal to the value " \
                         "#{allocatable.to_s.dump} determined by Node Allocatable feature"
          end
          converted = ids.to_h { |id| [id, {}] }
          reserved_memory.each do |entry|
            node = Integer(entry[:numa_node] || entry["numaNode"])
            (entry[:limits] || entry["limits"] || {}).each do |resource, value|
              amount = quantity(value).value
              raise Error, "could not covert a variable of type Quantity to int64" unless amount.denominator == 1

              converted[node][resource.to_s] = amount.to_i
            end
          end
          converted
        end

        def quantity(value)
          return ResourceHelpers::Quantity.new(Rational(value), :decimal_si) if value.is_a?(Integer)

          value.is_a?(ResourceHelpers::Quantity) ? value : ResourceHelpers::Quantity.from_json(value)
        end

        # Quantity.Add from a zero DecimalSI quantity: a zero sum takes the
        # addend's format.
        def add(sum, addend)
          sum ||= ResourceHelpers::Quantity.new(Rational(0), :decimal_si)
          return sum if addend.nil?

          format = sum.value.zero? ? addend.format : sum.format
          ResourceHelpers::Quantity.new(sum.value + addend.value, format)
        end
      end
    end
  end
end
