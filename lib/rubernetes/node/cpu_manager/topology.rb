# frozen_string_literal: true

require_relative "cpu_set"

module Rubernetes
  module Node
    module CPUManager
      # pkg/kubelet/cm/cpumanager/topology: the node's CPUs by NUMA node,
      # socket, core and uncore (L3) cache, built from cadvisor's machine
      # info exactly as Discover does -- a core's id is its lowest thread id,
      # and a core without an uncore cache takes its socket's id instead.
      module Topology
        class Error < StandardError; end

        CPUInfo = Struct.new(:numa_node_id, :socket_id, :core_id, :uncore_cache_id, keyword_init: true)

        # topology.CPUDetails: cpu id => CPUInfo.
        class CPUDetails
          attr_reader :map

          def initialize(map = {})
            @map = map.freeze
            freeze
          end

          def [](cpu) = @map[cpu]
          def key?(cpu) = @map.key?(cpu)
          def each(&) = @map.each(&)

          def keep_only(cpus)
            cpus = CPUSet.new(cpus.to_a) unless cpus.is_a?(CPUSet)
            CPUDetails.new(@map.select { |cpu, _| cpus.include?(cpu) })
          end

          def cpus = CPUSet.new(@map.keys)
          def numa_nodes = CPUSet.new(@map.values.map(&:numa_node_id))
          def sockets = CPUSet.new(@map.values.map(&:socket_id))
          def cores = CPUSet.new(@map.values.map(&:core_id))
          def uncore_caches = CPUSet.new(@map.values.map(&:uncore_cache_id))

          def numa_nodes_in_sockets(*ids) = collect(:socket_id, ids, :numa_node_id)
          def sockets_in_numa_nodes(*ids) = collect(:numa_node_id, ids, :socket_id)
          def cores_in_numa_nodes(*ids) = collect(:numa_node_id, ids, :core_id)
          def cores_in_sockets(*ids) = collect(:socket_id, ids, :core_id)
          def uncore_in_numa_nodes(*ids) = collect(:numa_node_id, ids, :uncore_cache_id)
          def cpus_in_numa_nodes(*ids) = cpus_where(:numa_node_id, ids)
          def cpus_in_sockets(*ids) = cpus_where(:socket_id, ids)
          def cpus_in_cores(*ids) = cpus_where(:core_id, ids)
          def cpus_in_uncore_caches(*ids) = cpus_where(:uncore_cache_id, ids)

          # CoresNeededInUncoreCache: the lowest +count+ core ids in the
          # caches, or all of them when there are no more.
          def cores_needed_in_uncore_cache(count, *ids)
            cores = collect(:uncore_cache_id, ids, :core_id)
            cores.size <= count ? cores : CPUSet.new(cores.list.first(count))
          end

          private

          def collect(field, ids, output)
            wanted = ids.flatten
            CPUSet.new(@map.values.select { |info| wanted.include?(info[field]) }.map { |info| info[output] })
          end

          def cpus_where(field, ids)
            wanted = ids.flatten
            CPUSet.new(@map.select { |_, info| wanted.include?(info[field]) }.keys)
          end
        end

        # topology.CPUTopology.
        class CPUTopology
          attr_reader :num_cpus, :num_cores, :num_uncore_cache, :num_sockets, :num_numa_nodes, :cpu_details

          def initialize(num_cpus:, num_cores:, num_sockets:, cpu_details:, num_numa_nodes: nil, num_uncore_cache: nil)
            @num_cpus = num_cpus
            @num_cores = num_cores
            @num_sockets = num_sockets
            @cpu_details = cpu_details
            @num_numa_nodes = num_numa_nodes || cpu_details.numa_nodes.size
            @num_uncore_cache = num_uncore_cache || cpu_details.uncore_caches.size
            freeze
          end

          def cpus_per_core = @num_cores.zero? ? 0 : @num_cpus / @num_cores
          def cpus_per_socket = @num_sockets.zero? ? 0 : @num_cpus / @num_sockets
          def cpus_per_uncore = @num_uncore_cache.zero? ? 0 : @num_cpus / @num_uncore_cache

          def cpu_core_id(cpu) = info!(cpu).core_id
          def cpu_socket_id(cpu) = info!(cpu).socket_id
          def cpu_numa_node_id(cpu) = info!(cpu).numa_node_id

          # CheckAlignment: every CPU shares one uncore cache.
          def aligned_at_uncore_cache?(cpus)
            list = cpus.to_a
            return true if list.length <= 1

            reference = @cpu_details[list.first]
            return false unless reference

            list.drop(1).all? { |cpu| @cpu_details[cpu] && @cpu_details[cpu].uncore_cache_id == reference.uncore_cache_id }
          end

          private

          def info!(cpu)
            @cpu_details[cpu] or raise Error, "unknown CPU ID: #{cpu}"
          end
        end

        module_function

        # topology.Discover over cadvisor's MachineInfo:
        # {num_cores:, num_sockets:, topology: [{id:, cores: [{id:, socket_id:, threads:, uncore_caches: [{id:}]}]}]}.
        def discover(machine_info)
          raise Error, "could not detect number of cpus" if machine_info[:num_cores].to_i.zero?

          details = {}
          physical_cores = 0
          Array(machine_info[:topology]).each do |node|
            cores = Array(node[:cores])
            physical_cores += cores.length
            cores.each do |core|
              threads = Array(core[:threads])
              raise Error, "no cpus provided" if threads.empty?
              raise Error, "cpus provided are not unique" if threads.uniq.length != threads.length

              uncore = Array(core[:uncore_caches]).first
              threads.each do |cpu|
                details[cpu] = CPUInfo.new(core_id: threads.min, socket_id: core[:socket_id], numa_node_id: node[:id],
                                           uncore_cache_id: uncore ? uncore[:id] : core[:socket_id])
              end
            end
          end
          cpu_details = CPUDetails.new(details)
          CPUTopology.new(num_cpus: machine_info[:num_cores], num_sockets: machine_info[:num_sockets],
                          num_cores: physical_cores, cpu_details: cpu_details)
        end

        # cadvisor's machine info from sysfs under +root+ (utils/sysinfo
        # GetNodesInfo; NumSockets from the distinct physical package ids).
        def machine_info(root: "/")
          SysfsReader.new(root).machine_info
        end

        def discover_host(root: "/") = discover(machine_info(root: root))

        # The cadvisor sysfs walk (utils/sysfs + utils/sysinfo).
        class SysfsReader
          CACHE_LEVEL2 = 2

          def initialize(root)
            @root = root
            @cpu_root = File.join(root, "sys/devices/system/cpu")
            @node_root = File.join(root, "sys/devices/system/node")
          end

          def machine_info
            nodes, count = nodes_info
            sockets = Dir.glob(File.join(@cpu_root, "cpu*[0-9]")).filter_map do |dir|
              read_int(File.join(dir, "topology/physical_package_id"))
            end.uniq.length
            {num_cores: count, num_sockets: sockets, topology: nodes}
          end

          # GetNodesInfo; without NUMA directories, one node per package.
          def nodes_info
            node_dirs = Dir.glob(File.join(@node_root, "node*[0-9]"))
            return cpu_topology if node_dirs.empty?

            total = 0
            nodes = node_dirs.map do |dir|
              id = Integer(File.basename(dir)[/\d+\z/])
              cpu_dirs = Dir.glob(File.join(dir, "cpu*[0-9]"))
              node = {id: id, cores: cpu_dirs.empty? ? [] : cores_info(cpu_dirs)}
              node[:cores].each { |core| total += core[:threads].length }
              add_cache_info(node)
              node[:memory] = node_memory(dir)
              node[:hugepages] = hugepages(File.join(dir, "hugepages"))
              node[:distances] = distances(dir)
              node
            end
            [nodes, total]
          end

          def cpu_topology
            cpu_dirs = Dir.glob(File.join(@cpu_root, "cpu*[0-9]"))
            raise Error, "no CPU is available, cpusPath: #{@cpu_root}" if cpu_dirs.empty?

            by_package = cpu_dirs.group_by { |dir| read_int(File.join(dir, "topology/physical_package_id")) }
            by_package.delete(nil)
            nodes = by_package.map do |package, dirs|
              node = {id: package, cores: cores_info(dirs)}
              add_cache_info(node)
              node
            end
            [nodes, cpu_dirs.length]
          end

          def cores_info(cpu_dirs)
            cores = []
            cpu_dirs.each do |dir|
              cpu = Integer(File.basename(dir)[/\d+\z/])
              next unless online?(cpu)

              core_id = read_int(File.join(dir, "topology/core_id"))
              package = read_int(File.join(dir, "topology/physical_package_id"))
              next if core_id.nil? || package.nil?

              core = cores.find { |entry| entry[:id] == core_id && entry[:socket_id] == package }
              unless core
                core = {id: core_id, socket_id: package, threads: [], uncore_caches: []}
                cores << core
              end
              core[:threads] << cpu
            end
            cores
          end

          # addCacheInfo: a level-3+ cache shared by every thread of the node
          # is a node cache; one shared by fewer is the core's uncore cache.
          def add_cache_info(node)
            node[:caches] = []
            node[:cores].each do |core|
              caches = cache_info(core[:threads].first)
              return if caches.nil?

              per_core = core[:threads].length
              per_node = node[:cores].length * per_core
              caches.each do |cache|
                entry = cache.except(:cpus)
                if cache[:level] > CACHE_LEVEL2
                  if cache[:cpus] == per_node
                    node[:caches] << entry unless node[:caches].include?(entry)
                  else
                    core[:uncore_caches] << entry unless core[:uncore_caches].include?(entry)
                  end
                elsif cache[:cpus] == per_core
                  (core[:caches] ||= []) << entry
                end
              end
            end
          end

          def cache_info(cpu)
            directory = File.join(@cpu_root, "cpu#{cpu}", "cache")
            return [] unless File.directory?(directory)

            Dir.children(directory).sort.select { |name| name.start_with?("index") }.map do |name|
              path = File.join(directory, name)
              id = read_int(File.join(path, "id"))
              size = File.read(File.join(path, "size"))[/\A(\d+)K/, 1]
              level = read_int(File.join(path, "level"))
              return nil if id.nil? || size.nil? || level.nil?

              {id: id, size: Integer(size) * 1024, level: level, type: File.read(File.join(path, "type")).strip,
               cpus: cpu_count(File.join(path, "shared_cpu_map"))}
            end
          rescue SystemCallError
            nil
          end

          def cpu_count(path)
            File.read(path).strip.delete(",").to_i(16).to_s(2).count("1")
          rescue SystemCallError
            0
          end

          def online?(cpu)
            path = File.join(@cpu_root, "online")
            return true unless File.exist?(path)

            CPUSet.parse(File.read(path)).include?(cpu)
          rescue CPUSet::ParseError, SystemCallError
            false
          end

          def node_memory(dir)
            text = File.read(File.join(dir, "meminfo"))
            kib = text[/MemTotal:\s*(\d+) kB/, 1]
            kib ? Integer(kib) * 1024 : 0
          rescue SystemCallError
            0
          end

          # GetHugePagesInfo: hugepages-<size>kB/nr_hugepages, in directory order.
          def hugepages(directory)
            return [] unless File.directory?(directory)

            Dir.children(directory).sort.filter_map do |name|
              size = name[/\Ahugepages-(\d+)kB\z/, 1]
              next unless size

              {page_size: Integer(size), num_pages: read_int(File.join(directory, name, "nr_hugepages")) || 0}
            end
          end

          def distances(dir)
            File.read(File.join(dir, "distance")).split.map { |value| Integer(value) }
          rescue SystemCallError
            nil
          end

          def read_int(path)
            Integer(File.read(path).strip, 10)
          rescue SystemCallError, ArgumentError
            nil
          end
        end
      end
    end
  end
end
