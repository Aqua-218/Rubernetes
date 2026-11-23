# frozen_string_literal: true

module Rubernetes
  module Node
    class StatsProvider
      # Kernel pressure and per-network-namespace interface counters used in
      # the Summary API. Absent kernel data is left out of the observation.
      module LinuxCounters
        private

        def add_pressure(stats, stamp, directory)
          %w[cpu memory io].each do |resource|
            filename = block_given? ? yield(resource) : resource
            pressure = pressure_sample(File.join(directory, filename))
            next unless pressure

            (stats[resource] ||= {"time" => stamp})["psi"] = pressure
          end
        end

        def pressure_sample(path)
          fields = File.foreach(path).each_with_object({}) do |line, result|
            scope, *tokens = line.split
            next unless %w[some full].include?(scope)

            values = tokens.to_h { |token| token.split("=", 2) }
            sample = %w[avg10 avg60 avg300].to_h { |key| [key, Float(values.fetch(key))] }
            # Linux publishes total in microseconds. Summary uses nanoseconds.
            sample["total"] = Integer(values.fetch("total")) * 1000
            result[scope] = sample
          end
          fields unless fields.empty?
        rescue SystemCallError, KeyError, ArgumentError
          nil
        end

        def add_cgroup_pressure(stats, usage, stamp)
          path = usage["path"]
          return if path.nil? || path.empty?

          directory = cgroup_directory(path, usage.fetch("cgroup_root") { runtime_cgroup_root })
          return unless directory

          add_pressure(stats, stamp, directory) { |resource| "#{resource}.pressure" }
        end

        def cgroup_directory(path, root)
          directory = File.expand_path(path.delete_prefix("/"), root)
          directory if directory.start_with?("#{File.expand_path(root)}/")
        end

        def runtime_cgroup_root
          runtime = native_stats_backend
          return runtime.config.cgroup_root if defined?(Runtime::Native) && runtime.is_a?(Runtime::Native)

          @cgroup_root
        end

        def native_stats_backend
          return @runtime unless defined?(Runtime::Multiplexer) && @runtime.is_a?(Runtime::Multiplexer)

          @runtime.backends[Runtime::Multiplexer::DEFAULT_HANDLER]
        end

        def kubelet_cgroup_stats(stamp)
          path = @system_cgroups.fetch("kubelet") do
            unified = File.foreach(File.join(@proc_root, "self", "cgroup")).find { |line| line.start_with?("0::") }
            unified&.delete_prefix("0::")&.strip
          end
          configured_cgroup_stats("kubelet", path, stamp)
        rescue SystemCallError
          nil
        end

        def runtime_service_cgroup_stats(stamp)
          return configured_cgroup_stats("runtime", @system_cgroups["runtime"], stamp) if @system_cgroups.key?("runtime")
          return if @cri_filesystem_stats

          runtime = native_stats_backend
          return unless defined?(Runtime::Native) && runtime.is_a?(Runtime::Native)

          directory = runtime.runtime_service_cgroup
          system_cgroup_stats("runtime", directory, stamp) if directory
        end

        def misc_cgroup_stats(stamp)
          configured_cgroup_stats("misc", @system_cgroups["misc"], stamp)
        end

        def configured_cgroup_stats(name, path, stamp)
          return if path.nil? || path.empty?

          directory = cgroup_directory(path, @cgroup_root)
          system_cgroup_stats(name, directory, stamp) if directory
        end

        def pods_cgroup_stats(stamp, limit)
          return unless defined?(Platform::Linux::CgroupV2)

          directory = File.join(runtime_cgroup_root, Platform::Linux::CgroupV2::HIERARCHY_PREFIX)
          system_cgroup_stats("pods", directory, stamp, limit: limit)
        end

        def system_cgroup_stats(name, directory, stamp, limit: nil)
          cpu = read_key_values(File.join(directory, "cpu.stat"))
          memory = read_key_values(File.join(directory, "memory.stat"))
          return unless cpu || memory

          stats = {"name" => name, "startTime" => File.stat(directory).ctime.utc.iso8601}
          stats["cpu"] = cpu_stats("node/system/#{name}", cpu, stamp) if cpu
          if memory
            usage = Integer(File.read(File.join(directory, "memory.current")), exception: false)
            stats["memory"] = memory_stats(usage, memory, stamp, limit: limit)
          end
          add_pressure(stats, stamp, directory) { |resource| "#{resource}.pressure" }
          stats.compact
        rescue SystemCallError
          nil
        end

        def network_stats(stamp, pid: nil)
          path = pid ? File.join(@proc_root, Integer(pid).to_s, "net/dev") : File.join(@proc_root, "net/dev")
          interfaces = File.foreach(path).filter_map do |line|
            name, values = line.split(":", 2)
            next unless values

            columns = values.split
            next if columns.length < 16

            {"name" => name.strip, "rxBytes" => Integer(columns[0]), "rxErrors" => Integer(columns[2]),
             "txBytes" => Integer(columns[8]), "txErrors" => Integer(columns[10])}
          end
          primary = interfaces.find { |interface| interface["name"] == "eth0" } ||
                    interfaces.find { |interface| interface["name"] != "lo" } || interfaces.first
          {"time" => stamp, "interfaces" => interfaces}.merge(primary) if primary
        rescue SystemCallError, ArgumentError
          nil
        end
      end
    end
  end
end
