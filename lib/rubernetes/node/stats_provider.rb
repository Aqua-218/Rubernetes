# frozen_string_literal: true

require_relative "stats_provider/linux_counters"
require_relative "stats_provider/filesystems"
require_relative "stats_provider/host_files"
require_relative "stats_provider/volume_stats"

require "time"
require_relative "cri_stats"
require_relative "directory_usage"
require_relative "kubelet_configz"
require_relative "../volume/types"

module Rubernetes
  module Node
    # The kubelet Summary API (stats/v1alpha1, /stats/summary) computed the way
    # the kubelet's cadvisor-backed stats provider computes it on cgroup v2:
    #
    #   memory: usage = memory.current (node: anon + file of the root
    #           memory.stat), workingSet = usage - inactive_file,
    #           available = capacity - workingSet (node only, or a set limit)
    #   cpu:    usageCoreNanoSeconds = cpu.stat usage_usec * 1000,
    #           usageNanoCores = its rate since the previous sample
    #   fs:     statfs of the kubelet root (nodefs) and the image store (imagefs)
    #   pods:   Pod and container cgroups, container rootfs (writable layer) and
    #           logs, and each volume, measured like `du` (blocks and inodes)
    #
    # This is what the eviction manager, the resource metrics endpoint and
    # metrics-server all read.  Directory usage is cached for +fs_ttl+ seconds:
    # walking every writable layer on every housekeeping pass is what cAdvisor
    # rate-limits too.
    class StatsProvider
      DEFAULT_FS_TTL = 30.0
      CPU_SAMPLE_INTERVAL = 10.0
      IDLE_CPU_SAMPLE_INTERVAL = 15.0
      include LinuxCounters
      include Filesystems
      include VolumeStats

      def initialize(node_name:, lifecycle:, runtime:, pod_root: nil, image_root: nil, container_root: nil, clock: -> { Time.now.utc },
                     monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     cgroup_root: "/sys/fs/cgroup", proc_root: "/proc", memory_capacity: nil, fs_ttl: DEFAULT_FS_TTL,
                     allocatable_memory: nil, volume_stats: nil, cri_clients: [], cri_log_roots: {}, system_cgroups: {},
                     volume_health: false, event_recorder: nil, project_quota_usage: nil, cri_image_client: nil,
                     volume_stats_agg_period: KubeletConfigz::DEFAULT_VOLUME_STATS_AGG_PERIOD_SECONDS)
        @node_name = node_name.to_s
        @lifecycle = lifecycle
        @has_stats_records = lifecycle.respond_to?(:stats_records)
        @cri_stats = CRIStats.new(cri_clients, log_roots: cri_log_roots) unless cri_clients.empty?
        @cri_filesystem_stats = Runtime::CRI::FilesystemStats.new(cri_image_client) if cri_image_client
        @runtime = runtime
        @pod_root = pod_root
        @image_root = image_root
        @container_root = container_root
        @clock = clock
        @monotonic = monotonic
        @cgroup_root = cgroup_root
        @proc_root = proc_root
        @system_cgroups = system_cgroups
        @memory_capacity = memory_capacity
        @fs_ttl = Float(fs_ttl)
        @allocatable_memory = allocatable_memory && Integer(allocatable_memory)
        @cpu_samples = {}
        @du_cache = {}
        # CSI volumes: the driver's NodeGetVolumeStats (csi metricsCsi) --
        # +volume_stats+.call(volume_id, path) returns the stats, :unsupported
        # (the volume is left out, as upstream without GET_VOLUME_STATS) or
        # nil for a volume measured like any directory.
        @volume_stats = volume_stats
        @project_quota_usage = project_quota_usage
        @volume_health = volume_health
        @event_recorder = event_recorder
        initialize_volume_stats(volume_stats_agg_period)
        @mutex = Mutex.new
      end

      # nil selects the cgroup-based collector. An empty string means the CRI
      # was selected but has no metrics to expose.
      def cri_metrics = @cri_stats&.metrics

      def summary = summary_with_filesystems.first

      def summary_with_filesystems
        now = @clock.call.utc
        stamp = now.iso8601
        pods = pod_stats(stamp)
        filesystems, layout = node_filesystem_stats(stamp)
        node = node_stats(stamp, filesystems: filesystems)
        system = [kubelet_cgroup_stats(stamp), runtime_service_cgroup_stats(stamp), misc_cgroup_stats(stamp),
                  pods_system_container(pods, stamp)].compact
        node["systemContainers"] = system unless system.empty?
        [{"node" => node, "pods" => pods}, layout]
      end

      # The "pods" system container (the kubepods cgroup upstream): every
      # Pod's memory, with the node's allocatable memory as its limit -- what
      # node allocatable enforcement sets kubepods' memory.max to -- so
      # availableBytes is what allocatableMemory.available is observed from.
      def pods_system_container(pods, stamp)
        limit = @allocatable_memory
        return nil unless limit

        actual = pods_cgroup_stats(stamp, limit)
        return actual if actual && actual["memory"]

        memories = pods.filter_map { |pod| pod["memory"] }
        working_set = memories.sum { |memory| memory["workingSetBytes"].to_i }
        usage = memories.sum { |memory| memory["usageBytes"].to_i }
        {"name" => "pods", "startTime" => boot_time,
         "memory" => {"time" => stamp, "availableBytes" => [limit - working_set, 0].max, "usageBytes" => usage,
                      "workingSetBytes" => working_set}}.compact
      end

      # --------------------------------------------------------------- node

      def node_stats(stamp, filesystems: node_filesystem_stats(stamp).first)
        memory_stat = read_key_values(File.join(@cgroup_root, "memory.stat"))
        cpu_stat = read_key_values(File.join(@cgroup_root, "cpu.stat"))
        capacity = memory_capacity
        usage = memory_stat && (memory_stat["anon"].to_i + memory_stat["file"].to_i)
        stats = {"nodeName" => @node_name, "startTime" => boot_time}
        stats["cpu"] = cpu_stats("node", cpu_stat, stamp) if cpu_stat
        stats["memory"] = memory_stats(usage, memory_stat, stamp, limit: capacity) if memory_stat
        stats["network"] = network_stats(stamp)
        add_pressure(stats, stamp, File.join(@proc_root, "pressure"))
        swap = node_swap_stats(stamp)
        stats["swap"] = swap if swap
        stats.merge!(filesystems)
        rlimit = rlimit_stats(stamp)
        stats["rlimit"] = rlimit if rlimit
        stats.compact
      end

      def memory_capacity
        return @memory_capacity if @memory_capacity

        File.foreach(File.join(@proc_root, "meminfo")) do |line|
          return @memory_capacity = Integer(line.split[1]) * 1024 if line.start_with?("MemTotal:")
        end
        nil
      rescue SystemCallError, ArgumentError
        nil
      end

      def boot_time
        File.foreach(File.join(@proc_root, "stat")) do |line|
          return Time.at(Integer(line.split[1])).utc.iso8601 if line.start_with?("btime ")
        end
        nil
      rescue SystemCallError, ArgumentError
        nil
      end

      def rlimit_stats(stamp)
        max_pid = Integer(File.read(File.join(@proc_root, "sys/kernel/pid_max")).strip)
        running = Dir.children(@proc_root).count { |entry| entry.match?(/\A\d+\z/) }
        {"time" => stamp, "maxpid" => max_pid, "curproc" => running}
      rescue SystemCallError, ArgumentError
        nil
      end

      # --------------------------------------------------------------- pods

      def pod_stats(stamp)
        volume_snapshot = @volume_mutex.synchronize { @volume_samples }
        records = running_stats_records
        live = []
        cri_samples = @cri_stats&.pod_samples(stamp) || {}
        stats = records.filter_map do |record|
          pod = record[:pod] || {}
          uid = record[:uid].to_s
          live << uid
          usage = pod_source_usage(record[:sandbox_id], cri_samples[record[:sandbox_id].to_s])
          containers = Array(usage && usage["containers"]).filter_map do |container|
            container_stats(uid, container, record, stamp, log_root: usage["logs_root"])
          end
          entry = {
            "podRef" => {"name" => pod.dig("metadata", "name").to_s, "namespace" => pod.dig("metadata", "namespace").to_s, "uid" => uid},
            "startTime" => record[:started_at],
            "containers" => containers
          }
          entry.merge!(usage["summary"]) if usage && usage["summary"]
          pod_usage = usage && usage["pod"]
          if pod_usage
            entry["cpu"] = cpu_stats("pod/#{uid}", pod_usage["cpu"], stamp) if pod_usage["cpu"]
            entry["memory"] = memory_stats(pod_usage["memory.current"], pod_usage["memory"], stamp, limit: pod_usage["memory.max"]) if pod_usage["memory"]
            entry["swap"] = swap_stats(pod_usage, stamp) if pod_usage.key?("memory.swap.current")
            entry["process_stats"] = {"process_count" => Integer(pod_usage["pids.current"])} if pod_usage["pids.current"]
            add_cgroup_pressure(entry, pod_usage, stamp)
          end
          entry["network"] ||= network_stats(stamp, pid: usage["netns_pid"]) if usage && usage["netns_pid"]
          specs = Array(record.dig(:pod, "spec", "volumes")).to_h { |volume| [volume["name"], volume] }
          volumes = pod_volume_stats(record, volume_snapshot)
          entry["volume"] = volumes unless volumes.empty?
          local = volumes.select { |volume| Volume::Types.local_ephemeral_volume?(specs[volume["name"]]) }
          entry["ephemeral-storage"] = ephemeral_storage(containers, local, stamp, record, usage && usage["logs_root"])
          entry.compact
        end
        forget_samples(live)
        stats
      end

      def pod_source_usage(sandbox_id, sample)
        return runtime_usage(sandbox_id) unless sample
        return sample unless sample["cgroup_fallback"]

        local = runtime_usage(sandbox_id) || {}
        containers = Array(local["containers"]).to_h { |container| [container["id"].to_s, container["usage"]] }
        combined = sample.fetch("containers").map { |container| container.merge("usage" => containers[container["id"]]) }
        sample.merge(local.slice("pod", "netns_pid"), "containers" => combined)
      end

      def runtime_usage(sandbox_id)
        return nil unless @runtime.respond_to?(:pod_usage)

        @runtime.pod_usage(sandbox_id)
      rescue StandardError
        nil
      end

      # The raw cgroup accounting of every running Pod (what /metrics/cadvisor
      # renders): [[record, pod_usage], ...].
      def raw_pod_usages
        running_stats_records.filter_map do |record|
          usage = runtime_usage(record[:sandbox_id])
          usage && [record, usage]
        end
      end

      private def running_stats_records
        records = if @has_stats_records
                    @lifecycle.stats_records
                  elsif @lifecycle.respond_to?(:records)
                    @lifecycle.records.values
                  else
                    []
                  end
        records.select { |record| record.is_a?(Hash) && record[:state].to_s == "Running" && record[:sandbox_id] }
      end

      def container_stats(uid, container, record, stamp, log_root: nil)
        usage = container["usage"] || {}
        entry = record[:containers].to_a.find { |candidate| candidate[:id].to_s == container["id"].to_s }
        return if container["summary"] && entry.nil?

        result = {"name" => container["name"].to_s,
                  "startTime" => entry && (entry[:started_at] || entry.dig(:status, "running", "startedAt"))}
        result.merge!(container["summary"]) if container["summary"]
        result["cpu"] = cpu_stats("container/#{uid}/#{container["id"]}", usage["cpu"], stamp) if usage["cpu"]
        result["memory"] = memory_stats(usage["memory.current"], usage["memory"], stamp, limit: usage["memory.max"]) if usage["memory"]
        result["swap"] = swap_stats(usage, stamp) if usage.key?("memory.swap.current")
        add_cgroup_pressure(result, usage, stamp)
        rootfs = container["rootfs"] && directory_stats(container["rootfs"], stamp, device: container["rootfs"])
        result["rootfs"] = rootfs if rootfs
        if result["rootfs"] && (mount = container["rootfs_mount"]) && !mount.empty?
          base = fs_stats(mount, stamp)&.except("usedBytes", "inodesUsed") || {}
          result["rootfs"] = base.merge(result["rootfs"])
        end
        logs = if (directory = container["logs"])
                 directory_stats(directory, stamp, device: directory)
               elsif log_root && entry
                 directory = File.join(cri_pod_log_directory(log_root, record), entry[:name].to_s)
                 files = log_file_stats(directory)
                 usage = [files.sum { |file| file["usedBytes"] }, files.size]
                 directory_stats(directory, stamp, device: directory, usage: usage)
               end
        result["logs"] = logs if logs
        result.compact
      end

      def cri_pod_log_directory(root, record)
        metadata = record[:pod].fetch("metadata", {})
        owner = %w[namespace name uid].map { |field| metadata[field].to_s }.join("_")
        File.join(root, owner)
      end

      # EphemeralStorage: container rootfs and logs plus ephemeral volumes.
      def ephemeral_storage(containers, volumes, stamp, record, log_root)
        parts = containers.flat_map { |container| [container["rootfs"], container["logs"]] }.compact + volumes
        hosts = record[:hosts_file] || record.dig(:pod_files, "/etc/hosts")
        parts << file_stats(hosts) if hosts
        parts.concat(log_file_stats(cri_pod_log_directory(log_root, record))) if log_root
        parts.compact!
        base = fs_stats(@pod_root || "/", stamp) || {"time" => stamp}
        {"time" => stamp, "availableBytes" => base["availableBytes"], "capacityBytes" => base["capacityBytes"],
         "usedBytes" => parts.sum { |part| part["usedBytes"].to_i }, "inodesFree" => base["inodesFree"],
         "inodes" => base["inodes"], "inodesUsed" => parts.sum { |part| part["inodesUsed"].to_i }}.compact
      end

      # ------------------------------------------------------------- helpers

      def cpu_stats(key, cpu_stat, stamp)
        usec = cpu_stat["usage_usec"]
        return nil if usec.nil?

        total = Integer(usec) * 1000
        now = @monotonic.call
        rate = @mutex.synchronize do
          previous_time, previous_total, previous_rate = @cpu_samples[key]
          if previous_time.nil? || total < previous_total
            @cpu_samples[key] = [now, total, nil]
            next
          end

          interval = now - previous_time
          # Kubelet's cAdvisor uses 10-second housekeeping and up to 15 seconds
          # for inactive containers. Scrapes in between keep the last rate.
          sample_interval = total == previous_total ? IDLE_CPU_SAMPLE_INTERVAL : CPU_SAMPLE_INTERVAL
          next previous_rate if interval < sample_interval

          measured = ((total - previous_total) / interval).to_i
          @cpu_samples[key] = [now, total, measured]
          measured
        end
        {"time" => stamp, "usageNanoCores" => rate, "usageCoreNanoSeconds" => total}.compact
      end

      # stats/v1alpha1 SwapStats: memory.swap.current, and the limit the
      # cgroup has (memory.swap.max, nil when unlimited).
      def swap_stats(usage, stamp)
        result = {"time" => stamp, "swapUsageBytes" => usage["memory.swap.current"].to_i}
        limit = usage["memory.swap.max"]
        result["swapAvailableBytes"] = [limit.to_i - result["swapUsageBytes"], 0].max if limit
        result
      end

      def node_swap_stats(stamp)
        total = nil
        free = nil
        File.foreach(File.join(@proc_root, "meminfo")) do |line|
          total = Integer(line.split[1]) * 1024 if line.start_with?("SwapTotal:")
          free = Integer(line.split[1]) * 1024 if line.start_with?("SwapFree:")
        end
        return nil if total.nil? || free.nil?

        {"time" => stamp, "swapAvailableBytes" => free, "swapUsageBytes" => total - free}
      rescue SystemCallError, ArgumentError
        nil
      end

      # ->(source, seconds) for kubelet_volume_metric_collection_duration_seconds.
      attr_accessor :metrics_observer

      def memory_stats(usage, memory_stat, stamp, limit: nil)
        return nil if usage.nil?

        usage = Integer(usage)
        inactive = memory_stat["inactive_file"].to_i
        working_set = usage < inactive ? 0 : usage - inactive
        result = {"time" => stamp, "usageBytes" => usage, "workingSetBytes" => working_set, "rssBytes" => memory_stat["anon"]&.to_i,
                  "pageFaults" => memory_stat["pgfault"]&.to_i, "majorPageFaults" => memory_stat["pgmajfault"]&.to_i}
        result["availableBytes"] = [limit - working_set, 0].max if limit
        result.compact
      end

      # `du`-style usage of a directory tree (allocated blocks, entries), with
      # the capacity figures of the filesystem it lives on.
      def directory_stats(path, stamp, device:, usage: nil)
        return nil unless File.exist?(path)

        used, inodes = usage || directory_usage(path)
        base = fs_stats(device, stamp) || {}
        {"time" => stamp, "availableBytes" => base["availableBytes"], "capacityBytes" => base["capacityBytes"],
         "usedBytes" => used, "inodesFree" => base["inodesFree"], "inodes" => base["inodes"], "inodesUsed" => inodes}.compact
      rescue Errno::ENOENT, Errno::ENOTDIR
        nil # Pod cleanup can remove this path after the sample starts.
      end

      def directory_usage(path)
        now = @monotonic.call
        cached = @mutex.synchronize { @du_cache[path] }
        return cached[1] if cached && now - cached[0] < @fs_ttl

        usage = DirectoryUsage.measure(path)
        @mutex.synchronize { @du_cache[path] = [now, usage] }
        usage
      end

      def forget_samples(live_uids)
        @mutex.synchronize do
          @cpu_samples.delete_if do |key, _|
            parts = key.split("/")
            parts[0] != "node" && !live_uids.include?(parts[1])
          end
          @du_cache.delete_if { |_path, (at, _)| @monotonic.call - at > @fs_ttl * 4 }
        end
      end

      def read_key_values(path)
        return nil unless File.exist?(path)

        File.read(path).lines.each_with_object({}) do |line, result|
          key, value = line.split
          result[key] = Integer(value) if key && value&.match?(/\A-?\d+\z/)
        end
      rescue SystemCallError
        nil
      end
    end
  end
end
