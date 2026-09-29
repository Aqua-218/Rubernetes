# frozen_string_literal: true

require "find"
require "time"

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

      def initialize(node_name:, lifecycle:, runtime:, pod_root: nil, image_root: nil, clock: -> { Time.now.utc },
                     monotonic: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     cgroup_root: "/sys/fs/cgroup", proc_root: "/proc", memory_capacity: nil, fs_ttl: DEFAULT_FS_TTL,
                     allocatable_memory: nil, volume_stats: nil)
        @node_name = node_name.to_s
        @lifecycle = lifecycle
        @runtime = runtime
        @pod_root = pod_root
        @image_root = image_root
        @clock = clock
        @monotonic = monotonic
        @cgroup_root = cgroup_root
        @proc_root = proc_root
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
        @csi_cache = {}
        @mutex = Mutex.new
      end

      def summary
        now = @clock.call.utc
        stamp = now.iso8601
        pods = pod_stats(stamp)
        node = node_stats(stamp)
        pods_container = pods_system_container(pods, stamp)
        node["systemContainers"] = [pods_container] if pods_container
        {"node" => node, "pods" => pods}
      end

      # The "pods" system container (the kubepods cgroup upstream): every
      # Pod's memory, with the node's allocatable memory as its limit -- what
      # node allocatable enforcement sets kubepods' memory.max to -- so
      # availableBytes is what allocatableMemory.available is observed from.
      def pods_system_container(pods, stamp)
        limit = @allocatable_memory
        return nil unless limit

        memories = pods.filter_map { |pod| pod["memory"] }
        working_set = memories.sum { |memory| memory["workingSetBytes"].to_i }
        usage = memories.sum { |memory| memory["usageBytes"].to_i }
        {"name" => "pods", "startTime" => boot_time,
         "memory" => {"time" => stamp, "availableBytes" => [limit - working_set, 0].max, "usageBytes" => usage,
                      "workingSetBytes" => working_set}}.compact
      end

      # --------------------------------------------------------------- node

      def node_stats(stamp)
        memory_stat = read_key_values(File.join(@cgroup_root, "memory.stat"))
        cpu_stat = read_key_values(File.join(@cgroup_root, "cpu.stat"))
        capacity = memory_capacity
        usage = memory_stat && (memory_stat["anon"].to_i + memory_stat["file"].to_i)
        stats = {"nodeName" => @node_name, "startTime" => boot_time}
        stats["cpu"] = cpu_stats("node", cpu_stat, stamp) if cpu_stat
        stats["memory"] = memory_stats(usage, memory_stat, stamp, limit: capacity) if memory_stat
        swap = node_swap_stats(stamp)
        stats["swap"] = swap if swap
        nodefs = fs_stats(@pod_root || "/", stamp)
        stats["fs"] = nodefs if nodefs
        imagefs = @image_root && fs_stats(@image_root, stamp)
        stats["runtime"] = {"imageFs" => imagefs || nodefs}.compact unless (imagefs || nodefs).nil?
        rlimit = rlimit_stats(stamp)
        stats["rlimit"] = rlimit if rlimit
        stats.compact
      end

      # The image filesystem alone (image garbage collection reads it every
      # pass; a full summary would walk every Pod's writable layer).
      def image_fs_stats
        fs_stats(@image_root || @pod_root || "/", @clock.call.utc.iso8601)
      end

      # Images and Pod data on different filesystems (HasDedicatedImageFs).
      def dedicated_image_fs?
        return false if @image_root.nil?

        File.stat(@image_root).dev != File.stat(@pod_root || "/").dev
      rescue SystemCallError
        false
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
        records = if @lifecycle.respond_to?(:stats_records)
                    @lifecycle.stats_records
                  elsif @lifecycle.respond_to?(:records)
                    @lifecycle.records.values
                  else
                    []
                  end
        live = []
        stats = records.filter_map do |record|
          next unless record.is_a?(Hash) && record[:state].to_s == "Running" && record[:sandbox_id]

          pod = record[:pod] || {}
          uid = record[:uid].to_s
          live << uid
          usage = runtime_usage(record[:sandbox_id])
          containers = Array(usage && usage["containers"]).map do |container|
            container_stats(uid, container, record, stamp)
          end
          entry = {
            "podRef" => {"name" => pod.dig("metadata", "name").to_s, "namespace" => pod.dig("metadata", "namespace").to_s, "uid" => uid},
            "startTime" => record[:started_at],
            "containers" => containers
          }
          pod_usage = usage && usage["pod"]
          if pod_usage
            entry["cpu"] = cpu_stats("pod/#{uid}", pod_usage["cpu"], stamp) if pod_usage["cpu"]
            entry["memory"] = memory_stats(pod_usage["memory.current"], pod_usage["memory"], stamp) if pod_usage["memory"]
            entry["swap"] = swap_stats(pod_usage, stamp) if pod_usage.key?("memory.swap.current")
            entry["process_stats"] = {"process_count" => Integer(pod_usage["pids.current"])} if pod_usage["pids.current"]
          end
          volumes = volume_stats(record, stamp)
          entry["volume"] = volumes unless volumes.empty?
          entry["ephemeral-storage"] = ephemeral_storage(containers, volumes, stamp)
          entry.compact
        end
        forget_samples(live)
        stats
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
        records = if @lifecycle.respond_to?(:stats_records)
                    @lifecycle.stats_records
                  elsif @lifecycle.respond_to?(:records)
                    @lifecycle.records.values
                  else
                    []
                  end
        records.filter_map do |record|
          next unless record.is_a?(Hash) && record[:state].to_s == "Running" && record[:sandbox_id]

          usage = runtime_usage(record[:sandbox_id])
          usage && [record, usage]
        end
      end

      def container_stats(uid, container, record, stamp)
        usage = container["usage"] || {}
        entry = record[:containers].to_a.find { |candidate| candidate[:id].to_s == container["id"].to_s }
        result = {"name" => container["name"].to_s, "startTime" => entry && (entry[:started_at] || entry.dig(:status, "running", "startedAt"))}
        result["cpu"] = cpu_stats("container/#{uid}/#{container["id"]}", usage["cpu"], stamp) if usage["cpu"]
        result["memory"] = memory_stats(usage["memory.current"], usage["memory"], stamp) if usage["memory"]
        rootfs = container["rootfs"] && directory_stats(container["rootfs"], stamp, device: @pod_root || container["rootfs"])
        result["rootfs"] = rootfs if rootfs
        logs = container["logs"] && directory_stats(container["logs"], stamp, device: container["logs"])
        result["logs"] = logs if logs
        result.compact
      end

      # VolumeStats for the Pod's volumes: ephemeral ones (no pvcRef) count
      # towards the Pod's ephemeral storage.
      def volume_stats(record, stamp)
        mounts = record[:volume].is_a?(Hash) ? (record[:volume]["mounts"] || {}) : {}
        pod_spec = (record[:pod] || {})["spec"] || {}
        claims = Array(pod_spec["volumes"]).to_h { |volume| [volume["name"].to_s, volume.dig("persistentVolumeClaim", "claimName")] }
        mounts.filter_map do |name, mount|
          path = mount.is_a?(Hash) ? mount["path"] : nil
          next if path.nil? || !File.directory?(path)

          driver_stats = csi_volume_stats(mount["id"], path, stamp)
          next if driver_stats == :unsupported

          stats = driver_stats || directory_stats(path, stamp, device: path)
          next unless stats

          entry = stats.merge("name" => name.to_s)
          claim = claims[name.to_s]
          entry["pvcRef"] = {"name" => claim, "namespace" => (record[:pod] || {}).dig("metadata", "namespace").to_s} if claim
          entry
        end
      end

      # EphemeralStorage: container rootfs and logs plus ephemeral volumes.
      def ephemeral_storage(containers, volumes, stamp)
        parts = containers.flat_map { |container| [container["rootfs"], container["logs"]] }.compact +
                volumes.reject { |volume| volume.key?("pvcRef") }
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
          previous = @cpu_samples[key]
          @cpu_samples[key] = [now, total]
          if previous && now > previous[0] && total >= previous[1]
            ((total - previous[1]) / (now - previous[0])).to_i
          end
        end
        {"time" => stamp, "usageNanoCores" => rate, "usageCoreNanoSeconds" => total}.compact
      end

      def memory_stats(usage, memory_stat, stamp, limit: nil)
        return nil if usage.nil?

        usage = Integer(usage)
        inactive = memory_stat["inactive_file"].to_i
        working_set = usage < inactive ? 0 : usage - inactive
        result = {"time" => stamp, "usageBytes" => usage, "workingSetBytes" => working_set, "rssBytes" => memory_stat["anon"]&.to_i,
                  "pageFaults" => memory_stat["pgfault"]&.to_i, "majorPageFaults" => memory_stat["pgmajfault"]&.to_i}
        result["availableBytes"] = limit - working_set if limit && limit > working_set
        result.compact
      end

      def fs_stats(path, stamp)
        require_relative "../platform/linux/statfs"
        return nil unless Platform::Linux::Statfs.supported? && File.exist?(path)

        result = Platform::Linux::Statfs.statfs(path)
        {"time" => stamp, "availableBytes" => result.available_bytes, "capacityBytes" => result.capacity_bytes,
         "usedBytes" => result.used_bytes, "inodesFree" => result.files_free, "inodes" => result.files,
         "inodesUsed" => result.files - result.files_free}
      rescue StandardError
        nil
      end

      # `du`-style usage of a directory tree (allocated blocks, entries), with
      # the capacity figures of the filesystem it lives on.
      def directory_stats(path, stamp, device:)
        return nil unless File.exist?(path)

        used, inodes = directory_usage(path)
        base = fs_stats(device, stamp) || {}
        {"time" => stamp, "availableBytes" => base["availableBytes"], "capacityBytes" => base["capacityBytes"],
         "usedBytes" => used, "inodesFree" => base["inodesFree"], "inodes" => base["inodes"], "inodesUsed" => inodes}.compact
      end

      def csi_volume_stats(id, path, stamp)
        return nil if @volume_stats.nil? || id.nil?

        now = @monotonic.call
        cached = @mutex.synchronize { @csi_cache[[id, path]] }
        value = if cached && now - cached[0] < @fs_ttl
                  cached[1]
                else
                  fresh = begin
                    @volume_stats.call(id, path)
                  rescue StandardError
                    nil
                  end
                  @mutex.synchronize { @csi_cache[[id, path]] = [now, fresh] }
                  fresh
                end
        return value if value.nil? || value == :unsupported

        {"time" => stamp}.merge(value.slice("availableBytes", "capacityBytes", "usedBytes", "inodesFree", "inodes", "inodesUsed")).compact
      end

      def directory_usage(path)
        now = @monotonic.call
        cached = @mutex.synchronize { @du_cache[path] }
        return cached[1] if cached && now - cached[0] < @fs_ttl

        bytes = 0
        entries = 0
        Find.find(path) do |entry|
          stat = File.lstat(entry)
          bytes += stat.blocks * 512
          entries += 1
        rescue SystemCallError
          Find.prune
        end
        @mutex.synchronize { @du_cache[path] = [now, [bytes, entries]] }
        [bytes, entries]
      end

      def forget_samples(live_uids)
        @mutex.synchronize do
          @cpu_samples.delete_if do |key, _|
            parts = key.split("/")
            parts[0] != "node" && !live_uids.include?(parts[1])
          end
          @du_cache.delete_if { |_path, (at, _)| @monotonic.call - at > @fs_ttl * 4 }
          @csi_cache.delete_if { |_key, (at, _)| @monotonic.call - at > @fs_ttl * 4 }
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
