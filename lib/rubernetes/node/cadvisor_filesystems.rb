# frozen_string_literal: true

require_relative "../platform/linux/pivot_root"
require_relative "../platform/linux/statfs"
require_relative "directory_usage"

module Rubernetes
  module Node
    module CadvisorMetrics
      # cAdvisor exports filesystem diskstats for the node (id=/). A Pod's
      # cgroup io.stat supplies its own bytes and requests separately.
      module Filesystems
        DISK_FAMILIES = [
          ["container_fs_reads_total", "counter", "Cumulative count of reads completed", 1],
          ["container_fs_reads_merged_total", "counter", "Cumulative count of reads merged", 1],
          ["container_fs_sector_reads_total", "counter", "Cumulative count of sector reads completed", 1],
          ["container_fs_read_seconds_total", "counter", "Cumulative count of seconds spent reading", 1000.0],
          ["container_fs_writes_total", "counter", "Cumulative count of writes completed", 1],
          ["container_fs_writes_merged_total", "counter", "Cumulative count of writes merged", 1],
          ["container_fs_sector_writes_total", "counter", "Cumulative count of sector writes completed", 1],
          ["container_fs_write_seconds_total", "counter", "Cumulative count of seconds spent writing", 1000.0],
          ["container_fs_io_current", "gauge", "Number of I/Os currently in progress", 1],
          ["container_fs_io_time_seconds_total", "counter", "Cumulative count of seconds spent doing I/Os", 1000.0],
          ["container_fs_io_time_weighted_seconds_total", "counter", "Cumulative weighted I/O time in seconds", 1000.0]
        ].freeze
        ROOT_LABELS = {"id" => "/", "container" => "", "image" => "", "name" => "", "namespace" => "", "pod" => ""}.freeze

        module_function

        def add_node(samples, stamp_ms, proc_root)
          disks = disk_counters(File.join(proc_root, "diskstats"))
          return if disks.empty?

          contents = File.read(File.join(proc_root, "self", "mountinfo"))
          Platform::Linux::PivotRoot.parse_mountinfo(contents).each do |mount|
            entry = disks[mount.major_minor]
            next unless entry

            path = mount.mountpoint
            stat = File.stat(path)
            next unless device_id(stat) == mount.major_minor

            name, counters = entry
            labels = ROOT_LABELS.merge("device" => "/dev/#{name}")
            DISK_FAMILIES.each_with_index do |(metric, _type, _help, divisor), field|
              samples[metric] << [labels, counters.fetch(field) / divisor, stamp_ms]
            end
            add_node_space(samples, path, labels, stamp_ms)
            disks.delete(mount.major_minor)
          rescue SystemCallError
            # Ignore mounts that went away between mountinfo and the scrape.
            next
          end
        rescue SystemCallError
          nil
        end

        def disk_counters(path)
          result = {}
          File.foreach(path) do |line|
            major, minor, name, *values = line.split
            next if values.length < DISK_FAMILIES.length

            counters = values.take(DISK_FAMILIES.length).map { |value| Integer(value, 10, exception: false) }
            result["#{major}:#{minor}"] = [name, counters] if counters.none?(&:nil?)
          end
          result
        rescue SystemCallError
          {}
        end

        def add_node_space(samples, path, labels, stamp_ms)
          stats = statfs(path)
          return unless stats

          samples["container_fs_limit_bytes"] << [labels, stats.capacity_bytes, stamp_ms]
          samples["container_fs_usage_bytes"] << [labels, stats.used_bytes, stamp_ms]
          samples["container_fs_inodes_total"] << [labels, stats.files, stamp_ms]
          samples["container_fs_inodes_free"] << [labels, stats.files_free, stamp_ms]
        end

        def add_container(samples, path, labels, stamp_ms, sys_root, disk_usage)
          stat = File.stat(path)
          return unless stat.directory?

          used, inodes = disk_usage ? disk_usage.call(path) : DirectoryUsage.measure(path)
          labels = labels.merge("device" => CadvisorMetrics.device_name(device_id(stat), sys_root))
          samples["container_fs_usage_bytes"] << [labels, used, stamp_ms]
          # A writable overlay layer contributes its own used inodes. Only
          # the backing filesystem has an available inode count without quotas.
          samples["container_fs_inodes_total"] << [labels, inodes, stamp_ms]
          stats = statfs(path)
          samples["container_fs_limit_bytes"] << [labels, stats.capacity_bytes, stamp_ms] if stats
        rescue Errno::ENOENT, Errno::ENOTDIR
          nil
        end

        def device_id(stat)
          "#{stat.dev_major}:#{stat.dev_minor}"
        end

        def statfs(path)
          Platform::Linux::Statfs.statfs(path) if Platform::Linux::Statfs.supported?
        rescue Platform::Linux::Error, SystemCallError, Fiddle::DLError
          nil
        end
      end
    end
  end
end
