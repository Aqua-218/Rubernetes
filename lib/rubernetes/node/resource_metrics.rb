# frozen_string_literal: true

require "time"
require "find"
require "etc"
require_relative "../observability/metrics"

module Rubernetes
  module Node
    # pkg/kubelet/metrics/collectors/resource_metrics.go: /metrics/resource,
    # what metrics-server (and so HPA and `kubectl top`) scrapes, rendered
    # from the Summary API with each sample's own timestamp in milliseconds.
    module ResourceMetrics
      DESCRIPTORS = [
        ["node_cpu_usage_seconds_total", "counter", "STABLE", "Cumulative cpu time consumed by the node in core-seconds"],
        ["node_memory_working_set_bytes", "gauge", "STABLE", "Current working set of the node in bytes"],
        ["container_cpu_usage_seconds_total", "counter", "STABLE", "Cumulative cpu time consumed by the container in core-seconds"],
        ["container_memory_working_set_bytes", "gauge", "STABLE", "Current working set of the container in bytes"],
        ["container_start_time_seconds", "gauge", "STABLE", "Start time of the container since unix epoch in seconds"],
        ["pod_cpu_usage_seconds_total", "counter", "STABLE", "Cumulative cpu time consumed by the pod in core-seconds"],
        ["pod_memory_working_set_bytes", "gauge", "STABLE", "Current working set of the pod in bytes"],
        ["resource_scrape_error", "gauge", "STABLE", "1 if there was an error while getting container metrics, 0 otherwise"]
      ].freeze

      module_function

      def render(summary, scrape_error: false)
        samples = Hash.new { |hash, key| hash[key] = [] }
        node = summary.fetch("node", {})
        add_cpu(samples["node_cpu_usage_seconds_total"], node["cpu"], {})
        add_memory(samples["node_memory_working_set_bytes"], node["memory"], {})
        Array(summary["pods"]).each do |pod|
          ref = pod["podRef"] || {}
          labels = {"namespace" => ref["namespace"].to_s, "pod" => ref["name"].to_s}
          add_cpu(samples["pod_cpu_usage_seconds_total"], pod["cpu"], labels)
          add_memory(samples["pod_memory_working_set_bytes"], pod["memory"], labels)
          Array(pod["containers"]).each do |container|
            container_labels = {"container" => container["name"].to_s}.merge(labels)
            add_cpu(samples["container_cpu_usage_seconds_total"], container["cpu"], container_labels)
            add_memory(samples["container_memory_working_set_bytes"], container["memory"], container_labels)
            started = parse_time(container["startTime"])
            samples["container_start_time_seconds"] << [container_labels, started.to_f, (started.to_f * 1000).to_i] if started
          end
        end
        samples["resource_scrape_error"] << [{}, scrape_error ? 1 : 0, nil]
        DESCRIPTORS.filter_map do |name, type, stability, help|
          lines = samples[name]
          next if lines.empty?

          header = "# HELP #{name} [#{stability}] #{help}\n# TYPE #{name} #{type}\n"
          header + lines.map { |labels, value, timestamp| sample(name, labels, value, timestamp) }.join
        end.join
      end

      def add_cpu(list, cpu, labels)
        return unless cpu.is_a?(Hash) && cpu["usageCoreNanoSeconds"]

        list << [labels, cpu["usageCoreNanoSeconds"].to_f / 1e9, millis(cpu["time"])]
      end

      def add_memory(list, memory, labels)
        return unless memory.is_a?(Hash) && memory["workingSetBytes"]

        list << [labels, memory["workingSetBytes"].to_i, millis(memory["time"])]
      end

      def sample(name, labels, value, timestamp)
        label_text = labels.empty? ? "" : "{#{labels.map { |key, item| "#{key}=\"#{escape(item)}\"" }.join(",")}}"
        rendered = format_float(value)
        "#{name}#{label_text} #{rendered}#{timestamp ? " #{timestamp}" : ""}\n"
      end

      # expfmt writeFloat: every sample value is a float64 ("1.3950976e+07").
      def format_float(value) = Observability::Metrics.go_float(value.to_f)

      def millis(time)
        parsed = parse_time(time)
        parsed ? (parsed.to_f * 1000).to_i : nil
      end

      def parse_time(value)
        value.nil? ? nil : Time.parse(value.to_s)
      rescue ArgumentError
        nil
      end

      def escape(value) = value.to_s.gsub("\\", "\\\\\\\\").gsub("\"", "\\\"").gsub("\n", "\\n")
    end
  end
end

module Rubernetes
  module Node
    # /metrics/cadvisor: the container metrics kubelet's embedded cAdvisor
    # exports (cadvisor/metrics/prometheus.go with the kubelet's included
    # metric sets: cpu, memory, disk usage and I/O, network, process, OOM),
    # rendered straight from each running Pod's cgroup v2 accounting
    # (Runtime#pod_usage) under cAdvisor's names, help strings and labels:
    # id (the cgroup path), name (the container's runtime id), image,
    # container, pod, namespace; the Pod's own cgroup is the entry with an
    # empty container, and carries the network counters of the Pod's
    # namespace.  Every container sample carries cAdvisor's millisecond
    # timestamp.  The machine_* gauges and cadvisor_version_info come with it.
    module CadvisorMetrics
      # Descriptors in cAdvisor's order: [name, type, help].
      CONTAINER_FAMILIES = [
        ["container_last_seen", "gauge", "Last time a container was seen by the exporter"],
        ["container_cpu_user_seconds_total", "counter", "Cumulative user cpu time consumed in seconds."],
        ["container_cpu_system_seconds_total", "counter", "Cumulative system cpu time consumed in seconds."],
        ["container_cpu_usage_seconds_total", "counter", "Cumulative cpu time consumed in seconds."],
        ["container_cpu_cfs_periods_total", "counter", "Number of elapsed enforcement period intervals."],
        ["container_cpu_cfs_throttled_periods_total", "counter", "Number of throttled period intervals."],
        ["container_cpu_cfs_throttled_seconds_total", "counter", "Total time duration the container has been throttled."],
        ["container_memory_cache", "gauge", "Number of bytes of page cache memory."],
        ["container_memory_rss", "gauge", "Size of RSS in bytes."],
        ["container_memory_kernel_usage", "gauge", "Size of kernel memory allocated in bytes."],
        ["container_memory_mapped_file", "gauge", "Size of memory mapped files in bytes."],
        ["container_memory_swap", "gauge", "Container swap usage in bytes."],
        ["container_memory_failcnt", "counter", "Number of memory usage hits limits"],
        ["container_memory_usage_bytes", "gauge", "Current memory usage in bytes, including all memory regardless of when it was accessed"],
        ["container_memory_max_usage_bytes", "gauge", "Maximum memory usage recorded in bytes"],
        ["container_memory_working_set_bytes", "gauge", "Current working set in bytes."],
        ["container_memory_failures_total", "counter", "Cumulative count of memory allocation failures."],
        ["container_oom_events_total", "counter", "Count of out of memory events observed for the container"],
        ["container_fs_inodes_free", "gauge", "Number of available Inodes"],
        ["container_fs_inodes_total", "gauge", "Number of Inodes"],
        ["container_fs_limit_bytes", "gauge", "Number of bytes that can be consumed by the container on this filesystem."],
        ["container_fs_usage_bytes", "gauge", "Number of bytes that are consumed by the container on this filesystem."],
        ["container_fs_reads_bytes_total", "counter", "Cumulative count of bytes read"],
        ["container_fs_reads_total", "counter", "Cumulative count of reads completed"],
        ["container_fs_writes_bytes_total", "counter", "Cumulative count of bytes written"],
        ["container_fs_writes_total", "counter", "Cumulative count of writes completed"],
        ["container_blkio_device_usage_total", "counter", "Blkio Device bytes usage"],
        ["container_network_receive_bytes_total", "counter", "Cumulative count of bytes received"],
        ["container_network_receive_packets_total", "counter", "Cumulative count of packets received"],
        ["container_network_receive_packets_dropped_total", "counter", "Cumulative count of packets dropped while receiving"],
        ["container_network_receive_errors_total", "counter", "Cumulative count of errors encountered while receiving"],
        ["container_network_transmit_bytes_total", "counter", "Cumulative count of bytes transmitted"],
        ["container_network_transmit_packets_total", "counter", "Cumulative count of packets transmitted"],
        ["container_network_transmit_packets_dropped_total", "counter", "Cumulative count of packets dropped while transmitting"],
        ["container_network_transmit_errors_total", "counter", "Cumulative count of errors encountered while transmitting"],
        ["container_tasks_state", "gauge", "Number of tasks in given state"],
        ["container_processes", "gauge", "Number of processes running inside the container."],
        ["container_threads", "gauge", "Number of threads running inside the container"],
        ["container_threads_max", "gauge", "Maximum number of threads allowed inside the container, infinity if value is zero"],
        ["container_file_descriptors", "gauge", "Number of open file descriptors for the container."],
        ["container_sockets", "gauge", "Number of open sockets for the container."],
        ["container_ulimits_soft", "gauge", "Soft ulimit values for the container root process. Unlimited if -1, except priority and nice"],
        ["container_spec_cpu_period", "gauge", "CPU period of the container."],
        ["container_spec_cpu_quota", "gauge", "CPU quota of the container."],
        ["container_spec_cpu_shares", "gauge", "CPU share of the container."],
        ["container_spec_memory_limit_bytes", "gauge", "Memory limit for the container."],
        ["container_spec_memory_swap_limit_bytes", "gauge", "Memory swap limit for the container."],
        ["container_spec_memory_reservation_limit_bytes", "gauge", "Memory reservation limit for the container."],
        ["container_start_time_seconds", "gauge", "Start time of the container since unix epoch in seconds."],
        ["container_scrape_error", "gauge", "1 if there was an error while getting container metrics, 0 otherwise"]
      ].freeze
      MACHINE_FAMILIES = [
        ["cadvisor_version_info", "gauge", "A metric with a constant '1' value labeled by kernel version, OS version, docker version, cadvisor version & cadvisor revision."],
        ["machine_cpu_cores", "gauge", "Number of logical CPU cores."],
        ["machine_cpu_physical_cores", "gauge", "Number of physical CPU cores."],
        ["machine_cpu_sockets", "gauge", "Number of CPU sockets."],
        ["machine_memory_bytes", "gauge", "Amount of memory installed on the machine."],
        ["machine_swap_bytes", "gauge", "Amount of swap memory available on the machine."],
        ["machine_scrape_error", "gauge", "1 if there was an error while getting machine metrics, 0 otherwise."]
      ].freeze
      # cAdvisor reports an unlimited memory.max as the largest page-aligned int64.
      UNLIMITED_MEMORY = 9_223_372_036_854_771_712
      TASK_STATES = {"R" => "running", "S" => "sleeping", "D" => "uninterruptible", "T" => "stopped", "t" => "stopped",
                     "Z" => "sleeping", "I" => "sleeping"}.freeze
      TASK_STATE_NAMES = %w[sleeping running stopped uninterruptible iowaiting].freeze
      # cAdvisor 0.52 is what kubelet v1.36 vendors.
      CADVISOR_VERSION = "v0.52.1"

      module_function

      # +usages+: [[record, pod_usage], ...] (StatsProvider#raw_pod_usages),
      # or a Summary hash (the older, poorer rendering kept for callers
      # without runtime access).
      def render(usages, machine: {}, images: {}, now: Time.now, proc_root: "/proc", sys_root: "/sys", disk_usage: nil)
        return render_summary(usages, machine: machine, images: images) if usages.is_a?(Hash)

        stamp_ms = (now.to_f * 1000).to_i
        samples = Hash.new { |hash, key| hash[key] = [] }
        failed = false
        Array(usages).each do |record, usage|
          render_pod(samples, record, usage, stamp_ms, now, proc_root, sys_root, disk_usage)
        rescue StandardError
          failed = true
        end
        # cAdvisor's plain gauge: 1 when any container's metrics failed.
        samples["container_scrape_error"] << [{}, failed ? 1 : 0, nil]
        machine_samples(samples, machine)
        (MACHINE_FAMILIES + CONTAINER_FAMILIES).filter_map do |name, type, help|
          lines = samples[name]
          next if lines.empty?

          "# HELP #{name} #{help}\n# TYPE #{name} #{type}\n" +
            lines.map { |labels, value, timestamp| ResourceMetrics.sample(name, labels.sort.to_h, value, timestamp) }.join
        end.join
      end

      def pod_identity(record, usage)
        pod = record.is_a?(Hash) ? (record[:pod] || record["pod"] || {}) : {}
        uid = (record.is_a?(Hash) && (record[:uid] || record["uid"])) || pod.dig("metadata", "uid")
        path = usage.is_a?(Hash) && usage["pod"].is_a?(Hash) ? usage["pod"]["path"] : nil
        {"container" => "", "id" => (path || "/kubepods/pod#{uid}").to_s, "image" => "", "name" => "",
         "namespace" => pod.dig("metadata", "namespace").to_s, "pod" => pod.dig("metadata", "name").to_s}
      end

      def render_pod(samples, record, usage, stamp_ms, now, proc_root, sys_root, disk_usage)
        pod_labels = pod_identity(record, usage)
        pod_usage = usage["pod"]
        if pod_usage.is_a?(Hash)
          add_cgroup(samples, pod_usage, pod_labels, stamp_ms, now, proc_root, sys_root)
          started = ResourceMetrics.parse_time(record[:started_at] || record["started_at"])
          samples["container_start_time_seconds"] << [pod_labels, started.to_f, stamp_ms] if started
        end
        netns_pid = usage["netns_pid"]
        add_network(samples, pod_labels, netns_pid, stamp_ms, proc_root) if netns_pid
        entries = Array(record[:containers] || record["containers"])
        Array(usage["containers"]).each do |container|
          next unless container.is_a?(Hash) && container["usage"].is_a?(Hash)

          id = container["id"].to_s
          labels = pod_labels.merge("container" => container["name"].to_s, "name" => id, "image" => container["image"].to_s,
                                    "id" => (container["usage"]["path"] || "#{pod_labels["id"]}/#{id}").to_s)
          add_cgroup(samples, container["usage"], labels, stamp_ms, now, proc_root, sys_root)
          entry = entries.find { |candidate| (candidate[:id] || candidate["id"]).to_s == id }
          started = entry && ResourceMetrics.parse_time(entry[:started_at] || entry["started_at"] || entry.dig(:status, "running", "startedAt"))
          samples["container_start_time_seconds"] << [labels, started.to_f, stamp_ms] if started
          add_rootfs(samples, container["rootfs"], labels, stamp_ms, disk_usage) if container["rootfs"]
        end
      end

      def add_cgroup(samples, usage, labels, stamp_ms, now, proc_root, sys_root)
        emit = ->(name, value, extra = {}) { samples[name] << [extra.empty? ? labels : labels.merge(extra), value, stamp_ms] }
        emit.call("container_last_seen", now.to_f.floor)
        cpu = usage["cpu"] || {}
        emit.call("container_cpu_user_seconds_total", cpu["user_usec"].to_f / 1e6) if cpu.key?("user_usec")
        emit.call("container_cpu_system_seconds_total", cpu["system_usec"].to_f / 1e6) if cpu.key?("system_usec")
        emit.call("container_cpu_usage_seconds_total", cpu["usage_usec"].to_f / 1e6, "cpu" => "total") if cpu.key?("usage_usec")
        emit.call("container_cpu_cfs_periods_total", cpu["nr_periods"].to_i) if cpu.key?("nr_periods")
        emit.call("container_cpu_cfs_throttled_periods_total", cpu["nr_throttled"].to_i) if cpu.key?("nr_throttled")
        emit.call("container_cpu_cfs_throttled_seconds_total", cpu["throttled_usec"].to_f / 1e6) if cpu.key?("throttled_usec")
        memory = usage["memory"] || {}
        current = usage["memory.current"]
        emit.call("container_memory_cache", memory["file"].to_i) if memory.key?("file")
        emit.call("container_memory_rss", memory["anon"].to_i) if memory.key?("anon")
        emit.call("container_memory_kernel_usage", memory["kernel"].to_i) if memory.key?("kernel")
        emit.call("container_memory_mapped_file", memory["file_mapped"].to_i) if memory.key?("file_mapped")
        emit.call("container_memory_swap", usage["memory.swap.current"].to_i) if usage["memory.swap.current"]
        events = usage["memory.events"] || {}
        emit.call("container_memory_failcnt", events["max"].to_i) if events.key?("max")
        if current
          emit.call("container_memory_usage_bytes", current.to_i)
          working_set = current.to_i - memory["inactive_file"].to_i
          emit.call("container_memory_working_set_bytes", working_set.negative? ? 0 : working_set)
        end
        emit.call("container_memory_max_usage_bytes", usage["memory.peak"].to_i) if usage["memory.peak"]
        %w[container hierarchy].each do |scope|
          emit.call("container_memory_failures_total", memory["pgfault"].to_i, "failure_type" => "pgfault", "scope" => scope) if memory.key?("pgfault")
          emit.call("container_memory_failures_total", memory["pgmajfault"].to_i, "failure_type" => "pgmajfault", "scope" => scope) if memory.key?("pgmajfault")
        end
        emit.call("container_oom_events_total", events["oom_kill"].to_i) if events.key?("oom_kill")
        add_io(samples, usage["io.stat"], labels, stamp_ms, sys_root) if usage["io.stat"].is_a?(Hash)
        add_processes(samples, usage, labels, stamp_ms, proc_root)
        add_spec(samples, usage, labels, stamp_ms)
      end

      def add_io(samples, io, labels, stamp_ms, sys_root)
        io.each do |device, counters|
          major, minor = device.split(":", 2)
          name = device_name(device, sys_root)
          device_labels = labels.merge("device" => name)
          samples["container_fs_reads_bytes_total"] << [device_labels, counters["rbytes"].to_i, stamp_ms]
          samples["container_fs_writes_bytes_total"] << [device_labels, counters["wbytes"].to_i, stamp_ms]
          samples["container_fs_reads_total"] << [device_labels, counters["rios"].to_i, stamp_ms]
          samples["container_fs_writes_total"] << [device_labels, counters["wios"].to_i, stamp_ms]
          samples["container_blkio_device_usage_total"] << [labels.merge("device" => name, "major" => major.to_s, "minor" => minor.to_s, "operation" => "Read"), counters["rbytes"].to_i, stamp_ms]
          samples["container_blkio_device_usage_total"] << [labels.merge("device" => name, "major" => major.to_s, "minor" => minor.to_s, "operation" => "Write"), counters["wbytes"].to_i, stamp_ms]
        end
      end

      def device_name(device, sys_root)
        link = File.readlink(File.join(sys_root, "dev", "block", device))
        "/dev/#{File.basename(link)}"
      rescue SystemCallError
        device
      end

      def add_rootfs(samples, path, labels, stamp_ms, disk_usage)
        return unless File.directory?(path)

        used, _inodes = disk_usage ? disk_usage.call(path) : directory_usage(path)
        stat = statfs(path)
        device_labels = labels.merge("device" => stat && stat[:device] ? stat[:device] : "rootfs")
        samples["container_fs_usage_bytes"] << [device_labels, used.to_i, stamp_ms]
        return unless stat

        samples["container_fs_limit_bytes"] << [device_labels, stat[:capacity], stamp_ms]
        samples["container_fs_inodes_free"] << [device_labels, stat[:inodes_free], stamp_ms]
        samples["container_fs_inodes_total"] << [device_labels, stat[:inodes], stamp_ms]
      end

      def statfs(path)
        require_relative "../platform/linux/statfs"
        return nil unless Platform::Linux::Statfs.supported?

        result = Platform::Linux::Statfs.statfs(path)
        {capacity: result.capacity_bytes, inodes_free: result.files_free, inodes: result.files, device: nil}
      rescue StandardError
        nil
      end

      def directory_usage(path)
        bytes = 0
        inodes = 0
        Find.find(path) do |entry|
          stat = File.lstat(entry)
          bytes += stat.blocks * 512
          inodes += 1
        rescue SystemCallError
          Find.prune
        end
        [bytes, inodes]
      end

      # /proc/<pid>/net/dev of the Pod's network namespace holder: every
      # interface but loopback, like cAdvisor.
      def add_network(samples, labels, netns_pid, stamp_ms, proc_root)
        path = File.join(proc_root, netns_pid.to_s, "net", "dev")
        return unless File.readable?(path)

        File.readlines(path).drop(2).each do |line|
          interface, counters = line.split(":", 2)
          next if interface.nil? || counters.nil?

          interface = interface.strip
          next if interface == "lo"

          fields = counters.split.map { |value| Integer(value, exception: false) || 0 }
          next if fields.length < 16

          with = labels.merge("interface" => interface)
          samples["container_network_receive_bytes_total"] << [with, fields[0], stamp_ms]
          samples["container_network_receive_packets_total"] << [with, fields[1], stamp_ms]
          samples["container_network_receive_errors_total"] << [with, fields[2], stamp_ms]
          samples["container_network_receive_packets_dropped_total"] << [with, fields[3], stamp_ms]
          samples["container_network_transmit_bytes_total"] << [with, fields[8], stamp_ms]
          samples["container_network_transmit_packets_total"] << [with, fields[9], stamp_ms]
          samples["container_network_transmit_errors_total"] << [with, fields[10], stamp_ms]
          samples["container_network_transmit_packets_dropped_total"] << [with, fields[11], stamp_ms]
        end
      end

      # The process set of the cgroup (cgroup.procs): task states, threads,
      # file descriptors, sockets and the root process's soft ulimit.
      def add_processes(samples, usage, labels, stamp_ms, proc_root)
        samples["container_processes"] << [labels, usage["pids.current"].to_i, stamp_ms] if usage["pids.current"]
        # pids.max "max" reads as nil: cAdvisor shows 0 for no limit.
        samples["container_threads_max"] << [labels, usage["pids.max"].to_i, stamp_ms] if usage.key?("pids.max")
        pids = Array(usage["cgroup.procs"])
        return if pids.empty?

        states = Hash.new(0)
        threads = 0
        descriptors = 0
        sockets = 0
        pids.each do |pid|
          stat = File.read(File.join(proc_root, pid.to_s, "stat"))
          state = stat[/\)\s+(\S)/, 1]
          states[TASK_STATES.fetch(state, "sleeping")] += 1
          status = File.read(File.join(proc_root, pid.to_s, "status"))
          threads += status[/^Threads:\s+(\d+)/, 1].to_i
          entries = Dir.children(File.join(proc_root, pid.to_s, "fd"))
          descriptors += entries.length
          sockets += entries.count do |fd|
            File.readlink(File.join(proc_root, pid.to_s, "fd", fd)).start_with?("socket:")
          rescue SystemCallError
            false
          end
        rescue SystemCallError
          next
        end
        TASK_STATE_NAMES.each { |name| samples["container_tasks_state"] << [labels.merge("state" => name), states[name], stamp_ms] }
        samples["container_threads"] << [labels, threads, stamp_ms]
        samples["container_file_descriptors"] << [labels, descriptors, stamp_ms]
        samples["container_sockets"] << [labels, sockets, stamp_ms]
        limits = File.read(File.join(proc_root, pids.first.to_s, "limits"))
        open_files = limits[/^Max open files\s+(\S+)/, 1]
        if open_files
          value = open_files == "unlimited" ? -1 : open_files.to_i
          samples["container_ulimits_soft"] << [labels.merge("ulimit" => "max_open_files"), value, stamp_ms]
        end
      rescue SystemCallError
        nil
      end

      # cpu.max "quota period" / "max period"; cpu.weight back to cgroup v1
      # shares (the inverse of what runc writes); memory.max "max" is the
      # int64 cAdvisor prints for unlimited.
      def add_spec(samples, usage, labels, stamp_ms)
        cpu_max = Array(usage["cpu.max"])
        if cpu_max.length == 2
          samples["container_spec_cpu_period"] << [labels, cpu_max[1].to_i, stamp_ms]
          samples["container_spec_cpu_quota"] << [labels, cpu_max[0].to_i, stamp_ms] unless cpu_max[0] == "max"
        end
        if usage["cpu.weight"]
          weight = usage["cpu.weight"].to_i
          shares = weight <= 1 ? 2 : ((weight - 1) * 262_142) / 9_999 + 2
          samples["container_spec_cpu_shares"] << [labels, shares, stamp_ms]
        end
        if usage.key?("memory.max")
          limit = usage["memory.max"].nil? ? UNLIMITED_MEMORY : usage["memory.max"].to_i
          samples["container_spec_memory_limit_bytes"] << [labels, limit, stamp_ms]
        end
        if usage.key?("memory.swap.max")
          swap_limit = usage["memory.swap.max"].nil? ? UNLIMITED_MEMORY : usage["memory.swap.max"].to_i
          samples["container_spec_memory_swap_limit_bytes"] << [labels, swap_limit, stamp_ms]
        end
        samples["container_spec_memory_reservation_limit_bytes"] << [labels, usage["memory.low"].to_i, stamp_ms] if usage["memory.low"]
      end

      def machine_samples(samples, machine)
        samples["cadvisor_version_info"] << [{"cadvisorRevision" => "", "cadvisorVersion" => CADVISOR_VERSION, "dockerVersion" => "",
                                              "kernelVersion" => machine[:kernel_version].to_s, "osVersion" => machine[:os_version].to_s}, 1, nil]
        samples["machine_cpu_cores"] << [{}, machine[:cpu_cores]] if machine[:cpu_cores]
        samples["machine_cpu_physical_cores"] << [{}, machine[:physical_cores]] if machine[:physical_cores]
        samples["machine_cpu_sockets"] << [{}, machine[:sockets]] if machine[:sockets]
        samples["machine_memory_bytes"] << [{}, machine[:memory_bytes]] if machine[:memory_bytes]
        samples["machine_swap_bytes"] << [{}, machine[:swap_bytes]] if machine[:swap_bytes]
        samples["machine_scrape_error"] << [{}, machine[:cpu_cores] ? 0 : 1]
      end

      # The machine facts the gauges need, from /proc and the kernel.
      def machine_info(proc_root: "/proc")
        info = {cpu_cores: Etc.nprocessors}
        meminfo = File.read(File.join(proc_root, "meminfo"))
        memory = meminfo[/^MemTotal:\s+(\d+) kB/, 1]
        swap = meminfo[/^SwapTotal:\s+(\d+) kB/, 1]
        info[:memory_bytes] = Integer(memory) * 1024 if memory
        info[:swap_bytes] = Integer(swap) * 1024 if swap
        cpuinfo = File.read(File.join(proc_root, "cpuinfo"))
        sockets = cpuinfo.scan(/^physical id\s*:\s*(\d+)/).flatten.uniq
        cores = cpuinfo.scan(/^physical id\s*:\s*(\d+)\n(?:.*\n)*?core id\s*:\s*(\d+)/).uniq
        info[:sockets] = sockets.empty? ? 1 : sockets.length
        info[:physical_cores] = cores.empty? ? info[:cpu_cores] : cores.length
        info[:kernel_version] = File.read(File.join(proc_root, "sys/kernel/osrelease")).strip
        info[:os_version] = os_version
        info
      rescue StandardError
        info
      end

      def os_version
        File.read("/etc/os-release")[/^PRETTY_NAME="?([^"\n]*)"?/, 1].to_s
      rescue SystemCallError
        ""
      end

      # The Summary-based rendering (cpu, memory, rootfs) for callers
      # without runtime access.
      SUMMARY_DESCRIPTORS = CONTAINER_FAMILIES.to_h { |name, type, help| [name, [type, help]] }.slice(
        "container_cpu_usage_seconds_total", "container_memory_usage_bytes", "container_memory_working_set_bytes",
        "container_memory_rss", "container_memory_failures_total", "container_fs_usage_bytes",
        "container_start_time_seconds", "container_last_seen"
      ).freeze

      def render_summary(summary, machine: {}, images: {})
        samples = Hash.new { |hash, key| hash[key] = [] }
        samples["machine_cpu_cores"] << [{}, machine[:cpu_cores]] if machine[:cpu_cores]
        samples["machine_memory_bytes"] << [{}, machine[:memory_bytes]] if machine[:memory_bytes]
        stamp = Time.now.to_f
        Array(summary["pods"]).each do |pod|
          ref = pod["podRef"] || {}
          pod_labels = {"namespace" => ref["namespace"].to_s, "pod" => ref["name"].to_s}
          pod_id = "/kubepods/pod#{ref["uid"]}"
          add_summary_entry(samples, pod, {"container" => "", "id" => pod_id, "image" => "", "name" => ""}.merge(pod_labels), stamp)
          Array(pod["containers"]).each do |container|
            name = container["name"].to_s
            labels = {"container" => name, "id" => "#{pod_id}/#{name}", "image" => images.fetch([ref["uid"].to_s, name], "").to_s,
                      "name" => name}.merge(pod_labels)
            add_summary_entry(samples, container, labels, stamp)
            started = ResourceMetrics.parse_time(container["startTime"])
            samples["container_start_time_seconds"] << [labels, started.to_f] if started
            rootfs = container["rootfs"]
            if rootfs.is_a?(Hash) && rootfs["usedBytes"]
              samples["container_fs_usage_bytes"] << [labels.merge("device" => "rootfs"), rootfs["usedBytes"].to_i]
            end
          end
        end
        DESCRIPTORS.filter_map do |name, type, help|
          lines = samples[name]
          next if lines.empty?

          "# HELP #{name} #{help}\n# TYPE #{name} #{type}\n" +
            lines.map { |labels, value| ResourceMetrics.sample(name, labels.sort.to_h, value, nil) }.join
        end.join
      end

      def add_entry(samples, entry, labels, stamp)
        cpu = entry["cpu"]
        if cpu.is_a?(Hash) && cpu["usageCoreNanoSeconds"]
          samples["container_cpu_usage_seconds_total"] << [labels.merge("cpu" => "total"), cpu["usageCoreNanoSeconds"].to_f / 1e9]
        end
        memory = entry["memory"]
        if memory.is_a?(Hash)
          samples["container_memory_usage_bytes"] << [labels, memory["usageBytes"].to_i] if memory["usageBytes"]
          samples["container_memory_working_set_bytes"] << [labels, memory["workingSetBytes"].to_i] if memory["workingSetBytes"]
          samples["container_memory_rss"] << [labels, memory["rssBytes"].to_i] if memory["rssBytes"]
          if memory["pageFaults"]
            samples["container_memory_failures_total"] << [labels.merge("failure_type" => "pgfault", "scope" => "container"), memory["pageFaults"].to_i]
          end
          if memory["majorPageFaults"]
            samples["container_memory_failures_total"] << [labels.merge("failure_type" => "pgmajfault", "scope" => "container"), memory["majorPageFaults"].to_i]
          end
        end
        samples["container_last_seen"] << [labels, stamp.floor]
      end
    end
  end
end
