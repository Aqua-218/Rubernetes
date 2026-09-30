# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/node/resource_metrics"

# /metrics/cadvisor rendered from cgroup v2 accounting: cAdvisor's names,
# labels, timestamps and unit conversions.
class CadvisorMetricsTest < Minitest::Test
  Cadvisor = Rubernetes::Node::CadvisorMetrics

  def usage(path:, cpu_usec: 1_500_000, current: 50_000_000, procs: [])
    {"cpu" => {"usage_usec" => cpu_usec, "user_usec" => 1_000_000, "system_usec" => 500_000, "nr_periods" => 10, "nr_throttled" => 2, "throttled_usec" => 250_000},
     "memory" => {"anon" => 30_000_000, "file" => 20_000_000, "kernel" => 1_000_000, "file_mapped" => 4_000_000, "inactive_file" => 10_000_000,
                  "pgfault" => 700, "pgmajfault" => 3},
     "memory.current" => current, "memory.max" => 100_000_000, "memory.low" => 0, "memory.peak" => 60_000_000,
     "memory.swap.current" => 0, "memory.swap.max" => 0, "memory.events" => {"max" => 4, "oom_kill" => 1},
     "pids.current" => procs.length, "pids.max" => 512, "cpu.weight" => 39, "cpu.max" => %w[50000 100000],
     "io.stat" => {"259:0" => {"rbytes" => 4096, "wbytes" => 8192, "rios" => 1, "wios" => 2}},
     "cgroup.procs" => procs, "path" => path}
  end

  def with_fake_proc
    Dir.mktmpdir do |root|
      proc_root = File.join(root, "proc")
      pid_dir = File.join(proc_root, "4242")
      FileUtils.mkdir_p(File.join(pid_dir, "fd"))
      File.write(File.join(pid_dir, "stat"),
                 "4242 (nginx) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 100 1000 200 18446744073709551615\n")
      File.write(File.join(pid_dir, "status"), "Name:\tnginx\nThreads:\t3\n")
      File.write(File.join(pid_dir, "limits"),
                 "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1048576              1048576              files\n")
      File.symlink("socket:[12345]", File.join(pid_dir, "fd", "3"))
      File.symlink("/dev/null", File.join(pid_dir, "fd", "0"))
      FileUtils.mkdir_p(File.join(proc_root, "777", "net"))
      File.write(File.join(proc_root, "777", "net", "dev"), <<~DEV)
        Inter-|   Receive                                                |  Transmit
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
            lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
          eth0:  123456     789    1    2    0     0          0         0   654321     987    3    4    0     0       0          0
      DEV
      sys_root = File.join(root, "sys")
      FileUtils.mkdir_p(File.join(sys_root, "dev", "block"))
      File.symlink("../../devices/pci0000:00/nvme0n1", File.join(sys_root, "dev", "block", "259:0"))
      yield proc_root, sys_root
    end
  end

  def value(text, name, **labels)
    found = text.lines.map(&:chomp).find do |entry|
      entry.start_with?("#{name}{", "#{name} ") && labels.all? { |key, item| entry.include?("#{key}=\"#{item}\"") }
    end
    found && found.split[1].to_f
  end

  def test_renders_cadvisor_families_from_cgroup_accounting
    record = {pod: {"metadata" => {"name" => "web-1", "namespace" => "shop", "uid" => "u1"}}, uid: "u1",
              started_at: "2026-09-29T10:00:00Z", containers: [{id: "c-abc", started_at: "2026-09-29T10:00:05Z"}]}
    pod_usage = {"pod" => usage(path: "/kubepods/burstable/podu1", cpu_usec: 2_000_000, current: 80_000_000),
                 "containers" => [{"id" => "c-abc", "name" => "nginx", "image" => "nginx:1.27",
                                   "usage" => usage(path: "/kubepods/burstable/podu1/c-abc", procs: [4242])}],
                 "netns_pid" => 777}
    now = Time.at(1_790_000_000).utc
    text = with_fake_proc do |proc_root, sys_root|
      Cadvisor.render([[record, pod_usage]], machine: {cpu_cores: 8, physical_cores: 4, sockets: 1, memory_bytes: 16_000_000_000, swap_bytes: 0,
                                                       kernel_version: "7.0.0", os_version: "Test OS"},
                                             now: now, proc_root: proc_root, sys_root: sys_root)
    end
    labels = {container: "nginx", id: "/kubepods/burstable/podu1/c-abc", image: "nginx:1.27", name: "c-abc", namespace: "shop",
              pod: "web-1"}

    assert_in_delta(1.5, value(text, "container_cpu_usage_seconds_total", cpu: "total", **labels))
    assert_in_delta(1.0, value(text, "container_cpu_user_seconds_total", **labels))
    assert_in_delta(2.0, value(text, "container_cpu_cfs_throttled_periods_total", **labels))
    assert_in_delta(0.25, value(text, "container_cpu_cfs_throttled_seconds_total", **labels))
    assert_in_delta(50_000_000.0, value(text, "container_memory_usage_bytes", **labels))
    assert_in_delta(40_000_000.0, value(text, "container_memory_working_set_bytes", **labels))
    assert_in_delta(30_000_000.0, value(text, "container_memory_rss", **labels))
    assert_in_delta(20_000_000.0, value(text, "container_memory_cache", **labels))
    assert_in_delta(60_000_000.0, value(text, "container_memory_max_usage_bytes", **labels))
    assert_in_delta(4.0, value(text, "container_memory_failcnt", **labels))
    assert_in_delta(1.0, value(text, "container_oom_events_total", **labels))
    assert_in_delta(700.0, value(text, "container_memory_failures_total", failure_type: "pgfault", scope: "container", **labels))
    assert_in_delta(3.0, value(text, "container_memory_failures_total", failure_type: "pgmajfault", scope: "hierarchy", **labels))
    # spec: cpu.max 50000/100000, cpu.weight 39 -> 1024 shares, memory.max.
    assert_in_delta(100_000.0, value(text, "container_spec_cpu_period", **labels))
    assert_in_delta(50_000.0, value(text, "container_spec_cpu_quota", **labels))
    assert_in_delta(998.0, value(text, "container_spec_cpu_shares", **labels))
    assert_in_delta(100_000_000.0, value(text, "container_spec_memory_limit_bytes", **labels))
    # io.stat by device name through /sys/dev/block.
    assert_in_delta(4096.0, value(text, "container_fs_reads_bytes_total", device: "/dev/nvme0n1", **labels))
    assert_in_delta(8192.0, value(text, "container_blkio_device_usage_total", device: "/dev/nvme0n1", major: "259", minor: "0", operation: "Write",
                                                                              **labels))
    # processes from cgroup.procs and /proc.
    assert_in_delta(1.0, value(text, "container_processes", **labels))
    assert_in_delta(3.0, value(text, "container_threads", **labels))
    assert_in_delta(512.0, value(text, "container_threads_max", **labels))
    assert_in_delta(2.0, value(text, "container_file_descriptors", **labels))
    assert_in_delta(1.0, value(text, "container_sockets", **labels))
    assert_in_delta(1.0, value(text, "container_tasks_state", state: "sleeping", **labels))
    assert_in_delta(0.0, value(text, "container_tasks_state", state: "running", **labels))
    assert_in_delta(1_048_576.0, value(text, "container_ulimits_soft", ulimit: "max_open_files", **labels))
    assert_equal Time.utc(2026, 9, 29, 10, 0, 5).to_f, value(text, "container_start_time_seconds", **labels)
    # The Pod's cgroup: empty container/name/image, network from its namespace.
    pod = {container: "", id: "/kubepods/burstable/podu1", image: "", name: "", namespace: "shop", pod: "web-1"}

    assert_in_delta(2.0, value(text, "container_cpu_usage_seconds_total", cpu: "total", **pod))
    assert_in_delta(123_456.0, value(text, "container_network_receive_bytes_total", interface: "eth0", **pod))
    assert_in_delta(4.0, value(text, "container_network_transmit_packets_dropped_total", interface: "eth0", **pod))
    assert_nil value(text, "container_network_receive_bytes_total", interface: "lo", **pod)
    # Timestamps in milliseconds on container samples; machine gauges bare.
    assert_match(/^container_last_seen\{[^}]*container="nginx"[^}]*\} 1\.79e\+09 1790000000000$/, text)
    assert_in_delta(8.0, value(text, "machine_cpu_cores"))
    assert_in_delta(4.0, value(text, "machine_cpu_physical_cores"))
    assert_in_delta(0.0, value(text, "container_scrape_error"))
    assert_in_delta(0.0, value(text, "machine_scrape_error"))
    assert_match(
      /^cadvisor_version_info\{cadvisorRevision="",cadvisorVersion="v0\.52\.1",dockerVersion="",kernelVersion="7\.0\.0",osVersion="Test OS"\} 1$/, text
    )
    assert_includes text,
                    "# HELP container_memory_working_set_bytes Current working set in bytes.\n# TYPE container_memory_working_set_bytes gauge"
  end

  def test_summary_rendering_still_works_without_runtime_access
    summary = {"pods" => [{"podRef" => {"name" => "p", "namespace" => "n", "uid" => "u"},
                           "cpu" => {"usageCoreNanoSeconds" => 2_000_000_000},
                           "containers" => [{"name" => "c", "cpu" => {"usageCoreNanoSeconds" => 1_000_000_000},
                                             "memory" => {"workingSetBytes" => 5}}]}]}
    text = Cadvisor.render(summary, machine: {cpu_cores: 2})

    assert_in_delta(1.0, value(text, "container_cpu_usage_seconds_total", container: "c", cpu: "total"))
    assert_in_delta(5.0, value(text, "container_memory_working_set_bytes", container: "c"))
    assert_in_delta(2.0, value(text, "machine_cpu_cores"))
  end

  def test_machine_info_reads_proc
    info = Cadvisor.machine_info

    assert_operator info[:cpu_cores], :>=, 1
    assert_operator info[:memory_bytes], :>, 0
    assert_operator info[:sockets], :>=, 1
    refute_empty info[:kernel_version]
  end
end
