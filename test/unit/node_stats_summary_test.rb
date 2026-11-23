# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/node_stats_summary_harness"
require "rubernetes/node"
require "fileutils"
require "json"
require "tmpdir"

# The Summary API (/stats/summary) computed the way the kubelet's
# cadvisor-backed provider computes it on cgroup v2, and /metrics/resource
# (collectors/resource_metrics.go) rendered from it.  Both used to be stubs:
# /stats/summary had no Pods and /metrics/resource no samples, so
# metrics-server, `kubectl top` and HPA had nothing to read, and the eviction
# manager had no signals.
class NodeStatsSummaryTest < Minitest::Test
  include NodeStatsSummaryHarness

  def test_summary_follows_the_cadvisor_semantics
    runtime = Runtime.new(usage(cpu_usec: 1_000_000))
    subject = provider(runtime)
    subject.sample_volume_stats
    subject.summary
    runtime.usage = usage(cpu_usec: 3_500_000)
    @mono += 10.0
    summary = subject.summary

    node = summary.fetch("node")

    assert_equal "node-a", node["nodeName"]
    assert_equal "2026-01-01T00:00:00Z", node["startTime"]
    assert_equal 2_000_000_000, node.dig("cpu", "usageCoreNanoSeconds")
    assert_equal 500 * MI, node.dig("memory", "usageBytes"), "anon + file of the root memory.stat"
    assert_equal 400 * MI, node.dig("memory", "workingSetBytes"), "usage - inactive_file"
    assert_equal (2048 * MI) - (400 * MI), node.dig("memory", "availableBytes"), "capacity - workingSet"
    assert_equal({"time" => "2026-01-01T00:01:00Z", "maxpid" => 32_768, "curproc" => 2}, node["rlimit"])
    pods_container = node.fetch("systemContainers").find { |entry| entry["name"] == "pods" }

    assert_equal 40 * MI, pods_container.dig("memory", "workingSetBytes")
    assert_equal (1024 * MI) - (40 * MI), pods_container.dig("memory", "availableBytes")

    pods = summary.fetch("pods")

    assert_equal 1, pods.length, "only running Pods are reported"
    pod = pods.first

    assert_equal({"name" => "web", "namespace" => "ns", "uid" => "u1"}, pod["podRef"])
    assert_equal 250_000_000, pod.dig("cpu", "usageNanoCores"), "rate over the 10s between samples"
    assert_equal 50 * MI, pod.dig("memory", "usageBytes")
    assert_equal 40 * MI, pod.dig("memory", "workingSetBytes")
    assert_equal({"process_count" => 3}, pod["process_stats"])
    container = pod.fetch("containers").first

    assert_equal "app", container["name"]
    assert_equal "2026-01-01T00:00:01Z", container["startTime"]
    assert_equal 35 * MI, container.dig("memory", "workingSetBytes")
    assert_operator container.dig("rootfs", "usedBytes"), :>=, 8192
    assert_operator container.dig("logs", "usedBytes"), :>=, 4096
    volumes = pod.fetch("volume").to_h { |volume| [volume["name"], volume] }

    assert_equal({"name" => "claim", "namespace" => "ns"}, volumes.fetch("data")["pvcRef"])
    refute volumes.fetch("scratch").key?("pvcRef")
    ephemeral = pod.fetch("ephemeral-storage")

    assert_equal container.dig("rootfs", "usedBytes") + container.dig("logs", "usedBytes") + volumes.fetch("scratch")["usedBytes"],
                 ephemeral["usedBytes"], "rootfs + logs + ephemeral volumes, not the PVC"
  end

  def test_container_filesystem_usage_counts_a_hardlinked_file_once
    data = File.join(@rootfs, "a")
    File.link(data, File.join(@rootfs, "second-name"))
    sparse = File.join(@rootfs, "sparse")
    File.open(sparse, "w") { |file| file.truncate(4 * MI) }
    expected = [@rootfs, data, sparse].sum { |path| File.lstat(path).blocks * 512 }

    summary = provider(Runtime.new(usage(cpu_usec: 1_000_000))).summary
    rootfs = summary.dig("pods", 0, "containers", 0, "rootfs")

    assert_equal [expected, 3], rootfs.values_at("usedBytes", "inodesUsed")
    assert_equal [expected, 3], Rubernetes::Node::CadvisorMetrics.directory_usage(@rootfs)
  end

  def test_rapid_summary_reads_keep_the_measured_cpu_rate
    runtime = Runtime.new(usage(cpu_usec: 1_000_000))
    subject = provider(runtime)
    first = subject.summary.dig("pods", 0, "cpu")

    assert_nil first["usageNanoCores"]

    @mono += 10
    runtime.usage = usage(cpu_usec: 1_250_000)
    sample = subject.summary.dig("pods", 0, "cpu")

    assert_equal 25_000_000, sample.fetch("usageNanoCores")

    @mono += 0.01
    repeat = subject.summary.dig("pods", 0, "cpu")

    assert_equal sample, repeat

    @mono += 11

    assert_equal sample, subject.summary.dig("pods", 0, "cpu"), "a short idle interval keeps the last rate"

    @mono += 4

    assert_equal 0, subject.summary.dig("pods", 0, "cpu", "usageNanoCores"), "an idle cgroup settles to zero"

    runtime.usage = usage(cpu_usec: 10_000)
    reset = subject.summary.dig("pods", 0, "cpu")

    assert_nil reset["usageNanoCores"]
    assert_equal 10_000_000, reset.fetch("usageCoreNanoSeconds")
  end

  def test_disappearing_writable_layer_does_not_discard_other_pod_metrics
    sample = usage(cpu_usec: 1_000_000)
    subject = provider(Runtime.new(sample))
    scan = subject.method(:directory_usage)
    removed = @rootfs
    lookup = lambda do |path|
      raise Errno::ENOENT, path if path == removed

      scan.call(path)
    end
    subject.define_singleton_method(:directory_usage, &lookup)
    container = subject.summary.dig("pods", 0, "containers", 0)

    refute container.key?("rootfs")
    assert_operator container.dig("logs", "usedBytes"), :>, 0
    text = Rubernetes::Node::CadvisorMetrics.render([[records.fetch("u1"), sample]], disk_usage: lookup)

    assert_includes text, "container_scrape_error 0"
    refute_match(/^container_fs_usage_bytes\{[^}]*container="app"/, text)
  end

  def test_summary_observes_shared_and_split_runtime_filesystems
    skip "no separate tmpfs for filesystem statistics" unless File.directory?("/dev/shm") && File.stat("/dev/shm").dev != File.stat("/").dev

    Dir.mktmpdir("stats-filesystems", "/dev/shm") do |runtime_root|
      # The image cache is created on first use. Its mount is identifiable
      # from its existing parent before the first Pod is admitted.
      image_root = File.join(runtime_root, "not-yet-created")
      data = usage(cpu_usec: 1_000_000)
      data.dig("containers", 0)["rootfs"] = runtime_root
      options = {node_name: "node-a", lifecycle: Lifecycle.new(records), runtime: Runtime.new(data), pod_root: "/", image_root: image_root}
      combined = Rubernetes::Node::StatsProvider.new(**options, container_root: runtime_root)
      summary = combined.summary
      node = summary.fetch("node")
      image = node.dig("runtime", "imageFs")
      container = node.dig("runtime", "containerFs")

      assert_predicate combined, :dedicated_image_fs?
      refute_predicate combined, :split_container_fs?
      statfs = Rubernetes::Platform::Linux::Statfs

      assert_equal statfs.statfs("/").capacity_bytes, node.dig("fs", "capacityBytes")
      assert_equal statfs.statfs(runtime_root).capacity_bytes, image.fetch("capacityBytes")
      assert_equal image.values_at("capacityBytes", "inodes"), container.values_at("capacityBytes", "inodes")
      assert_equal image.fetch("capacityBytes"), combined.image_fs_stats.fetch("capacityBytes")
      assert_equal container.fetch("capacityBytes"), summary.dig("pods", 0, "containers", 0, "rootfs", "capacityBytes")

      split = Rubernetes::Node::StatsProvider.new(**options, container_root: "/")
      node = split.summary.fetch("node")

      assert_predicate split, :dedicated_image_fs?
      assert_predicate split, :split_container_fs?
      assert_equal node.dig("fs", "capacityBytes"), node.dig("runtime", "containerFs", "capacityBytes")
      assert_equal image.fetch("capacityBytes"), node.dig("runtime", "imageFs", "capacityBytes")
    end
  end

  def test_only_kubelet_managed_disk_volumes_contribute_to_pod_ephemeral_storage
    pods = records
    record = pods.fetch("u1")
    sources = {"ram" => {"emptyDir" => {"medium" => "Memory"}}, "huge" => {"emptyDir" => {"medium" => "HugePages-2Mi"}},
               "config" => {"configMap" => {}}, "projected" => {"projected" => {}}, "secret" => {"secret" => {}},
               "host" => {"hostPath" => {"path" => @volume}}, "auto" => {"ephemeral" => {"volumeClaimTemplate" => {}}}}
    sources.each do |name, source|
      record.dig(:pod, "spec", "volumes") << source.merge("name" => name)
      record.dig(:volume, "mounts")[name] = {"path" => @volume}
    end
    subject = Rubernetes::Node::StatsProvider.new(node_name: "node-a", lifecycle: Lifecycle.new(pods), runtime: Runtime.new(nil), pod_root: @dir)
    subject.sample_volume_stats
    pod = subject.summary.fetch("pods").first
    volumes = pod.fetch("volume").to_h { |volume| [volume.fetch("name"), volume] }

    assert_equal %w[auto config data huge projected ram scratch secret], volumes.keys.sort
    assert_equal({"name" => "web-auto", "namespace" => "ns"}, volumes.fetch("auto").fetch("pvcRef"))
    %w[usedBytes inodesUsed].each do |field|
      assert_equal volumes.fetch("scratch").fetch(field) + volumes.fetch("config").fetch(field), pod.fetch("ephemeral-storage").fetch(field)
    end
  end

  def test_resource_metrics_render_the_summary
    runtime = Runtime.new(usage(cpu_usec: 1_000_000))
    body = Rubernetes::Node::ResourceMetrics.render(provider(runtime).summary)

    assert_includes body, "# HELP node_cpu_usage_seconds_total [STABLE] Cumulative cpu time consumed by the node in core-seconds\n" \
                          "# TYPE node_cpu_usage_seconds_total counter\nnode_cpu_usage_seconds_total 2 1767225660000\n"
    assert_includes body, "node_memory_working_set_bytes #{go_float(400 * MI)} 1767225660000\n"
    assert_includes body, "container_cpu_usage_seconds_total{container=\"app\",namespace=\"ns\",pod=\"web\"} 1 1767225660000\n"
    assert_includes body,
                    "container_memory_working_set_bytes{container=\"app\",namespace=\"ns\",pod=\"web\"} #{go_float(35 * MI)} 1767225660000\n"
    assert_includes body, "container_start_time_seconds{container=\"app\",namespace=\"ns\",pod=\"web\"} 1.767225601e+09 1767225601000\n"
    assert_includes body, "pod_memory_working_set_bytes{namespace=\"ns\",pod=\"web\"} #{go_float(40 * MI)} 1767225660000\n"
    assert_includes body, "resource_scrape_error 0\n"
    assert_includes Rubernetes::Node::ResourceMetrics.render({"node" => {}, "pods" => []}, scrape_error: true), "resource_scrape_error 1\n"
  end

  def test_ephemeral_usage_includes_managed_hosts_and_cri_logs_once
    pods = records
    hosts = File.join(@dir, "hosts")
    File.write(hosts, "h" * 8192)
    pods.fetch("u1")[:hosts_file] = hosts
    log_root = File.join(@dir, "pod-logs")
    owner = File.join(log_root, "ns_web_u1")
    app = File.join(owner, "app")
    FileUtils.mkdir_p(File.join(app, "archive"))
    [File.join(owner, "pod.log"), File.join(app, "0.log"), File.join(app, "archive", "unrelated")].each do |path|
      File.write(path, "l" * 8192)
    end
    usage = {"logs_root" => log_root, "containers" => [{"id" => "c1", "name" => "app"}]}
    subject = Rubernetes::Node::StatsProvider.new(node_name: "node-a", lifecycle: Lifecycle.new(pods), runtime: Runtime.new(usage), pod_root: @dir)
    subject.sample_volume_stats
    pod = subject.summary.fetch("pods").first
    scratch = pod.fetch("volume").find { |volume| volume["name"] == "scratch" }
    files = [hosts, File.join(owner, "pod.log"), File.join(app, "0.log")]

    assert_equal [File.stat(files.last).blocks * 512, 1], pod.dig("containers", 0, "logs").values_at("usedBytes", "inodesUsed")
    assert_equal files.sum { |path| File.stat(path).blocks * 512 } + scratch["usedBytes"], pod.dig("ephemeral-storage", "usedBytes")
    assert_equal 3 + scratch["inodesUsed"], pod.dig("ephemeral-storage", "inodesUsed")
  end

  def test_summary_reads_kernel_pressure_interface_counters_and_memory_limits
    sample = "some avg10=1.25 avg60=0.75 avg300=0.25 total=300\nfull avg10=0.25 avg60=0.10 avg300=0.01 total=20\n"
    directories = [File.join(@proc, "pressure"), File.join(@cgroup, "pod", "app"), File.join(@proc, "42", "net")]
    FileUtils.mkdir_p(directories)
    File.write(File.join(@proc, "pressure", "io"), sample)
    File.write(File.join(@cgroup, "pod", "io.pressure"), sample)
    File.write(File.join(@cgroup, "pod", "app", "cpu.pressure"), sample)
    File.write(File.join(@proc, "42", "net", "dev"), "  eth0: 123 3 2 0 0 0 0 0 456 4 1 0 0 0 0 0\n")
    File.write(File.join(@proc, "self", "cgroup"), "0::/kubelet.service\n")
    kubelet_cgroup = File.join(@cgroup, "kubelet.service")
    FileUtils.mkdir_p(kubelet_cgroup)
    File.write(File.join(kubelet_cgroup, "cpu.stat"), "usage_usec 1000000\n")
    measurement = usage(cpu_usec: 1_000_000)
    measurement["netns_pid"] = 42
    measurement["pod"].merge!("path" => "/pod", "memory.max" => 80 * MI)
    measurement.dig("containers", 0, "usage").merge!("path" => "/pod/app", "memory.max" => 60 * MI)

    summary = provider(Runtime.new(measurement)).summary
    pod = summary.fetch("pods").first
    container = pod.fetch("containers").first

    assert_equal 300_000, summary.dig("node", "io", "psi", "some", "total")
    assert_in_delta 1.25, pod.dig("io", "psi", "some", "avg10")
    assert_equal 20_000, container.dig("cpu", "psi", "full", "total")
    assert_equal [123, 2, 456, 1], pod.fetch("network").values_at("rxBytes", "rxErrors", "txBytes", "txErrors")
    assert_equal 40 * MI, pod.dig("memory", "availableBytes")
    assert_equal 25 * MI, container.dig("memory", "availableBytes")
    kubelet = summary.dig("node", "systemContainers").find { |entry| entry["name"] == "kubelet" }

    assert_equal 1_000_000_000, kubelet.dig("cpu", "usageCoreNanoSeconds")
  end

  def test_streaming_server_serves_summary_and_resource_metrics
    stats = provider(Runtime.new(usage(cpu_usec: 1_000_000)))
    server = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new(records), stats_provider: stats)
    status, headers, body = server.call(Request.new("/stats/summary", "GET", {}))

    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    full = JSON.parse(body.join)

    assert full.dig("node", "fs")
    status, _headers, body = server.call(Request.new("/stats/summary", "GET", {"only_cpu_and_memory" => "true"}))

    assert_equal 200, status
    trimmed = JSON.parse(body.join)

    assert_equal %w[cpu memory nodeName startTime systemContainers], trimmed["node"].keys.sort
    assert_equal %w[memory name startTime], trimmed.dig("node", "systemContainers", 0).keys.sort
    assert_equal %w[containers cpu memory podRef startTime], trimmed["pods"].first.keys.sort
    assert_equal %w[cpu memory name startTime], trimmed["pods"].first["containers"].first.keys.sort

    status, _headers, body = server.call(Request.new("/metrics/resource", "GET", {}))

    assert_equal 200, status
    assert_includes body.join, "pod_cpu_usage_seconds_total{namespace=\"ns\",pod=\"web\"} 1 "

    bare = Rubernetes::Node::StreamingServer.new(log_service: Object.new, lifecycle: Lifecycle.new({}))

    assert_equal 404, bare.call(Request.new("/stats/summary", "GET", {})).first
  end

  def test_summary_reads_pressure_from_the_runtime_owned_cgroup_root
    cri_root = File.join(@dir, "cri-cgroup")
    directory = File.join(cri_root, "pod")
    FileUtils.mkdir_p(directory)
    File.write(File.join(directory, "memory.pressure"), "full avg10=1.25 avg60=0.75 avg300=0.25 total=300\n")
    measurement = usage(cpu_usec: 1_000_000)
    measurement.fetch("pod").merge!("path" => "/pod", "cgroup_root" => cri_root)

    pressure = provider(Runtime.new(measurement)).summary.dig("pods", 0, "memory", "psi", "full")

    assert_equal 300_000, pressure.fetch("total")
    assert_in_delta 1.25, pressure.fetch("avg10")
  end

  def test_system_container_metrics_use_real_cgroup_observations
    namespace = Rubernetes::Platform::Linux::NativeAdapters::NamespaceAdapter.new(supervisor_cgroup_root: @cgroup)
    runtime = Rubernetes::Runtime::Native.new(profile: :pure, cgroup_root: @cgroup, namespace_adapter: namespace)
    setup_system_cgroup("rubernetes-supervisors", usage_usec: 230_000)
    setup_system_cgroup("system-daemons", usage_usec: 350_000)
    setup_system_cgroup("cri-daemon", usage_usec: 460_000)
    setup_system_cgroup("worker-agent", usage_usec: 1_750_000)

    summary = provider(runtime, system_cgroups: {"kubelet" => "/worker-agent", "misc" => "/system-daemons"}).summary
    groups = summary.dig("node", "systemContainers").to_h { |entry| [entry.fetch("name"), entry] }

    assert_equal 230_000_000, groups.dig("runtime", "cpu", "usageCoreNanoSeconds")
    assert_equal 350_000_000, groups.dig("misc", "cpu", "usageCoreNanoSeconds")
    assert_equal 1_750_000_000, groups.dig("kubelet", "cpu", "usageCoreNanoSeconds")
    assert_equal 10 * MI, groups.dig("runtime", "memory", "workingSetBytes")
    assert_nil groups.dig("runtime", "memory", "availableBytes")

    summary = provider(runtime, system_cgroups: {"runtime" => "/cri-daemon"}).summary
    groups = summary.dig("node", "systemContainers").to_h { |entry| [entry.fetch("name"), entry] }

    assert_equal 460_000_000, groups.dig("runtime", "cpu", "usageCoreNanoSeconds")
    assert_equal %w[pods runtime], groups.keys.sort
  end

  private

  def setup_system_cgroup(name, usage_usec:)
    path = File.join(@cgroup, name)
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "cpu.stat"), "usage_usec #{usage_usec}\n")
    File.write(File.join(path, "memory.stat"), "anon #{10 * MI}\ninactive_file #{2 * MI}\n")
    File.write(File.join(path, "memory.current"), (12 * MI).to_s)
  end
end
