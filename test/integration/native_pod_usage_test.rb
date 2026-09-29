# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"
require "tmpdir"
require "time"
require_relative "../test_helper"
require "rubernetes/runtime/native"
require "rubernetes/platform/linux/native_adapters"
require "rubernetes/node/stats_provider"
require "rubernetes/node/resource_metrics"

# Runtime::Native#pod_usage reads the Pod's and each container's cgroup
# accounting through the production CgroupAdapter; /stats/summary,
# /metrics/resource and metrics.k8s.io are built from it.  The adapter did
# not forward #usage, so every Pod's CPU and memory were absent from all
# three (kubectl top showed nothing) while the cgroup files were right there.
class NativePodUsageTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux

  def test_pod_usage_flows_from_the_cgroups_to_the_summary_and_resource_metrics
    skip "needs root and a cgroup v2 root" unless Process.euid.zero? && File.writable?("/sys/fs/cgroup/cgroup.procs")

    Dir.mktmpdir("rubernetes-pod-usage-") do |directory|
      lower = File.join(directory, "lower")
      FileUtils.mkdir_p(File.join(lower, "bin"))
      FileUtils.cp("/usr/bin/busybox", File.join(lower, "bin", "busybox"), preserve: true)
      sandbox_root = File.join(directory, "sandboxes")
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true,
        adapters: Linux::NativeAdapters.for_profile(profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup"),
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup", log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      sandbox_id = "usage-#{Process.pid}-#{SecureRandom.hex(3)}"
      sandbox = runtime.run_sandbox({"id" => sandbox_id, "image_bytes" => "img", "image_digest" => "sha256:#{Digest::SHA256.hexdigest("img")}",
                                     "lowerdirs" => [lower]}, request_id: sandbox_id)
      begin
        container = runtime.create_container(sandbox, {"id" => "app", "name" => "app", "rootfs_path" => lower,
                                                       "command" => ["/bin/busybox", "sh", "-c", "i=0; while true; do i=$((i+1)); done"]})
        runtime.start_container(container)
        sleep 1.0

        usage = runtime.pod_usage(sandbox_id)
        refute_nil usage, "pod_usage returned nil"
        assert_operator usage.dig("pod", "cpu", "usage_usec").to_i, :>, 0, usage.inspect
        assert_operator usage.dig("pod", "memory.current").to_i, :>, 0
        assert_equal ["app"], usage["containers"].map { |c| c["name"] }
        assert_operator usage["containers"][0].dig("usage", "cpu", "usage_usec").to_i, :>, 0

        lifecycle = Object.new
        record = {state: "Running", sandbox_id: sandbox_id, uid: "u1", pod: {"metadata" => {"name" => "p", "namespace" => "ns"}},
                  started_at: Time.now.utc.iso8601, containers: [{id: "app", name: "app", started_at: Time.now.utc.iso8601}], volume: {}}
        lifecycle.define_singleton_method(:stats_records) { [record] }
        provider = Rubernetes::Node::StatsProvider.new(node_name: "n", lifecycle: lifecycle, runtime: runtime, pod_root: directory)
        summary = provider.summary
        pod = summary["pods"].first
        assert_operator pod.dig("cpu", "usageCoreNanoSeconds").to_i, :>, 0, pod.inspect
        assert_operator pod.dig("memory", "workingSetBytes").to_i, :>, 0
        assert_equal "app", pod.dig("containers", 0, "name")
        assert_operator pod.dig("containers", 0, "memory", "usageBytes").to_i, :>, 0

        text = Rubernetes::Node::ResourceMetrics.render(summary)
        assert_match(/^container_cpu_usage_seconds_total\{container="app",namespace="ns",pod="p"\} \d/, text)
        assert_match(/^pod_memory_working_set_bytes\{namespace="ns",pod="p"\} \d/, text)
      ensure
        begin
          runtime.stop_sandbox(sandbox, timeout: 1) if runtime.sandboxes.any?
          runtime.remove_sandbox(sandbox) if runtime.sandboxes.any?
        rescue StandardError
          nil
        end
      end
    end
  end
end
