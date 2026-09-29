# frozen_string_literal: true

# Shared harness extracted from unit/node_stats_summary_test.rb; included by that
# test and by the tests that used to subclass it (a test file must not require
# another test file: its tests would run under both classes).
require "rubernetes/node"
require "fileutils"
require "json"
require "tmpdir"

module NodeStatsSummaryHarness
  MI = 1024**2

  class Lifecycle
    attr_reader :records

    def initialize(records) = @records = records
  end

  class Runtime
    attr_accessor :usage

    def initialize(usage) = @usage = usage
    def pod_usage(_sandbox_id) = @usage
  end

  Request = Struct.new(:path, :method, :query) do
    def query_value(name) = (query || {})[name]
  end

  def setup
    @dir = Dir.mktmpdir("stats-summary")
    @cgroup = File.join(@dir, "cgroup")
    @proc = File.join(@dir, "proc")
    FileUtils.mkdir_p([@cgroup, File.join(@proc, "sys/kernel"), File.join(@proc, "1"), File.join(@proc, "42"), File.join(@proc, "self")])
    File.write(File.join(@cgroup, "memory.stat"), "anon #{300 * MI}\nfile #{200 * MI}\ninactive_file #{100 * MI}\npgfault 7\npgmajfault 1\n")
    File.write(File.join(@cgroup, "cpu.stat"), "usage_usec 2000000\nuser_usec 1\n")
    File.write(File.join(@proc, "meminfo"), "MemTotal:        2097152 kB\nMemFree: 1 kB\n")
    File.write(File.join(@proc, "stat"), "cpu 1 2 3\nbtime 1767225600\n")
    File.write(File.join(@proc, "sys/kernel/pid_max"), "32768\n")
    @rootfs = File.join(@dir, "upper")
    @logs = File.join(@dir, "logs")
    @volume = File.join(@dir, "vol")
    FileUtils.mkdir_p([@rootfs, @logs, @volume])
    File.write(File.join(@rootfs, "a"), "x" * 8192)
    File.write(File.join(@logs, "0.log"), "y" * 4096)
    File.write(File.join(@volume, "data"), "z" * 4096)
    @mono = 100.0
  end

  def teardown
    FileUtils.rm_rf(@dir)
  end

  def usage(cpu_usec:)
    {"pod" => {"cpu" => {"usage_usec" => cpu_usec}, "memory" => {"inactive_file" => 10 * MI, "anon" => 40 * MI},
               "memory.current" => 50 * MI, "pids.current" => 3},
     "containers" => [{"id" => "c1", "name" => "app",
                       "usage" => {"cpu" => {"usage_usec" => cpu_usec}, "memory" => {"inactive_file" => 5 * MI, "anon" => 30 * MI},
                                   "memory.current" => 40 * MI},
                       "rootfs" => @rootfs, "logs" => @logs}]}
  end

  def records
    pod = {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1"},
           "spec" => {"volumes" => [{"name" => "scratch", "emptyDir" => {}}, {"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}],
                      "containers" => [{"name" => "app"}]}}
    {"u1" => {uid: "u1", state: "Running", sandbox_id: "s1", pod: pod, started_at: "2026-01-01T00:00:00Z",
              containers: [{id: "c1", name: "app", started_at: "2026-01-01T00:00:01Z"}],
              volume: {"mounts" => {"scratch" => {"path" => @volume}, "data" => {"path" => @volume}}}},
     "u2" => {uid: "u2", state: "Removed", sandbox_id: "s2", pod: {"metadata" => {"name" => "gone"}}, containers: []}}
  end

  def provider(runtime)
    Rubernetes::Node::StatsProvider.new(node_name: "node-a", lifecycle: Lifecycle.new(records), runtime: runtime, pod_root: @dir,
                                        cgroup_root: @cgroup, proc_root: @proc, allocatable_memory: 1024 * MI,
                                        clock: -> { Time.utc(2026, 1, 1, 0, 1) }, monotonic: -> { @mono })
  end

  # expfmt writes every sample as a float64 ("4.194304e+08").
  def go_float(value) = Rubernetes::Observability::Metrics.go_float(value.to_f)
end
