# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/platform/linux"
require "tmpdir"

# An exec helper is a fork of the agent; everything it did before execve ran
# inside the container's cgroup, attached right after fork.  Under a 10m CPU
# limit (cpu.max "1000 100000") that pre-exec work took 5-15 s per exec, and
# "Pod InPlace Resize" (a dozen execs per spec) ran 2-3x upstream, and even
# joining right before execve left the teardown of the forked agent's address
# space -- inside execve -- charged to the cgroup (0.7 s at 200 MB, 2.6 s at
# 800 MB).  The workload now traces itself, and the wrapper moves it into the
# cgroup at the stop after its execve: old address space gone, no
# instruction of the new program run yet.
class ExecLateCgroupJoinTest < Minitest::Test
  Connector = Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector
  CgroupV2 = Rubernetes::Platform::Linux::CgroupV2

  Container = Struct.new(:process, :spec, :cgroup, :security_plan, keyword_init: true)
  Sandbox = Struct.new(:namespace, keyword_init: true)
  WorkloadProcess = Struct.new(:workload_pid, :workload_start_time)

  class RecordingProcess
    attr_reader :spawned

    def initialize(late: true) = @late = late
    def join_cgroup_at_exec? = @late

    def spawn(**options)
      @spawned = options
      raise StopIteration
    end
  end

  class RecordingCgroup
    attr_reader :attached, :opened

    def initialize = @attached = []
    def open_procs(handle) = (@opened = handle) && IO.pipe.last
    def attach(handle, pid:) = @attached << [handle, pid]
  end

  def exec_with(process, cgroup)
    connector = Connector.allocate
    connector.instance_variable_set(:@process, process)
    connector.instance_variable_set(:@cgroup, cgroup)
    container = Container.new(process: WorkloadProcess.new(4242, "123"), spec: {"env" => {}}, cgroup: "/sys/fs/cgroup/x/c1",
                              security_plan: nil)
    connector.exec(sandbox: Sandbox.new(namespace: nil), container: container, command: %w[cat /sys/fs/cgroup/cpu.max])
  rescue StopIteration
    nil
  end

  def test_exec_hands_the_workload_a_cgroup_procs_descriptor
    process = RecordingProcess.new
    cgroup = RecordingCgroup.new
    exec_with(process, cgroup)
    assert_equal "/sys/fs/cgroup/x/c1", cgroup.opened
    assert_kind_of IO, process.spawned.fetch(:cgroup_procs)
    assert_empty cgroup.attached, "the wrapper is no longer attached to the container's cgroup"
  end

  # The production wiring, not a double: the late join was once silently
  # off because CgroupAdapter did not delegate open_procs.
  def test_the_production_adapters_take_the_late_join_path
    adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(profile: "kernel_isolation", sandbox_root: Dir.tmpdir,
                                                                         cgroup_root: "/sys/fs/cgroup")
    streams = adapters.values.find { |adapter| adapter.is_a?(Connector) }
    refute_nil streams
    assert streams.instance_variable_get(:@cgroup).respond_to?(:open_procs)
    assert streams.instance_variable_get(:@process).join_cgroup_at_exec?
  end

  def test_an_adapter_without_late_join_keeps_the_descriptor_out
    process = RecordingProcess.new(late: false)
    exec_with(process, RecordingCgroup.new)
    assert_nil process.spawned.fetch(:cgroup_procs)
  end

  Gate = Rubernetes::Platform::Linux::NativeAdapters::ProcessGateAdapter

  def with_limited_cgroup
    skip "needs root and a writable cgroup v2 root" unless Process.euid.zero? && File.writable?("/sys/fs/cgroup/cgroup.procs")

    hierarchy = "rbn-exec-stop-test-#{Process.pid}-#{rand(1 << 30)}"
    parent = File.join("/sys/fs/cgroup", hierarchy)
    Dir.mkdir(parent)
    File.write(File.join(parent, "cgroup.subtree_control"), "+cpu")
    path = File.join(parent, "c1")
    Dir.mkdir(path)
    File.write(File.join(path, "cpu.max"), "1000 100000")
    procs = CgroupV2.new(root: "/sys/fs/cgroup", hierarchy: hierarchy).open_procs(path)
    yield procs, "0::/#{hierarchy}/c1"
  ensure
    sleep 0.1
    [path, parent].each { |dir| Dir.rmdir(dir) if dir && Dir.exist?(dir) }
  end

  def traced_child(&block)
    fork do
      GC.disable
      exit!(126) if Gate::PTRACE.call(Gate::PTRACE_TRACEME, 0, nil, nil) == -1
      block.call
    end
  end

  def test_the_workload_is_moved_into_the_cgroup_at_its_exec_stop
    with_limited_cgroup do |procs, expected|
      Dir.mktmpdir do |dir|
        out = File.join(dir, "cgroup")
        # A big heap to tear down: without the exec stop this alone costs
        # seconds under 10m.
        junk = Array.new(300) { "x" * (1024 * 1024) }
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        pid = traced_child { exec("/bin/sh", "-c", "cat /proc/self/cgroup > #{out}") }
        assert_nil Gate.allocate.join_cgroup_at_exec_stop(pid, procs)
        _, status = Process.waitpid2(pid)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        assert_equal 0, status.exitstatus
        assert_equal expected, File.read(out).strip, "the new program ran inside the container's cgroup"
        assert_operator elapsed, :<, 1.5
        assert procs.closed?
        junk.clear
      end
    end
  end

  def test_a_workload_that_exits_before_exec_is_reaped
    with_limited_cgroup do |procs, _expected|
      pid = traced_child { exit!(3) }
      status = Gate.allocate.join_cgroup_at_exec_stop(pid, procs)
      assert_equal 3, status.exitstatus
    end
  end

  def test_a_signal_before_exec_is_passed_on
    with_limited_cgroup do |procs, expected|
      Dir.mktmpdir do |dir|
        out = File.join(dir, "cgroup")
        pid = traced_child do
          Signal.trap("USR1") { File.write("#{out}.usr1", "yes") }
          Process.kill("USR1", Process.pid)
          sleep 0.05
          exec("/bin/sh", "-c", "cat /proc/self/cgroup > #{out}")
        end
        assert_nil Gate.allocate.join_cgroup_at_exec_stop(pid, procs)
        Process.waitpid2(pid)
        assert_equal "yes", File.read("#{out}.usr1")
        assert_equal expected, File.read(out).strip
      end
    end
  end

  # The kernel side, for real: a descriptor the agent (root) opened lets a
  # child that has since dropped to nobody move itself with "0", and the
  # work done before the move is not charged to the throttled cgroup.
  def test_a_child_joins_through_a_descriptor_opened_before_it_dropped_privileges
    skip "needs root and a writable cgroup v2 root" unless Process.euid.zero? && File.writable?("/sys/fs/cgroup/cgroup.procs")

    hierarchy = "rbn-late-join-test-#{Process.pid}"
    parent = File.join("/sys/fs/cgroup", hierarchy)
    Dir.mkdir(parent)
    File.write(File.join(parent, "cgroup.subtree_control"), "+cpu")
    path = File.join(parent, "c1")
    Dir.mkdir(path)
    File.write(File.join(path, "cpu.max"), "1000 100000")
    cgroup = CgroupV2.new(root: "/sys/fs/cgroup", hierarchy: hierarchy)
    procs = cgroup.open_procs(path)
    reader, writer = IO.pipe
    pid = fork do
      reader.close
      Process::Sys.setresgid(65_534, 65_534, 65_534)
      Process::Sys.setresuid(65_534, 65_534, 65_534)
      # Pre-exec work, outside the limited cgroup.
      x = 0
      2_000_000.times { |i| x += i }
      pre_join_usec = (Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) * 1_000_000).to_i
      before = File.read("/proc/self/cgroup").strip
      procs.syswrite("0")
      after = File.read("/proc/self/cgroup").strip
      writer.write(JSON.generate("before" => before, "after" => after, "uid" => Process.euid,
                                 "pre_join_usec" => pre_join_usec))
      writer.close
      exit!(0)
    end
    writer.close
    procs.close
    report = JSON.parse(reader.read)
    Process.wait(pid)
    # CPU the cgroup was charged, not wall time: under host load the elapsed
    # time of even unthrottled work passed any fixed bound.  Only the few
    # steps after the join may be charged to c1, never the work before it.
    charged = File.read(File.join(path, "cpu.stat"))[/^usage_usec (\d+)/, 1].to_i
    assert_equal 65_534, report["uid"]
    refute_equal "0::/#{hierarchy}/c1", report["before"]
    assert_equal "0::/#{hierarchy}/c1", report["after"]
    assert_operator charged, :<, report["pre_join_usec"] / 2, "the pre-join work was charged to the throttled cgroup"
  ensure
    reader&.close unless reader.nil? || reader.closed?
    sleep 0.1
    [path, parent].each { |dir| Dir.rmdir(dir) if dir && Dir.exist?(dir) }
  end
end
