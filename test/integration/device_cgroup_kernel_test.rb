# frozen_string_literal: true

require "English"
require "digest"
require "fileutils"
require "securerandom"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux"
require "rubernetes/platform/linux/device_cgroup"

# The device cgroup allowlist on the real kernel: the program runc would
# load is accepted, attached to a cgroup (BPF_PROG_QUERY sees it), the
# standard devices stay usable from inside that cgroup, and a detach leaves
# nothing behind.  Positive checks only.
class DeviceCgroupKernelTest < Minitest::Test
  DeviceCgroup = Rubernetes::Platform::Linux::DeviceCgroup

  def setup
    skip "the cgroup device controller needs root" unless Process.uid.zero?
    skip "cgroup v2 hierarchy is unavailable" unless File.writable?("/sys/fs/cgroup")
  end

  def with_cgroup
    path = "/sys/fs/cgroup/rubernetes-test-devcg-#{Process.pid}-#{SecureRandom.hex(4)}"
    Dir.mkdir(path)
    yield path
  ensure
    Dir.rmdir(path) if path && File.directory?(path)
  end

  def test_default_program_loads_attaches_and_detaches
    attacher = DeviceCgroup::Attacher.new

    assert attacher.validate!
    with_cgroup do |path|
      assert_empty attacher.attached(path)
      id = attacher.attach(path, DeviceCgroup.rules_for)

      assert_equal [id], attacher.attached(path)
      fd = attacher.bpf.prog_get_fd_by_id(id)
      begin
        info = attacher.bpf.program_info(fd)

        assert_equal DeviceCgroup::PROGRAM_NAME, info.fetch(:name)
        assert_equal Rubernetes::Platform::Linux::BPF::BPF_PROG_TYPE_CGROUP_DEVICE, info.fetch(:type)
      ensure
        IO.for_fd(fd).close
      end

      # A task in the cgroup uses the devices the allowlist names.
      reader, writer = IO.pipe
      pid = fork do
        reader.close
        File.write(File.join(path, "cgroup.procs"), Process.pid.to_s)
        File.write(File::NULL, "discard")
        zero = File.binread("/dev/zero", 4)
        File.binread("/dev/urandom", 4)
        File.open("/dev/ptmx", "r+", &:fileno)
        writer.write(zero.unpack1("H*"))
        writer.close
        exit!(0)
      end
      writer.close
      output = reader.read
      Process.wait(pid)

      assert_predicate $CHILD_STATUS, :success?
      assert_equal "00000000", output

      assert_equal [id], attacher.detach(path)
      assert_empty attacher.attached(path)
    end
  end

  def test_detach_leaves_other_programs_alone_and_tolerates_a_missing_cgroup
    attacher = DeviceCgroup::Attacher.new
    with_cgroup do |path|
      ours = attacher.attach(path, DeviceCgroup.rules_for(privileged: true))
      # A program someone else attached (a different name) stays.
      instructions, license = DeviceCgroup.compile(DeviceCgroup.rules_for(privileged: true))
      foreign = attacher.bpf.load(instructions: instructions, program_type: Rubernetes::Platform::Linux::BPF::BPF_PROG_TYPE_CGROUP_DEVICE,
                                  license: license, expected_attach_type: Rubernetes::Platform::Linux::BPF::BPF_CGROUP_DEVICE, name: "other_devcg")
      begin
        File.open(path, File::RDONLY | DeviceCgroup::Attacher::O_DIRECTORY) do |directory|
          attacher.bpf.prog_attach(target_fd: directory.fileno, program: foreign, attach_type: Rubernetes::Platform::Linux::BPF::BPF_CGROUP_DEVICE,
                                   flags: Rubernetes::Platform::Linux::BPF::BPF_F_ALLOW_MULTI)
        end

        assert_equal [ours, foreign.id], attacher.attached(path)
        assert_equal [ours], attacher.detach(path)
        assert_equal [foreign.id], attacher.attached(path)
        File.open(path, File::RDONLY | DeviceCgroup::Attacher::O_DIRECTORY) do |directory|
          attacher.bpf.prog_detach(target_fd: directory.fileno, program: foreign, attach_type: Rubernetes::Platform::Linux::BPF::BPF_CGROUP_DEVICE)
        end
      ensure
        foreign.close
      end
    end

    assert_empty attacher.detach("/sys/fs/cgroup/rubernetes-test-devcg-gone-#{SecureRandom.hex(4)}")
  end

  # Detach finds the program on the cgroup itself (BPF_PROG_QUERY), so it
  # works after the loaded program left the LRU cache -- and after an agent
  # restart, when no cache exists at all.
  def test_detach_works_after_the_cached_program_was_evicted_or_the_attacher_is_gone
    attacher = DeviceCgroup::Attacher.new(cache_limit: 1)
    with_cgroup do |path|
      id = attacher.attach(path, DeviceCgroup.rules_for)
      with_cgroup do |other|
        attacher.attach(other, DeviceCgroup.rules_for(privileged: true))

        assert_equal 1, attacher.cached_rule_sets
        assert_equal [id], attacher.detach(path)
        assert_empty attacher.attached(path)
        # A fresh attacher (a restarted agent) detaches what the old one attached.
        assert_equal 1, DeviceCgroup::Attacher.new.detach(other).length
        assert_empty attacher.attached(other)
      end
    ensure
      attacher.close
    end
  end
end

# The production L3 runtime: every container cgroup carries the program, the
# container's /dev is a nodev tmpfs, the standard devices work, and a
# privileged container is allowed everything and sees the host's nodes.
class NativeRuntimeDeviceFilterTest < Minitest::Test
  Linux = Rubernetes::Platform::Linux
  DeviceCgroup = Linux::DeviceCgroup

  def setup
    skip "production Native runtime requires root" unless Process.uid.zero?
    skip "static busybox is unavailable" unless File.executable?("/usr/bin/busybox")
    skip "cgroup v2 hierarchy is unavailable" unless File.writable?("/sys/fs/cgroup")
    require "rubernetes/runtime/native"
  end

  SCRIPT = <<~'SH'
    b=/bin/busybox
    $b grep ' /dev ' /proc/self/mountinfo | $b head -n 1
    echo discard > /dev/null && echo null-ok
    $b head -c 4 /dev/zero | $b od -An -tx1 | $b tr -d ' \n'; echo
    $b head -c 4 /dev/urandom | $b wc -c | $b tr -d ' '
    $b ls /dev | $b tr '\n' ' '; echo
    $b sleep 30
  SH

  def with_runtime
    Dir.mktmpdir("rubernetes-native-devcg-") do |directory|
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
      sandbox_id = "devcg-#{Process.pid}-#{SecureRandom.hex(4)}"
      image_bytes = "device-filter-image"
      sandbox = runtime.run_sandbox(
        {"id" => sandbox_id, "image_bytes" => image_bytes,
         "image_digest" => "sha256:#{Digest::SHA256.hexdigest(image_bytes)}", "lowerdirs" => [lower]},
        request_id: sandbox_id
      )
      begin
        yield runtime, sandbox, lower
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

  def output_lines(runtime, container, count)
    Timeout.timeout(10) do
      text = +""
      text = runtime.logs(container).to_s until text.lines.length >= count || (sleep(0.1) && false)
      text.lines(chomp: true)
    end
  end

  def test_container_devices_are_filtered_and_dev_is_nodev
    with_runtime do |runtime, sandbox, lower|
      container = runtime.create_container(sandbox,
                                           {"id" => "main", "rootfs_path" => lower, "command" => ["/bin/busybox", "sh", "-c", SCRIPT]})
      cgroup = container.cgroup.path
      attacher = DeviceCgroup::Attacher.new
      ids = attacher.attached(cgroup)

      assert_equal 1, ids.length, "one device program on the container cgroup"
      fd = attacher.bpf.prog_get_fd_by_id(ids.first)
      begin
        info = attacher.bpf.program_info(fd)

        assert_equal DeviceCgroup::PROGRAM_NAME, info.fetch(:name)
        expected, = DeviceCgroup.compile(DeviceCgroup.rules_for)

        assert_equal expected.length, info.fetch(:xlated_instructions).length
      ensure
        IO.for_fd(fd).close
      end

      runtime.start_container(container)
      mountinfo, null, zero, urandom, listing = output_lines(runtime, container, 5)
      options = mountinfo.split[5].split(",")

      assert_includes options, "nodev", mountinfo
      assert_includes options, "nosuid", mountinfo
      assert_equal "null-ok", null
      assert_equal "00000000", zero
      assert_equal "4", urandom
      assert_equal %w[fd full mqueue null ptmx pts random shm stderr stdin stdout tty urandom zero], listing.split.sort

      runtime.stop_container(container, timeout: 2)
      runtime.remove_container(container)

      refute File.directory?(cgroup)
      detached = runtime.trace.find { |event| event.to_s.include?("device_filter_detached") }

      refute_nil detached
    end
  end

  def test_privileged_container_is_allowed_everything_and_sees_host_devices
    with_runtime do |runtime, sandbox, lower|
      container = runtime.create_container(sandbox, {"id" => "priv", "rootfs_path" => lower, "command" => ["/bin/busybox", "sh", "-c", SCRIPT],
                                                     "security_context" => {"privileged" => true, "allow_privilege_escalation" => true}})
      attacher = DeviceCgroup::Attacher.new
      ids = attacher.attached(container.cgroup.path)

      assert_equal 1, ids.length
      fd = attacher.bpf.prog_get_fd_by_id(ids.first)
      begin
        expected, = DeviceCgroup.compile(DeviceCgroup.rules_for(privileged: true))

        assert_equal expected.length, attacher.bpf.program_info(fd).fetch(:xlated_instructions).length
      ensure
        IO.for_fd(fd).close
      end
      runtime.start_container(container)
      mountinfo, null, _zero, _urandom, listing = output_lines(runtime, container, 5)

      assert_includes mountinfo.split[5].split(","), "nodev"
      assert_equal "null-ok", null
      host_nodes = Dir.children("/dev").select do |name|
        File.stat(File.join("/dev", name)).chardev?
      rescue StandardError
        false
      end
      host_nodes -= %w[console ptmx fd stdin stdout stderr]

      assert_operator (listing.split & host_nodes).length, :>, 8, "host device nodes visible: #{listing}"
      runtime.stop_container(container, timeout: 2)
      runtime.remove_container(container)
    end
  end
end
