# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime/native"

# The runtime attaches a device cgroup allowlist to every container cgroup
# it creates (containerd's rules for the container plus runc's defaults) and
# detaches it before the cgroup goes.
class NativeDeviceFilterWiringTest < Minitest::Test
  Native = Rubernetes::Runtime::Native
  DeviceCgroup = Rubernetes::Platform::Linux::DeviceCgroup

  class RecordingFilter
    attr_reader :attached, :detached

    def initialize(fail_attach: false)
      @attached = []
      @detached = []
      @fail_attach = fail_attach
      @ids = 0
    end

    def validate! = true

    def attach(cgroup_path, rules)
      raise DeviceCgroup::Error, "kernel refused the program" if @fail_attach

      @attached << [cgroup_path, rules.map(&:to_h)]
      @ids += 1
    end

    def detach(cgroup_path)
      @detached << cgroup_path
      [@ids]
    end
  end

  def runtime(filter)
    Native.new(adapters: {device_filter: filter})
  end

  def test_every_container_cgroup_gets_the_default_allowlist_and_loses_it_on_removal
    filter = RecordingFilter.new
    runtime = runtime(filter)
    sandbox_id = runtime.run_sandbox({"request_id" => "request-1"})
    container = runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"]})

    assert_equal 1, filter.attached.length
    cgroup_path, rules = filter.attached.first

    assert_equal container.cgroup.path, cgroup_path
    assert_equal DeviceCgroup.rules_for.map(&:to_h), rules
    assert_equal DeviceCgroup::DENY_ALL.to_h, rules.first
    attached = runtime.trace.find { |event| event[:event] == :device_filter_attached || event["event"] == "device_filter_attached" }

    refute_nil attached, runtime.trace.inspect

    runtime.start_container(container)
    runtime.stop_container(container)
    runtime.remove_container(container)

    assert_equal [cgroup_path], filter.detached
  end

  def test_privileged_containers_are_allowed_everything
    filter = RecordingFilter.new
    runtime = runtime(filter)
    sandbox_id = runtime.run_sandbox({"request_id" => "request-privileged"})
    runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"],
                                          "security_context" => {"privileged" => true}})

    _, rules = filter.attached.first

    assert_equal DeviceCgroup.rules_for(privileged: true).map(&:to_h), rules
    assert_equal DeviceCgroup::ALLOW_ALL.to_h, rules.first
  end

  def test_device_mounts_become_rules_with_their_permissions
    filter = RecordingFilter.new
    runtime = runtime(filter)
    sandbox_id = runtime.run_sandbox({"request_id" => "request-devices"})
    null = File.stat("/dev/null")
    container = runtime.create_container(sandbox_id, {
                                           "id" => "container-1", "command" => ["/bin/true"],
                                           "mounts" => [
                                             # A device plugin device: permissions verbatim.
                                             {"source" => "/dev/null", "destination" => "/dev/fake0", "device" => true,
                                              "permissions" => "rw"},
                                             # A CDI deviceNode naming its own type/major/minor.
                                             {"source" => "/dev/null", "destination" => "/dev/nvidia0", "device" => true, "permissions" => "rwm",
                                              "device_type" => "c", "major" => 195, "minor" => 0},
                                             # A plain volume bind mount contributes nothing.
                                             {"source" => "/tmp", "destination" => "/data"}
                                           ]
                                         })

    _, rules = filter.attached.first
    expected = DeviceCgroup.rules_for(devices: [
                                        {"type" => "c", "major" => null.rdev_major, "minor" => null.rdev_minor, "access" => "rw",
                                         "allow" => true},
                                        {"type" => "c", "major" => 195, "minor" => 0, "access" => "rwm", "allow" => true}
                                      ]).map(&:to_h)

    assert_equal expected, rules
    mounts = container.spec["mounts"]

    assert_equal({"source" => "/dev/null", "destination" => "/dev/fake0", "readonly" => false, "propagation" => "None",
                  "device" => true, "permissions" => "rw"}, mounts[0])
    assert_equal 195, mounts[1]["major"]
    refute mounts[2].key?("device")
  end

  def test_a_device_directory_contributes_every_node_beneath_it
    filter = RecordingFilter.new
    runtime = runtime(filter)
    sandbox_id = runtime.run_sandbox({"request_id" => "request-dir"})
    Dir.mktmpdir("rubernetes-devdir-") do |directory|
      # Symlinks are followed like containerd's os.Stat; non-devices are skipped.
      File.symlink("/dev/zero", File.join(directory, "zero"))
      File.symlink("/dev/full", File.join(directory, "full"))
      File.write(File.join(directory, "plain"), "")
      File.symlink("/nonexistent", File.join(directory, "dangling"))
      runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"],
                                            "mounts" => [{"source" => directory, "destination" => "/dev/tree", "device" => true, "permissions" => "r"}]})
    end

    _, rules = filter.attached.first
    devices = rules[1...-DeviceCgroup::DEFAULT_RULES.length]
    full = File.stat("/dev/full")
    zero = File.stat("/dev/zero")

    assert_equal [{"type" => "c", "major" => full.rdev_major, "minor" => full.rdev_minor, "access" => "r", "allow" => true},
                  {"type" => "c", "major" => zero.rdev_major, "minor" => zero.rdev_minor, "access" => "r", "allow" => true}], devices
  end

  def test_a_rejected_program_fails_the_create_and_releases_the_cgroup
    filter = RecordingFilter.new(fail_attach: true)
    runtime = runtime(filter)
    sandbox_id = runtime.run_sandbox({"request_id" => "request-fail"})
    error = assert_raises(Native::ResourceError) do
      runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"]})
    end
    assert_includes error.message, "kernel refused the program"
    assert_equal 1, filter.detached.length
    assert_empty runtime.sandboxes.first.fetch("containers"), runtime.sandboxes.inspect
  end

  def test_a_missing_device_source_is_a_configuration_error
    runtime = runtime(RecordingFilter.new)
    sandbox_id = runtime.run_sandbox({"request_id" => "request-missing"})
    assert_raises(Native::ConfigurationError) do
      runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"],
                                            "mounts" => [{"source" => "/dev/rubernetes-does-not-exist", "destination" => "/dev/x", "device" => true}]})
    end
  end

  def test_the_pure_profile_has_no_filter_and_host_profiles_fail_closed_without_bpf
    runtime = Native.new
    sandbox_id = runtime.run_sandbox({"request_id" => "request-pure"})
    runtime.create_container(sandbox_id, {"id" => "container-1", "command" => ["/bin/true"]})

    refute(runtime.trace.any? { |event| event.to_s.include?("device_filter") })

    skip "host profile construction requires root" unless Process.uid.zero?
    original = DeviceCgroup::Attacher.instance_method(:validate!)
    DeviceCgroup::Attacher.define_method(:validate!) do
      raise DeviceCgroup::Error, "cgroup device filter program rejected by the kernel: EINVAL"
    end
    begin
      Dir.mktmpdir("rubernetes-devcg-") do |directory|
        error = assert_raises(Native::CapabilityError) do
          Native.new(profile: :kernel_isolation, adapters: Rubernetes::Platform::Linux::NativeAdapters.for_profile(
            profile: :kernel_isolation, sandbox_root: directory, cgroup_root: "/sys/fs/cgroup"
          ), sandbox_root: directory, cgroup_root: "/sys/fs/cgroup", journal_path: File.join(directory, "journal.jsonl"),
                     log_root: File.join(directory, "logs"))
        end
        assert_includes error.message, "BPF_PROG_TYPE_CGROUP_DEVICE"
      end
    ensure
      DeviceCgroup::Attacher.define_method(:validate!, original)
    end
  end
end
