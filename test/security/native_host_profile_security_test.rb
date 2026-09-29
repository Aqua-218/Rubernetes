# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require "rubernetes/bootstrap"

class NativeHostProfileSecurityTest < Minitest::Test
  Native = Rubernetes::Runtime::Native
  Linux = Rubernetes::Platform::Linux

  class ContractAdapter
    attr_reader :calls

    def initialize
      @calls = []
    end

    def native_capabilities
      {
        namespace: true,
        filesystem: true,
        cgroup_v2: true,
        security_application: true,
        process_gate: true,
        pidfd: true,
        namespace_exec_streams: true,
        namespace_port_forward: true
      }
    end

    def validate_native_capabilities!
      @calls << :validate_native_capabilities
      true
    end

    def create(**arguments)
      @calls << [:create, arguments]
      "resource"
    end

    def destroy(**arguments)
      @calls << [:destroy, arguments]
      true
    end

    def prepare(**arguments)
      @calls << [:prepare, arguments]
      true
    end

    def cleanup(**arguments)
      @calls << [:cleanup, arguments]
      true
    end

    def available?
      true
    end

    def configure(*arguments)
      @calls << [:configure, arguments]
      true
    end

    def attach(*arguments)
      @calls << [:attach, arguments]
      true
    end

    def remove(*arguments)
      @calls << [:remove, arguments]
      true
    end

    def kill(*arguments)
      @calls << [:kill, arguments]
      true
    end

    def stats(*arguments)
      @calls << [:stats, arguments]
      {}
    end

    def events(*arguments)
      @calls << [:events, arguments]
      {}
    end

    def apply(**arguments)
      @calls << [:apply, arguments]
      true
    end

    def spawn(**arguments)
      @calls << [:spawn, arguments]
      {pid: 12_345, pidfd: nil, gate: Object.new, stdout: nil, stderr: nil}
    end

    def release_gate(gate)
      @calls << [:release_gate, gate]
      true
    end

    def wait(**arguments)
      @calls << [:wait, arguments]
      {exit_status: 0, term_signal: nil, code: 0}
    end

    def signal(**arguments)
      @calls << [:signal, arguments]
      true
    end

    def open(**arguments)
      @calls << [:open, arguments]
      12_345
    end

    def send_signal(**arguments)
      @calls << [:send_signal, arguments]
      true
    end

    def close(**arguments)
      @calls << [:close, arguments]
      true
    end

    def exec(**arguments)
      @calls << [:exec, arguments]
      true
    end

    def port_forward(**arguments)
      @calls << [:port_forward, arguments]
      true
    end
  end

  def test_host_profile_rejects_recording_and_fake_adapters_before_any_process_effect
    process = Native::FakeProcessAdapter.new

    error = assert_raises(Native::CapabilityError) do
      Native.new(
        profile: :host_integration,
        journal: Native::MemoryJournal.new,
        namespace_adapter: Native::Namespace::RecordingAdapter.new,
        filesystem_adapter: Native::RecordingAdapter.new,
        cgroup_adapter: Native::FakeCgroup.new,
        security_adapter: Linux::Security::RecordingAdapter.new,
        process_adapter: process
      )
    end

    assert_match(/recording\/fake adapter/, error.message)
    assert_empty(process.calls)
    refute(process.calls.any? { |call| call.first == :release_gate })
  end

  def test_capability_flags_without_effect_validation_are_rejected
    adapters = build_contract_adapters
    adapters[:security].define_singleton_method(:validate_native_capabilities!) do
      raise NoMethodError, "not available"
    end

    error = assert_raises(Native::CapabilityError) do
      build_host_runtime(adapters)
    end

    assert_match(/security adapter .*invalid native capability contract/, error.message)
  end

  def test_l3_requires_the_preflight_contract_and_pidfd
    adapters = build_contract_adapters
    adapters.delete(:pidfd)

    error = assert_raises(Native::CapabilityError) do
      Native.new(
        profile: :l3,
        l3: true,
        journal: Native::MemoryJournal.new,
        security_probe: -> { complete_probe },
        **adapters.transform_keys { |key| "#{key}_adapter".to_sym }
      )
    end

    assert_match(/requires an explicit pidfd adapter/, error.message)
  end

  def test_host_profile_rejects_fake_security_probe
    adapters = build_contract_adapters

    error = assert_raises(Native::CapabilityError) do
      Native.new(
        profile: :host_integration,
        journal: Native::MemoryJournal.new,
        security_probe: Native::FakeCapabilityProbe.new,
        **adapters.transform_keys { |key| "#{key}_adapter".to_sym }
      )
    end

    assert_match(/security probe .*fake adapter/, error.message)
  end

  def test_explicitly_proven_l3_adapters_validate_without_spawning_a_workload
    adapters = build_contract_adapters
    process = adapters.fetch(:process)

    runtime = Native.new(
      profile: :l3,
      l3: true,
      journal: Native::MemoryJournal.new,
      security_probe: -> { complete_probe },
      **adapters.transform_keys { |key| "#{key}_adapter".to_sym }
    )

    assert_equal(:l3, runtime.profile)
    assert_includes(process.calls, :validate_native_capabilities)
    refute(process.calls.any? { |call| call.is_a?(Array) && %i[spawn release_gate].include?(call.first) })
  end

  def test_production_profile_rejects_digest_only_image_identity
    runtime = build_host_runtime(build_contract_adapters)
    digest = "sha256:#{Digest::SHA256.hexdigest("unverified-image")}"

    error = assert_raises(Native::FailClosed) do
      runtime.send(:pin_image, "image_digest" => digest)
    end

    assert_match(/requires image bytes or an adapter-verified OCI identity/, error.message)
  end

  def test_production_profile_accepts_only_bytes_bound_to_the_digest
    runtime = build_host_runtime(build_contract_adapters)
    bytes = "verified OCI manifest bytes"
    digest = "sha256:#{Digest::SHA256.hexdigest(bytes)}"

    assert_equal(digest, runtime.send(:pin_image, "image_digest" => digest, "image_bytes" => bytes))
    assert_raises(Native::Filesystem::DigestMismatch) do
      runtime.send(:pin_image, "image_digest" => digest, "image_bytes" => "substituted")
    end
  end

  def test_assembler_preflights_available_host_profile_without_starting_a_workload
    Tempfile.create(["rubernetes-host-profile", ".yml"]) do |file|
      file.write("processes:\n  rubernetes-agent:\n    runtime_profile: host_integration\n")
      file.flush

      assembly = Rubernetes::Bootstrap::Assembler.new(
        process_name: "rubernetes-agent",
        config_path: file.path,
        log_io: StringIO.new
      ).build
      runtime = assembly.service.runtime

      assert_equal(:host_integration, runtime.profile)
      assert_instance_of(Linux::NativeAdapters::NamespaceAdapter, runtime.namespace.adapter)
      assert_empty(runtime.namespace.resources)
      assert_empty(runtime.filesystem.workspaces)
      assert_empty(runtime.process_supervisor.resources)
    end
  end

  private

  def build_contract_adapters
    {
      namespace: ContractAdapter.new,
      filesystem: ContractAdapter.new,
      cgroup: ContractAdapter.new,
      security: ContractAdapter.new,
      process: ContractAdapter.new,
      pidfd: ContractAdapter.new,
      exec: ContractAdapter.new,
      port_forward: ContractAdapter.new
    }
  end

  def build_host_runtime(adapters)
    Native.new(
      profile: :host_integration,
      journal: Native::MemoryJournal.new,
      namespace_adapter: adapters.fetch(:namespace),
      filesystem_adapter: adapters.fetch(:filesystem),
      cgroup_adapter: adapters.fetch(:cgroup),
      security_adapter: adapters.fetch(:security),
      process_adapter: adapters.fetch(:process),
      pidfd_adapter: adapters[:pidfd],
      exec_adapter: adapters.fetch(:exec),
      port_forward_adapter: adapters.fetch(:port_forward)
    )
  end

  def complete_probe
    Linux::Security::Probe.new(
      architecture: "x86_64",
      capabilities: Linux::Security::CAPABILITIES.transform_values { true },
      no_new_privs: true,
      seccomp: true,
      landlock: true,
      details: {"source" => "test"}
    )
  end
end
