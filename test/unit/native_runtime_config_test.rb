# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/runtime/native"

class NativeRuntimeConfigTest < Minitest::Test
  Native = Rubernetes::Runtime::Native
  Linux = Rubernetes::Platform::Linux

  def test_host_effects_require_an_explicit_profile
    error = assert_raises(Native::ConfigurationError) do
      Native::Configuration.new(host_integration: true)
    end

    assert_match(/explicit.*profile/, error.message)
  end

  def test_l3_profile_requires_the_l3_gate_and_does_not_downgrade
    error = assert_raises(Native::ConfigurationError) do
      Native::Configuration.new(profile: :l3)
    end

    assert_match(/l3: true/, error.message)
  end

  def test_security_plan_orders_rlimit_before_seccomp_and_fd_close
    probe = Linux::Security::Probe.new(
      architecture: "x86_64",
      capabilities: Linux::Security::CAPABILITIES.transform_values { true },
      no_new_privs: true,
      seccomp: true,
      landlock: true,
      details: {}
    )
    security = Linux::Security.new(capability_probe: -> { probe })
    names = security.plan({}, probe: probe).step_names

    assert_operator(names.index(:rlimit), :<, names.index(:seccomp))
    assert_operator(names.index(:seccomp), :<, names.index(:close_fds))
    assert_operator(names.index(:close_fds), :<, names.index(:execveat))
  end

  def test_seccomp_rejects_unknown_syscall_numbers
    compiler = Linux::SeccompCompiler.new(syscall_numbers: {"read" => 0}, allowlist: %w[read unknown])

    error = assert_raises(Linux::Security::Unsupported) { compiler.compile }

    assert_match(/unknown/, error.message)
  end

  def test_seccomp_argument_operands_must_fit_unsigned_64_bits
    arguments = {index: 0, op: "SCMP_CMP_LT", value: -1, value_two: 0}

    assert_raises(Linux::Seccomp::ProfileError) { Linux::Seccomp::Arg.new(**arguments) }
    assert_raises(Linux::Seccomp::ProfileError) do
      Linux::Seccomp::Arg.from({"index" => 0, "op" => "SCMP_CMP_MASKED_EQ", "valueTwo" => 1 << 64})
    end
    assert_operator Linux::Seccomp::Arg.new(**arguments, value: Linux::Seccomp::U64_MAX), :match?, 0
  end

  def test_the_native_runtime_refuses_to_create_a_user_namespace_with_host_networking
    namespace = Rubernetes::Runtime::Native::Namespace.new(profile: :host_integration)
    error = assert_raises(Rubernetes::Runtime::Native::Namespace::Unsupported) do
      namespace.create(id: "unsupported", spec: {"spec" => {"hostUsers" => false, "hostNetwork" => true}})
    end

    assert_match(/user namespaces with host networking/, error.message)
    assert_empty namespace.adapter.calls
  end
end
