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
    compiler = Linux::SeccompCompiler.new(syscall_numbers: {"read" => 0}, allowlist: ["read", "unknown"])

    error = assert_raises(Linux::Security::Unsupported) { compiler.compile }

    assert_match(/unknown/, error.message)
  end
end
