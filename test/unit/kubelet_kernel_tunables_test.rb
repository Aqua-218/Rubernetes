# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node/kernel_tunables"
require "rubernetes/bootstrap/agent_service"

class KubeletKernelTunablesTest < Minitest::Test
  KernelTunables = Rubernetes::Node::KernelTunables
  FLAG = "vm/overcommit_memory"

  def setup
    @root = Dir.mktmpdir("kernel-tunables")
    KernelTunables::EXPECTED.each do |name, value|
      path = File.join(@root, name)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, value.to_s)
    end
    @flag_path = File.join(@root, FLAG)
    File.write(@flag_path, "0")
  end

  def teardown = FileUtils.rm_rf(@root)

  def test_initial_namespace_keeps_the_existing_default_and_supports_verifying_and_tuning
    tunables = KernelTunables.new(root: @root, user_namespace: -> { false })

    assert tunables.apply!(allow_user_namespace: true)
    assert_equal "0", File.read(@flag_path)

    error = assert_raises(KernelTunables::Error) { tunables.apply!(protect_defaults: true) }
    assert_match(/vm\.overcommit_memory.*expected 1, got 0/, error.message)
    assert_equal "0", File.read(@flag_path)

    assert tunables.apply!(protect_defaults: false)
    assert_equal "1", File.read(@flag_path)
    assert tunables.apply!(protect_defaults: true)
  end

  def test_user_namespace_gate_only_ignores_write_failures_in_the_nested_namespace
    cannot_write = ->(*) { raise Errno::EROFS }
    userns = KernelTunables.new(root: @root, user_namespace: -> { true }, writer: cannot_write)
    host = KernelTunables.new(root: @root, user_namespace: -> { false }, writer: cannot_write)

    assert userns.apply!(allow_user_namespace: true)
    assert_raises(KernelTunables::Error) { userns.apply! }
    assert_raises(KernelTunables::Error) { userns.apply!(protect_defaults: true, allow_user_namespace: true) }
    assert_raises(KernelTunables::Error) { host.apply!(protect_defaults: false, allow_user_namespace: true) }

    File.delete(@flag_path)
    error = assert_raises(KernelTunables::Error) { userns.apply!(allow_user_namespace: true) }
    assert_match(/cannot read kernel flag vm\.overcommit_memory/, error.message)
  end

  def test_agent_checks_kernel_defaults_before_starting_the_runtime
    tunables = KernelTunables.new(root: @root, user_namespace: -> { false })
    runtime = Rubernetes::Bootstrap::AgentService::NullRuntime.new
    runtime.define_singleton_method(:start) { raise "runtime was started despite invalid kernel settings" }
    config = {"runtime_profile" => "host_integration", "protect_kernel_defaults" => true}
    node = Rubernetes::Bootstrap::AgentService.new(config: config, logger: Object.new, kernel_tunables: tunables, runtime: runtime)
    assert_raises(KernelTunables::Error) { node.start }
    assert_equal "0", File.read(@flag_path)
  end
end
