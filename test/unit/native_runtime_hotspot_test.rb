# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "fileutils"
require "rubernetes/runtime/native"

# Agent CPU hotspots removed 2026-09-27 (stackprof of a 90-pod burst): the
# security plan was rebuilt and serialized per container, container lookup
# raised once per sandbox on every miss, and container log directories were
# never removed.
class NativeRuntimeHotspotTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def setup
    @directory = Dir.mktmpdir("native-hotspot-")
    @runtime = Native.new(config: {log_root: File.join(@directory, "log"),
                                   sandbox_root: File.join(@directory, "sandbox"),
                                   journal_path: File.join(@directory, "ledger.jsonl")})
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def test_security_plan_is_shared_between_containers_with_the_same_context
    sandbox_id = @runtime.run_sandbox({"request_id" => "plan-cache"})
    first = @runtime.create_container(sandbox_id, {"id" => "c1", "command" => ["/bin/true"]})
    second = @runtime.create_container(sandbox_id, {"id" => "c2", "command" => ["/bin/true"]})
    other = @runtime.create_container(sandbox_id, {"id" => "c3", "command" => ["/bin/true"],
                                                   "security_context" => {"run_as_user" => 1234}})

    assert_same first.security_plan, second.security_plan
    refute_same first.security_plan, other.security_plan
    # Status serializes the plan once per plan object, not once per call.
    assert_same @runtime.container_status(first)["security_plan"], @runtime.container_status(second)["security_plan"]
  end

  def test_container_claim_records_the_plan_digest_not_the_plan
    sandbox_id = @runtime.run_sandbox({"request_id" => "plan-digest"})
    @runtime.create_container(sandbox_id, {"id" => "c1", "command" => ["/bin/true"]})
    claim = @runtime.ledger.resources(include_released: true).find do |resource|
      resource[:kind] == "cgroup" && resource[:id].end_with?(":c1")
    end

    refute_nil claim
    assert_match(/\A[0-9a-f]{64}\z/, claim[:metadata]["security_plan_digest"])
    refute claim[:metadata].key?("security_plan")
    assert claim[:metadata].key?("spec"), "the spec stays: startup reconstruction rebuilds the container from it"
  end

  def test_container_lookup_raises_nothing_while_scanning_other_sandboxes
    3.times { |index| @runtime.run_sandbox({"request_id" => "scan-#{index}"}) }
    last = @runtime.sandboxes.last.fetch("id")
    container = @runtime.create_container(last, {"id" => "c1", "command" => ["/bin/true"]})
    raised = []
    trace = TracePoint.new(:raise) { |point| raised << point.raised_exception }
    trace.enable { @runtime.container_status(container) }

    assert_empty(raised.grep(Native::Sandbox::Error))
    assert_raises(Native::Error) { @runtime.container_status("no-such-container") }
  end

  def test_remove_sandbox_removes_the_containers_log_directories
    sandbox_id = @runtime.run_sandbox({"request_id" => "logs"})
    container = @runtime.create_container(sandbox_id, {"id" => "c1", "command" => ["/bin/true"]})
    @runtime.start_container(container)
    log_directory = File.join(@directory, "log", "process-#{sandbox_id}-#{container.id}")
    FileUtils.mkdir_p(log_directory)
    File.write(File.join(log_directory, "0.log"), "hello\n")
    unrelated = File.join(@directory, "log", "process-other-sandbox-c1")
    FileUtils.mkdir_p(unrelated)
    @runtime.stop_sandbox(sandbox_id)
    @runtime.remove_sandbox(sandbox_id)

    refute_path_exists log_directory
    assert File.directory?(unrelated)
  end
end
