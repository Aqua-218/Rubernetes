# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/node"

# A Pod whose cleanup raced or was interrupted must not keep the node down.
# Reproduces the worker-1 sequence of 2026-09-27 09:25 (ledger seq 886-895):
# the runtime removed the sandbox while a second cleanup of the same Pod was
# running; the loser recorded "umount2 No such file or directory", the record
# stayed CleanupPending through 14 retries, and the agent restart died with
# RecoveryRequired.  Now: one terminate per Pod at a time, a sandbox the
# runtime reports Removed counts as cleaned, and a Pod that still cannot be
# cleaned at start is reported per Pod while the node comes up.
class KubeletRestartCleanupIdempotencyTest < Minitest::Test
  class Runtime
    attr_reader :calls
    attr_accessor :removed, :fail_remove, :unknown_after_first

    def initialize
      @calls = []
      @removed = {}
      @fail_remove = false
      @unknown_after_first = false
      @next = 0
      @gate = nil
    end

    def run_sandbox(_pod, **) = "sandbox-1"

    def create_container(_sandbox, _spec)
      @next += 1
      "container-#{@next}"
    end

    def start_container(_id) = true
    def stop_container(_id, timeout:) = true
    def remove_container(_id) = true

    # Two concurrent removals: the first blocks on +hold+ until released.
    attr_accessor :hold

    def remove_sandbox(id)
      @calls << [:remove_sandbox, id]
      raise "workspace: umount2 No such file or directory" if @fail_remove
      if @unknown_after_first && @removed[id]
        raise Rubernetes::Runtime::Native::Error, "unknown sandbox #{id}"
      end

      @hold&.pop
      @removed[id] = true
      true
    end

    def sandbox_removed?(id) = @removed[id] == true
  end

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "j66zs", "namespace" => "perf-burst", "uid" => "51c3d6d8"},
     "spec" => {"terminationGracePeriodSeconds" => 1, "containers" => [{"name" => "pause", "image" => "registry.k8s.io/pause:3.10"}]}}
  end

  def test_a_sandbox_the_runtime_already_removed_counts_as_cleaned
    runtime = Runtime.new
    runtime.unknown_after_first = true
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {})
    lifecycle.start(pod)
    runtime.removed["sandbox-1"] = true # an earlier attempt finished the removal
    result = lifecycle.terminate(pod)
    assert_equal "Removed", result.state
    assert_empty result.cleanup_errors
    assert_includes lifecycle.record("51c3d6d8")[:events].map { |entry| entry["type"] }, "sandbox.already_removed"
  end

  def test_concurrent_terminates_of_one_pod_run_the_cleanup_once
    runtime = Runtime.new
    runtime.hold = Queue.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {})
    lifecycle.start(pod)
    first = Thread.new { lifecycle.terminate(pod) }
    sleep 0.05 until runtime.calls.include?([:remove_sandbox, "sandbox-1"])
    # The cleanup retry (relist thread) and a DELETED event arrive meanwhile.
    assert_empty lifecycle.retry_pending_cleanups
    second = Thread.new { lifecycle.terminate(pod, gone: true) }
    sleep 0.05
    runtime.hold << :go
    results = [first.value, second.value]
    assert_equal %w[Removed Removed], results.map(&:state)
    assert_equal 1, runtime.calls.count { |call| call == [:remove_sandbox, "sandbox-1"] }, "the second waited for the first"
  end

  class API
    attr_reader :nodes

    def initialize = @nodes = []
    def register_node(node) = (@nodes << node).last
    def renew_lease(lease) = lease
  end

  class Loop
    def start(**) = true
    def stop(**) = true
  end

  def test_an_agent_starts_although_one_pod_cannot_be_cleaned_yet
    Dir.mktmpdir("restart-cleanup") do |dir|
      state = File.join(dir, "state.json")
      runtime = Runtime.new
      runtime.fail_remove = true
      first = Rubernetes::Node::Lifecycle.new(runtime: runtime, state_store: state, sleeper: ->(_) {})
      first.start(pod)
      assert_equal "CleanupPending", first.terminate(pod).state

      # Restart: the runtime still cannot clean this one Pod.
      runtime = Runtime.new
      runtime.fail_remove = true
      second = Rubernetes::Node::Lifecycle.new(runtime: runtime, state_store: state, sleeper: ->(_) {})
      notices = []
      api = API.new
      agent = Rubernetes::Node::Agent.new(node_name: "worker-1", api: api, lifecycle: second, sync_loop: Loop.new, sleeper: ->(_) {},
                                          error_handler: ->(error, *context) { notices << [error.message, context] })
      agent.start
      assert agent.registered?, "the node came up"
      assert_equal 1, api.nodes.length
      report = second.recover
      assert_equal true, report["ready"]
      assert_equal ["51c3d6d8"], report["blocked"]
      assert_match(/umount2 No such file or directory/, report.dig("pod_errors", "51c3d6d8").join)
      assert_equal [:pod_recovery_pending, "51c3d6d8"], notices.first[1]
      assert_equal "CleanupPending", second.state(pod)

      # The retry finishes it once the runtime can (the sandbox is gone).
      runtime.fail_remove = false
      runtime.removed["sandbox-1"] = true
      runtime.unknown_after_first = true
      second.retry_pending_cleanups(now: 10_000.0)
      assert_equal "Removed", second.state(pod)
    ensure
      agent&.stop rescue nil
    end
  end

  def test_runtime_level_errors_still_keep_the_node_down
    lifecycle = Class.new do
      def recover(**) = {"ready" => false, "errors" => ["resource identity mismatch: cgroup:x"], "blocked" => [], "pod_errors" => {}}
    end.new
    agent = Rubernetes::Node::Agent.new(node_name: "worker-1", api: API.new, lifecycle: lifecycle, sync_loop: Loop.new, sleeper: ->(_) {})
    assert_raises(Rubernetes::Runtime::RecoveryRequired) { agent.start }
  end
end

# OverlayFilesystemAdapter#cleanup_mounted_workspace: umount2 ENOENT / EINVAL
# (the overlay is already gone) is the state cleanup wants, not a failure.
class KubeletWorkspaceUmountIdempotencyTest < Minitest::Test
  Adapters = Rubernetes::Platform::Linux::NativeAdapters

  class Mount
    attr_accessor :errno

    def unmount(target:, flags:, resource_id:)
      raise Rubernetes::Platform::Linux::Error.new(errno: errno, operation: "umount2", resource_id: resource_id) if errno

      true
    end
  end

  class Namespaces
    def with_mount_namespace(_handle) = yield
  end

  def adapter(errno)
    mount = Mount.new
    mount.errno = errno
    adapter = Adapters::OverlayFilesystemAdapter.allocate
    adapter.instance_variable_set(:@mount, mount)
    adapter.instance_variable_set(:@namespace_adapter, Namespaces.new)
    adapter.define_singleton_method(:mount_readback) { |_handle, _target| "identity" }
    adapter.define_singleton_method(:mount_present?) { |_handle, _target| false }
    adapter.define_singleton_method(:same_mount_identity?) { |_left, _right| true }
    adapter
  end

  def workspace = Rubernetes::Runtime::Native::Filesystem::Workspace.new(id: "w", root: "/tmp/w/root", upper: nil, work: nil, identity: "workspace:w", image_digest: nil)

  def test_enoent_and_einval_are_success_other_errors_are_not
    require "rubernetes/runtime/native"
    assert_nil adapter(Errno::ENOENT::Errno).send(:cleanup_mounted_workspace, workspace, {"mount_identity" => "identity"}, "ns")
    assert_nil adapter(Errno::EINVAL::Errno).send(:cleanup_mounted_workspace, workspace, {"mount_identity" => "identity"}, "ns")
    assert_nil adapter(nil).send(:cleanup_mounted_workspace, workspace, {"mount_identity" => "identity"}, "ns")
    assert_raises(Rubernetes::Platform::Linux::Error) do
      adapter(Errno::EBUSY::Errno).send(:cleanup_mounted_workspace, workspace, {"mount_identity" => "identity"}, "ns")
    end
  end
end
