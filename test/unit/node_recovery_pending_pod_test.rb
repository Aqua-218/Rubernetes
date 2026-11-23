# frozen_string_literal: true

require_relative "../test_helper"
require_relative "node_lifecycle_test"
require "rubernetes/bootstrap/agent_service"

# Startup recovery on a node whose Pods lost their sandbox: the termination
# of such a Pod must finish (its namespace is gone, there is nothing to
# enter) and one Pod whose cleanup is still pending must not keep the whole
# agent down -- kubelet never refuses to start over a single leftover Pod.
class NodeRecoveryPendingPodTest < Minitest::Test
  # The runtime released the sandbox during recovery: a live lookup says so.
  class GoneSandboxRuntime < NodeLifecycleTest::Runtime
    attr_accessor :gone

    def network_sandbox_context(id)
      raise StandardError, "unknown sandbox #{id}" if gone

      {"sandbox_id" => id,
       "netns" => {"handle" => "namespace:#{id}", "path" => "/proc/4242/ns/net", "inode" => 4_026_531_842,
                   "pid" => 4242, "pidfd" => 31}}
    end
  end

  class RecordingNetwork < NodeLifecycleTest::Network
    def delete(sandbox, namespace_gone: false)
      @calls << [:network_delete, sandbox, namespace_gone]
      true
    end
  end

  def test_a_pod_whose_sandbox_is_gone_finishes_its_network_cleanup
    calls = []
    runtime = GoneSandboxRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, volume: NodeLifecycleTest::Volume.new(calls),
                                                network: RecordingNetwork.new(calls))
    object = pod
    lifecycle.start(object)
    runtime.gone = true
    result = lifecycle.terminate(object, reason: "StartupRecovery")

    assert_equal "Removed", result.state, result.inspect
    assert_empty Array(result.cleanup_errors)
    assert_equal([[:network_delete, "sandbox-1", true]],
                 calls.select { |call| Array(call).first == :network_delete })
  end

  # After a host reboot every container of the stored records is gone.
  class GoneContainerRuntime < GoneSandboxRuntime
    def stop_container(id, timeout:)
      raise StandardError, "unknown container #{id}" if gone

      super
    end
  end

  def test_a_container_the_runtime_lost_is_not_waited_for
    calls = []
    slept = []
    runtime = GoneContainerRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, volume: NodeLifecycleTest::Volume.new(calls),
                                                network: NodeLifecycleTest::Network.new(calls),
                                                sleeper: ->(seconds) { slept << seconds })
    object = pod
    lifecycle.start(object)
    runtime.gone = true
    slept.clear
    result = lifecycle.terminate(object, reason: "StartupRecovery")

    assert_equal "Removed", result.state, result.inspect
    # The grace period (30 s by default, 300 s for ingress-nginx) is for a
    # process that can still exit; there is none.
    assert_empty slept.select { |seconds| seconds >= 1 }, slept.inspect
  end

  # The holder of a sandbox died with the previous agent: the runtime has
  # no sandbox, so no container can be re-created in it.  The Pod must be
  # killed and synced from scratch (kubelet: pod sandbox changed), not
  # "restarted" into the void every backoff period.
  class GoneOnRestartRuntime < GoneContainerRuntime
    def create_container(sandbox, spec)
      raise StandardError, "unknown sandbox #{sandbox}" if gone

      super
    end
  end

  class StoppedSandboxRuntime < NodeLifecycleTest::Runtime
    attr_writer :sandbox_state

    def run_sandbox(pod, **options)
      super
      "sandbox-#{@calls.count { |call| call.first == :sandbox }}"
    end

    def sandbox_state(_id) = @sandbox_state
  end

  def test_a_restart_into_a_lost_sandbox_kills_the_pod
    calls = []
    runtime = GoneOnRestartRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, volume: NodeLifecycleTest::Volume.new(calls),
                                                network: NodeLifecycleTest::Network.new(calls),
                                                sleeper: ->(_seconds) {})
    object = pod
    lifecycle.start(object)
    record = lifecycle.instance_variable_get(:@records).values.first
    runtime.gone = true

    lifecycle.handle_container_exit(object, container_name: "app", exit_code: 1)
    lifecycle.send(:resume_backoff_restarts, record, object, now: Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3600)

    assert_includes %w[Removed Stopped], record[:state], record.inspect
    refute_empty calls.select { |call| Array(call).first == :network_delete }, "the sandbox must be torn down"
  end

  def test_replacement_of_a_stopped_cri_sandbox_keeps_the_pod_volume_and_restarts_init
    calls = []
    runtime = StoppedSandboxRuntime.new
    volume = NodeLifecycleTest::Volume.new(calls)
    object = pod
    object["spec"]["initContainers"] = [{"name" => "setup", "image" => "example/init"}]
    Dir.mktmpdir do |directory|
      options = {runtime: runtime, volume: volume, state_store: File.join(directory, "state.json")}
      original = lifecycle_at_boot("boot-one", **options)

      assert_equal "Running", original.start(object).phase

      runtime.sandbox_state = :stopped
      stopped = original.reconcile(object)

      assert_equal %w[Removed Pending], [stopped.state, stopped.phase]
      assert_equal [:volume_prepare], calls

      runtime.sandbox_state = :ready
      recovered = lifecycle_at_boot("boot-one", **options)
      replacement = recovered.reconcile(object)

      assert_equal "Running", replacement.phase
      assert_equal [:volume_prepare], calls
      assert_includes runtime.calls, [:sandbox_remove, "sandbox-1"]
      assert_equal 1, replacement.status.fetch("initContainerStatuses").first.fetch("restartCount")
      assert_equal 1, replacement.status.fetch("containerStatuses").first.fetch("restartCount")

      recovered.terminate(object)

      assert_equal [:volume_prepare, [:volume_release, "volume-1"]], calls
    end
  end

  def test_a_sandbox_marked_for_replacement_is_rebuilt_by_the_next_sync
    calls = []
    runtime = StoppedSandboxRuntime.new
    runtime.sandbox_state = :ready
    object = pod
    Dir.mktmpdir do |directory|
      lifecycle = lifecycle_at_boot("boot-one", runtime: runtime, volume: NodeLifecycleTest::Volume.new(calls),
                                                state_store: File.join(directory, "state.json"))

      assert_equal "Running", lifecycle.start(object).phase
      refute lifecycle.replace_sandbox("no-such-sandbox", message: "unused")
      assert lifecycle.replace_sandbox("sandbox-1", message: "network attachment could not be confirmed after restart")

      assert_equal "Removed", lifecycle.reconcile(object).state
      assert_includes runtime.calls, [:sandbox_remove, "sandbox-1"]

      replacement = lifecycle.reconcile(object)

      assert_equal "Running", replacement.phase
      assert_equal 1, replacement.status.fetch("containerStatuses").first.fetch("restartCount")
    end
  end

  def test_sandbox_replacement_after_a_kernel_reboot_prepares_volumes_again
    calls = []
    runtime = StoppedSandboxRuntime.new
    volume = NodeLifecycleTest::Volume.new(calls)
    object = pod
    Dir.mktmpdir do |directory|
      options = {runtime: runtime, volume: volume, state_store: File.join(directory, "state.json")}
      lifecycle_at_boot("boot-one", **options).start(object)
      runtime.sandbox_state = :stopped
      recovered = lifecycle_at_boot("boot-two", **options)

      assert_equal "Removed", recovered.reconcile(object).state
      assert_equal [:volume_prepare, [:volume_release, "volume-1"]], calls

      runtime.sandbox_state = :ready

      assert_equal "Running", recovered.reconcile(object).phase
      assert_equal [:volume_prepare, [:volume_release, "volume-1"], :volume_prepare], calls
    end
  end

  def test_reconciliation_does_not_replace_a_sandbox_before_its_removal_finishes
    runtime = StoppedSandboxRuntime.new
    removing = Queue.new
    release = Queue.new
    runtime.define_singleton_method(:remove_sandbox) do |sandbox|
      removing << sandbox
      release.pop
      super(sandbox)
    end
    object = pod
    lifecycle = lifecycle_at_boot("boot-one", runtime: runtime)
    lifecycle.start(object)
    runtime.sandbox_state = :stopped
    cleanup = Thread.new { lifecycle.reconcile(object) }

    assert_equal "sandbox-1", removing.pop(timeout: 5)
    assert_equal "Stopped", lifecycle.reconcile(object).state
    assert_equal(1, runtime.calls.count { |call| call.first == :sandbox })

    release << true
    cleanup.value
    runtime.sandbox_state = :ready

    assert_equal "Running", lifecycle.reconcile(object).phase
    assert_equal(2, runtime.calls.count { |call| call.first == :sandbox })
  ensure
    release&.close
    cleanup&.join
  end

  def test_a_pending_pod_cleanup_does_not_keep_the_agent_down
    service = Rubernetes::Bootstrap::AgentService.allocate
    report = {"ready" => true, "errors" => [], "blocked" => ["3229d668-uid"],
              "pod_errors" => {"3229d668-uid" => ["network cleanup failed"]}}

    assert_equal true, service.send(:ensure_recovery_ready!, report)
    error = assert_raises(Rubernetes::Bootstrap::AgentService::Error) do
      service.send(:ensure_recovery_ready!, {"ready" => false, "errors" => ["resource identity mismatch: cgroup:x"], "blocked" => []})
    end
    assert_match(/identity mismatch/, error.message)
  end

  private

  def lifecycle_at_boot(boot, **)
    lifecycle = Rubernetes::Node::Lifecycle.new(**)
    lifecycle.define_singleton_method(:kernel_boot_id) { boot }
    lifecycle
  end

  def pod
    NodeLifecycleTest.new("x").send(:pod)
  end
end
