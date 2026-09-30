# frozen_string_literal: true

require "tmpdir"

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/native"
require "rubernetes/platform/linux/process_supervisor"

class M2NodeRecoverySemanticsTest < Minitest::Test
  class ImageResolver
    attr_reader :resolved

    def initialize
      @resolved = []
    end

    def resolve(reference)
      @resolved << reference
      {
        "reference" => reference,
        "digest" => "sha256:#{"a" * 64}",
        "rootfs" => "/tmp/rootfs"
      }
    end

    def release(_image)
      true
    end
  end

  class Runtime
    attr_reader :calls, :created_specs
    attr_accessor :wait_result, :fail_sandbox_remove, :stop_result, :stuck

    def initialize(wait_result: {"state" => "terminated", "exitCode" => 0})
      @calls = []
      @created_specs = []
      @counter = 0
      @wait_result = wait_result
      @fail_sandbox_remove = false
      @stop_result = true
      @stuck = false
    end

    def run_sandbox(_pod, runtime_class: nil)
      @calls << [:sandbox, runtime_class]
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      @created_specs << spec
      @counter += 1
      "container-#{@counter}"
    end

    def start_container(id)
      @calls << [:start, id]
      true
    end

    def wait_container(id)
      @calls << [:wait, id]
      @wait_result
    end

    def stop_container(id, timeout:)
      @calls << [:stop, id, timeout]
      @stop_result
    end

    def container_status(id)
      @calls << [:status, id]
      {"id" => id, "state" => @stuck ? "running" : "stopped"}
    end

    def kill_container(id, signal:)
      @calls << [:kill, id, signal]
      true
    end

    def remove_container(id)
      @calls << [:remove, id]
      true
    end

    def remove_sandbox(id)
      @calls << [:sandbox_remove, id]
      raise "sandbox cleanup is temporarily unavailable" if @fail_sandbox_remove

      true
    end
  end

  class PidfdProcess
    def spawn(**_options)
      {pid: 1234, pidfd: 77, gate: nil, stdout: nil, stderr: nil}
    end

    def release_gate(_gate)
      true
    end

    def wait(pid:, timeout: nil)
      {"exit_status" => 0, "term_signal" => nil, "code" => 0}
    end

    def signal(pid:, signal:)
      true
    end
  end

  class PidfdAdapter
    attr_accessor :alive, :wait_result

    def initialize
      @alive = true
      @wait_result = nil
    end

    def alive?(pidfd:)
      @alive
    end

    def wait(pidfd:, timeout:, resource_id:)
      @wait_result
    end

    def send_signal(pidfd:, signal:, resource_id:)
      true
    end
  end

  def pod(init_containers: [], containers: [{"name" => "app", "image" => "example/app"}], **spec)
    {
      "metadata" => {"name" => "demo", "namespace" => "default", "uid" => "pod-1"},
      "spec" => {"initContainers" => init_containers, "containers" => containers}.merge(spec)
    }
  end

  def test_restartable_init_uses_the_pinned_source_image_key
    runtime = Runtime.new
    resolver = ImageResolver.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, image_resolver: resolver)

    result = lifecycle.start(pod(
      init_containers: [{"name" => "sidecar", "image" => "example/sidecar", "restartPolicy" => "Always"}]
    ))

    assert_equal "Running", result.phase
    assert_equal ["example/sidecar", "example/app"], resolver.resolved
    assert_equal "example/sidecar", runtime.created_specs.first.fetch("resolved_image").fetch("reference")
    assert_equal "example/app", runtime.created_specs.last.fetch("resolved_image").fetch("reference")
  end

  def test_missing_init_wait_is_not_treated_as_exit_zero
    runtime = Runtime.new(wait_result: nil)
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)

    result = lifecycle.start(pod(init_containers: [{"name" => "prepare", "image" => "example/init"}]))

    # An init container whose exit could not be confirmed is a failed start
    # attempt: kubelet keeps the Pod Pending and retries, it never reports
    # the init container as having succeeded.
    assert_equal "Pending", result.phase
    assert_match(/init container/, result.error)
    assert_equal "Removed", result.state
  end

  def test_cleanup_failure_is_durable_and_retried_after_stop_confirmation
    runtime = Runtime.new
    runtime.fail_sandbox_remove = true
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    object = pod
    lifecycle.start(object)

    pending = lifecycle.terminate(object)

    assert_equal "CleanupPending", pending.state
    assert_equal "Unknown", pending.phase
    assert_equal [{"kind" => "sandbox", "id" => "sandbox-1"}], pending.resources
    assert_match(/sandbox cleanup failed/, pending.cleanup_errors.join(" "))

    runtime.fail_sandbox_remove = false
    removed = lifecycle.terminate(object)

    assert_equal "Removed", removed.state
    assert_equal "Succeeded", removed.phase
    assert_empty removed.resources
  end

  def test_cleanup_does_not_remove_a_workload_without_stop_confirmation
    runtime = Runtime.new
    runtime.stop_result = false
    runtime.stuck = true
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_seconds) {})
    object = pod
    lifecycle.start(object)

    pending = lifecycle.terminate(object)

    assert_equal "CleanupPending", pending.state
    assert_equal [{"kind" => "sandbox", "id" => "sandbox-1"}], pending.resources
    refute(runtime.calls.any? { |call| call.first == :remove })

    runtime.stop_result = true
    runtime.stuck = false
    removed = lifecycle.terminate(object)

    assert_equal "Removed", removed.state
    assert_empty removed.resources
  end

  def test_probe_scheduler_honors_delay_period_timeout_and_failure_threshold
    runtime = Class.new do
      attr_reader :timeouts

      def initialize
        @timeouts = []
      end

      def exec(_container_id, _command, tty:, timeout:)
        @timeouts << timeout
        1
      end
    end.new
    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime)
    probe = {
      "exec" => {"command" => ["/health"]},
      "initialDelaySeconds" => 5,
      "periodSeconds" => 10,
      "timeoutSeconds" => 7,
      "failureThreshold" => 2
    }
    manager.register("container-1", probes: {"livenessProbe" => probe}, started_at: 0.0)

    deferred = manager.check("container-1", probe: probe, type: "liveness", now: 4.0)

    assert deferred.deferred
    assert_empty runtime.timeouts

    first = manager.check("container-1", probe: probe, type: "liveness", now: 5.0)

    assert_predicate first, :failed?
    assert_equal [7], runtime.timeouts
    refute manager.liveness_failed?("container-1")

    deferred = manager.check("container-1", probe: probe, type: "liveness", now: 10.0)

    assert deferred.deferred
    assert_equal [7], runtime.timeouts

    second = manager.check("container-1", probe: probe, type: "liveness", now: 15.0)

    assert_predicate second, :failed?
    assert_equal [7, 7], runtime.timeouts
    assert manager.liveness_failed?("container-1")
  end

  def test_lifecycle_state_store_restores_request_identity_and_running_record
    Dir.mktmpdir("node-state") do |directory|
      path = File.join(directory, "node-state.json")
      object = pod
      first = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, state_store: path)
      first_result = first.start(object, request_id: "request-42")
      first_id = first.record(object).fetch(:containers).first.fetch(:id)
      first.probes.register("probe-42", probes: {"livenessProbe" => {"exec" => {"command" => ["/health"]}}}, started_at: 0.0)
      first.probes.check("probe-42", type: "liveness", probe: {"exec" => {"command" => ["/health"]}}, now: 0.0)
      first.restarts.record_exit("pod-1/app", policy: "Always", exit_code: 1, at: 0.0)
      first.send(:persist_state!)

      second = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, state_store: path)
      restored = second.record(object)

      assert_equal "Running", first_result.state
      assert_equal "Running", restored.fetch(:state)
      assert_equal "request-42", restored.fetch(:request_id)
      assert_equal first_id, restored.fetch(:containers).first.fetch(:id)
      assert_equal 1, second.probes.failure_count("probe-42", type: "liveness")
      assert_equal "WaitingForRestart", second.restarts.state("pod-1/app")
      assert_equal first_result.pod_uid, second.start(object).pod_uid
      assert_equal first_id, second.record(object).fetch(:containers).first.fetch(:id)
    end
  end

  def test_state_store_rejects_duplicate_json_keys
    Dir.mktmpdir("node-state") do |directory|
      path = File.join(directory, "node-state.json")
      File.binwrite(path, "{\"records\":[],\"records\":[]}\n")

      assert_raises(Rubernetes::Node::Lifecycle::Error) do
        Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, state_store: path)
      end
    end
  end

  def test_native_recovery_requires_an_explicit_observer
    Dir.mktmpdir("native-observer") do |directory|
      runtime = Rubernetes::Runtime::Native.new(journal_path: File.join(directory, "journal.wal"))

      assert_raises(Rubernetes::Runtime::RecoveryRequired) { runtime.recover }
    end
  end

  def test_native_request_replay_after_restart_uses_the_durable_sandbox_identity
    Dir.mktmpdir("native-replay") do |directory|
      path = File.join(directory, "journal.wal")
      first_journal = Rubernetes::Runtime::Native::RollbackJournal.new(path, fsync: false)
      first = Rubernetes::Runtime::Native.new(profile: :pure, journal: first_journal)
      sandbox_id = first.run_sandbox({"request_id" => "durable-request"})

      second_journal = Rubernetes::Runtime::Native::RollbackJournal.new(path, fsync: false)
      second = Rubernetes::Runtime::Native.new(profile: :pure, journal: second_journal)

      assert_equal sandbox_id, second.run_sandbox({"request_id" => "durable-request"})
      assert_equal 1, second.ledger.operations.length
    end
  end

  def test_pidfd_liveness_requires_a_matching_exit_confirmation
    pidfd = PidfdAdapter.new
    supervisor = Rubernetes::Platform::Linux::ProcessSupervisor.new(
      process_adapter: PidfdProcess.new, pidfd_adapter: pidfd
    )
    handle = supervisor.spawn(command: ["/bin/true"])

    assert supervisor.alive?(handle)
    pidfd.alive = false
    assert_raises(Rubernetes::Platform::Linux::ProcessSupervisor::Error) { supervisor.alive?(handle) }

    pidfd.wait_result = {"exit_status" => 0, "term_signal" => nil, "code" => 0}

    refute supervisor.alive?(handle)
    assert handle.stopped? || supervisor.handles.fetch(handle.id).stopped?
  end

  def test_process_wait_rejects_a_result_without_exit_status_or_signal
    pidfd = PidfdAdapter.new
    pidfd.wait_result = {"code" => 0}
    supervisor = Rubernetes::Platform::Linux::ProcessSupervisor.new(
      process_adapter: PidfdProcess.new, pidfd_adapter: pidfd
    )
    handle = supervisor.spawn(command: ["/bin/true"])

    assert_raises(Rubernetes::Platform::Linux::ProcessSupervisor::Error) { supervisor.wait(handle, timeout: 0) }
  end
end
