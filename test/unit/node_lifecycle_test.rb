# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeLifecycleTest < Minitest::Test
  class Runtime
    attr_reader :calls

    def initialize(fail_container: nil, stop_result: true)
      @calls = []
      @counter = 0
      @fail_container = fail_container
      @stop_result = stop_result
    end

    def run_sandbox(_pod, runtime_class: nil)
      @calls << [:sandbox, runtime_class]
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      name = spec.fetch("name")
      @calls << [:create, name]
      raise "create failed for #{name}" if name == @fail_container

      @counter += 1
      "container-#{@counter}"
    end

    def start_container(id)
      @calls << [:start, id]
      true
    end

    def wait_container(id)
      @calls << [:wait, id]
      {"state" => "terminated", "exitCode" => 0}
    end

    def exec(id, command, tty: false)
      @calls << [:exec, id, command, tty]
      true
    end

    def signal(id, signal)
      @calls << [:signal, id, signal]
      true
    end

    def stop_container(id, timeout:)
      @calls << [:stop, id, timeout]
      @stop_result
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
      true
    end
  end

  class NetworkContextRuntime < Runtime
    def network_sandbox_context(id)
      {
        "sandbox_id" => id,
        "netns" => {
          "handle" => "namespace:#{id}",
          "path" => "/proc/4242/ns/net",
          "inode" => 4_026_531_842,
          "pid" => 4242
        }
      }
    end
  end

  class Volume
    attr_reader :calls

    def initialize(calls)
      @calls = calls
    end

    def prepare(_pod)
      @calls << :volume_prepare
      "volume-1"
    end

    def release(id)
      @calls << [:volume_release, id]
      true
    end
  end

  class Network
    attr_reader :calls

    def initialize(calls)
      @calls = calls
    end

    def add(sandbox, _pod)
      @calls << [:network_add, sandbox]
      "network-1"
    end

    def delete(sandbox)
      @calls << [:network_delete, sandbox]
      true
    end
  end

  class EndpointManager
    attr_reader :calls

    def initialize
      @calls = []
    end

    def remove(uid)
      @calls << [:remove, uid]
    end

    def set_ready(uid, value)
      @calls << [:ready, uid, value]
    end
  end

  def pod(containers: [{"name" => "app", "image" => "example/app"}], init_containers: [], **spec)
    {
      "apiVersion" => "v1",
      "kind" => "Pod",
      "metadata" => {"name" => "demo", "namespace" => "default", "uid" => "pod-1"},
      "spec" => {"nodeName" => "node-1", "containers" => containers, "initContainers" => init_containers}.merge(spec)
    }
  end

  def test_start_runs_volume_sandbox_network_init_sidecar_then_app
    calls = []
    runtime = Runtime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      volume: Volume.new(calls),
      network: Network.new(calls),
      sleeper: ->(seconds) { calls << [:sleep, seconds] }
    )
    result = lifecycle.start(
      pod(
        init_containers: [
          {"name" => "prepare", "image" => "example/prepare"},
          {"name" => "sidecar", "image" => "example/sidecar", "restartPolicy" => "Always"}
        ]
      )
    )

    assert_equal "Running", result.phase
    assert_equal :volume_prepare, calls.first
    assert_equal [:network_add, "sandbox-1"], calls[1]
    assert_equal [[:create, "prepare"], [:start, "container-1"], [:wait, "container-1"],
                  [:create, "sidecar"], [:start, "container-2"], [:create, "app"], [:start, "container-3"]],
                 runtime.calls.drop(1)
  end

  def test_resync_ignores_server_metadata_and_status_but_restarts_for_spec_change
    runtime = Runtime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    desired = pod
    lifecycle.start(desired)
    effects_after_start = runtime.calls.dup

    resync = Marshal.load(Marshal.dump(desired))
    resync.fetch("metadata").merge!(
      "resourceVersion" => "99",
      "managedFields" => [{"manager" => "node-agent"}],
      "creationTimestamp" => "2026-08-24T00:00:00Z"
    )
    resync["status"] = {"phase" => "Running", "podIP" => "10.0.0.2"}
    result = lifecycle.reconcile(resync)

    assert_equal "Running", result.state
    assert_equal effects_after_start, runtime.calls

    changed = Marshal.load(Marshal.dump(resync))
    changed.fetch("spec").fetch("containers").fetch(0)["command"] = ["/bin/changed"]
    lifecycle.reconcile(changed)

    assert_operator runtime.calls.count { |call| call.first == :sandbox }, :>, 1
    assert_includes runtime.calls.map(&:first), :stop
  end

  # A Pod that ran to completion under restartPolicy: Never is finished.  A
  # resync that re-creates it allocates a new sandbox and a new image staging
  # directory every time, so the node fills its own disk while the API server
  # still reports the Pod as Succeeded.
  def test_resync_does_not_recreate_a_finished_pod
    runtime = Runtime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    desired = pod
    desired.fetch("spec")["restartPolicy"] = "Never"
    lifecycle.start(desired)
    sandboxes_after_start = runtime.calls.count { |call| call.first == :sandbox }

    finished = Marshal.load(Marshal.dump(desired))
    finished["status"] = {"phase" => "Succeeded"}
    lifecycle.reconcile(finished)
    lifecycle.reconcile(finished)

    assert_equal(sandboxes_after_start, runtime.calls.count { |call| call.first == :sandbox },
                 "a finished Pod must not be started again")
  end

  def test_network_receives_and_reuses_native_namespace_context_for_add_and_delete
    calls = []
    runtime = NetworkContextRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      volume: Volume.new(calls),
      network: Network.new(calls)
    )

    lifecycle.start(pod)
    lifecycle.terminate(pod)

    expected = {
      "sandbox_id" => "sandbox-1",
      "netns" => {
        "handle" => "namespace:sandbox-1",
        "path" => "/proc/4242/ns/net",
        "inode" => 4_026_531_842,
        "pid" => 4242
      }
    }

    assert_includes calls, [:network_add, expected]
    assert_includes calls, [:network_delete, expected]
  end

  def test_admission_rejection_has_no_effects
    runtime = Runtime.new
    calls = []
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      volume: Volume.new(calls),
      network: Network.new(calls),
      admission: ->(_pod) { {"allowed" => false, "reason" => "OutOfcpu", "message" => "full"} }
    )

    result = lifecycle.start(pod)

    assert_equal "Failed", result.phase
    assert_match(/admission rejected/, result.error)
    assert_empty runtime.calls
    assert_empty calls
  end

  def test_failure_rolls_back_acquired_resources_in_reverse_order
    calls = []
    runtime = Runtime.new(fail_container: "app")
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      volume: Volume.new(calls),
      network: Network.new(calls),
      sleeper: ->(_seconds) {}
    )

    result = lifecycle.start(pod)

    # kubelet keeps a Pod whose container could not be created Pending and
    # retries after a backoff; only admission rejections are terminal.
    assert_equal "Pending", result.phase
    assert_match(/app/, result.error)
    assert_empty result.cleanup_errors
    assert_equal [:volume_prepare, [:network_add, "sandbox-1"],
                  [:network_delete, "sandbox-1"], [:volume_release, "volume-1"]], calls
    assert_equal [[:sandbox, nil], [:create, "app"], [:sandbox_remove, "sandbox-1"]], runtime.calls
    assert_equal "Removed", result.state
  end

  def test_termination_runs_prestop_term_grace_kill_then_reverse_cleanup
    calls = []
    runtime = Runtime.new(stop_result: false)
    lifecycle = Rubernetes::Node::Lifecycle.new(
      runtime: runtime,
      volume: Volume.new(calls),
      network: Network.new(calls),
      sleeper: ->(seconds) { calls << [:sleep, seconds] }
    )
    object = pod(
      containers: [{
        "name" => "app", "image" => "example/app",
        "lifecycle" => {"preStop" => {"exec" => {"command" => ["/bin/drain"]}}}
      }],
      terminationGracePeriodSeconds: 2
    )
    lifecycle.start(object)
    result = lifecycle.terminate(object)

    # kubelet getPhase for a terminal Pod: a container that ignored SIGTERM
    # and was SIGKILLed after the grace period exits 137, so the Pod is Failed.
    assert_equal "Failed", result.phase
    assert_equal 137, result.status.fetch("containerStatuses").first.dig("state", "terminated", "exitCode")
    assert_equal [[:start, "container-1"], [:exec, "container-1", ["/bin/drain"], false],
                  [:signal, "container-1", "TERM"], [:stop, "container-1", 2],
                  [:kill, "container-1", "KILL"], [:remove, "container-1"],
                  [:sandbox_remove, "sandbox-1"]], runtime.calls.drop(2)
    assert_equal [[:network_delete, "sandbox-1"], [:volume_release, "volume-1"]], calls.last(2)
  end
end
