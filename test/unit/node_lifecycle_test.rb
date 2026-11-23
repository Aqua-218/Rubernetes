# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "tmpdir"

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

  class RuntimeOwnedNetwork < Runtime
    attr_accessor :ips

    def sandbox_network_ips(id)
      @calls << [:runtime_network_ips, id]
      ips
    end
  end

  class InitializingRuntime < Runtime
    attr_reader :waiting

    def initialize
      super
      @waiting = Queue.new
      @release = Queue.new
    end

    def wait_container(id, timeout: nil)
      @waiting << id
      return super(id) if @release.pop(timeout: timeout)

      {"state" => "running", "exitCode" => nil}
    end

    def release_wait
      @release << true
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

  def test_runtime_owned_network_addresses_are_refreshed_and_persisted_without_network_ownership
    runtime = RuntimeOwnedNetwork.new
    workload = pod
    Dir.mktmpdir do |directory|
      state = File.join(directory, "lifecycle.json")
      lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, state_store: state)
      initial = lifecycle.start(workload)

      assert_nil initial.status["podIP"]
      runtime.ips = %w[10.1.0.8 fd00::2]

      updated = lifecycle.reconcile(workload)

      assert_equal "10.1.0.8", updated.status["podIP"]
      assert_equal [{"ip" => "10.1.0.8"}, {"ip" => "fd00::2"}], updated.status["podIPs"]
      refute(lifecycle.record("pod-1").fetch(:resources).any? { |resource| resource["kind"] == "network" })

      restarted = Rubernetes::Node::Lifecycle.new(runtime: runtime, state_store: state)

      assert_equal runtime.ips, restarted.pod_ips(restarted.record("pod-1"))
    end
  end

  def test_node_owned_network_does_not_lookup_runtime_addresses
    runtime = RuntimeOwnedNetwork.new
    attached = Network.new([])
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, network: attached)

    lifecycle.start(pod)

    assert_includes attached.calls, [:network_add, "sandbox-1"]
    refute_includes runtime.calls, [:runtime_network_ips, "sandbox-1"]
  end

  def test_missing_mounted_source_reports_the_pod_volume_name
    runtime = Runtime.new
    reader = Object.new
    reader.define_singleton_method(:get) { |*| nil }
    volumes = Rubernetes::Node::PodVolumes.new(volume: Object.new, reader: reader)
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, pod_volumes: volumes)
    container = {"name" => "app", "image" => "example/app", "volumeMounts" => [{"name" => "mount", "mountPath" => "/config"}]}
    source = {"name" => "mount", "configMap" => {"name" => "missing-config"}}
    result = lifecycle.start(pod(containers: [container], "volumes" => [source]))
    event = result.events.find { |candidate| candidate["type"] == "volume.failed" }

    assert_equal "Pending", result.phase
    assert_equal "FailedMount", event["reason"]
    assert_equal 'MountVolume.SetUp failed for volume "mount": configmap "missing-config" not found', event["message"]
    assert_empty runtime.calls
  end

  def test_allow_privilege_escalation_stays_unspecified_unless_set
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, container_spec: Rubernetes::Node::ContainerSpec.new)
    containers = [
      {"name" => "default", "image" => "example/app"},
      {"name" => "denied", "image" => "example/app", "securityContext" => {"allowPrivilegeEscalation" => false}},
      {"name" => "allowed", "image" => "example/app", "securityContext" => {"allowPrivilegeEscalation" => true}}
    ]
    workload = pod(containers: containers)
    result = lifecycle.start(workload)
    contexts = lifecycle.record(workload).fetch(:containers).map { |entry| entry.dig(:spec, "security_context") }

    assert_equal "Running", result.phase
    refute contexts.first.key?("allowPrivilegeEscalation")
    assert_equal false, contexts[1].fetch("allowPrivilegeEscalation")
    assert_equal true, contexts[2].fetch("allowPrivilegeEscalation")
  end

  def test_host_network_uses_both_node_ips_for_status_and_downward_environment
    runtime = Runtime.new
    specs = []
    runtime.define_singleton_method(:create_container) do |sandbox, spec|
      specs << spec
      super(sandbox, spec)
    end
    addresses = %w[10.240.0.1 fd00:d8::1]
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, container_spec: Rubernetes::Node::ContainerSpec.new, host_ips: addresses)
    container = {"name" => "app", "image" => "example/app", "env" => %w[hostIP hostIPs podIP podIPs].map do |field|
      {"name" => field, "valueFrom" => {"fieldRef" => {"fieldPath" => "status.#{field}"}}}
    end}
    result = lifecycle.start(pod(containers: [container], "hostNetwork" => true))
    status = result.status.to_h
    environment = specs.fetch(0).fetch("env").to_h { |entry| entry.values_at("name", "value") }

    assert_equal addresses.first, status.fetch("podIP")
    assert_equal addresses.first, status.fetch("hostIP")
    assert_equal(addresses, status.fetch("podIPs").map { |entry| entry.fetch("ip") })
    assert_equal(addresses, status.fetch("hostIPs").map { |entry| entry.fetch("ip") })
    assert_equal [addresses.first, addresses.join(","), addresses.first, addresses.join(",")], environment.values_at("hostIP", "hostIPs", "podIP", "podIPs")
  end

  def test_a_graceful_deletion_releases_a_pod_worker_waiting_for_init
    assert_init_cancelled(expect_terminal_status: true) do |sync, object|
      object.fetch("metadata")["deletionTimestamp"] = "2026-11-18T12:00:00Z"
      sync.process_event("type" => "MODIFIED", "object" => object)
    end
  end

  def test_observes_a_completed_init_image_change_queued_during_failed_application_replacement
    runtime = Runtime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    initial = pod(init_containers: [{"name" => "prepare", "image" => "example/init"}])
    initial.fetch("metadata")["generation"] = 3
    lifecycle.start(initial)

    replacement = Marshal.load(Marshal.dump(initial))
    replacement.fetch("metadata")["generation"] = 4
    replacement.dig("spec", "containers", 0)["image"] = "example/broken"
    latest = Marshal.load(Marshal.dump(replacement))
    latest.fetch("metadata")["generation"] = 5
    latest.dig("spec", "initContainers", 0)["image"] = "example/does-not-run-again"
    lifecycle.desired_pod_lookup = ->(_uid) { latest }
    runtime.instance_variable_set(:@fail_container, "app")
    result = lifecycle.reconcile(replacement)

    assert_equal "Pending", result.phase
    assert_equal 5, result.status.fetch("observedGeneration")
    assert_equal 1, runtime.calls.count([:create, "prepare"])
  end

  def test_init_completion_adopts_the_latest_watched_application_image_before_first_start
    runtime = InitializingRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    workers = Rubernetes::Node::PodWorkerPool.new(reconcile: lifecycle.method(:reconcile))
    sync = Rubernetes::Node::SyncLoop.new(source: Object.new, worker_pool: workers, removed: lifecycle.method(:pod_removed))
    lifecycle.desired_pod_lookup = sync.method(:cached_pod)
    object = pod(init_containers: [{"name" => "prepare", "image" => "example/prepare"}])
    sync.process_event("type" => "ADDED", "object" => object)

    assert_equal "container-1", runtime.waiting.pop(timeout: 2)

    %w[v2 v3].each do |tag|
      object.fetch("spec").fetch("containers").first["image"] = "example/app:#{tag}"
      sync.process_event("type" => "MODIFIED", "object" => object)
    end
    runtime.release_wait

    assert workers.drain(timeout: 2)

    record = lifecycle.record("pod-1")
    created = runtime.calls.select { |call| call.first == :create }
    sandboxes = runtime.calls.count { |call| call.first == :sandbox }

    assert_equal [[:create, "prepare"], [:create, "app"]], created
    assert_equal 1, sandboxes
    assert_equal "example/app:v3", record.dig(:status, "containerStatuses", 0, "image")
    assert_equal 0, record.dig(:status, "containerStatuses", 0, "restartCount")
  ensure
    runtime&.release_wait
    workers&.stop(drain: false, timeout: 2)
  end

  def test_running_sidecar_is_updated_while_ordinary_init_is_still_waiting
    runtime = InitializingRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    workers = Rubernetes::Node::PodWorkerPool.new(reconcile: lifecycle.method(:reconcile))
    sync = Rubernetes::Node::SyncLoop.new(source: Object.new, worker_pool: workers, removed: lifecycle.method(:pod_removed))
    lifecycle.desired_pod_lookup = sync.method(:cached_pod)
    object = pod(init_containers: [{"name" => "sidecar", "image" => "example/sidecar:v1", "restartPolicy" => "Always"},
                                   {"name" => "prepare", "image" => "example/prepare"}])
    sync.process_event("type" => "ADDED", "object" => object)

    assert_equal "container-2", runtime.waiting.pop(timeout: 2)

    object.dig("spec", "initContainers", 0)["image"] = "example/sidecar:v2"
    object.dig("spec", "containers", 0)["image"] = "example/app:v2"
    sync.process_event("type" => "MODIFIED", "object" => object)
    Timeout.timeout(2) do
      sleep 0.01 until lifecycle.record("pod-1").dig(:status, "initContainerStatuses", 0, "restartCount") == 1
    end

    assert_equal "example/sidecar:v2", lifecycle.record("pod-1").dig(:status, "initContainerStatuses", 0, "image")
    refute_includes runtime.calls, [:create, "app"]
    assert_equal 1, runtime.calls.count([:create, "prepare"])

    runtime.release_wait

    assert workers.drain(timeout: 2)
    assert_equal "example/app:v2", lifecycle.record("pod-1").dig(:status, "containerStatuses", 0, "image")
  ensure
    runtime&.release_wait
    workers&.stop(drain: false, timeout: 2)
  end

  def test_container_status_reports_the_manifest_digest_used_by_native_runtime
    digest = "sha256:#{"ab" * 32}"
    image = "example/app:v1"
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |reference| {"reference" => reference, "digest" => digest} }
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, image_resolver: resolver)
    result = lifecycle.start(pod(containers: [{"name" => "app", "image" => image}]))

    assert_equal("Running", result.phase, result.to_h.inspect)
    assert_equal(image, result.status.dig("containerStatuses", 0, "image"))
    assert_equal("docker.io/example/app@#{digest}", result.status.dig("containerStatuses", 0, "imageID"))
  end

  def test_image_volume_status_reports_the_digest_resolved_for_the_mount
    digest = "sha256:#{"ab" * 32}"
    image = "example/volume:latest"
    resolver = Object.new
    resolver.define_singleton_method(:resolve) { |reference| {"reference" => reference, "digest" => digest} }
    volumes = Object.new
    volumes.define_singleton_method(:attachable_volume_names) { |_pod| [] }
    volumes.define_singleton_method(:prepare) do |_pod, images:, **|
      raise "image volume was not pinned" unless images.dig(image, "digest") == digest

      {"ids" => ["volume"], "mounts" => {"image-data" => {"path" => "/image-data"}}}
    end
    object = pod(containers: [{"name" => "app", "image" => "example/app", "volumeMounts" => [
                   {"name" => "image-data", "mountPath" => "/data"}, {"name" => "empty", "mountPath" => "/empty"}
                 ]}], volumes: [{"name" => "image-data", "image" => {"reference" => image}}, {"name" => "empty", "emptyDir" => {}}])
    [true, false].each do |enabled|
      lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, pod_volumes: volumes,
                                                  image_resolver: resolver, image_volume_with_digest: enabled)
      result = lifecycle.start(object)

      assert_equal "Running", result.phase, result.to_h.inspect
      mounts = result.status.dig("containerStatuses", 0, "volumeMounts")
      actual = mounts.first.dig("volumeStatus", "image", "imageRef")
      enabled ? assert_equal(digest, actual) : assert_nil(actual)

      refute mounts.last.key?("volumeStatus")
    end
  end

  def test_a_watch_deletion_releases_a_pod_worker_waiting_for_init
    assert_init_cancelled { |sync, object| sync.process_event("type" => "DELETED", "object" => object) }
  end

  def test_a_relist_removal_releases_a_pod_worker_waiting_for_init
    assert_init_cancelled { |sync, _object| sync.resync }
  end

  def assert_init_cancelled(expect_terminal_status: false)
    runtime = InitializingRuntime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    workers = Rubernetes::Node::PodWorkerPool.new(reconcile: lifecycle.method(:reconcile))
    source = Object.new
    def source.list(**) = {"items" => []}

    sync = Rubernetes::Node::SyncLoop.new(source: source, worker_pool: workers, removed: lifecycle.method(:pod_removed))
    lifecycle.desired_pod_lookup = sync.method(:cached_pod)
    object = pod(init_containers: [{"name" => "prepare", "image" => "example/prepare"}])
    sync.process_event("type" => "ADDED", "object" => object)

    assert_equal "container-1", runtime.waiting.pop(timeout: 2)

    started_at = lifecycle.record("pod-1").dig(:status, "initContainerStatuses", 0, "state", "running", "startedAt")
    yield(sync, object)

    assert workers.drain(timeout: 2), "Pod worker is still waiting for the init container"
    assert_includes runtime.calls, [:remove, "container-1"]
    assert_includes runtime.calls, [:sandbox_remove, "sandbox-1"]
    refute_includes runtime.calls, [:create, "app"]
    return unless expect_terminal_status

    observation = lifecycle.record("pod-1").dig(:status, "initContainerStatuses", 0, "state", "terminated")

    assert_equal "container-1", observation.fetch("containerID")
    assert_equal started_at, observation.fetch("startedAt")
    assert_operator Time.iso8601(observation.fetch("finishedAt")), :>=, Time.iso8601(started_at)
  ensure
    runtime&.release_wait
    workers&.stop(drain: false, timeout: 2)
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
    assert_equal "OutOfcpu", result.status.fetch("reason")
    assert_equal "Pod was rejected: full", result.status.fetch("message")
    assert_match(/admission rejected/, result.error)
    assert_empty runtime.calls
    assert_empty calls
  end

  def test_native_rejects_requested_apparmor_before_creating_the_sandbox
    [false, true].each do |legacy|
      object = pod
      if legacy
        object["metadata"]["annotations"] = {"container.apparmor.security.beta.kubernetes.io/app" => "runtime/default"}
      else
        object.dig("spec", "containers", 0)["securityContext"] = {"appArmorProfile" => {"type" => "RuntimeDefault"}}
      end
      runtime = Runtime.new
      result = Rubernetes::Node::Lifecycle.new(runtime: runtime).start(object)

      assert_equal "Failed", result.phase
      assert_equal "AppArmor", result.status.fetch("reason")
      assert_match(/AppArmor/, result.status.fetch("message"))
      assert_empty runtime.calls
    end
  end

  def test_unavailable_ephemeral_apparmor_does_not_start_the_debug_container
    runtime = Runtime.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    object = pod
    lifecycle.start(object)
    debug = {"name" => "debug", "image" => "example/debug",
             "securityContext" => {"appArmorProfile" => {"type" => "RuntimeDefault"}}}
    object.fetch("spec")["ephemeralContainers"] = [debug]

    result = lifecycle.reconcile(object)

    assert_equal "Running", result.phase
    assert_equal "CreateContainerConfigError", result.status.dig("ephemeralContainerStatuses", 0, "state", "waiting", "reason")
    refute_includes runtime.calls, [:create, "debug"]
  end

  def test_status_only_readiness_gate_updates_change_pod_readiness
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new)
    object = pod
    gate = "example.test/ready"
    object["spec"]["readinessGates"] = [{"conditionType" => gate}]
    ready = ->(result) { result.status.fetch("conditions").find { |condition| condition["type"] == "Ready" }.fetch("status") }

    assert_equal "False", ready.call(lifecycle.start(object))

    completed = object.merge("status" => {"conditions" => [{"type" => gate, "status" => "True"}]})

    assert_equal "True", ready.call(lifecycle.reconcile(completed))
    assert_equal "False", ready.call(lifecycle.reconcile(object.merge("status" => {"conditions" => []})))
  end

  def test_failed_init_without_a_restart_keeps_its_terminated_container_until_deletion
    runtime = Runtime.new
    runtime.define_singleton_method(:wait_container) { |_id| {"state" => "terminated", "exitCode" => 42} }
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    object = pod(init_containers: [{"name" => "init", "image" => "example/init"}], restartPolicy: "Never")

    failed = lifecycle.start(object)

    assert_equal "Failed", failed.phase
    assert_nil failed.status["reason"]
    assert_equal 42, failed.status.fetch("initContainerStatuses").first.dig("state", "terminated", "exitCode")
    assert_equal [[:sandbox, nil], [:create, "init"], [:start, "container-1"]], runtime.calls
    assert_equal "Failed", lifecycle.reconcile(object).phase
    assert_equal "Failed", lifecycle.terminate(object).phase
    assert_includes runtime.calls, [:remove, "container-1"]
  end

  def test_failed_init_keeps_the_runtime_oom_reason
    runtime = Runtime.new
    runtime.define_singleton_method(:wait_container) do |_id|
      {"state" => "terminated", "exitCode" => 137, "signal" => 9, "reason" => "OOMKilled"}
    end
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    object = pod(init_containers: [{"name" => "init", "image" => "example/init"}], restartPolicy: "Never")

    result = lifecycle.start(object)

    assert_equal "Failed", result.phase
    assert_equal [137, "OOMKilled"], result.status.dig("initContainerStatuses", 0, "state", "terminated").values_at("exitCode", "reason")
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
        "readinessProbe" => {"exec" => {"command" => ["/bin/ready"]}, "periodSeconds" => 1},
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

  def test_regular_containers_reach_stop_concurrently_and_cleanup_waits_for_all
    runtime = Runtime.new
    stops = Queue.new
    stop_release = Queue.new
    runtime.define_singleton_method(:stop_container) do |id, timeout:|
      stops << [id, timeout]
      raise "test did not release the container" unless stop_release.pop(timeout: 7)

      super(id, timeout: timeout)
    end
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    containers = (1..4).map { |number| {"name" => "app-#{number}", "image" => "example/app"} }
    object = pod(containers: containers, terminationGracePeriodSeconds: 30)
    lifecycle.start(object)
    worker = Thread.new { lifecycle.terminate(object) }

    observed = Array.new(4) { stops.pop(timeout: 2) }

    assert_equal (1..4).map { |number| ["container-#{number}", 30] }, observed.compact.sort
    refute(runtime.calls.any? { |kind, _| %i[remove sandbox_remove].include?(kind) })

    4.times { stop_release << true }
    result = worker.value

    assert_equal "Removed", result.state
    assert_equal "Succeeded", result.phase
    assert_equal (1..4).map { |number| ["container-#{number}", 30] }, runtime.calls.filter_map { |kind, *arguments| arguments if kind == :stop }.sort
    assert_equal [:sandbox_remove, "sandbox-1"], runtime.calls.last
  ensure
    4.times { stop_release << true }
    worker&.join(2)
  end

  def test_regular_containers_stop_after_their_own_prestop_without_waiting_for_siblings
    runtime = Runtime.new
    hook_started = Queue.new
    hook_release = Queue.new
    stops = Queue.new
    runtime.define_singleton_method(:exec) do |*|
      hook_started << true
      hook_release.pop(timeout: 7)
      raise "drain hook failed"
    end
    runtime.define_singleton_method(:stop_container) do |id, timeout:|
      stops << id
      super(id, timeout: timeout)
    end
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    containers = [{"name" => "affected", "image" => "example/app", "lifecycle" => {"preStop" => {"exec" => {"command" => ["drain"]}}}},
                  {"name" => "other", "image" => "example/app"}]
    object = pod(containers: containers)
    lifecycle.start(object)
    worker = Thread.new { lifecycle.terminate(object) }

    assert hook_started.pop(timeout: 2), "preStop began"
    assert_equal "container-2", stops.pop(timeout: 2)

    hook_release << true
    result = worker.value

    assert_equal "container-1", stops.pop(timeout: 2)
    assert_equal "Removed", result.state
    assert(result.events.any? { |entry| entry["reason"] == "FailedPreStopHook" && entry["name"] == "affected" })
  ensure
    hook_release << true
    worker&.join(2)
  end

  def test_sidecar_hooks_run_together_before_regular_first_reverse_sidecar_stop
    runtime = Runtime.new
    hooks = Queue.new
    release_hooks = Queue.new
    runtime.define_singleton_method(:exec) do |id, _command, tty: false|
      hooks << id
      release_hooks.pop(timeout: 3)
    end
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    sidecars = %w[first second].map do |name|
      {"name" => name, "image" => "example/app", "restartPolicy" => "Always",
       "lifecycle" => {"preStop" => {"exec" => {"command" => ["prepare-stop"]}}}}
    end
    object = pod(init_containers: sidecars)
    lifecycle.start(object)
    worker = Thread.new { lifecycle.terminate(object) }

    assert_equal %w[container-1 container-2], [hooks.pop(timeout: 2), hooks.pop(timeout: 2)].compact.sort
    2.times { release_hooks << true }

    result = worker.value
    stopped = runtime.calls.filter_map { |kind, id| id if kind == :stop }

    assert_equal "Succeeded", result.phase
    assert_equal %w[container-3 container-2 container-1], stopped
  ensure
    2.times { release_hooks << true }
    worker&.join(2)
  end

  def test_a_failed_main_container_stop_waits_out_the_sidecar_ordering_budget
    runtime = Runtime.new
    sidecar_stops = Queue.new
    runtime.define_singleton_method(:stop_container) do |id, timeout:|
      next({"running" => true}) if id == "container-2"

      sidecar_stops << [Process.clock_gettime(Process::CLOCK_MONOTONIC), timeout]
      super(id, timeout: timeout)
    end
    runtime.define_singleton_method(:kill_container) { |_id, signal:| false }
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {})
    sidecar = {"name" => "sidecar", "image" => "example/app", "restartPolicy" => "Always"}
    object = pod(init_containers: [sidecar], terminationGracePeriodSeconds: 1)
    lifecycle.start(object)

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = lifecycle.terminate(object)
    stopped_at, grace = sidecar_stops.pop(true)

    assert_operator stopped_at - started, :>=, 0.9
    assert_equal 2, grace
    assert_equal "CleanupPending", result.state
    assert_match(/did not reach a confirmed stopped state/, result.cleanup_errors.join)
    refute(runtime.calls.any? { |kind, _| %i[remove sandbox_remove].include?(kind) })
  end
end
