# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "tmpdir"
require "rubernetes/schema/codec/kubernetes_protobuf"
require "rubernetes/storage/memory_store"
require "rubernetes/node/status"
require "rubernetes/node/pod_volumes"
require "rubernetes/node/container_spec"
require "rubernetes/api"

# Regressions found in the 2026-09-16 conformance round 15, each pinned to
# the upstream behaviour it reproduces.
class ConformanceRound15FixesTest < Minitest::Test
  # k8s.io/api v0.36.1: a Pod with two ephemeral containers, encoded by the
  # apimachinery protobuf serializer.  EphemeralContainerCommon is embedded
  # inline (json:",inline" protobuf:"bytes,1,req" -- no name= tag), so the
  # decoded JSON must carry name/image at the top level.
  POD_WITH_EPHEMERAL_CONTAINERS = ["6b3873000a090a0276311203506f6412df010a180a0674617267657412001a026e7322002a0032003800420012ad0112230a046d61696e120762757379626f782a0042006a007200800100880100900100a201001a00320042004a0052005800600068008201008a01009a0100c201009202350a310a086465627567676572120762757379626f781a05736c6565701a01312a0042006a007200800100880100900100a2010012009202310a290a0a64656275676765722d32120762757379626f782a0042006a007200800100880100900100a2010012046d61696e1a130a001a0022002a0032004a005a0072008801001a002200"].pack("H*").freeze

  def test_ephemeral_containers_decode_with_their_common_fields_inline
    pod = Rubernetes::Schema::Codec::KubernetesProtobuf.new.decode(POD_WITH_EPHEMERAL_CONTAINERS)
    containers = pod.dig("spec", "ephemeralContainers")

    assert_equal(%w[debugger debugger-2], containers.map { |entry| entry["name"] })
    assert_equal "main", containers[1]["targetContainerName"]
    refute(containers.any? { |entry| entry.key?("ephemeralContainerCommon") })
  end

  # etcd auto-compaction: a deleted object's versions leave the store once
  # the retention window passed, even when nothing writes that key again.
  def test_store_drops_a_deleted_keys_history_after_the_retention_window
    now = 1_000.0
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: 60, clock: -> { now })
    store.create("pods/ns/a", {"metadata" => {"name" => "a"}, "spec" => {"x" => 1}})
    3.times { |i| store.update("pods/ns/a", {"metadata" => {"name" => "a"}, "spec" => {"x" => i}}) }
    store.delete("pods/ns/a")
    store.create("pods/ns/b", {"metadata" => {"name" => "b"}})
    versions = store.instance_variable_get(:@versions)

    assert versions.key?("pods/ns/a"), "inside the window the deleted key keeps its history"

    now += 120
    store.update("pods/ns/b", {"metadata" => {"name" => "b"}, "spec" => {"y" => 1}})
    now += 120
    store.update("pods/ns/b", {"metadata" => {"name" => "b"}, "spec" => {"y" => 2}})

    refute versions.key?("pods/ns/a"), "a deleted key older than the window is gone"
    # The next window's compaction (triggered by any write) leaves a live key
    # its current version only.
    now += 120
    store.create("pods/ns/c", {"metadata" => {"name" => "c"}})

    assert_equal 1, versions.fetch("pods/ns/b").length, "a live key keeps only its current version"
    assert_equal({"y" => 2}, store.get("pods/ns/b")["spec"])
  end

  # kubelet getPhase: a container still Waiting keeps the Pod Pending; Running
  # means every container has been started.
  def test_pod_phase_is_pending_while_a_container_is_still_creating
    status = Rubernetes::Node::Status.allocate
    pod = {"spec" => {"restartPolicy" => "Always", "containers" => [{"name" => "a"}, {"name" => "b"}]}}
    running = {"name" => "a", "state" => {"running" => {"startedAt" => "2026-09-16T10:00:00Z"}}}
    creating = {"name" => "b", "state" => {"waiting" => {"reason" => "ContainerCreating"}}}
    crash = {"name" => "b", "state" => {"waiting" => {"reason" => "CrashLoopBackOff"}},
             "lastState" => {"terminated" => {"exitCode" => 1}}}
    done = {"name" => "b", "state" => {"terminated" => {"exitCode" => 0}}}
    failed = {"name" => "b", "state" => {"terminated" => {"exitCode" => 2}}}
    phase = lambda { |statuses, policy = "Always"|
      status.send(:derive_phase, {"spec" => pod["spec"].merge("restartPolicy" => policy)}, statuses, [],
                  explicit_phase: nil, explicit_reason: nil)
    }

    assert_equal "Pending", phase.call([running, creating])
    assert_equal "Running", phase.call([running, crash])
    assert_equal "Running", phase.call([running, done])
    assert_equal "Running", phase.call([{"name" => "a", "state" => {"terminated" => {"exitCode" => 0}}}, done])
    assert_equal "Succeeded", phase.call([{"name" => "a", "state" => {"terminated" => {"exitCode" => 0}}}, done], "Never")
    assert_equal "Failed", phase.call([{"name" => "a", "state" => {"terminated" => {"exitCode" => 0}}}, failed], "Never")
    assert_equal "Running", phase.call([{"name" => "a", "state" => {"terminated" => {"exitCode" => 0}}}, failed], "OnFailure")
    assert_equal "Succeeded", phase.call([{"name" => "a", "state" => {"terminated" => {"exitCode" => 0}}}, done], "OnFailure")
    assert_equal "Pending", phase.call([creating.merge("name" => "a"), creating])
    # The lifecycle's own "Running" never outranks a container still waiting.
    assert_equal "Pending", status.send(:derive_phase, pod, [running, creating], [], explicit_phase: "Running", explicit_reason: nil)
    assert_equal "Running",
                 status.send(:derive_phase, pod, [running, running.merge("name" => "b")], [], explicit_phase: "Running",
                                                                                              explicit_reason: nil)
    assert_equal "Failed", status.send(:derive_phase, pod, [running, creating], [], explicit_phase: "Failed", explicit_reason: nil)
  end

  # PodObservedGenerationTracking: each kubelet condition records the
  # generation it observed, as a wire field of the condition.
  def test_pod_conditions_carry_the_observed_generation
    status = Rubernetes::Node::Status.allocate
    status.instance_variable_set(:@clock, -> { Time.utc(2026, 9, 16) })
    pod = {"metadata" => {"generation" => 3}, "spec" => {"containers" => [{"name" => "a"}]}}
    running = {"name" => "a", "ready" => true, "state" => {"running" => {}}}
    conditions = status.send(:build_conditions, phase: "Running", regular_statuses: [running], init_statuses: [], pod: pod)

    assert_equal [3], conditions.map(&:observed_generation).uniq
    assert_equal 3, conditions.first.to_h["observedGeneration"]
  end

  # client-go SetAuthProxyHeaders: extra keys are percent-encoded (a "/" is
  # not legal in a header name; the sample API server answered a bare 400),
  # groups go one per header.
  def test_aggregator_forwards_identity_headers_like_client_go
    aggregator = Rubernetes::API::Aggregator.new
    request = Struct.new(:identity, :headers) { def header(name) = (headers || {})[name] }.new(
      {"username" => "system:serviceaccount:ns:sa", "groups" => %w[system:serviceaccounts system:authenticated],
       "extra" => {"authentication.kubernetes.io/pod-name" => ["e2e"], "authentication.kubernetes.io/pod-uid" => ["u1"]}},
      {"accept" => "application/json"}
    )
    headers = aggregator.send(:forwarded_headers, request)

    assert_equal %w[system:serviceaccounts system:authenticated], headers["X-Remote-Group"]
    assert_equal ["e2e"], headers["X-Remote-Extra-authentication.kubernetes.io%2Fpod-name"]
    assert headers.keys.all? { |key| key.match?(/\A[A-Za-z0-9%._-]+\z/) }, headers.keys.inspect
  end

  # A ConfigMap binaryData entry has to cross the node's JSON ledger: it goes
  # base64 under binaryFiles and the backend writes the raw bytes.
  def test_binary_volume_files_are_carried_as_base64_and_written_raw
    volumes = Rubernetes::Node::PodVolumes.allocate
    spec = volumes.send(:split_binary_files, {"text" => "hello", "blob" => "\xDE\xAD\xBE\xEF".b})

    assert_equal({"text" => "hello"}, spec["files"])
    assert_equal({"blob" => "3q2+7w=="}, spec["binaryFiles"])
    assert JSON.generate(spec)

    Dir.mktmpdir("binary-volume") do |dir|
      backend = Rubernetes::Volume::ConfigMapBackend.new(id: "v", root: dir, spec: spec.merge("backend" => "configMap"))

      assert_equal "\xDE\xAD\xBE\xEF".b, backend.send(:precomputed_files).fetch("blob")
    end
  end

  # kubelet chmods the termination message file to 0666 so a non-root
  # container can write it.
  def test_termination_message_file_is_world_writable
    Dir.mktmpdir("termination") do |dir|
      spec = Rubernetes::Node::ContainerSpec.allocate
      context = Struct.new(:pod_directory).new(dir)
      message = spec.send(:termination_message, {"name" => "c", "terminationMessagePath" => "/dev/termination-custom-log"}, context)

      assert_equal 0o666, File.stat(message.fetch("host_path")).mode & 0o777
    end
  end

  # pkg/registry/core/pod/strategy.go LogLocation: logs of a container that has
  # not started are refused at once from the Pod status.
  def test_logs_of_a_waiting_container_are_refused_from_the_pod_status
    bridge = Rubernetes::API::SubresourceBridge.allocate
    request = Struct.new(:params) { def query_value(name) = params[name] }.new({"container" => "b"})
    pod = {"metadata" => {"name" => "p"},
           "spec" => {"containers" => [{"name" => "a"}, {"name" => "b"}]},
           "status" => {"containerStatuses" => [{"name" => "a", "state" => {"running" => {}}},
                                                {"name" => "b", "state" => {"waiting" => {"reason" => "ImagePullBackOff"}}}]}}

    error = assert_raises(Rubernetes::API::Status::BadRequest) { bridge.send(:refuse_waiting_container!, pod, request) }
    assert_equal 'container "b" in pod "p" is waiting to start: ImagePullBackOff', error.message
    assert_nil bridge.send(:refuse_waiting_container!, pod, request.class.new({"container" => "a"}))
    crashed = pod.merge("status" => {"containerStatuses" => [{"name" => "b", "state" => {"waiting" => {"reason" => "CrashLoopBackOff"}},
                                                              "lastState" => {"terminated" => {"exitCode" => 1}}}]})

    assert_nil bridge.send(:refuse_waiting_container!, crashed, request), "a crashed container's last run is readable"
  end
end
