# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require_relative "../support/node_lifecycle_fakes"

# volumeManager.GetVolumesInUse / MarkVolumesAsReportedInUse and the kubelet's
# node status sync (v1.36.2): an attachable volume is reported in
# node.status.volumesInUse from the moment its Pod is admitted (desired state)
# until it is unmounted (actual state); the mount of an attachable volume
# waits until the Node's status carries it; the agent recomputes the status
# every nodeStatusUpdateFrequency, patches it when it changed (heartbeat
# times aside) or every nodeStatusReportFrequency, and marks the volumes the
# patched Node carries as reported.
class KubeletVolumesInUseTest < Minitest::Test
  Runtime = NodeLifecycleFakes::Runtime
  Reporter = NodeLifecycleFakes::Reporter
  UNIQUE = "kubernetes.io/csi/hostpath.csi.k8s.io^vol-1"

  # A PodVolumes stand-in: PVC "data" resolves to the CSI PV above.
  class Volumes
    attr_reader :prepared, :released

    def initialize
      @prepared = []
      @released = []
    end

    def attachable_volume_names(pod)
      Array(pod.dig("spec", "volumes")).filter_map do |volume|
        UNIQUE if volume["persistentVolumeClaim"] && volume["persistentVolumeClaim"]["claimName"] == "data"
      end.uniq.sort
    end

    def prepare(pod, **)
      @prepared << pod.dig("metadata", "uid")
      mounts = Array(pod.dig("spec", "volumes")).to_h do |volume|
        [volume["name"], {"name" => volume["name"], "id" => "vol-#{volume["name"]}", "path" => "/x",
                          "uniqueName" => (volume["persistentVolumeClaim"] ? UNIQUE : nil)}.compact]
      end
      {"ids" => mounts.values.map { |mount| mount["id"] }, "mounts" => mounts}
    end

    def release(pod, _handle, **) = @released << pod.dig("metadata", "uid")
    def rotate_tokens(*) = []
    def refresh_contents(*) = []
    def method_missing(*) = nil
    def respond_to_missing?(*) = true
  end

  def pod(name, claim: "data")
    volumes = [{"name" => "pv", "persistentVolumeClaim" => {"claimName" => claim}}, {"name" => "tmp", "emptyDir" => {}}]
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"},
     "spec" => {"nodeName" => "node-1", "volumes" => volumes, "containers" => [{"name" => "app", "image" => "example/busybox"}]}}
  end

  def build_lifecycle(observer: nil)
    @runtime = Runtime.new
    @volumes = Volumes.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: @runtime, reporter: Reporter.new, sleeper: ->(_) {}, pod_volumes: @volumes,
                                                volume: @volumes)
    lifecycle.volumes_in_use_observer = observer
    lifecycle
  end

  def test_pod_volumes_resolve_attachable_names_from_claims
    reader = Class.new do
      def initialize(objects) = @objects = objects
      def get(resource, name, namespace: nil) = @objects[[resource, name]]
    end.new(
      %w[persistentvolumeclaims data] => {"spec" => {"volumeName" => "pv-1"}, "status" => {"phase" => "Bound"}},
      %w[persistentvolumeclaims pending] => {"spec" => {}, "status" => {"phase" => "Pending"}},
      %w[persistentvolumeclaims web-eph] => {"spec" => {"volumeName" => "pv-1"}, "status" => {"phase" => "Bound"}},
      %w[persistentvolumeclaims host] => {"spec" => {"volumeName" => "pv-host"}, "status" => {"phase" => "Bound"}},
      %w[persistentvolumes
         pv-1] => {"spec" => {"accessModes" => ["ReadWriteOnce"], "csi" => {"driver" => "hostpath.csi.k8s.io", "volumeHandle" => "vol-1"}}},
      %w[persistentvolumes pv-host] => {"spec" => {"accessModes" => ["ReadWriteOnce"], "hostPath" => {"path" => "/data"}}}
    )
    volumes = Rubernetes::Node::PodVolumes.new(volume: Object.new, reader: reader, root: "/tmp/fake-pods")
    spec = {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u"},
            "spec" => {"volumes" => [
              {"name" => "a", "persistentVolumeClaim" => {"claimName" => "data"}},
              {"name" => "again", "persistentVolumeClaim" => {"claimName" => "data"}},
              # A claim that is not bound yet: nothing to report until it is.
              {"name" => "b", "persistentVolumeClaim" => {"claimName" => "pending"}},
              # Generic ephemeral: the claim <pod>-<volume>.
              {"name" => "eph", "ephemeral" => {"volumeClaimTemplate" => {}}},
              # Not attachable: hostPath PV, inline CSI, emptyDir.
              {"name" => "h", "persistentVolumeClaim" => {"claimName" => "host"}},
              {"name" => "inline", "csi" => {"driver" => "hostpath.csi.k8s.io"}},
              {"name" => "tmp", "emptyDir" => {}}
            ]}}

    assert_equal [UNIQUE], volumes.attachable_volume_names(spec)
    assert_empty volumes.attachable_volume_names({"metadata" => {"name" => "x"}, "spec" => {}})
  end

  def test_volumes_are_in_use_from_admission_until_unmounted
    lifecycle = build_lifecycle
    lifecycle.start(pod("a"))

    assert_equal [UNIQUE], lifecycle.volumes_in_use
    assert_equal [UNIQUE], lifecycle.record("uid-a")[:attachable_volumes]
    # A second Pod on the same volume: still one entry.
    lifecycle.start(pod("b"))

    assert_equal [UNIQUE], lifecycle.volumes_in_use
    lifecycle.terminate(pod("a"))

    assert_equal [UNIQUE], lifecycle.volumes_in_use, "b still holds it"
    lifecycle.terminate(pod("b"))

    assert_empty lifecycle.volumes_in_use
    assert_equal %w[uid-a uid-b], @volumes.released
  end

  def test_desired_state_is_reported_before_the_mount_and_the_mount_waits_for_the_report
    reported = Queue.new
    lifecycle = build_lifecycle(observer: -> { reported << :sync })
    # The publisher: as soon as it is asked to sync, it reports what the
    # lifecycle wants in use and marks it.
    publisher = Thread.new do
      reported.pop
      @seen_before_mount = lifecycle.volumes_in_use
      @prepared_before_mark = @volumes.prepared.dup
      lifecycle.mark_volumes_reported_in_use(lifecycle.volumes_in_use)
    end
    lifecycle.start(pod("a"))
    publisher.join

    assert_equal [UNIQUE], @seen_before_mount, "reported from the desired state, before anything was mounted"
    assert_empty @prepared_before_mark, "the mount waited for the report"
    assert_equal %w[uid-a], @volumes.prepared
    assert_equal [UNIQUE], lifecycle.volumes_reported_in_use
  end

  def test_a_mount_that_is_never_reported_fails_as_failed_mount
    lifecycle = build_lifecycle(observer: -> {})
    lifecycle.volumes_reported_in_use_timeout = 0.05
    spec = pod("a")
    lifecycle.start(spec)
    record = lifecycle.record("uid-a")

    assert_equal "FailedMount", record[:reason]
    # rubocop:disable-next Layout/LineLength -- the pattern reads better whole
    assert_match(/Unable to attach or mount volumes: unmounted volumes=\["pv"\], unattached volumes=\["pv"\], failed to process volumes=\[\]: timed out waiting for the condition/,
                 record[:error].to_s)
    assert_empty @volumes.prepared
    # Non-attachable volumes never wait.
    lifecycle.start(pod("plain", claim: "other"))

    assert_equal %w[uid-plain], @volumes.prepared
  end

  # Only attachable volumes wait: a Pod of emptyDir / hostPath / configMap
  # volumes mounts at once, never asks for a status sync, and reports nothing.
  def test_non_attachable_volumes_never_wait_nor_report
    syncs = 0
    lifecycle = build_lifecycle(observer: -> { syncs += 1 })
    lifecycle.volumes_reported_in_use_timeout = 0.05
    spec = pod("local")
    spec["spec"]["volumes"] = [{"name" => "tmp", "emptyDir" => {}}, {"name" => "h", "hostPath" => {"path" => "/data"}},
                               {"name" => "cm", "configMap" => {"name" => "c"}}]
    lifecycle.start(spec)

    assert_equal %w[uid-local], @volumes.prepared
    assert_equal 0, syncs
    assert_empty lifecycle.volumes_in_use
    assert_nil lifecycle.record("uid-local")[:attachable_volumes]
  end

  # The agent's own 10 s loop satisfies the wait: volumesInUse is part of
  # the status compared, so a new desired volume alone is a change that goes
  # out and is marked, and the mount proceeds.
  def test_the_status_loop_alone_reports_and_releases_the_mount
    agent = build_agent
    lifecycle = build_lifecycle(observer: -> {})
    @stub.define_singleton_method(:volumes_in_use) { lifecycle.volumes_in_use }
    @stub.define_singleton_method(:mark_volumes_reported_in_use) { |names| lifecycle.mark_volumes_reported_in_use(names) }
    lifecycle.volumes_reported_in_use_timeout = 5
    ticker = Thread.new do
      sleep 0.05 until lifecycle.volumes_in_use.include?(UNIQUE)
      @patched = agent.sync_node_status
    end
    lifecycle.start(pod("a"))
    ticker.join

    assert @patched, "the periodic sync saw volumesInUse change and patched"
    assert_equal [UNIQUE], @api.nodes.last.dig("status", "volumesInUse")
    assert_equal %w[uid-a], @volumes.prepared
  ensure
    begin
      agent&.stop
    rescue StandardError
      nil
    end
  end

  def test_attachable_volumes_survive_a_restart_of_the_lifecycle_state
    store = Class.new do
      attr_accessor :payload

      def save(payload) = @payload = payload
      def load = @payload
    end.new
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, reporter: Reporter.new, sleeper: ->(_) {},
                                                pod_volumes: Volumes.new, state_store: store)
    lifecycle.start(pod("a"))
    restored = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, reporter: Reporter.new, sleeper: ->(_) {},
                                               pod_volumes: Volumes.new, state_store: store)

    assert_equal [UNIQUE], restored.record("uid-a")[:attachable_volumes]
    assert_equal [UNIQUE], restored.volumes_in_use
  end

  # ------------------------------------------------------------ agent

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

  class LifecycleStub
    attr_accessor :in_use, :marked, :observer

    def initialize
      @in_use = []
      @marked = []
    end

    def recover(**) = {"ready" => true, "errors" => [], "blocked" => []}
    def record(_uid) = nil
    def volumes_in_use = @in_use
    def mark_volumes_reported_in_use(names) = @marked << names

    def volumes_in_use_observer=(observer)
      @observer = observer
    end
  end

  def build_agent(report_frequency: 300.0)
    @api = API.new
    @stub = LifecycleStub.new
    agent = Rubernetes::Node::Agent.new(node_name: "node-a", api: @api, lifecycle: @stub, sync_loop: Loop.new, sleeper: ->(_) {},
                                        node_status_report_frequency: report_frequency)
    agent.start
    agent
  end

  def test_node_status_is_patched_when_it_changed_and_carries_volumes_in_use
    agent = build_agent

    assert_equal 1, @api.nodes.length, "registration"
    refute @api.nodes.last.fetch("status").key?("volumesInUse")
    # Nothing changed: no patch, but the (empty) list is marked anyway
    # (markVolumesFromNode).
    refute agent.sync_node_status
    assert_equal 1, @api.nodes.length
    assert_equal [], @stub.marked.last
    @stub.in_use = [UNIQUE]

    assert agent.sync_node_status
    assert_equal 2, @api.nodes.length
    assert_equal [UNIQUE], @api.nodes.last.dig("status", "volumesInUse")
    assert_equal [UNIQUE], @stub.marked.last
    refute agent.sync_node_status, "unchanged again"
    # Gone: the key is sent as null so the merge patch removes it.
    @stub.in_use = []

    assert agent.sync_node_status
    assert @api.nodes.last.fetch("status").key?("volumesInUse")
    assert_nil @api.nodes.last.dig("status", "volumesInUse")
    # A desired-state change asks for an immediate sync.
    assert_respond_to @stub.observer, :call
    assert @stub.observer.call
  ensure
    begin
      agent&.stop
    rescue StandardError
      nil
    end
  end

  def test_node_status_is_reported_at_least_every_report_frequency
    agent = build_agent(report_frequency: 0.0)

    assert agent.sync_node_status, "the report frequency elapsed: patched although unchanged"
    assert_equal 2, @api.nodes.length
  ensure
    begin
      agent&.stop
    rescue StandardError
      nil
    end
  end

  def test_node_status_changed_ignores_heartbeat_times_and_condition_order
    changed = Rubernetes::Node::Agent.method(:node_status_changed?)
    base = {"conditions" => [{"type" => "Ready", "status" => "True", "lastHeartbeatTime" => "t1", "lastTransitionTime" => "t0"},
                             {"type" => "MemoryPressure", "status" => "False", "lastHeartbeatTime" => "t1"}],
            "capacity" => {"cpu" => "2"}}
    heartbeat = {"conditions" => [{"type" => "MemoryPressure", "status" => "False", "lastHeartbeatTime" => "t2"},
                                  {"type" => "Ready", "status" => "True", "lastHeartbeatTime" => "t2", "lastTransitionTime" => "t0"}],
                 "capacity" => {"cpu" => "2"}}

    refute changed.call(base, heartbeat)
    assert changed.call(base, heartbeat.merge("capacity" => {"cpu" => "3"}))
    transition = {"conditions" => [base["conditions"][0].merge("lastTransitionTime" => "t9"), base["conditions"][1]],
                  "capacity" => {"cpu" => "2"}}

    assert changed.call(base, transition)
    assert changed.call(base, base.merge("volumesInUse" => [UNIQUE]))
    assert changed.call(nil, base)
    refute changed.call(nil, nil)
  end
end
