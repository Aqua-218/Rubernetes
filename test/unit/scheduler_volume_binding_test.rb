# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# The VolumeBinding plugin (pkg/scheduler/framework/plugins/volumebinding,
# v1.36.2): PreFilter claim checks, Filter (bound PV node affinity, static
# matches, provisioning with allowedTopologies and CSIStorageCapacity),
# Reserve's assumptions, PreBind's API writes and wait, Unreserve.
class SchedulerVolumeBindingTest < Minitest::Test
  S = Rubernetes::Scheduler
  VB = S::VolumeBinding

  # The API PreBind talks to: writes are stored with a new resourceVersion;
  # a claim becomes bound (the PV controller's work) on the next read.
  class FakeAPI
    attr_reader :updates, :objects

    def initialize(objects, bind: true)
      @objects = objects
      @updates = []
      @bind = bind
      @rv = 100
    end

    def get_pv(name) = @objects["pv/#{name}"]
    def get_node(name) = @objects["node/#{name}"]
    def get_pod(namespace, name) = @objects["pod/#{namespace}/#{name}"]

    def get_pvc(namespace, name)
      claim = @objects["pvc/#{namespace}/#{name}"]
      return claim unless claim && @bind

      volume = claim.dig("spec", "volumeName") || @objects.values.find do |object|
        object.dig("spec", "claimRef", "name") == name
      end&.dig("metadata", "name")
      if volume.nil? && claim.dig("metadata", "annotations", VB::ANN_SELECTED_NODE)
        volume = "provisioned-#{name}"
        @objects["pv/#{volume}"] ||= {"metadata" => {"name" => volume, "resourceVersion" => "1"}, "spec" => {}}
      end
      return claim if volume.nil?

      claim.merge("spec" => claim["spec"].merge("volumeName" => volume),
                  "metadata" => claim["metadata"].merge("annotations" => (claim.dig("metadata",
                                                                                    "annotations") || {}).merge(VB::ANN_BIND_COMPLETED => "yes")))
    end

    def update_pv(pv) = store("pv/#{pv.dig("metadata", "name")}", pv)
    def update_pvc(pvc) = store("pvc/#{pvc.dig("metadata", "namespace")}/#{pvc.dig("metadata", "name")}", pvc)

    private

    def store(key, object)
      @rv += 1
      stored = object.merge("metadata" => object["metadata"].merge("resourceVersion" => @rv.to_s))
      @updates << [key, stored]
      @objects[key] = stored
    end
  end

  def pod(volumes)
    S::Pod.new({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "pod-uid"},
                "spec" => {"containers" => [{"name" => "c", "image" => "i"}], "volumes" => volumes}})
  end

  def node(name = "node-a", labels: {"zone" => "a"})
    S::Node.new({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => labels},
                 "status" => {"allocatable" => {"cpu" => "4", "memory" => "4Gi", "pods" => "110"}}})
  end

  def claim(name, class_name: "wffc", volume: nil, bound: false, size: "1Gi", annotations: {})
    annotations = annotations.merge(VB::ANN_BIND_COMPLETED => "yes") if bound
    {"metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}", "resourceVersion" => "1", "annotations" => annotations},
     "spec" => {"storageClassName" => class_name, "volumeName" => volume, "accessModes" => ["ReadWriteOnce"],
                "resources" => {"requests" => {"storage" => size}}}.compact}
  end

  def volume(name, class_name: "wffc", zone: nil, size: "5Gi", claim_ref: nil, phase: "Available")
    spec = {"storageClassName" => class_name, "capacity" => {"storage" => size}, "accessModes" => ["ReadWriteOnce"]}
    if zone
      spec["nodeAffinity"] =
        {"required" => {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "zone", "operator" => "In", "values" => [zone]}]}]}}
    end
    spec["claimRef"] = claim_ref if claim_ref
    {"metadata" => {"name" => name, "resourceVersion" => "1"}, "spec" => spec, "status" => {"phase" => phase}}
  end

  def storage_class(name, mode: "WaitForFirstConsumer", provisioner: "csi.example.com", topologies: nil)
    {"metadata" => {"name" => name}, "provisioner" => provisioner, "volumeBindingMode" => mode, "allowedTopologies" => topologies}.compact
  end

  def context(claims: [], volumes: [], classes: [storage_class("wffc"), storage_class("now", mode: "Immediate")], drivers: [],
              capacities: [])
    S::CycleContext.new(nodes: [], pods: [], volume_data: {
                          "persistentVolumeClaims" => claims, "persistentVolumes" => volumes, "storageClasses" => classes,
                          "csiNodes" => [], "csiDrivers" => drivers, "csiStorageCapacities" => capacities
                        })
  end

  def uses(*names) = names.map { |name| {"name" => name, "persistentVolumeClaim" => {"claimName" => name}} }

  def plugin(api = nil) = VB.new(api: api, sleeper: ->(_seconds) {}, bind_timeout: 5)

  def test_prefilter_rejections
    vb = plugin

    assert_equal true, vb.filter(pod([{"name" => "tmp", "emptyDir" => {}}]), node, context)
    missing = vb.filter(pod(uses("gone")), node, context)

    assert_equal ["UnschedulableAndUnresolvable", %(persistentvolumeclaim "gone" not found)], [missing.code, missing.reason]
    ephemeral = vb.filter(pod([{"name" => "scratch", "ephemeral" => {"volumeClaimTemplate" => {}}}]), node, context)

    assert_equal %(waiting for ephemeral volume controller to create the persistentvolumeclaim "web-scratch"), ephemeral.reason
    immediate = plugin.filter(pod(uses("data")), node, context(claims: [claim("data", class_name: "now")]))

    assert_equal VB::REASON_UNBOUND_IMMEDIATE, immediate.reason
    deleting = claim("data").tap { |object| object["metadata"]["deletionTimestamp"] = "2026-09-24T00:00:00Z" }

    assert_equal %(persistentvolumeclaim "data" is being deleted),
                 plugin.filter(pod(uses("data")), node, context(claims: [deleting])).reason
  end

  def test_bound_claims_follow_the_pv_node_affinity
    claims = [claim("data", volume: "pv-a", bound: true)]
    volumes = [volume("pv-a", zone: "a")]

    assert_equal true, plugin.filter(pod(uses("data")), node, context(claims: claims, volumes: volumes))
    conflict = plugin.filter(pod(uses("data")), node("node-b", labels: {"zone" => "b"}), context(claims: claims, volumes: volumes))

    assert_equal VB::REASON_NODE_CONFLICT, conflict.reason
    gone = plugin.filter(pod(uses("data")), node, context(claims: claims, volumes: []))

    assert_equal VB::REASON_PV_NOT_EXIST, gone.reason
  end

  def test_static_binding_picks_the_smallest_fitting_pv_on_the_node
    claims = [claim("data", size: "2Gi")]
    volumes = [volume("pv-big", zone: "a", size: "10Gi"), volume("pv-small", zone: "a", size: "3Gi"),
               volume("pv-tiny", zone: "a", size: "1Gi"), volume("pv-elsewhere", zone: "b", size: "2Gi")]
    api = FakeAPI.new({"node/node-a" => node.to_h, "pod/ns/web" => pod([]).to_h, "pvc/ns/data" => claims.first})
    vb = plugin(api)
    ctx = context(claims: claims, volumes: volumes, classes: [storage_class("wffc", provisioner: VB::NOT_SUPPORTED_PROVISIONER)])
    target = pod(uses("data"))

    assert_equal true, vb.filter(target, node, ctx)
    assert_equal VB::REASON_BIND_CONFLICT, vb.filter(target, node("node-b", labels: {"zone" => "c"}), ctx).reason
    assert_equal true, vb.reserve(target, node, ctx)
    assert_equal true, vb.pre_bind(target, node, ctx)
    key, written = api.updates.first

    assert_equal "pv/pv-small", key
    assert_equal({"kind" => "PersistentVolumeClaim", "namespace" => "ns", "name" => "data", "uid" => "uid-data", "apiVersion" => "v1",
                  "resourceVersion" => "1"}, written.dig("spec", "claimRef"))
    assert_equal "yes", written.dig("metadata", "annotations", VB::ANN_BOUND_BY_CONTROLLER)
  end

  def test_dynamic_provisioning_sets_the_selected_node
    claims = [claim("data")]
    api = FakeAPI.new({"node/node-a" => node.to_h, "pod/ns/web" => pod([]).to_h, "pvc/ns/data" => claims.first})
    vb = plugin(api)
    ctx = context(claims: claims)
    target = pod(uses("data"))

    assert_equal true, vb.filter(target, node, ctx)
    assert_equal true, vb.reserve(target, node, ctx)
    assert_equal true, vb.pre_bind(target, node, ctx)
    key, written = api.updates.first

    assert_equal ["pvc/ns/data", "node-a"], [key, written.dig("metadata", "annotations", VB::ANN_SELECTED_NODE)]
  end

  def test_provisioning_limits
    claims = [claim("data", size: "10Gi")]
    no_provisioner = context(claims: claims, classes: [storage_class("wffc", provisioner: VB::NOT_SUPPORTED_PROVISIONER)])

    assert_equal VB::REASON_BIND_CONFLICT, plugin.filter(pod(uses("data")), node, no_provisioner).reason
    topology = [{"matchLabelExpressions" => [{"key" => "zone", "values" => ["b"]}]}]
    restricted = context(claims: claims, classes: [storage_class("wffc", topologies: topology)])

    assert_equal VB::REASON_BIND_CONFLICT, plugin.filter(pod(uses("data")), node, restricted).reason
    assert_equal true, plugin.filter(pod(uses("data")), node("node-b", labels: {"zone" => "b"}), restricted)

    drivers = [{"metadata" => {"name" => "csi.example.com"}, "spec" => {"storageCapacity" => true}}]
    small = [{"metadata" => {"name" => "cap", "namespace" => "kube-system"}, "storageClassName" => "wffc", "capacity" => "5Gi",
              "nodeTopology" => {"matchLabels" => {"zone" => "a"}}}]

    assert_equal VB::REASON_NOT_ENOUGH_SPACE,
                 plugin.filter(pod(uses("data")), node, context(claims: claims, drivers: drivers, capacities: small)).reason
    large = [small.first.merge("capacity" => "100Gi", "maximumVolumeSize" => "20Gi")]

    assert_equal true, plugin.filter(pod(uses("data")), node, context(claims: claims, drivers: drivers, capacities: large))
    elsewhere = [large.first.merge("nodeTopology" => {"matchLabels" => {"zone" => "z"}})]

    assert_equal VB::REASON_NOT_ENOUGH_SPACE,
                 plugin.filter(pod(uses("data")), node, context(claims: claims, drivers: drivers, capacities: elsewhere)).reason
    assert_equal true, plugin.filter(pod(uses("data")), node, context(claims: claims, drivers: [], capacities: small)),
                 "a driver that does not opt in is not capacity-checked"
  end

  def test_a_claim_selected_for_another_node_only_fits_there
    claims = [claim("data", annotations: {VB::ANN_SELECTED_NODE => "node-b"})]

    assert_equal VB::REASON_BIND_CONFLICT, plugin.filter(pod(uses("data")), node, context(claims: claims)).reason
    assert_equal true, plugin.filter(pod(uses("data")), node("node-b"), context(claims: claims))
  end

  def test_a_failed_provisioning_fails_prebind_and_reverts
    claims = [claim("data")]
    api = FakeAPI.new({"node/node-a" => node.to_h, "pod/ns/web" => pod([]).to_h, "pvc/ns/data" => claims.first}, bind: false)
    api.define_singleton_method(:update_pvc) do |pvc|
      super(pvc.merge("metadata" => pvc["metadata"].merge("annotations" => {})))
    end
    vb = plugin(api)
    ctx = context(claims: claims)
    target = pod(uses("data"))
    vb.filter(target, node, ctx)
    vb.reserve(target, node, ctx)
    result = vb.pre_bind(target, node, ctx)

    assert_equal "binding volumes: provisioning failed for PVC \"data\"", result.reason
  end

  def test_the_binding_cycle_can_wait_off_the_scheduling_thread
    claims = [claim("data")]
    api = FakeAPI.new({"node/node-a" => node.to_h, "pod/ns/web" => pod([]).to_h, "pvc/ns/data" => claims.first})
    vb = plugin(api)
    vb.defer_wait = true
    ctx = context(claims: claims)
    target = pod(uses("data"))
    vb.filter(target, node, ctx)
    vb.reserve(target, node, ctx)

    assert_equal true, vb.pre_bind(target, node, ctx)
    assert vb.pending?(target)
    assert vb.wait_for_bindings(target, "node-a")
    refute vb.pending?(target)
  end

  def test_unreserve_drops_the_assumed_pv
    claims = [claim("a"), claim("b")]
    volumes = [volume("pv-1", zone: "a")]
    ctx = context(claims: claims, volumes: volumes, classes: [storage_class("wffc", provisioner: VB::NOT_SUPPORTED_PROVISIONER)])
    vb = plugin
    first = pod(uses("a"))

    assert_equal true, vb.filter(first, node, ctx)
    vb.reserve(first, node, ctx)
    second = S::Pod.new(pod(uses("b")).to_h.merge("metadata" => {"name" => "other", "namespace" => "ns", "uid" => "other-uid"}))
    ctx2 = context(claims: claims, volumes: volumes, classes: [storage_class("wffc", provisioner: VB::NOT_SUPPORTED_PROVISIONER)])

    assert_equal VB::REASON_BIND_CONFLICT, vb.filter(second, node, ctx2).reason, "pv-1 is assumed for claim a"
    vb.unreserve(first, node, ctx)
    ctx3 = context(claims: claims, volumes: volumes, classes: [storage_class("wffc", provisioner: VB::NOT_SUPPORTED_PROVISIONER)])

    assert_equal true, vb.filter(second, node, ctx3)
  end

  def test_the_framework_uses_one_stateful_instance
    framework = S::Framework.new

    assert_kind_of VB, framework.volume_binding
    refute_same framework.volume_binding, S::Framework.new.volume_binding
  end
end
