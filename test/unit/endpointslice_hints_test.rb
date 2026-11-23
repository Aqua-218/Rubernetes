# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

class EndpointSliceHintsTest < Minitest::Test
  Controller = Rubernetes::Controller::EndpointSliceController
  TOPOLOGY = "service.kubernetes.io/topology-mode"
  LEGACY = "service.kubernetes.io/topology-aware-hints"
  ZONE = "topology.kubernetes.io/zone"

  def test_explicit_distribution_assigns_zone_and_node_only_to_ready_endpoints
    nodes = [node("worker-a", "a"), node("worker-empty", nil)]
    pods = [pod(1, "worker-a"), pod(2, "worker-empty"), pod(3, "worker-a", ready: false)]
    node_hints = endpoints(reconcile(service(distribution: "PreferSameNode"), pods, nodes))

    assert_equal %w[a worker-a], hint_names(node_hints.fetch(0))
    assert_equal [nil, "worker-empty"], hint_names(node_hints.fetch(1))
    refute node_hints.fetch(2).key?("hints")

    %w[PreferSameZone PreferClose].each do |distribution|
      zone_hints = endpoints(reconcile(service(distribution: distribution), pods, nodes))

      assert_equal ["a", nil], hint_names(zone_hints.fetch(0))
      refute zone_hints.fetch(1).key?("hints")
      refute zone_hints.fetch(2).key?("hints")
    end
  end

  def test_auto_uses_ready_worker_allocatable_cpu_and_redistributes_across_slices
    nodes = [node("worker-a", "a", cpu: "2000m"), node("worker-b", "b"), node("worker-c", "c"),
             node("control", nil, cpu: nil, labels: {"node-role.kubernetes.io/control-plane" => ""}),
             node("offline", nil, cpu: nil, ready: false)]
    pods = [pod(1, "worker-a"), pod(2, "worker-b"), pod(3, "worker-b", port: 8081), pod(4, "worker-c", port: 8081)]
    spec = service(distribution: "PreferSameNode", annotations: {TOPOLOGY => "Auto"})
    slices = reconcile(spec, pods, nodes)
    values = endpoints(slices)

    assert_equal 2, slices.length
    assert_equal({"a" => 2, "b" => 1, "c" => 1}, values.map { |endpoint| hint_names(endpoint).first }.tally)
    assert(values.any? { |endpoint| endpoint["zone"] == "b" && hint_names(endpoint).first == "a" })
    assert(values.none? { |endpoint| hint_names(endpoint).last })
    assert_empty reconcile(spec, pods, nodes, existing: slices)

    changed = reconcile(spec, pods.first(3), nodes, existing: slices)

    assert(endpoints(changed).all? { |endpoint| !endpoint.key?("hints") })
  end

  def test_auto_removes_stale_hints_when_a_ready_worker_has_incomplete_capacity
    nodes = [node("worker-a", "a"), node("worker-b", "b"), node("worker-c", "c")]
    pods = [pod(1, "worker-a"), pod(2, "worker-b"), pod(3, "worker-c")]
    spec = service(annotations: {TOPOLOGY => "Auto"})
    slices = reconcile(spec, pods, nodes)

    assert_equal(%w[a b c], endpoints(slices).map { |endpoint| hint_names(endpoint).first })

    missing_capacity = nodes + [node("worker-d", "d", cpu: nil)]
    refreshed = reconcile(spec, pods, missing_capacity, existing: slices)

    assert_equal 3, endpoints(refreshed).length
    assert(endpoints(refreshed).none? { |endpoint| endpoint.key?("hints") })
    assert_equal(%w[a b c], endpoints(slices).map { |endpoint| hint_names(endpoint).first })
  end

  def test_service_sync_reads_and_refreshes_node_topology_through_the_store
    adapter = Rubernetes::Controller::StoreAdapter.new(Rubernetes::Storage::MemoryStore.new)
    configured = adapter.create(service(annotations: {TOPOLOGY => "Auto"}))
    %w[a b c].each_with_index do |zone, index|
      worker = "worker-#{zone}"
      adapter.create(node(worker, zone))
      adapter.create(pod(index + 1, worker))
    end
    controller = Controller.new(store: adapter)
    result = controller.reconcile(configured)

    assert result.applied
    assert_in_delta 15.0, result.requeue_after
    slices = adapter.list("EndpointSlice", namespace: "ns")

    assert_equal(%w[a b c], endpoints(slices).map { |endpoint| hint_names(endpoint).first })
    assert_empty controller.reconcile(configured).operations

    adapter.create(node("worker-without-zone", nil))
    controller.reconcile(configured)
    refreshed = adapter.list("EndpointSlice", namespace: "ns")

    assert_equal 3, endpoints(refreshed).length
    assert(endpoints(refreshed).none? { |endpoint| endpoint.key?("hints") })
  end

  def test_auto_allocates_separately_per_address_family
    nodes = [node("worker-a", "a"), node("worker-b", "b"), node("worker-c", "c")]
    pods = [pod(1, "worker-a", v6: true), pod(2, "worker-b"), pod(3, "worker-c")]
    spec = service(annotations: {TOPOLOGY => "Auto"}, families: %w[IPv4 IPv6])
    slices = reconcile(spec, pods, nodes).to_h { |slice| [slice.fetch("addressType"), slice.fetch("endpoints")] }

    assert_equal(%w[a b c], slices.fetch("IPv4").map { |endpoint| hint_names(endpoint).first })
    refute slices.fetch("IPv6").first.key?("hints")
  end

  def test_deprecated_annotation_overrides_new_mode_and_explicit_hints_clear_on_removal
    nodes = [node("worker-a", "a")]
    pods = [pod(1, "worker-a")]
    annotations = {TOPOLOGY => "Auto", LEGACY => "Disabled"}
    configured = service(distribution: "PreferSameNode", annotations: annotations)
    original = reconcile(configured, pods, nodes)

    assert_equal %w[a worker-a], hint_names(endpoints(original).first)

    refreshed = reconcile(service, pods, nodes, existing: original)

    refute endpoints(refreshed).first.key?("hints")
  end

  private

  def service(distribution: nil, annotations: {}, families: ["IPv4"])
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "service-uid", "annotations" => annotations},
     "spec" => {"selector" => {"app" => "web"}, "ipFamilies" => families,
                "ports" => [{"name" => "http", "port" => 80, "targetPort" => "http"}],
                "trafficDistribution" => distribution}.compact}
  end

  def node(name, zone, cpu: "1", ready: true, labels: {})
    {"apiVersion" => "v1", "kind" => "Node",
     "metadata" => {"name" => name, "labels" => {ZONE => zone}.compact.merge(labels)},
     "status" => {"conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}],
                  "allocatable" => {"cpu" => cpu}.compact}}
  end

  def pod(index, node_name, port: 8080, ready: true, v6: false)
    ips = ["10.20.0.#{index}"]
    ips << "fd00::#{index}" if v6
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "pod-#{index}", "namespace" => "ns", "uid" => "uid-#{index}", "labels" => {"app" => "web"}},
     "spec" => {"nodeName" => node_name, "containers" => [{"name" => "app", "ports" => [{"name" => "http", "containerPort" => port}]}]},
     "status" => {"phase" => "Running", "podIP" => ips.first, "podIPs" => ips.map { |ip| {"ip" => ip} },
                  "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False"}]}}
  end

  def reconcile(service, pods, nodes, existing: [])
    result = Controller.new.reconcile(service, pods: pods, nodes: nodes, endpoint_slices: existing, apply: false)
    result.operations.reject(&:delete?).map(&:object)
  end

  def endpoints(slices) = slices.flat_map { |slice| slice.fetch("endpoints") }

  def hint_names(endpoint)
    [endpoint.dig("hints", "forZones", 0, "name"), endpoint.dig("hints", "forNodes", 0, "name")]
  end
end
