# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/observability/metrics"

# The controllers' own metrics (pkg/controller/*/metrics, v1.36.2), recorded
# into the controller manager's process-wide registry once the operation
# they planned was applied.
class ControllerManagerMetricsTest < Minitest::Test
  Controller = Rubernetes::Controller

  def setup
    @registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")
    Controller.metrics = @registry
  end

  def teardown = Controller.metrics = nil

  def count(series)
    line = @registry.render.lines.find { |text| text.start_with?("#{series} ") }
    line&.split&.last.to_f
  end

  def test_ttl_after_finished_deletion_duration
    now = Time.now.utc
    job = {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => {"name" => "j", "namespace" => "ns", "uid" => "u"},
           "spec" => {"ttlSecondsAfterFinished" => 10}, "status" => {"completionTime" => (now - 30).iso8601}}
    operation = Controller::TTLController.new.plan(job, now: now).operations.first
    operation.notify(true)

    assert_equal 1, count("ttl_after_finished_controller_job_deletion_duration_seconds_count")
    assert_in_delta 20, count("ttl_after_finished_controller_job_deletion_duration_seconds_sum"), 2
  end

  def test_taint_eviction_counts_deletes_that_went_through
    node = {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "n"},
            "spec" => {"taints" => [{"key" => "node.kubernetes.io/unreachable", "effect" => "NoExecute", "timeAdded" => "2026-01-01T00:00:00Z"}]}}
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
           "spec" => {"nodeName" => "n"}, "status" => {"phase" => "Running"}}
    result = Controller::TaintEvictionController.new(clock: -> { Time.utc(2026, 1, 1, 0, 0, 30) }).plan(node, pods: [pod])
    result.operations.each { |operation| operation.notify(true) }

    assert_equal 1, count("taint_eviction_controller_pod_deletions_total")
    assert_equal 1, count("taint_eviction_controller_pod_deletion_duration_seconds_count")
    assert_in_delta(1e18, Controller::TaintEvictionController.go_duration_times_second(1), 0.001, "upstream's Duration * time.Second")
  end

  def test_cronjob_creation_skew
    at = Time.at(Time.now.to_i - 3).utc
    cron = {"apiVersion" => "batch/v1", "kind" => "CronJob",
            "metadata" => {"name" => "cron", "namespace" => "ns", "uid" => "c", "creationTimestamp" => (at - 600).iso8601},
            "spec" => {"schedule" => "* * * * *", "jobTemplate" => {"spec" => {"template" => {"spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}}}}}
    result = Controller::CronJobController.new(clock: -> { at }).plan(cron, jobs: [], now: at)
    result.operations.select(&:create?).each { |operation| operation.notify(true) }

    assert_equal 1, count("cronjob_controller_job_creation_skew_duration_seconds_count")
    assert_operator count("cronjob_controller_job_creation_skew_duration_seconds_sum"), :>=, 3
  end

  def test_no_registry_records_nothing
    Controller.metrics = nil
    job = {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => {"name" => "j", "namespace" => "ns", "uid" => "u"},
           "spec" => {"ttlSecondsAfterFinished" => 0}, "status" => {"completionTime" => "2026-01-01T00:00:00Z"}}
    Controller::TTLController.new.plan(job, now: Time.now.utc).operations.first.notify(true)
  end

  # reportSortingDeletionAgeRatioMetric.
  def test_replicaset_sorting_deletion_age_ratio
    now = Time.now.utc
    pod = lambda do |name, age|
      {"metadata" => {"name" => name, "uid" => name, "creationTimestamp" => (now - age).iso8601},
       "spec" => {"nodeName" => "n"},
       "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => "True",
                                                            "lastTransitionTime" => (now - age).iso8601}]}}
    end
    pods = [pod.call("old", 400), pod.call("young", 100), pod.call("mid", 250)]
    Controller::PodDeletionRanking.pods_to_delete(pods, 1)

    assert_equal 1, count("replicaset_controller_sorting_deletion_age_ratio_count")
    Controller::PodDeletionRanking.pods_to_delete(pods, 3)

    assert_equal 1, count("replicaset_controller_sorting_deletion_age_ratio_count"), "all Pods go: no sort, no metric"
  end

  # rootcacertpublisher recordMetrics: one per namespace sync.
  def test_root_ca_publisher_sync_metrics
    controller = Controller::RootCACertificatePublisherController.new(root_ca: "CA")
    namespaces = [{"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "a"}, "status" => {"phase" => "Active"}},
                  {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "b"}, "status" => {"phase" => "Active"}}]
    current = {"apiVersion" => "v1", "kind" => "ConfigMap",
               "metadata" => {"name" => "kube-root-ca.crt", "namespace" => "b",
                              "annotations" => {"kubernetes.io/description" => "x"}}, "data" => {"ca.crt" => "CA"}}
    result = controller.plan(nil, namespaces: namespaces, config_maps: [current])

    assert_equal 1, count(%(root_ca_cert_publisher_sync_total{code="200"})), "b needed nothing"
    error = Class.new(StandardError) { def status = 403 }.new("forbidden")
    result.operations.each { |operation| operation.notify(false, error) }

    assert_equal 1, count(%(root_ca_cert_publisher_sync_total{code="403"}))
    assert_equal 1, count(%(root_ca_cert_publisher_sync_duration_seconds_count{code="403"}))
  end

  def test_cluster_trust_bundle_publisher_sync_metrics
    controller = Controller::KubeAPIServerServingClusterTrustBundlePublisherController.new(ca_bundle: "CA")
    stale = {"apiVersion" => "certificates.k8s.io/v1beta1", "kind" => "ClusterTrustBundle", "metadata" => {"name" => "old"},
             "spec" => {"signerName" => "kubernetes.io/kube-apiserver-serving", "trustBundle" => "OLD"}}
    result = controller.plan(nil, trust_bundles: [stale])

    assert_equal 2, result.operations.length
    result.operations.first.notify(true)

    assert_equal 0, count(%(clustertrustbundle_publisher_sync_total{code="200"}))
    gone = Class.new(StandardError) { def status = 404 }.new("gone")
    result.operations.last.notify(false, gone)

    assert_equal 1, count(%(clustertrustbundle_publisher_sync_total{code="200"})), "a stale bundle already gone is fine"
    controller.plan(nil, trust_bundles: [result.operations.first.object])

    assert_equal 2, count(%(clustertrustbundle_publisher_sync_total{code="200"})), "nothing to do still counts a sync"
  end

  # node lifecycle controller: zone size / health / unhealthy nodes and the
  # evictions (NoExecute taints) per zone.
  def test_node_collector_zone_metrics
    Controller::NodeController::ZONE_NODES.clear
    now = Time.utc(2026, 1, 1, 1)
    controller = Controller::NodeController.new(clock: -> { now })
    zone = {"topology.kubernetes.io/region" => "r", "topology.kubernetes.io/zone" => "z"}
    node = lambda do |name, status|
      {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => zone},
       "status" => {"conditions" => [{"type" => "Ready", "status" => status, "lastHeartbeatTime" => (now - (status == "True" ? 1 : 3600)).iso8601,
                                      "lastTransitionTime" => (now - 3600).iso8601}]}}
    end
    controller.plan(node.call("a", "True"), pods: [], lease: {})
    result = controller.plan(node.call("b", "False"), pods: [], lease: {})
    key = "r:\u0000:z"
    labels = %(zone="#{key}")

    assert_equal 2, count(%(node_collector_zone_size{#{labels}}))
    assert_equal 1, count(%(node_collector_unhealthy_nodes_in_zone{#{labels}}))
    assert_equal 50, count(%(node_collector_zone_health{#{labels}}))
    assert_equal 0, count(%(node_collector_evictions_total{#{labels}}))
    # The taint write (not the status-subresource write) is the eviction.
    result.operations.find { |operation| operation.action == :update }.notify(true)

    assert_equal 1, count(%(node_collector_evictions_total{#{labels}}))
    Controller::NodeController.new.plan_orphans("b")

    assert_equal 1, count(%(node_collector_zone_size{#{labels}}))
    assert_equal 100, count(%(node_collector_zone_health{#{labels}}))
    assert_equal 2, count("node_collector_update_node_health_duration_seconds_count")
  end

  # endpointslice/metrics: per-sync endpoint and slice changes, and the
  # cache's gauges.
  def test_endpoint_slice_controller_metrics
    Controller::EndpointSliceController::SERVICE_CACHE.clear
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "s"},
               "spec" => {"selector" => {"app" => "web"}, "ipFamilies" => ["IPv4"], "ports" => [{"name" => "http", "port" => 80, "protocol" => "TCP"}],
                          "trafficDistribution" => "PreferClose"}}
    pods = Array.new(3) do |i|
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p#{i}", "namespace" => "ns", "uid" => "p#{i}", "labels" => {"app" => "web"}},
       "spec" => {"nodeName" => "n", "containers" => [{"name" => "c", "ports" => [{"containerPort" => 80}]}]},
       "status" => {"phase" => "Running", "podIP" => "10.0.0.#{i + 1}", "podIPs" => [{"ip" => "10.0.0.#{i + 1}"}],
                    "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    end
    result = Controller::EndpointSliceController.new.plan(service, pods: pods, endpoint_slices: [])
    result.operations.each { |operation| operation.notify(true) }

    assert_equal 1, count(%(endpoint_slice_controller_syncs{result="success"}))
    assert_equal 3, count("endpoint_slice_controller_endpoints_added_per_sync_sum")
    assert_equal 1, count(%(endpoint_slice_controller_changes{operation="create"}))
    assert_equal 1, count("endpoint_slice_controller_num_endpoint_slices")
    assert_equal 3, count("endpoint_slice_controller_endpoints_desired")
    assert_equal 1, count(%(endpoint_slice_controller_services_count_by_traffic_distribution{traffic_distribution="PreferClose"}))
    assert_equal 1,
                 count(%(endpoint_slice_controller_endpointslices_changed_per_sync_count{topology="Disabled",traffic_distribution="PreferClose"}))
  end

  def test_endpoint_slice_mirroring_controller_metrics
    Controller::EndpointSliceMirroringController::ENDPOINTS_CACHE.clear
    endpoints = {"apiVersion" => "v1", "kind" => "Endpoints", "metadata" => {"name" => "ext", "namespace" => "ns", "uid" => "e"},
                 "subsets" => [{"addresses" => [{"ip" => "10.1.0.1"}, {"ip" => "10.1.0.2"}], "ports" => [{"name" => "p", "port" => 80, "protocol" => "TCP"}]}]}
    result = Controller::EndpointSliceMirroringController.new.plan(endpoints, endpoint_slices: [])
    result.operations.each { |operation| operation.notify(true) }

    assert_equal 1, count("endpoint_slice_mirroring_controller_endpoints_sync_duration_count")
    assert_equal 2, count("endpoint_slice_mirroring_controller_endpoints_added_per_sync_sum")
    assert_equal 1, count(%(endpoint_slice_mirroring_controller_changes{operation="create"}))
    assert_equal 2, count("endpoint_slice_mirroring_controller_endpoints_desired")
    assert_equal 1, count("endpoint_slice_mirroring_controller_num_endpoint_slices")
  end
end
