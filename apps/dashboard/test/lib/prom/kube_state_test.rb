# frozen_string_literal: true

require "test_helper"

module Prom
  class KubeStateTest < ActiveSupport::TestCase
    class FakeClient
      def initialize(objects) = @objects = objects

      def get(resource, api_version: "v1", **)
        {"items" => @objects.fetch(resource, [])}
      end
    end

    OBJECTS = {
      "nodes" => [{"metadata" => {"name" => "worker-0", "creationTimestamp" => "2026-09-29T08:00:00Z"},
                   "spec" => {},
                   "status" => {"nodeInfo" => {"kernelVersion" => "7.0.0", "osImage" => "Ubuntu", "kubeletVersion" => "v1.36.2"},
                                "addresses" => [{"type" => "InternalIP", "address" => "10.240.0.1"}],
                                "conditions" => [{"type" => "Ready", "status" => "True"}],
                                "capacity" => {"cpu" => "64", "memory" => "128Gi", "pods" => "110"},
                                "allocatable" => {"cpu" => "63500m", "memory" => "120Gi", "pods" => "110"}}}],
      "namespaces" => [{"metadata" => {"name" => "gitlab"}, "status" => {"phase" => "Active"}}],
      "pods" => [{"metadata" => {"name" => "web-1", "namespace" => "gitlab", "uid" => "u1",
                                 "ownerReferences" => [{"kind" => "ReplicaSet", "name" => "web-abc", "controller" => true}]},
                  "spec" => {"nodeName" => "worker-0", "containers" => [{"name" => "app", "resources" => {"requests" => {"cpu" => "250m", "memory" => "1Gi"},
                                                                                                          "limits" => {"memory" => "2Gi"}}}]},
                  "status" => {"phase" => "Running", "podIP" => "10.240.0.5", "hostIP" => "10.240.0.1", "startTime" => "2026-09-29T09:00:00Z",
                               "conditions" => [{"type" => "Ready", "status" => "True"}],
                               "containerStatuses" => [{"name" => "app", "ready" => true, "restartCount" => 3, "state" => {"running" => {}}}],
                               "initContainerStatuses" => [{"name" => "init", "ready" => false, "restartCount" => 0,
                                                            "state" => {"terminated" => {"reason" => "Completed"}}}]}},
                 {"metadata" => {"name" => "crash", "namespace" => "gitlab", "uid" => "u2"}, "spec" => {"containers" => [{"name" => "c"}]},
                  "status" => {"phase" => "Running", "containerStatuses" => [{"name" => "c", "ready" => false, "restartCount" => 9,
                                                                              "state" => {"waiting" => {"reason" => "CrashLoopBackOff"}}}]}}],
      "deployments" => [{"metadata" => {"name" => "web", "namespace" => "gitlab", "generation" => 4},
                         "spec" => {"replicas" => 2},
                         "status" => {"replicas" => 2, "availableReplicas" => 1, "readyReplicas" => 1, "updatedReplicas" => 2, "observedGeneration" => 4,
                                      "conditions" => [{"type" => "Available", "status" => "False"}]}}],
      "statefulsets" => [{"metadata" => {"name" => "db", "namespace" => "gitlab"}, "spec" => {"replicas" => 1},
                          "status" => {"replicas" => 1, "readyReplicas" => 1}}],
      "daemonsets" => [{"metadata" => {"name" => "ds", "namespace" => "kube-system"},
                        "status" => {"desiredNumberScheduled" => 3, "numberReady" => 2}}],
      "jobs" => [{"metadata" => {"name" => "migrate", "namespace" => "gitlab"},
                  "status" => {"succeeded" => 1, "conditions" => [{"type" => "Complete", "status" => "True"}]}}],
      "services" => [{"metadata" => {"name" => "web", "namespace" => "gitlab"},
                      "spec" => {"clusterIP" => "10.96.0.5", "type" => "ClusterIP"}}],
      "persistentvolumeclaims" => [{"metadata" => {"name" => "data", "namespace" => "gitlab"}, "spec" => {"resources" => {"requests" => {"storage" => "50Gi"}}},
                                    "status" => {"phase" => "Bound"}}]
    }.freeze

    test "renders kube-state-metrics compatible series that the exposition parser accepts" do
      text = Prom::KubeState.new(client: FakeClient.new(OBJECTS)).render
      families = Prom::Exposition.parse(text)
      by_name = families.to_h { |f| [f.name, f] }
      samples = families.flat_map(&:samples)

      ready = samples.find do |s|
        s.name == "kube_node_status_condition" && s.labels["condition"] == "Ready" && s.labels["status"] == "true"
      end

      assert_in_delta(1.0, ready.value)
      cpu = samples.find { |s| s.name == "kube_node_status_allocatable" && s.labels["resource"] == "cpu" }

      assert_in_delta(63.5, cpu.value)
      memory = samples.find { |s| s.name == "kube_node_status_capacity" && s.labels["resource"] == "memory" }

      assert_equal 128 * (1024**3), memory.value

      phase = samples.find { |s| s.name == "kube_pod_status_phase" && s.labels["pod"] == "web-1" && s.labels["phase"] == "Running" }

      assert_in_delta(1.0, phase.value)
      restarts = samples.find { |s| s.name == "kube_pod_container_status_restarts_total" && s.labels["pod"] == "crash" }

      assert_in_delta(9.0, restarts.value)
      assert_equal "counter", by_name["kube_pod_container_status_restarts_total"].type
      waiting = samples.find { |s| s.name == "kube_pod_container_status_waiting_reason" }

      assert_equal "CrashLoopBackOff", waiting.labels["reason"]
      request = samples.find { |s| s.name == "kube_pod_container_resource_requests" && s.labels["resource"] == "cpu" }

      assert_in_delta(0.25, request.value)
      owner = samples.find { |s| s.name == "kube_pod_owner" }

      assert_equal(
        {"namespace" => "gitlab", "pod" => "web-1", "uid" => "u1", "owner_kind" => "ReplicaSet", "owner_name" => "web-abc",
         "owner_is_controller" => "true"}, owner.labels
      )

      available = samples.find { |s| s.name == "kube_deployment_status_replicas_available" }

      assert_in_delta(1.0, available.value)
      condition = samples.find { |s| s.name == "kube_deployment_status_condition" && s.labels["status"] == "false" }

      assert_in_delta(1.0, condition.value)
      assert_in_delta(3.0, samples.find { |s| s.name == "kube_daemonset_status_desired_number_scheduled" }.value)
      assert_in_delta(1.0, samples.find { |s| s.name == "kube_job_complete" && s.labels["condition"] == "true" }.value)
      assert_equal 50 * (1024**3), samples.find { |s| s.name == "kube_persistentvolumeclaim_resource_requests_storage_bytes" }.value
      assert_in_delta(1.0, samples.find { |s| s.name == "kube_namespace_status_phase" && s.labels["phase"] == "Active" }.value)
    end

    test "is an in-process scrape target" do
      target = Prom::KubeState.new(client: FakeClient.new(OBJECTS)).target

    assert_equal "kube-state", target.job
    status, body = target.fetch.call

    assert_equal 200, status
    assert_includes body, "kube_pod_info{"
  end
end
