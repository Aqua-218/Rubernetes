# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# "When no endpoint slices would usually exist, we need to add a placeholder"
# (staging/src/k8s.io/endpointslice/reconciler.go).  A Service with a selector
# always owns at least one EndpointSlice even when it matches no Pods; we
# created none and deleted every slice it had, so [sig-network] EndpointSlice
# "should create and delete EndpointSlices for a Service with a selector that
# matches no pods" found nothing when listing by kubernetes.io/service-name.
class EndpointSlicePlaceholderTest < Minitest::Test
  Controller = Rubernetes::Controller::EndpointSliceController

  def service(selector: {"does-not-match-anything" => "true"})
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "example-empty-selector", "namespace" => "ns", "uid" => "svc-uid"},
     # ipFamilies as the API server defaults it for a single-stack cluster;
     # without any family and without a clusterIP the controller assumes a
     # dual-stack headless Service, as upstream does.
     "spec" => {"selector" => selector, "ipFamilies" => ["IPv4"],
                "ports" => [{"name" => "example", "port" => 80, "protocol" => "TCP"}]}}
  end

  def reconcile(svc, pods: [], slices: [])
    Controller.new.reconcile(svc, pods: pods, endpoint_slices: slices, apply: false)
  end

  def creates(result)
    result.operations.select { |operation| operation.action == :create }
  end

  def deletes(result)
    result.operations.select { |operation| operation.action == :delete }
  end

  def test_a_service_matching_no_pods_gets_one_empty_slice
    result = reconcile(service)

    created = creates(result)

    assert_equal 1, created.length, "a Service with a selector must own a placeholder slice"
    slice = created.first.object

    assert_equal "ns", slice.dig("metadata", "namespace")
    assert_equal "example-empty-selector", slice.dig("metadata", "labels", "kubernetes.io/service-name")
    assert_empty Array(slice["endpoints"])
    assert_empty Array(slice["ports"])
  end

  def test_an_existing_placeholder_is_kept_not_recreated
    placeholder = reconcile(service).operations.first.object
    result = reconcile(service, slices: [placeholder])

    assert_empty creates(result), "the placeholder must not be recreated"
    assert_empty deletes(result), "the placeholder must not be deleted"
  end

  def test_a_service_without_a_selector_gets_no_placeholder
    result = reconcile(service(selector: {}))

    assert_empty creates(result)
  end

  def test_a_service_with_endpoints_gets_real_slices_not_a_placeholder
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-uid",
                          "labels" => {"app" => "demo"}},
           "spec" => {"nodeName" => "node-a",
                      "containers" => [{"name" => "c", "ports" => [{"containerPort" => 80}]}]},
           "status" => {"podIP" => "10.0.0.5", "phase" => "Running",
                        "conditions" => [{"type" => "Ready", "status" => "True"}]}}
    result = reconcile(service(selector: {"app" => "demo"}), pods: [pod])

    created = creates(result)

    assert_equal 1, created.length
    refute_empty Array(created.first.object["endpoints"]),
                 "a Service with a matching Pod must get a real slice"
  end

  def test_the_placeholder_replaces_stale_slices_that_no_longer_apply
    stale = reconcile(service(selector: {"app" => "demo"}),
                      pods: [{"apiVersion" => "v1", "kind" => "Pod",
                              "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u",
                                             "labels" => {"app" => "demo"}},
                              "spec" => {"nodeName" => "n",
                                         "containers" => [{"name" => "c", "ports" => [{"containerPort" => 80}]}]},
                              "status" => {"podIP" => "10.0.0.5", "phase" => "Running",
                                           "conditions" => [{"type" => "Ready", "status" => "True"}]}}])
      .operations.first.object

    # The Pod is gone now: the populated slice goes and a placeholder arrives.
    result = reconcile(service(selector: {"app" => "demo"}), pods: [], slices: [stale])

    assert_equal 1, creates(result).length
    assert_empty Array(creates(result).first.object["endpoints"])
  end

  class MissingServiceStore < Rubernetes::Controller::StoreAdapter
    def initialize; end
    def find(*, **) = nil
  end

  def test_a_managed_slice_of_a_deleted_service_is_deleted
    slice = {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
             "metadata" => {"name" => "example-empty-selector-abc", "namespace" => "ns",
                            "labels" => {"kubernetes.io/service-name" => "example-empty-selector",
                                         "endpointslice.kubernetes.io/managed-by" => "endpointslice-controller.k8s.io"}}}
    result = Controller.new.plan(slice, store: MissingServiceStore.new)

    assert_equal [:delete], result.operations.map(&:action)

    foreign = Rubernetes::Controller::Support.deep_copy(slice)
    foreign["metadata"]["labels"]["endpointslice.kubernetes.io/managed-by"] = "someone-else"

    assert_empty Controller.new.plan(foreign, store: MissingServiceStore.new).operations
  end
end
