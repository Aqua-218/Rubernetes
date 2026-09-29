# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# An EndpointSlice event must reach exactly the Service (or, for a mirror, the
# Endpoints) it belongs to.  Routed as a plain :all watch it reconciled a key
# named after the slice, and routed by label against selector-less Endpoints it
# fanned out to every Endpoints in the namespace: 150 Services in one namespace
# produced 18,000 mirroring enqueues in thirty seconds.
class EndpointSliceEventRoutingTest < Minitest::Test
  Controller = Rubernetes::Controller

  def slice(managed_by:, service: "web")
    labels = {"endpointslice.kubernetes.io/managed-by" => managed_by}
    labels["kubernetes.io/service-name"] = service if service
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
     "metadata" => {"name" => "web-abc12", "namespace" => "ns", "labels" => labels}}
  end

  def slice_watch(controller)
    Controller.default_registry.fetch(controller).watches.find { |watch| watch.resource.kind == "EndpointSlice" }
  end

  def test_the_endpointslice_controller_routes_its_own_slices_to_their_service
    watch = slice_watch("endpointslice-controller")
    own = slice(managed_by: "endpointslice-controller.k8s.io")

    assert_equal :self, watch.route
    assert watch.predicate.call(own)
    assert_equal "ns/web", watch.queue_key.call(own)
    refute watch.predicate.call(slice(managed_by: "endpointslicemirroring-controller.k8s.io"))
    assert_nil watch.queue_key.call(slice(managed_by: "endpointslice-controller.k8s.io", service: nil))
  end

  def test_the_mirroring_controller_routes_its_own_slices_to_their_endpoints
    watch = slice_watch("endpointslice-mirroring-controller")
    mirror = slice(managed_by: "endpointslicemirroring-controller.k8s.io")

    assert_equal :self, watch.route
    assert watch.predicate.call(mirror)
    assert_equal "ns/web", watch.queue_key.call(mirror)
    refute watch.predicate.call(slice(managed_by: "endpointslice-controller.k8s.io"))
  end
end
