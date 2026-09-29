# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A mirrored EndpointSlice belongs to the Endpoints object it mirrors, so when
# that object is deleted its mirror has to go with it.  Upstream's mirroring
# controller does that itself -- its queue receives the Endpoints key on a
# delete and it removes the slices -- rather than waiting for the garbage
# collector to notice the owner is gone.  Leaving it to the collector made the
# removal wait for the next sweep, and "[sig-network] EndpointSliceMirroring
# should mirror a custom Endpoints resource through create update and delete"
# allows twelve seconds for it.
class EndpointSliceMirrorDeletionTest < Minitest::Test
  Controller = Rubernetes::Controller

  MANAGED_BY = "endpointslicemirroring-controller.k8s.io"

  def slice(name, service:, managed_by: MANAGED_BY)
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid",
                    "labels" => {"kubernetes.io/service-name" => service,
                                 "endpointslice.kubernetes.io/managed-by" => managed_by}},
     "addressType" => "IPv4", "endpoints" => [], "ports" => []}
  end

  def endpoints(name)
    {"apiVersion" => "v1", "kind" => "Endpoints",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid"},
     "subsets" => []}
  end

  def adapter_with(objects)
    store = Rubernetes::Storage::MemoryStore.new
    adapter = Controller::StoreAdapter.new(store)
    Array(objects).each do |object|
      descriptor = Controller::ResourceDescriptor.parse(object)
      store.create("registry/#{descriptor.api_version}/#{descriptor.resource}/ns/#{object.dig("metadata", "name")}",
                   object)
    end
    adapter
  end

  def controller = Controller::EndpointSliceMirroringController.new(store: nil)

  def plan_orphans(objects, key: "ns/ex")
    controller.plan_orphans(key, store: adapter_with(objects))
  end

  def test_the_mirror_is_deleted_when_its_endpoints_is_gone
    result = plan_orphans([slice("ex-mirror-1", service: "ex")])

    refute_nil(result)
    assert_equal([:delete], result.operations.map(&:action))
    assert_equal(%w[ex-mirror-1], result.operations.map { |o| o.object.dig("metadata", "name") })
  end

  # A live Endpoints object keeps its mirror.
  def test_a_live_endpoints_keeps_its_mirror
    assert_nil(plan_orphans([endpoints("ex"), slice("ex-mirror-1", service: "ex")]))
  end

  # A slice belonging to another Service is not ours.
  def test_another_services_slice_is_untouched
    assert_nil(plan_orphans([slice("other-1", service: "other")]))
  end

  # A slice the endpointslice controller owns is not a mirror.
  def test_a_slice_from_another_controller_is_untouched
    assert_nil(plan_orphans([slice("ex-1", service: "ex", managed_by: "endpointslice-controller.k8s.io")]))
  end

  def test_a_key_without_a_namespace_plans_nothing
    assert_nil(plan_orphans([slice("ex-mirror-1", service: "ex")], key: "ex"))
  end

  def test_nothing_to_delete_plans_nothing
    assert_nil(plan_orphans([]))
  end
end
