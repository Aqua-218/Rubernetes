# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# "Delete the corresponding endpoints, as the service has been deleted"
# (pkg/controller/endpoint/endpoints_controller.go:370).  We returned an empty
# plan when the Service was gone, so the Endpoints object survived for ever --
# "[sig-network] EndpointsController should create and delete Endpoints for a
# Service" fails with "Endpoints resource not deleted after Service was
# deleted".
class EndpointsOrphanDeletionTest < Minitest::Test
  Controller = Rubernetes::Controller::Builtins::EndpointController

  class Store
    def initialize(objects) = @objects = objects

    def find(descriptor, name:, namespace: nil)
      @objects.find do |object|
        object["kind"] == descriptor.kind &&
          object.dig("metadata", "name") == name &&
          object.dig("metadata", "namespace") == namespace
      end
    end

    def list(descriptor, namespace: nil)
      @objects.select { |o| o["kind"] == descriptor.kind && o.dig("metadata", "namespace") == namespace }
    end
  end

  def endpoints
    {"apiVersion" => "v1", "kind" => "Endpoints",
     "metadata" => {"name" => "svc", "namespace" => "ns"}, "subsets" => []}
  end

  def service
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "svc", "namespace" => "ns"},
     "spec" => {"selector" => {"app" => "demo"}, "ports" => [{"port" => 80}]}}
  end

  def plan_for(objects, resource)
    Controller.new.plan(resource, store: Store.new(objects))
  end

  def test_endpoints_are_deleted_when_their_service_is_gone
    result = plan_for([endpoints], endpoints)
    deletes = result.operations.select { |operation| operation.action == :delete }

    assert_equal 1, deletes.length, "an Endpoints whose Service is gone must be deleted"
    assert_equal "svc", deletes.first.object.dig("metadata", "name")
  end

  def test_endpoints_are_kept_while_the_service_exists
    result = plan_for([endpoints, service], endpoints)

    assert_empty result.operations.select { |operation| operation.action == :delete }
  end
end

# endpoints_controller.go syncService: a Service without a selector gets no
# Endpoints from the controller; the user owns that object.  Creating an empty
# one raced the user's create ("[sig-network] EndpointSliceMirroring should
# mirror a custom Endpoints resource": AlreadyExists on its own Endpoints).
class EndpointsSelectorlessServiceTest < Minitest::Test
  Controller = Rubernetes::Controller::Builtins::EndpointController

  def selectorless_service
    {"apiVersion" => "v1", "kind" => "Service",
     "metadata" => {"name" => "example-custom-endpoints", "namespace" => "ns"},
     "spec" => {"ports" => [{"name" => "example", "port" => 80, "protocol" => "TCP"}]}}
  end

  def test_a_service_without_a_selector_plans_no_endpoints
    result = Controller.new.plan(selectorless_service, store: EndpointsOrphanDeletionTest::Store.new([selectorless_service]))

    assert_empty result.operations
  end

  def test_a_users_endpoints_for_a_selectorless_service_are_left_alone
    user_endpoints = {"apiVersion" => "v1", "kind" => "Endpoints",
                      "metadata" => {"name" => "example-custom-endpoints", "namespace" => "ns"},
                      "subsets" => [{"addresses" => [{"ip" => "10.1.2.3"}], "ports" => [{"port" => 80}]}]}
    store = EndpointsOrphanDeletionTest::Store.new([selectorless_service, user_endpoints])

    assert_empty Controller.new.plan(selectorless_service, store: store).operations
    assert_empty Controller.new.plan(user_endpoints, store: store).operations
  end
end
