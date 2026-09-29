# frozen_string_literal: true

# Leader election renews its Lease the way client-go's LeaseLock does -- a
# PUT carrying the resourceVersion it read -- because the bootstrap policy
# gives kube-controller-manager and kube-scheduler get/update on their lease
# and nothing else.  A merge patch was refused with 403 under the component
# identities, and the elector took any APIError for a transient failure, so
# neither component ever renewed a lease it had acquired and nothing said so.

require_relative "../test_helper"
require "rubernetes"
require "rubernetes/bootstrap"

class LeaseUpdateVerbTest < Minitest::Test
  class Client
    attr_reader :calls

    def initialize = @calls = []

    def update(object, namespace:)
      @calls << [:update, namespace, object]
      object.merge("metadata" => object["metadata"].merge("resourceVersion" => "8"))
    end

    def patch(*args, **options)
      @calls << [:patch, args, options]
      raise "a lease must not be patched"
    end
  end

  def lease(resource_version)
    {"apiVersion" => "coordination.k8s.io/v1", "kind" => "Lease",
     "metadata" => {"name" => "kube-controller-manager", "namespace" => "kube-system", "resourceVersion" => resource_version,
                    "managedFields" => [{"manager" => "kube-controller-manager", "operation" => "Update"}]},
     "spec" => {"holderIdentity" => "cm", "renewTime" => "2026-09-25T05:57:39.697516Z", "leaseDurationSeconds" => 15}}
  end

  def test_a_lease_is_renewed_with_a_put_carrying_the_read_resource_version
    client = Client.new
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(
      client: client, resource_descriptors: [Rubernetes::Controller::ResourceDescriptor.parse("Lease")]
    )
    current = lease("7")
    renewed = Marshal.load(Marshal.dump(current))
    renewed["spec"]["renewTime"] = "2026-09-25T05:57:41.000000Z"
    adapter.update(renewed, descriptor: Rubernetes::Controller::ResourceDescriptor.parse("Lease"), existing: current)

    verb, namespace, body = client.calls.fetch(0)
    assert_equal :update, verb
    assert_equal "kube-system", namespace
    assert_equal "7", body.dig("metadata", "resourceVersion")
    refute body["metadata"].key?("managedFields")
    assert_equal "2026-09-25T05:57:41.000000Z", body.dig("spec", "renewTime")
  end

  def test_a_refused_renewal_is_not_transient
    elector = Rubernetes::Controller::LeaseElector.new(store: Object.new, identity: "cm")
    forbidden = Rubernetes::Client::APIError.allocate
    forbidden.define_singleton_method(:status) { 403 }
    forbidden.define_singleton_method(:message) { "leases is forbidden" }
    refute elector.send(:transient_error?, forbidden)
    unavailable = Rubernetes::Client::APIError.allocate
    unavailable.define_singleton_method(:status) { 503 }
    unavailable.define_singleton_method(:message) { "unavailable" }
    assert elector.send(:transient_error?, unavailable)
  end
end
