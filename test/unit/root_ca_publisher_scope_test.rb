# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/api"

# pkg/controller/certificates/rootcacertpublisher/publisher.go syncs exactly one
# namespace per work item.  Ours planned every namespace on every key, so each
# reconcile was O(namespaces) and a single namespace that refuses writes -- one
# being terminated, one behind a fail-closed webhook -- aborted the batch for
# all of them.  Under a parallel conformance run that starved freshly created
# namespaces of both their kube-root-ca.crt ConfigMap and, behind it in the same
# work queue, their default ServiceAccount.
class RootCAPublisherScopeTest < Minitest::Test
  Controller = Rubernetes::Controller

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    @adapter = Controller::StoreAdapter.new(@store)
    @namespace_descriptor = Controller::ResourceDescriptor.parse("Namespace")
  end

  def namespace(name, phase: "Active")
    {"apiVersion" => "v1", "kind" => "Namespace",
     "metadata" => {"name" => name, "uid" => "uid-#{name}"},
     "status" => {"phase" => phase}}
  end

  def store_namespaces(*names)
    names.each { |name| @adapter.create(namespace(name), descriptor: @namespace_descriptor) }
  end

  def publisher
    Controller::RootCACertificatePublisherController.new(root_ca: "CA-1")
  end

  def test_a_namespace_key_plans_only_its_own_config_map
    store_namespaces("alpha", "beta", "gamma")

    operations = publisher.plan(namespace("alpha"), store: @store).operations

    assert_equal(1, operations.length)
    assert_equal("alpha", operations.first.object.dig("metadata", "namespace"))
  end

  # A ConfigMap key names the namespace whose published copy has to be repaired.
  def test_a_config_map_key_plans_only_its_own_namespace
    store_namespaces("alpha", "beta")
    config_map = {"apiVersion" => "v1", "kind" => "ConfigMap",
                  "metadata" => {"name" => "kube-root-ca.crt", "namespace" => "beta"}}

    operations = publisher.plan(config_map, store: @store).operations

    assert_equal(1, operations.length)
    assert_equal("beta", operations.first.object.dig("metadata", "namespace"))
  end

  # A terminating namespace refuses new content, so planning a write into it is
  # a guaranteed 403 that used to abort every other namespace in the same batch.
  def test_a_terminating_namespace_is_planned_for_nothing
    terminating = namespace("closing")
    terminating["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    @adapter.create(terminating, descriptor: @namespace_descriptor)

    assert_empty(publisher.plan(namespace("closing"), store: @store).operations)
  end

  def test_an_up_to_date_namespace_plans_nothing
    store_namespaces("alpha")
    created = publisher.plan(namespace("alpha"), store: @store).creates.first.object
    @adapter.create(created, descriptor: Controller::ResourceDescriptor.parse("ConfigMap"))

    assert_empty(publisher.plan(namespace("alpha"), store: @store).operations)
  end

  # The published ConfigMap is deleted by users and by namespace teardown, and
  # the key then names nothing: the orphan hook is what brings it back.
  def test_a_deleted_config_map_is_republished_from_its_key
    store_namespaces("alpha")

    operations = publisher.plan_orphans("alpha/kube-root-ca.crt", store: @store).operations

    assert_equal(1, operations.length)
    assert_equal("alpha", operations.first.object.dig("metadata", "namespace"))
  end

  # The stub the orphan hook used to plan with was taken for the live object,
  # so the republish went out as an UPDATE the API answered 404 -- and the
  # ConfigMap never came back within the 30 s the conformance spec waits.
  def test_a_deleted_config_map_is_republished_with_a_create_not_an_update
    store_namespaces("alpha")

    result = publisher.plan_orphans("alpha/kube-root-ca.crt", store: @store)

    assert_equal([:create], result.operations.map(&:action))
    assert_equal("CA-1", result.operations.first.object.dig("data", "ca.crt"))
  end

  def test_an_orphan_key_for_a_namespace_that_is_gone_plans_nothing
    assert_empty(publisher.plan_orphans("vanished/kube-root-ca.crt", store: @store).operations)
  end

  def test_an_orphan_key_for_another_config_map_is_ignored
    store_namespaces("alpha")

    assert_nil(publisher.plan_orphans("alpha/some-other-map", store: @store))
  end

  # Without a key to scope to -- a full resync -- every namespace is still fair
  # game, which is what keeps a missed watch event from stranding one.
  def test_a_keyless_resync_still_covers_every_namespace
    store_namespaces("alpha", "beta", "gamma")

    namespaces = publisher.plan(nil, store: @store).operations.map do |operation|
      operation.object.dig("metadata", "namespace")
    end

    assert_equal(%w[alpha beta gamma], namespaces.sort)
  end
end
