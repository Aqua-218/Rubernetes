# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/bootstrap/control_plane_services"

# The collector scans a fixed corpus of kinds, so "I did not see the owner" is
# not the same statement as "the owner is gone".  Upstream never conflates the
# two: attemptToDeleteItem re-reads the owner through the REST mapper and only
# collects the dependent on a definitive 404
# (pkg/controller/garbagecollector/garbagecollector.go).  Conflating them would
# delete every object owned by a custom resource -- a kind the scan does not
# cover -- the moment garbage collection is switched on, and would delete a
# dependent whose owner the informer cache has simply not caught up with yet.
class GarbageCollectorUnknownOwnerTest < Minitest::Test
  Controller = Rubernetes::Controller

  KNOWN = ["v1/Service", "apps/v1/ReplicaSet"].freeze

  def dependent(owner_api_version:, owner_kind:, owner_uid: "owner-uid", name: "slice")
    {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid",
                    "ownerReferences" => [{"apiVersion" => owner_api_version, "kind" => owner_kind,
                                           "name" => "owner", "uid" => owner_uid}]}}
  end

  def names(result)
    result.operations.map { |operation| operation.object.dig("metadata", "name") }
  end

  def test_a_dependent_of_an_unscanned_kind_is_never_collected
    collector = Controller::GarbageCollector.new(known_kinds: KNOWN)
    orphan = dependent(owner_api_version: "example.com/v1", owner_kind: "Widget")

    assert_empty(collector.plan([orphan]).operations)
  end

  def test_a_dependent_of_a_scanned_kind_is_collected
    collector = Controller::GarbageCollector.new(known_kinds: KNOWN)
    orphan = dependent(owner_api_version: "v1", owner_kind: "Service")

    assert_equal(%w[slice], names(collector.plan([orphan])))
  end

  # An informer cache that has not yet seen a freshly created owner would make
  # its dependent look orphaned; the live read is what stops the deletion.
  def test_a_live_read_that_finds_the_owner_keeps_the_dependent
    asked = []
    lookup = lambda do |reference, namespace|
      asked << [Controller::Support.ref_value(reference, "kind", nil), namespace]
      true
    end
    collector = Controller::GarbageCollector.new(known_kinds: KNOWN, owner_lookup: lookup)

    assert_empty(collector.plan([dependent(owner_api_version: "v1", owner_kind: "Service")]).operations)
    assert_equal([%w[Service ns]], asked)
  end

  def test_a_live_read_that_confirms_the_owner_is_gone_collects_the_dependent
    collector = Controller::GarbageCollector.new(known_kinds: KNOWN, owner_lookup: ->(_reference, _namespace) { false })

    assert_equal(%w[slice], names(collector.plan([dependent(owner_api_version: "v1", owner_kind: "Service")])))
  end

  # A lookup that raises cannot be read as "gone"; the kind is scanned, so the
  # corpus still decides, and an unscanned kind still keeps the dependent.
  def test_a_failing_live_read_falls_back_to_the_scanned_corpus
    lookup = ->(_reference, _namespace) { raise IOError, "apiserver unreachable" }
    collector = Controller::GarbageCollector.new(known_kinds: KNOWN, owner_lookup: lookup)

    assert_equal(%w[slice], names(collector.plan([dependent(owner_api_version: "v1", owner_kind: "Service")])))
    assert_empty(collector.plan([dependent(owner_api_version: "example.com/v1", owner_kind: "Widget")]).operations)
  end

  # Without a known-kind set the caller has declared the corpus complete, which
  # is how every in-memory planner test uses it.
  def test_an_unrestricted_planner_keeps_its_old_behaviour
    collector = Controller::GarbageCollector.new

    assert_equal(%w[slice], names(collector.plan([dependent(owner_api_version: "example.com/v1", owner_kind: "Widget")])))
  end

  def test_a_live_owner_in_the_corpus_is_still_honoured
    collector = Controller::GarbageCollector.new(known_kinds: KNOWN)
    owner = {"apiVersion" => "v1", "kind" => "Service",
             "metadata" => {"name" => "owner", "namespace" => "ns", "uid" => "owner-uid"}}

    assert_empty(collector.plan([owner, dependent(owner_api_version: "v1", owner_kind: "Service")]).operations)
  end

  class CustomCollectionClient
    PATH = "/apis/example.com/v1/specialwidgets"

    attr_reader :requests

    def initialize(dependent)
      @dependent = dependent
      @requests = []
    end

    def get(resource, name = nil, **)
      @requests << [resource, name]
      case [resource, name]
      when ["pods", nil] then list([])
      when ["customresourcedefinitions", nil] then list([definition])
      when [PATH, nil] then list([@dependent])
      when [PATH, "dependent"] then @dependent
      else
        raise Rubernetes::Client::APIError.new("not found", response: Struct.new(:status).new(404))
      end
    end

    def list(items)
      {"items" => items, "metadata" => {"resourceVersion" => "42"}}
    end

    def delete(resource, name, options:, **)
      @requests << [resource, name, options]
      {"kind" => "Status"}
    end

    def definition
      {"spec" => {"group" => "example.com", "scope" => "Cluster", "names" => {"kind" => "Widget", "plural" => "specialwidgets"},
                  "versions" => [{"name" => "v1", "served" => true, "storage" => true}]},
       "status" => {"conditions" => [{"type" => "Established", "status" => "True"}]}}
    end
  end

  def test_custom_collection_uses_established_plural_and_cluster_scope
    instance = dependent(owner_api_version: "example.com/v1", owner_kind: "Widget", name: "dependent")
    instance["apiVersion"] = "example.com/v1"
    instance["kind"] = "Widget"
    instance.fetch("metadata").delete("namespace")
    client = CustomCollectionClient.new(instance)
    store = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [Controller::ResourceDescriptor.parse("Pod")])
    gc = Controller::Builtins::GarbageCollectorController.new
    result = gc.plan_orphans("periodic", store: store)

    assert_equal ["dependent"], names(result)
    descriptor = result.operations.first.resource

    assert_equal "specialwidgets", descriptor.resource
    assert_predicate descriptor, :cluster_scoped?
    assert_includes client.requests, [CustomCollectionClient::PATH, "owner"]
    assert_includes client.requests, [CustomCollectionClient::PATH, "dependent"]
    store.apply(result.operations.first)

    assert_includes client.requests, [CustomCollectionClient::PATH, "dependent", {"preconditions" => {"uid" => "dependent-uid"}}]
  end
end
