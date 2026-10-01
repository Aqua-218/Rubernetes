# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller/advanced_misc"

# pkg/controller/resourceclaim (v1.36.2): claims created from a Pod's
# ResourceClaimTemplates and recorded in status.resourceClaimStatuses, and
# allocated claims reserved for Pods bound without the scheduler.  Only the
# claim-side cleanup existed before, so a Pod using a template never got a
# claim and never scheduled.
class ResourceClaimControllerTest < Minitest::Test
  Controller = Rubernetes::Controller
  RCC = Controller::ResourceClaimController

  class Adapter < Controller::StoreAdapter
    def initialize(objects)
      @objects = objects
    end

    def list(descriptor, namespace: :all)
      @objects.select do |object|
        Controller::Support.kind(object) == descriptor.kind &&
          (namespace == :all || Controller::Support.namespace(object) == namespace)
      end
    end

    def find(descriptor, name:, namespace: nil)
      list(descriptor, namespace: namespace || :all).find { |object| Controller::Support.name(object) == name }
    end
  end

  def controller = RCC.new(name: "resourceclaim-controller", random: Random.new(7))

  def template(name = "gpu-template")
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaimTemplate",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => "t-1"},
     "spec" => {"metadata" => {"labels" => {"team" => "ml"}, "annotations" => {"note" => "x"}},
                "spec" => {"devices" => {"requests" => [{"name" => "gpu", "exactly" => {"deviceClassName" => "gpu"}}]}}}}
  end

  def pod(name = "p1", status: {}, node: nil, claims: [{"name" => "gpu", "resourceClaimTemplateName" => "gpu-template"}])
    spec = {"containers" => [{"name" => "c", "image" => "x"}], "resourceClaims" => claims}
    spec["nodeName"] = node if node
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"},
     "spec" => spec, "status" => status}
  end

  def claim(name, owner: nil, pod_claim: nil, allocation: nil, reserved: nil)
    metadata = {"name" => name, "namespace" => "ns", "uid" => "c-#{name}"}
    if owner
      metadata["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "Pod", "name" => owner["metadata"]["name"],
                                      "uid" => owner["metadata"]["uid"], "controller" => true}]
    end
    metadata["annotations"] = {"resource.kubernetes.io/pod-claim-name" => pod_claim} if pod_claim
    status = {}
    status["allocation"] = allocation if allocation
    status["reservedFor"] = reserved if reserved
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim", "metadata" => metadata,
     "spec" => {"devices" => {"requests" => []}}, "status" => status}
  end

  def test_a_claim_is_created_from_the_template_and_recorded_in_the_pod_status
    result = controller.plan(pod, claims: [], templates: [template])
    create, status = result.operations

    assert_equal :create, create.action
    created = create.object

    assert_match(/\Ap1-gpu-[bcdfghjklmnpqrstvwxz2456789]{5}\z/, created.dig("metadata", "name"))
    assert_equal "ns", created.dig("metadata", "namespace")
    assert_equal [{"apiVersion" => "v1", "kind" => "Pod", "name" => "p1", "uid" => "uid-p1", "controller" => true, "blockOwnerDeletion" => true}],
                 created.dig("metadata", "ownerReferences")
    assert_equal({"note" => "x", "resource.kubernetes.io/pod-claim-name" => "gpu"}, created.dig("metadata", "annotations"))
    assert_equal({"team" => "ml"}, created.dig("metadata", "labels"))
    assert_equal template.dig("spec", "spec"), created["spec"]
    assert_equal :status_update, status.action
    assert_equal({"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => created.dig("metadata", "name")}]}, status.patch)
  end

  def test_nothing_to_do_once_the_claim_exists_and_is_recorded
    owner = pod
    existing = claim("p1-gpu-abcde", owner: owner, pod_claim: "gpu")
    recorded = pod(status: {"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => "p1-gpu-abcde"}]})

    assert_empty controller.plan(recorded, claims: [existing], templates: [template]).operations
  end

  def test_a_claim_created_before_the_status_update_failed_is_reused
    owner = pod
    existing = claim("p1-gpu-abcde", owner: owner, pod_claim: "gpu")
    operations = controller.plan(owner, claims: [existing], templates: [template]).operations

    assert_equal [:status_update], operations.map(&:action)
    assert_equal({"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => "p1-gpu-abcde"}]}, operations.first.patch)
  end

  def test_a_recorded_claim_owned_by_someone_else_is_replaced
    stranger = claim("p1-gpu-abcde", owner: pod("other"), pod_claim: "gpu")
    recorded = pod(status: {"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => "p1-gpu-abcde"}]})
    operations = controller.plan(recorded, claims: [stranger], templates: [template]).operations

    assert_equal %i[create status_update], operations.map(&:action)
    refute_equal "p1-gpu-abcde", operations.first.object.dig("metadata", "name")
  end

  def test_a_missing_template_is_reported_on_the_pod
    result = controller.plan(pod, claims: [], templates: [])

    assert_empty result.operations
    event = result.events.fetch(0)

    assert_equal "FailedResourceClaimCreation", event["reason"]
    assert_equal "PodResourceClaim gpu: resource claim template \"gpu-template\": resourceclaimtemplate.resource.k8s.io \"gpu-template\" not found",
                 event["message"]
  end

  def test_a_scheduled_pod_reserves_its_allocated_claims
    shared = claim("shared", allocation: {"devices" => {"results" => []}},
                             reserved: [{"resource" => "pods", "name" => "x", "uid" => "uid-x"}])
    bound = pod(node: "n1", claims: [{"name" => "s", "resourceClaimName" => "shared"}])
    operations = controller.plan(bound, claims: [shared], templates: []).operations

    assert_equal [:status_update], operations.map(&:action)
    assert_equal [{"resource" => "pods", "name" => "x", "uid" => "uid-x"}, {"resource" => "pods", "name" => "p1", "uid" => "uid-p1"}],
                 operations.first.patch["reservedFor"]
    # Already reserved, or not allocated: nothing.
    reserved = claim("shared", allocation: {"devices" => {"results" => []}},
                               reserved: [{"resource" => "pods", "name" => "p1", "uid" => "uid-p1"}])

    assert_empty controller.plan(bound, claims: [reserved], templates: []).operations
    assert_empty controller.plan(bound, claims: [claim("shared")], templates: []).operations
  end

  def test_deleted_pods_and_pods_without_claims_are_left_alone
    deleting = pod
    deleting["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"

    assert_empty controller.plan(deleting, claims: [], templates: [template]).operations
    assert_empty controller.plan(pod(claims: []), claims: [], templates: []).operations
  end

  def test_a_template_event_plans_the_pods_that_use_it
    adapter = Adapter.new([pod("p1"), pod("p2", claims: [{"name" => "x", "resourceClaimTemplateName" => "other"}]), template])
    operations = controller.plan(template, store: adapter).operations

    assert_equal %i[create status_update], operations.map(&:action)
    assert_equal "p1", operations.first.object.dig("metadata", "ownerReferences", 0, "name")
  end

  def test_a_pod_sharing_a_claims_name_still_gets_its_claims
    same_name = claim("p1")
    adapter = Adapter.new([pod("p1"), same_name, template])
    operations = controller.plan(same_name, store: adapter).operations

    assert_includes operations.map(&:action), :create
  end

  def test_watches_route_pods_and_templates_to_themselves
    specs = Controller::AdvancedMiscControllerFactory.watch_specs("resourceclaim-controller")

    assert_equal({"ResourceClaim" => :fan_out, "Pod" => :self, "ResourceClaimTemplate" => :self},
                 specs.to_h { |spec| [spec.resource.kind, spec.route] })
  end

  # enqueuePod: a Pod event also queues the claims it names, so a Pod that
  # completed (or is gone) releases its reservation.
  def test_pod_events_queue_the_claims_the_pod_names
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "p1"},
           "spec" => {"resourceClaims" => [{"name" => "a", "resourceClaimName" => "shared"}, {"name" => "b", "resourceClaimTemplateName" => "t"}]},
           "status" => {"phase" => "Succeeded", "resourceClaimStatuses" => [{"name" => "b", "resourceClaimName" => "p-b-xyz"}],
                        "extendedResourceClaimStatus" => {"resourceClaimName" => "p-extended-resources-q"}}}
    spec = Controller::AdvancedMiscControllerFactory.watch_specs("resourceclaim-controller").find { |s| s.resource.kind == "Pod" }

    assert_equal %w[ns/p ns/p-extended-resources-q ns/shared ns/p-b-xyz], spec.queue_key.call(pod)

    claim = {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
             "metadata" => {"name" => "shared", "namespace" => "ns", "uid" => "c1", "finalizers" => ["resource.kubernetes.io/delete-protection"]},
             "spec" => {}, "status" => {"allocation" => {"devices" => {"results" => []}},
                                        "reservedFor" => [{"resource" => "pods", "name" => "p", "uid" => "p1"}]}}
    operations = controller.plan(claim, store: Adapter.new([pod, claim])).operations
    status = operations.find { |operation| operation.action == :status_update }

    assert_equal({"reservedFor" => []}, status.patch, "a done Pod's reservation is dropped and the claim deallocated")
    assert(operations.any? { |operation| operation.action == :update && operation.object.dig("metadata", "finalizers") == [] })
  end
end
