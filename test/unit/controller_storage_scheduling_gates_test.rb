# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/security_admission_fake_context"
require "rubernetes/controller"
require "rubernetes/bootstrap/security_assembly"
require "rubernetes/node/dra_manager"
require "rubernetes/security/admission/plugins/core"

class ControllerStorageSchedulingGatesTest < Minitest::Test
  Controller = Rubernetes::Controller
  Admission = Rubernetes::Security::Admission
  GATES = {"WorkloadWithJob" => true, "GenericWorkload" => true}.freeze
  NOW = Time.utc(2026, 1, 1)

  def test_job_creates_workload_and_pod_group_before_creating_grouped_pods
    job = job_object
    controller = Controller::JobController.new
    store = Controller::StoreAdapter.new(Rubernetes::Storage::MemoryStore.new)
    ordinary = controller.plan(job, store: store)

    assert_equal(%w[Pod Pod], ordinary.creates.map { |operation| operation.resource.kind })
    assert_nil ordinary.creates.first.object.dig("spec", "schedulingGroup")

    workload = controller.plan(job, store: store, feature_gates: GATES).creates.fetch(0).object

    assert_equal "Workload", workload["kind"]
    assert_equal "gang-7dccc85c97", workload.dig("metadata", "name")
    assert_equal "job-uid", workload.dig("metadata", "ownerReferences", 0, "uid")
    save(store, workload, "workload-uid")

    group = controller.plan(job, store: store, feature_gates: GATES).creates.fetch(0).object

    assert_equal "PodGroup", group["kind"]
    assert_equal 2, group.dig("spec", "schedulingPolicy", "gang", "minCount")
    assert_equal workload.dig("metadata", "name"), group.dig("spec", "podGroupTemplateRef", "workload", "workloadName")
    assert_equal(%w[workload-uid job-uid], group.dig("metadata", "ownerReferences").map { |reference| reference["uid"] })
    save(store, group, "group-uid")

    scheduled = controller.plan(job, store: store, feature_gates: GATES)

    assert_equal(%w[Pod Pod], scheduled.creates.map { |operation| operation.resource.kind })
    scheduled.creates.each do |operation|
      pod = operation.object

      assert_equal group.dig("metadata", "name"), pod.dig("spec", "schedulingGroup", "podGroupName")
      assert_equal(%w[group-uid job-uid], pod.dig("metadata", "ownerReferences").map { |reference| reference["uid"] })
    end
  end

  def test_existing_job_without_scheduling_objects_does_not_start_using_gang_scheduling
    job = job_object.merge("status" => {"startTime" => NOW.iso8601})
    result = Controller::JobController.new.plan(job, pods: [], feature_gates: GATES)

    assert_equal(%w[Pod Pod], result.creates.map { |operation| operation.resource.kind })
    assert_nil result.creates.first.object.dig("spec", "schedulingGroup")
  end

  def test_job_admission_only_blocks_parallelism_change_when_a_gang_group_matches
    job = job_object
    candidate = Controller::Support.deep_copy(job)
    candidate["spec"]["parallelism"] = 3
    context = SecurityAdmissionFakeContext.new
    plugin = Admission::Registry.factories.fetch("JobValidation").call(context, {})
    group = {"metadata" => {"name" => "group", "ownerReferences" => [{"controller" => true, "uid" => "job-uid"}]},
             "spec" => {"schedulingPolicy" => {"gang" => {"minCount" => 2}}}}
    context.put("podgroups", "default", "group", group, group: "scheduling.k8s.io")
    args = {operation: "UPDATE", user: Rubernetes::Security::UserInfo.new(name: "tester"), group: "batch", version: "v1",
            resource: "jobs", kind: "Job", name: "gang",
            namespace: "default", object: candidate, old_object: job}
    attributes = Admission::Attributes.new(**args)

    assert_nil plugin.validate(attributes)
    context.feature_gates.merge!(GATES)
    rejected = assert_raises(Admission::Rejected) { plugin.validate(attributes) }

    assert_includes rejected.message, 'gang-scheduled PodGroup "group"'
    assert_nil plugin.validate(Admission::Attributes.new(**args, subresource: "status"))
  end

  def test_incomplete_pool_retries_and_expiration_uses_uid_preconditions
    controller = Controller::ResourcePoolStatusRequestController.new
    request = {"apiVersion" => "resource.k8s.io/v1alpha3", "kind" => "ResourcePoolStatusRequest",
               "metadata" => {"name" => "request", "uid" => "request-uid", "creationTimestamp" => NOW.iso8601},
               "spec" => {"driver" => "driver.example"}}
    slice = {"spec" => {"driver" => "driver.example", "pool" => {"name" => "pool", "generation" => 1, "resourceSliceCount" => 2}}}
    options = {resource_slices: [slice], resource_claims: []}

    assert_raises(Controller::StoreError) { controller.plan(request, **options, now: NOW, reconcile_attempt: 0) }
    dropped = controller.plan(request, **options, now: NOW, reconcile_attempt: 5)

    assert_empty dropped.operations
    assert_operator dropped.requeue_after, :>, 86_400
    expired = controller.plan(request, **options, now: NOW + dropped.requeue_after, reconcile_attempt: 0)

    assert_equal :delete, expired.operations.first.action
    assert_equal "request-uid", expired.operations.first.patch.dig("preconditions", "uid")
  end

  def test_bootstrap_permissions_follow_feature_gates
    role_name = "system:controller:resourcepoolstatusrequest-controller"
    disabled = Rubernetes::Bootstrap::SecurityAssembly.bootstrap_documents
    enabled = Rubernetes::Bootstrap::SecurityAssembly.bootstrap_documents(feature_gates: GATES.merge("DRAResourcePoolStatus" => true))

    refute_includes disabled.fetch("clusterroles").map { |role| role.dig("metadata", "name") }, role_name
    assert_includes enabled.fetch("clusterroles").map { |role| role.dig("metadata", "name") }, role_name
    assert_includes enabled.fetch("clusterrolebindings").map { |binding| binding.dig("roleRef", "name") }, role_name
    job_role = enabled.fetch("clusterroles").find { |role| role.dig("metadata", "name") == "system:controller:job-controller" }

    assert_includes job_role.fetch("rules").map { |rule| rule["resources"] }, %w[podgroups workloads]
  end

  def test_pod_group_generated_claim_is_shared_and_released_when_group_disappears
    controller = Controller::ResourceClaimController.new(random: Random.new(2))
    store = Controller::StoreAdapter.new(Rubernetes::Storage::MemoryStore.new)
    group = {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup",
             "metadata" => {"namespace" => "default", "name" => "gang", "uid" => "group-uid"},
             "spec" => {"resourceClaims" => [{"name" => "device", "resourceClaimTemplateName" => "accelerator"}]}}
    template = {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaimTemplate",
                "metadata" => {"namespace" => "default", "name" => "accelerator"},
                "spec" => {"metadata" => {"labels" => {"example.org/from-template" => "true"}}, "spec" => {}}}
    save(store, template, "template-uid")
    gates = {"DRAWorkloadResourceClaims" => true}

    assert_empty controller.plan(group, store: store).operations
    plan = controller.plan(group, store: store, feature_gates: gates, root_ca: nil, type_checker: Object.new)
    claim = Controller::Support.deep_copy(plan.creates.first.object)
    pod_group_status = plan.operations.find { |operation| operation.action == :status_update }

    assert_equal "PodGroup", claim.dig("metadata", "ownerReferences", 0, "kind")
    assert_equal "group-uid", claim.dig("metadata", "ownerReferences", 0, "uid")
    assert_equal "true", claim.dig("metadata", "labels", "example.org/from-template")
    assert_equal claim.dig("metadata", "name"), pod_group_status.patch.dig("resourceClaimStatuses", 0, "resourceClaimName")

    group["status"] = pod_group_status.patch
    save(store, group, "group-uid")
    claim["status"] = {"allocation" => {"devices" => {"results" => []}}}
    claim["metadata"]["finalizers"] = [Controller::AdvancedMiscSupport::RESOURCE_CLAIM_FINALIZER]
    save(store, claim, "claim-uid")
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"namespace" => "default", "name" => "member", "uid" => "pod-uid"},
           "spec" => {"nodeName" => "node", "schedulingGroup" => {"podGroupName" => "gang"},
                      "resourceClaims" => group.dig("spec", "resourceClaims")}}
    member = controller.plan(pod, store: store, feature_gates: gates)

    assert_empty member.creates
    assert_equal pod_group_status.patch, member.operations.find { |operation| operation.resource.kind == "Pod" }.patch
    reservation = member.operations.find { |operation| operation.resource.kind == "ResourceClaim" }.patch

    assert_equal [{"apiGroup" => "scheduling.k8s.io", "resource" => "podgroups", "name" => "gang", "uid" => "group-uid"}], reservation["reservedFor"]
    claim["status"] = reservation
    claim["metadata"]["uid"] = "claim-uid"

    assert_empty controller.plan(claim, store: store, feature_gates: gates).operations
    cleanup = controller.plan(claim, store: store, feature_gates: gates, pod_groups: [])

    assert_equal %i[status_update update], cleanup.operations.map(&:action)
    assert_empty cleanup.operations.first.patch["reservedFor"]
    assert_nil cleanup.operations.first.patch["allocation"]
  end

  def test_kubelet_accepts_only_the_pods_own_group_when_the_gate_is_enabled
    claim = {"metadata" => {"name" => "claim", "namespace" => "default", "uid" => "claim-uid", "ownerReferences" => [
      {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup", "name" => "group", "uid" => "group-uid", "controller" => true}
    ]}, "status" => {"reservedFor" => [{"apiGroup" => "scheduling.k8s.io", "resource" => "podgroups", "name" => "group", "uid" => "group-uid"}],
                     "allocation" => {"devices" => {"results" => []}}}}
    client = Object.new
    client.define_singleton_method(:get) { |*_args, **_options| claim }
    pod = {"metadata" => {"name" => "member", "namespace" => "default", "uid" => "pod-uid"},
           "spec" => {"schedulingGroup" => {"podGroupName" => "group"}, "resourceClaims" => [{"name" => "device", "resourceClaimTemplateName" => "t"}]},
           "status" => {"resourceClaimStatuses" => [{"name" => "device", "resourceClaimName" => "claim"}]}}
    manager = Rubernetes::Node::DRAManager
    Dir.mktmpdir do |directory|
      disabled = manager.new(client: client, node_name: "node", state_directory: directory)

      assert_raises(manager::Error) { disabled.prepare_resources(pod) }
      enabled = manager.new(client: client, node_name: "node", state_directory: directory, workload_claims: true)

      assert enabled.prepare_resources(pod)
      pod["spec"]["schedulingGroup"]["podGroupName"] = "other"

      assert_raises(manager::Error) { enabled.prepare_resources(pod) }
    end
  end

  private

  def job_object
    {"kind" => "Job", "apiVersion" => "batch/v1", "metadata" => {"name" => "gang", "namespace" => "default", "uid" => "job-uid"},
     "spec" => {"completionMode" => "Indexed", "completions" => 2, "parallelism" => 2,
                "template" => {"spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "job", "image" => "test"}]}}}}
  end

  def save(store, object, uid)
    saved = Controller::Support.deep_copy(object)
    saved["metadata"]["uid"] = uid
    store.create(saved)
  end
end
