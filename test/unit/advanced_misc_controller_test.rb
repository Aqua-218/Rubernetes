# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller/advanced_misc"

class AdvancedMiscControllerTest < Minitest::Test
  Controller = Rubernetes::Controller

  def test_resource_claim_releases_only_owned_allocation_and_preserves_unknown_consumers
    claim = object("ResourceClaim", "claim", uid: "claim-1", api_version: "resource.k8s.io/v1")
    claim["metadata"]["finalizers"] = ["other.finalizer", Controller::AdvancedMiscSupport::RESOURCE_CLAIM_FINALIZER]
    claim["spec"] = {"devices" => {"requests" => [{"name" => "gpu"}]}}
    claim["status"] = {
      "reservedFor" => [{"apiGroup" => "", "resource" => "pods", "name" => "gone", "uid" => "pod-1"}],
      "allocation" => {"devices" => {"results" => [{"driver" => "gpu.example.io", "pool" => "default"}]}}
    }
    original = Controller::Support.deep_copy(claim)

    result = Controller::ResourceClaimController.new(name: "resourceclaim-controller").plan(claim, pods: [])
    assert_equal [:status_update, :update], result.operations.map(&:action)
    assert_empty result.operations.first.patch.fetch("reservedFor")
    assert_nil result.operations.first.patch["allocation"]
    assert_equal ["other.finalizer"], result.operations.last.object.dig("metadata", "finalizers")
    assert_equal [], result.operations.last.object.dig("status", "reservedFor").select { |entry| entry["resource"] == "pods" }
    assert_equal original, claim

    unknown = Controller::Support.deep_copy(claim)
    unknown["status"]["reservedFor"] << {"apiGroup" => "example.io", "resource" => "widgets", "name" => "consumer", "uid" => "w-1"}
    unknown_result = Controller::ResourceClaimController.new(name: "resourceclaim-controller").plan(unknown, pods: [])
    assert_equal ["example.io"], unknown_result.operations.first.patch.fetch("reservedFor").map { |entry| entry.fetch("apiGroup") }

    converged = Controller::Support.deep_copy(claim)
    converged["status"] = result.operations.first.patch
    converged["metadata"] = result.operations.last.object.fetch("metadata")
    assert_empty Controller::ResourceClaimController.new(name: "resourceclaim-controller").plan(converged, pods: []).operations
  end

  def test_resource_pool_status_request_aggregates_latest_generation_and_retries_incomplete_pool
    request = object("ResourcePoolStatusRequest", "request", uid: "request-1",
                     api_version: "resource.k8s.io/v1alpha3")
    request["spec"] = {"driver" => "example.io", "limit" => 10}
    slice_old = resource_slice("old", generation: 1, expected: 1, devices: ["old"])
    slice_one = resource_slice("one", generation: 2, expected: 2, devices: ["gpu-a"])
    slice_two = resource_slice("two", generation: 2, expected: 2, devices: ["gpu-b"], node: "node-b")
    claim = object("ResourceClaim", "allocated", uid: "claim-1", api_version: "resource.k8s.io/v1")
    claim["status"] = {"allocation" => {"devices" => {"results" => [{"driver" => "example.io", "pool" => "default"}]}}}

    result = Controller::ResourcePoolStatusRequestController.new(name: "resourcepoolstatusrequest-controller").plan(
      request, resource_slices: [slice_old, slice_one, slice_two], resource_claims: [claim], now: Time.utc(2026, 1, 1)
    )
    pool = result.status.fetch("pools").fetch(0)
    assert_equal 2, pool.fetch("totalDevices")
    assert_equal 1, pool.fetch("allocatedDevices")
    assert_equal 1, pool.fetch("availableDevices")
    assert_equal 2, pool.fetch("resourceSliceCount")
    assert_nil pool["nodeName"]
    assert_equal :status_update, result.operations.fetch(0).action

    complete_request = Controller::Support.deep_copy(request)
    complete_request["status"] = result.status
    assert_empty Controller::ResourcePoolStatusRequestController.new(name: "resourcepoolstatusrequest-controller").plan(
      complete_request, resource_slices: [slice_one], resource_claims: [claim], now: Time.utc(2026, 1, 1)
    ).operations

    incomplete = Controller::ResourcePoolStatusRequestController.new(name: "resourcepoolstatusrequest-controller").plan(
      request, resource_slices: [slice_one], resource_claims: [], now: Time.utc(2026, 1, 1)
    )
    assert_empty incomplete.operations
    assert incomplete.events.first.fetch("retryable")
    assert_match(/incomplete/, incomplete.status.fetch("pools").fetch(0).fetch("validationError"))
  end

  def test_legacy_token_cleaner_marks_then_deletes_only_verified_unused_token
    now = Time.utc(2026, 2, 1, 12)
    secret = object("Secret", "builder-token", uid: "secret-1", api_version: "v1")
    secret["type"] = Controller::AdvancedMiscSupport::SERVICE_ACCOUNT_TOKEN_TYPE
    secret["metadata"]["creationTimestamp"] = "2025-12-01T00:00:00Z"
    secret["metadata"]["annotations"] = {
      "kubernetes.io/service-account.name" => "builder",
      "kubernetes.io/service-account.uid" => "sa-1"
    }
    service_account = object("ServiceAccount", "builder", uid: "sa-1")
    service_account["secrets"] = [{"name" => "builder-token"}]
    options = {service_accounts: [service_account], pods: [],
               tracking_config_map: {"data" => {"since" => "2025-01-01"}}, now: now,
               cleanup_period: 30 * 24 * 60 * 60}

    controller = Controller::LegacyServiceAccountTokenCleanerController.new(name: "legacy-serviceaccount-token-cleaner-controller")
    first = controller.plan(secret, **options)
    assert_equal [:update], first.operations.map(&:action)
    assert_equal "2026-02-01", first.operations.first.object.dig("metadata", "labels", Controller::AdvancedMiscSupport::INVALID_SINCE_LABEL)
    assert_equal "kubernetes.io/service-account-token", secret.fetch("type")

    marked = first.operations.first.object
    second = controller.plan(marked, **options.merge(now: Time.utc(2026, 3, 4)))
    assert_equal [:delete], second.operations.map(&:action)

    mounted = Controller::Support.deep_copy(secret)
    mounted["metadata"]["labels"] = {Controller::AdvancedMiscSupport::INVALID_SINCE_LABEL => "2025-01-01"}
    mounted_pod = object("Pod", "consumer", uid: "pod-1")
    mounted_pod["spec"] = {"volumes" => [{"name" => "token", "secret" => {"secretName" => "builder-token"}}]}
    assert_empty controller.plan(mounted, **options.merge(pods: [mounted_pod])).operations

    mismatched = Controller::Support.deep_copy(marked)
    mismatched["metadata"]["annotations"]["kubernetes.io/service-account.uid"] = "different"
    assert_empty controller.plan(mismatched, **options).operations
  end

  def test_validating_admission_policy_status_updates_type_check_only_and_converges
    policy = object("ValidatingAdmissionPolicy", "policy", uid: "policy-1",
                    api_version: "admissionregistration.k8s.io/v1", namespace: nil)
    policy["metadata"]["generation"] = 3
    policy["spec"] = {"validations" => [{"expression" => "object.spec.replicas > 0"}]}
    binding = object("ValidatingAdmissionPolicyBinding", "binding", uid: "binding-1",
                     api_version: "admissionregistration.k8s.io/v1", namespace: nil)
    original_spec = Controller::Support.deep_copy(policy.fetch("spec"))
    checker = ->(_policy) { [{"fieldRef" => "spec.validations[0].expression", "warning" => "unknown field"}] }

    result = Controller::ValidatingAdmissionPolicyStatusController.new(name: "validatingadmissionpolicy-status-controller").plan(
      policy, bindings: [binding], type_checker: checker, now: Time.utc(2026, 1, 1)
    )
    assert_equal :status_update, result.operations.fetch(0).action
    assert_equal 3, result.status.fetch("observedGeneration")
    assert_equal "unknown field", result.status.dig("typeChecking", "expressionWarnings", 0, "warning")
    assert_equal original_spec, policy.fetch("spec")
    assert_equal "ValidatingAdmissionPolicyBinding", binding.fetch("kind")

    updated = Controller::Support.deep_copy(policy)
    updated["status"] = result.status
    assert_empty Controller::ValidatingAdmissionPolicyStatusController.new(name: "validatingadmissionpolicy-status-controller").plan(
      updated, type_checker: checker, now: Time.utc(2026, 1, 1)
    ).operations
  end

  def test_service_cidr_adds_own_finalizer_and_blocks_or_then_unblocks_deletion
    cidr = object("ServiceCIDR", "services", uid: "cidr-1", api_version: "networking.k8s.io/v1", namespace: nil)
    cidr["spec"] = {"cidrs" => ["10.96.0.0/16"]}
    controller = Controller::ServiceCIDRController.new(name: "service-cidr-controller")
    first = controller.plan(cidr, now: Time.utc(2026, 1, 1))
    assert_equal [:update, :status_update], first.operations.map(&:action)
    assert_includes first.operations.first.object.dig("metadata", "finalizers"), Controller::AdvancedMiscSupport::SERVICE_CIDR_FINALIZER
    assert_equal "True", first.status.dig("conditions", 0, "status")

    converged = Controller::Support.deep_copy(cidr)
    converged["metadata"] = first.operations.first.object.fetch("metadata")
    converged["status"] = first.status
    assert_empty controller.plan(converged, now: Time.utc(2026, 1, 1)).operations

    deleting = Controller::Support.deep_copy(converged)
    deleting["metadata"]["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    ip = object("IPAddress", "10.96.0.4", uid: "ip-1", api_version: "networking.k8s.io/v1", namespace: nil)
    blocked = controller.plan(deleting, service_cidrs: [deleting], ip_addresses: [ip], now: Time.utc(2026, 1, 1, 0, 1))
    assert_equal [:status_update], blocked.operations.map(&:action)
    assert_equal "False", blocked.status.dig("conditions", 0, "status")

    unblocked = controller.plan(deleting, service_cidrs: [deleting], ip_addresses: [], now: Time.utc(2026, 1, 1, 0, 20))
    assert_equal [:update], unblocked.operations.map(&:action)
    assert_equal [], unblocked.operations.first.object.dig("metadata", "finalizers")
  end

  def test_storage_version_migrator_fences_resources_and_handles_conflict_retry_and_terminal_states
    migration = object("StorageVersionMigration", "migrate", uid: "migration-1",
                       api_version: "storagemigration.k8s.io/v1beta1", namespace: nil)
    migration["spec"] = {"resource" => {"group" => "apps", "resource" => "deployments"}}
    migration["status"] = {"resourceVersion" => "10"}
    deployment = object("Deployment", "web", uid: "deployment-1", api_version: "apps/v1")
    deployment["metadata"]["resourceVersion"] = "9"
    newer = object("Deployment", "newer", uid: "deployment-2", api_version: "apps/v1")
    newer["metadata"]["resourceVersion"] = "11"

    controller = Controller::StorageVersionMigratorController.new(name: "storage-version-migrator-controller")
    result = controller.plan(migration, resources: [deployment, newer], now: Time.utc(2026, 1, 1))
    assert_equal [:patch, :status_update], result.operations.map(&:action)
    patch = result.operations.first
    assert_equal "apps/v1", patch.patch.fetch("apiVersion")
    assert_equal "deployment-1", patch.patch.dig("metadata", "uid")
    assert_equal "9", patch.patch.dig("metadata", "resourceVersion")

    conflict = controller.plan(migration, resources: [deployment], patch_results: {"web" => :conflict}, now: Time.utc(2026, 1, 1))
    assert_equal [:status_update], conflict.operations.map(&:action)
    retry_result = controller.plan(migration, resources: [deployment], patch_results: {"web" => :retry}, now: Time.utc(2026, 1, 1))
    assert_empty retry_result.operations
    assert retry_result.events.first.fetch("retryable")

    terminal = Controller::Support.deep_copy(migration)
    terminal["status"]["conditions"] = [{"type" => "MigrationSucceeded", "status" => "True"}]
    assert_empty controller.plan(terminal, resources: [deployment]).operations
  end

  def test_selinux_warning_aggregates_two_directional_events_without_mutating_pods
    first = object("Pod", "first", uid: "pod-1")
    second = object("Pod", "second", uid: "pod-2")
    first["spec"] = {"volumes" => [{"name" => "shared", "persistentVolumeClaim" => {"claimName" => "data"}}],
                    "securityContext" => {"seLinuxOptions" => {"user" => "system_u", "role" => "system_r", "type" => "container_t", "level" => "s0:c1"}}}
    second["spec"] = {"volumes" => [{"name" => "shared", "persistentVolumeClaim" => {"claimName" => "data"}}],
                     "securityContext" => {"seLinuxOptions" => {"user" => "system_u", "role" => "system_r", "type" => "container_t", "level" => "s0:c2"}}}
    original_first = Controller::Support.deep_copy(first)
    original_second = Controller::Support.deep_copy(second)
    controller = Controller::SELinuxWarningController.new(name: "selinux-warning-controller")

    result = controller.plan(first, pods: [first, second])
    assert_empty result.operations
    assert_equal ["SELinuxLabelConflict", "SELinuxLabelConflict"], result.events.map { |event| event.fetch("reason") }
    assert_equal original_first, first
    assert_equal original_second, second
    repeated = controller.plan(first, pods: [first, second])
    assert_equal result.events, repeated.events
  end

  def test_advanced_misc_factory_exposes_pinned_metadata_and_concrete_definitions
    factory = Controller::AdvancedMiscControllerFactory
    assert_equal 7, factory.names.length
    factory.definitions.each do |definition|
      assert definition.implementation
      assert definition.reconcile_block.respond_to?(:call)
      definition.validate!(corpus_entry: Controller::BuiltinControllerCorpus.fetch(definition.name))
    end
    assert_equal ["DynamicResourceAllocation"], factory.metadata("resourceclaim-controller").fetch(:feature_gates)
  end

  private

  def object(kind, name, uid:, api_version: "v1", namespace: "default")
    metadata = {"name" => name, "uid" => uid}
    metadata["namespace"] = namespace unless namespace.nil?
    {"apiVersion" => api_version, "kind" => kind, "metadata" => metadata}
  end

  def resource_slice(name, generation:, expected:, devices:, node: nil)
    slice = object("ResourceSlice", name, uid: "slice-#{name}", api_version: "resource.k8s.io/v1", namespace: nil)
    pool = {"name" => "default", "generation" => generation, "resourceSliceCount" => expected}
    slice["spec"] = {"driver" => "example.io", "pool" => pool,
                     "devices" => devices.map { |device| {"name" => device} }}
    slice["spec"]["nodeName"] = node if node
    slice
  end
end
