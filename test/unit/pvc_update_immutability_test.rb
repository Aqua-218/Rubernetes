# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidatePersistentVolumeClaimUpdate: "spec is immutable after creation except
# resources.requests and volumeAttributesClassName for bound claims".  Nothing
# enforced it, so a client could repoint a bound PVC at another StorageClass or
# another volume and the API accepted it.
class PVCUpdateImmutabilityTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def claim(spec_extra = {}, phase = "Bound")
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
     "metadata" => {"name" => "c", "namespace" => "ns"},
     "spec" => {"accessModes" => ["ReadWriteOnce"], "storageClassName" => "gold",
                "resources" => {"requests" => {"storage" => "1Gi"}}}.merge(spec_extra),
     "status" => {"phase" => phase}}
  end

  def errors(new_claim, old_claim, operation: :update)
    Validator.send(:pvc_update_errors, new_claim, old_claim, operation)
  end

  def test_an_unchanged_spec_is_accepted
    assert_empty errors(claim, claim)
  end

  def test_a_bound_claim_may_grow
    assert_empty errors(claim("resources" => {"requests" => {"storage" => "2Gi"}}), claim)
  end

  def test_a_bound_claim_may_change_its_volume_attributes_class
    assert_empty errors(claim("volumeAttributesClassName" => "fast"), claim)
  end

  def test_the_storage_class_may_not_change
    refute_empty errors(claim("storageClassName" => "silver"), claim)
  end

  def test_controller_can_assign_a_class_once_to_an_unclassified_claim
    pending = claim({}, "Pending")
    pending.fetch("spec").delete("storageClassName")
    updated = claim({"storageClassName" => "new-default"}, "Pending")

    assert_empty errors(updated, pending)
    assert_empty errors(claim({"storageClassName" => ""}, "Pending"), pending)
    refute_empty errors(updated, claim({"storageClassName" => ""}, "Pending"))
    updated.fetch("spec")["accessModes"] = ["ReadWriteMany"]

    refute_empty errors(updated, pending)
  end

  def test_preserves_legacy_storage_class_while_migrating_its_annotation
    key = "volume.beta.kubernetes.io/storage-class"
    legacy = claim
    legacy.fetch("spec").delete("storageClassName")
    legacy.fetch("metadata")["annotations"] = {key => "gold"}

    assert_empty errors(claim, legacy)
    assert_empty errors(claim.merge("metadata" => legacy.fetch("metadata")), legacy)
    refute_empty errors(claim("storageClassName" => "silver"), legacy)
    changed = claim
    changed.fetch("metadata")["annotations"] = {key => "silver"}

    refute_empty errors(changed, legacy)
    refute_empty errors(changed, claim)
  end

  def test_the_access_modes_may_not_change
    refute_empty errors(claim("accessModes" => ["ReadWriteMany"]), claim)
  end

  # ValidatePersistentVolumeClaimUpdate: "PVController needs to update PVC.Spec
  # w/ VolumeName" -- binding sets volumeName once on an unbound claim.  An
  # externally provisioned (local-path) claim stayed Pending forever without it.
  def test_binding_may_set_the_volume_name_of_an_unbound_claim_once
    assert_empty errors(claim({"volumeName" => "pvc-123"}, "Pending"), claim({}, "Pending"))
    refute_empty errors(claim({"volumeName" => "pv-2"}, "Pending"), claim({"volumeName" => "pv-1"}, "Pending"))
    refute_empty errors(claim({"volumeName" => "pvc-123", "storageClassName" => "other"}, "Pending"), claim({}, "Pending"))
  end

  def test_the_volume_name_may_not_change
    refute_empty errors(claim("volumeName" => "pv-2"), claim("volumeName" => "pv-1"))
  end

  def test_an_unbound_claim_may_not_resize_through_this_rule
    unbound = claim({}, "Pending")

    refute_empty errors(claim({"resources" => {"requests" => {"storage" => "2Gi"}}}, "Pending"), unbound)
  end

  def test_failed_expansion_can_be_retried_only_above_the_actual_capacity
    old = claim("resources" => {"requests" => {"storage" => "8Gi"}})
    old.fetch("status")["capacity"] = {"storage" => "4Gi"}

    refute_empty errors(claim("resources" => {"requests" => {"storage" => "4096Mi"}}), old)
    assert_equal [%w[spec resources requests storage]], errors(claim, old).map(&:path)
    assert_empty errors(claim("resources" => {"requests" => {"storage" => "6Gi"}}), old)
  end

  def test_empty_selector_retains_its_presence
    assert_equal [%w[spec]], errors(claim("selector" => {}), claim).map(&:path)
    assert_empty errors(claim("selector" => {"matchLabels" => {}}), claim("selector" => {}))
  end

  def test_pending_immutable_quantities_accept_equivalent_spelling_without_changing_input
    pending = claim({}, "Pending")
    same = claim({"resources" => {"requests" => {"storage" => "1024Mi"}}}, "Pending")

    assert_empty errors(same, pending)
    assert_equal "1024Mi", same.dig("spec", "resources", "requests", "storage")
    assert_equal "1Gi", pending.dig("spec", "resources", "requests", "storage")
  end

  def test_attributes_class_cannot_be_removed_after_successful_application
    previous = claim("volumeAttributesClassName" => "fast")

    assert_empty errors(claim, previous)
    previous.fetch("status")["currentVolumeAttributesClassName"] = "fast"

    assert_equal [%w[spec volumeAttributesClassName]], errors(claim, previous).map(&:path)
    empty = errors(claim("volumeAttributesClassName" => ""), previous)

    assert_match(/to empty string/, empty.fetch(0).message)
    assert_empty errors(claim("volumeAttributesClassName" => "faster"), previous)
  end

  def test_volume_mode_change_reports_the_immutable_field
    assert_equal [%w[spec], %w[volumeMode]], errors(claim("volumeMode" => "Block"), claim("volumeMode" => "Filesystem")).map(&:path)
  end

  def test_a_create_is_never_restricted
    assert_empty errors(claim("storageClassName" => "other"), claim, operation: :create)
  end
end
