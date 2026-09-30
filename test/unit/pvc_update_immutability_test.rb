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

  def test_a_create_is_never_restricted
    assert_empty errors(claim("storageClassName" => "other"), claim, operation: :create)
  end
end
