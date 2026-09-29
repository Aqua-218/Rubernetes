# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# apimachineryvalidation.ValidateImmutableField, applied per kind where
# upstream applies it.  None of these were enforced, so a StorageClass's
# provisioner, parameters, reclaimPolicy or volumeBindingMode could be
# rewritten in place -- upstream refuses every one of them
# (pkg/apis/storage/validation/validation.go:65-71).
class ImmutableFieldUpdatesTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def storage_class(extra = {})
    {"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass",
     "metadata" => {"name" => "gold"},
     "provisioner" => "example.com/csi",
     "reclaimPolicy" => "Delete",
     "volumeBindingMode" => "Immediate",
     "parameters" => {"type" => "ssd"}}.merge(extra)
  end

  def errors(new_object, old_object, kind: "StorageClass", operation: :update)
    Validator.send(:immutable_field_errors, new_object, old_object, kind, operation)
  end

  def test_an_unchanged_storage_class_is_accepted
    assert_empty errors(storage_class, storage_class)
  end

  def test_the_provisioner_is_immutable
    refute_empty errors(storage_class("provisioner" => "other.com/csi"), storage_class)
  end

  def test_the_parameters_are_immutable
    refute_empty errors(storage_class("parameters" => {"type" => "hdd"}), storage_class)
  end

  def test_the_reclaim_policy_is_immutable
    refute_empty errors(storage_class("reclaimPolicy" => "Retain"), storage_class)
  end

  def test_the_volume_binding_mode_is_immutable
    refute_empty errors(storage_class("volumeBindingMode" => "WaitForFirstConsumer"), storage_class)
  end

  def test_mutable_fields_are_left_alone
    assert_empty errors(storage_class("allowVolumeExpansion" => true), storage_class)
  end

  def test_a_create_is_never_restricted
    assert_empty errors(storage_class("provisioner" => "other"), storage_class, operation: :create)
  end

  def test_kinds_without_immutable_fields_are_unaffected
    assert_empty errors({"spec" => {"a" => 1}}, {"spec" => {"a" => 2}}, kind: "ConfigMap")
  end
end
