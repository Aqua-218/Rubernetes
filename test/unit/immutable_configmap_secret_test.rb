# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateSecretUpdate / ValidateConfigMapUpdate: once `immutable: true` is set
# neither the flag nor the data may change, and a Secret's type is immutable
# outright.  None of it was enforced -- and the whole point of the field is
# that the kubelet may cache the object without watching it.
class ImmutableConfigMapSecretTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def config_map(extra = {})
    {"apiVersion" => "v1", "kind" => "ConfigMap",
     "metadata" => {"name" => "c", "namespace" => "ns"},
     "data" => {"key" => "value"}}.merge(extra)
  end

  def secret(extra = {})
    {"apiVersion" => "v1", "kind" => "Secret",
     "metadata" => {"name" => "s", "namespace" => "ns"},
     "type" => "Opaque", "data" => {"key" => "dmFsdWU="}}.merge(extra)
  end

  def errors(new_object, old_object, kind, operation: :update)
    Validator.send(:immutable_data_errors, new_object, old_object, kind, operation)
  end

  def test_a_mutable_config_map_may_change
    assert_empty errors(config_map("data" => {"key" => "other"}), config_map, "ConfigMap")
  end

  def test_an_immutable_config_map_may_not_change_its_data
    old = config_map("immutable" => true)

    refute_empty errors(config_map("immutable" => true, "data" => {"key" => "other"}), old, "ConfigMap")
  end

  def test_an_immutable_config_map_may_not_become_mutable
    old = config_map("immutable" => true)

    refute_empty errors(config_map("immutable" => false), old, "ConfigMap")
    refute_empty errors(config_map, old, "ConfigMap")
  end

  def test_an_immutable_config_map_that_does_not_change_is_accepted
    old = config_map("immutable" => true)

    assert_empty errors(config_map("immutable" => true), old, "ConfigMap")
  end

  def test_binary_data_is_covered_too
    old = config_map("immutable" => true, "binaryData" => {"b" => "AA=="})

    refute_empty errors(config_map("immutable" => true, "binaryData" => {"b" => "AQ=="}), old, "ConfigMap")
  end

  def test_a_secret_type_is_immutable
    refute_empty errors(secret("type" => "kubernetes.io/tls"), secret, "Secret")
  end

  def test_an_immutable_secret_may_not_change_its_data
    old = secret("immutable" => true)

    refute_empty errors(secret("immutable" => true, "data" => {"key" => "b3RoZXI="}), old, "Secret")
  end

  def test_a_create_is_never_restricted
    assert_empty errors(config_map("data" => {"key" => "x"}), config_map("immutable" => true),
                        "ConfigMap", operation: :create)
  end

  def test_other_kinds_are_unaffected
    assert_empty errors({"data" => {"a" => 1}}, {"data" => {"a" => 2}, "immutable" => true}, "Pod")
  end
end
