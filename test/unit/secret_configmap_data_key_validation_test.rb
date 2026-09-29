# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateSecret/ValidateConfigMap run IsConfigMapKey over every data key
# (pkg/apis/core/validation/validation.go -> apimachinery IsConfigMapKey): the
# key must match [-._a-zA-Z0-9]+, be at most 253 characters, and must not be
# "." or ".." or start with "..".  We accepted an empty key, so the conformance
# spec "[sig-node] Secrets should fail to create secret due to empty secret
# key" -- which requires the CREATE to fail -- passed the creation instead.
class SecretConfigMapDataKeyValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def secret(data)
    {"apiVersion" => "v1", "kind" => "Secret",
     "metadata" => {"name" => "s", "namespace" => "ns"}, "data" => data}
  end

  def config_map(data)
    {"apiVersion" => "v1", "kind" => "ConfigMap",
     "metadata" => {"name" => "c", "namespace" => "ns"}, "data" => data}
  end

  def key_errors(object)
    Validator.send(:data_key_errors, object, object.fetch("kind"))
  end

  def test_an_empty_secret_key_is_rejected
    refute_empty key_errors(secret("" => "dmFsdWU="))
  end

  def test_an_empty_config_map_key_is_rejected
    refute_empty key_errors(config_map("" => "v"))
  end

  def test_ordinary_keys_are_accepted
    assert_empty key_errors(secret("username" => "x", "app.properties" => "y",
                                   "KEY_NAME" => "z", "key-name" => "w"))
  end

  def test_dot_and_dotdot_are_rejected
    refute_empty key_errors(config_map("." => "v"))
    refute_empty key_errors(config_map(".." => "v"))
    refute_empty key_errors(config_map("..hidden" => "v"))
  end

  def test_a_leading_single_dot_is_allowed
    assert_empty key_errors(secret(".dockerconfigjson" => "v"))
  end

  def test_invalid_characters_are_rejected
    refute_empty key_errors(config_map("has space" => "v"))
    refute_empty key_errors(config_map("has/slash" => "v"))
  end

  def test_an_over_long_key_is_rejected
    refute_empty key_errors(config_map(("a" * 254) => "v"))
    assert_empty key_errors(config_map(("a" * 253) => "v"))
  end

  # MaxSecretSize (pkg/apis/core/types.go:6626): 1 MiB total.
  def test_a_secret_larger_than_one_mebibyte_is_rejected
    refute_empty key_errors(secret("blob" => "x" * (1024 * 1024 + 1)))
    assert_empty key_errors(secret("blob" => "x" * (1024 * 1024)))
  end

  def test_the_size_limit_counts_every_section
    big = "x" * (600 * 1024)
    object = {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "s"},
              "data" => {"a" => big}, "stringData" => {"b" => big}}

    refute_empty key_errors(object)
  end

  def test_string_data_and_binary_data_are_checked_too
    refute_empty key_errors({"apiVersion" => "v1", "kind" => "Secret",
                             "metadata" => {"name" => "s"}, "stringData" => {"" => "v"}})
    refute_empty key_errors({"apiVersion" => "v1", "kind" => "ConfigMap",
                             "metadata" => {"name" => "c"}, "binaryData" => {"" => "dg=="}})
  end
end
