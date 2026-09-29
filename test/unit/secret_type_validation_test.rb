# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateSecret (pkg/apis/core/validation/validation.go:7781-7811): each
# built-in Secret type requires its own keys.  Nothing checked them, so a
# kubernetes.io/tls Secret with no certificate was accepted and every consumer
# failed at use instead of at creation.
class SecretTypeValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def secret(type, data = {}, annotations: nil)
    metadata = {"name" => "s", "namespace" => "ns"}
    metadata["annotations"] = annotations if annotations
    {"apiVersion" => "v1", "kind" => "Secret", "metadata" => metadata,
     "type" => type, "data" => data}
  end

  def errors(object)
    Validator.send(:secret_type_errors, object)
  end

  def test_opaque_needs_nothing
    assert_empty errors(secret("Opaque"))
    assert_empty errors(secret(""))
  end

  def test_tls_needs_both_halves
    refute_empty errors(secret("kubernetes.io/tls"))
    refute_empty errors(secret("kubernetes.io/tls", {"tls.crt" => "x"}))
    assert_empty errors(secret("kubernetes.io/tls", {"tls.crt" => "x", "tls.key" => "y"}))
  end

  def test_basic_auth_needs_username_and_password
    refute_empty errors(secret("kubernetes.io/basic-auth", {"username" => "u"}))
    assert_empty errors(secret("kubernetes.io/basic-auth", {"username" => "u", "password" => "p"}))
  end

  def test_ssh_auth_needs_the_private_key
    refute_empty errors(secret("kubernetes.io/ssh-auth"))
    assert_empty errors(secret("kubernetes.io/ssh-auth", {"ssh-privatekey" => "k"}))
  end

  def test_docker_config_json_needs_its_key
    refute_empty errors(secret("kubernetes.io/dockerconfigjson"))
    assert_empty errors(secret("kubernetes.io/dockerconfigjson", {".dockerconfigjson" => "{}"}))
  end

  def test_string_data_satisfies_the_requirement
    object = secret("kubernetes.io/tls", {})
    object["stringData"] = {"tls.crt" => "x", "tls.key" => "y"}

    assert_empty errors(object)
  end

  def test_a_service_account_token_needs_its_annotation
    refute_empty errors(secret("kubernetes.io/service-account-token"))
    assert_empty errors(secret("kubernetes.io/service-account-token", {},
                               annotations: {"kubernetes.io/service-account.name" => "default"}))
  end

  def test_an_unknown_type_is_left_alone
    assert_empty errors(secret("example.com/custom"))
  end
end
