# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema/codec/kubernetes_protobuf"

# gogo generated a handful of Kubernetes messages from the Go field name
# rather than its JSON tag, so the proto field is capitalised while the wire
# JSON is not.  Matching on the proto spelling dropped those fields without a
# word: a ValidatingAdmissionPolicy sent as protobuf -- which is what
# client-go sends by default -- arrived with no expression at all, and a
# webhook configuration arrived with no webhooks.
class ProtobufCapitalisedFieldsTest < Minitest::Test
  def codec
    @codec ||= Rubernetes::Schema::Codec::KubernetesProtobuf.new
  end

  def roundtrip(object)
    codec.decode(codec.encode(object))
  end

  def test_validation_expression_survives_a_protobuf_roundtrip
    policy = {
      "apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "ValidatingAdmissionPolicy",
      "metadata" => {"name" => "policy"},
      "spec" => {"validations" => [{"expression" => "object.spec.replicas <= 100"}],
                 "variables" => [{"name" => "count", "expression" => "object.spec.replicas"}]}
    }
    spec = roundtrip(policy).fetch("spec")

    assert_equal "object.spec.replicas <= 100", spec.dig("validations", 0, "expression")
    assert_equal "count", spec.dig("variables", 0, "name")
    assert_equal "object.spec.replicas", spec.dig("variables", 0, "expression")
  end

  def test_webhook_configuration_keeps_its_webhooks
    configuration = {
      "apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "ValidatingWebhookConfiguration",
      "metadata" => {"name" => "config"},
      "webhooks" => [{"name" => "deny.example.com", "sideEffects" => "None",
                      "admissionReviewVersions" => ["v1"],
                      "clientConfig" => {"url" => "https://example.test/validate"}}]
    }
    webhooks = roundtrip(configuration).fetch("webhooks")

    assert_equal 1, webhooks.length
    assert_equal "deny.example.com", webhooks.fetch(0).fetch("name")
    assert_equal "https://example.test/validate", webhooks.dig(0, "clientConfig", "url")
  end

  # v1.DaemonEndpoint is the one field whose JSON name really is capitalised
  # (`json:"Port"`), so it must not be folded to lowercase with the rest.
  def test_the_kubelet_endpoint_port_keeps_its_capital
    node = {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "worker-0"},
            "status" => {"daemonEndpoints" => {"kubeletEndpoint" => {"Port" => 21_250}}}}

    endpoint = roundtrip(node).dig("status", "daemonEndpoints", "kubeletEndpoint")
    assert_equal({"Port" => 21_250}, endpoint)
  end
end
