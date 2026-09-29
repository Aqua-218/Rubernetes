# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/schema/codec/kubernetes_protobuf"

# authentication/authorization ExtraValue is `type ExtraValue []string` with
# the same shape as metav1.Verbs: the wire form is a message holding one
# repeated string field, while JSON is a plain array.  Encoding it as an
# ordinary message rejects the array outright --
# "expected an object for k8s.io.api.authentication.v1.ExtraValue, got Array"
# -- so a TokenReview or SubjectAccessReview whose user carries any `extra`
# value answered HTTP 500 to every protobuf client, which is every client-go
# client and therefore the whole e2e suite.
class ProtobufExtraValueTest < Minitest::Test
  Codec = Rubernetes::Schema::Codec::KubernetesProtobuf

  REVIEW = {
    "apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview",
    "spec" => {"token" => "abc"},
    "status" => {
      "authenticated" => true,
      "user" => {
        "username" => "system:serviceaccount:ns:default",
        "uid" => "uid-1",
        "groups" => %w[system:serviceaccounts system:authenticated],
        "extra" => {"authentication.kubernetes.io/pod-name" => %w[web-0],
                    "authentication.kubernetes.io/credential-id" => %w[JTI=abc]}
      }
    }
  }.freeze

  def codec = Codec.new

  def test_a_token_review_with_extra_values_encodes
    bytes = codec.encode(REVIEW)

    refute_empty(bytes)
  end

  def test_the_extra_values_survive_a_round_trip
    decoded = codec.decode(codec.encode(REVIEW))
    extra = decoded.dig("status", "user", "extra")

    assert_equal(%w[web-0], extra.fetch("authentication.kubernetes.io/pod-name"))
    assert_equal(%w[JTI=abc], extra.fetch("authentication.kubernetes.io/credential-id"))
  end

  def test_the_rest_of_the_review_survives_too
    decoded = codec.decode(codec.encode(REVIEW))

    assert_equal(true, decoded.dig("status", "authenticated"))
    assert_equal("system:serviceaccount:ns:default", decoded.dig("status", "user", "username"))
    assert_equal(%w[system:serviceaccounts system:authenticated], decoded.dig("status", "user", "groups"))
  end

  # A review with no extra values at all still works.
  def test_a_review_without_extra_values_round_trips
    review = JSON.parse(JSON.generate(REVIEW))
    review["status"]["user"].delete("extra")

    decoded = codec.decode(codec.encode(review))

    assert_equal("system:serviceaccount:ns:default", decoded.dig("status", "user", "username"))
  end

  # A SubjectAccessReview carries the same wrapper type in another group.
  def test_a_subject_access_review_with_extra_values_encodes
    review = {
      "apiVersion" => "authorization.k8s.io/v1", "kind" => "SubjectAccessReview",
      "spec" => {"user" => "alice", "extra" => {"scopes" => %w[openid]},
                 "resourceAttributes" => {"verb" => "get", "resource" => "pods"}}
    }

    decoded = codec.decode(codec.encode(review))

    assert_equal(%w[openid], decoded.dig("spec", "extra", "scopes"))
  end
end
