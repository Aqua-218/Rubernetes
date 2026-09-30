# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"

# OpenAPI `required` on a list or map field is met by Go's zero value: a
# client that marshals an empty slice sends null (nothing over protobuf) and
# kube-apiserver accepts it; only kind-specific validation demands entries.
# The conformance CSINode spec creates `spec: {drivers: null}`.
class SchemaRequiredGoZeroValueTest < Minitest::Test
  def errors_for(schema, object)
    Rubernetes::Generated.definition_for(schema).validator.errors(object, operation: :create).map(&:to_s)
  end

  def test_a_null_or_absent_required_list_is_the_zero_value
    [{"drivers" => nil}, {}, {"drivers" => []}].each do |spec|
      object = {"apiVersion" => "storage.k8s.io/v1", "kind" => "CSINode", "metadata" => {"name" => "n1"}, "spec" => spec}
      errors = errors_for("io.k8s.api.storage.v1.CSINode", object)

      assert_empty errors.grep(/drivers/), "spec=#{spec.inspect}: #{errors.inspect}"
    end
  end

  def test_a_required_scalar_and_a_required_object_are_still_required
    object = {"apiVersion" => "storage.k8s.io/v1", "kind" => "CSINode", "metadata" => {"name" => "n1"},
              "spec" => {"drivers" => [{"nodeID" => "x"}]}}
    errors = errors_for("io.k8s.api.storage.v1.CSINode", object)

    assert(errors.any? { |message| message.include?("name") && message.include?("required") }, errors.inspect)
  end

  def test_pod_containers_stay_required_through_the_kind_rules
    object = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "d"}, "spec" => {}}
    causes = Rubernetes::API::ObjectValidation.validate("Pod", object)

    assert(causes.any? { |cause| cause.field.to_s.include?("containers") && cause.reason.to_s =~ /Required/i }, causes.map(&:to_h).inspect)
  end
end
