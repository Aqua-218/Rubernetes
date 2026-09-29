# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateOwnerReferences (apimachinery objectmeta.go:92-107): only one
# ownerReference may set controller:true.  Nothing checked it, so an object
# could carry two controllers and the garbage collector would follow whichever
# it happened to see first.
class OwnerReferenceValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def reference(name, controller:)
    {"apiVersion" => "apps/v1", "kind" => "ReplicaSet", "name" => name,
     "uid" => "uid-#{name}", "controller" => controller}
  end

  def errors(refs)
    Validator.send(:owner_reference_errors, {"ownerReferences" => refs})
  end

  def test_no_owner_references_is_fine
    assert_empty errors([])
  end

  def test_one_controller_is_fine
    assert_empty errors([reference("a", controller: true), reference("b", controller: false)])
  end

  def test_two_controllers_are_rejected
    issues = errors([reference("a", controller: true), reference("b", controller: true)])

    refute_empty issues
    assert_includes issues.first.message, "Only one reference can have Controller set to true"
    assert_includes issues.first.message, "ReplicaSet/a"
    assert_includes issues.first.message, "ReplicaSet/b"
  end

  def test_many_non_controllers_are_fine
    assert_empty errors(Array.new(5) { |i| reference("r#{i}", controller: false) })
  end
end
