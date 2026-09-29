# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateFinalizerName (apimachinery objectmeta.go:111): every finalizer must
# be a qualified name.  Nothing checked it, so an object could be stored with a
# finalizer nothing can ever match -- and become undeletable.
class FinalizerNameValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def errors(finalizers)
    Validator.send(:finalizer_name_errors, {"finalizers" => finalizers})
  end

  def test_no_finalizers_is_fine
    assert_empty errors(nil)
    assert_empty errors([])
  end

  def test_qualified_names_are_accepted
    assert_empty errors(["kubernetes.io/pvc-protection", "example.com/cleanup", "simple"])
  end

  def test_an_empty_finalizer_is_rejected
    refute_empty errors([""])
  end

  def test_a_finalizer_with_spaces_is_rejected
    refute_empty errors(["not a name"])
  end

  def test_a_finalizer_with_two_slashes_is_rejected
    refute_empty errors(["a/b/c"])
  end

  def test_the_offending_index_is_reported
    issues = errors(["kubernetes.io/ok", "bad name"])

    assert_equal 1, issues.length
    assert_equal %w[metadata finalizers 1], issues.first.path
  end
end
