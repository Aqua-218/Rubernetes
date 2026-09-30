# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateAnnotations (apimachinery objectmeta.go:44): every annotation key is
# a qualified name (case-insensitive) and one object's annotations may not
# exceed 256 kB in total.  Neither was checked, so an object could carry an
# unbounded annotation payload with keys nothing can address.
class ObjectAnnotationValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def errors(annotations)
    Validator.send(:object_annotation_errors, {"annotations" => annotations})
  end

  def test_no_annotations_is_fine
    assert_empty errors(nil)
    assert_empty errors({})
  end

  def test_ordinary_annotations_are_accepted
    assert_empty errors("kubectl.kubernetes.io/last-applied-configuration" => "{}",
                        "example.com/Note" => "hello", "plain" => "v")
  end

  def test_an_invalid_key_is_rejected
    refute_empty errors("bad key" => "v")
    refute_empty errors("a/b/c" => "v")
  end

  def test_the_total_size_is_capped
    big = "x" * (128 * 1024)

    assert_empty errors("a" => big)
    refute_empty errors("a" => big, "b" => big, "c" => "overflow")
  end

  def test_the_offending_key_is_named
    issues = errors("ok" => "v", "bad key" => "v")

    assert_equal %w[metadata annotations], issues.first.path.first(2)
    assert_equal "bad key", issues.first.path.last
  end
end
