# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateLabels (apimachinery meta/v1/validation:113) runs over every object's
# metadata.labels.  Only selector requirement keys were checked here, so an
# object could be stored with a label that no selector can ever match.
class ObjectLabelValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def errors(labels)
    Validator.send(:object_label_errors, {"labels" => labels})
  end

  def test_no_labels_is_fine
    assert_empty errors(nil)
    assert_empty errors({})
  end

  def test_ordinary_labels_are_accepted
    assert_empty errors("app" => "demo", "app.kubernetes.io/name" => "web",
                        "example.com/tier" => "front-end", "empty" => "")
  end

  def test_an_invalid_key_is_rejected
    refute_empty errors("bad key" => "v")
  end

  def test_an_invalid_value_is_rejected
    refute_empty errors("app" => "not valid")
    refute_empty errors("app" => "-leading")
    refute_empty errors("app" => "trailing-")
  end

  def test_an_over_long_value_is_rejected
    refute_empty errors("app" => "a" * 64)
    assert_empty errors("app" => "a" * 63)
  end

  def test_the_offending_label_is_named
    issues = errors("app" => "ok", "bad" => "not valid")

    assert_equal 1, issues.length
    assert_equal %w[metadata labels bad], issues.first.path
  end
end
