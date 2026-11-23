# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/k5_differential"

class ConformanceK5NormalizationTest < Minitest::Test
  K5 = Conformance::K5Differential

  def test_normalization_preserves_ownership_but_compares_time_by_format
    fields = {"f:spec" => {"f:containers" => {'k:{"name":"worker"}' => {"." => {}, "f:image" => {}}}}}
    manager = {"manager" => "controller", "operation" => "Update", "fieldsV1" => fields, "time" => "2026-11-20T03:00:00Z"}
    normalize = ->(entry) { K5.scrub("metadata" => {"managedFields" => [entry]}) }

    assert_equal normalize.call(manager), normalize.call(manager.merge("time" => "2026-11-19T20:00:00Z"))
    refute_equal normalize.call(manager), normalize.call(manager.merge("manager" => "different"))
    refute_equal normalize.call(manager), normalize.call(manager.merge("fieldsV1" => {"f:spec" => {"f:tolerations" => {}}}))
  end

  def test_user_keys_named_like_metadata_keep_their_literal_values
    payload = {"uid" => "fixture", "generation" => "1", "time" => "2026-11-19T00:00:00Z"}
    object = {"data" => payload, "metadata" => {"labels" => payload, "annotations" => payload, "resourceVersion" => "123"}}
    normalized = K5.scrub(object)

    assert_equal payload, normalized["data"]
    assert_equal payload, normalized.dig("metadata", "labels")
    assert_equal payload, normalized.dig("metadata", "annotations")
    assert_equal "<numeric-string>", normalized.dig("metadata", "resourceVersion")
  end
end
