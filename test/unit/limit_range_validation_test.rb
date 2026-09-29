# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateLimitRange (pkg/apis/core/validation/validation.go:7636-7720): a type
# appears once and the min/max/default/defaultRequest of one resource must be
# internally consistent.  None of it was checked, so a LimitRange could be
# stored that rejects every Pod it defaults -- min above max, or a default
# outside its own bounds.
class LimitRangeValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def range(limits)
    {"apiVersion" => "v1", "kind" => "LimitRange",
     "metadata" => {"name" => "lr", "namespace" => "ns"}, "spec" => {"limits" => limits}}
  end

  def errors(limits)
    Validator.send(:limit_range_consistency_errors, range(limits))
  end

  def test_a_consistent_range_is_accepted
    assert_empty errors([{"type" => "Container", "min" => {"cpu" => "100m"},
                          "max" => {"cpu" => "2"}, "default" => {"cpu" => "1"},
                          "defaultRequest" => {"cpu" => "500m"}}])
  end

  def test_min_above_max_is_rejected
    refute_empty errors([{"type" => "Container", "min" => {"cpu" => "4"}, "max" => {"cpu" => "2"}}])
  end

  def test_a_default_above_max_is_rejected
    refute_empty errors([{"type" => "Container", "max" => {"cpu" => "1"}, "default" => {"cpu" => "2"}}])
  end

  def test_a_default_below_min_is_rejected
    refute_empty errors([{"type" => "Container", "min" => {"cpu" => "2"}, "default" => {"cpu" => "1"}}])
  end

  def test_a_default_request_above_the_default_limit_is_rejected
    refute_empty errors([{"type" => "Container", "default" => {"cpu" => "1"},
                          "defaultRequest" => {"cpu" => "2"}}])
  end

  def test_a_duplicate_type_is_rejected
    refute_empty errors([{"type" => "Container", "max" => {"cpu" => "1"}},
                         {"type" => "Container", "max" => {"cpu" => "2"}}])
  end

  def test_a_pod_type_may_not_carry_a_default
    refute_empty errors([{"type" => "Pod", "default" => {"cpu" => "1"}}])
    assert_empty errors([{"type" => "Pod", "max" => {"cpu" => "1"}}])
  end

  def test_a_ratio_below_one_is_rejected
    refute_empty errors([{"type" => "Container", "maxLimitRequestRatio" => {"cpu" => "0"}}])
    assert_empty errors([{"type" => "Container", "maxLimitRequestRatio" => {"cpu" => "2"}}])
  end
end
