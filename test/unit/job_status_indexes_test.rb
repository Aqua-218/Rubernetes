# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema/kubernetes_validator/job_status_indexes"

class JobStatusIndexesTest < Minitest::Test
  VALIDATOR = Rubernetes::Schema::KubernetesValidator
  INDEXED = {completionMode: "Indexed", completions: 10, backoffLimitPerIndex: 0}.freeze

  def causes(spec, status, previous = {})
    VALIDATOR.job_status_index_errors(spec, status, previous).map(&:to_cause)
  end

  def test_reports_format_and_strategy_errors_in_upstream_order
    errors = causes({completions: 5}, {completedIndexes: "0,0", failedIndexes: "0"})

    assert_equal(%w[status.completedIndexes status.completedIndexes status.failedIndexes status.failedIndexes], errors.map { |error| error.fetch("field") })
    assert_equal([
                   'Invalid value: "0,0": error parsing completedIndexes: non-increasing order, previous: 0, current: 0',
                   'Invalid value: "0,0": cannot set non-empty completedIndexes when non-indexed completion mode',
                   'Invalid value: "0": cannot set non-null failedIndexes when backoffLimitPerIndex is null',
                   'Invalid value: "0": failedIndexes and completedIndexes overlap at index: 0'
                 ], errors.map { |error| error.fetch("message") })
  end

  def test_overlap_skips_malformed_fragments_but_checks_valid_ranges
    errors = causes(INDEXED, {completedIndexes: "bad,0-3", failedIndexes: "<,2,5"})

    assert_equal([
                   'Invalid value: "bad,0-3": error parsing completedIndexes: cannot convert string to integer for index: "bad"',
                   'Invalid value: "\u003c,2,5": error parsing failedIndexes: cannot convert string to integer for index: "<"',
                   'Invalid value: "<,2,5": failedIndexes and completedIndexes overlap at index: 2'
                 ], errors.map { |error| error.fetch("message") })
  end

  def test_comparisons_follow_the_string_and_optional_string_zero_values
    assert_empty causes({}, {completedIndexes: ""}, {completedIndexes: nil})
    assert_empty causes({}, {failedIndexes: nil}, {failedIndexes: ""})
    assert_empty causes(INDEXED, {completedIndexes: "bad,2", failedIndexes: "2"}, {completedIndexes: "bad,2", failedIndexes: "2"})
    assert_equal(["status.failedIndexes"], causes({}, {failedIndexes: ""}).map { |error| error.fetch("field") })
    assert_equal(['Invalid value: "2": failedIndexes and completedIndexes overlap at index: 2'],
                 causes(INDEXED, {completedIndexes: "bad,2", failedIndexes: "2"}, {completedIndexes: "bad,2", failedIndexes: "3"}).map do |error|
                   error.fetch("message")
                 end)
  end

  def test_range_parsing_does_not_expand_indexes
    spec = INDEXED.merge(completions: 2_147_483_647)

    assert_equal(['Invalid value: "2147483646": failedIndexes and completedIndexes overlap at index: 2147483646'],
                 causes(spec, {completedIndexes: "+0000-2147483646", failedIndexes: "2147483646"}).map { |error| error.fetch("message") })
    assert_empty causes(spec, {completedIndexes: "0-2147483645", failedIndexes: "2147483646"})
  end

  def test_first_malformed_endpoint_and_format_error
    {
      "0," => 'cannot convert string to integer for index: ""',
      "0-1-2" => %q(the fragment "0-1-2" violates the requirement that an index interval can have at most two parts separated by '-'),
      "10-no" => 'too large index: "10"',
      "3-2" => "non-increasing order, previous: 3, current: 2",
      "0-3,3-5" => "non-increasing order, previous: 3, current: 3",
      "9223372036854775808" => 'cannot convert string to integer for index: "9223372036854775808"'
    }.each do |value, detail|
      errors = causes(INDEXED, {completedIndexes: value})

      assert_equal(["Invalid value: \"#{value}\": error parsing completedIndexes: #{detail}"], errors.map { |error| error.fetch("message") })
    end
  end
end
