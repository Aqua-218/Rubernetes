# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/lint/budget"
require "tempfile"

# The budget lint: lib/ may get smaller and plainer, never bigger or more
# guarded, and a regression cannot be recorded away.
class LintBudgetTest < Minitest::Test
  B = Lint::Budget

  def measure(source)
    Tempfile.create(["sample", ".rb"]) do |file|
      file.write(source)
      file.flush
      B.measure(file.path)
    end
  end

  def test_a_file_is_measured_by_size_longest_method_and_guards
    numbers = measure(<<~RUBY)
      class Sample
        def short = 1

        def long(thing)
          thing.close if thing.respond_to?(:close)
          thing.name
        rescue StandardError
          nil
        end

        def loud
          work
        rescue IOError
          nil
        rescue StandardError => error
          log(error)
        end
      end
    RUBY

    assert_equal({"lines" => 18, "longest_method" => 7, "respond_to" => 1, "swallowed" => 1}, numbers)
  end

  def test_only_what_is_over_a_limit_needs_a_budget
    assert_empty B.over("lines" => 800, "longest_method" => 60, "respond_to" => 0, "swallowed" => 0)
    assert_equal({"lines" => 801, "respond_to" => 2}, B.over("lines" => 801, "longest_method" => 12, "respond_to" => 2, "swallowed" => 0))
  end

  def test_growth_is_a_violation_and_shrinking_is_not
    budget = {"lib/a.rb" => {"lines" => 1000, "respond_to" => 5}}

    assert_empty B.violations({"lib/a.rb" => {"lines" => 900, "respond_to" => 5}}, budget)
    assert_equal ["lib/a.rb: lines is 1001, budget 1000"], B.violations({"lib/a.rb" => {"lines" => 1001}}, budget)
    assert_equal ["lib/a.rb: swallowed is 1, budget 0"], B.violations({"lib/a.rb" => {"swallowed" => 1}}, budget),
                 "a number the file was never over has only the limit"
    assert_equal ["lib/new.rb: longest_method is 61, budget 60"], B.violations({"lib/new.rb" => {"longest_method" => 61}}, budget),
                 "a new file gets no allowance"
  end

  def test_the_tree_is_within_its_recorded_budget
    assert_empty B.violations(B.current, B.recorded)
  end
end
