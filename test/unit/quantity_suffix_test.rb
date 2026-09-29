# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/scheduler"

# resource.Quantity takes binary suffixes Ki..Ei and the decimal SI suffixes
# n u m k M G T P E -- the kilo is a LOWER-case k, and "1k" is the canonical
# form of 1000.  The node's and the scheduler's parsers knew only an
# upper-case "K" (which Kubernetes rejects) and accepted nothing but n/u/m for
# cpu.  A Node an e2e spec patched with example.com/fakecpu: 1000 therefore
# advertised "1k", which neither the scheduler nor the node could read, and
# "[sig-scheduling] SchedulerPreemption PreemptionExecutionPath" never ran.
class QuantitySuffixTest < Minitest::Test
  CASES = {
    ["1k", "example.com/fakecpu"] => 1000,
    ["200", "example.com/fakecpu"] => 200,
    ["1M", "example.com/fakecpu"] => 1_000_000,
    ["500m", "cpu"] => Rational(1, 2),
    ["2k", "cpu"] => 2000,
    ["1Gi", "memory"] => 1024**3,
    ["1G", "memory"] => 1000**3,
    ["1Ki", "memory"] => 1024
  }.freeze

  def test_the_node_parser_reads_every_kubernetes_suffix
    manager = Rubernetes::Node::ResourceManager.new
    CASES.each do |(value, resource), expected|
      assert_equal Rational(expected), manager.parse_quantity(value, resource), "#{value} #{resource}"
    end
  end

  def test_the_scheduler_parser_reads_every_kubernetes_suffix
    CASES.each do |(value, resource), expected|
      assert_equal Rational(expected), Rubernetes::Scheduler::Support.quantity(value, resource), "#{value} #{resource}"
    end
  end
end
