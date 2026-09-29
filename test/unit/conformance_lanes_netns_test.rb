# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/conformance/lanes"

# The IPv6 and dual-stack conformance clusters live in a network namespace
# of their own (tools/conformance/netns_env.sh); their kubeconfig endpoint
# is that namespace's loopback.  With RUBERNETES_M8_NETNS set, every lane
# runner and reachability probe is entered into the namespace; unset, the
# lanes run exactly as before.
class ConformanceLanesNetnsTest < Minitest::Test
  Lanes = Conformance::Lanes

  def with_env(value)
    previous = ENV["RUBERNETES_M8_NETNS"]
    value.nil? ? ENV.delete("RUBERNETES_M8_NETNS") : ENV["RUBERNETES_M8_NETNS"] = value
    yield
  ensure
    previous.nil? ? ENV.delete("RUBERNETES_M8_NETNS") : ENV["RUBERNETES_M8_NETNS"] = previous
  end

  def test_unset_leaves_the_command_alone
    with_env(nil) { assert_equal %w[hydrophone --conformance], Lanes.in_cluster_namespace(%w[hydrophone --conformance]) }
    with_env("  ") { assert_equal %w[kubectl version], Lanes.in_cluster_namespace(%w[kubectl version]) }
  end

  def test_a_namespace_wraps_the_command_and_capture_runs_inside_it
    with_env("lanes6") do
      assert_equal %w[ip netns exec lanes6 hydrophone --conformance], Lanes.in_cluster_namespace(%w[hydrophone --conformance])
    end
    with_env("no such") { assert_raises(ArgumentError) { Lanes.in_cluster_namespace(%w[true]) } }
    with_env(nil) do
      result = Lanes.capture(["sh", "-c", "echo out; exit 3"])
      assert_equal 3, result.fetch("exit_status")
      assert_equal "out\n", result.fetch("stdout")
    end
  end
end
