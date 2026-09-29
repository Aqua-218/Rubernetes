# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"

class NetworkPolicyNftablesReadbackKernelTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'.freeze
    require "rubernetes/network"

    class FaultInjectingPolicyAdapter < Rubernetes::Network::NftablesPolicyAdapter
      def corrupt_second_readback!
        @reads_until_corruption = 2
      end

      private

      def read_kernel_ruleset
        actual = super
        return actual unless @reads_until_corruption

        @reads_until_corruption -= 1
        return actual unless @reads_until_corruption.zero?

        @reads_until_corruption = nil
        rules = actual.fetch("rules").map(&:dup)
        rules.first["expressions"] = [] unless rules.empty?
        actual.merge("rules" => rules)
      end
    end

    table = "rkpolreadback#{Process.pid}"
    snapshot = {
      "revision" => 1,
      "entries" => {
        "kernel" => {
          "pod_index_present" => true,
          "targets" => [{"direction" => "ingress", "ip" => "10.244.9.2", "family" => "ipv4"}],
          "rules" => []
        }
      }
    }
    owner = FaultInjectingPolicyAdapter.new(
      table_name: table, instance_identity: "node-a/agent-owner"
    )
    foreign = Rubernetes::Network::NftablesPolicyAdapter.new(
      table_name: table, instance_identity: "node-a/agent-foreign"
    )

    begin
      abort "owner apply failed" unless owner.atomic_swap(snapshot)
      readback = owner.readback(snapshot: snapshot)
      abort "owned readback was not verified" unless readback.fetch("verified") == true
      rules = readback.fetch("rules")
      abort "kernel rule readback is empty" if rules.empty?
      abort "kernel expressions were not decoded" unless rules.all? do |rule|
        expressions = rule.fetch("expressions")
        !expressions.empty? && expressions.all? do |expression|
          !expression.fetch("name").empty? && expression.fetch("data").is_a?(Array)
        end
      end
      abort "foreign instance accepted owner markers" if foreign.readback(snapshot: snapshot).fetch("verified")
      begin
        foreign.atomic_swap(snapshot)
        abort "foreign instance replaced owner ruleset"
      rescue Rubernetes::Network::PolicyRevisionError
        # Expected: an instance digest mismatch is a hard ownership boundary.
      end

      replacement = Marshal.load(Marshal.dump(snapshot))
      replacement["revision"] = 2
      replacement.dig("entries", "kernel", "targets").first["ip"] = "10.244.9.3"
      owner.corrupt_second_readback!
      begin
        owner.atomic_swap(replacement)
        abort "corrupt replacement readback was accepted"
      rescue Rubernetes::Network::PolicyRevisionError
        # Expected: rollback must restore revision 1 before returning failure.
      end
      abort "prior nftables revision was not restored" unless owner.readback(snapshot: snapshot).fetch("verified")
    ensure
      owner.detach
    end
  RUBY

  def test_instance_marker_and_decoded_expression_readback_in_isolated_netns
    library = File.expand_path("../../lib", __dir__)
    output, error, status = Open3.capture3(
      "unshare", "-Urn", "--", RbConfig.ruby, "-I#{library}", "-e", KERNEL_SCRIPT
    )
    unless status.success?
      blocker = "#{output}\n#{error}"
      if blocker.match?(/Operation not permitted|not supported|Permission denied/)
        skip "isolated nftables kernel blocker: #{blocker.strip}"
      end
    end

    assert status.success?, "isolated nftables readback failed: #{output}\n#{error}"
  end
end
