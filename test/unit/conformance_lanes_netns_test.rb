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
    previous = ENV.fetch("RUBERNETES_M8_NETNS", nil)
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

  def test_hydrophone_keeps_both_byte_streams_in_compressed_artifacts
    with_env(nil) do
      Dir.mktmpdir do |directory|
        stdout = ("payload\n" * 40_000).b + "• [FAILED] [1.25 seconds]\nspec \xff\n•\n".b
        stderr = "diagnostic\n" * 8000
        command = [RbConfig.ruby, "-e", 'STDOUT.binmode; print "payload\n" * 40_000, "• [FAILED] [1.25 seconds]\nspec \xff\n•\n".b;
                                         warn "diagnostic\n" * 8000; exit 1']
        receipt = Lanes.capture_archived(command, directory: directory, basename: "hydrophone", timeout: 30)

        assert_equal 1, receipt.fetch("exit_status")
        refute receipt.key?("stdout")
        assert_operator JSON.generate(receipt).bytesize, :<, 4096
        [stdout, stderr].zip(%w[stdout stderr]).each do |original, name|
          path = File.join(directory, receipt.fetch("#{name}_artifact"))

          assert_equal original.bytesize, receipt.fetch("#{name}_bytes")
          assert_equal original.b, Zlib::GzipReader.open(path, &:read).b
          assert_operator File.size(path), :<, original.bytesize / 10
        end
        path = File.join(directory, receipt.fetch("stdout_artifact"))
        progress = Zlib::GzipReader.open(path) { |log| Lanes.ginkgo_progress(log) }

        assert_equal [2, 1, 1], progress.values_at("completed", "passed", "failed")
        assert_equal [{"seconds" => 1.25, "spec" => "spec ?"}], progress.fetch("failures")
      end
    end
  end
end
