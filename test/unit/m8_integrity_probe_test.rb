# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../../tools/milestones/m8_integrity_probe"

class M8IntegrityProbeTest < Minitest::Test
  Probe = M8IntegrityProbe

  def test_full_suite_selection_is_checked_on_the_original_argv
    assert_empty Probe.selection_flags(%w[sonobuoy run --mode=certified-conformance --skip-preflight=dnscheck])
    assert_empty Probe.selection_flags(%w[hydrophone --kubeconfig /tmp/test--skip-flag])
    assert_equal ["--mode"], Probe.selection_flags(%w[sonobuoy run --mode quick])
    assert_equal ["--ginkgo.focus", "E2E_SKIP"], Probe.selection_flags(%w[hydrophone --extra-args=--ginkgo.focus=Foo E2E_SKIP=Bar])
  end

  def test_relocated_original_is_read_and_missing_or_changed_commands_are_reported
    Dir.mktmpdir do |dir|
      path = File.join(dir, "k1/hydrophone-command.json")
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, JSON.generate("command" => %w[hydrophone --conformance]))
      artifact = {"path" => "/original/fixture/k1/hydrophone-command.json", "sha256" => Digest::SHA256.file(path).hexdigest}
      lane = {"lane" => "K1", "status" => "COMPLETE", "artifacts" => [artifact]}
      manifest = {"_path" => File.join(dir, "manifest.json"), "lanes" => [lane], "artifacts" => [artifact]}

      assert_empty Probe.command_violations([manifest])

      File.write(path, JSON.generate("command" => %w[hydrophone --ginkgo.skip=X]))

      assert_match(/SHA-256/, Probe.command_violations([manifest]).first.fetch("detail"))
      artifact["sha256"] = Digest::SHA256.file(path).hexdigest

      assert_equal ["--ginkgo.skip"], Probe.command_violations([manifest]).first.fetch("flags")
      File.unlink(path)

      assert_match(/missing/, Probe.command_violations([manifest]).first.fetch("detail"))
      lane["lane"] = "K7"

      assert_empty Probe.command_violations([manifest])
    end
  end

  def test_k5_mode_and_endpoints_are_taken_from_the_recorded_command
    args = %w[ruby /tools/k5_differential.rb --output=/report --oracle-kubeconfig /oracle --kubeconfig /target]

    refute M8K5Evidence.cbor_enabled?(args)
    assert M8K5Evidence.cbor_enabled?(%w[ip netns exec ns] + args + %w[--cbor-enabled])
    assert_raises(ArgumentError) { M8K5Evidence.cbor_enabled?(args + %w[--kubeconfig /target]) }
    assert_raises(ArgumentError) { M8K5Evidence.cbor_enabled?(args.take(5) + %w[--kubeconfig /oracle]) }
  end
end
