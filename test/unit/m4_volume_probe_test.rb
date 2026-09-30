# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "open3"
require "rbconfig"

class M4VolumeProbeTest < Minitest::Test
  PROBE = File.expand_path("../../tools/milestones/m4_volume_probe.rb", __dir__)
  EXTERNAL_RUNNER_KEYS = %w[
    RUBERNETES_M4_VOLUME_OBSERVATION_COMMAND RUBERNETES_M4_CONTAINER_OBSERVATION_COMMAND
    RUBERNETES_M4_CSI_ORACLE_COMMAND RUBERNETES_M4_EXTERNAL_CSI_COMMAND
    RUBERNETES_M4_SNAPSHOT_RECOVERY_COMMAND RUBERNETES_M4_VOLUME_CRASH_COMMAND
  ].freeze

  def test_probe_reports_feasible_production_semantics_without_fabricating_external_evidence
    # A nil value unsets the variable in the child; deleting the key from a
    # copied hash would let Open3 inherit it from the parent environment.
    environment = EXTERNAL_RUNNER_KEYS.to_h { |key| [key, nil] }
    stdout, _stderr, status = Open3.capture3(environment, RbConfig.ruby, "-Ilib", PROBE,
                                             chdir: File.expand_path("../..", __dir__))
    report = JSON.parse(stdout)

    refute_predicate status, :success?, "the probe must remain incomplete without independent runners"
    refute report.fetch("passed")
    assert_equal "production_module_unprivileged_adapter", report.fetch("measurement_source")
    assert_equal false, report.dig("adapter_provenance", "kernel_backed")
    assert_equal({}, report.fetch("kernel_observation"))
    assert_equal({}, report.fetch("csi_oracle"))
    assert_equal({}, report.fetch("snapshot_recovery"))
    assert_equal %w[ReadOnlyMany ReadWriteMany ReadWriteOnce ReadWriteOncePod], report.fetch("access_modes").sort
    assert_equal %w[attach detach mount unmount], report.fetch("stages").map { |entry| entry.fetch("id") }.sort

    kinds = report.fetch("volume_kinds").to_h { |entry| [entry.fetch("id"), entry] }

    assert_equal "production_module_object_construction", kinds.fetch("persistent_volume").fetch("measurement_source")
    assert_equal "production_module_object_construction", kinds.fetch("persistent_volume_claim").fetch("measurement_source")
    assert_equal "production_module_object_construction", kinds.fetch("storage_class").fetch("measurement_source")
    assert_equal "production_module_injected_client", kinds.fetch("csi").fetch("measurement_source")

    snapshot_operations = report.fetch("snapshot_operations")

    assert_equal %w[snapshot_create snapshot_restore], snapshot_operations.map { |entry| entry.fetch("id") }.sort
    assert(snapshot_operations.all? do |entry|
      entry.fetch("passed") == true && entry.key?("expected") && entry.key?("actual") && entry.key?("expected_sha256") && entry.key?("actual_sha256")
    end)
    assert_equal(["crash_recovery"], report.fetch("crash_recovery_operations").map { |entry| entry.fetch("id") })
    assert_equal true, report.fetch("crash_recovery_operations").first.fetch("passed")
  end
end
