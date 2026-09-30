# frozen_string_literal: true

# M3 controller registry contract: spec/control-plane/controllers.md §5.5.1
# (C6/C7). This integration test verifies that the duplicate-registration
# evidence records the exact production exception class.

require_relative "../test_helper"
require "json"
require "open3"
require "rbconfig"

class M3ControllerRegistryProbeTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__).freeze
  PROBE = File.join(ROOT, "tools/milestones/m3_controller_registry_probe.rb").freeze

  # Requirement: the pinned 52-controller registry must reject a duplicate
  # registration with DuplicateControllerError. Mutation target: rescuing a
  # generic StandardError and still claiming duplicate rejection.
  def test_duplicate_registration_records_the_exact_production_exception
    stdout, stderr, process = Open3.capture3(RbConfig.ruby, "-Ilib", PROBE, chdir: ROOT)
    report = JSON.parse(stdout)

    assert_predicate process, :success?, "controller registry probe failed: #{stderr}\n#{report.fetch("errors", []).join("; ")}"
    assert_equal "PASS", report.fetch("status")
    assert_equal true, report.fetch("passed")
    assert_equal 52, report.fetch("registered_count")
    assert_equal 0, report.fetch("duplicate_count")
    assert_equal "Rubernetes::Controller::DuplicateControllerError", report.fetch("duplicate_exception_class")
    assert_equal true, report.fetch("duplicate_check_passed")
    assert_equal true, report.fetch("startup_validation").fetch("passed")
    assert_equal 1, report.fetch("startup_validation").fetch("attempt_count")
    assert(
      report.fetch("controllers").all? do |entry|
        binding = entry.fetch("binding")
        binding.fetch("authoritative_corpus").fetch("gvk").is_a?(Array) &&
          binding.fetch("ownership_edges").is_a?(Array) &&
          binding.fetch("watch_wiring").is_a?(Array) &&
          entry.fetch("metadata_digest").match?(/\A[0-9a-f]{64}\z/)
      end
    )
  end
end
