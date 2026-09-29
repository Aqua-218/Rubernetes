# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# Only four access modes exist (pkg/apis/core/validation/validation.go:2470).
# An unrecognised one was accepted and then meant nothing to the attach/mount
# path, so the claim bound to something that could never honour it.
class PVCAccessModeValidationTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def claim(modes)
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
     "metadata" => {"name" => "c", "namespace" => "ns"},
     "spec" => {"accessModes" => modes, "resources" => {"requests" => {"storage" => "1Gi"}}}}
  end

  def errors(modes)
    Validator.send(:pvc_errors, claim(modes))
  end

  def test_each_supported_mode_is_accepted
    %w[ReadOnlyMany ReadWriteMany ReadWriteOnce ReadWriteOncePod].each do |mode|
      assert_empty errors([mode]), "#{mode} must be accepted"
    end
  end

  def test_several_supported_modes_are_accepted
    assert_empty errors(%w[ReadWriteOnce ReadOnlyMany])
  end

  def test_an_unknown_mode_is_rejected
    refute_empty errors(["ReadWriteSome"])
  end

  def test_a_misspelled_mode_is_rejected
    refute_empty errors(["readwriteonce"])
  end

  def test_the_offending_index_is_reported
    issues = errors(%w[ReadWriteOnce Nonsense])

    assert_equal 1, issues.length
    assert_equal %w[spec accessModes 1], issues.first.path
  end

  def test_no_access_modes_is_still_required
    refute_empty errors([])
  end
end
