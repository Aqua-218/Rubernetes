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

  def test_the_offending_mode_is_reported_at_the_upstream_list_field
    issues = errors(%w[ReadWriteOnce Nonsense])

    assert_equal 1, issues.length
    assert_equal %w[spec accessModes], issues.first.path
    assert_equal "Nonsense", issues.first.value
  end

  def test_single_pod_access_cannot_be_combined_with_other_supported_modes
    assert_equal [:forbidden], errors(%w[ReadWriteOncePod ReadOnlyMany]).map(&:code)
    assert_empty errors(%w[ReadWriteOncePod ReadWriteOncePod])
  end

  def test_templates_report_the_same_errors_under_the_actual_claim_path
    template = claim([])
    template["spec"].merge!("volumeMode" => "disk", "volumeAttributesClassName" => "Bad_Name", "resources" => {"requests" => {"storage" => "0"}})
    paths = Validator.claim_template_errors({"spec" => {"volumeClaimTemplates" => [template]}}).map(&:kubernetes_field)

    assert_equal %w[spec.volumeClaimTemplates[0].spec.accessModes spec.volumeClaimTemplates[0].spec.resources[storage]
                    spec.volumeClaimTemplates[0].spec.volumeAttributesClassName spec.volumeClaimTemplates[0].spec.volumeMode], paths
  end

  def test_no_access_modes_is_still_required
    refute_empty errors([])
  end
end
