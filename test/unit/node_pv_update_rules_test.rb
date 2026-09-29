# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# ValidateNodeUpdate: podCIDR and providerID may only go from unset to a value.
# ValidatePersistentVolumeUpdate: the volume SOURCE and volumeMode are
# immutable after creation.  Neither was enforced, so a live Node could be
# repointed at a different pod network and a bound PV at a different backing
# volume.
class NodePVUpdateRulesTest < Minitest::Test
  Validator = Rubernetes::Schema::KubernetesValidator

  def node(spec = {})
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "n"}, "spec" => spec}
  end

  def node_errors(new_node, old_node, operation: :update)
    Validator.send(:node_update_errors, new_node, old_node, operation)
  end

  def test_setting_a_pod_cidr_for_the_first_time_is_allowed
    assert_empty node_errors(node("podCIDRs" => ["10.0.0.0/24"]), node)
  end

  def test_changing_a_pod_cidr_is_forbidden
    refute_empty node_errors(node("podCIDRs" => ["10.0.1.0/24"]), node("podCIDRs" => ["10.0.0.0/24"]))
  end

  def test_an_unchanged_pod_cidr_is_fine
    assert_empty node_errors(node("podCIDRs" => ["10.0.0.0/24"]), node("podCIDRs" => ["10.0.0.0/24"]))
  end

  def test_setting_a_provider_id_for_the_first_time_is_allowed
    assert_empty node_errors(node("providerID" => "aws://i-1"), node)
  end

  def test_changing_a_provider_id_is_forbidden
    refute_empty node_errors(node("providerID" => "aws://i-2"), node("providerID" => "aws://i-1"))
  end

  def volume(spec = {})
    {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => "pv"},
     "spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"],
                "hostPath" => {"path" => "/data"}, "volumeMode" => "Filesystem"}.merge(spec)}
  end

  def pv_errors(new_pv, old_pv, operation: :update)
    Validator.send(:persistent_volume_update_errors, new_pv, old_pv, operation)
  end

  def test_an_unchanged_volume_is_accepted
    assert_empty pv_errors(volume, volume)
  end

  def test_the_volume_source_is_immutable
    refute_empty pv_errors(volume("hostPath" => {"path" => "/other"}), volume)
  end

  def test_switching_the_source_kind_is_immutable
    changed = volume
    changed["spec"].delete("hostPath")
    changed["spec"]["nfs"] = {"server" => "s", "path" => "/p"}

    refute_empty pv_errors(changed, volume)
  end

  def test_the_volume_mode_is_immutable
    refute_empty pv_errors(volume("volumeMode" => "Block"), volume)
  end

  def test_capacity_may_change
    assert_empty pv_errors(volume("capacity" => {"storage" => "2Gi"}), volume)
  end

  def test_a_create_is_never_restricted
    assert_empty pv_errors(volume("hostPath" => {"path" => "/other"}), volume, operation: :create)
    assert_empty node_errors(node("podCIDRs" => ["10.0.1.0/24"]), node("podCIDRs" => ["10.0.0.0/24"]),
                             operation: :create)
  end
end
