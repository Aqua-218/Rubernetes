# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# lifecycle.NewPodFeaturesAdmitHandler (features_linux.go): a Pod with
# pod-level resources is refused only when the PodLevelResources gate is off.
class NodeAdmissionPodFeaturesTest < Minitest::Test
  CAPACITY = {"cpu" => "4", "memory" => "8Gi", "pods" => "10"}.freeze

  def pod(resources) = {"metadata" => {"name" => "p", "uid" => "u"}, "spec" => {"resources" => resources, "containers" => [{"name" => "c"}]}.compact}

  def test_pod_level_resources_need_the_gate
    off = Rubernetes::Node::Admission.new(node_name: "n", capacity: CAPACITY, features: {"PodLevelResources" => false})
    decision = off.admit(pod({"limits" => {"cpu" => "1"}}))
    refute decision.accepted
    assert_equal ["PodLevelResourcesNotSupported", "PodLevelResources feature gate is disabled"], [decision.reason, decision.message]
    assert off.admit(pod(nil)).accepted, "a Pod without pod-level resources is not affected"
    assert Rubernetes::Node::Admission.new(node_name: "n", capacity: CAPACITY).admit(pod({"limits" => {"cpu" => "1"}})).accepted,
           "the gate is on by default"
  end
end
