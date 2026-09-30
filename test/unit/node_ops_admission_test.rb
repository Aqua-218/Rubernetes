# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/admission"

class NodeOpsAdmissionTest < Minitest::Test
  def setup
    @pod = {
      "metadata" => {"name" => "workload", "namespace" => "default"},
      "spec" => {
        "nodeName" => "node-a",
        "containers" => [{"name" => "main", "resources" => {"requests" => {"cpu" => "500m", "memory" => "1Gi"}}}]
      }
    }
  end

  def admission(**)
    Rubernetes::Node::Admission.new(
      node_name: "node-a", capacity: {"cpu" => "1", "memory" => "2Gi"}, operating_system: "linux", architecture: "amd64", **
    )
  end

  def test_accepts_matching_node_os_arch_and_resources
    decision = admission.admit(@pod)

    assert_predicate(decision, :accepted?)
    assert_equal("Admitted", decision.reason)
  end

  def test_rejects_wrong_node_os_arch_and_cpu_without_side_effects
    assert_equal("NodeNameMismatch", admission.admit(@pod.merge("spec" => @pod["spec"].merge("nodeName" => "node-b"))).reason)
    assert_equal("UnsupportedOS", admission.admit(@pod.merge("spec" => @pod["spec"].merge("os" => {"name" => "windows"}))).reason)
    assert_equal("UnsupportedArchitecture",
                 admission.admit(@pod.merge("metadata" => {"name" => "arm", "annotations" => {"kubernetes.io/arch" => "arm64"}})).reason)
    cpu_heavy = @pod.merge("spec" => @pod["spec"].merge("containers" => [{"name" => "main",
                                                                          "resources" => {"requests" => {"cpu" => "2"}}}]))

    assert_equal("OutOfcpu", admission.admit(cpu_heavy).reason)
  end

  def test_selector_and_runtime_class_are_checked
    selected = @pod.merge("spec" => @pod["spec"].merge("nodeSelector" => {"disk" => "ssd"}))

    assert_equal("NodeSelectorMismatch", admission.admit(selected).reason)
    runtime = @pod.merge("spec" => @pod["spec"].merge("runtimeClassName" => "microvm"))

    assert_equal("RuntimeClassNotFound", admission.admit(runtime).reason)
    assert(admission(node_labels: {"disk" => "ssd"}, runtime_classes: {"microvm" => {"handler" => "x"}}).admitted?(runtime))
  end
end
