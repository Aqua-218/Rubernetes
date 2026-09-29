# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# An in-place resize must not be acknowledged (status.observedGeneration) before
# its PodResizeInProgress condition is published: the resize e2e treats
# "generation observed, no resize condition, Pod ready" as done, and round 101's
# "extended resize with equivalents" then read the condition that appeared a
# moment later.  Other spec updates are still acknowledged at once.
class ResizeGenerationAckTest < Minitest::Test
  Lifecycle = Rubernetes::Node::Lifecycle

  def pod(generation, cpu: "5m", image: "img")
    {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u", "generation" => generation},
     "spec" => {"containers" => [{"name" => "c", "image" => image,
                                  "resources" => {"requests" => {"cpu" => cpu}, "limits" => {"cpu" => cpu}}}]}}
  end

  def acknowledged(record, object)
    subject = Lifecycle.allocate
    calls = []
    subject.define_singleton_method(:update_status) { |pod, _record| calls << pod.dig("metadata", "generation") }
    subject.send(:acknowledge_generation, object, record)
    calls
  end

  def test_a_resize_is_left_to_the_resize_path
    assert_empty acknowledged({state: "Running", pod: pod(1, cpu: "1m")}, pod(2, cpu: "5m"))
  end

  def test_other_updates_and_stopped_pods_are_acknowledged
    assert_equal [2], acknowledged({state: "Running", pod: pod(1)}, pod(2, image: "img2"))
    assert_equal [2], acknowledged({state: "Stopped", pod: pod(1, cpu: "1m")}, pod(2, cpu: "5m"))
    assert_empty acknowledged({state: "Running", pod: pod(2)}, pod(2)), "an already observed generation"
  end
end
