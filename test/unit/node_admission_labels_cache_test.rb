# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# Node admission reads the Node's labels (nodeSelector, node affinity) from
# the last copy it read, and reads the live Node again only when a label
# check would reject.  It used to GET the Node on every admission -- one API
# call per Pod start (a 90-Pod burst scheduled noticeably slower).
class NodeAdmissionLabelsCacheTest < Minitest::Test
  def admission(labels_source)
    calls = 0
    provider = lambda do
      calls += 1
      labels_source.call
    end
    subject = Rubernetes::Node::Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                                              node_labels: {"kubernetes.io/hostname" => "n1"}, node_labels_provider: provider)
    [subject, -> { calls }]
  end

  def pod(selector = nil)
    spec = {"containers" => [{"name" => "c"}]}
    spec["nodeSelector"] = selector if selector
    {"metadata" => {"name" => "p", "uid" => "u"}, "spec" => spec}
  end

  def test_pods_without_label_constraints_never_read_the_node
    subject, calls = admission(-> { {"zone" => "a"} })

    3.times { assert subject.admit(pod).accepted }
    assert_equal 0, calls.call
  end

  def test_labels_are_read_once_and_reused
    subject, calls = admission(-> { {"zone" => "a"} })

    3.times { assert subject.admit(pod("zone" => "a")).accepted }
    assert_equal 1, calls.call
  end

  def test_a_mismatch_on_cached_labels_reads_the_node_again
    labels = {"zone" => "a"}
    subject, calls = admission(-> { labels })

    assert subject.admit(pod("zone" => "a")).accepted
    labels = {"zone" => "b"} # kubectl label node n1 zone=b --overwrite

    assert subject.admit(pod("zone" => "b")).accepted, "the fresh labels admit the Pod"
    assert_equal 2, calls.call
    decision = subject.admit(pod("zone" => "c"))

    refute decision.accepted
    assert_equal "NodeSelectorMismatch", decision.reason
    assert_equal 3, calls.call, "a rejection is only ever made on labels read just now"
  end
end
