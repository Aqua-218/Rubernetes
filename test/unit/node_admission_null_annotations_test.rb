# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A Pod whose metadata carries "annotations": null (as Pods created by the Job
# controller did) must pass the OS/architecture admission checks like a Pod
# without annotations; indexing the nil failed every start of GitLab's Helm
# hook Jobs with NoMethodError.
class NodeAdmissionNullAnnotationsTest < Minitest::Test
  def test_null_annotations_are_treated_as_empty
    admission = Rubernetes::Node::Admission.new(node_name: "n1")
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1", "annotations" => nil, "labels" => nil},
           "spec" => {"nodeName" => "n1", "containers" => [{"name" => "c", "image" => "img"}]}}
    decision = admission.admit(pod)

    assert_predicate decision, :success?, decision.respond_to?(:message) ? decision.message.to_s : decision.inspect
  end
end
