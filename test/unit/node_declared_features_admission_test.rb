# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/security/admission/plugins/core"

# plugin/pkg/admission/nodedeclaredfeatures/admission_test.go TestAdmission,
# plus the real default registry end to end.
class NodeDeclaredFeaturesAdmissionTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission
  NDF = Rubernetes::NodeDeclaredFeatures

  class Context
    attr_accessor :gates

    def initialize(nodes)
      @nodes = nodes.to_h { |node| [node.dig("metadata", "name"), node] }
      @gates = {"NodeDeclaredFeatures" => true}
    end

    def get(resource, _namespace, name, **) = resource == "nodes" ? @nodes[name] : nil
    def feature_enabled?(gate) = @gates.fetch(gate, false)
  end

  class Mock
    attr_reader :name, :max_version

    def initialize(name, update, max_version = nil)
      @name = name
      @update = update
      @max_version = max_version
    end

    def infer_for_update(_old, _new) = @update
    def infer_for_scheduling(_pod) = false
  end

  def setup
    @nodes = [
      {"metadata" => {"name" => "test-node"}, "status" => {"declaredFeatures" => ["TestFeature"]}},
      {"metadata" => {"name" => "test-node-no-feature"}, "status" => {"declaredFeatures" => []}}
    ]
    @context = Context.new(@nodes)
    @old_pod = {
      "metadata" => {"name" => "test-pod", "namespace" => "test-ns"},
      "spec" => {"nodeName" => "test-node",
                 "containers" => [{"name" => "container", "image" => "image",
                                   "resources" => {"requests" => {"cpu" => "1000m", "memory" => "100Mi"}}}]}
    }
    @new_pod = Marshal.load(Marshal.dump(@old_pod))
    @new_pod["spec"]["containers"][0]["resources"]["requests"]["cpu"] = "2000m"
  end

  def test_upstream_table
    cases = [
      ["Feature gate disabled", pod, [], false, "1.35.0", nil],
      ["skip validation when pod is not bound to node", pod(node: ""), [], true, "1.35.0", nil],
      ["skip validation on invalid node name", pod(node: "not-found-node"), [Mock.new("TestFeature", true, "1.35.0")], true, "1.35.0",
       'node "not-found-node" not found'],
      ["No feature requirements", pod, [Mock.new("FeatureA", false)], true, "1.35.0", nil],
      ["Feature requirement met", pod, [Mock.new("TestFeature", true, "1.35.0")], true, "1.35.0", nil],
      ["Feature requirement not met", pod(node: "test-node-no-feature"), [Mock.new("TestFeature", true, "1.35.0")], true, "1.34.0",
       'pod update requires features TestFeature which are not available on node "test-node-no-feature"'],
      ["skip validation when generation not updated", pod(unchanged: true, node: "test-node-no-feature"),
       [Mock.new("TestFeature", true, "1.35.0")], true, "1.34.0", nil],
      ["Feature not need as its generally available", pod(node: "test-node-no-feature"), [Mock.new("TestFeature", true, "1.35.0")], true,
       "1.35.1", nil],
      ["skip validation for status subresource", pod(node: "test-node-no-feature"), [Mock.new("TestFeature", true)], true, "1.35.0", nil,
       "status"],
      ["DO not skip validation for resize subresource", pod, [Mock.new("TestFeature", true)], true, "1.35.0", nil, "resize"]
    ]
    cases.each do |name, new_pod, registry, gate, version, error, subresource|
      @context.gates = {"NodeDeclaredFeatures" => gate}
      plugin = A::Plugins::NodeDeclaredFeatureValidator.new("NodeDeclaredFeatureValidator", context: @context)
      plugin.framework = NDF::Framework.new(registry)
      plugin.version = version
      run = -> { plugin.validate(attributes(new_pod, subresource: subresource.to_s)) }
      if error
        rejected = assert_raises(A::Rejected, name) { run.call }
        assert_includes rejected.message, error, name
        assert_equal 403, rejected.code, name
        assert_match(/\Apods "test-pod" is forbidden: /, rejected.message, name)
      else
        run.call
      end
    end
  end

  # The real registry: pod-level resize needs InPlacePodLevelResourcesVerticalScaling.
  def test_default_registry_pod_level_resize
    plugin = A::Plugins::NodeDeclaredFeatureValidator.new("NodeDeclaredFeatureValidator", context: @context)
    old_pod = Marshal.load(Marshal.dump(@old_pod))
    old_pod["spec"]["nodeName"] = "test-node-no-feature"
    old_pod["spec"]["resources"] = {"limits" => {"cpu" => "1"}}
    resized = Marshal.load(Marshal.dump(old_pod))
    resized["spec"]["resources"] = {"limits" => {"cpu" => "2"}}
    rejected = assert_raises(A::Rejected) { plugin.validate(attributes(resized, old: old_pod, subresource: "resize")) }
    assert_includes rejected.message, "pod update requires features InPlacePodLevelResourcesVerticalScaling which are not available"

    # A container-level resize needs no declared feature.
    plugin.validate(attributes(pod(node: "test-node-no-feature"), subresource: "resize"))
    # A node that declares it admits the update.
    @nodes[1]["status"]["declaredFeatures"] = ["InPlacePodLevelResourcesVerticalScaling"]
    plugin.validate(attributes(resized, old: old_pod, subresource: "resize"))
  end

  def test_other_operations_and_resources_are_ignored
    plugin = A::Plugins::NodeDeclaredFeatureValidator.new("NodeDeclaredFeatureValidator", context: @context)
    plugin.framework = NDF::Framework.new([Mock.new("Missing", true)])
    plugin.validate(attributes(pod, operation: "CREATE"))
    plugin.validate(attributes(pod, subresource: "binding"))
    rejected = assert_raises(A::Rejected) { plugin.validate(attributes(pod)) }
    assert_includes rejected.message, "Missing"
  end

  private

  def pod(node: nil, unchanged: false)
    value = Marshal.load(Marshal.dump(unchanged ? @old_pod : @new_pod))
    value["spec"]["nodeName"] = node unless node.nil?
    value
  end

  def attributes(object, old: nil, subresource: "", operation: "UPDATE")
    old ||= Marshal.load(Marshal.dump(@old_pod)).tap { |value| value["spec"]["nodeName"] = object["spec"]["nodeName"] }
    A::Attributes.new(operation: operation, user: S::UserInfo.new(name: "alice"), group: "", version: "v1", resource: "pods",
                      kind: "Pod", namespace: "test-ns", name: "test-pod", object: object, old_object: old, subresource: subresource)
  end
end
