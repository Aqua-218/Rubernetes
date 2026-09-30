# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node_declared_features"

# Behaviour tables ported from k8s.io/component-helpers/nodedeclaredfeatures
# v1.36.2 (bitmap_test.go, featureset_test.go, framework_test.go and the
# per-feature *_test.go files).
class NodeDeclaredFeaturesTest < Minitest::Test
  NDF = Rubernetes::NodeDeclaredFeatures

  # testing/mocks.go mockFeature.
  class MockFeature
    attr_reader :name, :max_version

    def initialize(name, discover: nil, schedule: nil, update: nil, max_version: nil)
      @name = name
      @discover = discover || ->(config) { config.gate_enabled?(name) }
      @schedule = schedule || ->(_pod) { false }
      @update = update || ->(_old, _new) { false }
      @max_version = max_version
    end

    def discover(config) = @discover.call(config)
    def infer_for_scheduling(pod) = @schedule.call(pod)
    def infer_for_update(old_pod, new_pod) = @update.call(old_pod, new_pod)
    def requirements = NDF::FeatureRequirements.new(enabled_feature_gates: [name], required_runtime_features: nil)
  end

  def test_bitmap_operations
    set = NDF::FeatureSet.new(130).set(0).set(64).set(129)

    assert set.get(64)
    refute set.get(1)
    other = NDF::FeatureSet.new(130).set(0)

    assert other.subset?(set)
    refute set.subset?(other)
    assert_equal NDF::FeatureSet.new(130).set(64).set(129), set.difference(other)
    assert_empty NDF::FeatureSet.new(3)
    assert_equal "101", NDF::FeatureSet.new(3).set(0).set(2).to_s
    assert_raises(IndexError) { set.get(130) }
    assert_raises(NDF::Error) { set.subset?(NDF::FeatureSet.new(3)) }
    refute_equal NDF::FeatureSet.new(3), NDF::FeatureSet.new(4)
  end

  # featureset_test.go TestFeatureMapper.
  def test_feature_mapper_table
    mapper = NDF::FeatureMapper.new(%w[a b c d])
    [
      [nil, false, []],
      [%w[a], false, [0]],
      [%w[a c], false, [0, 2]],
      [%w[a b c d], false, [0, 1, 2, 3]],
      [%w[0 a], true, [0]],
      [%w[a ab b], true, [0, 1]],
      [%w[d e], true, [3]]
    ].each do |input, error, expected|
      set = mapper.try_map(input)

      4.times { |index| assert_equal expected.include?(index), set.get(index), "#{input.inspect} index #{index}" }
      if error
        assert_raises(NDF::Error) { mapper.map_sorted(input) }
      else
        assert_equal set, mapper.map_sorted(input)
        assert_equal Array(input), mapper.unmap(set)
      end

      assert_equal expected.length, mapper.unmap(set).length
    end
    assert_raises(NDF::Error) { mapper.unmap(NDF::FeatureSet.new(2)) }
  end

  # framework_test.go TestDiscoverNodeFeatures.
  def test_discover_node_features
    framework = NDF::Framework.new([MockFeature.new("feature-b"), MockFeature.new("feature-a", max_version: "1.38.0")])
    config = ->(gates, version = "1.36.0") { NDF::NodeConfiguration.new(feature_gates: gates, version: version) }

    assert_equal %w[feature-a], framework.discover_node_features(config.call({"feature-a" => true}))
    assert_equal %w[feature-a feature-b], framework.discover_node_features(config.call({"feature-a" => true, "feature-b" => true}))
    assert_empty framework.discover_node_features(config.call({}))
    assert_empty framework.discover_node_features(config.call({"feature-a" => true}, "1.39.0"))
    assert_empty framework.discover_node_features(config.call({"feature-a" => true}, "1.39.0-alpha.2.39+049eafd34dfbd2"))
  end

  # framework_test.go TestInferForPodScheduling.
  def test_infer_for_pod_scheduling
    pod_level = ->(pod) { !NDF::PodHelpers.spec(pod)["resources"].nil? }
    with = {"spec" => {"resources" => {"requests" => {"cpu" => "1"}}}}
    without = {"spec" => {}}
    feature = ->(**options) { NDF::Framework.new([MockFeature.new("PodLevelResources", schedule: pod_level, **options)]) }

    assert_equal %w[PodLevelResources], infer(feature.call, with, "1.31.0")
    assert_empty infer(feature.call, without, "1.31.0")
    assert_empty infer(NDF::Framework.new([MockFeature.new("PodLevelResources")]), with, "1.31.0")
    assert_equal %w[PodLevelResources], infer(feature.call(max_version: "1.30.0"), with, "0.0.0-alpha.2.39+049eafd34dfbd2")
    assert_empty infer(feature.call(max_version: "1.30.0"), with, "1.40.0")
    error = assert_raises(NDF::Error) { feature.call.infer_for_pod_scheduling(with, nil) }
    assert_includes error.message, "target version cannot be nil"
  end

  # framework_test.go TestInferForPodUpdate.
  def test_infer_for_pod_update
    changed = ->(old_pod, new_pod) { old_pod != new_pod }
    framework = NDF::Framework.new([MockFeature.new("InPlacePodResize", update: changed)])
    old_pod = {"spec" => {"containers" => [{"resources" => {"requests" => {"cpu" => "1"}}}]}}
    new_pod = {"spec" => {"containers" => [{"resources" => {"requests" => {"cpu" => "2"}}}]}}

    assert_equal %w[InPlacePodResize], framework.unmap(framework.infer_for_pod_update(old_pod, new_pod, "1.36.0"))
    assert_equal %w[InPlacePodResize], framework.unmap(framework.infer_for_pod_update(old_pod, new_pod, "1.36.0-alpha.1"))
    assert_empty framework.unmap(framework.infer_for_pod_update(old_pod, old_pod, "1.36.0"))
    assert_raises(NDF::Error) { framework.infer_for_pod_update(old_pod, new_pod, nil) }
  end

  # framework_test.go TestMatchNode.
  def test_match_node
    framework = NDF::Framework.new([MockFeature.new("feature-a"), MockFeature.new("feature-b")])
    required = framework.map_sorted(%w[feature-a feature-b])
    node = ->(declared) { {"status" => {"declaredFeatures" => declared}} }
    [
      [%w[feature-a feature-b], true, []],
      [%w[feature-a], false, %w[feature-b]],
      [%w[feature-c], false, %w[feature-a feature-b]],
      [nil, false, %w[feature-a feature-b]]
    ].each do |declared, match, missing|
      result = framework.match_node(required, node.call(declared))

      assert_equal match, result.match?, declared.inspect
      assert_equal missing, result.unsatisfied_requirements
    end
    assert_predicate framework.match_node(framework.new_feature_set, node.call(nil)), :match?
    assert_raises(NDF::Error) { framework.match_node(required, nil) }
  end

  def test_default_registry_is_sorted_upstream_feature_list
    assert_equal %w[ExtendWebSocketsToKubelet InPlacePodLevelResourcesVerticalScaling InPlacePodVerticalScalingInitContainers
                    RestartAllContainersOnContainerExits UserNamespacesHostNetworkSupport],
                 NDF::DEFAULT_FRAMEWORK.registry.map(&:name)
    assert_equal %w[InPlacePodLevelResourcesVerticalScaling], NDF::DEFAULT_FRAMEWORK.feature_requirements("InPlacePodLevelResourcesVerticalScaling").enabled_feature_gates
    assert_raises(NDF::Error) { NDF::DEFAULT_FRAMEWORK.feature_requirements("Nope") }
  end

  def test_gate_only_discovery
    NDF::Features::ALL.reject { |feature| feature.is_a?(NDF::Features::UserNamespacesHostNetwork) }.each do |feature|
      assert feature.discover(NDF::NodeConfiguration.new(feature_gates: {feature.name => true})), feature.name
      refute feature.discover(NDF::NodeConfiguration.new(feature_gates: {feature.name => false})), feature.name
    end
  end

  # pod_level_resource_resize_test.go.
  def test_pod_level_resources_resize
    feature = NDF::Features::PodLevelResourcesResize.new
    one = {"requests" => {"cpu" => "1"}, "limits" => {"cpu" => "1"}}
    two = {"requests" => {"cpu" => "2"}, "limits" => {"cpu" => "1"}}
    pod = ->(resources) { {"spec" => resources ? {"resources" => resources} : {}} }

    refute feature.infer_for_scheduling(pod.call(one))
    refute feature.infer_for_update(pod.call(one), pod.call(one))
    assert feature.infer_for_update(pod.call(nil), pod.call(one))
    assert feature.infer_for_update(pod.call(one), pod.call(nil))
    assert feature.infer_for_update(pod.call(one), pod.call(two))
    refute feature.infer_for_update(pod.call(nil), pod.call(nil))
    # Semantic equality: the same quantity in another spelling is no change.
    refute feature.infer_for_update(pod.call({"requests" => {"cpu" => "1"}}), pod.call({"requests" => {"cpu" => "1000m"}}))
  end

  # nonsidecar_initcontainers_resize_test.go.
  def test_non_sidecar_init_container_resize
    feature = NDF::Features::NonSidecarInitContainerResize.new
    init = lambda do |cpu, sidecar: false|
      container = {"name" => "init-1", "resources" => {"requests" => {"cpu" => cpu}}}
      container["restartPolicy"] = "Always" if sidecar
      container
    end
    pod = ->(inits, containers = []) { {"spec" => {"initContainers" => inits, "containers" => containers}} }

    refute feature.infer_for_scheduling(pod.call([init.call("100m")]))
    refute feature.infer_for_update(pod.call([init.call("100m")]), pod.call([init.call("100m")]))
    assert feature.infer_for_update(pod.call([init.call("100m")]), pod.call([init.call("200m")]))
    refute feature.infer_for_update(pod.call([init.call("100m", sidecar: true)]), pod.call([init.call("200m", sidecar: true)]))
    app = ->(cpu) { {"name" => "app", "resources" => {"requests" => {"cpu" => cpu}}} }

    assert feature.infer_for_update(pod.call([init.call("100m")], [app.call("1")]), pod.call([init.call("200m")], [app.call("1")]))
    refute feature.infer_for_update(pod.call([init.call("100m")], [app.call("1")]), pod.call([init.call("100m")], [app.call("2")]))
    refute feature.infer_for_update(pod.call([]), pod.call([]))
  end

  # restart_all_containers_test.go.
  def test_restart_all_containers
    feature = NDF::Features::RestartAllContainers.new
    rule = ->(action) { [{"action" => action, "exitCodes" => {"operator" => "In", "values" => [42]}}] }

    assert feature.infer_for_scheduling({"spec" => {"containers" => [{"name" => "c",
                                                                      "restartPolicyRules" => rule.call("RestartAllContainers")}]}})
    assert feature.infer_for_scheduling({"spec" => {"initContainers" => [{"name" => "i",
                                                                          "restartPolicyRules" => rule.call("RestartAllContainers")}]}})
    refute feature.infer_for_scheduling({"spec" => {"containers" => [{"name" => "c", "restartPolicyRules" => rule.call("Restart")}]}})
    refute feature.infer_for_scheduling({"spec" => {"containers" => [{"name" => "c"}]}})
    refute feature.infer_for_update({"spec" => {}}, {"spec" => {}})
  end

  # user_namespaces_host_network_test.go.
  def test_user_namespaces_host_network
    feature = NDF::Features::UserNamespacesHostNetwork.new
    gate = {"UserNamespacesHostNetworkSupport" => true}
    runtime = {"userNamespacesHostNetwork" => true}

    assert feature.discover(NDF::NodeConfiguration.new(feature_gates: gate, runtime_features: runtime))
    refute feature.discover(NDF::NodeConfiguration.new(feature_gates: gate))
    refute feature.discover(NDF::NodeConfiguration.new(feature_gates: {}, runtime_features: runtime))
    assert feature.infer_for_scheduling({"spec" => {"hostNetwork" => true, "hostUsers" => false}})
    refute feature.infer_for_scheduling({"spec" => {"hostNetwork" => true}})
    refute feature.infer_for_scheduling({"spec" => {"hostNetwork" => false, "hostUsers" => false}})
    assert_equal({"userNamespacesHostNetwork" => true}, feature.requirements.required_runtime_features)
  end

  private

  def infer(framework, pod, version)
    framework.unmap(framework.infer_for_pod_scheduling(pod, version))
  end
end
