# frozen_string_literal: true

require_relative "../test_helper"

class ControllerLabelSelectorsTest < Minitest::Test
  Controller = Rubernetes::Controller

  def test_equality_and_in_require_the_label_to_be_present
    [
      {"tag" => ""},
      {"tag" => ["", "blue"]},
      {"matchLabels" => {"tag" => ""}},
      {"matchExpressions" => [{"operator" => "In", "key" => "tag", "values" => ["", "blue"]}]},
      "tag=",
      "tag in ()",
      "tag in (,blue),!other"
    ].each do |selector|
      refute matches?(selector, {}), selector.inspect
      assert matches?(selector, {tag: ""}), selector.inspect
      refute matches?(selector, {"tag" => "red"}), selector.inspect
    end
  end

  def test_inequality_and_not_in_accept_an_absent_label
    [
      {"matchExpressions" => [{"operator" => "NotIn", "key" => "tag", "values" => ["", "blue"]}]},
      "tag!=",
      "tag notin ()",
      "tag notin (blue,),!other"
    ].each do |selector|
      assert matches?(selector, {}), selector.inspect
      refute matches?(selector, {tag: ""}), selector.inspect
      assert matches?(selector, {"tag" => "red"}), selector.inspect
    end
  end

  def test_reserved_field_names_are_also_legal_label_keys
    labels = {"matchLabels" => "", "matchExpressions" => "blue"}

    assert matches?(labels, labels)
    refute matches?(labels, {"matchExpressions" => "blue"})
    assert matches?({"matchLabels" => labels}, labels)
    refute matches?({"matchLabels" => labels}, {"matchExpressions" => "blue"})
    assert matches?({"matchExpressions" => %w[blue green]}, labels)
    assert matches?({"matchExpressions" => []}, {})
    assert matches?({"matchLabels" => nil}, {})
  end

  def test_text_sets_compose_and_use_label_keys_only
    selector = "tag in (green,blue),spec.nodeName=,!disabled"

    assert matches?(selector, {"tag" => "blue", "spec.nodeName" => ""})
    assert matches?(selector, {"tag" => "green", "spec.nodeName" => ""})
    refute matches?(selector, {"tag" => "green"})
    refute matches?(selector, {"tag" => "red", "spec.nodeName" => ""})
    refute matches?(selector, {"tag" => "blue", "spec.nodeName" => "", "disabled" => ""})
  end

  def test_service_controllers_only_publish_pods_with_both_label_keys
    adapter = Controller::StoreAdapter.new(Rubernetes::Storage::MemoryStore.new)
    selector = {"matchLabels" => "", "matchExpressions" => "blue"}
    service = {
      "apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "test"},
      "spec" => {"selector" => selector,
                 "ports" => [{"port" => 80}], "clusterIP" => "10.96.0.1"}
    }
    service = adapter.create(service)
    pod_labels = [selector, selector.except("matchLabels"), selector.merge("matchExpressions" => "red")]
    pod_labels.each_with_index { |labels, index| adapter.create(pod(labels, index + 1)) }
    adapter.create({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "worker"}})
    result = Controller::EndpointSliceController.new(store: adapter).reconcile(service)
    legacy = Controller::EndpointController.new(store: adapter).reconcile(service)
    addresses = adapter.list("EndpointSlice", namespace: "test").flat_map do |slice|
      slice.fetch("endpoints").flat_map { |endpoint| endpoint.fetch("addresses") }
    end
    endpoints = adapter.find("Endpoints", namespace: "test", name: "web")

    assert result.applied
    assert_equal ["10.42.0.1"], addresses
    assert legacy.applied
    assert_equal "10.42.0.1", endpoints.dig("subsets", 0, "addresses", 0, "ip")
    assert_equal 1, endpoints.dig("subsets", 0, "addresses").size
  end

  private

  def matches?(selector, labels)
    Controller::Support.selector_matches?(selector, {"metadata" => {"labels" => labels}})
  end

  def pod(labels, index)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "pod-#{index}", "namespace" => "test", "labels" => labels},
     "spec" => {"nodeName" => "worker"},
     "status" => {"podIP" => "10.42.0.#{index}", "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end
end
