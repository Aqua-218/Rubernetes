# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/schema/codec/kubernetes_protobuf"

# A Pod update cost 7 ms of apiserver CPU before any consensus work: the
# schema walks visited every node of the object several times over.  These
# pin the shortcuts that removed that work to the answers the full walks gave.
class APIUpdateHotPathTest < Minitest::Test
  Schema = Rubernetes::Schema
  API = Rubernetes::API

  def codec = API::StoreAdapter.time_codec

  # ---- truncate_times only descends where a metav1.Time can live ----------

  def pod
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "creationTimestamp" => "2026-09-18T03:45:58.843311Z"},
     "spec" => {"containers" => [{"name" => "c", "image" => "i", "env" => [{"name" => "T", "value" => "2026-09-18T03:45:58.5Z"}]}],
                "volumes" => [{"name" => "e", "ephemeral" => {"volumeClaimTemplate" => {
                  "metadata" => {"creationTimestamp" => "2026-09-18T03:45:59.25Z"}, "spec" => {}}}}]},
     "status" => {"conditions" => [{"type" => "Ready", "lastTransitionTime" => "2026-09-18T03:46:01.123456Z"}]}}
  end

  def test_time_fields_below_a_pruned_spec_are_still_truncated
    out = codec.truncate_times(pod)

    assert_equal "2026-09-18T03:45:58Z", out.dig("metadata", "creationTimestamp")
    assert_equal "2026-09-18T03:45:59Z",
                 out.dig("spec", "volumes", 0, "ephemeral", "volumeClaimTemplate", "metadata", "creationTimestamp")
    assert_equal "2026-09-18T03:46:01Z", out.dig("status", "conditions", 0, "lastTransitionTime")
  end

  def test_a_subtree_that_cannot_hold_a_time_is_returned_as_is
    input = pod
    out = codec.truncate_times(input)

    assert_same input["spec"]["containers"], out["spec"]["containers"]
    assert_equal "2026-09-18T03:45:58.5Z", out.dig("spec", "containers", 0, "env", 0, "value")
  end

  def test_truncation_never_mutates_its_argument
    input = pod
    snapshot = Marshal.load(Marshal.dump(input))
    codec.truncate_times(input)

    assert_equal snapshot, input
  end

  def test_time_bearing_types
    registry = codec.registry
    bearing = ->(name) { codec.send(:time_bearing?, registry.fetch(name)) }

    assert bearing.call("k8s.io.api.core.v1.PodStatus")
    assert bearing.call("k8s.io.api.core.v1.Volume"), "ephemeral volume templates carry ObjectMeta"
    refute bearing.call("k8s.io.api.core.v1.Container")
    refute bearing.call("k8s.io.api.core.v1.ResourceRequirements")
  end

  # ---- DeepFreeze ------------------------------------------------------------

  def test_deep_freeze_freezes_everything_and_survives_cycles
    shared = {"k" => +"v"}
    value = {"a" => [shared, shared, +"s"], "b" => {"c" => shared}}
    value["b"]["self"] = value
    Schema::DeepFreeze.call(value)

    assert value.frozen?
    assert value["a"].frozen?
    assert shared.frozen?
    assert shared["k"].frozen?
    assert value["a"][2].frozen?
    assert_equal 1, Schema::DeepFreeze.call(1)
    assert_nil Schema::DeepFreeze.call(nil)
  end

  # ---- Validator field lookup ----------------------------------------------

  def definition
    Schema::Definition.new(kind: "Thing", version: "v1",
                           fields: {"foo_bar" => {type: :string, json_name: "fooBar"}, "count" => {type: :integer}})
  end

  def test_fields_are_read_under_any_spelling_json_name_first
    validator = Schema::Validator.new(definition, unknown_fields: :reject)
    field = definition.fields.values.find { |candidate| candidate.json_name == "fooBar" }

    assert_equal [true, "x"], validator.send(:read_field, {"fooBar" => "x"}, field)
    assert_equal [true, "y"], validator.send(:read_field, {fooBar: "y"}, field)
    assert_equal [true, "x"], validator.send(:read_field, {"fooBar" => "x", "foo_bar" => "z"}, field)
    assert_equal [true, "z"], validator.send(:read_field, {"foo_bar" => "z"}, field)
    assert_equal [true, nil], validator.send(:read_field, {"fooBar" => nil}, field)
    assert_equal [false, nil], validator.send(:read_field, {"other" => 1}, field)
  end

  def test_unknown_fields_are_reported_and_known_spellings_are_not
    validator = Schema::Validator.new(definition, unknown_fields: :reject)
    codes = validator.errors({"fooBar" => "x", "foo_bar" => "x", "count" => 1, "extra" => 2}).map { |issue| [issue.code, issue.path] }

    assert_equal [[:unknown_field, ["extra"]]], codes
    assert definition.known_key?("foo_bar")
    refute definition.known_key?("extra")
  end

  # ---- KubernetesValidator.walk ----------------------------------------------

  def test_walk_skips_managed_fields_and_scalars
    object = {"metadata" => {"name" => "n", "managedFields" => [{"fieldsV1" => {"f:spec" => {"f:volumes" => {}}}}]},
              "spec" => {"volumes" => [{"name" => "v"}]}}
    paths = []
    Schema::KubernetesValidator.walk(object) { |_value, path| paths << path }

    assert_equal [[], %w[metadata], %w[spec], %w[spec volumes], %w[spec volumes 0]], paths
  end

  # ---- no-op update detection -------------------------------------------------

  def test_noop_update_ignores_sub_second_times_and_leaves_the_request_alone
    server = API::Server.new(registry: API::Registry.new, store: API::MemoryStore.new)
    stored = codec.truncate_times(pod).merge("metadata" => codec.truncate_times(pod)["metadata"].merge("resourceVersion" => "5"))
    submitted = pod.merge("metadata" => pod["metadata"].merge("resourceVersion" => "4"))
    snapshot = Marshal.load(Marshal.dump(submitted))

    assert server.send(:noop_update?, submitted, stored)
    assert_equal snapshot, submitted
    changed = submitted.merge("spec" => submitted["spec"].merge("activeDeadlineSeconds" => 5))
    refute server.send(:noop_update?, changed, stored)
  end
end
