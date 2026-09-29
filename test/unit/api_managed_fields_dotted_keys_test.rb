# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "json"

# Field paths were dot-joined strings, so a map KEY containing a dot was
# indistinguishable from nesting.  FieldsV1 recorded
#   f:app -> f:kubernetes -> f:io/name
# instead of the single key f:app.kubernetes.io/name, which is what upstream
# writes (a map key is one PathElement, never a path).  Ownership was then
# tracked against paths that do not exist in the object, so conflict detection
# compared nil to nil and apply could not see a real conflict.  Reproduced live
# on 2026-09-14 for ConfigMap data keys, labels, and a ResourceQuota's
# hard["count/replicasets.apps"].
class APIManagedFieldsDottedKeysTest < Minitest::Test
  MF = Rubernetes::API::ManagedFields
  OPENAPI = File.expand_path("../../generated/openapi/v3/api/v1.json", __dir__)

  def type_converter
    @type_converter ||= MF::Schema::TypeConverter.from_components(JSON.parse(File.read(OPENAPI)).dig("components", "schemas"))
  end

  def field_manager(kind)
    MF::FieldManager.new(type_converter: type_converter, group: "", version: "v1", kind: kind)
  end

  def configmap(data)
    {"apiVersion" => "v1", "kind" => "ConfigMap",
     "metadata" => {"name" => "cm", "namespace" => "ns"}, "data" => data}
  end

  def apply(existing, desired, manager:, managed_fields: [], force: false)
    live = existing && existing.merge("metadata" => existing["metadata"].merge("managedFields" => managed_fields))
    field_manager(desired["kind"]).apply(live: live, config: desired, manager: manager, force: force)
  end

  def test_a_dotted_data_key_is_one_field
    _result, entries = apply(nil, configmap("app.properties" => "a=1", "plain" => "b"), manager: "probe")
    fields = entries.first.fetch("fieldsV1").fetch("f:data")

    assert_equal({"f:app.properties" => {}, "f:plain" => {}}, fields)
  end

  def test_a_dotted_label_is_one_field
    desired = {"apiVersion" => "v1", "kind" => "ConfigMap",
               "metadata" => {"name" => "cm", "namespace" => "ns",
                              "labels" => {"app.kubernetes.io/name" => "probe"}}}
    _result, entries = apply(nil, desired, manager: "probe")
    labels = entries.first.fetch("fieldsV1").fetch("f:metadata").fetch("f:labels")

    assert_equal({"f:app.kubernetes.io/name" => {}}, labels)
  end

  def test_quota_resource_names_with_dots_and_slashes_are_one_field_each
    desired = {"apiVersion" => "v1", "kind" => "ResourceQuota",
               "metadata" => {"name" => "q", "namespace" => "ns"},
               "spec" => {"hard" => {"count/replicasets.apps" => "5",
                                     "requests.example.com/dongle" => "3",
                                     "gold.storageclass.storage.k8s.io/requests.storage" => "10Gi"}}}
    _result, entries = apply(nil, desired, manager: "e2e")
    hard = entries.first.fetch("fieldsV1").fetch("f:spec").fetch("f:hard")

    assert_equal(%w[f:count/replicasets.apps f:gold.storageclass.storage.k8s.io/requests.storage
                    f:requests.example.com/dongle].sort, hard.keys.sort)
  end

  def test_ownership_of_a_dotted_key_round_trips
    _first, entries = apply(nil, configmap("app.properties" => "a=1"), manager: "one")
    existing = configmap("app.properties" => "a=1")

    # A second manager changing the same dotted key must conflict.
    error = assert_raises(Rubernetes::API::Status::Conflict) do
      apply(existing, configmap("app.properties" => "a=2"), manager: "two", managed_fields: entries)
    end
    assert_includes error.message, "conflict with \"one\""
  end

  def test_a_different_dotted_key_is_not_a_conflict
    _first, entries = apply(nil, configmap("app.properties" => "a=1"), manager: "one")
    existing = configmap("app.properties" => "a=1")

    result, = apply(existing, configmap("other.properties" => "c=3"), manager: "two", managed_fields: entries)

    assert_equal "c=3", result.fetch("data").fetch("other.properties")
  end

  def test_release_of_a_dotted_key_removes_it
    first, entries = apply(nil, configmap("app.properties" => "a=1", "plain" => "b"), manager: "one")
    result, = apply(first, configmap("plain" => "b"), manager: "one", managed_fields: entries)

    refute result.fetch("data").key?("app.properties"),
           "a field the sole owner stopped applying must be removed"
  end

  def test_update_managed_fields_records_a_dotted_key_once
    entries = field_manager("ConfigMap").update(live: nil, new_object: configmap("a.b" => "1"), manager: "kubelet")
    fields = entries.first.fetch("fieldsV1").fetch("f:data")

    assert_equal({"." => {}, "f:a.b" => {}}, fields)
  end
end
