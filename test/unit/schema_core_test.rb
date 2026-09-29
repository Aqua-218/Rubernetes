# frozen_string_literal: true

require_relative "../test_helper"

class SchemaCoreTest < Minitest::Test
  def test_registry_enforces_unique_gvk_and_gvr
    registry = Rubernetes::Schema::Registry.new
    definition = schema_definition

    assert_same(definition, registry.register(definition))
    assert_same(definition, registry.fetch_gvk("example.io/v1/Demo"))
    assert_same(definition, registry.fetch_gvr("example.io/v1/demos"))
    assert_raises(Rubernetes::Schema::DuplicateGVKError) { registry.register(definition) }
    assert_equal(1, registry.size)
  end

  def test_value_object_preserves_presence_unknown_fields_and_deep_freezes
    object = schema_definition.build(
      "name" => "demo",
      "spec" => {"replicas" => 2},
      "futureField" => {"enabled" => true}
    )

    assert_predicate(object, :frozen?)
    assert_predicate(object.spec, :frozen?)
    assert(object.present?("name"))
    refute(object.present?("status"))
    assert_equal({"futureField" => {"enabled" => true}}, object.unknown_fields)
    assert_raises(FrozenError) { object.unknown_fields.fetch("futureField")["enabled"] = false }
    assert_equal("demo-2", object.with(name: "demo-2").name)
    refute(object.without(:name).present?(:name))
    assert_equal({"name" => "demo", "spec" => {"replicas" => 2}, "futureField" => {"enabled" => true}}, object.to_h)
  end

  def test_validator_reports_required_type_enum_range_and_pattern_errors
    validator = schema_definition.validator
    errors = validator.errors(
      "spec" => {"replicas" => -1, "mode" => "Broken", "name" => "bad value"},
      "extra" => true
    )

    assert_includes(errors.map(&:code), :required)
    assert_includes(errors.map(&:code), :range)
    assert_includes(errors.map(&:code), :enum)
    assert_includes(errors.map(&:code), :pattern)
    assert_includes(errors.map(&:code), :unknown_field)
    assert_raises(Rubernetes::Schema::ValidationError) { validator.validate!("spec" => {}) }
  end

  def test_defaulting_only_fills_omitted_fields_and_is_default_aware
    defaulting = schema_definition.defaulting

    defaulted = defaulting.apply_hash("name" => "demo", "spec" => {})
    assert_equal(1, defaulted.fetch("spec").fetch("replicas"))
    assert_equal("Always", defaulted.fetch("spec").fetch("mode"))
    assert_nil(defaulting.apply_hash("name" => "demo", "spec" => {"mode" => nil}).fetch("spec").fetch("mode"))
    assert_predicate(defaulted, :frozen?)
  end

  def test_kubernetes_admission_defaults_are_explicitly_scoped
    definition = Rubernetes::Schema::Definition.new(
      name: "Container",
      group: "",
      version: "v1",
      kind: "Container",
      resource: "containers",
      fields: {
        "image" => {type: String},
        "imagePullPolicy" => {type: String},
        "resources" => {type: :object},
        "terminationMessagePath" => {type: String},
        "terminationMessagePolicy" => {type: String}
      }
    )
    input = {"image" => "registry.example/demo:v1"}

    schema_defaulted = definition.defaulting.apply_hash(
      input,
      kubernetes_admission_defaults: false
    )
    admission_defaulted = definition.defaulting.apply_hash(
      input,
      kubernetes_admission_defaults: true
    )

    assert_equal(input, schema_defaulted)
    assert_equal("IfNotPresent", admission_defaulted.fetch("imagePullPolicy"))
    assert_equal({}, admission_defaulted.fetch("resources"))
    assert_equal("/dev/termination-log", admission_defaulted.fetch("terminationMessagePath"))
    assert_equal("File", admission_defaulted.fetch("terminationMessagePolicy"))
  end

  def test_diff_separates_spec_and_status_and_ignores_missing_default
    definition = schema_definition
    before = {"name" => "demo", "spec" => {"replicas" => 1}, "status" => {"phase" => "Pending"}}
    after = {"name" => "demo", "spec" => {"replicas" => 2}, "status" => {"phase" => "Running"}}

    diff = definition.diff.call(before, after)
    assert_equal(1, diff.spec.size)
    assert_equal(1, diff.status.size)
    assert_equal(%w[spec replicas], diff.spec.first.path)
    assert_equal(%w[status phase], diff.status.first.path)
    assert(definition.diff.semantic_equal?(
      {"name" => "demo", "spec" => {}},
      {"name" => "demo", "spec" => {"replicas" => 1}}
    ))
  end

  private

  def schema_definition
    Rubernetes::Schema::Definition.new(
      name: "Demo",
      group: "example.io",
      version: "v1",
      resource: "demos",
      fields: {
        "name" => {type: String, required: true},
        "spec" => {
          type: :object,
          properties: {
            "replicas" => {type: Integer, default: 1, minimum: 0, maximum: 10},
            "mode" => {type: String, default: "Always", enum: %w[Always Never]},
            "name" => {type: String, pattern: "\\A[a-z]+\\z"}
          }
        },
        "status" => {
          type: :object,
          properties: {"phase" => {type: String}}
        }
      }
    )
  end
end
