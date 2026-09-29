# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# A repeated mapping key is dropped silently by every YAML parser -- Ruby and
# Go alike keep the last one -- so the apiserver runs a Strict body through
# sigs.k8s.io/yaml YAMLToJSONStrict a second time purely to catch it
# (apimachinery runtime/serializer/json/json.go Serializer.unmarshal) and
# reports the decoder's own multi-line error as one strict violation.  Without
# it a YAML body could repeat any field and Strict would accept it:
# "[sig-api-machinery] FieldValidation should detect duplicates in a CR when
# preserving unknown fields" matches on the exact text
# `line 9: key "foo" already set in map`.
class YAMLDuplicateFieldTest < Minitest::Test
  Server = Rubernetes::API::Server

  Request = Struct.new(:body, :content_type)

  def server = Server.allocate

  CR_BODY = <<~YAML.freeze

    apiVersion: fv.example.com/v1
    kind: Noxu
    metadata:
      name: mytest
    spec:
      unknown: uk1
      foo: foo1
      foo: foo2
      cronSpec: "* * * * */5"
      ports:
      - name: x
        containerPort: 80
        protocol: TCP
  YAML

  def test_the_duplicate_is_reported_on_the_line_the_decoder_names
    assert_equal([[9, "foo"]], server.send(:duplicate_yaml_keys, CR_BODY))
  end

  def test_a_nested_duplicate_is_found_too
    body = "a: 1\nb:\n  c: 1\n  d: 2\n  c: 3\n"

    assert_equal([[5, "c"]], server.send(:duplicate_yaml_keys, body))
  end

  def test_a_duplicate_inside_a_list_item_is_found
    body = "items:\n- name: x\n  name: y\n"

    assert_equal([[3, "name"]], server.send(:duplicate_yaml_keys, body))
  end

  def test_distinct_keys_are_not_duplicates
    body = "a: 1\nb: 2\nc:\n  a: 3\n"

    assert_empty(server.send(:duplicate_yaml_keys, body))
  end

  def test_an_apply_patch_body_produces_the_decoder_error_block
    request = Request.new(CR_BODY, "application/apply-patch+yaml")

    errors = server.send(:request_duplicate_yaml_errors, request)

    assert_equal(1, errors.length)
    assert_equal("yaml: unmarshal errors:\n  line 9: key \"foo\" already set in map", errors.first)
  end

  def test_a_json_body_is_left_to_the_json_scanner
    request = Request.new(%({"a": 1, "a": 2}), "application/json")

    assert_empty(server.send(:request_duplicate_yaml_errors, request))
    assert_equal(%w[a], server.send(:request_duplicate_fields, request))
  end

  # Warn splits the block back into one warning per line, exactly as
  # endpoints/handlers/rest.go parseYAMLWarnings does.
  def test_the_block_splits_into_one_warning_per_line
    block = "yaml: unmarshal errors:\n  line 9: key \"field2\" already set in map\n" \
            "  line 14: key \"nestedField2\" already set in map"

    assert_equal(["line 9: key \"field2\" already set in map",
                  "line 14: key \"nestedField2\" already set in map"],
                 server.send(:split_yaml_strict_error, block))
  end

  def test_a_non_yaml_violation_is_left_alone
    assert_equal(["unknown field \"spec.foo\""],
                 server.send(:split_yaml_strict_error, "unknown field \"spec.foo\""))
  end

  # The YAML decoder runs before the typed decoder, so its errors come first.
  def test_yaml_errors_precede_unknown_field_violations
    violations = server.send(:strict_field_violations, nil, {},
                             duplicates: ["spec.replicas"],
                             yaml_errors: ["yaml: unmarshal errors:\n  line 5: key \"other\" already set in map"])

    assert_equal(["yaml: unmarshal errors:\n  line 5: key \"other\" already set in map",
                  "duplicate field \"spec.replicas\""], violations)
  end

  def test_a_body_that_is_not_yaml_at_all_reports_nothing
    request = Request.new("\tthis: [is: not\n  valid", "application/yaml")

    assert_empty(server.send(:request_duplicate_yaml_errors, request))
  end
end
