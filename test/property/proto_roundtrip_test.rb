# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "tmpdir"

require "rubernetes/schema/codec/proto_roundtrip"

class ProtoRoundtripPropertyTest < Minitest::Test
  Coverage = Rubernetes::Schema::Codec::ProtoDescriptor::RoundtripCoverage
  SCHEMA_ROOT = File.expand_path("../../schema/kubernetes/v1.36.2", __dir__)
  OPENAPI_PATH = File.join(SCHEMA_ROOT, "openapi/swagger.json")
  PROTOBUF_ROOT = File.join(SCHEMA_ROOT, "protobuf")

  class << self
    def runner
      @runner ||= Coverage.new(openapi_path: OPENAPI_PATH, protobuf_root: PROTOBUF_ROOT)
    end

    def report
      @report ||= runner.run!
    end
  end

  def test_all_upstream_supported_openapi_schemas_round_trip
    report = self.class.report

    assert_equal true, report.fetch("success")
    assert_equal 771, report.fetch("schema_count")
    assert_equal 770, report.fetch("resolved_count")
    assert_equal 1, report.fetch("unsupported_count")
    assert_equal 770, report.fetch("case_count")
    assert_equal 0, report.fetch("failure_count")
    assert_empty report.fetch("failures")

    cases = report.fetch("cases")
    assert_equal 770, cases.map { |item| item.fetch("schema") }.uniq.length
    assert cases.all? { |item| item.fetch("unknown_wire_preserved") }
    assert(cases.all? do |item|
      kinds = item.fetch("field_kinds")
      item.fetch("field_count") == kinds.fetch("scalar_fields") + kinds.fetch("nested_fields") + kinds.fetch("map_fields")
    end)
  end

  def test_report_covers_every_concrete_field_shape
    report = self.class.report
    coverage = report.fetch("coverage")

    assert_equal 770, coverage.fetch("empty_cases")
    assert_equal 770, coverage.fetch("sample_cases")
    assert_equal 770, coverage.fetch("unknown_wire_cases")
    assert_operator coverage.fetch("fields"), :>, 0
    assert_operator coverage.fetch("scalar_fields"), :>, 0
    assert_operator coverage.fetch("map_fields"), :>, 0
    assert_operator coverage.fetch("repeated_fields"), :>, 0
    assert_operator coverage.fetch("nested_fields"), :>, 0
    assert_equal 0, coverage.fetch("enum_fields")
    assert_match(/declares no protobuf enums/, report.dig("compatibility", "enum_note"))
  end

  def test_only_version_info_is_explicitly_unsupported
    unsupported = self.class.report.fetch("unsupported")

    assert_equal 1, unsupported.length
    assert_equal "io.k8s.apimachinery.pkg.version.Info", unsupported.fetch(0).fetch("schema")
    assert_equal "concrete_protobuf", unsupported.fetch(0).fetch("capability")
    assert_match(/without an upstream generated\.proto descriptor/, unsupported.fetch(0).fetch("reason"))
  end

  def test_machine_readable_report_is_canonical_and_stable
    json = self.class.runner.generate_json
    decoded = JSON.parse(json)

    assert_equal self.class.report, decoded
    assert_equal json, self.class.runner.generate_json
    assert_match(/\A\{"case_count":770,/, json)
    assert_equal 64, decoded.fetch("input_sha256").length
    assert_equal "generic_descriptor_wire", decoded.dig("compatibility", "level")
  end

  def test_unexpected_missing_descriptor_fails_closed
    Dir.mktmpdir("rubernetes-protobuf-roundtrip-") do |directory|
      openapi_path = File.join(directory, "openapi.json")
      File.write(openapi_path, JSON.generate("definitions" => {"io.example.Missing" => {"type" => "object"}}))
      runner = Coverage.new(
        openapi_path: openapi_path,
        protobuf_root: PROTOBUF_ROOT,
        expected_schema_count: 1,
        expected_supported_schema_count: 1,
        unsupported_schemas: {}
      )

      report = runner.run
      assert_equal false, report.fetch("success")
      assert_equal 0, report.fetch("resolved_count")
      assert_equal 2, report.fetch("failure_count")
      assert_equal %w[descriptor_resolution supported_schema_count],
                   report.fetch("failures").map { |failure| failure.fetch("stage") }
      assert_raises(Coverage::CoverageError) { runner.run! }
    end
  end
end
