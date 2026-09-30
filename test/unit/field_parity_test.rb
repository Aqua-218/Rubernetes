# frozen_string_literal: true

require "fileutils"
require "json"
require "tmpdir"
require_relative "../test_helper"
require File.expand_path("../../tools/schema/field_parity", __dir__)

class FieldParityTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  GENERATED_ROOT = File.join(ROOT, "generated")
  CORPUS_ROOT = File.join(ROOT, "schema/kubernetes/v1.36.2")

  def test_canonical_and_generated_surfaces_have_complete_parity
    report = verifier.verify

    assert_equal(true, report.fetch("passed"), failure_summary(report))
    assert_equal(
      {
        "types" => 771,
        "type_gvks" => 311,
        "gvks" => 321,
        "primary_gvrs" => 95,
        "served_gvrs" => 153,
        "route_gvrs" => 150
      },
      report.fetch("counts")
    )
    protobuf = report.fetch("protobuf")

    assert_equal(770, protobuf.fetch("supported_count"))
    assert_equal(770, protobuf.fetch("roundtrip_count"))
    assert_equal(1, protobuf.fetch("unsupported_count"))
    unsupported = protobuf.fetch("capabilities").reject { |entry| entry.fetch("protobuf_supported") }

    assert_equal(
      [{
        "schema" => "io.k8s.apimachinery.pkg.version.Info",
        "protobuf_supported" => false,
        "reason" => "upstream has no generated.proto"
      }],
      unsupported
    )
  end

  def test_missing_field_is_rejected
    with_generated_copy do |generated_root|
      path = File.join(generated_root, "fixtures/field-sets.json")
      fields = JSON.parse(File.binread(path))
      schema_name = fields.keys.first
      fields.fetch(schema_name).fetch("codec").pop
      File.binwrite(path, JSON.generate(fields) << "\n")

      report = verifier(generated_root: generated_root).verify

      assert_equal(false, report.fetch("passed"))
      assert(report.fetch("issues").any? do |issue|
        issue.fetch("code") == "field_parity" && issue.fetch("subject") == "#{schema_name}:codec"
      end, failure_summary(report))
    end
  end

  def test_duplicate_gvk_is_rejected
    with_generated_copy do |generated_root|
      path = File.join(generated_root, "schema/registry.json")
      registry = JSON.parse(File.binread(path))
      duplicate = registry.fetch("gvks").first.dup
      registry.fetch("gvks") << duplicate
      File.binwrite(path, JSON.generate(registry) << "\n")

      report = verifier(generated_root: generated_root).verify

      assert_equal(false, report.fetch("passed"))
      assert(report.fetch("issues").any? do |issue|
        issue.fetch("code") == "duplicate_identifier" && issue.fetch("subject").start_with?("registry GVK:")
      end, failure_summary(report))
    end
  end

  def test_reserved_accessor_is_rejected
    with_generated_copy do |generated_root|
      path = File.join(generated_root, "ruby/kubernetes_types.rb")
      source = File.binread(path)
      marker = "      def nullable\n        field(\"nullable\")\n      end\n"
      replacement = marker + "      def not\n        field(\"not\")\n      end\n"

      assert_includes(source, marker)
      File.binwrite(path, source.sub(marker, replacement))

      report = verifier(generated_root: generated_root).verify

      assert_equal(false, report.fetch("passed"))
      assert(report.fetch("issues").any? do |issue|
        issue.fetch("code") == "reserved_accessor" && issue.fetch("subject").end_with?("#not")
      end, failure_summary(report))
    end
  end

  def test_patch_field_path_difference_is_rejected
    with_generated_copy do |generated_root|
      path = File.join(generated_root, "schema/registry.json")
      registry = JSON.parse(File.binread(path))
      resource = registry.fetch("resources").find { |entry| !entry.fetch("field_paths").empty? }
      removed = resource.fetch("field_paths").pop
      File.binwrite(path, JSON.generate(registry) << "\n")

      report = verifier(generated_root: generated_root).verify

      assert_equal(false, report.fetch("passed"))
      assert(report.fetch("issues").any? do |issue|
        issue.fetch("code") == "patch_metadata" &&
          issue.fetch("subject").end_with?(":field_paths") &&
          issue.fetch("expected").include?(removed)
      end, failure_summary(report))
    end
  end

  private

  def verifier(generated_root: GENERATED_ROOT)
    RubernetesFieldParity::Verifier.new(
      root: ROOT,
      corpus_root: CORPUS_ROOT,
      generated_root: generated_root
    )
  end

  def with_generated_copy
    Dir.mktmpdir("rubernetes-field-parity-") do |directory|
      generated_root = File.join(directory, "generated")
      FileUtils.cp_r(GENERATED_ROOT, generated_root)
      yield generated_root
    end
  end

  def failure_summary(report)
    report.fetch("issues").first(5).map do |issue|
      "#{issue.fetch("code")}: #{issue.fetch("subject")}"
    end.join("\n")
  end
end
