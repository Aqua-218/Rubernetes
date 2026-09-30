# frozen_string_literal: true

require "json"
require "digest"
require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require File.expand_path("../../tools/schema/import_kubernetes", __dir__)

class CorpusImporterTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  CORPUS_ROOT = File.join(ROOT, "schema/kubernetes/v1.36.2")

  def setup
    @importer = KubernetesCorpusImporter::Importer.new(root: ROOT, output_root: CORPUS_ROOT)
  end

  def test_offline_check_verifies_closure_and_discovery_consistency
    manifest = @importer.run(check: true)
    coverage = manifest.fetch("coverage")

    assert_equal(127, manifest.fetch("source_count"))
    assert_equal(153, coverage.fetch("served_gvr_count"))
    assert_equal([], coverage.fetch("served_gvr_missing_openapi_gvrs"))
    assert_equal([], coverage.fetch("served_gvr_ambiguous_openapi_gvrs"))
    assert_equal([], coverage.fetch("discovery_consistency").fetch("duplicate_resources"))
    assert_equal([], coverage.fetch("discovery_consistency").fetch("kind_conflicts"))
    assert_equal([], coverage.fetch("discovery_consistency").fetch("scope_conflicts"))
    assert_equal([], coverage.fetch("discovery_consistency").fetch("verbs_conflicts"))
    assert_equal(true, coverage.fetch("protobuf_closure").fetch("closed"))
    assert_equal(65, coverage.fetch("protobuf_closure").fetch("reachable_source_count"))
    assert_equal([], coverage.fetch("protobuf_closure").fetch("unresolved_imports"))
  end

  def test_offline_check_rejects_a_manifest_consistent_scope_mutation
    Dir.mktmpdir("rubernetes-corpus-check-") do |directory|
      corpus = File.join(directory, "corpus")
      FileUtils.cp_r(CORPUS_ROOT, corpus)
      lock = File.join(directory, "lock.json")
      FileUtils.cp(File.join(ROOT, "third_party/locks/kubernetes-v1.36.2.json"), lock)

      manifest_path = File.join(corpus, "sources.json")
      manifest = JSON.parse(File.binread(manifest_path))
      record = manifest.fetch("sources").find { |source| source.fetch("id") == "discovery:aggregated_v2.json" }
      discovery_path = File.join(corpus, record.fetch("path"))
      discovery = JSON.parse(File.binread(discovery_path))
      discovery.fetch("items").first.fetch("versions").first.fetch("resources").first["scope"] = "Namespaced"
      mutated_bytes = @importer.send(:canonical_json, discovery)
      File.binwrite(discovery_path, mutated_bytes)
      record["sha256"] = Digest::SHA256.hexdigest(mutated_bytes)
      record["bytes"] = mutated_bytes.bytesize
      File.binwrite(manifest_path, @importer.send(:canonical_json, manifest))

      importer = KubernetesCorpusImporter::Importer.new(root: directory, lock_path: lock, output_root: corpus)
      error = assert_raises(KubernetesCorpusImporter::ValidationError) { importer.run(check: true) }

      assert_match(/scope conflicts/, error.message)
    end
  end

  def test_protobuf_closure_rejects_an_import_missing_from_the_corpus
    source = protobuf_source(
      "k8s.io/api/example/v1/generated.proto",
      "import \"k8s.io/apimachinery/pkg/missing/generated.proto\";\n"
    )

    error = assert_raises(KubernetesCorpusImporter::ValidationError) do
      @importer.send(:validate_protobuf_closure!, [source])
    end

    assert_match(/not present in the corpus/, error.message)
    assert_match(%r{missing/generated\.proto}, error.message)
  end

  def test_protobuf_closure_allows_standard_descriptor_imports
    source = protobuf_source(
      "k8s.io/api/example/v1/generated.proto",
      "import \"google/protobuf/descriptor.proto\";\n"
    )

    report = @importer.send(:validate_protobuf_closure!, [source])

    assert_equal(true, report.fetch("closed"))
    assert_equal(["google/protobuf/descriptor.proto"], report.fetch("standard_descriptor_imports"))
    assert_empty(report.fetch("unresolved_imports"))
  end

  def test_discovery_consistency_rejects_scope_contradiction
    discovery = {
      records: [
        discovery_record("aggregated", "Namespaced", %w[get list]),
        discovery_record("resource-list", "Cluster", %w[get list])
      ]
    }

    error = assert_raises(KubernetesCorpusImporter::ValidationError) do
      @importer.send(:validate_discovery_consistency!, discovery)
    end

    assert_match(/scope conflicts/, error.message)
  end

  def test_discovery_consistency_rejects_kind_contradiction
    first = discovery_record("aggregated", "Namespaced", %w[get list])
    second = discovery_record("resource-list", "Namespaced", %w[get list]).merge("kind" => "OtherExample")
    discovery = {records: [first, second]}

    error = assert_raises(KubernetesCorpusImporter::ValidationError) do
      @importer.send(:validate_discovery_consistency!, discovery)
    end

    assert_match(/kind conflicts/, error.message)
  end

  def test_discovery_consistency_rejects_verb_contradiction
    discovery = {
      records: [
        discovery_record("aggregated", "Namespaced", %w[get list]),
        discovery_record("resource-list", "Namespaced", %w[get watch])
      ]
    }

    error = assert_raises(KubernetesCorpusImporter::ValidationError) do
      @importer.send(:validate_discovery_consistency!, discovery)
    end

    assert_match(/verbs conflicts/, error.message)
  end

  def test_discovery_consistency_rejects_duplicate_resource_in_one_representation
    record = discovery_record("resource-list", "Namespaced", %w[get list])
    discovery = {records: [record, record.merge("document_id" => "discovery:other.json")]}

    error = assert_raises(KubernetesCorpusImporter::ValidationError) do
      @importer.send(:validate_discovery_consistency!, discovery)
    end

    assert_match(/duplicate resources/, error.message)
  end

  def test_served_gvr_coverage_rejects_an_unknown_protocol_only_kind
    discovery = {
      gvrs: {
        "example.k8s.io/v1/examples" => discovery_record("resource-list", "Namespaced", %w[get list]).merge(
          "kind" => "UnknownOptions"
        )
      }
    }

    error = assert_raises(KubernetesCorpusImporter::ValidationError) do
      @importer.send(:validate_served_gvr_openapi_coverage!, discovery, keys: [], duplicates: [])
    end

    assert_match(/missing from OpenAPI/, error.message)
  end

  private

  def protobuf_source(path, body)
    KubernetesCorpusImporter::FetchedSource.new(
      id: "protobuf:#{path}",
      upstream_path: "staging/src/#{path}",
      relative_path: "protobuf/#{path}",
      kind: "protobuf",
      canonical_bytes: ("syntax = \"proto2\";\n" + body).b
    )
  end

  def discovery_record(document, scope, verbs)
    {
      "group" => "example.k8s.io",
      "version" => "v1",
      "kind" => "Example",
      "resource" => "examples",
      "endpoint_group" => "example.k8s.io",
      "endpoint_version" => "v1",
      "scope" => scope,
      "verbs" => verbs,
      "document" => document,
      "document_id" => "discovery:#{document}.json"
    }
  end
end
