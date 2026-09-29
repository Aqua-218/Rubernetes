#!/usr/bin/env ruby
# frozen_string_literal: true

# Validate the pinned corpus coverage against the runtime schema catalog.

require_relative "m1_probe_support"

def coverage_document(expected, registered)
  duplicates = registered.length - registered.uniq.length
  missing = expected - registered
  unexpected = registered.uniq - expected
  {
    "expected_count" => expected.length,
    "registered_count" => registered.length,
    "expected_items" => expected,
    "registered_items" => registered,
    "duplicate_count" => duplicates,
    "missing_count" => missing.length,
    "unexpected_count" => unexpected.length,
    "missing_items" => missing,
    "unexpected_items" => unexpected
  }
end

M1ProbeSupport.run_probe("m1_corpus_coverage") do |_current, input|
  corpus_path = File.join(ROOT, "schema/kubernetes/v1.36.2/sources.json")
  sources = M1ProbeSupport.parse_json(corpus_path, label: "canonical corpus manifest")
  openapi_path = File.join(ROOT, "schema/kubernetes/v1.36.2/openapi/swagger.json")
  openapi = M1ProbeSupport.parse_json(openapi_path, label: "canonical OpenAPI document")
  registry_path = File.join(ROOT, "generated/schema/registry.json")
  registry = M1ProbeSupport.parse_json(registry_path, label: "generated schema registry")

  coverage = sources.fetch("coverage")
  openapi_gvks = openapi.fetch("definitions").values.flat_map do |definition|
    Array(definition["x-kubernetes-group-version-kind"]).map do |gvk|
      M1ProbeSupport.identifier(gvk.fetch("group", ""), gvk.fetch("version"), gvk.fetch("kind"))
    end
  end.uniq.sort
  discovery_gvks = Array(coverage.fetch("covered_gvks")).map(&:to_s)
  expected_gvks = (openapi_gvks + discovery_gvks).uniq.sort
  expected_gvrs = Array(coverage.fetch("covered_gvrs")).map(&:to_s).sort
  raise M1ProbeSupport::ProbeError, "canonical corpus GVK coverage is empty" if expected_gvks.empty?
  raise M1ProbeSupport::ProbeError, "canonical corpus GVR coverage is empty" if expected_gvrs.empty?
  raise M1ProbeSupport::ProbeError, "canonical corpus GVR coverage contains duplicates" unless expected_gvrs.uniq.length == expected_gvrs.length

  _server, _store, runtime_registry = M1ProbeSupport.build_api_server
  registered_gvrs = Array(runtime_registry.fetch("gvrs")).map { |entry| entry.fetch("identifier") }.sort
  registered_gvks = runtime_registry.fetch("gvks").map do |gvk|
    gvk["identifier"] ||
      M1ProbeSupport.identifier(gvk.fetch("group", ""), gvk.fetch("version"), gvk.fetch("kind"))
  end.sort
  errors = []
  errors << "canonical OpenAPI GVK count must equal 311 (got #{openapi_gvks.length})" unless openapi_gvks.length == 311
  errors << "canonical GVK union count must equal 321 (got #{expected_gvks.length})" unless expected_gvks.length == 321
  errors << "canonical GVR count must equal 153 (got #{expected_gvrs.length})" unless expected_gvrs.length == 153
  if discovery_gvks.uniq.length != discovery_gvks.length
    errors << "canonical discovery GVK coverage contains duplicates"
  end
  if registered_gvks.empty?
    errors << "generated registry has no top-level GVK inventory"
  end
  if registered_gvrs.empty?
    errors << "generated registry has no GVR inventory"
  end

  type_backed_gvks = runtime_registry.fetch("types").flat_map do |type|
    Array(type.fetch("gvks")).map do |gvk|
      M1ProbeSupport.identifier(gvk.fetch("group", ""), gvk.fetch("version"), gvk.fetch("kind"))
    end
  end.uniq.sort

  gvk_coverage = coverage_document(expected_gvks, registered_gvks)
  gvr_coverage = coverage_document(expected_gvrs, registered_gvrs)
  failures = [gvk_coverage, gvr_coverage].sum do |entry|
    entry.fetch("missing_count") + entry.fetch("unexpected_count") + entry.fetch("duplicate_count")
  end
  failures += errors.length
  {
    "gvk" => gvk_coverage,
    "gvr" => gvr_coverage,
    "openapi_gvk_count" => openapi_gvks.length,
    "discovery_gvk_count" => discovery_gvks.uniq.length,
    "type_backed_gvk_count" => type_backed_gvks.length,
    "registry_gvk_count" => registered_gvks.length,
    "registry_type_count" => Array(registry["types"]).length,
    "registry_resource_count" => Array(registry["resources"]).length,
    "registry_gvr_count" => Array(registry["gvrs"]).length,
    "corpus_source_count" => sources.fetch("source_count"),
    "errors" => errors,
    "failure_count" => failures,
    "passed" => failures.zero? && input.fetch("stable")
  }
end
