#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require_relative "lean_oracle"
require_relative "../schema/field_parity"

module SchemaFieldsOracle
  ROOT = File.expand_path("../..", __dir__)
  SOURCE = File.join(ROOT, "verification/lean/SchemaFields.lean")
  SWAGGER = File.join(ROOT, "schema/kubernetes/v1.36.2/openapi/swagger.json")
  FIELD_SETS = File.join(ROOT, "generated/fixtures/field-sets.json")
  SURFACES = %w[ruby rbs codec openapi patch].freeze

  module_function

  def run(lean: LeanOracle.executable)
    artifacts = RubernetesFieldParity::Verifier.new(root: ROOT).verify
    definitions = JSON.parse(File.read(SWAGGER), max_nesting: 512).fetch("definitions")
    field_sets = JSON.parse(File.read(FIELD_SETS))
    cases = definitions.map do |name, schema|
      {"schema" => name, "fields" => schema.fetch("properties", {}).keys, "surfaces" => field_sets.fetch(name).slice(*SURFACES)}
    end
    positive_count = cases.length
    cases.concat(mutations(cases.find { |input| input.fetch("fields").length > 2 }))
    reference = LeanOracle.run(SOURCE, cases, lean: lean)

    mismatches = cases.each_with_index.filter_map do |input, index|
      expected = index < positive_count
      actual = reference.fetch(index)
      {"schema" => input.fetch("schema"), "expected" => expected, "lean" => actual} unless actual == expected
    end
    {"passed" => artifacts.fetch("passed") && mismatches.empty?, "cases" => cases.length,
     "source_sha256" => Digest::SHA256.file(SOURCE).hexdigest, "artifact_checks" => artifacts.fetch("counts"),
     "artifact_issues" => artifacts.fetch("issues"), "mismatches" => mismatches}
  end

  def mutations(input)
    SURFACES.flat_map do |surface|
      original = input.fetch("surfaces").fetch(surface)
      [original.drop(1), original + ["__formal_oracle_extra_field__"]].map.with_index do |altered, index|
        input.merge("schema" => "#{input.fetch("schema")}:#{surface}:mutation-#{index}",
                    "surfaces" => input.fetch("surfaces").merge(surface => altered))
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  report = SchemaFieldsOracle.run
  puts JSON.pretty_generate(report)
  exit(report.fetch("passed") ? 0 : 1)
end
