# frozen_string_literal: true

require "digest"
require_relative "k5_differential"

module Conformance
  # Verifies a differential report against the case definitions and encoding
  # used by its producer. Callers tie it to their command and artifact receipts.
  module K5Evidence
    FIXTURE = /\Ak5-[0-9a-f]{16}\z/
    class Invalid < StandardError; end

    module_function

    def verify(report, cbor_enabled:)
      expected = K5Differential.observables(cbor_enabled: cbor_enabled)
      entries = report.fetch("cases")
      unless report.values_at("schema_version", "kind", "observables", "matching", "differences") ==
             [1, "k5_api_wire_differential", expected.length, expected.length, []] && entries.is_a?(Array) && entries.all?(Hash) &&
             entries.map { |entry| entry["id"] } == expected.map { |observable| observable.fetch("id") }
        raise Invalid, "K5 report does not contain the complete current observable inventory in order"
      end

      fixture = report.fetch("fixture")
      attestation = report.fetch("attestation")
      verify_attestation!(fixture, attestation)
      entries.zip(expected).each do |entry, observable|
        verify_case!(entry, observable, fixture)
      end
      {"passed" => true, "observables" => entries.length, "matching" => entries.length, "fixture" => fixture, "attestation" => attestation}
    rescue Invalid, KeyError, TypeError, NoMethodError, Rubernetes::Schema::Codec::Error => error
      {"passed" => false, "detail" => error.is_a?(Invalid) ? error.message : "K5 report is missing or malformed"}
    end

    def verify_attestation!(fixture, attestation)
      target, oracle = attestation.values_at("target_default_namespace_uid", "oracle_default_namespace_uid")
      return if FIXTURE.match?(fixture.to_s) && attestation["oracle_commit"] == Lock.source_commit &&
                [target, oracle].all? { |uid| uid.is_a?(String) && !uid.empty? } && target != oracle

      raise Invalid, "K5 report does not attest a fixture on distinct target and pinned oracle clusters"
    end

    def verify_case!(entry, observable, fixture)
      left, right = entry.values_at("rubernetes", "kubernetes")
      id = observable.fetch("id")
      unless entry.values_at("matches", "expected_responses") == [true, true] && left.is_a?(Hash) && left == right && expected_response?(left, observable)
        raise Invalid, "K5 observable #{id} did not record matching expected responses"
      end

      %w[rubernetes kubernetes].each do |side|
        digest = Digest::SHA256.hexdigest(Rubernetes::Schema::Codec.canonical_json(entry.fetch(side)))
        raise Invalid, "K5 observable #{id} has an invalid normalized response digest" unless entry["#{side}_sha256"] == digest
      end
      return unless %w[create_configmap get_configmap].include?(id) && left.dig("body", "metadata", "name") != fixture

      raise Invalid, "K5 observable #{id} did not read the recorded fixture"
    end

    def expected_response?(response, observable)
      pattern = observable["expected_error"]
      error = response["error"]
      return false unless response.key?("body") && error.is_a?(Array) && error.all?(String)
      return false unless response["exit_status"] == (pattern ? 1 : 0)
      return false if pattern && !pattern.match?(error.join("\n"))

      %w[http_status content_type].all? { |key| !observable.key?(key) || response[key] == observable[key] }
    end
  end
end
