#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m3_probe_support"
require_relative "m3_gate"

M3ProbeSupport.run_report(kind: "m3_controller_registry", adapter_name: "controller-registry-probe") do |_input, errors|
  controller_module = M3ProbeSupport.constant("Rubernetes::Controller")
  registry_class = M3ProbeSupport.constant("Rubernetes::Controller::ControllerRegistry") ||
                   M3ProbeSupport.constant("Rubernetes::Controller::Registry")
  registry = controller_module.respond_to?(:default_registry) ? controller_module.default_registry : nil
  unless registry || registry_class.is_a?(Class)
    errors << "production controller registry is unavailable"
    next {"measurement_source" => "missing_production_module", "required_controller_names" => [], "registered_controller_names" => [],
          "controllers" => []}
  end

  registry ||= registry_class.new
  corpus = M3ProbeSupport.constant("Rubernetes::Controller::BuiltinControllerCorpus")
  expected = M3Gate::REQUIRED_CONTROLLER_NAMES.sort
  corpus_names = corpus && corpus.respond_to?(:names) ? Array(corpus.names).map(&:to_s).sort : []
  errors << "production controller corpus does not match pinned Kubernetes v1.36.2 corpus" unless corpus_names == expected
  startup_error = nil
  begin
    registry.startup_validate!
  rescue StandardError => error
    startup_error = error
    errors << "production registry startup_validate! failed: #{error.class}: #{error.message}"
  end
  registered = if registry.respond_to?(:names)
                 Array(registry.names).map(&:to_s).sort
               elsif registry.respond_to?(:definitions)
                 Array(registry.definitions).map { |definition| definition.respond_to?(:name) ? definition.name.to_s : nil }.compact.sort
               else
                 []
               end
  errors << "production registry does not expose every built-in controller" unless registered == expected
  entries = expected.map do |name|
    definition = registry.respond_to?(:fetch) ? registry.fetch(name) : registry[name]
    corpus_entry = corpus.fetch(name)
    implementation = definition.respond_to?(:implementation) ? definition.implementation : nil
    implementation_present = !implementation.nil?
    implementation_name = implementation.respond_to?(:name) ? implementation.name.to_s : implementation.class.name.to_s
    uses_corpus_controller = (definition.respond_to?(:corpus_fallback?) && definition.corpus_fallback?) ||
                             implementation_name.end_with?("::CorpusController") || implementation_name == "Rubernetes::Controller::CorpusController"
    errors << "controller #{name} has no concrete implementation" unless implementation_present
    errors << "controller #{name} uses CorpusController fallback" if uses_corpus_controller
    owns = definition.respond_to?(:owns)
    reconcile = definition.respond_to?(:reconcile_block) && !definition.reconcile_block.nil?
    validation_error = nil
    begin
      definition.validate!(corpus_entry: corpus_entry) if definition.respond_to?(:validate!)
    rescue StandardError => error
      validation_error = "#{error.class}: #{error.message}"
    end
    errors << "controller #{name} failed production validation: #{validation_error}" if validation_error
    binding = M3Gate.controller_registry_binding(definition, corpus_entry)
    binding_valid = binding["authoritative_corpus"]["name"] == name &&
                    binding["authoritative_corpus"]["descriptor"] == binding["registered_definition"]["descriptor"] &&
                    binding["registered_definition"]["reconcile_declared"] == reconcile
    errors << "controller #{name} registry binding does not match the authoritative corpus" unless binding_valid
    {
      "id" => name,
      "name" => name,
      "owns_declared" => owns,
      "reconcile_declared" => reconcile,
      "implementation_class" => implementation_name,
      "implementation_present" => implementation_present,
      "uses_corpus_controller" => uses_corpus_controller,
      "authoritative_descriptor" => binding.dig("authoritative_corpus", "descriptor"),
      "authoritative_gvk" => binding.dig("authoritative_corpus", "gvk"),
      "authoritative_gvr" => binding.dig("authoritative_corpus", "gvr"),
      "ownership_edges" => binding["ownership_edges"],
      "watch_wiring" => binding["watch_wiring"],
      "metadata_digest" => binding["metadata_digest"],
      "binding_digest" => binding["binding_digest"],
      "binding" => binding,
      "measurement_source" => "production_module",
      "attempt_count" => 1,
      "passed" => implementation_present && owns && reconcile && validation_error.nil? && binding_valid
    }
  rescue StandardError => error
    errors << "controller #{name} could not be measured: #{error.class}: #{error.message}"
    {"id" => name, "name" => name, "owns_declared" => false, "reconcile_declared" => false,
     "implementation_class" => "", "uses_corpus_controller" => false,
     "implementation_present" => false,
     "measurement_source" => "production_module", "attempt_count" => 1, "passed" => false}
  end
  duplicate_count = 0
  duplicate_exception_class = nil
  duplicate_check_passed = false
  begin
    registry.register(registry.fetch(expected.first))
  rescue Rubernetes::Controller::DuplicateControllerError => error
    duplicate_count = 0
    duplicate_exception_class = error.class.name
    duplicate_check_passed = true
  rescue StandardError => error
    duplicate_exception_class = error.class.name
    errors << "production registry duplicate check raised unexpected #{error.class}: #{error.message}"
  else
    duplicate_count = 1
    errors << "production registry accepted a duplicate controller"
  end
  missing = expected - registered
  unexpected = registered - expected
  binding_failure_count = entries.count { |entry| entry["passed"] != true }
  {
    "measurement_source" => "production_module",
    "required_controller_names" => expected,
    "registered_controller_names" => registered,
    "expected_count" => expected.length,
    "registered_count" => registered.length,
    "controllers" => entries,
    "startup_validation" => {
      "attempt_count" => 1,
      "passed" => startup_error.nil?,
      "exception_class" => startup_error&.class&.name,
      "error" => startup_error&.message
    },
    "duplicate_count" => duplicate_count,
    "duplicate_exception_class" => duplicate_exception_class,
    "duplicate_check_passed" => duplicate_check_passed,
    "missing_count" => missing.length,
    "unregistered_count" => missing.length,
    "unexpected_count" => unexpected.length,
    "binding_failure_count" => binding_failure_count
  }
end
