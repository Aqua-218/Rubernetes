# frozen_string_literal: true

require "json"

require_relative "framework"

module Rubernetes
  module Security
    module Admission
      # Plugin registry mirroring pkg/kubeapiserver/options/plugins.go: the
      # ordered plugin list and the default-on set come from the pinned
      # corpus (schema/kubernetes/v1.36.2-defaults/admission-plugins.json) so the
      # chain composition is a checked fact, not a hand-maintained list.
      module Registry
        CORPUS = File.expand_path("../../../../schema/kubernetes/v1.36.2-defaults/admission-plugins.json", __dir__)

        @factories = {}

        class << self
          def register(name, &factory)
            @factories[name] = factory
          end

          attr_reader :factories

          def corpus
            @corpus ||= JSON.parse(File.read(CORPUS))
          end

          def ordered_names
            corpus.fetch("ordered_plugins")
          end

          def default_on(feature_gates: {})
            names = corpus.fetch("default_on").dup
            corpus.fetch("default_on_when_gate_enabled", []).each do |entry|
              names << entry["plugin"] if feature_gates[entry["feature_gate"]] == true
            end
            names
          end

          # Every plugin named by the corpus must have a factory; a missing
          # implementation is a configuration error, never a silent skip.
          def missing_implementations
            ordered_names.reject { |name| @factories.key?(name) }
          end

          def default_chain(context:, enable: [], disable: [], config: {}, feature_gates: {})
            missing = missing_implementations
            raise ConfigurationError, "admission plugins without implementation: #{missing.join(", ")}" unless missing.empty?

            unknown = (enable + disable) - ordered_names
            raise ConfigurationError, "unknown admission plugins: #{unknown.join(", ")}" unless unknown.empty?

            enabled = (default_on(feature_gates: feature_gates) + enable) - disable
            plugins = ordered_names.select { |name| enabled.include?(name) }.map do |name|
              @factories.fetch(name).call(context, config[name] || {})
            end
            Chain.new(plugins: plugins)
          end
        end
      end
    end
  end
end
