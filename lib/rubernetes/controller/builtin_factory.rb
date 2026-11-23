# frozen_string_literal: true

require_relative "builtin_controller_corpus"

module Rubernetes
  module Controller
    module BuiltinFactory
      def entries
        names.map { |name| BuiltinControllerCorpus.fetch(name) || raise(ValidationError, "missing pinned corpus entry #{name.inspect}") }
      end

      def register!(registry, **)
        definitions(registry: registry, **).each { |definition| registry.register(definition) }
        registry
      end

      def usable_descriptor(descriptor, registry)
        registry&.validate_descriptor!(descriptor)
        descriptor
      rescue UnknownGVKError
        ResourceDescriptor.parse(descriptor.kind)
      end
    end
  end
end
