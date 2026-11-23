# frozen_string_literal: true

require_relative "builtin_controller_corpus"
require_relative "ownership"

module Rubernetes
  module Controller
    class ControllerRegistry
      include Enumerable

      attr_reader :schema_registry, :ownership_index, :corpus

      def initialize(schema_registry: nil, corpus: BuiltinControllerCorpus, require_corpus: true)
        @schema_registry = schema_registry
        @corpus = corpus
        @require_corpus = !!require_corpus
        @definitions = {}
        @ownership_index = OwnerReferenceIndex.new
        @mutex = Mutex.new
        @sealed = false
      end

      def register(definition, incomplete_reasons: [])
        raise ArgumentError, "controller definition is required" unless definition.is_a?(ControllerDefinition)

        reasons = Array(incomplete_reasons).map(&:to_s).reject(&:empty?).uniq
        definition = definition.with_incomplete_reasons(reasons) if reasons.any?
        @mutex.synchronize do
          raise RegistrySealedError, "controller registry is sealed" if @sealed
          raise DuplicateControllerError, "controller #{definition.name.inspect} is already registered" if @definitions.key?(definition.name)

          validate_definition!(definition)
          @definitions[definition.name] = definition
          definition.owns.each do |edge|
            @ownership_index.register(edge.owner, edge.dependent,
                                      controller: edge.controller,
                                      block_owner_deletion: edge.block_owner_deletion)
          end
        end
        definition
      end

      alias add register

      def register_many(definitions)
        Array(definitions).each { |definition| register(definition) }
        self
      end

      def fetch(name)
        find(name) || raise(UnknownControllerError, "controller #{name.inspect} is not registered")
      end

      def [](name)
        find(name)
      end

      def find(name)
        key = name.to_s
        @mutex.synchronize { @definitions[key] }
      end

      def definitions
        @mutex.synchronize { @definitions.values.sort_by(&:name).freeze }
      end

      alias all definitions

      def each(&block)
        return enum_for(__method__) unless block

        definitions.each(&block)
      end

      def names
        @mutex.synchronize { @definitions.keys.sort.freeze }
      end

      # Names in the pinned corpus that are not represented by a concrete
      # registered implementation.  Keeping this explicit lets startup and
      # callers report the exact fail-closed boundary instead of treating a
      # generic status observer as a completed controller.
      def missing_names
        @corpus.names.reject { |name| find(name) }.freeze
      end

      def unimplemented_names
        definitions.filter_map { |definition| definition.name unless definition.implemented? }.freeze
      end

      def incomplete_names
        definitions.filter_map { |definition| definition.name if definition.incomplete? }.freeze
      end

      def incomplete_controllers
        definitions.filter_map do |definition|
          next if definition.complete?

          [definition.name, definition.completeness_reasons]
        end.to_h.freeze
      end

      def registered_complete_count
        definitions.count(&:complete?)
      end

      def size
        @mutex.synchronize { @definitions.size }
      end

      alias length size

      def sealed?
        @sealed
      end

      def seal!
        startup_validate!
        @mutex.synchronize { @sealed = true }
        self
      end

      def startup_validate!
        missing = missing_names
        unimplemented = @require_corpus ? unimplemented_names : []
        incomplete = @require_corpus ? incomplete_controllers : {}
        unless (missing.empty? && unimplemented.empty? && incomplete.empty?) || !@require_corpus
          details = []
          details << "missing: #{missing.join(", ")}" unless missing.empty?
          details << "without concrete implementation: #{unimplemented.join(", ")}" unless unimplemented.empty?
          unless incomplete.empty?
            detail = incomplete.map { |name, reasons| "#{name} [#{reasons.join(", ")}]" }.join("; ")
            details << "incomplete: #{detail}"
          end
          raise MissingControllerError, "built-in controller corpus #{@corpus::VERSION} is not ready (#{details.join("; ")})"
        end
        definitions.each { |definition| validate_definition!(definition) }
        validate_ownership_cycles!
        self
      end

      def requires_corpus?
        @require_corpus
      end

      def entry(name)
        @corpus.fetch(name)
      end

      def resource_registered?(descriptor)
        return true if ResourceDescriptor::KNOWN.any? do |_kind, values|
          values[0] == descriptor.group && values[1] == descriptor.version &&
          values[2] == descriptor.resource && values[3] == descriptor.scope
        end

        if @corpus.respond_to?(:descriptors_for)
          return true if @corpus.descriptors_for(descriptor.kind).any? do |expected|
            expected.gvk == descriptor.gvk && expected.gvr == descriptor.gvr && expected.scope == descriptor.scope
          end
        elsif @corpus.entries.any? do |entry|
          expected = ResourceDescriptor.parse(entry.kind)
          expected.group == descriptor.group && expected.version == descriptor.version && expected.kind == descriptor.kind
        end
          return true
        end
        return false unless schema_registry

        if schema_registry.respond_to?(:find_gvk)
          !!schema_registry.find_gvk(group: descriptor.group, version: descriptor.version, kind: descriptor.kind)
        elsif schema_registry.respond_to?(:fetch_gvk)
          schema_registry.fetch_gvk(descriptor.identifier)
          true
        else
          false
        end
      rescue StandardError
        false
      end

      def validate_descriptor!(descriptor)
        raise UnknownGVKError, "unknown or unregistered GVK #{descriptor.identifier}" unless resource_registered?(descriptor)

        descriptor
      end

      private

      def validate_definition!(definition)
        corpus_entry = @require_corpus ? @corpus.fetch(definition.name) : nil
        definition.validate!(corpus_entry: corpus_entry)
        if @require_corpus && corpus_entry && corpus_entry.descriptor != definition.kind
          raise ValidationError,
                "controller #{definition.name.inspect} is registered for #{definition.kind.identifier}, expected #{corpus_entry.descriptor.identifier}"
        end
        validate_descriptor!(definition.kind)
        definition.owns.each do |edge|
          validate_descriptor!(edge.owner)
          validate_descriptor!(edge.dependent)
          validate_scope_edge!(edge.owner, edge.dependent)
        end
        definition.watches.each do |watch|
          validate_descriptor!(watch.resource)
          expected_scope = watch.scope || watch.resource.scope
          unless expected_scope == watch.resource.scope
            raise ScopeMismatchError, "watch scope #{expected_scope.inspect} conflicts with #{watch.resource.identifier}"
          end
          raise InvalidWatchError, "unsupported watch relationship #{watch.via.inspect}" unless %i[owner_reference label selector all].include?(watch.via)
        end
        raise MissingReconcileError, "controller #{definition.name} has no reconcile block" unless definition.reconcile_block
      end

      def validate_scope_edge!(owner, dependent)
        return true if owner.cluster_scoped? && dependent.cluster_scoped?
        if owner.namespaced? && dependent.cluster_scoped?
          raise ScopeMismatchError, "namespaced owner #{owner.identifier} cannot own cluster-scoped #{dependent.identifier}"
        end

        true
      end

      def validate_ownership_cycles!
        graph = Hash.new { |hash, key| hash[key] = [] }
        definitions.each do |definition|
          definition.owns.each { |edge| graph[edge.owner.identifier] << edge.dependent.identifier }
        end
        visiting = {}
        visited = {}
        walk = lambda do |node|
          return false if visited[node]
          raise OwnershipCycleError, "ownership declaration contains a cycle at #{node}" if visiting[node]

          visiting[node] = true
          graph[node].each { |child| walk.call(child) }
          visiting.delete(node)
          visited[node] = true
          false
        end
        graph.keys.each { |node| walk.call(node) }
        true
      end
    end
  end
end
