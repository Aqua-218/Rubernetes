# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Container
      class Error < StandardError; end
      class DuplicateRegistration < Error; end
      class MissingDependency < Error; end
      class DependencyCycle < Error; end

      def initialize
        @factories = {}
        @instances = {}
        @resolving = []
        @sealed = false
      end

      def register(name, value = nil, &factory)
        key = name.to_sym
        raise Error, "container is sealed" if @sealed
        raise DuplicateRegistration, "dependency already registered: #{key}" if @factories.key?(key)
        raise ArgumentError, "provide a value or a factory, not both" if factory && !value.nil?

        @factories[key] = factory || ->(_container) { value }
        self
      end

      def seal!
        @sealed = true
        self
      end

      def resolve(name)
        key = name.to_sym
        return @instances.fetch(key) if @instances.key?(key)
        raise MissingDependency, "dependency is not registered: #{key}" unless @factories.key?(key)
        raise DependencyCycle, "dependency cycle: #{(@resolving + [key]).join(" -> ")}" if @resolving.include?(key)

        @resolving << key
        @instances[key] = @factories.fetch(key).call(self)
      ensure
        @resolving.pop if @resolving.last == key
      end
    end
  end
end
