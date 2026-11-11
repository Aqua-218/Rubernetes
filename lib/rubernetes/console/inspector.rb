# frozen_string_literal: true

module Rubernetes
  module Console
    # How a value is shown at the console.  A component's objects hold the
    # whole cluster between them: Ruby's own #inspect of a scheduler prints
    # megabytes.  Data is shown as data, cut where it gets long; an object is
    # shown as its class and the names of what it holds, to be looked into
    # one step at a time.
    module Inspector
      ITEMS = 20
      TEXT = 400
      DEPTH = 3

      module_function

      def render(value, depth = DEPTH)
        case value
        when nil, true, false, Numeric, Symbol, Range, Module, Time then value.inspect
        when String then value.length > TEXT ? "#{value[0, TEXT].inspect}... (#{value.length} characters)" : value.inspect
        when Array then depth.zero? ? "[#{value.length} items]" : "[#{items(value, depth)}]"
        when Hash then depth.zero? ? "{#{value.length} entries}" : "{#{items(value.map { |key, item| Pair.new(key, item) }, depth)}}"
        when Struct, Data then "#<#{value.class.name} #{items(value.to_h.map { |key, item| Pair.new(key, item) }, depth)}>"
        when Exception then "#<#{value.class}: #{value.message}>"
        else object(value)
        end
      end

      # A hash entry on its way to being rendered.
      Pair = Struct.new(:key, :value)

      def items(values, depth)
        shown = values.first(ITEMS).map do |item|
          item.is_a?(Pair) ? "#{render(item.key, 0)} => #{render(item.value, depth - 1)}" : render(item, depth - 1)
        end
        shown << "... (#{values.length - ITEMS} more)" if values.length > ITEMS
        shown.join(", ")
      end

      # A short name for a value in a list or a trace line: a Kubernetes
      # object by kind and name, anything else by class.
      def summary(value)
        case value
        when nil, true, false, Numeric, Symbol then value.inspect
        when String then value.length > 60 ? "#{value[0, 60].inspect}..." : value.inspect
        when Array then "[#{value.length} items]"
        when Hash then value.key?("metadata") ? named(value["kind"] || "object", value["metadata"]) : "{#{value.length} entries}"
        when Module then value.inspect
        else
          return named(value.class.name, value) if value.respond_to?(:name)

          value.respond_to?(:status) ? "#<#{value.class.name} #{value.status}>" : "#<#{value.class.name}>"
        end
      end

      def named(kind, source)
        namespace, name = if source.is_a?(Hash)
                            source.values_at("namespace", "name")
                          else
                            [(source.namespace if source.respond_to?(:namespace)), source.name]
                          end
        "#<#{kind} #{[namespace, name].compact.reject { |part| part.to_s.empty? }.join("/")}>"
      end

      def object(value)
        names = value.instance_variables
        return "#<#{value.class.name}>" if names.empty?

        "#<#{value.class.name} #{names.first(ITEMS).join(" ")}#{" ..." if names.length > ITEMS}>"
      end
    end
  end
end
