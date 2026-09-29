# frozen_string_literal: true

require_relative "schema/definition"
require_relative "schema/registry"
require_relative "schema/value_object"
require_relative "schema/validator"
require_relative "schema/kubernetes_validator"
require_relative "schema/defaulting"
require_relative "schema/diff"
require_relative "schema/catalog"

module Rubernetes
  # Public schema compiler/runtime primitives.
  module Schema
    class << self
      def registry
        @registry ||= Registry.new
      end

      def register(definition = nil, **keywords)
        registry.register(definition, **keywords)
      end

      def define(name = nil, **keywords)
        Definition.new(name, **keywords)
      end

      def gvk(group = "", version = nil, kind = nil, **keywords)
        GVK.new(group, version, kind, **keywords)
      end

      def gvr(group = "", version = nil, resource = nil, **keywords)
        GVR.new(group, version, resource, **keywords)
      end
    end
  end
end
