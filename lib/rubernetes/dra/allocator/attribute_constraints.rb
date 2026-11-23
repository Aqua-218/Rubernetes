# frozen_string_literal: true

module Rubernetes
  module DRA
    module Allocator
      module_function

      # matchAttributeConstraint.
      class MatchAttributeConstraint
        def initialize(requests, attribute)
          @requests = Array(requests).to_set
          @attribute_name = attribute
          @attribute = nil
          @count = 0
        end

        def add(request_name, sub_request_name, device, device_id)
          return true if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          attribute = Allocator.lookup_attribute(device, device_id, @attribute_name)
          return false if attribute.nil?

          if @count.zero?
            @attribute = attribute
            @count = 1
            return true
          end
          type = Allocator.attribute_type(attribute)
          return false if type.nil?
          return false unless @attribute.key?(type) && @attribute[type] == attribute[type]

          @count += 1
          true
        end

        def remove(request_name, sub_request_name, _device, _device_id)
          return if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          @count -= 1
        end
      end

      # distinctAttributeConstraint.
      class DistinctAttributeConstraint
        def initialize(requests, attribute)
          @requests = Array(requests).to_set
          @attribute_name = attribute
          @attributes = {}
          @count = 0
        end

        def add(request_name, sub_request_name, device, device_id)
          return true if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          attribute = Allocator.lookup_attribute(device, device_id, @attribute_name)
          return false if attribute.nil?

          if @count.zero?
            @attributes[request_name] = attribute
            @count = 1
            return true
          end
          return false unless distinct?(attribute)

          @attributes[request_name] = attribute
          @count += 1
          true
        end

        def remove(request_name, sub_request_name, _device, _device_id)
          return if !@requests.empty? && !Allocator.constraint_applies?(@requests, request_name, sub_request_name)

          @attributes.delete(request_name)
          @count -= 1
        end

        private

        def distinct?(attribute)
          type = Allocator.attribute_type(attribute)
          @attributes.each_value do |existing|
            return false if type.nil?
            return false if existing.key?(type) && existing[type] == attribute[type]
          end
          true
        end
      end

      def constraint_applies?(requests, request_name, sub_request_name)
        return requests.include?(request_name) if sub_request_name.to_s.empty?

        requests.include?(request_name) || requests.include?("#{request_name}/#{sub_request_name}")
      end

      # Treat scalars as singleton sets. Match requires a value common to every
      # device, while distinct requires disjoint sets for every pair of devices.
      class ListAttributeConstraint
        TYPES = {"ints" => "int", "bools" => "bool", "strings" => "string", "versions" => "version"}.freeze

        def initialize(requests, attribute, distinct:)
          @requests = Array(requests).to_set
          @attribute_name = attribute
          @distinct = distinct
          @values = []
        end

        def add(request_name, sub_request_name, device, device_id)
          return true unless applies?(request_name, sub_request_name)

          attribute = Allocator.lookup_attribute(device, device_id, @attribute_name)
          return false unless attribute

          values = value_set(attribute)
          return false if values.empty?

          previous = @values.last
          if previous && @distinct
            return false if previous.intersect?(values)

            values = previous | values
          elsif previous
            values = previous & values
            return false if values.empty?
          end
          @values << values
          true
        end

        def remove(request_name, sub_request_name, _device, _device_id)
          @values.pop if applies?(request_name, sub_request_name)
        end

        private

        def applies?(request_name, sub_request_name)
          @requests.empty? || Allocator.constraint_applies?(@requests, request_name, sub_request_name)
        end

        def value_set(attribute)
          TYPES.each do |list_type, type|
            values = Array(attribute[list_type])
            return values.to_set { |value| [type, value] } unless values.empty?
          end

          type = Allocator.attribute_type(attribute)
          type ? Set[[type, attribute.fetch(type)]] : Set.new
        end
      end

      # The one value field of an attribute (string / int / bool / version).
      def attribute_type(attribute)
        %w[string int bool version].find { |type| attribute.key?(type) && !attribute[type].nil? }
      end

      # lookupAttribute: the fully qualified name, or the bare name when the
      # domain is the device's driver.
      def lookup_attribute(device, device_id, name)
        attributes = device["attributes"] || {}
        return attributes[name] if attributes.key?(name)

        index = name.index("/")
        return nil if index.nil? || name[0...index] != device_id.driver

        attributes[name[(index + 1)..]]
      end
    end
  end
end
