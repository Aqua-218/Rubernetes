# frozen_string_literal: true

require "json"
require_relative "value"

module Rubernetes
  module API
    module ManagedFields
      # sigs.k8s.io/structured-merge-diff/v6/fieldpath: path elements, field
      # sets and their FieldsV1 serialization.
      module FieldPath
        class DecodeError < StandardError; end

        # One step of a path: a struct field or map key (f:), the key fields
        # of an associative-list item (k:), the value of a set item (v:) or
        # a list index (i:).  Ordered as PathElement.Compare orders them.
        class PathElement
          FIELD = 0
          KEY = 1
          VALUE = 2
          INDEX = 3

          attr_reader :kind, :data, :hash

          def self.field(name) = new(FIELD, name.to_s.dup.freeze)
          def self.value(value) = new(VALUE, canonical(value))
          def self.index(index) = new(INDEX, Integer(index))

          # +pairs+: [name, value] in any order; sorted by name like
          # FieldList.Sort.
          def self.key(pairs)
            sorted = pairs.map { |name, value| [name.to_s.dup.freeze, canonical(value)].freeze }
              .each_with_index.sort_by { |(name, _), index| [name, index] }.map(&:first)
            new(KEY, sorted.freeze)
          end

          def self.canonical(value)
            case value
            when Hash then value.each_with_object({}) { |(key, item), out| out[key.to_s] = canonical(item) }.freeze
            when Array then value.map { |item| canonical(item) }.freeze
            when String then value.frozen? ? value : value.dup.freeze
            else Value.normalize(value)
            end
          end

          def initialize(kind, data)
            @kind = kind
            @data = data
            @hash = [kind, data].hash
            freeze
          end

          def field? = @kind == FIELD
          def key? = @kind == KEY
          def value? = @kind == VALUE
          def index? = @kind == INDEX
          def field_name = field? ? @data : nil

          def <=>(other)
            return @kind <=> other.kind unless @kind == other.kind

            case @kind
            when FIELD, INDEX then @data <=> other.data
            when VALUE then Value.compare(@data, other.data)
            else compare_keys(@data, other.data)
            end
          end

          def eql?(other) = other.is_a?(PathElement) && other.kind == @kind && other.data.eql?(@data)
          alias == eql?

          # PathElement.String.
          def to_s
            case @kind
            when FIELD then ".#{@data}"
            when KEY then "[#{@data.map { |name, value| "#{name}=#{Value.to_string(value)}" }.join(",")}]"
            when VALUE then "[=#{Value.to_string(@data)}]"
            else "[#{@data}]"
            end
          end
          alias inspect to_s

          # SerializePathElement.
          def serialize
            case @kind
            when FIELD then "f:#{@data}"
            when KEY then "k:{#{@data.map { |name, value| "#{Value.json_string(name)}:#{Value.to_json(value)}" }.join(",")}}"
            when VALUE then "v:#{Value.to_json(@data)}"
            else "i:#{@data}"
            end
          end

          # DeserializePathElement; nil for an unknown element type (skipped
          # like ErrUnknownPathElementType).
          def self.deserialize(text)
            raise DecodeError, "key must be 2 characters long:" if text.length < 2
            raise DecodeError, "missing colon: #{text}" unless text[1] == ":"

            rest = text[2..]
            case text[0]
            when "f" then field(rest)
            when "v" then value(parse_json(rest))
            when "k"
              object = parse_json(rest)
              raise DecodeError, "key must be an object: #{text}" unless object.is_a?(Hash)

              key(object.to_a)
            when "i"
              raise DecodeError, "invalid index: #{text}" unless rest.match?(/\A[+-]?\d+\z/)

              index(rest.to_i)
            end
          end

          def self.parse_json(text)
            JSON.parse(text)
          rescue JSON::ParserError => error
            raise DecodeError, error.message
          end

          private

          def compare_keys(left, right)
            left.each_with_index do |(name, value), index|
              return 1 if index >= right.length

              other_name, other_value = right[index]
              result = name <=> other_name
              return result unless result.zero?

              result = Value.compare(value, other_value)
              return result unless result.zero?
            end
            left.length < right.length ? -1 : 0
          end
        end

        # Path.String.
        def self.path_string(path) = path.join

        # A set of paths as a trie: the elements that are members at this
        # level and the child sets below elements.  Sets are never changed
        # once built (only #insert! on a set under construction), so child
        # sets are shared between results.
        class Set
          attr_reader :members, :children

          def self.from_paths(paths)
            set = new
            paths.each { |path| set.insert!(path) }
            set
          end

          def initialize(members = {}, children = {})
            @members = members
            @children = children
          end

          def insert!(path)
            return self if path.empty?

            node = self
            path[0...-1].each { |element| node = (node.children[element] ||= Set.new) }
            node.members[path.last] = true
            self
          end

          def union(other)
            return other if empty_structure?
            return self if other.empty_structure?

            children = @children.dup
            other.children.each do |element, set|
              mine = children[element]
              children[element] = mine ? mine.union(set) : set
            end
            Set.new(@members.merge(other.members), children)
          end

          def intersection(other)
            members = @members.select { |element, _| other.members.key?(element) }
            children = {}
            @children.each do |element, set|
              theirs = other.children[element]
              next unless theirs

              result = set.intersection(theirs)
              children[element] = result unless result.empty?
            end
            Set.new(members, children)
          end

          def difference(other)
            return self if other.empty_structure? || empty_structure?

            members = @members.reject { |element, _| other.members.key?(element) }
            children = {}
            @children.each do |element, set|
              theirs = other.children[element]
              if theirs.nil?
                children[element] = set
              else
                result = set.difference(theirs)
                children[element] = result unless result.empty?
              end
            end
            Set.new(members, children)
          end

          # Like #difference, but a member of +other+ also removes everything
          # below it.
          def recursive_difference(other)
            members = @members.reject { |element, _| other.members.key?(element) }
            children = {}
            @children.each do |element, set|
              next if other.members.key?(element)

              theirs = other.children[element]
              if theirs.nil?
                children[element] = set
              else
                result = set.recursive_difference(theirs)
                children[element] = result unless result.empty?
              end
            end
            Set.new(members, children)
          end

          def empty?
            @members.empty? && @children.each_value.all?(&:empty?)
          end

          def empty_structure? = @members.empty? && @children.empty?

          def size = @members.size + @children.each_value.sum(&:size)

          def has?(path)
            return false if path.empty?

            node = self
            path[0...-1].each do |element|
              node = node.children[element]
              return false if node.nil?
            end
            node.members.key?(path.last)
          end

          def with_prefix(element) = @children[element] || Set.new

          def ==(other)
            other.is_a?(Set) && @members.keys.sort == other.members.keys.sort &&
              @children.keys.sort == other.children.keys.sort &&
              @children.all? { |element, set| set == other.children[element] }
          end

          # Set.Leaves: members that are not also the root of a child set.
          def leaves
            members = @members.reject { |element, _| @children.key?(element) }
            Set.new(members, @children.transform_values(&:leaves))
          end

          # Set.EnsureNamedFieldsAreMembers.
          def ensure_named_fields_are_members(schema, type_ref)
            atom = schema.resolve(type_ref) || Schema::Atom::EMPTY
            members = @members.dup
            children = {}
            @children.each do |element, set|
              child_type = Schema::TypeRef::EMPTY
              if element.field? && atom.map
                field = atom.map.find_field(element.data)
                members[element] = true if field
                child_type = field ? field.type : atom.map.element_type
              elsif element.key? && atom.list
                child_type = atom.list.element_type
              end
              children[element] = set.ensure_named_fields_are_members(schema, child_type)
            end
            Set.new(members, children)
          end

          # Set.Iterate: members first, then the children, each in order.
          def each_path(prefix = [], &block)
            return enum_for(:each_path, prefix) unless block

            @members.keys.sort.each { |element| yield(prefix + [element]) }
            @children.keys.sort.each { |element| @children[element].each_path(prefix + [element], &block) }
          end

          def to_s = each_path.map { |path| FieldPath.path_string(path) }.join("\n")
          alias inspect to_s

          # Set.ToJSON as the FieldsV1 object.
          def to_fields_v1 = emit(false)

          def emit(include_self)
            out = {}
            out["."] = {} if include_self && !empty_structure?
            (@members.keys | @children.keys).sort.each do |element|
              child = @children[element]
              out[element.serialize] = if child.nil?
                                         {}
                                       else
                                         child.emit(@members.key?(element))
                                       end
            end
            out
          end

          # Set.FromJSON (readIterV1).
          def self.from_fields_v1(fields)
            return Set.new if fields.nil?
            raise DecodeError, "fieldsV1 must be an object" unless fields.is_a?(Hash)

            found, = read(fields)
            found || Set.new
          end

          def self.read(fields)
            children = nil
            member = false
            fields.each do |key, value|
              key = key.to_s
              if key == "."
                member = true
                next
              end
              element = PathElement.deserialize(key)
              next if element.nil?
              raise DecodeError, "fieldsV1 entries must be objects" unless value.is_a?(Hash)

              grandchildren, child_member = read(value)
              if child_member
                children ||= Set.new
                children.members[element] = true
              end
              if grandchildren
                children ||= Set.new
                children.children[element] = grandchildren
              end
            end
            member = true if children.nil?
            [children, member]
          end
        end
      end
    end
  end
end
