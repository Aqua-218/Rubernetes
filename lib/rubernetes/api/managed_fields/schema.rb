# frozen_string_literal: true

module Rubernetes
  module API
    module ManagedFields
      # sigs.k8s.io/structured-merge-diff/v6/schema and the OpenAPI
      # conversion of k8s.io/kube-openapi/pkg/schemaconv (v1.36.2 pins).
      module Schema
        ASSOCIATIVE = "associative"
        ATOMIC = "atomic"
        SEPARABLE = "separable"

        NUMERIC = "numeric"
        STRING = "string"
        BOOLEAN = "boolean"
        UNTYPED = "untyped"

        UNTYPED_NAME = "__untyped_atomic_"
        DEDUCED_NAME = "__untyped_deduced_"
        QUANTITY = "io.k8s.apimachinery.pkg.api.resource.Quantity"
        RAW_EXTENSION = "io.k8s.apimachinery.pkg.runtime.RawExtension"

        # A named type, an inlined atom, and an optional elementRelationship
        # override.
        class TypeRef
          attr_reader :named, :inlined, :relationship

          def initialize(named: nil, inlined: nil, relationship: nil)
            @named = named&.dup&.freeze
            @inlined = inlined
            @relationship = relationship
            freeze
          end

          def empty? = @named.nil? && (@inlined.nil? || @inlined.empty?) && @relationship.nil?

          EMPTY = new
        end

        StructField = Struct.new(:name, :type, :default)

        class MapType
          attr_reader :fields, :element_type, :relationship

          def initialize(fields: {}, element_type: TypeRef::EMPTY, relationship: "")
            @fields = fields.freeze
            @element_type = element_type
            @relationship = relationship.to_s
            freeze
          end

          def find_field(name) = @fields[name]
          def atomic? = @relationship == ATOMIC
          def with_relationship(relationship) = MapType.new(fields: @fields, element_type: @element_type, relationship: relationship)
        end

        class ListType
          attr_reader :element_type, :relationship, :keys

          def initialize(element_type: TypeRef::EMPTY, relationship: ATOMIC, keys: [])
            @element_type = element_type
            @relationship = relationship.to_s
            @keys = keys.map { |key| key.to_s.dup.freeze }.freeze
            freeze
          end

          def atomic? = @relationship == ATOMIC
          def associative? = @relationship == ASSOCIATIVE
          def with_relationship(relationship) = ListType.new(element_type: @element_type, relationship: relationship, keys: @keys)
        end

        class Atom
          attr_reader :scalar, :list, :map

          def initialize(scalar: nil, list: nil, map: nil)
            @scalar = scalar
            @list = list
            @map = map
            freeze
          end

          def empty? = @scalar.nil? && @list.nil? && @map.nil?

          def ==(other)
            other.is_a?(Atom) && other.scalar == @scalar && other.list.equal?(@list) && other.map.equal?(@map)
          end

          EMPTY = new
        end

        UNTYPED_ATOM = Atom.new(
          scalar: UNTYPED,
          list: ListType.new(element_type: TypeRef.new(named: UNTYPED_NAME), relationship: ATOMIC),
          map: MapType.new(element_type: TypeRef.new(named: UNTYPED_NAME), relationship: ATOMIC)
        )
        DEDUCED_ATOM = Atom.new(
          scalar: UNTYPED,
          list: ListType.new(element_type: TypeRef.new(named: UNTYPED_NAME), relationship: ATOMIC),
          map: MapType.new(element_type: TypeRef.new(named: DEDUCED_NAME), relationship: SEPARABLE)
        )

        # schema.Schema: named types and Resolve with elementRelationship
        # overrides.
        class Model
          attr_reader :types

          def initialize(types)
            @types = types
            @resolved = {}
            @mutex = Mutex.new
          end

          def named?(name) = @types.key?(name)

          def resolve(type_ref)
            base = if type_ref.named
                     @types[type_ref.named]
                   else
                     type_ref.inlined || Atom::EMPTY
                   end
            return base if base.nil? || type_ref.relationship.nil?

            @mutex.synchronize do
              @resolved[type_ref] ||= if base.map
                                        Atom.new(map: base.map.with_relationship(type_ref.relationship))
                                      elsif base.list
                                        Atom.new(list: base.list.with_relationship(type_ref.relationship))
                                      else
                                        false
                                      end
            end || nil
          end
        end

        DEDUCED_MODEL = Model.new({UNTYPED_NAME => UNTYPED_ATOM, DEDUCED_NAME => DEDUCED_ATOM}.freeze)
        DEDUCED_TYPE = TypeRef.new(named: DEDUCED_NAME)

        # schemaconv.ToSchemaFromOpenAPI over OpenAPI v3 components.schemas.
        class Converter
          attr_reader :errors

          def self.convert(models, preserve_unknown_fields: false)
            converter = new(preserve_unknown_fields)
            types = {}
            models.each do |name, spec|
              next unless spec.is_a?(Hash)
              next if spec["$ref"].to_s != ""

              atom = case name
                     when QUANTITY then Atom.new(scalar: UNTYPED)
                     when RAW_EXTENSION then UNTYPED_ATOM
                     else converter.visit_spec(spec, name, preserve_unknown_fields)
                     end
              types[name] = atom unless atom.empty?
            end
            types[UNTYPED_NAME] = UNTYPED_ATOM
            types[DEDUCED_NAME] = DEDUCED_ATOM
            [Model.new(types.freeze), converter.errors]
          end

          def initialize(preserve)
            @preserve = preserve
            @errors = []
          end

          def visit_spec(spec, name, preserve)
            preserve = true if spec["x-kubernetes-preserve-unknown-fields"] == true
            parse_schema(spec, name, preserve)
          end

          private

          def parse_schema(spec, name, preserve)
            type = Array(spec["type"]).first.to_s
            case type
            when ""
              Atom.new(scalar: UNTYPED, list: parse_list(spec, name, preserve), map: parse_object(spec, name, preserve))
            when "object" then Atom.new(map: parse_object(spec, name, preserve))
            when "array" then Atom.new(list: parse_list(spec, name, preserve))
            when "integer", "number" then Atom.new(scalar: NUMERIC)
            when "boolean" then Atom.new(scalar: BOOLEAN)
            when "string"
              format = spec["format"].to_s
              Atom.new(scalar: format.empty? || format == "byte" ? STRING : UNTYPED)
            else
              @errors << "#{name}: unrecognized type: '#{type}'"
              Atom.new(scalar: UNTYPED)
            end
          end

          def make_ref(spec, name, preserve)
            ref = spec["$ref"].to_s
            all_of = spec["allOf"]
            if ref.empty? && all_of.is_a?(Array) && all_of.length == 1 && all_of.first.is_a?(Hash)
              ref = all_of.first["$ref"].to_s
            end
            target = ref.split("/").last.to_s
            unless target.empty?
              relationship = map_relationship(spec, name)
              return TypeRef.new(named: target, relationship: relationship)
            end

            TypeRef.new(inlined: visit_spec(spec, "inlined in #{name}", preserve))
          end

          def parse_object(spec, name, preserve)
            fields = {}
            (spec["properties"] || {}).each do |field, member|
              next unless member.is_a?(Hash)

              fields[field] = StructField.new(field, make_ref(member, name, preserve), member["default"])
            end
            additional = spec["additionalProperties"]
            element = if additional.nil?
                        preserve || fields.empty? ? DEDUCED_TYPE : TypeRef::EMPTY
                      elsif additional.is_a?(Hash)
                        make_ref(additional, name, preserve)
                      elsif additional == true
                        DEDUCED_TYPE
                      else
                        TypeRef::EMPTY
                      end
            MapType.new(fields: fields, element_type: element, relationship: map_relationship(spec, name).to_s)
          end

          def parse_list(spec, name, preserve)
            relationship, keys = list_relationship(spec, name)
            items = spec["items"]
            element = if items.is_a?(Hash)
                        make_ref(items, name, preserve)
                      elsif items.is_a?(Array)
                        @errors << "#{name}: structural schema arrays must have exactly one member subtype"
                        DEDUCED_TYPE
                      else
                        @errors << "#{name}: `items` must be specified on arrays" unless Array(spec["type"]).first.to_s.empty?
                        TypeRef.new(named: UNTYPED_NAME)
                      end
            ListType.new(element_type: element, relationship: relationship, keys: keys)
          end

          def list_relationship(spec, name)
            if spec.key?("x-kubernetes-list-type")
              case spec["x-kubernetes-list-type"]
              when "atomic" then [ATOMIC, []]
              when "set" then [ASSOCIATIVE, []]
              when "map"
                keys = spec["x-kubernetes-list-map-keys"]
                unless keys.is_a?(Array)
                  @errors << "#{name}: missing map keys"
                  return [ASSOCIATIVE, []]
                end
                [ASSOCIATIVE, keys.grep(String)]
              else
                @errors << "#{name}: unknown list type #{spec["x-kubernetes-list-type"]}"
                [ATOMIC, []]
              end
            elsif spec.key?("x-kubernetes-patch-strategy")
              case spec["x-kubernetes-patch-strategy"]
              when "merge", "merge,retainKeys"
                key = spec["x-kubernetes-patch-merge-key"]
                key.is_a?(String) ? [ASSOCIATIVE, [key]] : [ASSOCIATIVE, []]
              when "retainKeys" then [ATOMIC, []]
              else
                @errors << "#{name}: unknown patch strategy #{spec["x-kubernetes-patch-strategy"]}"
                [ATOMIC, []]
              end
            else
              [ATOMIC, []]
            end
          end

          def map_relationship(spec, name)
            return nil unless spec.key?("x-kubernetes-map-type")

            case spec["x-kubernetes-map-type"]
            when "atomic" then ATOMIC
            when "granular" then SEPARABLE
            else
              @errors << "#{name}: unknown map type #{spec["x-kubernetes-map-type"]}"
              nil
            end
          end
        end

        # The parseable type for each group/version/kind a set of OpenAPI
        # models declares (typeconverter.go indexModels).
        class TypeConverter
          def self.from_components(schemas, preserve_unknown_fields: false)
            model, errors = Converter.convert(schemas, preserve_unknown_fields: preserve_unknown_fields)
            index = {}
            schemas.each do |name, spec|
              next unless spec.is_a?(Hash)

              Array(spec["x-kubernetes-group-version-kind"]).each do |gvk|
                next unless gvk.is_a?(Hash) && !gvk["kind"].to_s.empty?

                index[[gvk["group"].to_s, gvk["version"].to_s, gvk["kind"].to_s]] = TypeRef.new(named: name)
              end
            end
            new(model, index.freeze, errors)
          end

          attr_reader :model, :errors

          def initialize(model, index, errors = [])
            @model = model
            @index = index
            @errors = errors
          end

          # [model, type_ref] for a kind, or nil (NoCorrespondingTypeError).
          def type_for(group, version, kind)
            ref = @index[[group.to_s, version.to_s, kind.to_s]]
            ref && [@model, ref]
          end
        end

        # NewDeducedTypeConverter: every kind is the deduced type.
        class DeducedTypeConverter
          def type_for(_group, _version, _kind) = [DEDUCED_MODEL, DEDUCED_TYPE]
          def errors = []
        end
      end
    end
  end
end
