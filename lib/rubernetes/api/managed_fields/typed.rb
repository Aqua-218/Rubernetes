# frozen_string_literal: true

require_relative "value"
require_relative "fieldpath"
require_relative "schema"

module Rubernetes
  module API
    module ManagedFields
      # sigs.k8s.io/structured-merge-diff/v6/typed: a value with its schema,
      # and the walks over it -- ToFieldSet, Compare, Merge, RemoveItems,
      # Validate and ReconcileFieldSetWithSchema.
      #
      # +typed+ values are objects as a typed (reflected) Go struct would
      # present them: a key whose value is nil is an omitted pointer, i.e.
      # absent.  Unstructured values (an apply configuration) keep nulls.
      class TypedValue
        class Error < StandardError; end

        PathElement = FieldPath::PathElement
        FSet = FieldPath::Set
        Schema_ = Schema
        ABSENT = Value::ABSENT

        Comparison = Struct.new(:removed, :modified, :added) do
          def same? = removed.empty? && modified.empty? && added.empty?

          # Comparison.FilterFields with an exclude filter.
          def exclude(fields)
            return self if fields.nil? || fields.empty?

            Comparison.new(removed.recursive_difference(fields), modified.recursive_difference(fields),
                           added.recursive_difference(fields))
          end
        end

        attr_reader :model, :type_ref, :value, :api_version

        def initialize(value, model, type_ref, typed: true, api_version: nil)
          @value = value
          @model = model
          @type_ref = type_ref
          @typed = typed
          @api_version = api_version
        end

        def typed? = @typed

        def with_value(value, typed: @typed)
          TypedValue.new(value, @model, @type_ref, typed: typed, api_version: @api_version)
        end

        # ---- helpers (helpers.go) -------------------------------------------

        # A field outside the schema (an element type that is empty) is
        # walked as the deduced type; an apply configuration is validated
        # against the schema before it gets here.
        def atom_for(type_ref)
          return Schema_::DEDUCED_ATOM if type_ref.empty?

          @model.resolve(type_ref)
        end

        def resolve(type_ref, value)
          atom = atom_for(type_ref)
          raise Error, "schema error: no type found matching: #{type_ref.named || "inlined type"}" if atom.nil?

          deduce(atom, value)
        end

        def deduce(atom, value)
          return atom if Value.absent?(value)

          if Value.scalar?(value)
            return Schema_::Atom.new(scalar: atom.scalar) if atom.scalar
          elsif value.is_a?(Array)
            return Schema_::Atom.new(list: atom.list) if atom.list
          elsif value.is_a?(Hash)
            return Schema_::Atom.new(map: atom.map) if atom.map
          end
          atom
        end

        def self.each_entry(map, typed)
          map.each do |key, item|
            next if typed && item.nil?

            yield key.to_s, item
          end
        end

        def entries(map, typed = @typed, &) = TypedValue.each_entry(map, typed, &)

        def fetch(map, key, typed = @typed)
          return ABSENT unless map.is_a?(Hash)

          item = map.fetch(key) { map.fetch(key.to_sym, ABSENT) }
          typed && item.nil? ? ABSENT : item
        end

        def field_type(map_type, key)
          field = map_type.find_field(key)
          field ? field.type : map_type.element_type
        end

        def key_default(list, name)
          atom = @model.resolve(list.element_type)
          raise Error, "invalid elementType for list" if atom.nil?
          raise Error, "associative list may not have non-map types" if atom.map.nil?

          atom.map.find_field(name)&.default
        end

        # listItemToPathElement.
        def list_item_element(list, child)
          raise Error, "invalid indexing of non-associative list" unless list.associative?

          if list.keys.any?
            raise Error, "associative list with keys may not have a null element" if child.nil?
            raise Error, "associative list with keys may not have non-map elements" unless child.is_a?(Hash)

            pairs = []
            list.keys.each do |name|
              item = child.fetch(name, ABSENT)
              if Value.absent?(item)
                default = key_default(list, name)
                pairs << [name, default] unless default.nil?
              else
                pairs << [name, item]
              end
            end
            if pairs.empty?
              raise Error, "associative list with keys has an element that omits all key fields #{list.keys.inspect} " \
                           "(and doesn't have default values for any key fields)"
            end
            PathElement.key(pairs)
          else
            raise Error, "associative list without keys has an element that's a map type" if child.is_a?(Hash)
            raise Error, "not supported: associative list with lists as elements" if child.is_a?(Array)
            raise Error, "associative list without keys has an element that's an explicit null" if child.nil?

            PathElement.value(child)
          end
        end

        def validate_scalar(scalar, value, prefix)
          return nil if Value.absent?(value) || value.nil?

          case scalar
          when Schema_::NUMERIC
            "#{prefix}expected numeric (int or float), got #{go_type(value)}" unless Value.numeric?(value)
          when Schema_::STRING
            "#{prefix}expected string, got #{value.inspect}" unless value.is_a?(String)
          when Schema_::BOOLEAN
            "#{prefix}expected boolean, got #{value.inspect}" unless [true, false].include?(value)
          when Schema_::UNTYPED
            "#{prefix}expected any scalar, got #{value.inspect}" unless Value.scalar?(value)
          else
            "#{prefix}unexpected scalar type in schema: #{scalar}"
          end
        end

        def go_type(value)
          case value
          when String then "string"
          when Hash then "map[string]interface {}"
          when Array then "[]interface {}"
          when true, false then "bool"
          else value.class.name
          end
        end

        # ---- Validate (validate.go) ------------------------------------------

        def validate(allow_duplicates: false)
          errors = []
          validate_value(@type_ref, @value, "", errors, allow_duplicates)
          errors
        end

        def validate_value(type_ref, value, path, errors, allow_duplicates)
          atom = begin
            resolve(type_ref, value)
          rescue Error => error
            errors << prefixed(path, error.message)
            return
          end
          if atom.map
            return if Value.absent?(value) || value.nil?
            return errors << prefixed(path, "expected map, got #{value.inspect}") unless value.is_a?(Hash)

            entries(value) do |key, item|
              element = PathElement.field(key)
              child_path = "#{path}#{element}"
              field = atom.map.find_field(key)
              if field.nil? && atom.map.element_type.empty?
                errors << prefixed(child_path, "field not declared in schema")
                break
              end
              validate_value(field ? field.type : atom.map.element_type, item, child_path, errors, allow_duplicates)
            end
          elsif atom.scalar
            message = validate_scalar(atom.scalar, value, "")
            errors << prefixed(path, message) if message
          elsif atom.list
            return if Value.absent?(value) || value.nil?
            return errors << prefixed(path, "expected list, got #{value.inspect}") unless value.is_a?(Array)

            seen = {}
            value.each_with_index do |child, index|
              element = if atom.list.associative?
                          begin
                            list_item_element(atom.list, child)
                          rescue Error => error
                            errors << prefixed(path, "element #{index}: #{error.message}")
                            return # rubocop:disable Lint/NonLocalExitFromIterator -- the method is done once this holds
                          end
                        else
                          PathElement.index(index)
                        end
              if atom.list.associative?
                errors << prefixed(path, "duplicate entries for key #{element}") if seen.key?(element) && !allow_duplicates
                seen[element] = true
              end
              validate_value(atom.list.element_type, child, "#{path}#{element}", errors, allow_duplicates)
            end
          else
            errors << prefixed(path, "schema error: invalid atom: #{type_ref.named ? "named type: #{type_ref.named}" : "inlined"}")
          end
        end

        def prefixed(path, message) = path.empty? ? message : "#{path}: #{message}"

        # ---- ToFieldSet (tofieldset.go) --------------------------------------

        def to_field_set
          root = FSet.new
          field_set_walk(@type_ref, @value, nil, nil, root)
          root
        end

        # +parent+ is the set holding the current element +element+ (nil at
        # the root, whose path is empty and never inserted); +node+ the set
        # its children go into.
        def field_set_walk(type_ref, value, parent, element, node)
          atom = resolve(type_ref, value)
          if atom.map
            if atom.map.atomic?
              parent.members[element] = true if parent
              return
            end
            return unless value.is_a?(Hash)

            entries(value) do |key, item|
              child_element = PathElement.field(key)
              field = atom.map.find_field(key)
              child = FSet.new
              field_set_walk(field ? field.type : atom.map.element_type, item, node, child_element, child)
              node.children[child_element] = child unless child.empty_structure?
              node.members[child_element] = true if item.nil? || (item.is_a?(Hash) && item.empty?) || field.nil?
            end
          elsif atom.scalar
            parent.members[element] = true if parent
          elsif atom.list
            if atom.list.atomic?
              parent.members[element] = true if parent
              return
            end
            return unless value.is_a?(Array)

            elements = value.map do |child|
              list_item_element(atom.list, child)
            rescue Error
              nil
            end
            seen = {}
            duplicates = {}
            elements.each do |child_element|
              next if child_element.nil?

              if seen.key?(child_element)
                unless duplicates.key?(child_element)
                  node.members[child_element] = true
                  duplicates[child_element] = true
                end
              else
                seen[child_element] = true
              end
            end
            value.each_with_index do |child, index|
              child_element = elements[index]
              next if child_element.nil? || duplicates.key?(child_element)

              grand = FSet.new
              field_set_walk(atom.list.element_type, child, node, child_element, grand)
              node.children[child_element] = grand unless grand.empty_structure?
              node.members[child_element] = true
            end
          else
            raise Error, "schema error: invalid atom: #{type_ref.named ? "named type: #{type_ref.named}" : "inlined"}"
          end
        end

        # ---- Compare (compare.go) --------------------------------------------

        CompareState = Struct.new(:in_leaf)

        def compare(other)
          comparison = Comparison.new(FSet.new, FSet.new, FSet.new)
          errors = []
          compare_walk(@type_ref, @value, other.value, [], comparison, errors, other.typed?)
          raise Error, errors.join("\n") if errors.any?

          comparison
        end

        def compare_walk(type_ref, lhs, rhs, path, comparison, errors, rhs_typed)
          raise Error, "at least one of lhs and rhs must be provided" if Value.absent?(lhs) && Value.absent?(rhs)
          # Equal values compare to nothing added, removed or modified at
          # any depth; Hash/Array#== settles that without the walk.
          return if !Value.absent?(lhs) && !Value.absent?(rhs) && (lhs.equal?(rhs) || lhs == rhs)

          atom = atom_for(type_ref)
          raise Error, "schema error: no type found matching: #{type_ref.named}" if atom.nil?

          left = deduce(atom, lhs)
          right = deduce(atom, rhs)
          state = CompareState.new(false)
          if Value.absent?(rhs)
            compare_atom(left, type_ref, lhs, rhs, path, comparison, errors, state, rhs_typed)
          elsif Value.absent?(lhs) || left == right
            compare_atom(right, type_ref, lhs, rhs, path, comparison, errors, state, rhs_typed)
          else
            compare_atom(left, type_ref, lhs, rhs, path, comparison, errors, CompareState.new(false), rhs_typed)
            compare_atom(right, type_ref, lhs, rhs, path, comparison, errors, state, rhs_typed)
          end
          return if state.in_leaf

          if Value.absent?(lhs)
            comparison.added.insert!(path)
          elsif Value.absent?(rhs)
            comparison.removed.insert!(path)
          end
        end

        def compare_leaf(lhs, rhs, path, comparison, state)
          return if state.in_leaf

          state.in_leaf = true
          if Value.absent?(lhs)
            comparison.added.insert!(path)
          elsif Value.absent?(rhs)
            comparison.removed.insert!(path)
          elsif !Value.equal?(rhs, lhs)
            comparison.modified.insert!(path)
          end
        end

        def compare_atom(atom, type_ref, lhs, rhs, path, comparison, errors, state, rhs_typed)
          if atom.map
            left_map = deref(lhs, Hash, "lhs: ", "map", errors)
            right_map = deref(rhs, Hash, "rhs: ", "map", errors)
            if atom.map.atomic? || ((left_map.nil? || left_map.empty?) && (right_map.nil? || right_map.empty?))
              return compare_leaf(lhs, rhs, path, comparison, state)
            end
            return if left_map.nil? && right_map.nil?

            keys = []
            seen = {}
            entries(left_map || {}) do |key, _|
              keys << key
              seen[key] = true
            end
            TypedValue.each_entry(right_map || {}, rhs_typed) { |key, _| keys << key unless seen.key?(key) }
            keys.each do |key|
              element = PathElement.field(key)
              compare_walk(field_type(atom.map, key), fetch(left_map, key), fetch(right_map, key, rhs_typed),
                           path + [element], comparison, errors, rhs_typed)
            rescue Error => error
              errors << "#{element}: #{error.message}"
            end
          elsif atom.scalar
            left_error = validate_scalar(atom.scalar, lhs, "lhs: ")
            right_error = validate_scalar(atom.scalar, rhs, "rhs: ")
            if left_error && right_error
              errors << left_error << right_error
              return
            end
            compare_leaf(lhs, rhs, path, comparison, state)
          elsif atom.list
            left_list = deref(lhs, Array, "lhs: ", "list", errors)
            right_list = deref(rhs, Array, "rhs: ", "list", errors)
            if atom.list.atomic? || ((left_list.nil? || left_list.empty?) && (right_list.nil? || right_list.empty?))
              return compare_leaf(lhs, rhs, path, comparison, state)
            end
            return if left_list.nil? && right_list.nil?

            compare_list_items(atom.list, left_list || [], right_list || [], path, comparison, errors, rhs_typed)
          else
            errors << "schema error: invalid atom: #{type_ref.named ? "named type: #{type_ref.named}" : "inlined"}"
          end
        end

        def deref(value, klass, prefix, kind, errors)
          return nil if Value.absent?(value) || value.nil?
          return value if value.is_a?(klass)

          errors << "#{prefix}expected #{kind}, got #{value.inspect}"
          nil
        end

        def compare_list_items(list, lhs, rhs, path, comparison, errors, rhs_typed)
          order = []
          left_values = {}
          lhs.each_with_index do |child, index|
            element = list_item_element(list, child)
            unless left_values.key?(element)
              order << element
              left_values[element] = []
            end
            left_values[element] << child
          rescue Error => error
            errors << "element #{index}: #{error.message}"
          end
          right_values = {}
          rhs.each_with_index do |child, index|
            element = list_item_element(list, child)
            unless right_values.key?(element)
              order << element unless left_values.key?(element)
              right_values[element] = []
            end
            right_values[element] << child
          rescue Error => error
            errors << "element #{index}: #{error.message}"
          end
          order.each do |element|
            left = left_values[element] || []
            right = right_values[element] || []
            if left.length <= 1 && right.length <= 1
              compare_walk(list.element_type, left.empty? ? ABSENT : left.first, right.empty? ? ABSENT : right.first,
                           path + [element], comparison, errors, rhs_typed)
            elsif left.length >= 2 && right.length >= 2
              same = left.length == right.length && left.each_index.all? { |index| Value.equal?(left[index], right[index]) }
              comparison.modified.insert!(path + [element]) unless same
            elsif left.length >= 2
              compare_walk(list.element_type, ABSENT, right.first, path + [element], comparison, errors, rhs_typed) if right.any?
              comparison.removed.insert!(path + [element])
            else
              compare_walk(list.element_type, left.first, ABSENT, path + [element], comparison, errors, rhs_typed) if left.any?
              comparison.added.insert!(path + [element])
            end
          rescue Error => error
            errors << "#{element}: #{error.message}"
          end
        end

        # ---- Merge (merge.go, ruleKeepRHS) -----------------------------------

        MergeState = Struct.new(:in_leaf, :out)

        # The live value merged with +other+ (an apply configuration).
        def merge(other)
          errors = []
          out = merge_walk(@type_ref, @value, other.value, errors, other.typed?)
          raise Error, errors.join("\n") if errors.any?

          with_value(Value.absent?(out) ? nil : out, typed: false)
        end

        def merge_walk(type_ref, lhs, rhs, errors, rhs_typed)
          raise Error, "at least one of lhs and rhs must be provided" if Value.absent?(lhs) && Value.absent?(rhs)

          atom = atom_for(type_ref)
          raise Error, "schema error: no type found matching: #{type_ref.named}" if atom.nil?

          left = deduce(atom, lhs)
          right = deduce(atom, rhs)
          state = MergeState.new(false, ABSENT)
          if Value.absent?(rhs)
            merge_atom(left, type_ref, lhs, rhs, errors, state, rhs_typed)
          elsif Value.absent?(lhs) || left == right
            merge_atom(right, type_ref, lhs, rhs, errors, state, rhs_typed)
          else
            merge_atom(left, type_ref, lhs, rhs, errors, MergeState.new(false, ABSENT), rhs_typed)
            merge_atom(right, type_ref, lhs, rhs, errors, state, rhs_typed)
          end
          state.out
        end

        def merge_leaf(lhs, rhs, state)
          return if state.in_leaf

          state.in_leaf = true
          state.out = Value.absent?(rhs) ? lhs : rhs
        end

        def merge_atom(atom, type_ref, lhs, rhs, errors, state, rhs_typed)
          if atom.map
            left_map = deref(lhs, Hash, "lhs: ", "map", errors)
            right_map = deref(rhs, Hash, "rhs: ", "map", errors)
            if atom.map.atomic? || ((left_map.nil? || left_map.empty?) && (right_map.nil? || right_map.empty?))
              return merge_leaf(lhs, rhs, state)
            end
            return if left_map.nil? && right_map.nil?

            out = {}
            keys = []
            seen = {}
            entries(left_map || {}) do |key, _|
              keys << key
              seen[key] = true
            end
            TypedValue.each_entry(right_map || {}, rhs_typed) { |key, _| keys << key unless seen.key?(key) }
            keys.each do |key|
              child = merge_walk(field_type(atom.map, key), fetch(left_map, key), fetch(right_map, key, rhs_typed), errors, rhs_typed)
              out[key] = child unless Value.absent?(child)
            rescue Error => error
              errors << ".#{key}: #{error.message}"
            end
            state.out = out unless out.empty?
          elsif atom.scalar
            left_error = validate_scalar(atom.scalar, lhs, "lhs: ")
            right_error = validate_scalar(atom.scalar, rhs, "rhs: ")
            if left_error && right_error
              errors << left_error << right_error
              return
            end
            merge_leaf(lhs, rhs, state)
          elsif atom.list
            left_list = deref(lhs, Array, "lhs: ", "list", errors)
            right_list = deref(rhs, Array, "rhs: ", "list", errors)
            if atom.list.atomic? || ((left_list.nil? || left_list.empty?) && (right_list.nil? || right_list.empty?))
              return merge_leaf(lhs, rhs, state)
            end
            return if left_list.nil? && right_list.nil?

            merge_list_items(atom.list, left_list || [], right_list || [], errors, state, rhs_typed)
          else
            errors << "schema error: invalid atom: #{type_ref.named ? "named type: #{type_ref.named}" : "inlined"}"
          end
        end

        def index_list(list, items, allow_duplicates, errors)
          elements = []
          observed = {}
          items.each_with_index do |child, index|
            element = list_item_element(list, child)
            if observed.key?(element)
              unless allow_duplicates
                errors << "duplicate entries for key #{element}"
                next
              end
              observed[element] = nil
            else
              observed[element] = child
            end
            elements << element
          rescue Error => error
            errors << "element #{index}: #{error.message}"
          end
          [elements, observed]
        end

        def merge_list_items(list, lhs, rhs, errors, state, rhs_typed)
          local = []
          right_elements, observed_right = index_list(list, rhs, false, local)
          left_elements, observed_left = index_list(list, lhs, true, local)
          unless local.empty?
            errors.concat(local)
            return
          end

          shared = right_elements.select { |element| observed_left.key?(element) }
          next_shared = shared.shift
          merged_right = {}
          out = []
          merge_item = lambda do |_element, left, right|
            child = merge_walk(list.element_type, left, right, [], rhs_typed)
            out << child unless Value.absent?(child)
          rescue Error
            nil
          end
          left_index = 0
          right_index = 0
          while left_index < left_elements.length || right_index < right_elements.length
            if left_index < left_elements.length && right_index < right_elements.length
              element = left_elements[left_index]
              if element.eql?(right_elements[right_index])
                merged_right[element] = true
                merge_item.call(element, observed_left.fetch(element, ABSENT), observed_right.fetch(element, ABSENT))
                left_index += 1
                right_index += 1
                next_shared = shared.shift
                next
              end
              if observed_right.key?(element) && next_shared && !next_shared.eql?(left_elements[left_index])
                left_index += 1
                next
              end
            end
            if left_index < left_elements.length
              element = left_elements[left_index]
              if !observed_right.key?(element)
                merge_item.call(element, lhs[left_index], ABSENT)
                left_index += 1
                next
              elsif merged_right.key?(element)
                left_index += 1
              end
            end
            next unless right_index < right_elements.length

            element = right_elements[right_index]
            merged_right[element] = true
            merge_item.call(element, observed_left.fetch(element, ABSENT), observed_right.fetch(element, ABSENT))
            right_index += 1
            next_shared = shared.shift if next_shared.eql?(element)
          end
          state.out = out unless out.empty?
        end

        # ---- RemoveItems (remove.go) -----------------------------------------

        def remove_items(items)
          with_value(remove_walk(@type_ref, @value, items))
        end

        def remove_walk(type_ref, value, to_remove)
          atom = resolve(type_ref, value)
          if atom.map
            return nil unless value.is_a?(Hash)
            return nil if value.empty? || atom.map.atomic?

            out = {}
            had_matches = false
            entries(value) do |key, item|
              element = PathElement.field(key)
              next if to_remove.members.key?(element)

              subset = to_remove.children[element]
              if subset && !subset.empty?
                had_matches = true
                was_map = item.is_a?(Hash)
                was_list = item.is_a?(Array)
                item = remove_walk(field_type(atom.map, key), item, subset)
                item = {} if item.nil? && was_map
                item = [] if item.nil? && was_list
              end
              out[key] = item
            end
            out.empty? && !had_matches ? nil : out
          elsif atom.scalar
            value
          elsif atom.list
            return nil unless value.is_a?(Array)
            return nil if value.empty? || atom.list.atomic?

            out = []
            had_matches = false
            value.each do |item|
              element = begin
                list_item_element(atom.list, item)
              rescue Error
                nil
              end
              next if element && to_remove.members.key?(element)

              subset = element && to_remove.children[element]
              if subset && !subset.empty?
                had_matches = true
                was_map = item.is_a?(Hash)
                was_list = item.is_a?(Array)
                item = remove_walk(atom.list.element_type, item, subset)
                item = {} if item.nil? && was_map
                item = [] if item.nil? && was_list
              end
              out << item
            end
            out.empty? && !had_matches ? nil : out
          end
        end

        # ---- ReconcileFieldSetWithSchema (reconcile_schema.go) ----------------

        RECONCILED = ObjectSpace::WeakMap.new
        RECONCILED_LOCK = Mutex.new

        # Sets and schemas never change, so a set reconciled against a type
        # once reconciles the same way again.
        def reconcile_field_set(field_set)
          key = [@model.object_id, @type_ref.object_id]
          cached = RECONCILED_LOCK.synchronize { RECONCILED[field_set] }
          if cached && cached.first == key
            return cached.last == :unchanged ? nil : cached.last
          end

          result = reconcile_uncached(field_set)
          RECONCILED_LOCK.synchronize { RECONCILED[field_set] = [key, result || :unchanged].freeze }
          result
        end

        def reconcile_uncached(field_set)
          state = {remove: nil, add: nil}
          reconcile_walk(@type_ref, field_set, [], false, state)
          return nil if state[:remove].nil? && state[:add].nil?

          out = field_set
          out = out.recursive_difference(state[:remove]) if state[:remove]
          out = out.union(state[:add]) if state[:add]
          out
        end

        def reconcile_walk(type_ref, field_set, path, atomic_member, state)
          atom = atom_for(type_ref)
          raise Error, "could not resolve #{type_ref.named}" if atom.nil?

          if atom.map
            map = atom.map
            return if untyped_deduced?(map.element_type) && map.fields.empty?

            if !atomic_member && map.atomic?
              mark_atomic(path, state) if field_set && field_set.size.positive?
              return
            end
            return if field_set.nil?

            reconcile_elements(field_set) do |element, member|
              child_type = if element.field?
                             field = map.find_field(element.data)
                             field ? field.type : map.element_type
                           else
                             map.element_type
                           end
              next if child_type.empty?

              child = field_set.children[element]
              reconcile_walk(child_type, child, path + [element], member && child.nil?, state)
            end
          elsif atom.list
            list = atom.list
            if !atomic_member && list.atomic?
              mark_atomic(path, state)
              return
            end
            return if field_set.nil?

            reconcile_elements(field_set) do |element, member|
              child = field_set.children[element]
              reconcile_walk(list.element_type, child, path + [element], member && child.nil?, state)
            end
          end
        end

        def untyped_deduced?(type_ref)
          return type_ref.named == Schema_::DEDUCED_NAME if type_ref.named

          type_ref.inlined&.scalar == Schema_::UNTYPED
        end

        def reconcile_elements(field_set)
          field_set.children.keys.sort.each { |element| yield(element, false) unless field_set.members.key?(element) }
          field_set.members.keys.sort.each { |element| yield(element, true) }
        end

        def mark_atomic(path, state)
          single = FSet.from_paths([path])
          state[:remove] = state[:remove] ? state[:remove].union(single) : single
          state[:add] = state[:add] ? state[:add].union(single) : single
        end
      end
    end
  end
end
