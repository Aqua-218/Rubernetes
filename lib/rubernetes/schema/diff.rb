# frozen_string_literal: true

module Rubernetes
  module Schema
    # One semantic difference between two schema objects.
    class DiffChange
      attr_reader :path, :before, :after, :operation, :category

      def initialize(path:, operation:, category:, before: nil, after: nil)
        @path = Array(path).map(&:to_s).freeze
        @before = before
        @after = after
        @operation = operation.to_sym
        @category = category.to_sym
        freeze
      end

      def added?
        operation == :added
      end

      def removed?
        operation == :removed
      end

      def changed?
        operation == :changed
      end

      def path_string
        path.join(".")
      end

      def to_h
        {
          path: path,
          before: before,
          after: after,
          operation: operation,
          category: category
        }.freeze
      end

      def ==(other)
        other.is_a?(DiffChange) && to_h == other.to_h
      end
      alias eql? ==

      def hash
        to_h.hash
      end
    end

    Change = DiffChange

    # The result of a diff, with convenient spec/status partitions.
    class DiffResult
      include Enumerable

      attr_reader :changes

      def initialize(changes)
        @changes = Array(changes).freeze
        freeze
      end

      def each(&block)
        return enum_for(__method__) unless block

        changes.each(&block)
      end

      def empty?
        changes.empty?
      end

      alias none? empty?

      def any?
        !empty?
      end

      def size
        changes.size
      end
      alias length size

      def spec
        self.class.new(changes.select { |change| change.category == :spec })
      end

      def status
        self.class.new(changes.select { |change| change.category == :status })
      end

      def metadata
        self.class.new(changes.select { |change| change.category == :metadata })
      end

      def unknown
        self.class.new(changes.select { |change| change.category == :unknown })
      end

      alias spec_changes spec
      alias status_changes status

      def semantic_equal?
        empty?
      end
      alias equal? semantic_equal?

      def to_a
        changes
      end

      def to_h
        {
          changes: changes.map(&:to_h),
          spec: spec.changes.map(&:to_h),
          status: status.changes.map(&:to_h),
          metadata: metadata.changes.map(&:to_h),
          unknown: unknown.changes.map(&:to_h)
        }.transform_values(&:freeze).freeze
      end
    end

    # Computes deterministic, default-aware semantic differences.
    class Diff
      attr_reader :definition

      def self.diff(left, right, definition: nil, **)
        new(definition).call(left, right, **)
      end

      class << self
        alias compare diff
      end

      def initialize(definition = nil, defaulting: true)
        @definition = if definition.nil? || definition.is_a?(Definition)
                        definition
                      else
                        Definition.new(definition)
                      end
        @defaulting = !!defaulting
      end

      def call(left, right, default_aware: @defaulting, apply_defaults: nil, **options)
        default_aware = apply_defaults unless apply_defaults.nil?
        before = normalize(left, default_aware, options)
        after = normalize(right, default_aware, options)
        DiffResult.new(diff_values(before, after, [], :root, options))
      end

      alias diff call
      alias compare call
      alias semantic call

      def structural(left, right, **)
        call(left, right, default_aware: false, **)
      end

      def spec(left, right, **)
        call(left, right, **).spec
      end

      def status(left, right, **)
        call(left, right, **).status
      end

      def semantic_equal?(left, right, **)
        call(left, right, **).empty?
      end

      def self.call(left, right, definition: nil, **)
        new(definition).call(left, right, **)
      end

      def self.semantic_equal?(left, right, definition: nil, **)
        new(definition).semantic_equal?(left, right, **)
      end

      private

      def normalize(value, default_aware, options)
        hash = value.is_a?(ValueObject) ? value.to_h : value
        return deep_copy(hash) unless default_aware && definition

        definition.defaulting.apply_hash(hash, unknown_fields: options.fetch(:unknown_fields, :preserve))
      end

      def diff_values(before, after, path, root_category, options)
        if before.is_a?(Hash) && after.is_a?(Hash)
          diff_hashes(before, after, path, root_category, options)
        elsif before.is_a?(Array) && after.is_a?(Array)
          diff_arrays(before, after, path, root_category, options)
        elsif before != after
          [DiffChange.new(path: path, before: before, after: after, operation: :changed,
                          category: category_for(path, root_category, options))]
        else
          []
        end
      end

      def diff_hashes(before, after, path, root_category, options)
        keys = (before.keys + after.keys).map(&:to_s).uniq.sort
        keys.each_with_object([]) do |key, changes|
          before_present = key_present?(before, key)
          after_present = key_present?(after, key)
          next if before_present && after_present && before_value(before, key) == after_value(after, key)

          category = category_for(path + [key], root_category, options)
          if !before_present
            changes << DiffChange.new(path: path + [key], after: after_value(after, key), operation: :added,
                                      category: category)
          elsif !after_present
            changes << DiffChange.new(path: path + [key], before: before_value(before, key), operation: :removed,
                                      category: category)
          else
            changes.concat(diff_values(before_value(before, key), after_value(after, key), path + [key], category, options))
          end
        end
      end

      def diff_arrays(before, after, path, root_category, options)
        max = [before.length, after.length].max
        max.times.each_with_object([]) do |index, changes|
          before_present = index < before.length
          after_present = index < after.length
          if !before_present
            changes << DiffChange.new(path: path + [index.to_s], after: after[index], operation: :added,
                                      category: category_for(path, root_category, options))
          elsif !after_present
            changes << DiffChange.new(path: path + [index.to_s], before: before[index], operation: :removed,
                                      category: category_for(path, root_category, options))
          else
            changes.concat(diff_values(before[index], after[index], path + [index.to_s], root_category, options))
          end
        end
      end

      def category_for(path, inherited, options)
        return :spec if path.include?("spec")
        return :status if path.include?("status")
        return :unknown if path.first == "unknown" || options.fetch(:unknown_paths, []).include?(path)
        return inherited unless inherited == :root
        return :unknown if definition && path.first && !definition.field?(path.first) && path.first != "metadata"
        return :metadata if path.first == "metadata"

        :metadata
      end

      def key_present?(hash, key)
        hash.key?(key) || hash.key?(key.to_sym)
      end

      def before_value(hash, key)
        hash.key?(key) ? hash[key] : hash[key.to_sym]
      end

      alias after_value before_value

      def deep_copy(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, item), result| result[key.to_s] = deep_copy(item) }
        when Array
          value.map { |item| deep_copy(item) }
        else
          value
        end
      end
    end
  end
end
