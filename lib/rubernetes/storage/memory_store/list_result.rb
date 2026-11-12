# frozen_string_literal: true

module Rubernetes
  module Storage
    # A tuple-compatible list response. It supports `objects, rv = list(...)`
    # while exposing Kubernetes-style metadata for callers that prefer names.
    # It intentionally is not an Array subclass: StoreAdapter must be able to
    # see `items`/`continue_token` and preserve pagination metadata instead of
    # treating the result as a bare two-element tuple.
    class ListResult
      include Enumerable

      attr_reader :items, :resource_version, :continue_token, :remaining_item_count

      def initialize(items:, resource_version:, continue_token: nil, remaining_item_count: nil)
        @items = items.freeze
        @resource_version = String(resource_version).freeze
        @continue_token = continue_token&.dup&.freeze
        @remaining_item_count = remaining_item_count
        freeze
      end

      alias resourceVersion resource_version
      alias continue continue_token
      alias remainingItemCount remaining_item_count

      def [](index, *)
        return @items if [:items, "items"].include?(index)
        return @resource_version if [:resource_version, "resourceVersion", "resource_version"].include?(index)
        return @continue_token if [:continue, "continue", "continue_token"].include?(index)
        return @remaining_item_count if [:remaining_item_count, "remainingItemCount"].include?(index)

        tuple = [@items, @resource_version]
        tuple[index, *]
      end

      def fetch(index, *args)
        return self[index] if index.is_a?(Symbol) || index.is_a?(String)

        [@items, @resource_version].fetch(index, *args)
      rescue IndexError
        return args.fetch(0) unless args.empty?

        raise
      end

      def each
        return enum_for(__method__) unless block_given?

        yield @items
        yield @resource_version
        self
      end

      def to_ary
        [@items, @resource_version]
      end

      alias to_a to_ary

      def first(count = nil)
        count.nil? ? @items : to_ary.first(count)
      end

      def last(count = nil)
        count.nil? ? @resource_version : to_ary.last(count)
      end

      def length
        2
      end
      alias size length

      def ==(other)
        to_ary == (Array.try_convert(other) || other)
      end
      alias eql? ==

      def hash
        to_ary.hash
      end

      def to_h
        {
          "items" => @items,
          "resourceVersion" => @resource_version,
          "continue" => @continue_token,
          "remainingItemCount" => @remaining_item_count
        }
      end
    end
  end
end
