# frozen_string_literal: true

require_relative "support"

module Rubernetes
  module Watch
    # Thread-safe local cache with immutable reads and deterministic secondary
    # indexes.  The mutex protects the object map and every index as one unit;
    # callers therefore never observe an object whose index update is partial.
    class Indexer
      # Keep each object's memberships so changing one Pod never scans other
      # Pods' buckets. User callbacks run before any index mutation.
      class SecondaryIndex
        def initialize(function)
          @function = function
          @buckets = {}
          @memberships = {}
        end

        def values_for(object)
          Array(@function.call(object)).compact.map { |value| -value.to_s }.uniq
        end

        def replace(key, values)
          return if @memberships[key] == values

          delete(key)
          return if values.empty?

          @memberships[key] = values
          values.each { |value| (@buckets[value] ||= {})[key] = true }
        end

        def delete(key)
          @memberships.delete(key)&.each do |value|
            bucket = @buckets.fetch(value)
            bucket.delete(key)
            @buckets.delete(value) if bucket.empty?
          end
        end

        def keys_for(value) = @buckets.fetch(value, {}).keys

        def clear
          @buckets.clear
          @memberships.clear
        end
      end
      private_constant :SecondaryIndex

      def initialize(key_func: nil, indices: {}, freeze_objects: true)
        raise ArgumentError, "key_func must respond to call" if key_func && !key_func.respond_to?(:call)
        raise ArgumentError, "indices must be a Hash" unless indices.is_a?(Hash)
        raise ArgumentError, "freeze_objects must be true" unless freeze_objects == true

        @key_func = key_func || Support.method(:object_key)
        @metadata_keys = @key_func == Support.method(:object_key)
        @mutex = Mutex.new
        @objects = {}
        @indices = {}
        @list_version = 0
        indices.each { |name, function| add_index(name, &function) }
      end

      # Register a secondary index.  Replacing an index in a live cache would
      # make concurrent listers disagree about ownership, so duplicate names
      # fail closed instead of silently changing query semantics.
      def add_index(name, &function)
        raise ArgumentError, "index function is required" unless function

        index_name = normalize_index_name(name)
        loop do
          objects, version = @mutex.synchronize do
            raise ArgumentError, "index #{index_name.inspect} is already registered" if @indices.key?(index_name)

            [@objects.dup, @list_version]
          end
          index = SecondaryIndex.new(function)
          objects.each { |key, object| index.replace(key, index.values_for(object)) }
          registered = @mutex.synchronize do
            raise ArgumentError, "index #{index_name.inspect} is already registered" if @indices.key?(index_name)
            next false unless version == @list_version

            @indices = @indices.merge(index_name => index)
            true
          end
          break if registered
        end
        self
      end

      def add(object)
        upsert(object, replace: false)
      end

      def update(object)
        upsert(object, replace: true)
      end

      def replace(object_or_objects)
        object_or_objects.is_a?(Array) ? replace_all(object_or_objects) : update(object_or_objects)
      end

      alias replace! replace
      alias add_indexer add_index

      # Upsert an object atomically with all secondary indexes.  Index
      # functions run before acquiring the cache mutex so an application
      # callback cannot deadlock the cache by recursively reading it.
      def upsert(object, replace: true)
        write_object(object) do |key|
          raise KeyError, "object #{key.inspect} already exists" if !replace && @objects.key?(key)
        end
      end

      # Bring an entry that is there up to `object`, a version of it that is
      # not older; never create one.  This is what a writer's own response
      # may do to the cache: the watch alone says what exists, so a response
      # that arrives after the object's DELETED event must not put the object
      # back.  Answers whether the entry was replaced.
      def refresh(object)
        write_object(object) do |key, value|
          current = @objects[key]
          return false if current.nil? || Support.version_newer?(Support.resource_version(current), Support.resource_version(value))
        end
        true
      end

      # Replace the cache with one list snapshot.  This is used by relist and
      # intentionally validates duplicate keys before changing any state.
      def replace_all(objects)
        keyed = {}
        Array(objects).each do |input|
          object = copy_for_storage(input)
          key = key_for(object)
          raise ArgumentError, "replace_all contains duplicate object keys" if keyed.key?(key)

          keyed[key] = object
        end

        loop do
          indices = @mutex.synchronize { @indices }
          values = keyed.transform_values { |object| build_index_values(indices, object) }
          replaced = @mutex.synchronize do
            next false unless indices.equal?(@indices)

            @objects = keyed
            indices.each_value(&:clear)
            values.each { |key, entries| index_object_locked(key, entries) }
            invalidate_list_locked
            true
          end
          break if replaced
        end
        list
      end

      alias replace_all! replace_all

      def delete(object_or_key)
        key = key_for_argument(object_or_key)
        @mutex.synchronize do
          return nil unless @objects.key?(key)

          existing = @objects.delete(key)
          invalidate_list_locked

          @indices.each_value { |index| index.delete(key) }
          existing
        end
      end

      def metadata_keys? = @metadata_keys

      def get(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @objects[normalized] }
      end

      alias fetch get
      alias get_by_key get

      def include?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @objects.key?(normalized) }
      end

      alias key? include?

      # Controllers share one sorted list per cache revision. Sort a snapshot
      # outside the mutex so writers can continue while a reader builds it.
      def list
        objects, version = @mutex.synchronize do
          return @sorted_list if @sorted_list

          [@objects.dup, @list_version]
        end
        sorted = objects.values_at(*objects.keys.sort).freeze
        @mutex.synchronize { @sorted_list = sorted if @list_version == version }
        sorted
      end

      def invalidate_list_locked
        @sorted_list = nil
        @list_version += 1
      end

      alias values list
      alias objects list

      def each(&)
        return enum_for(__method__) unless block_given?

        list.each(&)
        self
      end

      def size
        @mutex.synchronize { @objects.size }
      end

      alias length size

      def empty?
        size.zero?
      end

      def keys
        @mutex.synchronize { @objects.keys.sort.freeze }
      end

      def clear
        @mutex.synchronize do
          @objects.clear
          invalidate_list_locked
          @indices.each_value(&:clear)
        end
        self
      end

      def by_index(index_name, lookup_key)
        by_index_values(index_name, [lookup_key])
      end

      # Resolve a union against one cache revision; a concurrent selector
      # change cannot move an object between two reads of individual buckets.
      def by_index_values(index_name, lookup_keys)
        name = normalize_index_name(index_name)
        values = lookup_keys.map { |key| normalize_index_value(key) }
        @mutex.synchronize do
          index = @indices.fetch(name) { raise KeyError, "unknown index #{index_name.inspect}" }
          keys = values.flat_map { |value| index.keys_for(value) }.uniq.sort
          @objects.values_at(*keys).freeze
        end
      end

      alias index_get by_index

      def index_names
        @mutex.synchronize { @indices.keys.sort.freeze }
      end

      # Return a detached immutable mapping suitable for diagnostics or a
      # resync source.  It is never the mutable internal object map.
      def snapshot
        @mutex.synchronize { @objects.dup.freeze }
      end

      private

      def normalize_index_name(name)
        normalized = String(name)
        raise ArgumentError, "index name must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "index name must be coercible to String"
      end

      def normalize_key(key)
        normalized = String(key)
        raise ArgumentError, "index key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "index key must be coercible to String"
      end

      def normalize_index_value(value)
        raise ArgumentError, "index lookup value must not be nil" if value.nil?

        value.to_s.freeze
      end

      def key_for(object)
        normalize_key(@key_func.call(object))
      rescue ArgumentError => error
        raise error
      rescue StandardError => error
        raise ArgumentError, "failed to derive index key: #{error.message}"
      end

      def key_for_argument(object_or_key)
        if object_or_key.is_a?(String) || object_or_key.is_a?(Symbol)
          normalize_key(object_or_key)
        else
          key_for(object_or_key)
        end
      end

      def copy_for_storage(object)
        Support.immutable_copy(object)
      rescue StandardError => error
        raise ArgumentError, "failed to copy indexed object: #{error.message}"
      end

      # add_index publishes a new registry. If one appeared while the index
      # callbacks ran outside the lock, compute its entries before committing.
      def write_object(object)
        value = copy_for_storage(object)
        key = key_for(value)
        loop do
          indices = @mutex.synchronize { @indices }
          entries = build_index_values(indices, value)
          @mutex.synchronize do
            next unless indices.equal?(@indices)

            yield(key, value)
            @objects[key] = value
            index_object_locked(key, entries)
            invalidate_list_locked
            return value
          end
        end
      end

      def build_index_values(indices, object)
        indices.transform_values { |index| index.values_for(object) }
      end

      def index_object_locked(key, entries)
        entries.each { |name, values| @indices.fetch(name).replace(key, values) }
      end
    end

    WatchCache = Indexer unless const_defined?(:WatchCache, false)
    ThreadSafeStore = Indexer unless const_defined?(:ThreadSafeStore, false)
  end
end
