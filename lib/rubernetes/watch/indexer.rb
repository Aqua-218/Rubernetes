# frozen_string_literal: true

require_relative "support"

module Rubernetes
  module Watch
    # Thread-safe local cache with immutable reads and deterministic secondary
    # indexes.  The mutex protects the object map and every index as one unit;
    # callers therefore never observe an object whose index update is partial.
    class Indexer
      def initialize(key_func: nil, indices: {}, freeze_objects: true)
        raise ArgumentError, "key_func must respond to call" if key_func && !key_func.respond_to?(:call)
        raise ArgumentError, "indices must be a Hash" unless indices.is_a?(Hash)
        raise ArgumentError, "freeze_objects must be true" unless freeze_objects == true

        @key_func = key_func || Support.method(:object_key)
        @freeze_objects = true
        @mutex = Mutex.new
        @objects = {}
        @indices = {}
        indices.each { |name, function| add_index(name, &function) }
      end

      # Register a secondary index.  Replacing an index in a live cache would
      # make concurrent listers disagree about ownership, so duplicate names
      # fail closed instead of silently changing query semantics.
      def add_index(name, &function)
        raise ArgumentError, "index function is required" unless function&.respond_to?(:call)

        index_name = normalize_index_name(name)
        loop do
          objects = @mutex.synchronize do
            raise ArgumentError, "index #{index_name.inspect} is already registered" if @indices.key?(index_name)

            @objects.dup
          end
          values = Hash.new { |hash, key| hash[key] = {} }
          objects.each { |key, object| add_index_values_locked(values, key, yield(object)) }
          registered = @mutex.synchronize do
            raise ArgumentError, "index #{index_name.inspect} is already registered" if @indices.key?(index_name)
            next false unless @objects.keys == objects.keys && objects.all? { |key, object| @objects[key].equal?(object) }

            @indices[index_name] = {function: function, values: values}
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
        value = copy_for_storage(object)
        key = key_for(value)
        loop do
          index_values = build_index_values(value)
          result = @mutex.synchronize do
            if index_values.keys.sort == @indices.keys.sort
              raise KeyError, "object #{key.inspect} already exists" if !replace && @objects.key?(key)

              remove_indexes_locked(key)
              @objects[key] = value
              invalidate_list_locked
              @indices.each_key do |name|
                add_index_values_locked(@indices.fetch(name).fetch(:values), key, index_values.fetch(name))
              end
              read_copy(value)
            end
          end
          return result unless result.nil?
        end
      end

      # Replace the cache with one list snapshot.  This is used by relist and
      # intentionally validates duplicate keys before changing any state.
      def replace_all(objects)
        incoming = Array(objects).map { |object| copy_for_storage(object) }
        keyed = {}
        incoming.each do |object|
          key = key_for(object)
          raise ArgumentError, "replace_all contains duplicate object keys" if keyed.key?(key)

          keyed[key] = object
        end

        loop do
          prepared = keyed.transform_values { |object| [object, build_index_values(object)] }
          replaced = @mutex.synchronize do
            index_names = @indices.keys.sort
            prepared_names = prepared.values.first ? prepared.values.first.last.keys.sort : index_names
            next false unless index_names == prepared_names

            @objects.clear
            invalidate_list_locked
            @indices.each_value { |index| index.fetch(:values).clear }
            prepared.each do |key, (object, values)|
              @objects[key] = object
              @indices.each_key do |name|
                add_index_values_locked(@indices.fetch(name).fetch(:values), key, values.fetch(name))
              end
            end
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

          remove_indexes_locked(key)
          read_copy(existing)
        end
      end

      def get(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @objects.key?(normalized) ? read_copy(@objects.fetch(normalized)) : nil }
      end

      alias fetch get
      alias get_by_key get

      def include?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @objects.key?(normalized) }
      end

      alias key? include?

      # The sorted list is memoised until the next mutation.  Every controller
      # that routes an event lists a kind from here -- a Pod event lists
      # Services, Pods, ReplicaSets ... once per controller -- and re-sorting
      # three thousand Pods per call put the Pod informer 90 events and 20 s
      # behind during a rollout, so a DaemonSet controller reading stale
      # readiness deleted every old Pod at once ("Daemon set should rollback
      # without unnecessary restarts").  Stored values are frozen and replaced
      # rather than edited, so handing out one frozen array is safe.
      def list
        cached, version, objects = @mutex.synchronize { [@sorted_list, @list_version, @objects.values.dup] }
        return cached if cached

        # Key functions run outside the mutex (a custom one may read the
        # cache); the result is kept only if nothing changed meanwhile.
        sorted = objects.sort_by { |object| key_for(object) }.map { |value| read_copy(value) }.freeze
        @mutex.synchronize { @sorted_list = sorted if @list_version == version }
        sorted
      end

      def invalidate_list_locked
        @sorted_list = nil
        @list_version = (@list_version || 0) + 1
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
          @indices.each_value { |index| index.fetch(:values).clear }
        end
        self
      end

      def by_index(index_name, lookup_key)
        name = normalize_index_name(index_name)
        value = normalize_index_value(lookup_key)
        @mutex.synchronize do
          index = @indices.fetch(name) { raise KeyError, "unknown index #{index_name.inspect}" }
          keys = index.fetch(:values).fetch(value, {}).keys.sort
          keys.map { |key| read_copy(@objects.fetch(key)) }.freeze
        end
      end

      alias index_get by_index

      def index_names
        @mutex.synchronize { @indices.keys.sort.freeze }
      end

      # Return a detached immutable mapping suitable for diagnostics or a
      # resync source.  It is never the mutable internal object map.
      def snapshot
        @mutex.synchronize do
          Support.immutable_copy(@objects.transform_values { |value| Support.deep_copy(value) })
        end
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
        copy = Support.deep_copy(object)
        @freeze_objects ? Support.immutable_copy(copy) : copy
      rescue StandardError => error
        raise ArgumentError, "failed to copy indexed object: #{error.message}"
      end

      # Stored values are deep-frozen copies nobody else holds (see
      # copy_for_storage), so a reader can be handed the stored value itself:
      # it cannot change it, and the cache replaces rather than edits entries.
      # Copying and re-freezing on every read made a 3000-Pod list take
      # 0.75 s, and the controllers list from here on every reconcile -- the
      # endpointslice controller spent 1.06 s per Service and
      # "[sig-network] Service endpoints latency should not be very high"
      # measured a 29 s median.
      def read_copy(object)
        return object if @freeze_objects && object.frozen?

        copy = Support.deep_copy(object)
        @freeze_objects ? Support.immutable_copy(copy) : copy
      end

      def build_index_values(object)
        functions = @mutex.synchronize { @indices.transform_values { |index| index.fetch(:function) } }
        functions.transform_values do |function|
          Array(function.call(object)).compact.map(&:to_s).uniq.freeze
        end
      end

      def add_index_values_locked(values, key, raw_values)
        Array(raw_values).compact.each { |value| values[value.to_s][key] = true }
      end

      def remove_indexes_locked(key)
        @indices.each_value do |index|
          index.fetch(:values).each_value { |keys| keys.delete(key) }
        end
      end
    end

    WatchCache = Indexer unless const_defined?(:WatchCache, false)
    ThreadSafeStore = Indexer unless const_defined?(:ThreadSafeStore, false)
  end
end
