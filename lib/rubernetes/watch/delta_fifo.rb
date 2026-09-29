# frozen_string_literal: true

require "thread"
require_relative "support"

module Rubernetes
  module Watch
    # Key-coalescing FIFO that retains every delta observed while a consumer
    # processes a key.  The order is key-fair, while each key's deltas remain
    # in arrival order so an update/delete pair cannot be lost.
    class DeltaFIFO
      Delta = Struct.new(:type, :key, :object, :old_object, :resource_version, keyword_init: true) do
        def initialize(type:, key:, object: nil, old_object: nil, resource_version: nil)
          normalized_type = type.respond_to?(:to_sym) ? type.to_sym : nil
          raise ArgumentError, "delta type must be a symbol or string" unless normalized_type
          unless DeltaFIFO::VALID_TYPES.include?(normalized_type)
            raise ArgumentError, "unknown delta type #{type.inspect}"
          end
          normalized_key = String(key)
          raise ArgumentError, "delta key must not be empty" if normalized_key.empty?

          super(
            type: normalized_type,
            key: normalized_key.freeze,
            object: DeltaFIFO.immutable_copy(object),
            old_object: DeltaFIFO.immutable_copy(old_object),
            resource_version: resource_version.nil? ? nil : String(resource_version).freeze
          )
          freeze
        end

        def to_h
          {
            type: type,
            key: key,
            object: DeltaFIFO.deep_copy(object),
            old_object: DeltaFIFO.deep_copy(old_object),
            resource_version: resource_version
          }
        end
      end

      VALID_TYPES = %i[add update delete sync].freeze

      def self.deep_copy(value)
        Support.deep_copy(value)
      end

      def self.immutable_copy(value)
        Support.immutable_copy(value)
      end

      def initialize(key_func: nil, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        raise ArgumentError, "key_func must respond to call" if key_func && !key_func.respond_to?(:call)
        raise ArgumentError, "clock must respond to call" unless clock.respond_to?(:call)

        @key_func = key_func || Support.method(:object_key)
        @clock = clock
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @items = {}
        @order = []
        @queued = {}
        # informer_processing_latency_seconds: when each queued key was first
        # queued (until it is popped) and, once popped, until it is done.
        @enqueued_at = {}
        @popped_age = {}
        @processing = {}
        @latest = {}
        @resource_version = nil
        @has_synced = false
        @closed = false
      end

      attr_reader :clock

      def resource_version
        @mutex.synchronize { @resource_version }
      end

      def add(object, resource_version: nil)
        enqueue(:add, object, resource_version: resource_version)
      end

      def update(object, old_object: nil, resource_version: nil)
        enqueue(:update, object, old_object: old_object, resource_version: resource_version)
      end

      def delete(object, resource_version: nil)
        enqueue(:delete, object, resource_version: resource_version)
      end

      def sync(object, resource_version: nil)
        enqueue(:sync, object, resource_version: resource_version)
      end

      # Queue a complete list snapshot.  Existing keys absent from the list
      # become deletes; listed objects become sync deltas.  All validation is
      # done before the mutex is acquired so malformed lists cannot partially
      # replace a cache.
      def replace(objects, resource_version: nil)
        incoming = Array(objects).map { |object| Support.deep_copy(object) }
        incoming_by_key = {}
        incoming.each do |object|
          key = key_for(object)
          raise ArgumentError, "replace contains duplicate key #{key.inspect}" if incoming_by_key.key?(key)

          incoming_by_key[key] = object
        end
        version = resource_version.nil? ? nil : String(resource_version).freeze

        @mutex.synchronize do
          ensure_open_locked!
          existing_keys = @latest.keys | @items.keys | @processing.keys
          (existing_keys - incoming_by_key.keys).each do |key|
            next if @latest[key].nil?

            append_locked(Delta.new(type: :delete, key: key, object: @latest[key], resource_version: version))
          end
          incoming_by_key.each do |key, object|
            append_locked(Delta.new(type: :sync, key: key, object: object, resource_version: version))
          end
          @resource_version = version if Support.version_newer?(version, @resource_version)
          signal_locked
        end
        self
      end

      alias replace! replace

      # Return one key and all deltas accumulated for it.  A nil timeout waits
      # indefinitely; timeout 0 is a non-blocking poll.
      def pop(timeout = nil, **options)
        timeout = options.fetch(:timeout, timeout)
        timeout_value = timeout.nil? ? nil : validate_timeout(timeout)
        deadline = timeout_value.nil? ? nil : @clock.call + timeout_value
        wall_deadline = timeout_value.nil? ? nil : Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout_value
        @mutex.synchronize do
          loop do
            key = shift_ready_key_locked
            if key
              @processing[key] = true
              deltas = @items.delete(key) || []
              queued_at = @enqueued_at.delete(key)
              @popped_age[key] = queued_at ? [queued_at, @clock.call] : nil
              return [key, deltas.freeze]
            end
            return nil if @closed
            return nil if deadline && (@clock.call >= deadline || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= wall_deadline)

            wait_locked(deadline, wall_deadline)
          end
        end
      end

      def done(key)
        normalized = normalize_key(key)
        @mutex.synchronize do
          @processing.delete(normalized)
          # Events that arrived while the caller was processing the key stay
          # pending and must be made visible exactly once after completion.
          if @closed
            @items.delete(normalized)
            @queued.delete(normalized)
          else
            enqueue_order_locked(normalized) if @items.key?(normalized)
          end
          signal_locked
        end
        self
      end

      def requeue(key, deltas)
        normalized = normalize_key(key)
        normalized_deltas = Array(deltas).map { |delta| normalize_delta(delta, normalized) }
        @mutex.synchronize do
          ensure_open_locked!
          @processing.delete(normalized)
          existing = @items[normalized] || []
          @items[normalized] = normalized_deltas + existing
          (@items[normalized]).each { |delta| update_latest_locked(delta) }
          @has_synced ||= normalized_deltas.any? { |delta| delta.type == :sync }
          enqueue_order_locked(normalized)
          signal_locked
        end
        self
      end

      def has_synced?
        @mutex.synchronize { @has_synced }
      end

      def length
        @mutex.synchronize { @order.length }
      end

      alias size length

      def processing?
        @mutex.synchronize { !@processing.empty? }
      end

      def empty?
        length.zero?
      end

      def keys
        @mutex.synchronize { @order.dup.freeze }
      end

      def pending?(key)
        normalized = normalize_key(key)
        @mutex.synchronize { @items.key?(normalized) || @processing.key?(normalized) }
      end

      def shutdown
        @mutex.synchronize do
          @closed = true
          @items.clear
          @order.clear
          @queued.clear
          @latest.clear
          @condition.broadcast
        end
        self
      end

      alias shut_down shutdown
      alias close shutdown

      def shutdown?
        @mutex.synchronize { @closed }
      end

      alias closed? shutdown?
      alias shut_down? shutdown?

      private

      def enqueue(type, object, old_object: nil, resource_version: nil)
        normalized_type = type.respond_to?(:to_sym) ? type.to_sym : nil
        raise ArgumentError, "unknown delta type #{type.inspect}" unless VALID_TYPES.include?(normalized_type)

        snapshot = Support.deep_copy(object)
        key = key_for(snapshot)
        version = resource_version || Support.resource_version(snapshot)
        delta = Delta.new(type: normalized_type, key: key, object: snapshot, old_object: old_object,
                          resource_version: version)
        @mutex.synchronize do
          ensure_open_locked!
          append_locked(delta)
          @resource_version = version.to_s.freeze if version && Support.version_newer?(version.to_s, @resource_version)
          signal_locked
        end
        self
      end

      def append_locked(delta)
        key = delta.key
        @items[key] ||= []
        @items[key] << delta
        update_latest_locked(delta)
        @has_synced = true if delta.type == :sync
        enqueue_order_locked(key) unless @processing.key?(key)
      end

      def update_latest_locked(delta)
        if delta.type == :delete
          @latest.delete(delta.key)
        else
          @latest[delta.key] = delta.object
        end
      end

      def enqueue_order_locked(key)
        return if @queued.key?(key)

        @queued[key] = true
        @order << key
      end

      def shift_ready_key_locked
        key = @order.shift
        @queued.delete(key) if key
        key
      end

      def normalize_delta(delta, key)
        return delta if delta.is_a?(Delta) && delta.key == key

        hash = delta.respond_to?(:to_h) ? delta.to_h : {}
        type = hash[:type] || hash["type"] || :sync
        Delta.new(
          type: type,
          key: key,
          object: hash[:object] || hash["object"],
          old_object: hash[:old_object] || hash["old_object"],
          resource_version: hash[:resource_version] || hash["resource_version"] || hash["resourceVersion"]
        )
      end

      def key_for(object)
        key = @key_func.call(object)
        normalized = String(key)
        raise ArgumentError, "delta key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "delta key must be coercible to String"
      rescue StandardError => error
        raise ArgumentError, "failed to derive delta key: #{error.message}"
      end

      def normalize_key(key)
        normalized = String(key)
        raise ArgumentError, "delta key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "delta key must be coercible to String"
      end

      def validate_timeout(timeout)
        value = Float(timeout)
        raise ArgumentError, "timeout must be a non-negative finite number" if value.negative? || !value.finite?

        value
      rescue TypeError, ArgumentError
        raise ArgumentError, "timeout must be a non-negative number"
      end

      def ensure_open_locked!
        raise IOError, "DeltaFIFO is shut down" if @closed
      end

      def signal_locked
        @condition.broadcast
      end

      def wait_locked(deadline, wall_deadline)
        return @condition.wait(@mutex) if deadline.nil?

        remaining = deadline - @clock.call
        remaining = [remaining, wall_deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)].min
        return if remaining <= 0

        @condition.wait(@mutex, remaining)
      end
    end

    DeltaQueue = DeltaFIFO unless const_defined?(:DeltaQueue, false)
  end
end
