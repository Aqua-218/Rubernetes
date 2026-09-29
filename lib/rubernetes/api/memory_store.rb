# frozen_string_literal: true

require "securerandom"
require "base64"
require "json"
require "thread"
require "time"

module Rubernetes
  module API
    # In-process MVCC Store used by the API core and deterministic tests.
    class MemoryStore
      class Error < StandardError
        attr_reader :reason, :code, :details, :resource_version, :compacted_revision

        def initialize(message, reason:, code:, details: nil, resource_version: nil, compacted_revision: nil)
          @reason = reason.to_s
          @code = Integer(code)
          @details = details
          @resource_version = resource_version
          @compacted_revision = compacted_revision
          super(message)
        end
      end

      class NotFound < Error
        def initialize(message = "resource was not found")
          super(message, reason: "NotFound", code: 404)
        end
      end

      class AlreadyExists < Error
        def initialize(message = "resource already exists")
          super(message, reason: "AlreadyExists", code: 409)
        end
      end

      class Conflict < Error
        def initialize(message = "resource version conflict")
          super(message, reason: "Conflict", code: 409)
        end
      end

      class Gone < Error
        def initialize(message = "requested resource version is no longer available",
                       resource_version: nil, compacted_revision: nil)
          details = {}
          details["resourceVersion"] = resource_version.to_s unless resource_version.nil?
          details["compactedRevision"] = compacted_revision.to_s unless compacted_revision.nil?
          super(message, reason: "Gone", code: 410,
                details: details.empty? ? nil : details,
                resource_version: resource_version, compacted_revision: compacted_revision)
        end
      end

      class InvalidSelector < Error
        def initialize(message = "invalid selector", field: nil)
          cause = field && [{"reason" => "FieldValueInvalid", "message" => message.to_s, "field" => field.to_s}]
          super(message, reason: "BadRequest", code: 400,
                details: cause && {"causes" => cause})
        end
      end

      class InvalidContinueToken < Error
        def initialize(message = "invalid continue token")
          super(message, reason: "BadRequest", code: 400,
                details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                         "field" => "continue"}]})
        end
      end

      class InvalidResourceVersion < Error
        def initialize(message = "invalid resource version")
          super(message, reason: "BadRequest", code: 400,
                details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                         "field" => "resourceVersion"}]})
        end
      end

      class InvalidLimit < Error
        def initialize(message = "limit must be a positive integer")
          super(message, reason: "BadRequest", code: 400,
                details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                         "field" => "limit"}]})
        end
      end

      Event = Struct.new(:type, :object, :key, keyword_init: true) do
        def initialize(type:, object:, key: nil)
          super(type: type.to_s, object: deep_freeze(deep_copy(object)), key: key&.to_s&.freeze)
          freeze
        end

        def [](key)
          return type if key.to_s == "type"
          return object if key.to_s == "object"
          nil
        end

        def to_h
          {"type" => type, "object" => deep_copy(object)}
        end

        def self.deep_copy(value)
          case value
          when Hash then value.each_with_object({}) { |(key, item), copy| copy[key] = deep_copy(item) }
          when Array then value.map { |item| deep_copy(item) }
          else value
          end
        end

        def self.deep_freeze(value)
          case value
          when Hash then value.each { |key, item| deep_freeze(key); deep_freeze(item) }
          when Array then value.each { |item| deep_freeze(item) }
          end
          value.freeze
        end

        private

        def deep_copy(value)
          self.class.deep_copy(value)
        end

        def deep_freeze(value)
          self.class.deep_freeze(value)
        end
      end

      ListResult = Struct.new(:items, :resource_version, :continue_token, :remaining_item_count, keyword_init: true) do
        include Enumerable

        def initialize(items:, resource_version:, continue_token: nil, remaining_item_count: nil)
          normalized_items = Array(items)
          super(items: normalized_items.freeze, resource_version: Integer(resource_version).to_s,
                continue_token: continue_token, remaining_item_count: remaining_item_count)
          freeze
        end

        def each(&block)
          items.each(&block)
        end

        def [](index)
          items[index]
        end

        def length
          items.length
        end

        alias size length

        def to_ary
          [items, resource_version]
        end

        def to_a
          items.dup
        end
      end

      # Enumerable stream registered against this store. `each` drains events
      # already available; `next` can block for a newly committed event.
      class Watcher
        include Enumerable

        def initialize(store:, queue:, condition:, mutex:, subscription:, timeout_seconds: nil)
          @store = store
          @queue = queue
          @condition = condition
          @mutex = mutex
          @subscription = subscription
          @timeout_seconds = timeout_seconds
          @closed = false
        end

        def next(timeout: nil)
          effective_timeout = timeout.nil? ? @timeout_seconds : timeout
          deadline = effective_timeout.nil? ? nil :
                     Process.clock_gettime(Process::CLOCK_MONOTONIC) + effective_timeout.to_f
          @mutex.synchronize do
            loop do
              return @queue.shift unless @queue.empty?
              return nil if @closed
              remaining = deadline && deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              return nil if remaining && remaining <= 0
              @condition.wait(@mutex, remaining)
            end
          end
        end

        def each(timeout: :default, &block)
          return enum_for(:each, timeout: timeout) unless block
          effective_timeout = timeout == :default ? (@timeout_seconds || 0) : timeout
          loop do
            event = self.next(timeout: effective_timeout)
            break if event.nil?
            block.call(event)
          end
          self
        end

        def to_a(timeout: :default)
          events = []
          each(timeout: timeout) { |event| events << event }
          events
        end

        def each_json_line(timeout: :default)
          return enum_for(:each_json_line, timeout: timeout) unless block_given?

          each(timeout: timeout) { |event| yield JSON.generate(event.to_h) << "\n" }
          self
        end

        alias events to_a

        def close
          @mutex.synchronize do
            return if @closed
            @closed = true
            @condition.broadcast
          end
          @store.remove_watcher(@subscription)
          nil
        end

        def closed?
          @closed
        end
      end

      DEFAULT_HISTORY_LIMIT = 100_000
      # kube-apiserver runs etcd compaction on a timer
      # (--etcd-compaction-interval, 5m by default).  Revisions older than the
      # previous tick stop being addressable, which is what makes a stale
      # continue token or a stale watch resourceVersion fail with 410 instead
      # of silently returning a different snapshot.
      DEFAULT_COMPACTION_INTERVAL_SECONDS = 300

      def initialize(clock: -> { Time.now.utc }, uid_generator: -> { SecureRandom.uuid }, history_limit: DEFAULT_HISTORY_LIMIT,
                     compaction_interval: DEFAULT_COMPACTION_INTERVAL_SECONDS)
        @clock = clock
        @uid_generator = uid_generator
        @history_limit = Integer(history_limit)
        raise ArgumentError, "history_limit must be positive" unless @history_limit.positive?
        @compaction_interval = compaction_interval.nil? ? nil : Float(compaction_interval)
        raise ArgumentError, "compaction_interval must be positive" if @compaction_interval && !@compaction_interval.positive?
        @mutex = Mutex.new
        @revision = 0
        @objects = {}
        @history = []
        @watchers = {}
        @compacted_revision = 0
        @compaction_floor_candidate = 0
        @last_compaction_at = monotonic_now
      end

      attr_reader :revision

      def resource_version
        @mutex.synchronize { @revision.to_s }
      end

      alias current_resource_version resource_version

      def get(key = nil, gvr: nil, namespace: nil, name: nil, resource_version: nil, **_options)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name)
        @mutex.synchronize do
          ensure_resource_version(resource_version)
          object = @objects[normalized_key]
          raise NotFound, "resource #{normalized_key.inspect} was not found" if object.nil?

          deep_freeze(deep_copy(object))
        end
      end

      def list(prefix = nil, gvr: nil, namespace: :all, selector: nil, label_selector: nil,
               field_selector: nil, resource_version: nil, resource_version_match: nil, limit: nil,
               continue_token: nil, **_options)
        @mutex.synchronize do
          normalized_match = normalize_resource_version_match(resource_version_match)
          normalized_limit = normalize_limit(limit)
          snapshot_revision = resolve_list_revision(resource_version, normalized_match, limit: normalized_limit)
          selector = normalize_selector(selector, label_selector: label_selector, field_selector: field_selector)
          normalized_gvr = gvr && gvr_key(gvr)
          normalized_prefix = prefix && prefix.to_s.sub(%r{\A/}, "")
          objects = @objects.filter_map do |key, object|
            next unless key_matches?(key, normalized_prefix, normalized_gvr, namespace)
            next unless selector.nil? || selector.matches?(object)

            object
          end.sort_by { |object| [metadata_value(object, "namespace").to_s, metadata_value(object, "name").to_s] }
          compact_if_due!
          continuation = decode_continue(continue_token)
          start = continuation.fetch(:offset)
          # A token bound to a snapshot the store has already compacted away
          # cannot be served consistently.  kube-apiserver answers 410 and
          # hands back an "inconsistent" token that resumes at the same
          # position against the current snapshot, which is what clients use
          # to finish the listing.
          if continuation[:revision] && @compacted_revision.positive? && continuation[:revision] <= @compacted_revision
            raise Gone.new("The provided continue parameter is too old to display a consistent list result. " \
                           "You can start a new list without the continue parameter.",
                           resource_version: continuation[:revision], compacted_revision: @compacted_revision)
                  .tap { |error| error.details["continue"] = encode_continue_token(start) if error.details }
          end
          snapshot_revision = continuation[:revision] if continuation[:revision] && normalized_limit
          objects = objects.drop(start) if start.positive?
          selected = normalized_limit.nil? ? objects : objects.first(normalized_limit)
          next_token = if normalized_limit && objects.length > selected.length
                         encode_continue_token(start + selected.length, snapshot_revision)
                       end
          remaining = if normalized_limit && objects.length > selected.length && !selector_filtered?(selector)
                        objects.length - selected.length
                      end
          ListResult.new(items: selected.map { |object| deep_freeze(deep_copy(object)) },
                         resource_version: snapshot_revision, continue_token: next_token,
                         remaining_item_count: remaining)
        end
      end

      def create(key = nil, object = nil, gvr: nil, namespace: nil, name: nil, **_options)
        object = object || _options.delete(:object) || _options.delete(:resource) || _options.delete(:body)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name, object: object)
        @mutex.synchronize do
          raise AlreadyExists, "resource #{normalized_key.inspect} already exists" if @objects.key?(normalized_key)
          stored = prepare_object(object, normalized_key)
          commit(normalized_key, stored, "ADDED")
        end
      end

      def update(key = nil, object = nil, gvr: nil, namespace: nil, name: nil, resource_version: nil, **_options)
        object = object || _options.delete(:object) || _options.delete(:resource) || _options.delete(:body)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name, object: object)
        @mutex.synchronize do
          existing = @objects[normalized_key]
          raise NotFound, "resource #{normalized_key.inspect} was not found" if existing.nil?
          expected = resource_version || metadata_value(object, "resourceVersion")
          check_expected_version!(existing, expected)
          stored = prepare_object(object, normalized_key, existing: existing)
          commit(normalized_key, stored, "MODIFIED")
        end
      end

      alias replace update

      # Optimistic update helper matching the storage contract. The caller's
      # block runs against a detached copy and may be retried after a conflict.
      def guaranteed_update(key = nil, resource_version: nil, max_retries: 8, **options)
        attempts = 0
        loop do
          attempts += 1
          current = get(key, resource_version: resource_version, **options)
          candidate = deep_copy(current)
          candidate = yield(candidate)
          return update(key, candidate, resource_version: metadata_value(current, "resourceVersion"), **options)
        rescue Conflict
          raise if attempts >= Integer(max_retries)

          resource_version = nil
        end
      end

      def delete(key = nil, gvr: nil, namespace: nil, name: nil, resource_version: nil, **_options)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name)
        @mutex.synchronize do
          existing = @objects[normalized_key]
          raise NotFound, "resource #{normalized_key.inspect} was not found" if existing.nil?
          check_expected_version!(existing, resource_version)
          @objects.delete(normalized_key)
          deleted = deep_copy(existing)
          deleted["metadata"] ||= {}
          deleted["metadata"]["resourceVersion"] = next_revision.to_s
          event = Event.new(type: "DELETED", object: deleted, key: normalized_key)
          append_event(event)
          notify_watchers(event)
          deep_freeze(deep_copy(deleted))
        end
      end

      def delete_collection(gvr:, namespace: :all, selector: nil, label_selector: nil, field_selector: nil, **_options)
        keys = @mutex.synchronize do
          normalized_gvr = gvr_key(gvr)
          selector = normalize_selector(selector, label_selector: label_selector, field_selector: field_selector)
          @objects.filter_map do |key, object|
            next unless key_matches?(key, nil, normalized_gvr, namespace)
            next unless selector.nil? || selector.matches?(object)

            key
          end
        end
        keys.map { |key| delete(key) }
      end

      def watch(prefix = nil, gvr: nil, namespace: :all, resource_version: nil, selector: nil,
                label_selector: nil, field_selector: nil, allow_bookmarks: false,
                send_initial_events: false, resource_version_match: nil, timeout_seconds: nil, resource: nil, **_options)
        @mutex.synchronize do
          normalized_match = normalize_resource_version_match(resource_version_match)
          unset_resource_version = resource_version.nil? || resource_version.to_s.empty?
          since = unset_resource_version ? @revision : Integer(resource_version)
          raise InvalidResourceVersion, "resourceVersion must be a non-negative integer" if since.negative?
          raise InvalidResourceVersion, "resourceVersion #{since} is ahead of current revision #{@revision}" if since > @revision
          # "Get State and Start at Any": an unset or zero resourceVersion asks
          # for the current state as synthetic ADDED events before the stream.
          initial_state = send_initial_events || unset_resource_version || since.zero?
          since = @revision if normalized_match == "NotOlderThan" || initial_state
          raise Gone.new("resource version #{since} is older than compacted revision #{@compacted_revision}",
                         resource_version: since, compacted_revision: @compacted_revision) if since < @compacted_revision
          normalized_gvr = gvr && gvr_key(gvr)
          normalized_prefix = prefix && prefix.to_s.sub(%r{\A/}, "")
          selector = normalize_selector(selector, label_selector: label_selector, field_selector: field_selector)
          condition = ConditionVariable.new
          subscription = Object.new
          if initial_state
            # The synthetic ADDED set replaces history replay; replaying both
            # would deliver every retained object twice when resourceVersion=0.
            # The "initial events end" bookmark belongs to sendInitialEvents
            # alone; a plain unset-resourceVersion watch never carries one.
            queue = []
            @objects.keys.sort.each do |key|
              object = @objects.fetch(key)
              next unless key_matches?(key, normalized_prefix, normalized_gvr, namespace)
              next unless selector.nil? || selector.matches?(object)

              queue << Event.new(type: "ADDED", object: object, key: key)
            end
            if send_initial_events && allow_bookmarks
              queue << Event.new(type: "BOOKMARK", object: bookmark_object(resource, initial_events_end: true))
            end
            since = @revision
          elsif allow_bookmarks
            queue = @history.filter_map do |event|
              next unless event.object.fetch("metadata", {}).fetch("resourceVersion", "0").to_i > since
              next unless event_matches?(event, normalized_prefix, normalized_gvr, namespace, selector)

              event
            end
            queue << Event.new(type: "BOOKMARK", object: bookmark_object(resource)) if @revision > since
          else
            queue = @history.filter_map do |event|
              next unless event.object.fetch("metadata", {}).fetch("resourceVersion", "0").to_i > since
              next unless event_matches?(event, normalized_prefix, normalized_gvr, namespace, selector)

              event
            end
          end
          @watchers[subscription] = {condition: condition, queue: queue, prefix: normalized_prefix,
                                     gvr: normalized_gvr, namespace: namespace, selector: selector}
          Watcher.new(store: self, queue: queue, condition: condition, mutex: @mutex, subscription: subscription,
                      timeout_seconds: timeout_seconds)
        end
      rescue ArgumentError, TypeError
        raise InvalidResourceVersion, "resourceVersion must be a non-negative integer"
      end

      def bookmark_object(resource, initial_events_end: false)
        object = {"metadata" => {"resourceVersion" => @revision.to_s}}
        if resource&.respond_to?(:api_version) && resource.respond_to?(:kind)
          object["apiVersion"] = resource.api_version.to_s
          object["kind"] = resource.kind.to_s
        end
        if initial_events_end
          object["metadata"]["annotations"] = {"k8s.io/initial-events-end" => "true"}
        end
        object
      end

      # The revision before which no watch event can be replayed.
      def compacted_revision
        @mutex.synchronize { @compacted_revision }
      end

      def remove_watcher(subscription)
        @mutex.synchronize { @watchers.delete(subscription) }
      end

      # Stored objects per resource key space, as Storage::MemoryStore
      # answers it (apiserver_storage_objects).
      def object_counts
        keys = @mutex.synchronize { @objects.filter_map { |key, object| key unless object.nil? } }
        keys.each_with_object(Hash.new(0)) do |key, counts|
          parts = key.split("/", 5)
          width = parts[1].to_s.match?(/\Av\d/) ? 3 : 4
          next if parts.length < width

          counts[parts.first(width).join("/")] += 1
        end
      end

      private

      def commit(key, object, event_type)
        revision = next_revision
        object = deep_copy(object)
        object["metadata"] ||= {}
        object["metadata"]["resourceVersion"] = revision.to_s
        @objects[key] = object
        event = Event.new(type: event_type, object: object, key: key)
        append_event(event)
        notify_watchers(event)
        deep_freeze(deep_copy(object))
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # Advance the compaction floor once per interval to the revision that
      # was current at the previous tick, so a revision stays addressable for
      # between one and two intervals, as etcd's periodic compaction does.
      # Called with the store mutex held.
      def compact_if_due!
        return unless @compaction_interval

        now = monotonic_now
        return if now - @last_compaction_at < @compaction_interval

        @last_compaction_at = now
        @compacted_revision = [@compacted_revision, @compaction_floor_candidate].max
        @compaction_floor_candidate = @revision
        @history.shift while @history.first && event_revision(@history.first) <= @compacted_revision
      end

      def event_revision(event)
        object = event.respond_to?(:object) ? event.object : nil
        return 0 unless object.is_a?(Hash)

        object.fetch("metadata", {}).fetch("resourceVersion", "0").to_i
      end

      def append_event(event)
        @history << event
        while @history.length > @history_limit
          dropped = @history.shift
          @compacted_revision = [@compacted_revision, dropped.object.fetch("metadata", {}).fetch("resourceVersion", "0").to_i].max
        end
      end

      def notify_watchers(event)
        @watchers.each_value do |watcher|
          if event_matches?(event, watcher[:prefix], watcher[:gvr], watcher[:namespace], watcher[:selector])
            watcher[:queue] << event
          end
          watcher[:condition].broadcast
        end
      end

      def next_revision
        @revision += 1
      end

      def event_matches?(event, prefix, normalized_gvr, namespace, selector)
        return false if event.type == "BOOKMARK"
        key = event.key || key_for_object(event.object)
        key_matches?(key, prefix, normalized_gvr, namespace) && (selector.nil? || selector.matches?(event.object))
      end

      def key_matches?(key, prefix, normalized_gvr, namespace)
        parts = key.to_s.split("/")
        return false unless parts.length >= 4 && parts[0] == "registry"
        return false if prefix && !(key == prefix || key.start_with?("#{prefix}/"))
        stored_gvr = parts[1...-2].join("/")
        return false if normalized_gvr && stored_gvr != normalized_gvr
        expected_namespace = namespace == :cluster ? "_cluster" : namespace.to_s
        return false unless namespace == :all || namespace.nil? || parts[-2] == expected_namespace

        true
      end

      def key_for(key = nil, gvr: nil, namespace: nil, name: nil, object: nil)
        if key
          if key.to_s.start_with?("/registry/") || key.to_s.start_with?("registry/")
            return key.to_s.sub(%r{\A/}, "")
          end
          if key.respond_to?(:to_s) && key.to_s.count("/") == 3
            return key.to_s.sub(%r{\A/}, "")
          end
        end
        resource = gvr || key
        resource_key = gvr_key(resource)
        namespace = metadata_value(object, "namespace") if namespace.nil? && object
        name = metadata_value(object, "name") if name.nil? && object
        namespace = "_cluster" if namespace.nil? || namespace == :cluster
        raise ArgumentError, "storage key requires resource and name" if resource_key.empty? || name.to_s.empty?

        "registry/#{resource_key}/#{namespace}/#{name}"
      end

      def key_for_object(object)
        metadata = object.fetch("metadata", {})
        resource = object.fetch("_rubernetes_resource", nil)
        resource ||= object.fetch("apiVersion", "v1")
        resource = resource.to_s
        key_for("registry/#{resource}/#{metadata.fetch("namespace", "_cluster")}/#{metadata.fetch("name")}")
      end

      def gvr_key(value)
        return "" if value.nil?
        if value.is_a?(Hash)
          group = value[:group] || value["group"] || ""
          version = value[:version] || value["version"] || "v1"
          resource = value[:resource] || value["resource"] || value[:name] || value["name"]
          return "#{group.to_s.empty? ? version : "#{group}/#{version}"}/#{resource}" if resource
        end
        if value.respond_to?(:gvr)
          return gvr_key(value.gvr)
        end
        if value.respond_to?(:group_version) && value.respond_to?(:resource)
          return "#{value.group_version}/#{value.resource}"
        end
        if value.respond_to?(:group) && value.respond_to?(:version) && value.respond_to?(:resource)
          group = value.group.to_s
          return "#{group.empty? ? value.version : "#{group}/#{value.version}"}/#{value.resource}"
        end
        value.to_s.sub(%r{\A/}, "").sub(%r{\Aregistry/}, "").sub(%r{/\z}, "")
      end

      def prepare_object(object, key, existing: nil)
        raise ArgumentError, "resource object must be a Hash" unless object.is_a?(Hash)
        prepared = deep_copy(object)
        prepared.delete("_rubernetes_resource")
        metadata = prepared["metadata"] ||= {}
        metadata = metadata.transform_keys(&:to_s)
        prepared["metadata"] = metadata
        key_parts = key.split("/")
        metadata["name"] ||= key_parts.last
        metadata["namespace"] ||= key_parts[-2] unless key_parts[-2] == "_cluster"
        if existing
          metadata["uid"] = metadata_value(existing, "uid") if metadata_value(existing, "uid")
          metadata["creationTimestamp"] = metadata_value(existing, "creationTimestamp") if metadata_value(existing, "creationTimestamp")
        else
          metadata["uid"] ||= @uid_generator.call.to_s
          metadata["creationTimestamp"] ||= @clock.call.utc.iso8601(6)
        end
        metadata.delete("resourceVersion") if existing.nil?
        prepared
      end

      def check_expected_version!(existing, expected)
        return if expected.nil? || expected.to_s.empty?
        actual = metadata_value(existing, "resourceVersion").to_s
        raise Conflict, "resourceVersion #{expected.inspect} does not match current #{actual.inspect}" unless expected.to_s == actual
      end

      def ensure_resource_version(value)
        return if value.nil? || value.to_s.empty?
        requested = Integer(value)
        raise InvalidResourceVersion, "resource version must be non-negative" if requested.negative?
        raise InvalidResourceVersion, "resource version #{requested} is newer than current #{@revision}" if requested > @revision
      rescue ArgumentError
        raise InvalidResourceVersion, "resourceVersion #{value.inspect} is not an integer"
      end

      def normalize_resource_version_match(value)
        return nil if value.nil? || value.to_s.empty?
        normalized = value.to_s
        return normalized if %w[Exact NotOlderThan].include?(normalized)

        raise InvalidResourceVersion, "resourceVersionMatch must be Exact or NotOlderThan"
      end

      def resolve_list_revision(value, match, limit: nil)
        return @revision if value.nil? || value.to_s.empty? || value.to_s == "0"

        requested = Integer(value)
        raise InvalidResourceVersion, "resource version must be non-negative" if requested.negative?
        raise InvalidResourceVersion, "resource version #{requested} is newer than current #{@revision}" if requested > @revision
        return @revision if match.to_s == "NotOlderThan"
        return requested if match.to_s == "Exact" || (limit && limit.positive?)

        @revision
      rescue ArgumentError, TypeError
        raise MemoryStore::InvalidResourceVersion, "resourceVersion #{value.inspect} is not an integer"
      end

      def normalize_limit(value)
        return nil if value.nil? || value.to_s.empty?

        limit = Integer(value)
        return nil if limit.zero?
        raise ArgumentError, "limit must be non-negative" if limit.negative?

        limit
      rescue ArgumentError, TypeError
        raise InvalidLimit, "limit must be a non-negative integer"
      end

      def normalize_selector(selector, label_selector:, field_selector:)
        return selector if selector.respond_to?(:matches?)
        return nil if selector.nil? && label_selector.nil? && field_selector.nil?
        Selectors.new(label: selector, label_selector: label_selector, field_selector: field_selector)
      end

      def selector_filtered?(selector)
        selector.respond_to?(:empty?) ? !selector.empty? : !selector.nil?
      end

      def metadata_value(object, name)
        metadata = object.is_a?(Hash) ? (object["metadata"] || object[:metadata] || {}) : {}
        metadata[name] || metadata[name.to_sym]
      end

      # A continue token carries the snapshot it belongs to as well as the
      # position, the way kube-apiserver's does: paging must observe one
      # consistent snapshot, and a token whose snapshot has been compacted
      # away has to be rejected with 410 rather than silently answered from a
      # newer state.  The legacy offset-only form is still accepted.
      def encode_continue_token(offset, revision = nil)
        return [Integer(offset)].pack("N").unpack1("H*") if revision.nil?

        payload = JSON.generate({"v" => 1, "rv" => Integer(revision), "start" => Integer(offset)})
        Base64.urlsafe_encode64(payload, padding: false)
      end

      def decode_continue_token(token)
        decode_continue(token).fetch(:offset)
      end

      # [offset, revision] for a token; revision is nil for the legacy form
      # and for an inconsistent token (one that resumes at a position but
      # against a fresh snapshot).
      def decode_continue(token)
        return {offset: 0, revision: nil} if token.nil? || token.to_s.empty?

        encoded = token.to_s
        return {offset: legacy_continue_offset(encoded), revision: nil} if encoded.match?(/\A[0-9a-f]{8}\z/i)

        document = begin
          JSON.parse(Base64.urlsafe_decode64(encoded))
        rescue ArgumentError, JSON::ParserError
          raise InvalidContinueToken
        end
        raise InvalidContinueToken unless document.is_a?(Hash) && document["v"].to_i == 1

        offset = Integer(document.fetch("start", 0))
        raise InvalidContinueToken if offset.negative?

        {offset: offset, revision: document["rv"] && Integer(document["rv"])}
      rescue TypeError
        raise InvalidContinueToken
      end

      def legacy_continue_offset(encoded)
        [encoded].pack("H*").unpack1("N")
      rescue ArgumentError, TypeError
        raise InvalidContinueToken
      end

      def deep_copy(value)
        case value
        when Hash then value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = deep_copy(item) }
        when Array then value.map { |item| deep_copy(item) }
        else value
        end
      end

      def deep_freeze(value)
        case value
        when Hash
          value.each { |key, item| deep_freeze(key); deep_freeze(item) }
        when Array
          value.each { |item| deep_freeze(item) }
        end
        value.freeze
      end
    end
  end
end
