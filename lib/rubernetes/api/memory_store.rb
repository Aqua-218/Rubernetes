# frozen_string_literal: true

require_relative "../support/object_tree"

require "securerandom"
require "base64"
require "json"
require "time"
require_relative "../watch/event_stream"
require_relative "object_copy"
require_relative "memory_store/sharding"
require_relative "memory_store/history"

module Rubernetes
  module API
    # In-process MVCC Store used by the API core and deterministic tests.
    class MemoryStore
      include ObjectCopy
      include Sharding

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

      Event = Struct.new(:type, :object, :key, :old_object, keyword_init: true) do
        def initialize(type:, object:, key: nil, old_object: nil, stringify_keys: false)
          copy = self.class.deep_copy(object, stringify_keys: stringify_keys)
          yield copy if block_given?
          super(type: type.to_s, object: self.class.deep_freeze(copy), key: key&.to_s&.freeze,
                old_object: self.class.deep_freeze(old_object))
          freeze
        end

        def [](key)
          return type if key.to_s == "type"
          return object if key.to_s == "object"

          nil
        end

        def to_h
          {"type" => type, "object" => self.class.deep_copy(object)}
        end

        def self.deep_copy(value, stringify_keys: false)
          case value
          when Hash
            copy = {}
            value.each_pair { |key, item| copy[stringify_keys ? key.to_s : key] = deep_copy(item, stringify_keys: stringify_keys) }
            copy
          when Array then value.map { |item| deep_copy(item, stringify_keys: stringify_keys) }
          when String then value.frozen? ? value : value.dup
          else value
          end
        end

        def self.deep_freeze(value) = ObjectTree.deep_freeze(value)
      end

      ListResult = Struct.new(:items, :resource_version, :continue_token, :remaining_item_count, keyword_init: true) do
        include Enumerable

        def initialize(items:, resource_version:, continue_token: nil, remaining_item_count: nil)
          normalized_items = Array(items)
          super(items: normalized_items.freeze, resource_version: Integer(resource_version).to_s,
                continue_token: continue_token, remaining_item_count: remaining_item_count)
          freeze
        end

        def each(&)
          items.each(&)
        end

        def [](index)
          items[index]
        end

        def length
          items.length
        end

        alias_method :size, :length

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
        include Rubernetes::Watch::EventStream

        def initialize(store:, queue:, condition:, mutex:, subscription:, timeout_seconds: nil)
          @store = store
          @queue = queue
          @condition = condition
          @mutex = mutex
          @subscription = subscription
          @timeout_seconds = Float(timeout_seconds) unless timeout_seconds.nil?
          @watch_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout_seconds if @timeout_seconds&.positive?
          @closed = false
        end

        def next(timeout: nil)
          effective_timeout = timeout.nil? ? @timeout_seconds : timeout
          deadline = if effective_timeout.nil?
                       nil
                     else
                       Process.clock_gettime(Process::CLOCK_MONOTONIC) + effective_timeout.to_f
                     end
          deadline = @watch_deadline if @watch_deadline && @watch_deadline < deadline
          @mutex.synchronize do
            loop do
              return nil if @watch_deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) >= @watch_deadline
              return @queue.shift unless @queue.empty?
              return nil if @closed

              remaining = deadline && (deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC))
              return nil if remaining && remaining <= 0

              @condition.wait(@mutex, remaining)
            end
          end
        end

        def each(timeout: :default, &)
          super(timeout: drain_timeout(timeout), &)
        end

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
        @collection_keys = {}
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
          @objects.fetch(normalized_key) { raise NotFound, "resource #{normalized_key.inspect} was not found" }
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
          normalized_prefix = prefix && prefix.to_s.delete_prefix("/").delete_suffix("/")
          return list_shard(normalized_prefix, normalized_gvr, namespace, selector, normalized_limit, continue_token, snapshot_revision) if sharded?(selector)

          objects = scoped_keys(normalized_prefix, normalized_gvr, namespace).filter_map do |key|
            object = @objects.fetch(key)
            object if selector.nil? || selector.matches?(object)
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
            raise(Gone.new("The provided continue parameter is too old to display a consistent list result. " \
                           "You can start a new list without the continue parameter.",
                           resource_version: continuation[:revision], compacted_revision: @compacted_revision)
              .tap { |error| error.details["continue"] = encode_continue_token(start) if error.details })
          end
          snapshot_revision = continuation[:revision] if continuation[:revision] && normalized_limit
          selected = objects
          selected = objects.slice(start, normalized_limit || objects.length) || [] if normalized_limit || start.positive?
          offset = start + selected.length
          more = offset < objects.length
          ListResult.new(items: selected, resource_version: snapshot_revision,
                         continue_token: (encode_continue_token(offset, snapshot_revision) if more),
                         remaining_item_count: (objects.length - offset if more && !selector_filtered?(selector)))
        end
      end

      def create(key = nil, object = nil, gvr: nil, namespace: nil, name: nil, related_versions: nil, **options)
        object = object || options.delete(:object) || options.delete(:resource) || options.delete(:body)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name, object: object)
        @mutex.synchronize do
          raise AlreadyExists, "resource #{normalized_key.inspect} already exists" if @objects.key?(normalized_key)

          check_related_versions!(related_versions)

          commit(normalized_key, object, "ADDED")
        end
      end

      def update(key = nil, object = nil, gvr: nil, namespace: nil, name: nil, resource_version: nil, related_versions: nil, **options)
        object = object || options.delete(:object) || options.delete(:resource) || options.delete(:body)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name, object: object)
        @mutex.synchronize do
          existing = @objects[normalized_key]
          raise NotFound, "resource #{normalized_key.inspect} was not found" if existing.nil?

          expected = resource_version || metadata_value(object, "resourceVersion")
          check_expected_version!(existing, expected)
          check_related_versions!(related_versions)
          commit(normalized_key, object, "MODIFIED")
        end
      end

      alias replace update

      # Optimistic update helper matching the storage contract. The caller's
      # block runs against a detached copy and may be retried after a conflict.
      def guaranteed_update(key = nil, resource_version: nil, max_retries: 8, **)
        attempts = 0
        loop do
          attempts += 1
          current = get(key, resource_version: resource_version, **)
          candidate = deep_copy(current)
          candidate = yield(candidate)
          return update(key, candidate, resource_version: metadata_value(current, "resourceVersion"), **)
        rescue Conflict
          raise if attempts >= Integer(max_retries)

          resource_version = nil
        end
      end

      def delete(key = nil, gvr: nil, namespace: nil, name: nil, resource_version: nil, related_versions: nil, **_options)
        normalized_key = key_for(key, gvr: gvr, namespace: namespace, name: name)
        @mutex.synchronize do
          existing = @objects[normalized_key]
          raise NotFound, "resource #{normalized_key.inspect} was not found" if existing.nil?

          check_expected_version!(existing, resource_version)
          check_related_versions!(related_versions)
          commit(normalized_key, existing, "DELETED")
        end
      end

      def delete_collection(gvr:, namespace: :all, selector: nil, label_selector: nil, field_selector: nil, **_options)
        keys = @mutex.synchronize do
          normalized_gvr = gvr_key(gvr)
          selector = normalize_selector(selector, label_selector: label_selector, field_selector: field_selector)
          scoped_keys(nil, normalized_gvr, namespace).select { |key| selector.nil? || selector.matches?(@objects.fetch(key)) }
        end
        keys.map { |key| delete(key) }
      end

      def watch(prefix = nil, gvr: nil, namespace: :all, resource_version: nil, selector: nil,
                label_selector: nil, field_selector: nil, allow_bookmarks: false,
                send_initial_events: nil, resource_version_match: nil, timeout_seconds: nil, resource: nil, **_options)
        @mutex.synchronize do
          normalize_resource_version_match(resource_version_match)
          unset_resource_version = resource_version.nil? || resource_version.to_s.empty?
          since = unset_resource_version ? @revision : Integer(resource_version)
          raise InvalidResourceVersion, "resourceVersion must be a non-negative integer" if since.negative?
          raise InvalidResourceVersion, "resourceVersion #{since} is ahead of current revision #{@revision}" if since > @revision

          # An unset or zero resourceVersion replays current state for legacy
          # watches. An explicit sendInitialEvents value controls that replay.
          initial_state = send_initial_events.nil? ? (unset_resource_version || since.zero?) : send_initial_events
          since = @revision if initial_state || since.zero?
          if since < @compacted_revision
            raise Gone.new("resource version #{since} is older than compacted revision #{@compacted_revision}",
                           resource_version: since, compacted_revision: @compacted_revision)
          end
          normalized_gvr = gvr && gvr_key(gvr)
          normalized_prefix = prefix && prefix.to_s.delete_prefix("/").delete_suffix("/")
          selector = normalize_selector(selector, label_selector: label_selector, field_selector: field_selector)
          metric_labels = shard_metric_labels(gvr, selector)
          shard_mismatch = -> { @metrics.increment("apiserver_watch_filtered_events_total", metric_labels) } if metric_labels
          condition = ConditionVariable.new
          subscription = Object.new
          watch_scope = [normalized_prefix, normalized_gvr, namespace, selector]
          queue = if initial_state
                    initial_watch_events(*watch_scope, resource, send_initial_events && allow_bookmarks)
                  else
                    retained_watch_events(since, *watch_scope, resource, allow_bookmarks, &shard_mismatch)
                  end
          @watchers[subscription] = {condition: condition, queue: queue, prefix: normalized_prefix,
                                     gvr: normalized_gvr, namespace: namespace, selector: selector,
                                     metric_labels: metric_labels, shard_mismatch: shard_mismatch}
          @metrics.increment("apiserver_watch_shards_total", metric_labels) if metric_labels
          Watcher.new(store: self, queue: queue, condition: condition, mutex: @mutex, subscription: subscription,
                      timeout_seconds: timeout_seconds)
        end
      rescue ArgumentError, TypeError
        raise InvalidResourceVersion, "resourceVersion must be a non-negative integer"
      end

      def bookmark_object(resource, initial_events_end: false)
        object = {"metadata" => {"resourceVersion" => @revision.to_s}}
        if resource.respond_to?(:api_version) && resource.respond_to?(:kind)
          object["apiVersion"] = resource.api_version.to_s
          object["kind"] = resource.kind.to_s
        end
        object["metadata"]["annotations"] = {"k8s.io/initial-events-end" => "true"} if initial_events_end
        object
      end

      # The revision before which no watch event can be replayed.
      def compacted_revision
        @mutex.synchronize { @compacted_revision }
      end

      def remove_watcher(subscription)
        @mutex.synchronize do
          labels = @watchers.delete(subscription)&.fetch(:metric_labels)
          @metrics.increment("apiserver_watch_shards_total", labels, by: -1) if labels
        end
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

      def initial_watch_events(prefix, gvr, namespace, selector, resource, send_bookmark)
        queue = scoped_keys(prefix, gvr, namespace).sort.filter_map do |key|
          object = @objects.fetch(key)
          next unless selector.nil? || selector.matches?(object)

          Event.new(type: "ADDED", object: object, key: key)
        end
        queue << Event.new(type: "BOOKMARK", object: bookmark_object(resource, initial_events_end: true)) if send_bookmark
        queue
      end

      def retained_watch_events(since, prefix, gvr, namespace, selector, resource, allow_bookmarks, &)
        first = @history.bsearch_index { |event| event_revision(event) > since } || @history.size
        queue = (first...@history.size).filter_map do |index|
          matching_watch_event(@history[index], prefix, gvr, namespace, selector, &)
        end
        queue << Event.new(type: "BOOKMARK", object: bookmark_object(resource)) if allow_bookmarks && @revision > since
        queue
      end

      def commit(key, object, event_type)
        raise ArgumentError, "resource object must be a Hash" unless object.is_a?(Hash)

        revision = @revision + 1
        existing = @objects[key]
        parts = key.split("/")
        event = Event.new(type: event_type, object: object, key: key, old_object: existing, stringify_keys: true) do |copy|
          prepare_metadata(copy, parts, existing) unless event_type == "DELETED"
          copy.fetch("metadata")["resourceVersion"] = revision.to_s
        end
        @revision = revision
        # The event owns the frozen revision shared by history, readers and watchers.
        if event_type == "DELETED"
          @objects.delete(key)
          collection_scopes(parts).each do |scope|
            keys = @collection_keys.fetch(scope)
            keys.delete(key)
            @collection_keys.delete(scope) if keys.empty?
          end
        else
          collection_scopes(parts).each { |scope| (@collection_keys[scope] ||= {})[key] = true } unless event.old_object
          @objects[key] = event.object
        end
        append_event(event)
        notify_watchers(event)
        event.object
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      def event_revision(event)
        event.object.fetch("metadata").fetch("resourceVersion").to_i
      end

      def notify_watchers(event)
        @watchers.each_value do |watcher|
          selected = matching_watch_event(event, watcher[:prefix], watcher[:gvr], watcher[:namespace], watcher[:selector],
                                          &watcher[:shard_mismatch])
          next unless selected

          watcher[:queue] << selected
          watcher[:condition].broadcast
        end
      end

      # Keys in both indexes keep insertion order, including delete-then-create.
      # The namespace index bounds a Pod LIST even if every other key is a Pod.
      def collection_scopes(parts)
        return [] unless parts.length >= 4 && parts.first == "registry"

        gvr = parts[1...-2].join("/")
        [gvr, [gvr, parts[-2]]]
      end

      def scoped_keys(prefix, gvr, namespace)
        return enum_for(__method__, prefix, gvr, namespace) unless block_given?

        if gvr
          scope = collection_scope(gvr, namespace)
          @collection_keys[scope]&.each_key { |key| yield key if prefix_matches?(key, prefix) }
        else
          @objects.each_key { |key| yield key if key_matches?(key, prefix, nil, namespace) }
        end
      end

      def collection_scope(gvr, namespace)
        return gvr if namespace == :all || namespace.nil?

        [gvr, namespace == :cluster ? "_cluster" : namespace.to_s]
      end

      def prefix_matches?(key, prefix)
        !prefix || key == prefix || key.start_with?("#{prefix}/")
      end

      def key_matches?(key, prefix, gvr, namespace)
        return false unless prefix_matches?(key, prefix)

        parts = key.split("/")
        return false unless parts.length >= 4 && parts.first == "registry"
        return false if gvr && parts[1...-2].join("/") != gvr

        namespace == :all || namespace.nil? || parts[-2] == (namespace == :cluster ? "_cluster" : namespace.to_s)
      end

      def key_for(key = nil, gvr: nil, namespace: nil, name: nil, object: nil)
        if key
          return key.to_s.delete_prefix("/") if key.to_s.start_with?("/registry/", "registry/")
          return key.to_s.delete_prefix("/") if key.respond_to?(:to_s) && key.to_s.count("/") == 3
        end
        resource = gvr || key
        resource_key = gvr_key(resource)
        namespace = metadata_value(object, "namespace") if namespace.nil? && object
        name = metadata_value(object, "name") if name.nil? && object
        namespace = "_cluster" if namespace.nil? || namespace == :cluster
        raise ArgumentError, "storage key requires resource and name" if resource_key.empty? || name.to_s.empty?

        "registry/#{resource_key}/#{namespace}/#{name}"
      end

      def gvr_key(value)
        return "" if value.nil?

        if value.is_a?(Hash)
          group = value[:group] || value["group"] || ""
          version = value[:version] || value["version"] || "v1"
          resource = value[:resource] || value["resource"] || value[:name] || value["name"]
          return "#{group.to_s.empty? ? version : "#{group}/#{version}"}/#{resource}" if resource
        end
        return gvr_key(value.gvr) if value.respond_to?(:gvr)
        return "#{value.group_version}/#{value.resource}" if value.respond_to?(:group_version) && value.respond_to?(:resource)

        if value.respond_to?(:group) && value.respond_to?(:version) && value.respond_to?(:resource)
          group = value.group.to_s
          return "#{group.empty? ? value.version : "#{group}/#{value.version}"}/#{value.resource}"
        end
        value.to_s.delete_prefix("/").delete_prefix("registry/").delete_suffix("/")
      end

      def prepare_metadata(object, key_parts, existing)
        object.delete("_rubernetes_resource")
        metadata = object["metadata"] ||= {}
        metadata["name"] ||= key_parts.last
        metadata["namespace"] ||= key_parts[-2] unless key_parts[-2] == "_cluster"
        if existing
          metadata["uid"] = metadata_value(existing, "uid") if metadata_value(existing, "uid")
          metadata["creationTimestamp"] = metadata_value(existing, "creationTimestamp") if metadata_value(existing, "creationTimestamp")
        else
          metadata["uid"] ||= @uid_generator.call.to_s
          metadata["creationTimestamp"] ||= @clock.call.utc.iso8601(6)
        end
      end

      def check_related_versions!(versions)
        versions&.each do |key, expected|
          next if @objects[key]&.dig("metadata", "resourceVersion") == expected

          raise Conflict, "related key #{key} changed"
        end
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
    end
  end
end
