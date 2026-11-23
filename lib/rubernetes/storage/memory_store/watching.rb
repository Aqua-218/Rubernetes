# frozen_string_literal: true

module Rubernetes
  module Storage
    # Opening watches, replaying their initial events and the registry of live ones.
    class MemoryStore
      # Start a Watcher after atomically capturing retained history and registering
      # the live subscriber. This ordering is what prevents a list/watch race from
      # dropping the first mutation after a caller's resourceVersion.
      def watch(prefix = "", *positional, since: nil, resource_version: nil, label_selector: nil, field_selector: nil,
                selector: nil, allow_bookmarks: false, allow_watch_bookmarks: nil,
                bookmark_interval: @bookmark_interval, send_initial_events: nil,
                resource_version_match: nil, timeout_seconds: nil, shard_selector: nil, **options)
        raise ArgumentError, "watch accepts at most one positional since revision" if positional.length > 1
        raise ArgumentError, "watch since revision was supplied twice" if !positional.empty? && !since.nil?

        since = positional.first if since.nil? && !positional.empty?
        since = resource_version if since.nil? && !resource_version.nil?
        since = options.delete(:start_revision) if since.nil? && options.key?(:start_revision)
        allow_bookmarks = allow_watch_bookmarks unless allow_watch_bookmarks.nil?
        allow_bookmarks = options.delete(:allow_bookmark) unless options[:allow_bookmark].nil?
        bookmark_interval = options.delete(:bookmark_interval_seconds) if options.key?(:bookmark_interval_seconds)
        resource = options.delete(:resource)
        max_events = buffer_option(options, :buffer_size, :max_events, @watcher_buffer_size)
        max_bytes = buffer_option(options, :buffer_bytes, :max_bytes, @watcher_buffer_bytes)
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown watch options: #{options.keys.join(", ")}" unless options.empty?

        normalized_prefix = String(prefix || "")
        selector_object = build_selector(selector, label_selector, field_selector, shard: shard_selector)
        normalized_since = since.nil? || since == "" ? nil : parse_revision(since)
        normalize_resource_version_match(resource_version_match)

        # Legacy watches with an unset or zero resourceVersion replay current
        # state. An explicit sendInitialEvents value chooses whether the
        # subscription should receive those synthetic ADDED events.
        initial_state = send_initial_events.nil? ? (normalized_since.nil? || normalized_since.zero?) : send_initial_events

        @monitor.synchronize do
          start_revision = watch_start_revision_locked(normalized_since, initial_state)
          watcher = Watcher.new(
            prefix: normalized_prefix, selector: selector_object, allow_bookmarks: !!allow_bookmarks,
            bookmark_interval: bookmark_interval, max_events: max_events, max_bytes: max_bytes, clock: @clock,
            bookmark_provider: -> { revision },
            bookmark_callback: ->(bookmark_watcher) { enqueue_bookmark(bookmark_watcher) },
            bookmark_identity: bookmark_identity(resource),
            on_close: ->(closed_watcher) { unregister_watcher(closed_watcher) },
            on_shard_mismatch: shard_mismatch_metric(normalized_prefix, selector_object),
            timeout_seconds: timeout_seconds
          )
          init_events = if initial_state
                          # The "initial events end" bookmark belongs to sendInitialEvents
                          # alone; a plain unset-resourceVersion watch never carries one.
                          replay_current_state_locked(watcher, send_initial_events && allow_bookmarks)
                        else
                          replay_history_locked(watcher, start_revision)
                        end
          record_init_events(normalized_prefix, init_events) if @metrics && init_events.positive?
          register_watcher(watcher)
          watcher
        end
      end

      def watcher_count
        @monitor.synchronize { @watchers.length }
      end

      # Waits (at most +timeout+ seconds) until every watcher that was handed
      # the event of +revision+ has written it to its client; see
      # Watcher#await_delivered.  Returns false if some watcher was not done.
      def await_watch_delivery(revision, timeout:)
        target = Integer(revision)
        watchers = @monitor.synchronize { @watchers.keys }
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout)
        watchers.map { |watcher| watcher.await_delivered(target, deadline) }.all?
      rescue ArgumentError, TypeError
        true
      end

      # This store's state is being replaced wholesale (a raft follower
      # restoring a snapshot swaps in a new store).  Every open watch follows
      # THIS store, so it would stay healthy-looking and silent while all new
      # writes land in the replacement -- until the client's watch timed out
      # minutes later.  End each one with 410 Expired, which tells the client
      # to relist and re-watch, exactly as a compacted etcd watch does.
      def expire_watchers!
        watchers = @monitor.synchronize do
          current = @watchers.keys
          current.each { |watcher| record_sharded_watch(watcher, -1) }
          @watchers.clear
          current
        end
        watchers.each { |watcher| watcher.fail_with(WatchOverflow.new) }
        self
      end

      def close
        @monitor.synchronize do
          @watchers.keys.each(&:close)
          @watchers.clear
        end
        self
      end

      private

      def register_watcher(watcher)
        return if watcher.closed?

        @watchers[watcher] = true
        record_sharded_watch(watcher, 1)
      end

      def watch_start_revision_locked(since, initial_state)
        if since && since > @revision
          raise InvalidResourceVersion,
                "watch revision #{since} is ahead of current revision #{@revision}"
        end

        # The current snapshot is used only for initial events or an unset
        # cursor. An explicit positive cursor replays retained events.
        start_revision = initial_state || since.nil? || since.zero? ? @revision : since
        ensure_snapshot_available!(start_revision)
        start_revision
      end

      # The current objects the watcher selects, as ADDED events in key order.
      # Returns how many it accepted.
      def replay_current_state_locked(watcher, initial_events_end)
        prefix = watcher.prefix
        init_events = 0
        each_key_with_prefix_locked(prefix) do |key|
          object = current_object(key)
          next unless object

          init_events += 1 if watcher.enqueue_initial(key, object, object_revision(object))
          break if watcher.closed?
        end
        watcher.enqueue_bookmark(@revision, initial_events_end: true) if initial_events_end && !watcher.closed?
        init_events
      end

      # The retained mutations after +start_revision+.  Returns how many the
      # watcher accepted.
      def replay_history_locked(watcher, start_revision)
        init_events = 0
        history_offset_after(start_revision).upto(@history.length - 1) do |index|
          init_events += 1 if watcher.enqueue(@history[index])
          break if watcher.closed?
        end
        init_events
      end

      def unregister_watcher(watcher)
        @monitor.synchronize do
          record_sharded_watch(watcher, -1) if @watchers.delete(watcher)
        end
      end

      def enqueue_bookmark(watcher)
        @monitor.synchronize do
          # Read and enqueue while holding the Store monitor so a bookmark can
          # never be placed behind a newer mutation with an older revision.
          watcher.enqueue_bookmark(@revision)
          unregister_watcher(watcher) if watcher.closed?
        end
      end

      # An API::Registry::Resource names the type a bookmark carries; a caller
      # that passes a plain resource name (or nothing) gets an untyped one.
      def bookmark_identity(resource)
        return {} unless Shape.typed_resource?(resource)

        {"apiVersion" => resource.api_version.to_s, "kind" => resource.kind.to_s}
      end
    end
  end
end
