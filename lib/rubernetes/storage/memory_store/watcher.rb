# frozen_string_literal: true

require_relative "../../watch/event_stream"

module Rubernetes
  module Storage
    class MemoryStore
      # One watch stream: a bounded queue the store fills under its monitor
      # and a single consumer drains.
      class Watcher
        include Rubernetes::Watch::EventStream

        def initialize(prefix:, selector:, allow_bookmarks:, bookmark_interval:, max_events:, max_bytes:, clock:,
                       bookmark_provider:, on_close:, bookmark_callback: nil, bookmark_identity: nil,
                       timeout_seconds: nil, on_shard_mismatch: nil)
          @prefix = prefix.freeze
          @selector = selector
          @allow_bookmarks = allow_bookmarks
          @bookmark_interval = Float(bookmark_interval)
          @max_events = self.class.positive_limit(max_events, "max_events")
          @max_bytes = self.class.positive_limit(max_bytes, "max_bytes")
          @clock = clock
          @timeout_seconds = timeout_seconds.nil? ? nil : Float(timeout_seconds)
          raise ArgumentError, "timeout_seconds must be non-negative" if @timeout_seconds&.negative?

          @watch_deadline = monotonic_now + @timeout_seconds if @timeout_seconds&.positive?
          @bookmark_provider = bookmark_provider
          @bookmark_callback = bookmark_callback
          @bookmark_identity = MemoryStoreSupport.immutable_copy(bookmark_identity || {})
          @on_close = on_close
          @on_shard_mismatch = on_shard_mismatch
          @mutex = Mutex.new
          @condition = ConditionVariable.new
          @queue = []
          @queue_bytes = 0
          @closed = false
          @error = nil
          @last_bookmark_at = clock_value
          @last_revision = nil
          @returned_revision = nil
          @delivered_revision = nil
        end

        # A consumer asks for the next event only after it has written the
        # previous one to its client, so the revision it was last handed is
        # "delivered" once it comes back.  #await_delivered lets a writer
        # hold its own response until the watchers it woke have sent the
        # event: a client that reads its informer cache right after a write
        # (the e2e CRUD helper polls it, then waits 2 s before looking again)
        # otherwise raced the event and lost two seconds per step.
        BACKLOG_LIMIT = 2

        def await_delivered(revision, deadline)
          @mutex.synchronize do
            loop do
              return true if @closed || @error
              return true if @last_revision.nil? || @last_revision < revision
              return true if @delivered_revision && @delivered_revision >= revision
              # A watcher already behind is a slow reader; it is not waited for.
              return true if @queue.length > BACKLOG_LIMIT

              remaining = deadline - monotonic_now
              return false if remaining <= 0

              @condition.wait(@mutex, remaining)
            end
          end
        end

        def enqueue(mutation, bytesize: nil)
          deliver(bytesize) { event_for(mutation) }
        end

        def enqueue_initial(key, object, revision)
          return unless @selector.matches?(object)

          deliver { Event.new(type: Event::ADDED, key: key, object: object, revision: revision) }
        end

        def next(timeout: nil)
          timeout = @timeout_seconds if timeout.nil? && !@timeout_seconds.nil?
          deadline = timeout.nil? ? nil : monotonic_now + Float(timeout)
          deadline = @watch_deadline if @watch_deadline && @watch_deadline < deadline
          loop do
            action = nil
            @mutex.synchronize do
              raise @error if @error

              if @returned_revision && (@delivered_revision.nil? || @delivered_revision < @returned_revision)
                @delivered_revision = @returned_revision
                @condition.broadcast
              end
              return nil if @watch_deadline && monotonic_now >= @watch_deadline

              unless @queue.empty?
                event = @queue.shift.tap { |entry| @queue_bytes -= entry[1] }.first
                @returned_revision = event.revision
                return event
              end
              return nil if @closed

              if @allow_bookmarks && bookmark_due?
                action = :bookmark
              else
                wait_for = wait_duration(deadline)
                return nil if wait_for&.negative? || wait_for == 0.0

                @condition.wait(@mutex, wait_for)
              end
            end
            bookmark! if action == :bookmark
          end
        end

        def pop(timeout = nil, **options)
          timeout = options.fetch(:timeout, timeout)
          self.next(timeout: timeout)
        end

        def poll(timeout: 0)
          self.next(timeout: timeout)
        end

        def bookmark!
          return nil unless @allow_bookmarks

          return @bookmark_callback.call(self) if @bookmark_callback

          enqueue_bookmark(Integer(@bookmark_provider.call))
        end

        def enqueue_bookmark(current_revision, initial_events_end: false)
          current_revision = Integer(current_revision)
          object = MemoryStoreSupport.deep_dup(@bookmark_identity)
          metadata = object["metadata"] ||= {}
          metadata["resourceVersion"] = current_revision.to_s
          if initial_events_end
            annotations = metadata["annotations"] ||= {}
            annotations["k8s.io/initial-events-end"] = "true"
          end
          push_event(Event.new(type: Event::BOOKMARK, object: object, revision: current_revision))
        end

        def fail_with(error)
          @mutex.synchronize { close_locked(error) unless @closed }
        end

        def close
          should_unregister = @mutex.synchronize { close_locked(@error) unless @closed && @error.nil? }
          @on_close.call(self) if should_unregister
          self
        end

        alias stop close
        alias close! close

        # A single boolean read, asked of every watcher on every commit: the
        # mutex around it was a twentieth of an apiserver's CPU.  @closed only
        # ever goes from false to true, so a stale false costs one extra
        # enqueue attempt, which checks again under the lock.
        def closed?
          @closed
        end

        alias closed closed?

        def overflowed?
          @mutex.synchronize { @error.is_a?(WatchOverflow) }
        end

        def alive?
          !closed?
        end

        attr_reader :prefix, :selector, :error, :last_revision

        def last_resource_version
          @last_revision&.to_s
        end

        def self.positive_limit(value, name)
          number = Integer(value)
          raise ArgumentError, "#{name} must be positive" unless number.positive?

          number
        rescue TypeError, ArgumentError
          raise ArgumentError, "#{name} must be a positive integer"
        end

        private

        def deliver(size = nil)
          event = yield
          !!(event && push_event(event, size))
        # A selector is evaluated while the Store monitor is held. Propagating a
        # user callback exception would make a committed mutation look failed, so
        # terminate only this watcher and surface the original error on next().
        rescue StandardError => error
          fail_with(error)
          false
        end

        def push_event(event, size = nil)
          size ||= JSON.generate(event.to_h).bytesize
          @mutex.synchronize do
            return if @closed

            if @queue.length >= @max_events || @queue_bytes + size > @max_bytes
              close_locked(WatchOverflow.new)
              return
            end

            @queue << [event, size]
            @queue_bytes += size
            @last_revision = event.revision
            @last_bookmark_at = clock_value if event.type == Event::BOOKMARK
            @condition.broadcast
            event
          end
        end

        def close_locked(error)
          @error = error
          @closed = true
          @queue.clear
          @queue_bytes = 0
          @condition.broadcast
          true
        end

        def event_for(mutation)
          return nil unless mutation.key.start_with?(@prefix)

          old_matches = mutation.old_object && @selector.matches?(mutation.old_object, &@on_shard_mismatch)
          new_matches = mutation.object && mutation.type != :deleted && @selector.matches?(mutation.object, &@on_shard_mismatch)
          object = mutation.object
          if new_matches
            type = old_matches ? Event::MODIFIED : Event::ADDED
          elsif old_matches
            type = Event::DELETED
            object = departing_object(mutation) unless mutation.type == :deleted
          else
            return
          end

          Event.new(type: type, object: object, revision: mutation.revision, key: mutation.key)
        end

        # A selector exit carries the old matching object at the mutation's
        # revision. Watch clients resume and order events using this field.
        def departing_object(mutation)
          previous = mutation.old_object
          metadata = previous.fetch("metadata").merge("resourceVersion" => mutation.revision.to_s)
          previous.merge("metadata" => metadata)
        end

        def bookmark_due?
          clock_value - @last_bookmark_at >= @bookmark_interval
        end

        def wait_duration(deadline)
          durations = []
          durations << (deadline - monotonic_now) if deadline
          durations << (@bookmark_interval - (clock_value - @last_bookmark_at)) if @allow_bookmarks
          durations.compact.min
        end

        def clock_value
          @clock.call.to_f
        end

        def monotonic_now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      end
    end
  end
end
