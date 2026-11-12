# frozen_string_literal: true

module Rubernetes
  module Storage
    class MemoryStore
      # One watch stream: a bounded queue the store fills under its monitor
      # and a single consumer drains.
      class Watcher
        def initialize(prefix:, selector:, allow_bookmarks:, bookmark_interval:, max_events:, max_bytes:, clock:,
                       bookmark_provider:, on_close:, bookmark_callback: nil, bookmark_identity: nil,
                       timeout_seconds: nil)
          @prefix = prefix.freeze
          @selector = selector
          @allow_bookmarks = allow_bookmarks
          @bookmark_interval = Float(bookmark_interval)
          @max_events = self.class.positive_limit(max_events, "max_events")
          @max_bytes = self.class.positive_limit(max_bytes, "max_bytes")
          @clock = clock
          @timeout_seconds = timeout_seconds.nil? ? nil : Float(timeout_seconds)
          raise ArgumentError, "timeout_seconds must be non-negative" if @timeout_seconds&.negative?

          @bookmark_provider = bookmark_provider
          @bookmark_callback = bookmark_callback
          @bookmark_identity = MemoryStoreSupport.immutable_copy(bookmark_identity || {})
          @on_close = on_close
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
          event = event_for(mutation)
          return false unless event

          size = bytesize || JSON.generate(event.to_h).bytesize
          @mutex.synchronize do
            return false if @closed

            if @queue.length >= @max_events || @queue_bytes + size > @max_bytes
              @error = WatchOverflow.new
              @closed = true
              @queue.clear
              @queue_bytes = 0
              @condition.broadcast
              return false
            end

            @queue << [event, size]
            @queue_bytes += size
            @last_revision = event.revision
            @condition.broadcast
            true
          end
        # A selector is evaluated while the Store monitor is held. Propagating a
        # user callback exception would make a committed mutation look failed, so
        # terminate only this watcher and surface the original error on next().
        rescue StandardError => error
          fail_with(error)
          false
        end

        def next(timeout: nil)
          timeout = @timeout_seconds if timeout.nil? && !@timeout_seconds.nil?
          deadline = timeout.nil? ? nil : monotonic_now + Float(timeout)
          loop do
            action = nil
            @mutex.synchronize do
              raise @error if @error

              if @returned_revision && (@delivered_revision.nil? || @delivered_revision < @returned_revision)
                @delivered_revision = @returned_revision
                @condition.broadcast
              end
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

        def each(timeout: nil)
          return enum_for(__method__, timeout: timeout) unless block_given?

          loop do
            event = self.next(timeout: timeout)
            break if event.nil?

            yield event
          end
          self
        end

        def to_a(timeout: :default)
          events = []
          effective_timeout = timeout == :default ? (@timeout_seconds || 0) : timeout
          each(timeout: effective_timeout) { |event| events << event }
          events
        end

        alias events to_a

        def each_json_line(timeout: :default)
          return enum_for(__method__, timeout: timeout) unless block_given?

          effective_timeout = timeout == :default ? (@timeout_seconds || 0) : timeout
          each(timeout: effective_timeout) { |event| yield JSON.generate(event.to_h) << "\n" }
          self
        end

        def bookmark!
          return nil unless @allow_bookmarks

          return @bookmark_callback.call(self) if @bookmark_callback

          enqueue_bookmark(Integer(@bookmark_provider.call))
        end

        def enqueue_bookmark(current_revision, initial_events_end: false)
          current_revision = Integer(current_revision)
          object = MemoryStoreSupport.deep_dup(@bookmark_identity)
          metadata = object["metadata"] = MemoryStoreSupport.deep_dup(object["metadata"] || {})
          metadata["resourceVersion"] = current_revision.to_s
          if initial_events_end
            annotations = metadata["annotations"] = MemoryStoreSupport.deep_dup(metadata["annotations"] || {})
            annotations["k8s.io/initial-events-end"] = "true"
          end
          event = Event.new(
            type: Event::BOOKMARK,
            object: object,
            revision: current_revision
          )
          size = JSON.generate(event.to_h).bytesize
          @mutex.synchronize do
            return nil if @closed

            if @queue.length >= @max_events || @queue_bytes + size > @max_bytes
              @error = WatchOverflow.new
              @closed = true
              @queue.clear
              @queue_bytes = 0
              @condition.broadcast
              return nil
            end

            @queue << [event, size]
            @queue_bytes += size
            @last_revision = current_revision
            @last_bookmark_at = clock_value
            @condition.broadcast
            event
          end
        end

        def fail_with(error)
          @mutex.synchronize do
            return if @closed

            @error = error
            @closed = true
            @queue.clear
            @queue_bytes = 0
            @condition.broadcast
          end
        end

        def close
          should_unregister = @mutex.synchronize do
            next false if @closed && @error.nil?

            @closed = true
            @queue.clear
            @queue_bytes = 0
            @condition.broadcast
            true
          end
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

        def event_for(mutation)
          return nil unless mutation.key.start_with?(@prefix)

          old_matches = mutation.old_object && @selector.matches?(mutation.old_object)
          new_matches = mutation.object && mutation.type != :deleted && @selector.matches?(mutation.object)
          type, object = case mutation.type
                         when :added
                           new_matches ? [Event::ADDED, mutation.object] : [nil, nil]
                         when :modified
                           if old_matches && new_matches
                             [Event::MODIFIED, mutation.object]
                           elsif !old_matches && new_matches
                             [Event::ADDED, mutation.object]
                           elsif old_matches && !new_matches
                             [Event::DELETED, mutation.old_object]
                           else
                             [nil, nil]
                           end
                         when :deleted
                           old_matches ? [Event::DELETED, mutation.object] : [nil, nil]
                         end
          return nil unless type

          Event.new(type: type, object: object, revision: mutation.revision, key: mutation.key)
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
