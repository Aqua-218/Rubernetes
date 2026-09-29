# frozen_string_literal: true

require "json"
require "thread"
require_relative "support"

module Rubernetes
  module Watch
    # List-then-watch adapter.  A list establishes the starting
    # resourceVersion, while the store's replayable watch contract closes the
    # registration race between the two calls.
    class Reflector
      class Gone < StandardError
        attr_reader :status, :code

        def initialize(message = "watch resource version is gone", status: 410, code: 410)
          @status = Integer(status)
          @code = Integer(code)
          super(String(message))
        end
      end

      DEFAULT_BACKOFF = 0.005
      MAX_BACKOFF = 30.0
      # A watch that lived at least this long counts as a healthy connection
      # and resets the reconnect backoff.
      HEALTHY_WATCH_SECONDS = 1.0

      def initialize(client:, fifo:, resource:, namespace: :all, selector: nil,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                     sleeper: ->(seconds) { sleep(seconds) }, min_backoff: DEFAULT_BACKOFF,
                     max_backoff: MAX_BACKOFF, key_func: nil, error_handler: nil)
        raise ArgumentError, "client is required" unless client
        raise ArgumentError, "error_handler must respond to call" if error_handler && !error_handler.respond_to?(:call)

        # client-go's reflector logs every failed watch.  Ours only stored the
        # last one behind #last_error, which nothing polls, so a broken watch
        # was completely silent: the control plane went deaf for minutes at a
        # time -- no default ServiceAccount for new namespaces, every spec
        # failing in [BeforeEach] -- and the process log said nothing at all.
        @error_handler = error_handler
        raise ArgumentError, "fifo must implement replace and add" unless fifo.respond_to?(:replace) && fifo.respond_to?(:add)
        raise ArgumentError, "clock must respond to call" unless clock.respond_to?(:call)
        raise ArgumentError, "sleeper must respond to call" unless sleeper.respond_to?(:call)
        raise ArgumentError, "key_func must respond to call" if key_func && !key_func.respond_to?(:call)

        @client = client
        @fifo = fifo
        @resource = resource
        @namespace = namespace
        @selector = selector
        @clock = clock
        @sleeper = sleeper
        @min_backoff = positive_float(min_backoff, "min_backoff")
        @max_backoff = Float(max_backoff)
        raise ArgumentError, "max_backoff must be at least min_backoff" if @max_backoff < @min_backoff
        raise ArgumentError, "max_backoff must be finite" unless @max_backoff.finite?
        @key_func = key_func
        @mutex = Mutex.new
        @call_mutex = Mutex.new
        @resource_version = nil
        @last_error = nil
        @running = false
        @stopping = false
        @thread = nil
        @stream = nil
        @closed_stream = nil
      end

      def resource_version
        @mutex.synchronize { @resource_version }
      end

      def last_error
        @mutex.synchronize { @last_error }
      end

      def list!
        result = @call_mutex.synchronize { invoke_list(resource_version_snapshot) }
        objects, version = normalize_list(result)
        @fifo.replace(objects, resource_version: version)
        immutable_objects = objects.map { |object| Support.immutable_copy(object) }.freeze
        @mutex.synchronize do
          # A relist is authoritative.  It may intentionally move to a new
          # opaque RV token, so unlike event processing it replaces the value.
          @resource_version = version.nil? ? nil : String(version).freeze
        end
        [immutable_objects, resource_version]
      end

      # Consume one watch stream.  A normal stream termination is a completed
      # attempt; run() still applies a reconnect delay before opening another.
      def watch_once
        list! if resource_version_snapshot.nil?
        version = resource_version_snapshot
        stream = @call_mutex.synchronize { invoke_watch(version) }
        raise IOError, "watch client returned nil stream" if stream.nil?

        register_stream(stream)
        each_event(stream) { |event| process_event(event) }
        true
      rescue StandardError => error
        record_error(error)
        if gone_error?(error)
          reset_resource_version
          list!
        end
        false
      ensure
        unregister_stream(stream) if stream
        close_stream(stream) if stream
      end

      # Keep reconnect policy in one place. Every disconnected watch uses the
      # current delay and then doubles it, including a stream that ended
      # without an exception.
      def run(iterations: nil)
        limit = iterations.nil? ? nil : Integer(iterations)
        raise ArgumentError, "iterations must be non-negative" if limit && limit.negative?

        should_run = @mutex.synchronize do
          next false if @stopping

          @running = true
          true
        end
        return self unless should_run
        attempts = 0
        backoff = @min_backoff
        while running? && (limit.nil? || attempts < limit)
          attempts += 1
          begin
            list! if resource_version_snapshot.nil?
            # Returning from a watch means the connection was disconnected,
            # even when the stream ended without an exception.  I2 requires
            # exponential reconnect delay for both forms of disconnect; a
            # connection that stayed healthy for a while resets the delay so
            # routine server-side watch expiry never degrades into the maximum
            # delay (the same rule as client-go's reflector backoff manager).
            started = @clock.call
            watch_once
            backoff = @min_backoff if @clock.call - started >= HEALTHY_WATCH_SECONDS
            sleep_if_running(backoff)
            backoff = [backoff * 2.0, @max_backoff].min
          rescue StandardError => error
            record_error(error)
            reset_resource_version if gone_error?(error)
            sleep_if_running(backoff)
            backoff = [backoff * 2.0, @max_backoff].min
          end
        end
        self
      ensure
        set_running(false)
      end

      def start(thread: true, **options)
        return run(**options) unless thread

        @mutex.synchronize do
          return self if @running
          @stopping = false
          @running = true
          begin
            @thread = Thread.new do
              run(**options)
            rescue StandardError => error
              record_error(error)
              set_running(false)
            end
          rescue StandardError
            @running = false
            @stopping = true
            raise
          end
        end
        self
      end

      def stop
        thread, stream, interrupt = @mutex.synchronize do
          already_stopping = @stopping
          @running = false
          @stopping = true
          [@thread, @stream, !already_stopping]
        end
        close_stream(stream) if stream
        if interrupt && thread && thread != Thread.current && thread.alive?
          # Thread#kill is a quiet, asynchronous shutdown. It runs the
          # reflector/watch ensures without publishing an exception to the
          # informer thread that is joining it. In particular, this also
          # interrupts an injected sleeper that is blocked in Kernel#sleep.
          thread.kill
        end
        thread.join if thread && thread != Thread.current
        self
      end

      def running?
        @mutex.synchronize { @running }
      end

      private

      def invoke_list(version)
        options = {resource: @resource, namespace: @namespace, selector: @selector, resource_version: version}
        if @client.respond_to?(:list)
          invoke_method(:list, options.merge(selectors: @selector))
        elsif @client.respond_to?(:call)
          @client.call(:list, **options)
        else
          raise ArgumentError, "watch client must implement list or call"
        end
      end

      # client-go: every watch asks the server to end it after a random
      # 5-10 minutes (minWatchTimeout * rand(1..2)) so streams are recycled
      # by the server, not by a client read timeout firing on an idle stream.
      MIN_WATCH_TIMEOUT_SECONDS = 300

      def invoke_watch(version)
        options = {resource: @resource, namespace: @namespace, selector: @selector, resource_version: version,
                   timeout_seconds: MIN_WATCH_TIMEOUT_SECONDS + rand(MIN_WATCH_TIMEOUT_SECONDS + 1)}
        if @client.respond_to?(:watch)
          invoke_method(:watch, options.merge(selectors: @selector))
        elsif @client.respond_to?(:call)
          @client.call(:watch, **options)
        else
          raise ArgumentError, "watch client must implement watch or call"
        end
      end

      def invoke_method(name, options)
        method = @client.method(name)
        parameters = method.parameters
        accepts_keywords = parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
        if accepts_keywords
          accepted = if parameters.any? { |kind, _| kind == :keyrest }
                       names = parameters.filter_map { |kind, parameter| parameter if %i[key keyreq].include?(kind) }
                       names.include?(:selectors) ? options : options.reject { |key, _| key == :selectors }
                     else
                       names = parameters.filter_map { |kind, parameter| parameter if %i[key keyreq].include?(kind) }
                       options.select { |key, _| names.include?(key) }
                     end
          positional = parameters.any? { |kind, _| %i[req opt].include?(kind) }
          positional ? method.call(@resource, **accepted) : method.call(**accepted)
        elsif parameters.any? { |kind, _| kind == :rest } || method.arity.zero?
          method.call
        else
          method.call(@resource)
        end
      end

      def normalize_list(result)
        if result.respond_to?(:items)
          items = result.items
          version = result.respond_to?(:resource_version) ? result.resource_version : nil
          version ||= result.resourceVersion if result.respond_to?(:resourceVersion)
          items = Array(items)
          version ||= infer_resource_version(items)
          raise ArgumentError, "watch list response must include resourceVersion" if version.nil?

          return [items, version]
        end

        if result.is_a?(Hash)
          raise ArgumentError, "watch list response must contain items" unless result.key?(:items) || result.key?("items")

          items = Support.value_at(result, :items, "items")
          metadata = Support.value_at(result, :metadata, "metadata")
          version = Support.value_at(result, :resource_version, :resourceVersion, "resourceVersion", "resource_version")
          version ||= Support.value_at(metadata, :resource_version, :resourceVersion, "resourceVersion", "resource_version")
          items = Array(items)
          version ||= infer_resource_version(items)
          raise ArgumentError, "watch list response must include resourceVersion" if version.nil?

          return [items, version]
        end

        items = Array(result)
        version = infer_resource_version(items)
        raise ArgumentError, "watch list response must include resourceVersion" if version.nil?

        [items, version]
      end

      def infer_resource_version(objects)
        versions = objects.filter_map { |object| Support.resource_version(object) }
        versions.max_by { |version| Support.numeric_version(version) || -1 }
      end

      def each_event(stream)
        if stream.respond_to?(:each)
          stream.each { |event| yield event }
        elsif stream.respond_to?(:next)
          loop do
            event = stream.next
            break if event.nil?

            yield event
          end
        else
          raise ArgumentError, "watch client must return an Enumerable or next-capable stream"
        end
      end

      def process_event(event)
        value = parse_event(event)
        type = Support.event_type(value)
        object = Support.event_object(value)
        version = Support.resource_version(value)
        version ||= Support.resource_version(object)
        case type
        when "ADDED"
          require_event_object!(type, object)
          @fifo.add(object, resource_version: version)
        when "MODIFIED"
          require_event_object!(type, object)
          @fifo.update(object, resource_version: version)
        when "DELETED"
          require_event_object!(type, object)
          @fifo.delete(object, resource_version: version)
        when "BOOKMARK"
          # Bookmarks carry no object contract; only the RV advances.
        when "ERROR"
          code = Support.value_at(value, :code, "code") || Support.value_at(object, :code, "code")
          reason = Support.value_at(value, :reason, "reason") || Support.value_at(object, :reason, "reason")
          raise Gone, "watch resource version is gone (HTTP 410)" if code.to_i == 410 || reason.to_s.casecmp("gone").zero?

          message = Support.value_at(object, :message, "message") || "watch returned an error"
          raise IOError, String(message)
        else
          raise ArgumentError, "unknown watch event type #{type.inspect}"
        end
        advance_resource_version(version)
        value
      end

      def parse_event(event)
        parsed = if event.is_a?(String)
                   JSON.parse(event, create_additions: false)
                 elsif event.is_a?(Hash)
                   event
                 elsif event.respond_to?(:to_h)
                   value = event.to_h
                   version = Support.resource_version(event)
                   if version && value.is_a?(Hash) && Support.resource_version(value).nil?
                     value.merge("resourceVersion" => version)
                   else
                     value
                   end
                 else
                   event
                 end
        parsed
      rescue JSON::ParserError => error
        raise ArgumentError, "watch event is not valid JSON: #{error.message}"
      end

      def require_event_object!(type, object)
        raise ArgumentError, "#{type} watch event is missing object" unless object
      end

      def advance_resource_version(version)
        return if version.nil?

        candidate = version.to_s.freeze
        @mutex.synchronize do
          @resource_version = candidate if Support.version_newer?(candidate, @resource_version)
        end
      end

      def resource_version_snapshot
        @mutex.synchronize { @resource_version }
      end

      def reset_resource_version
        @mutex.synchronize { @resource_version = nil }
      end

      def set_running(value)
        @mutex.synchronize { @running = value }
      end

      def register_stream(stream)
        @mutex.synchronize { @stream = stream }
      end

      def unregister_stream(stream)
        @mutex.synchronize { @stream = nil if @stream.equal?(stream) }
      end

      def close_stream(stream)
        return unless stream.respond_to?(:close)

        should_close = @mutex.synchronize do
          next false if @closed_stream.equal?(stream)

          @closed_stream = stream
          true
        end
        return unless should_close

        stream.close
      rescue StandardError => error
        record_error(error)
      end

      def sleep_if_running(seconds)
        return unless running?

        @sleeper.call(seconds)
      end

      def record_error(error)
        @mutex.synchronize { @last_error = error }
        return unless @error_handler

        begin
          @error_handler.call(error)
        rescue StandardError
          # Reporting a watch failure must never end the watch.
          nil
        end
      end

      def gone_error?(error)
        return true if error.is_a?(Gone)
        return true if error.respond_to?(:code) && error.code.to_i == 410
        return true if error.respond_to?(:status) && error.status.to_i == 410

        error.message.to_s.match?(/(?:^|\D)410(?:\D|$)/)
      end

      def positive_float(value, name)
        number = Float(value)
        raise ArgumentError, "#{name} must be positive" unless number.positive? && number.finite?

        number
      rescue TypeError, ArgumentError
        raise ArgumentError, "#{name} must be a positive finite number"
      end
    end
  end
end
