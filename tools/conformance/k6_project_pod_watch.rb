# frozen_string_literal: true

require "json"
require "open3"
require "uri"

module Conformance
  # Advance a project-scoped cursor without keeping any Pod objects. A fresh
  # LIST after an expired cursor cannot recover workloads already deleted.
  class K6ProjectPodWatch
    WATCH_SECONDS = 5
    REQUEST_SECONDS = 12
    STOP_SECONDS = (REQUEST_SECONDS * 2) + 2
    MAX_EVENT_BYTES = 3 * 1024 * 1024
    MAX_ERROR_BYTES = 8192
    MAX_FAILURES = 3
    POD_EVENTS = %w[ADDED MODIFIED DELETED].freeze
    TRANSIENT_STATUS_CODES = [408, 429, 500, 502, 503, 504].freeze
    class StreamError < StandardError
    end

    class Expired < StreamError
    end

    class Transient < StreamError
    end

    def initialize(command, namespace, &observe)
      @command = command
      @namespace = namespace
      @path = "/api/v1/namespaces/#{URI.encode_www_form_component(namespace)}/pods"
      @observe = observe
      @lock = Mutex.new
      @started = false
      @stopping = false
      @forced = false
      @drained = false
      @error = nil
    end

    def start
      @started = true
      list, _stderr, status = Open3.capture3(*raw_command(limit: 1), binmode: true)
      raise StreamError, "initial namespace Pod LIST failed" unless status.success?

      @cursor = cursor(parse_json(list))
      first = open_stream
      @thread = Thread.new { follow(first) }
    rescue JSON::ParserError, SystemCallError, StreamError, TypeError, NoMethodError => error
      record_error(error.is_a?(StreamError) ? error.message : "could not open namespace Pod watch")
    end

    def stop
      return unless @thread

      @lock.synchronize { @stopping = true }
      return if @thread.join(STOP_SECONDS)

      record_error("namespace Pod watch did not drain before its deadline")
      child = @lock.synchronize do
        @forced = true
        @child
      end
      signal(child, "TERM")
      return if @thread.join(2)

      signal(child, "KILL")
      @thread.join(2) || @thread.kill
    end

    def evidence
      @lock.synchronize do
        status = if !@started
                   "not_started"
                 elsif @error || !@drained || @thread&.alive?
                   "incomplete"
                 else
                   "complete"
                 end
        {"status" => status, "errors" => [@error].compact}
      end
    end

    private

    def follow(stream)
      failures = 0
      loop do
        begin
          read_stream(stream)
          if stream.last
            @lock.synchronize { @drained = true }
            return
          end

          failures = 0
        rescue Transient
          failures += 1
          raise StreamError, "namespace Pod watch did not reconnect" if failures >= MAX_FAILURES
        end
        sleep 0.1
        stream = open_stream
        return unless stream
      end
    rescue StreamError => error
      record_error(error.message)
    rescue StandardError
      record_error("could not read namespace Pod watch")
    end

    def open_stream
      @lock.synchronize do
        return if @forced

        parameters = {watch: true, resourceVersion: @cursor, timeoutSeconds: WATCH_SECONDS, allowWatchBookmarks: true}
        input, output, errors, child = Open3.popen3(*raw_command(parameters))
        @child = child
        input.close
        output.binmode
        errors.binmode
        # A new request after stop covers updates between the previous
        # server closing and the local reader receiving that EOF.
        [output, errors, child, @stopping]
      end
    end

    def read_stream(stream)
      output, errors, child = stream
      error_reader = Thread.new { drain_error(errors) }
      begin
        while (line = output.gets("\n", MAX_EVENT_BYTES + 1))
          raise StreamError, "namespace Pod watch event exceeded its size limit" if line.bytesize > MAX_EVENT_BYTES

          receive(parse_json(line))
        end
        status = child.value
        diagnostic = error_reader.value
        return if status.success?
        raise Expired, "namespace Pod watch resourceVersion expired" if diagnostic.match?(/\(Expired\)|\(Gone\)|too old resource version/i)

        raise Transient
      rescue JSON::ParserError
        raise StreamError, "namespace Pod watch returned invalid JSON"
      ensure
        signal(child, "TERM")
        output.close
        error_reader.join
        errors.close
        child.join
        @lock.synchronize { @child = nil }
      end
    end

    def receive(event)
      type = event.fetch("type")
      object = event.fetch("object")
      if type == "ERROR"
        code = object["code"]
        raise Expired, "namespace Pod watch resourceVersion expired" if code == 410
        raise Transient if TRANSIENT_STATUS_CODES.include?(code)

        raise StreamError, "namespace Pod watch returned an API error"
      end
      raise StreamError, "namespace Pod watch returned an unknown event" unless type == "BOOKMARK" || POD_EVENTS.include?(type)

      @cursor = cursor(object)
      return if type == "BOOKMARK"
      raise StreamError, "namespace Pod watch returned a Pod outside its scope" unless object.dig("metadata", "namespace") == @namespace

      @observe.call(object, type, @cursor)
    rescue KeyError, NoMethodError, TypeError
      raise StreamError, "namespace Pod watch returned an invalid event"
    end

    def raw_command(parameters)
      [*@command, "--request-timeout=#{REQUEST_SECONDS}s", "get", "--raw", "#{@path}?#{URI.encode_www_form(parameters)}"]
    end

    def parse_json(bytes)
      json = bytes.force_encoding(Encoding::UTF_8)
      raise JSON::ParserError, "namespace Pod watch JSON is not UTF-8" unless json.valid_encoding?

      JSON.parse(json)
    end

    def cursor(object)
      value = object.dig("metadata", "resourceVersion")
      return value if value.is_a?(String) && !value.empty?

      raise StreamError, "namespace Pod watch response had no resourceVersion"
    end

    def drain_error(io)
      buffer = +""
      while (chunk = io.read(1024))
        buffer = (buffer << chunk).byteslice(-MAX_ERROR_BYTES, MAX_ERROR_BYTES) || buffer
      end
      buffer
    end

    def signal(child, signal)
      Process.kill(signal, child.pid) if child&.alive?
    rescue Errno::ESRCH
      nil
    end

    def record_error(message)
      @lock.synchronize { @error ||= message }
    end
  end
end
