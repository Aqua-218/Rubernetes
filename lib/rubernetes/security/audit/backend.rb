# frozen_string_literal: true

require "json"
require "fileutils"
require "monitor"
require "uri"
require "openssl"
require_relative "../egress"

module Rubernetes
  module Security
    module Audit
      # apiserver/pkg/audit/metrics.go: the families every backend reports to.
      module BackendMetrics
        attr_reader :metrics

        def metrics=(registry)
          @metrics = registry
          return unless registry

          registry.register("apiserver_audit_event_total", type: :counter,
                                                           help: "Counter of audit events generated and sent to the audit backend.")
          registry.register("apiserver_audit_error_total", type: :counter,
                                                           help: "Counter of audit events that failed to be audited properly. Plugin identifies the plugin affected by the error.")
          registry.register("apiserver_audit_level_total", type: :counter,
                                                           help: "Counter of policy levels for audit events (1 per request).")
          registry.register("apiserver_audit_requests_rejected_total", type: :counter,
                                                                       help: "Counter of apiserver requests rejected due to an error in audit logging backend.")
        end

        def observe_event
          @metrics&.increment("apiserver_audit_event_total")
        rescue StandardError
          nil
        end

        def observe_error(plugin, count = 1)
          @metrics&.increment("apiserver_audit_error_total", {"plugin" => plugin}, by: count)
        rescue StandardError
          nil
        end

        def observe_level(level)
          @metrics&.increment("apiserver_audit_level_total", {"level" => level.to_s})
        rescue StandardError
          nil
        end
      end

      # Bounded asynchronous log backend (spec 5.1.8): events are queued and
      # written by a worker to a JSON-lines file.  When the queue is full the
      # event is dropped, counted and recorded to the durable local overflow
      # log so an audit sink outage never blocks API writes and never goes
      # unnoticed.
      class LogBackend
        include BackendMetrics

        attr_reader :path, :dropped, :written

        def initialize(path:, max_queue: 10_000, overflow_path: nil, fsync: false)
          @path = File.expand_path(path)
          @overflow_path = overflow_path ? File.expand_path(overflow_path) : "#{@path}.overflow"
          FileUtils.mkdir_p(File.dirname(@path))
          @queue = Queue.new
          @max_queue = max_queue
          @fsync = fsync
          @dropped = 0
          @written = 0
          @monitor = Monitor.new
          @worker = Thread.new { drain }
          @worker.name = "audit-log-backend"
          @closed = false
        end

        def process(event)
          observe_event
          if @queue.length >= @max_queue
            @monitor.synchronize { @dropped += 1 }
            observe_error("log")
            record_overflow(event)
            return false
          end
          @queue << event
          true
        end

        def flush(timeout: 5)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          sleep 0.005 while !@queue.empty? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
          @queue.empty?
        end

        def close
          return if @closed

          @closed = true
          @queue << :close
          @worker.join(5)
        end

        private

        def drain
          File.open(@path, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |file|
            loop do
              event = @queue.pop
              break if event == :close

              file.write(JSON.generate(event) << "\n")
              file.flush
              file.fsync if @fsync
              @monitor.synchronize { @written += 1 }
            end
          end
        rescue StandardError
          # A failing sink must not take the API server down; keep counting.
          observe_error("log", [@queue.length, 1].max)
          @monitor.synchronize { @dropped += @queue.length }
          @queue.clear
          retry unless @closed
        end

        def record_overflow(event)
          File.open(@overflow_path, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |file|
            file.write(JSON.generate("auditID" => event["auditID"], "stage" => event["stage"], "dropped" => true, "verb" => event["verb"],
                                     "requestURI" => event["requestURI"], "stageTimestamp" => event["stageTimestamp"]) << "\n")
          end
        rescue SystemCallError
          nil
        end
      end

      # Collects events in memory (tests and evidence probes).
      # A blocking-strict webhook failed to record the RequestReceived event:
      # the request is refused (apiserver_audit_requests_rejected_total).
      class RejectedError < StandardError; end

      # --audit-webhook-config-file / --audit-webhook-mode: events POSTed as
      # an audit.k8s.io/v1 EventList.  "batch" (the default) queues and
      # flushes in the background; "blocking" sends inline and only logs a
      # failure; "blocking-strict" sends inline and fails the request when
      # the RequestReceived event cannot be delivered.
      class WebhookBackend
        include BackendMetrics

        MODES = %w[batch blocking blocking-strict].freeze
        DEFAULT_BATCH_MAX_SIZE = 400
        DEFAULT_BATCH_MAX_WAIT = 30.0

        attr_reader :mode

        def initialize(url:, mode: "batch", ca_file: nil, token: nil, timeout: 30.0, batch_max_size: DEFAULT_BATCH_MAX_SIZE,
                       batch_max_wait: DEFAULT_BATCH_MAX_WAIT, http: nil)
          raise ArgumentError, "audit webhook mode must be one of #{MODES.join(", ")}" unless MODES.include?(mode.to_s)

          @uri = URI(url)
          @mode = mode.to_s
          @ca_file = ca_file
          @token = token
          @timeout = Float(timeout)
          @batch_max_size = Integer(batch_max_size)
          @batch_max_wait = Float(batch_max_wait)
          @http = http
          @queue = []
          @monitor = Monitor.new
          @flusher = nil
          @closed = false
        end

        def strict? = @mode == "blocking-strict"

        def process(event)
          observe_event
          if @mode == "batch"
            @monitor.synchronize do
              @queue << event
              start_flusher_locked
            end
            return true
          end
          send_events([event])
          true
        rescue StandardError => error
          observe_error("webhook")
          raise RejectedError, "audit webhook rejected the event: #{error.message}" if strict? && event["stage"] == "RequestReceived"

          false
        end

        def flush(timeout: 5)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          loop do
            batch = @monitor.synchronize { @queue.shift(@batch_max_size) }
            break if batch.empty?

            begin
              send_events(batch)
            rescue StandardError
              observe_error("webhook", batch.length)
            end
            break if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          end
          true
        end

        def close
          @monitor.synchronize { @closed = true }
          flush
          @flusher&.join(1)
        end

        private

        def start_flusher_locked
          return if @flusher&.alive?

          @flusher = Thread.new do
            Thread.current.name = "audit-webhook"
            until @monitor.synchronize { @closed && @queue.empty? }
              sleep(@batch_max_wait) unless @monitor.synchronize { @queue.length >= @batch_max_size }
              flush
            end
          end
        end

        def send_events(events)
          body = JSON.generate("apiVersion" => "audit.k8s.io/v1", "kind" => "EventList", "metadata" => {}, "items" => events)
          status = (@http || method(:post)).call(body)
          raise "HTTP #{status}" unless status.to_i.between?(200, 299)

          status
        end

        def post(body)
          require "net/http"
          http = Egress.http(@uri, "controlplane")
          http.use_ssl = @uri.scheme == "https"
          if http.use_ssl?
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            http.ca_file = @ca_file if @ca_file
          end
          http.open_timeout = @timeout
          http.read_timeout = @timeout
          headers = {"content-type" => "application/json"}
          headers["authorization"] = "Bearer #{@token}" if @token
          http.post(@uri.request_uri, body, headers).code
        end
      end

      # Several backends fed the same events (log + webhook): a strict
      # webhook's rejection propagates, everything else is best effort.
      class UnionBackend
        include BackendMetrics

        def initialize(*backends)
          @backends = backends.flatten.compact
        end

        def metrics=(registry)
          super
          @backends.each { |backend| backend.metrics = registry if backend.respond_to?(:metrics=) }
        end

        def strict? = @backends.any? { |backend| backend.respond_to?(:strict?) && backend.strict? }

        def process(event)
          rejection = nil
          @backends.each do |backend|
            backend.process(event)
          rescue RejectedError => error
            rejection = error
          end
          raise rejection if rejection

          true
        end

        def flush(timeout: 5) = @backends.each { |backend| backend.flush(timeout: timeout) if backend.respond_to?(:flush) }
        def close = @backends.each { |backend| backend.close if backend.respond_to?(:close) }
        def events = @backends.filter_map { |backend| backend.respond_to?(:events) ? backend.events : nil }.flatten
      end

      class MemoryBackend
        include BackendMetrics

        attr_reader :events

        def initialize
          @events = []
          @mutex = Mutex.new
        end

        def process(event)
          observe_event
          @mutex.synchronize { @events << event }
          true
        end

        def flush(timeout: 0) = true
        def close = nil
      end
    end
  end
end
