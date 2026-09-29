# frozen_string_literal: true

require "json"
require "fileutils"
require "monitor"

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
          registry.register("apiserver_audit_level_total", type: :counter, help: "Counter of policy levels for audit events (1 per request).")
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
