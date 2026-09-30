# frozen_string_literal: true

module Rubernetes
  module Node
    # pkg/kubelet/pleg/evented.go (EventedPLEG feature gate): container
    # lifecycle events streamed by the CRI runtime (GetContainerEvents)
    # instead of a one-second relist.  Every stream attempt is counted in
    # kubelet_evented_pleg_connection_{success,error}_count and each event's
    # age when it arrives in kubelet_evented_pleg_connection_latency_seconds.
    # After max_stream_retries failed connections the generic relist takes
    # over again at its default period.
    class EventedPLEG
      MAX_STREAM_RETRIES = 5
      GENERIC_RELIST_SECONDS_WITH_EVENTS = 300.0
      RETRY_DELAY_SECONDS = 1.0
      SIGNIFICANT_EVENTS = %w[CONTAINER_STOPPED_EVENT CONTAINER_STARTED_EVENT CONTAINER_DELETED_EVENT].freeze

      attr_reader :attempts

      # +client+: Runtime::CRI::Client (stream(service, method, request) yields
      # :connected then each event Hash); +on_event+: ->(pod_uid, type,
      # container_id); +relist+: forces a generic relist; +on_fallback+: the
      # stream gave up.
      def initialize(client:, on_event:, metrics: nil, relist: nil, on_fallback: nil, max_stream_retries: MAX_STREAM_RETRIES,
                     retry_delay: RETRY_DELAY_SECONDS, logger: nil, clock: -> { Time.now.to_f })
        @client = client
        @on_event = on_event
        @metrics = metrics
        @relist = relist
        @on_fallback = on_fallback
        @max_stream_retries = max_stream_retries
        @retry_delay = retry_delay
        @logger = logger
        @clock = clock
        @attempts = 0
        @stop = false
        @thread = nil
        @in_use = false
      end

      def in_use? = @in_use

      def start
        return self if @thread&.alive?

        @stop = false
        @in_use = true
        @thread = Thread.new do
          Thread.current.name = "evented-pleg"
          watch_events
        end
        self
      end

      def stop
        @stop = true
        @in_use = false
        thread = @thread
        @thread = nil
        thread&.join(2)
        self
      end

      # watchEventsChannel: one stream after another until told to stop or
      # the retries run out.
      def watch_events
        until @stop
          if @attempts >= @max_stream_retries
            @in_use = false
            @on_fallback&.call
            break
          end
          begin
            @client.stream("RuntimeService", "GetContainerEvents", {}) do |message|
              if message == :connected
                @metrics&.evented_pleg_connected
              else
                process_event(message)
              end
              break if @stop
            end
            # A stream the runtime ended cleanly is opened again.
          rescue StandardError => error
            @metrics&.evented_pleg_connection_error
            @attempts += 1
            @logger&.warn("pleg.evented_stream_failed", attempt: @attempts, error: error.message.to_s[0, 200]) if @logger.respond_to?(:warn)
            begin
              @relist&.call
            rescue StandardError
              nil
            end
            sleep(@retry_delay) unless @stop
          end
        end
      end

      # processCRIEvent: stopped/started/deleted containers reach the
      # lifecycle; the event's age is the connection latency.
      def process_event(event)
        return unless event.is_a?(Hash)

        created_at = event["created_at"].to_i
        @metrics&.evented_pleg_latency([(@clock.call * 1_000_000_000).to_i - created_at, 0].max / 1_000_000_000.0) if created_at.positive?
        uid = event.dig("pod_sandbox_status", "metadata", "uid").to_s
        return if uid.empty?

        type = event["container_event_type"].to_s
        return unless SIGNIFICANT_EVENTS.include?(type)

        @on_event.call(uid, type, event["container_id"].to_s)
      rescue StandardError => error
        @logger&.warn("pleg.evented_event_failed", error: error.message.to_s[0, 200]) if @logger.respond_to?(:warn)
      end
    end
  end
end
