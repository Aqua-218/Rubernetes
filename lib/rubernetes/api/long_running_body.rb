# frozen_string_literal: true

module Rubernetes
  module API
    # A long-running response (a watch, a followed log, a proxied stream)
    # as kube-apiserver's endpoints/metrics sees it: counted in
    # apiserver_longrunning_requests while it is served, each watch event in
    # apiserver_watch_events_total and, once the transport has encoded it,
    # apiserver_watch_events_sizes; +finish+ runs once, when the stream ends
    # or is closed, so the request itself is recorded with its whole
    # duration (upstream's InstrumentRouteFunc returns only then).
    #
    # The pieces pass through unchanged -- in-process callers still read
    # decoded events -- and everything else is delegated to the stream.
    class LongRunningBody
      # +watch_list+: {labels:, started:} for a watch that asked for its
      # initial events (sendInitialEvents): the time from the request's
      # arrival to the initial-events-end bookmark being written is
      # apiserver_watch_list_duration_seconds (handlers/watch.go).
      def initialize(body, metrics:, labels:, watch: nil, finish: nil, watch_list: nil)
        @body = body
        @metrics = metrics
        @labels = labels
        @watch = watch
        @watch_list = watch_list
        @finish = finish
        @mutex = Mutex.new
        @started = false
        @finished = false
        singleton_class.alias_method(:close, :close_stream) if body.respond_to?(:close)
      end

      attr_reader :body

      def each(**options, &block)
        return enum_for(:each, **options) unless block

        start
        begin
          forward = accepts_timeout? ? options : {}
          @body.each(**forward) do |piece|
            @metrics.watch_event(@watch) if @watch && !piece.nil?
            initial_events_end = @watch_list && initial_events_end?(piece)
            begin
              yield(piece)
            ensure
              # Once the bookmark is written -- a consumer may stop right
              # after it; a failed write ($!) is not recorded.
              record_watch_list if initial_events_end && $!.nil?
            end
          end
        ensure
          finish
        end
      end

      # Transport::HTTPServer reports each piece's encoded size.
      def piece_written(bytes)
        @metrics.watch_event_size(@watch, bytes) if @watch
      end

      # #close exists only when the stream has one: the transport decides by
      # respond_to?(:close) whether to watch the peer, and a wrapper that
      # always answered yes changed that decision for every stream it wrapped.
      def close_stream
        @body.close
      ensure
        finish
      end

      def respond_to_missing?(name, include_private = false) = @body.respond_to?(name, include_private) || super

      def method_missing(name, ...)
        return super unless @body.respond_to?(name)

        @body.public_send(name, ...)
      end

      private

      INITIAL_EVENTS_END = "k8s.io/initial-events-end"

      def initial_events_end?(piece)
        type, object = if piece.respond_to?(:type) && piece.respond_to?(:object)
                         [piece.type, piece.object]
                       elsif piece.is_a?(Hash)
                         [piece["type"] || piece[:type], piece["object"] || piece[:object]]
                       end
        type.to_s == "BOOKMARK" && object.is_a?(Hash) && object.dig("metadata", "annotations", INITIAL_EVENTS_END) == "true"
      rescue StandardError
        false
      end

      def record_watch_list
        watch_list = @watch_list
        @watch_list = nil
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - watch_list[:started]
        @metrics.observe("apiserver_watch_list_duration_seconds", elapsed, watch_list[:labels])
      rescue StandardError
        nil
      end

      def accepts_timeout?
        @body.method(:each).parameters.any? { |kind, name| (%i[key keyreq].include?(kind) && name == :timeout) || kind == :keyrest }
      rescue NameError
        false
      end

      def start
        @mutex.synchronize do
          return if @started

          @started = true
        end
        @metrics.longrunning(@labels, 1)
      end

      def finish
        started = @mutex.synchronize do
          return if @finished

          @finished = true
          @started
        end
        @metrics.longrunning(@labels, -1) if started
        @finish&.call
      rescue StandardError
        nil
      end
    end
  end
end
