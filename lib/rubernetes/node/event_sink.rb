# frozen_string_literal: true

require_relative "event_recorder"
require_relative "status"

module Rubernetes
  module Node
    # Writes Events through the Kubernetes client: a new Event is created,
    # a repeated one (same aggregate name) has its count and timestamps
    # patched, the way client-go's EventCorrelator updates a series.
    #
    # Events are written from a background thread, as client-go's recorder
    # does: the caller (a scheduling cycle, a Pod worker) must not wait a
    # write round trip for a record nobody reads synchronously.  A bounded
    # queue keeps a slow API server from holding events in memory without
    # limit; past it the oldest pending event is dropped and logged.
    class EventSink
      MAX_PENDING = 1024
      IDLE_TIMEOUT_SECONDS = 30

      def initialize(client:, logger: nil, async: true)
        @client = client
        @logger = logger
        @async = async
        @queue = Queue.new
        @mutex = Mutex.new
        @thread = nil
        @draining = false
        @dropped = 0
        @in_flight = 0
        @idle = ConditionVariable.new
      end

      def record_event(event)
        return write_event(event) unless @async

        @mutex.synchronize do
          if @queue.size >= MAX_PENDING
            @queue.pop(true)
            @in_flight -= 1
            @dropped += 1
            log(:warn, "events.dropped", dropped: @dropped, pending: @queue.size)
          end
          @queue << event
          @in_flight += 1
          # @draining, not Thread#alive?: a writer thread that has timed out
          # and is on its way to returning is still "alive", so a record
          # arriving in that window started no thread and its event sat in
          # the queue until some later record happened to find the thread
          # dead.  Specs that wait for an Event -- kubectl describe, the
          # DaemonSet retry spec -- then waited tens of seconds for a record
          # that had already been queued.  The flag is set and cleared under
          # this mutex, so the hand-off has no window.
          unless @draining
            @draining = true
            @thread = Thread.new { drain }
          end
        end
        event
      end

      # Waits until every queued event has been written (tests, shutdown).
      def flush(timeout: 5.0)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        @mutex.synchronize do
          while @in_flight.positive?
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            return false if remaining <= 0

            @idle.wait(@mutex, remaining)
          end
        end
        true
      end

      def pending
        @mutex.synchronize { @in_flight }
      end

      attr_reader :dropped

      private

      def drain
        loop do
          event = @queue.pop(timeout: IDLE_TIMEOUT_SECONDS)
          if event.nil?
            # Idle: let the thread go; the next record starts a new one.
            retire = @mutex.synchronize do
              if @queue.empty?
                @draining = false
                @thread = nil
                true
              else
                false
              end
            end
            return if retire

            next
          end
          begin
            write_event(event)
          ensure
            @mutex.synchronize do
              @in_flight -= 1
              @idle.broadcast if @in_flight.zero?
            end
          end
        end
      rescue StandardError => error
        log(:warn, "events.writer_failed", error: "#{error.class}: #{error.message}")
      ensure
        # However this thread ends, the next record must be able to start
        # another one, and nothing may be left counted as in flight.
        @mutex.synchronize do
          if @draining && @thread == Thread.current
            @draining = false
            @thread = nil
          end
          remaining = @queue.size
          if remaining.positive? && !@draining
            @draining = true
            @thread = Thread.new { drain }
          end
        end
      end

      def write_event(event)
        namespace = event.dig("metadata", "namespace") || "default"
        name = event.dig("metadata", "name")
        @client.create(event, namespace: namespace, api_version: "v1")
      rescue StandardError => error
        if conflict?(error)
          patch = {"count" => event["count"], "lastTimestamp" => event["lastTimestamp"], "message" => event["message"],
                   "series" => event["series"]}.compact
          begin
            @client.patch("events", patch, type: :merge, namespace: namespace, api_version: "v1", name: name)
          rescue StandardError => patch_error
            log(:debug, "events.update_failed", name: name, error: "#{patch_error.class}: #{patch_error.message}")
          end
        else
          log(:debug, "events.create_failed", name: name, error: "#{error.class}: #{error.message}")
        end
        event
      end

      def conflict?(error)
        message = error.message.to_s
        message.include?("409") || message.include?("AlreadyExists") || message.include?("already exists") ||
          error.class.name.include?("Conflict") || error.class.name.include?("AlreadyExists")
      end

      def log(level, event, **fields)
        return unless @logger

        @logger.respond_to?(:call) ? @logger.call(level, event, **fields) : @logger.public_send(level, event, **fields)
      rescue StandardError
        nil
      end
    end

    # Turns the lifecycle's internal trace entries into the Events the
    # kubelet publishes about a Pod (Pulled, Created, Started, Killing,
    # Failed, BackOff, FailedMount, ...), with source.component "kubelet" and
    # source.host the node name, as the conformance suite expects.
    class KubeletEventPublisher
      IMAGE_ERRORS = %w[ErrImagePull ErrImageNeverPull].freeze
      REASONS = {
        "image.resolve" => ["Normal", "Pulling", ->(payload, _) { "Pulling image #{payload["reference"].to_s.inspect}" }],
        # images/image_manager.go EnsureImageExists / pullImage.
        "image.pulled" => ["Normal", "Pulled", lambda do |payload, _|
          took = Helpers.go_duration(payload["seconds"])
          "Successfully pulled image #{payload["reference"].to_s.inspect} in #{took} (#{took} including waiting). " \
            "Image size: #{payload["size"].to_i} bytes."
        end],
        "image.present" => ["Normal", "Pulled", lambda do |payload, _|
          "Container image #{payload["reference"].to_s.inspect} already present on machine and can be accessed by the pod"
        end],
        "image.pull_failed" => ["Warning", "Failed", lambda { |payload, _|
          "Failed to pull image #{payload["reference"].to_s.inspect}: #{payload["error"]}"
        }],
        "image.never_pull" => ["Warning", "ErrImageNeverPull", lambda do |payload, _|
          "Container image #{payload["reference"].to_s.inspect} is not present with pull policy of Never"
        end],
        "image.pinned" => nil,
        "hook.http_fallback" => ["Warning", "LifecycleHTTPFallback", lambda do |payload, _|
          "request to HTTPS lifecycle hook #{payload["host"]} got HTTP response, retry with HTTP succeeded"
        end],
        "container.create" => ["Normal", "Created", ->(payload, _) { "Created container: #{payload["name"]}" }],
        "container.started" => ["Normal", "Started", ->(payload, _) { "Started container #{payload["name"]}" }],
        "container.killing" => ["Normal", "Killing", ->(payload, _) { payload["message"] || "Stopping container #{payload["name"]}" }],
        # kubelet reports a container it could not (re)start as Failed with the
        # runtime's own message; without it a restart that keeps failing is
        # invisible to everyone reading the Pod's events.
        "container.restart_failed" => ["Warning", "Failed",
                                       ->(payload, _) { "Error: #{payload["message"] || payload["error"]}" }],
        "container.exited" => nil,
        "container.backoff" => ["Warning", "BackOff", ->(payload, _) { payload["message"] }],
        "probe.unhealthy" => ["Warning", "Unhealthy", ->(payload, _) { payload["message"] }],
        "volume.failed" => ["Warning", "FailedMount", ->(payload, _) { payload["message"] }],
        "sandbox.failed" => ["Warning", "FailedCreatePodSandBox", ->(payload, _) { payload["message"] }],
        # kuberuntime startContainer: a container whose image could not be
        # had is Failed "Error: <reason>"; the pull's own error is the
        # image manager's event above.
        "pod.failed" => ["Warning", "Failed", lambda do |payload, _|
          IMAGE_ERRORS.include?(payload["reason"].to_s) ? "Error: #{payload["reason"]}" : payload["message"]
        end],
        "pod.admission_failed" => ["Warning", "Failed", ->(payload, _) { payload["message"] }],
        # events/event.go ResizeStarted/Completed/Deferred/Error (events/resize.go messages).
        "pod.resize_started" => ["Normal", "ResizeStarted", ->(payload, _) { payload["message"] }],
        "pod.resize_completed" => ["Normal", "ResizeCompleted", ->(payload, _) { payload["message"] }],
        "pod.resize_deferred" => ["Warning", "ResizeDeferred", ->(payload, _) { payload["message"] }],
        "pod.resize_infeasible" => ["Warning", "ResizeInfeasible", ->(payload, _) { payload["message"] }],
        "pod.resize_error" => ["Warning", "ResizeError", ->(payload, _) { payload["message"] }],
        "pod.dra_prepare_failed" => ["Warning", "FailedPrepareDynamicResources", ->(payload, _) { payload["message"] }],
        # kubelet/events FileSystemResizeSuccess / FileSystemResizeFailed.
        "volume.fs_resized" => ["Normal", "FileSystemResizeSuccessful", ->(payload, _) { payload["message"] }],
        "volume.fs_resize_failed" => ["Warning", "FileSystemResizeFailed", ->(payload, _) { payload["message"] }]
      }.freeze

      def initialize(recorder:, node_name:, lifecycle: nil, logger: nil)
        @recorder = recorder
        @lifecycle = lifecycle
        @node_name = node_name
        @logger = logger
      end

      attr_writer :lifecycle

      # The lifecycle's event_sink contract: (uid, entry).
      def call(uid, entry)
        # Every lifecycle transition also goes to the agent log.  The durable
        # node state keeps events only for live Pods, so a Pod that failed a
        # spec and was deleted left nothing to read afterwards: why a preStop
        # hook did not reach its target, or why a container that exited was
        # still reported Running, could not be answered after the fact.
        log_entry(uid, entry)
        mapping = REASONS.fetch(entry["type"].to_s) { return nil }
        return nil if mapping.nil?

        type, reason, builder = mapping
        record = @lifecycle.respond_to?(:record) ? @lifecycle.record(uid) : nil
        pod = record.is_a?(Hash) ? (record[:pod] || record["pod"]) : nil
        return nil unless pod.is_a?(Hash)

        message = builder.call(entry, pod).to_s
        return nil if message.empty?

        reference = involved(pod)
        reference["fieldPath"] = "spec.containers{#{entry["name"]}}" if entry["name"] && reason != "BackOff" && !entry["name"].to_s.empty?
        @recorder.record(involved_object: reference, reason: reason, message: message, type: type,
                         namespace: reference["namespace"])
      rescue StandardError => error
        @logger&.call(:debug, "events.publish_failed", error: "#{error.class}: #{error.message}")
        nil
      end

      private

      LOGGED_FIELDS = %w[type state name reason exit_code exitCode message seconds error phase restart_count attempt].freeze

      def log_entry(uid, entry)
        return unless @logger

        record = @lifecycle.respond_to?(:record) ? @lifecycle.record(uid) : nil
        pod = record.is_a?(Hash) ? (record[:pod] || record["pod"]) : nil
        metadata = pod.is_a?(Hash) ? (pod["metadata"] || {}) : {}
        fields = entry.select { |key, _| LOGGED_FIELDS.include?(key.to_s) }.transform_keys(&:to_sym)
        fields[:message] = fields[:message].to_s[0, 300] if fields.key?(:message)
        @logger.call(:info, "lifecycle.event", uid: uid, pod: "#{metadata["namespace"]}/#{metadata["name"]}", **fields)
      rescue StandardError
        nil
      end

      def involved(pod)
        metadata = pod["metadata"] || {}
        {"kind" => "Pod", "apiVersion" => "v1", "namespace" => (metadata["namespace"] || "default").to_s,
         "name" => metadata["name"].to_s, "uid" => metadata["uid"].to_s,
         "resourceVersion" => metadata["resourceVersion"]}.compact
      end
    end
  end
end
