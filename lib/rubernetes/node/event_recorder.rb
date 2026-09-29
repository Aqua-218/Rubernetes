# frozen_string_literal: true

# Kubernetes Event aggregation.  Callers can use the recorder with an API
# writer or entirely in memory; repeated occurrences update one Event record
# and expose the series count rather than producing an unbounded event stream.

require "digest"
require "json"
require "securerandom"
require "thread"
require "time"

require_relative "registration"

module Rubernetes
  module Node
    class EventRecorder
      EventRecord = Data.define(:key, :event, :created) do
        def to_h
          {"key" => key, "event" => event, "created" => created}
        end
      end

      DEFAULT_AGGREGATION_WINDOW_SECONDS = 600
      EVENT_RESOURCE = "v1/events".freeze

      def initialize(client: nil, sink: nil, component: "rubernetes-node-agent", reporting_component: nil,
                     reporting_instance: nil, source: nil, clock: -> { Time.now.utc },
                     uid_generator: -> { SecureRandom.uuid }, aggregation_window_seconds: DEFAULT_AGGREGATION_WINDOW_SECONDS,
                     namespace: "default", publish: true, event_time: true, spam_filter: false)
        # `eventTime` is what tells the API server an Event is the newer
        # events.k8s.io shape, which then requires reportingController,
        # reportingInstance and action (validation/events.go
        # legacyValidateEvent).  kubelet's core/v1 events carry
        # firstTimestamp/lastTimestamp and source instead, so a recorder that
        # writes core/v1 leaves eventTime unset.
        @event_time = event_time
        @client = client || sink
        @component = String(reporting_component || component)
        @instance = reporting_instance
        @source = Support.stringify_keys(source || {"component" => @component}.compact)
        @clock = clock
        @uid_generator = uid_generator
        @aggregation_window_seconds = Float(aggregation_window_seconds)
        raise ArgumentError, "aggregation_window_seconds must not be negative" if @aggregation_window_seconds.negative?
        @default_namespace = String(namespace)
        @publish = !!publish
        @mutex = Mutex.new
        @records = {}
        # client-go's EventSourceObjectSpamFilter (opt-in): per source and
        # involved object, a token bucket of 25 refilled at one per 300 s.
        @spam_filter = spam_filter
        @spam_buckets = {}
        @aggregates = {}
        @recorded_since_prune = 0
      end

      SPAM_BURST = 25
      SPAM_QPS = 1.0 / 300
      PRUNE_EVERY = 256

      attr_reader :client, :component, :reporting_instance

      def record(involved_object:, reason:, message:, type: "Normal", action: nil, namespace: nil, count: 1,
                 now: @clock.call, publish: true, annotations: nil, related: nil)
        object = normalize_reference(involved_object, namespace: namespace)
        reason = String(reason)
        message = String(message)
        count = Integer(count)
        raise ArgumentError, "event count must be positive" unless count.positive?
        raise ArgumentError, "event reason must not be empty" if reason.empty?
        raise ArgumentError, "event message must not be empty" if message.empty?
        type = String(type)
        raise ArgumentError, "event type must be Normal or Warning" unless %w[Normal Warning].include?(type)

        timestamp = Support.iso8601(now)
        return nil if @spam_filter && spam?(object, now)

        event = nil
        created = false
        @mutex.synchronize do
          prune(timestamp)
          # client-go events_cache.go: the count of an Event only grows for an
          # identical event (getEventKey: involved object INCLUDING fieldPath,
          # type, reason and message).  Keying on the reason alone merged the
          # "Created container: kas" record into the init container's "Created
          # container: certificates" one, and every later container event of
          # a Pod carried the first container's fieldPath.
          message, key = aggregate(object, reason: reason, action: action, type: type, message: message, now: now)
          existing = @records[key]
          if existing && within_window?(existing.event, timestamp)
            event = merge_event(existing.event, object: object, reason: reason, message: message, type: type,
                                action: action, increment: count, timestamp: timestamp, annotations: annotations,
                                related: related)
          else
            key = unique_key(key, timestamp) if existing
            event = new_event(object: object, reason: reason, message: message, type: type,
                              action: action, count: count, timestamp: timestamp, annotations: annotations,
                              related: related, key: key)
            created = true
          end
          @records[key] = EventRecord.new(key: key, event: event, created: created)
        end
        publish_event(event, namespace: Support.value(object, "namespace", @default_namespace), created: created) if publish && @publish
        Support.deep_copy(event)
      end

      alias event record
      alias record_event record

      # EventAggregatorByReasonFunc: everything but fieldPath and message.
      def aggregate_key(involved_object, reason:, action: nil, type: "Normal", **_options)
        object = normalize_reference(involved_object)
        [
          Support.value(object, "apiVersion", "v1"),
          Support.value(object, "kind", ""),
          Support.value(object, "namespace", ""),
          Support.value(object, "name", ""),
          Support.value(object, "uid", ""),
          String(reason), String(action || ""), String(type), @component.to_s, @instance.to_s
        ].join("|")
      end

      # getEventKey: the aggregate key plus fieldPath and message; two events
      # share a record (count, series) only when they are the same event.
      def event_key(involved_object, reason:, message:, action: nil, type: "Normal")
        object = normalize_reference(involved_object)
        [aggregate_key(object, reason: reason, action: action, type: type),
         Support.value(object, "fieldPath", ""), String(message)].join("|")
      end

      AGGREGATE_MAX_EVENTS = 10
      AGGREGATE_MESSAGE_PREFIX = "(combined from similar events): "

      def get(key)
        @mutex.synchronize { record = @records[key.to_s]; record && Support.deep_copy(record.event) }
      end

      def events
        @mutex.synchronize { @records.values.map { |record| Support.deep_copy(record.event) } }
      end

      alias records events

      def flush
        current = @mutex.synchronize { @records.values.map(&:to_h) }
        current.each do |record|
          event = record.fetch("event")
          publish_event(event, namespace: Support.value(event, "metadata", {})["namespace"] || @default_namespace,
                        created: record.fetch("created"))
        end
        current.length
      end

      def clear(key = nil)
        @mutex.synchronize do
          key ? @records.delete(key.to_s) : @records.clear
        end
      end

      private

      # Aggregation records older than the window can never be merged into
      # again; dropping them keeps a long-lived recorder from growing with
      # every object it ever reported on.
      def prune(timestamp)
        @recorded_since_prune += 1
        return if @recorded_since_prune < PRUNE_EVERY

        @recorded_since_prune = 0
        now = Time.parse(timestamp)
        @records.delete_if do |_, record|
          last = Time.parse(Support.value(record.event, "lastTimestamp").to_s)
          now - last > @aggregation_window_seconds
        rescue ArgumentError
          true
        end
        @spam_buckets.delete_if { |_, bucket| bucket[:tokens] >= SPAM_BURST && now - bucket[:at] > SPAM_BURST / SPAM_QPS }
        @aggregates.delete_if { |_, record| now - record[:at] > @aggregation_window_seconds }
      end

      # getSpamKey: source component/host plus the involved object.
      def spam?(object, now)
        key = [@source["component"], @source["host"], Support.value(object, "kind", ""), Support.value(object, "namespace", ""),
               Support.value(object, "name", ""), Support.value(object, "uid", ""), Support.value(object, "apiVersion", "")].join("|")
        @mutex.synchronize do
          bucket = (@spam_buckets[key] ||= {tokens: SPAM_BURST.to_f, at: now})
          bucket[:tokens] = [SPAM_BURST.to_f, bucket[:tokens] + (now - bucket[:at]) * SPAM_QPS].min
          bucket[:at] = now
          next true if bucket[:tokens] < 1

          bucket[:tokens] -= 1
          false
        end
      end

      def normalize_reference(object, namespace: nil)
        value = Support.object_hash(object)
        metadata = Support.metadata(value)
        result = {
          "apiVersion" => Support.value(value, "apiVersion", "v1"),
          "kind" => Support.value(value, "kind", "Pod"),
          "name" => Support.value(metadata, "name") || Support.value(value, "name"),
          "namespace" => Support.value(metadata, "namespace") || Support.value(value, "namespace") || namespace || @default_namespace,
          "uid" => Support.value(metadata, "uid") || Support.value(value, "uid"),
          "fieldPath" => Support.value(value, "fieldPath")
        }.compact
        raise ArgumentError, "involved object name is required" if result["name"].to_s.empty?
        result
      end

      def new_event(object:, reason:, message:, type:, action:, count:, timestamp:, annotations:, related:, key: "")
        count = Integer(count)
        raise ArgumentError, "event count must be positive" unless count.positive?
        # client-go names an Event "<name>.<unix nanos hex>"; two distinct
        # events of one object in the same instant must not share a name, or
        # the second's create conflicts and the sink's count/message patch
        # lands on the first (the kas container's "Created" ended up on the
        # certificates init container's Event).  The key carries fieldPath
        # and message, so the name is unique per distinct event and stable
        # for its repeats.
        metadata_name = event_name(object, reason, "#{key}|#{timestamp}")
        event = {
          "apiVersion" => "v1",
          "kind" => "Event",
          "metadata" => {
            "name" => metadata_name,
            "namespace" => Support.value(object, "namespace", @default_namespace),
            "uid" => @uid_generator.call.to_s
          },
          "involvedObject" => Support.deep_copy(object),
          "reason" => reason,
          "message" => message,
          "type" => type,
          "count" => count,
          "firstTimestamp" => timestamp,
          "lastTimestamp" => timestamp,
          "reportingComponent" => @component
        }
        event["eventTime"] = timestamp if @event_time
        event["action"] = action.to_s unless action.nil?
        event["reportingInstance"] = @instance.to_s if @instance
        event["source"] = Support.deep_copy(@source) unless @source.empty?
        event["related"] = Support.deep_copy(related) if related
        event["metadata"]["annotations"] = Support.stringify_keys(annotations) if annotations
        event["series"] = {"count" => count, "lastObservedTime" => timestamp} if count > 1
        event
      end

      def merge_event(existing, object:, reason:, message:, type:, action:, increment:, timestamp:, annotations:, related:)
        event = Support.deep_copy(existing)
        event["count"] = Integer(event.fetch("count", 1)) + Integer(increment)
        event["lastTimestamp"] = timestamp
        event["eventTime"] = timestamp if @event_time
        event["message"] = message
        event["involvedObject"] = Support.deep_copy(object)
        event["series"] = {"count" => event["count"], "lastObservedTime" => timestamp}
        event["metadata"] ||= {}
        if annotations
          event["metadata"]["annotations"] = Support.merge_hashes(event["metadata"]["annotations"], annotations)
        end
        event["related"] = Support.deep_copy(related) if related
        event
      end

      # EventAggregator#EventAggregate: similar events (same aggregate key,
      # different messages) are counted per key within the window; from the
      # tenth distinct message on, the event is recorded under the aggregate
      # key with the combined-message prefix, so a flood of distinct messages
      # becomes one Event whose count grows.  Called under @mutex.
      def aggregate(object, reason:, action:, type:, message:, now:)
        group_key = aggregate_key(object, reason: reason, action: action, type: type)
        local_key = event_key(object, reason: reason, message: message, action: action, type: type)
        record = @aggregates[group_key]
        record = nil if record && (now - record[:at]) > @aggregation_window_seconds
        record ||= {keys: {}, at: now}
        record[:keys][local_key] = true
        record[:at] = now
        @aggregates[group_key] = record
        return [message, local_key] if record[:keys].size < AGGREGATE_MAX_EVENTS

        record[:keys].delete(record[:keys].keys.first)
        [AGGREGATE_MESSAGE_PREFIX + message, group_key]
      end

      def within_window?(event, timestamp)
        last = Time.parse(Support.value(event, "lastTimestamp").to_s)
        delta = Time.parse(timestamp) - last
        delta >= 0 && delta <= @aggregation_window_seconds
      rescue ArgumentError
        false
      end

      def unique_key(base, timestamp)
        "#{base}|#{timestamp}"
      end

      def event_name(object, reason, seed)
        name = [Support.value(object, "name"), reason, Digest::SHA256.hexdigest(seed)[0, 10]].compact.join(".")
        name.downcase.gsub(/[^a-z0-9.-]+/, "-")[0, 253]
      end

      def publish_event(event, namespace:, created:)
        return event unless @client
        if @client.respond_to?(:record_event)
          return @client.record_event(event)
        end
        if @client.respond_to?(:upsert)
          return Support.invoke(@client, :upsert, resource: EVENT_RESOURCE, namespace: namespace,
                                 name: Support.value(Support.metadata(event), "name"), object: event)
        end
        method_name = created ? :create : :update
        method_name = :create unless @client.respond_to?(method_name)
        return event unless @client.respond_to?(method_name)

        Support.invoke(@client, method_name, resource: EVENT_RESOURCE, namespace: namespace,
                       name: Support.value(Support.metadata(event), "name"), object: event) || event
      end
    end

    NodeEventRecorder = EventRecorder unless const_defined?(:NodeEventRecorder, false)
  end
end
