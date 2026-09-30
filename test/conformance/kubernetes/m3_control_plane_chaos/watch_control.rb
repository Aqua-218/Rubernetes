#!/usr/bin/env ruby
# frozen_string_literal: true

# Project-owned watch chaos control. Every list, watch, and mutation goes to
# the shared HTTP API process. Faults only transform a real HTTP watch stream
# before it enters the production Reflector/Informer/DeltaFIFO pipeline.

require "digest"
require "json"
require "securerandom"
require "time"

ROOT = File.expand_path("../../../..", __dir__).freeze
require File.join(ROOT, "lib", "rubernetes", "client")
require File.join(ROOT, "lib", "rubernetes", "controller")
require File.join(ROOT, "lib", "rubernetes", "watch")

module M3WatchControl
  REQUIRED_PROPERTIES = %w[
    duplicate_suppression out_of_order_delivery watch_reconnect resync
  ].freeze

  # Instrument the production WorkQueue without replacing it.  Informer owns
  # the queue instance and this adapter records the complete consumer
  # lifecycle; the underlying queue still performs all deduplication, dirty
  # key, retry backoff, token-bucket, and shutdown decisions.
  class ObservedWorkQueue
    attr_reader :operations, :retry_delays

    def initialize(queue)
      @queue = queue
      @operations = []
      @retry_delays = []
      @mutex = Mutex.new
    end

    def add(key)
      record("add", key)
      @queue.add(key)
    end

    def add_rate_limited(key)
      delay = @queue.add_rate_limited(key)
      @mutex.synchronize do
        @retry_delays << delay
        @operations << {"operation" => "retry", "key" => key.to_s, "delay_seconds" => delay,
                        "retry_count" => @queue.num_requeues(key)}
      end
      delay
    end

    def get(timeout: nil)
      key, shutdown = @queue.get(timeout: timeout)
      @mutex.synchronize do
        @operations << {"operation" => "get", "key" => key, "shutdown" => shutdown,
                        "inflight" => @queue.respond_to?(:length) ? @queue.length : nil}
      end
      [key, shutdown]
    end

    def done(key)
      @queue.done(key)
      record("done", key)
    end

    def shutdown
      record("shutdown", nil)
      @queue.shutdown
    end

    def method_missing(name, *, **keywords, &)
      return super unless @queue.respond_to?(name)

      @queue.public_send(name, *, **keywords, &)
    end

    def respond_to_missing?(name, include_private = false)
      @queue.respond_to?(name, include_private) || super
    end

    private

    def record(operation, key)
      @mutex.synchronize { @operations << {"operation" => operation, "key" => key&.to_s} }
    end
  end

  def exercise_queue(queue, injected_failure: false, dirty_key: nil)
    failure_injected = injected_failure
    processed = []
    loop do
      key, shutdown = queue.get(timeout: 0)
      break if shutdown || key.nil?

      key = key.to_s
      processed << key
      # A write arriving while the key is in flight must mark it dirty and
      # produce exactly one follow-up after done.  This is the same race the
      # controller Manager faces when a watch update lands during reconcile.
      queue.add(dirty_key || key) if processed.length == 1
      if !failure_injected && queue.respond_to?(:add_rate_limited)
        queue.add_rate_limited(key)
        failure_injected = true
      end
      queue.done(key)
    end
    # Retry backoff is part of the production contract.  Consume one delayed
    # retry and complete it so the observation proves get/done/retry ordering.
    if failure_injected
      key, shutdown = queue.get(timeout: 0.25)
      queue.done(key) if key && !shutdown
    end
    {"processed_keys" => processed, "failure_injected" => failure_injected,
     "operation_count" => queue.operations.length, "operations" => queue.operations,
     "retry_delays" => queue.retry_delays,
     "retry_count" => processed.sum { |key| queue.respond_to?(:num_requeues) ? queue.num_requeues(key) : 0 }}
  end

  module_function :exercise_queue

  module_function

  class RealHTTPFaultSource
    attr_reader :watch_calls, :observations, :gone_observed

    def initialize(client:, namespace:, target:, faults:)
      @client = client
      @namespace = namespace
      @target = target
      @faults = faults
      @watch_calls = 0
      @observations = {}
      @gone_observed = false
      @producer_error = nil
    end

    def list(resource:, namespace: @namespace, resource_version: nil, **_options)
      descriptor = descriptor_for(resource)
      query = {}
      query["resourceVersion"] = resource_version.to_s unless resource_version.nil?
      @client.get(descriptor.resource, namespace: namespace, api_version: descriptor.api_version,
                                       query: query.empty? ? nil : query)
    end

    def watch(resource:, namespace: @namespace, resource_version: nil, **_options)
      descriptor = descriptor_for(resource)
      fault = @faults.fetch(@watch_calls, "eof").to_s
      @watch_calls += 1
      if fault == "gone_410"
        compact_history!
        begin
          @client.watch_events(
            descriptor.resource,
            namespace: namespace,
            api_version: descriptor.api_version,
            query: {"resourceVersion" => resource_version.to_s, "timeoutSeconds" => "1"},
            # The production Reflector owns the 410 relist decision in this
            # probe.  Disable the client's lower-level transparent reconnect
            # so the real HTTP 410 reaches Reflector#watch_once exactly once.
            reconnect: false,
            max_reconnects: 0
          )
        rescue Rubernetes::Client::APIError => error
          @gone_observed = true if error.status == 410
          raise
        end
      else
        producer = Thread.new do
          sleep 0.03
          if fault == "out_of_order"
            patch_target("#{fault}-first-#{SecureRandom.hex(4)}")
            sleep 0.01
            patch_target("#{fault}-second-#{SecureRandom.hex(4)}")
          else
            patch_target("#{fault}-#{SecureRandom.hex(4)}")
          end
        rescue StandardError => error
          @producer_error = error
        end
        events = @client.watch_events(
          descriptor.resource,
          namespace: namespace,
          api_version: descriptor.api_version,
          query: {
            "resourceVersion" => resource_version.to_s,
            "timeoutSeconds" => "1",
            "allowWatchBookmarks" => "true"
          }
        )
        producer.join
        raise @producer_error if @producer_error

        transformed = transform(events, fault)
        @observations[fault] = {
          "delivered_event_count" => transformed.length,
          "delivered_resource_versions" => transformed.filter_map { |event| event.dig("object", "metadata", "resourceVersion") },
          "unique_delivered_resource_versions" => transformed.filter_map do |event|
            event.dig("object", "metadata", "resourceVersion")
          end.uniq,
          "delivered_bookmark_count" => transformed.count { |event| event["type"].to_s == "BOOKMARK" },
          "real_http_event_count" => events.length
        }
        transformed
      end
    end

    private

    def descriptor_for(resource)
      resource.is_a?(Rubernetes::Controller::ResourceDescriptor) ? resource : Rubernetes::Controller::ResourceDescriptor.parse(resource)
    end

    def patch_target(value)
      @client.patch(
        "ConfigMap",
        {"metadata" => {"annotations" => {"rubernetes.io/m3-watch-sequence" => value}}},
        type: :merge,
        namespace: @namespace,
        api_version: "v1",
        name: @target.fetch("name")
      )
    end

    def compact_history!
      # The built-in API server uses a bounded in-process history, but the
      # process remains shared across workers. Enough real commits force the
      # stale watch RV into the API's HTTP 410 Gone path.
      160.times { |index| patch_target("compaction-#{index}-#{SecureRandom.hex(3)}") }
    end

    def transform(events, fault)
      values = Array(events)
      case fault
      when "duplicate"
        values.empty? ? values : [values.first, values.first, *values.drop(1)]
      when "out_of_order"
        values.length < 2 ? values : [values[1], values[0], *values.drop(2)]
      when "bookmark"
        bookmark_revision = values.last&.dig("object", "metadata", "resourceVersion") || "0"
        [{"type" => "BOOKMARK", "object" => {"metadata" => {"resourceVersion" => bookmark_revision}}}, *values]
      else
        values
      end
    end
  end

  def run
    request = JSON.parse($stdin.read, max_nesting: 128)
    raise ArgumentError, "watch control request must be an object" unless request.is_a?(Hash)
    raise ArgumentError, "watch control request schema_version must be 1" unless request["schema_version"] == 1

    endpoint = ENV.fetch("RUBERNETES_M3_API_ENDPOINT")
    client = Rubernetes::Client::KubernetesClient.new(server: endpoint)
    namespace = request.dig("target", "namespace").to_s
    raise ArgumentError, "watch target namespace is required" if namespace.empty?

    target = create_target(client, namespace, request["component"].to_s)
    faults = Array(request["watch_faults"]).map(&:to_s)
    source = RealHTTPFaultSource.new(client: client, namespace: namespace, target: target, faults: faults)
    queue = ObservedWorkQueue.new(Rubernetes::Watch::WorkQueue.new)
    informer = Rubernetes::Watch::Informer.new(
      client: source,
      resource: Rubernetes::Controller::ResourceDescriptor.parse("ConfigMap"),
      namespace: namespace,
      resync_period: 3600.0,
      queue: queue
    )
    counters = Hash.new(0)
    informer.on(:add) { counters[:add] += 1 }
    informer.on(:update) { counters[:update] += 1 }
    informer.on(:delete) { counters[:delete] += 1 }
    informer.on(:sync) { counters[:sync] += 1 }

    events = []
    faults.each do |fault|
      before_sync = counters[:sync]
      before_handlers = counters.dup
      before_watch_calls = source.watch_calls
      informer.run_once
      informer.resync! if fault == "resync"
      queue_observation = exercise_queue(queue, dirty_key: "#{namespace}/#{target.fetch("name")}")
      target_object = informer.indexer.get("#{namespace}/#{target.fetch("name")}")
      runtime_observation = {
        "handler_delta" => counter_delta(before_handlers, counters),
        "watch_call_delta" => source.watch_calls - before_watch_calls,
        "indexer_resource_version" => target_object&.dig("metadata", "resourceVersion"),
        "indexer_contains_target" => !target_object.nil?
      }
      events << {
        "id" => fault,
        "event" => fault,
        "passed" => event_passed?(fault, source, target, client, counters, before_sync, runtime_observation),
        "attempt_count" => 1,
        "observed_at" => Time.now.utc.iso8601(6),
        "observation" => runtime_observation.merge(
          "fault" => fault,
          "watch_call_count" => source.watch_calls,
          "gone_410_observed" => source.gone_observed,
          "source_observation" => source.observations[fault] || {},
          "queue_observation" => queue_observation,
          "sync_callbacks" => counters[:sync],
          "resource_version" => informer.reflector.resource_version
        )
      }
    end

    properties = property_results(events, source, counters)
    passed = events.all? { |event| event["passed"] == true } && properties.all? { |property| property["passed"] == true }
    result = {
      "schema_version" => 1,
      "scenario" => request["scenario"],
      "component" => request["component"],
      "passed" => passed,
      "faults" => faults,
      "events" => events,
      "properties" => properties,
      "duplicate_loss_count" => fault_failures(events, "duplicate"),
      "out_of_order_count" => fault_failures(events, "out_of_order"),
      "reconnect_loss_count" => %w[eof reconnect].sum { |fault| fault_failures(events, fault) },
      "resync_loss_count" => fault_failures(events, "resync"),
      "watch_calls" => source.watch_calls,
      "raw_trace_sha256" => Digest::SHA256.hexdigest(JSON.generate(events: events, properties: properties)),
      "observation" => {
        "endpoint" => endpoint,
        "production_classes" => %w[Rubernetes::Watch::Reflector Rubernetes::Watch::Informer Rubernetes::Watch::DeltaFIFO
                                   Rubernetes::Watch::Indexer Rubernetes::Watch::WorkQueue],
        "indexer_size" => informer.indexer.size,
        "handler_counters" => counters,
        "queue" => {"class" => Rubernetes::Watch::WorkQueue.name,
                    "operations" => queue.operations,
                    "retry_delays" => queue.retry_delays,
                    "get_count" => queue.operations.count { |entry| entry["operation"] == "get" },
                    "done_count" => queue.operations.count { |entry| entry["operation"] == "done" },
                    "retry_count" => queue.operations.count { |entry| entry["operation"] == "retry" }}
      }
    }
    JSON.pretty_generate(result)
  ensure
    informer&.stop
  end

  def create_target(client, namespace, component)
    name = "m3-watch-#{Process.pid}-#{component.tr("-", "")}-#{SecureRandom.hex(3)}"
    object = {
      "apiVersion" => "v1",
      "kind" => "ConfigMap",
      "metadata" => {"name" => name, "namespace" => namespace, "annotations" => {"rubernetes.io/m3-watch-sequence" => "initial"}},
      "data" => {"m3" => "watch"}
    }
    client.create(object, namespace: namespace, api_version: "v1")
    {"kind" => "ConfigMap", "api_version" => "v1", "namespace" => namespace, "name" => name}
  rescue Rubernetes::Client::APIError => error
    raise unless error.status == 409

    {"kind" => "ConfigMap", "api_version" => "v1", "namespace" => namespace, "name" => name}
  end

  def event_passed?(fault, source, target, client, counters, before_sync, runtime_observation)
    object = client.get("ConfigMap", target.fetch("name"), namespace: target.fetch("namespace"), api_version: "v1")
    marker = object.dig("metadata", "annotations", "rubernetes.io/m3-watch-sequence").to_s
    source_observation = source.observations[fault] || {}
    delivered_versions = Array(source_observation["delivered_resource_versions"]).map(&:to_s)
    unique_versions = Array(source_observation["unique_delivered_resource_versions"]).map(&:to_s)
    handler_updates = runtime_observation.dig("handler_delta", "update").to_i
    indexer_version = runtime_observation["indexer_resource_version"].to_s
    case fault
    when "duplicate"
      delivered_versions.length > unique_versions.length && unique_versions.length.positive? &&
        handler_updates == unique_versions.length && indexer_version == newest_version(unique_versions)
    when "out_of_order"
      delivered_versions.length >= 2 && unique_versions.length >= 2 &&
        delivered_versions != delivered_versions.sort_by { |version| Integer(version) } &&
        indexer_version == newest_version(unique_versions) && handler_updates < delivered_versions.length
    when "gone_410"
      source.gone_observed && !marker.empty?
    when "bookmark"
      source_observation["delivered_bookmark_count"].to_i == 1 && !marker.empty?
    when "eof", "reconnect"
      runtime_observation["watch_call_delta"].to_i.positive? && !marker.empty?
    when "resync"
      counters[:sync] > before_sync
    else
      !marker.empty?
    end
  end

  def counter_delta(before, after)
    after.each_with_object({}) do |(key, value), result|
      result[key.to_s] = value.to_i - before.fetch(key, 0).to_i
    end
  end

  def newest_version(versions)
    Array(versions).map(&:to_s).max_by { |version| Integer(version) }
  end

  def fault_failures(events, fault)
    Array(events).count { |event| event["id"] == fault && event["passed"] != true }
  end

  def property_results(events, source, _counters)
    event_by_id = events.to_h { |event| [event.fetch("id"), event] }
    queue = events.filter_map { |event| event.dig("observation", "queue_observation") }.first || {}
    queue_operations = Array(queue["operations"])
    queue_gets = queue_operations.count { |entry| entry["operation"] == "get" }
    queue_dones = queue_operations.count { |entry| entry["operation"] == "done" }
    queue_retries = queue_operations.count { |entry| entry["operation"] == "retry" }
    queue_contract = queue["failure_injected"] == true && queue_gets.positive? && queue_dones.positive? &&
                     queue_retries.positive? && queue_operations.any? do |entry|
                                                  entry["operation"] == "get" && entry["inflight"].to_i.positive?
                                                end &&
                     Array(queue["retry_delays"]).all? { |delay| delay.is_a?(Numeric) && delay.positive? }
    [
      property(
        "duplicate_suppression",
        event_by_id["duplicate"]["passed"] == true &&
          source.observations.fetch("duplicate", {}).fetch("delivered_event_count", 0) >= 2 &&
          source.observations.fetch("duplicate", {}).fetch("unique_delivered_resource_versions", []).length >= 1 &&
          queue_contract,
        "duplicate watch event was delivered through the real HTTP stream and converged once"
      ),
      property(
        "out_of_order_delivery",
        event_by_id["out_of_order"]["passed"] == true &&
          source.observations.fetch("out_of_order", {}).fetch("delivered_resource_versions", []).length >= 2 &&
          source.observations.fetch("out_of_order", {}).fetch("unique_delivered_resource_versions", []).length >= 2 &&
          queue_contract,
        "out-of-order resource versions were delivered to the production reflector"
      ),
      property(
        "watch_reconnect",
        event_by_id["eof"]["passed"] == true && event_by_id["reconnect"]["passed"] == true &&
          event_by_id["eof"].dig("observation", "watch_call_delta").to_i.positive? &&
          event_by_id["reconnect"].dig("observation", "watch_call_delta").to_i.positive? &&
          queue_contract,
        "EOF and reconnect each completed a real HTTP watch attempt"
      ),
      property(
        "resync",
        event_by_id["resync"]["passed"] == true &&
          event_by_id["resync"].dig("observation", "handler_delta", "sync").to_i.positive? &&
          queue_contract,
        "informer resync re-enqueued the cached object"
      )
    ]
  end

  def property(id, passed, detail)
    {
      "id" => id,
      "property" => id,
      "passed" => passed == true,
      "attempt_count" => 1,
      "measurement_source" => "production_module",
      "observation" => {"detail" => detail}
    }
  end
end

puts M3WatchControl.run if $PROGRAM_NAME == __FILE__
