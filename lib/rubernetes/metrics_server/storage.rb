# frozen_string_literal: true

require_relative "../schema/quantity"

module Rubernetes
  module MetricsServer
    # sigs.k8s.io/metrics-server pkg/storage (v0.8.0): the last two scrapes of
    # every node and container.  CPU usage is the cumulative counter's
    # increase over the time between the two points; memory is the latest
    # working set.  A point without an older one to compare with yields
    # nothing yet.
    class Storage
      Point = Struct.new(:start_time, :timestamp, :cumulative_cpu, :memory, keyword_init: true) do
        def empty? = start_time.nil? && timestamp.nil? && cumulative_cpu.to_i.zero? && memory.to_i.zero?
      end
      Batch = Struct.new(:nodes, :pods, keyword_init: true) do
        def self.empty = new(nodes: {}, pods: {})
      end
      Usage = Struct.new(:cpu, :memory, :timestamp, :window, keyword_init: true)

      FRESH_CONTAINER_MIN_RESOLUTION = 10.0
      MAX_INT64 = (1 << 63) - 1
      # Go's zero time.Time: an unknown start time is before every timestamp.
      ZERO_TIME = Time.utc(1, 1, 1).freeze

      def initialize(metric_resolution: 15.0)
        @metric_resolution = Float(metric_resolution)
        @node_last = {}
        @node_prev = {}
        @pod_last = {}
        @pod_prev = {}
        @mutex = Mutex.new
      end

      def ready? = @mutex.synchronize { !@node_prev.empty? || !@pod_prev.empty? }

      def store(batch)
        @mutex.synchronize do
          store_nodes(batch.nodes)
          store_pods(batch.pods)
        end
      end

      # nodeStorage.GetMetrics: name -> Usage for the nodes that have two points.
      def node_usage(name)
        @mutex.synchronize do
          last = @node_last[name]
          prev = @node_prev[name]
          last && prev ? resource_usage(last, prev) : nil
        end
      end

      # podStorage.GetMetrics: [container usages, earliest time info], or nil
      # unless every container of the latest scrape has a previous point.
      def pod_usage(namespace, name)
        key = [namespace.to_s, name.to_s]
        @mutex.synchronize do
          last = @pod_last[key]
          prev = @pod_prev[key]
          next nil unless last && prev

          containers = []
          earliest = nil
          complete = last.all? do |container, point|
            before = prev[container]
            next false unless before

            usage = resource_usage(point, before)
            next true if usage.nil?

            containers << [container, usage]
            earliest = usage if earliest.nil? || earliest.timestamp > usage.timestamp
            true
          end
          complete ? [containers, earliest] : nil
        end
      end

      private

      # storage.resourceUsage: nil when the start time or the counter went
      # backwards (a restarted node or container).
      def resource_usage(last, prev)
        return nil if start_of(last) < start_of(prev)
        return nil if last.cumulative_cpu < prev.cumulative_cpu

        # Exact nanoseconds, like time.Time.Sub; the rate itself is Go's
        # float64(delta) / window.Seconds(), truncated to uint64.
        window = last.timestamp.to_r - prev.timestamp.to_r
        rate = window.zero? ? 0 : ((last.cumulative_cpu - prev.cumulative_cpu).to_f / window.to_f).to_i
        Usage.new(cpu: nano_quantity(rate), memory: binary_quantity(last.memory), timestamp: last.timestamp, window: window)
      end

      # uint64Quantity(val, DecimalSI, -9).
      def nano_quantity(nanocores)
        return Schema::Quantity.parse("#{nanocores / 10}e-8").to_s if nanocores > MAX_INT64

        Schema::Quantity.parse("#{nanocores}n").to_s
      end

      # uint64Quantity(val, BinarySI, 0).
      def binary_quantity(bytes)
        bytes = (bytes / 10) * 10 if bytes > MAX_INT64
        Schema::Quantity.new(Rational(bytes), :binary_si).to_s
      end

      def start_of(point) = point.start_time || ZERO_TIME

      def store_nodes(nodes)
        last = {}
        prev = {}
        nodes.each do |name, point|
          next if last.key?(name)

          last[name] = point
          old = @node_last[name]
          next unless old

          if point.timestamp > old.timestamp
            prev[name] = old
          elsif (older = @node_prev[name]) && older.timestamp < point.timestamp
            prev[name] = older
          end
        end
        @node_last = last
        @node_prev = prev
      end

      def store_pods(pods)
        last = {}
        prev = {}
        pods.each do |key, containers|
          next if last.key?(key)

          new_last = {}
          new_prev = {}
          containers.each do |container, point|
            next if new_last.key?(container)

            new_last[container] = point
            started = start_of(point)
            age = point.timestamp.to_r - started.to_r
            if started < point.timestamp && age < @metric_resolution && age >= FRESH_CONTAINER_MIN_RESOLUTION
              # A container younger than one resolution: compare with its start.
              new_prev[container] = Point.new(start_time: started, timestamp: started, cumulative_cpu: 0, memory: point.memory)
            elsif (old_pod = @pod_last[key]) && (old = old_pod[container]) && started < old.timestamp
              if point.timestamp > old.timestamp
                new_prev[container] = old
              elsif (older_pod = @pod_prev[key]) && (older = older_pod[container]) && older.timestamp < point.timestamp
                new_prev[container] = older
              end
            end
          end
          prev[key] = new_prev unless new_prev.empty?
          last[key] = new_last
        end
        @pod_last = last
        @pod_prev = prev
      end
    end
  end
end
