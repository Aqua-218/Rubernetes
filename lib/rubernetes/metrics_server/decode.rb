# frozen_string_literal: true

require_relative "storage"

module Rubernetes
  module MetricsServer
    # metrics-server pkg/scraper/client/resource/decode.go: one node's
    # /metrics/resource (Prometheus text) as a batch.  Timestamps are the
    # samples' own milliseconds, or the request time when a sample has none.
    # A node without both CPU and memory, or a container missing either, is
    # left out rather than reported as zero.
    module Decode
      NODE_CPU = "node_cpu_usage_seconds_total"
      NODE_MEMORY = "node_memory_working_set_bytes"
      CONTAINER_CPU = "container_cpu_usage_seconds_total"
      CONTAINER_MEMORY = "container_memory_working_set_bytes"
      CONTAINER_START = "container_start_time_seconds"
      SAMPLE = /\A([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)(?:\s+(-?\d+))?\s*\z/

      module_function

      def batch(text, default_time:, node_name:)
        node = Storage::Point.new(cumulative_cpu: 0, memory: 0)
        pods = Hash.new { |hash, key| hash[key] = {} }
        default_ms = (default_time.to_r * 1000).to_i
        text.to_s.each_line do |line|
          line = line.strip
          next if line.empty? || line.start_with?("#")

          match = SAMPLE.match(line)
          next unless match

          name, labels, value, stamp = match.captures
          value = Float(value, exception: false)
          next if value.nil?

          time = Time.at(Rational(stamp ? Integer(stamp) : default_ms, 1000)).utc
          case name
          when NODE_CPU
            node.cumulative_cpu = (value * 1e9).to_i
            node.timestamp = time
          when NODE_MEMORY
            node.memory = value.to_i
            node.timestamp = time
          when CONTAINER_CPU, CONTAINER_MEMORY, CONTAINER_START
            namespace, pod, container = container_labels(labels)
            point = (pods[[namespace, pod]][container] ||= Storage::Point.new(cumulative_cpu: 0, memory: 0))
            case name
            when CONTAINER_CPU
              point.cumulative_cpu = (value * 1e9).to_i
              point.timestamp = time
            when CONTAINER_MEMORY
              point.memory = value.to_i
              point.timestamp = time
            else
              point.start_time = Time.at(Rational((value * 1e9).to_i, 1_000_000_000)).utc
            end
          end
        end
        result = Storage::Batch.empty
        result.nodes[node_name] = node if node.timestamp && node.cumulative_cpu.positive? && node.memory.positive?
        pods.each do |key, containers|
          next if containers.empty?

          complete = check_containers(containers)
          result.pods[key] = complete if complete
        end
        result
      end

      # parseContainerLabels.
      def container_labels(labels)
        values = labels.to_s.scan(/(\w+)="((?:[^"\\]|\\.)*)"/).to_h
        [values["namespace"].to_s, values["pod"].to_s, values["container"].to_s]
      end

      # checkContainerMetrics: a container seen only as a start time is
      # skipped; one with CPU or memory missing drops the whole Pod.
      def check_containers(containers)
        result = {}
        containers.each do |name, point|
          next if point.timestamp.nil? && point.cumulative_cpu.zero? && point.memory.zero? && point.start_time.nil?
          return nil if point.cumulative_cpu.zero? || point.memory.zero?

          result[name] = point
        end
        result
      end
    end
  end
end
