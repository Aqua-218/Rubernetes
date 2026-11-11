# frozen_string_literal: true

require "time"

module Rubernetes
  module Scheduler
    # What the scheduler last decided about each Pod, and why: which plugin
    # turned each node away, and how every plugin scored the nodes that were
    # left.  kube-scheduler shows this only in its log at verbosity 10, for
    # the next attempt; here the last attempt of the most recent Pods is
    # kept and can be asked for (`rubectl why`).
    class Decisions
      LIMIT = 512
      # A decision on a large cluster is remembered for its best nodes only.
      NODES = 20

      def initialize(limit: LIMIT, clock: -> { Time.now.utc })
        @limit = limit
        @clock = clock
        @entries = {}
        @mutex = Mutex.new
      end

      def record(result, seconds)
        pod = result.pod
        key = "#{pod.namespace}/#{pod.name}"
        entry = {
          "pod" => key, "status" => result.status.to_s, "node" => result.node&.name, "at" => @clock.call.iso8601(3),
          "milliseconds" => (seconds * 1000).round(2), "error" => describe(result.error),
          "filtered" => rejections(result.filtered),
          "scores" => result.scores.sort_by { |breakdown| [-breakdown.total, breakdown.node.name] }.first(NODES).map do |breakdown|
            {"node" => breakdown.node.name, "total" => breakdown.total,
             "plugins" => breakdown.plugins.map { |plugin| plugin.slice("plugin", "score", "weight") }}
          end
        }
        @mutex.synchronize do
          entry["attempts"] = @entries.delete(key)&.fetch("attempts").to_i + 1
          @entries[key] = entry
          @entries.shift while @entries.length > @limit
        end
        entry
      end

      # The framework notes a verdict for every node it looked at; the ones
      # that passed every filter are in the scores.
      def rejections(filtered)
        filtered.select { |_node, verdict| verdict["accepted"] == false }
          .to_h { |node, verdict| [node, {"plugin" => verdict["plugin"], "reason" => verdict["reason"]}] }
      end

      def describe(error)
        error.is_a?(Exception) ? "#{error.class}: #{error.message}" : error&.to_s
      end

      # The decision for "namespace/name", or nil.
      def [](key)
        @mutex.synchronize { @entries[key] }
      end

      def keys
        @mutex.synchronize { @entries.keys }
      end

      # The decision as a person reads it: the chosen node first, then the
      # other candidates by score, then the nodes that were ruled out.
      def explain(key)
        entry = self[key]
        return "no scheduling decision is remembered for #{key} (the last #{@limit} Pods this scheduler tried are)" if entry.nil?

        outcome = entry["node"] ? "#{entry["status"]} on #{entry["node"]}" : entry["status"]
        lines = ["#{key}: #{outcome}  (attempt #{entry["attempts"]}, #{entry["milliseconds"]} ms, #{entry["at"]})"]
        lines << "  error: #{entry["error"]}" if entry["error"]
        width = (entry["scores"].map { |score| score["node"] } + entry["filtered"].keys).map(&:length).max.to_i
        entry["scores"].each do |score|
          parts = score["plugins"].reject { |plugin| plugin["score"].zero? }.map do |plugin|
            plugin["weight"] == 1 ? "#{plugin["plugin"]} #{plugin["score"]}" : "#{plugin["plugin"]} #{plugin["score"]}x#{plugin["weight"]}"
          end
          lines << format("  %-#{width}s  %5d  %s", score["node"], score["total"], parts.join("  "))
        end
        entry["filtered"].sort.each do |node, verdict|
          lines << format("  %-#{width}s  %5s  %s: %s", node, "-", verdict["plugin"], verdict["reason"])
        end
        lines.join("\n")
      end
    end
  end
end
