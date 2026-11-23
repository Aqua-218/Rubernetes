# frozen_string_literal: true

module Rubernetes
  module Controller
    # Process-wide gauges are the sum of the latest contribution from each
    # owner. Replacing one contribution and publishing its totals is atomic.
    class EndpointSliceMetrics
      GAUGES = {slices: "num_endpoint_slices", desired: "desired_endpoint_slices", endpoints: "endpoints_desired"}.freeze

      def initialize(prefix, track_traffic: false)
        @prefix = prefix
        @track_traffic = track_traffic
        @mutex = Mutex.new
        clear
      end

      def clear
        @mutex.synchronize do
          @owners = {}
          @totals = Hash.new(0)
          @traffic = Hash.new(0)
        end
      end

      def update(key, entry)
        @mutex.synchronize do
          previous = @owners[key]
          return unless previous || entry

          if entry
            @owners[key] = entry
          else
            @owners.delete(key)
          end
          GAUGES.each do |field, suffix|
            @totals[field] += entry&.fetch(field).to_i - previous&.fetch(field).to_i
            ControllerMetrics.set("#{@prefix}_#{suffix}", @totals[field])
          end
          if @track_traffic
            if (old = previous&.fetch(:traffic))
              @traffic[old] -= 1
              @traffic.delete(old) if @traffic[old].zero?
            end
            @traffic[entry[:traffic]] += 1 if entry && entry[:traffic]
            metric = "#{@prefix}_services_count_by_traffic_distribution"
            Controller.metrics&.reset(metric)
            @traffic.each { |name, count| ControllerMetrics.set(metric, count, {"traffic_distribution" => name}) }
          end
        end
      end

      def observe_changes(operations)
        operations.map do |operation|
          action = operation.create? || operation.delete? ? operation.action.to_s : "update"
          operation.observed do |succeeded, _|
            ControllerMetrics.increment("#{@prefix}_changes", {"operation" => action}) if succeeded
          end
        end
      end
    end
  end
end
