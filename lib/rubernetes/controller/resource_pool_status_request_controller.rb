# frozen_string_literal: true

module Rubernetes
  module Controller
    # Computes ResourcePoolStatusRequest synchronously from ResourceSlices and
    # current ResourceClaim allocations.  Incomplete pools are retried rather
    # than finalized, matching the v1.36.2 controller's bounded queue policy.
    class ResourcePoolStatusRequestController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      COMPLETED_TTL = 3_600
      PENDING_TTL = 86_400
      CLEANUP_INTERVAL = 600
      MAX_RETRIES = 5
      DEFAULT_LIMIT = 100
      METRIC_PREFIX = "resourcepoolstatusrequest_controller"

      def plan(request, resource_slices: nil, resource_claims: nil, now: nil, limit: nil, store: nil, reconcile_attempt: nil, **_options)
        options = {controller: name, descriptor: RESOURCE_POOL_STATUS_REQUEST}
        return result(request, operations: [], **options) unless request.is_a?(Hash)

        timestamp = normalize_time(now || Time.now.utc)
        expired = cleanup_expired([request], now: timestamp)
        unless expired.empty?
          return result(request, operations: [], requeue_after: CLEANUP_INTERVAL, **options) if reconcile_attempt.to_i.positive?

          return result(request, operations: expired, **options)
        end
        return result(request, operations: [], requeue_after: CLEANUP_INTERVAL, **options) unless Support.value(request, "status", nil).nil?
        if reconcile_attempt && reconcile_attempt > MAX_RETRIES
          return result(request, operations: [], requeue_after: pending_cleanup_delay(request, timestamp), **options)
        end

        started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        desired_status = observed_pool_status(request, resource_slices, resource_claims, timestamp, limit, store)
        if Array(Support.value(desired_status, "pools", [])).any? { |pool| Support.value(pool, "validationError", nil) }
          raise StoreError, "incomplete pools detected, requeueing" if reconcile_attempt && reconcile_attempt < MAX_RETRIES

          events = if reconcile_attempt.nil?
                     [{"type" => "Warning", "reason" => "ResourcePoolStatusIncomplete", "message" => "one or more resource pools are incomplete",
                       "retryable" => true, "maxRetries" => MAX_RETRIES}]
                   else
                     []
                   end
          # Retry via the rate-limited queue up to MAX_RETRIES, then leave a
          # timer for cleanup of this still-pending request.
          delay = pending_cleanup_delay(request, timestamp) if reconcile_attempt
          return result(request, operations: [], events: events, status: desired_status, requeue_after: delay, **options)
        end

        operation = operation_status(request, desired_status, descriptor: RESOURCE_POOL_STATUS_REQUEST,
                                                              reason: "calculate ResourcePoolStatusRequest status")&.observed do |success, _error|
          labels = {"driver_name" => Support.spec(request)["driver"].to_s}
          ControllerMetrics.increment("#{METRIC_PREFIX}_requests_processed_total", labels)
          ControllerMetrics.increment("#{METRIC_PREFIX}_request_processing_errors_total", labels) unless success
          ControllerMetrics.observe("#{METRIC_PREFIX}_request_processing_duration_seconds",
                                    Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at, labels)
        end
        result(request, operations: [operation], status: desired_status, requeue_after: CLEANUP_INTERVAL, **options)
      end

      def observed_pool_status(request, resource_slices, resource_claims, timestamp, limit, store)
        adapter = adapter_for(store)
        begin
          listing = "ResourceSlices"
          resource_slices ||= list_for(adapter, RESOURCE_SLICE, namespace: :all)
          listing = "ResourceClaims"
          resource_claims ||= list_for(adapter, RESOURCE_CLAIM, namespace: :all)
        rescue StandardError => error
          return {"poolCount" => 0, "conditions" => [{"type" => "Failed", "status" => "True", "lastTransitionTime" => timestamp.utc.iso8601,
                                                      "reason" => "CalculationFailed", "message" => "Failed to list #{listing}: #{error.message}"}]}
        end
        calculate_status(request, resource_slices: resource_slices, resource_claims: resource_claims, now: timestamp, limit: limit)
      end
      private :observed_pool_status

      private def pending_cleanup_delay(request, timestamp)
        creation_time = Support.creation_time(request)
        return unless creation_time

        [creation_time + PENDING_TTL - timestamp + CLEANUP_INTERVAL, CLEANUP_INTERVAL].max
      end

      # The upstream controller's periodic cleanup is exposed as a pure
      # planner for callers that own the request list.  Every delete carries
      # the original UID in the immutable object for StoreAdapter fencing.
      def cleanup_expired(requests, now:, completed_ttl: COMPLETED_TTL, pending_ttl: PENDING_TTL)
        timestamp = normalize_time(now)
        Array(requests).filter_map do |request|
          status = Support.value(request, "status", nil)
          reference_time = if status
                             completed_condition = Array(Support.value(status, "conditions", [])).find do |condition|
                               %w[Complete Failed].include?(Support.value(condition, "type", "").to_s)
                             end
                             if completed_condition
                               Support.parse_time(Support.value(completed_condition, "lastTransitionTime", nil))
                             else
                               Support.creation_time(request)
                             end
                           else
                             Support.creation_time(request)
                           end
          next unless reference_time

          age = timestamp.to_f - reference_time.to_f
          next if age <= 0

          ttl = status.nil? ? pending_ttl.to_f : completed_ttl.to_f
          next unless age > ttl

          operation_delete(request, descriptor: RESOURCE_POOL_STATUS_REQUEST, options: {"preconditions" => {"uid" => Support.uid(request)}},
                                    reason: "delete expired ResourcePoolStatusRequest")
        end
      end

      private

      def calculate_status(request, resource_slices:, resource_claims:, now:, limit: nil)
        statuses = pool_statuses(request, resource_slices, resource_claims)
        effective_limit = limit.nil? ? value_at(Support.spec(request), "limit") : limit
        effective_limit = Support.integer(effective_limit, DEFAULT_LIMIT)
        effective_limit = DEFAULT_LIMIT if effective_limit.negative?
        returned = statuses.first(effective_limit)
        incomplete_count = returned.count { |pool| Support.value(pool, "validationError", nil) }
        message = "Calculated status for #{returned.length} pools"
        message = "#{message} (#{incomplete_count} incomplete)" if incomplete_count.positive?
        status = {
          "poolCount" => statuses.length,
          "conditions" => [{"type" => "Complete", "status" => "True", "lastTransitionTime" => now.utc.iso8601(9),
                            "reason" => "CalculationComplete", "message" => message}]
        }
        status["pools"] = returned unless returned.empty?
        status
      end

      def pool_statuses(request, resource_slices, resource_claims)
        driver = value_at(Support.spec(request), "driver").to_s
        pool_filter = value_at(Support.spec(request), "poolName", "pool_name").to_s
        slices = Array(resource_slices).select do |slice|
          spec = Support.spec(slice)
          next false unless value_at(spec, "driver").to_s == driver

          pool_name = pool_name_for(slice)
          pool_filter.empty? || pool_name == pool_filter
        end
        max_generations = slices.each_with_object({}) do |slice, result_hash|
          key = [value_at(Support.spec(slice), "driver").to_s, pool_name_for(slice)]
          generation = generation_for(slice)
          result_hash[key] = [result_hash[key] || generation, generation].max
        end
        pools = {}
        slices.each do |slice|
          key = [value_at(Support.spec(slice), "driver").to_s, pool_name_for(slice)]
          next unless generation_for(slice) == max_generations[key]

          spec = Support.spec(slice)
          pool = (pools[key] ||= {
            "driver" => key[0], "poolName" => key[1], "generation" => max_generations[key],
            "nodeName" => nil, "_nodes" => [], "totalDevices" => 0, "resourceSliceCount" => 0,
            "expectedSliceCount" => expected_slice_count(slice)
          })
          pool["totalDevices"] += Array(value_at(spec, "devices")).length
          pool["resourceSliceCount"] += 1
          pool["_nodes"] << value_at(spec, "nodeName").to_s
        end

        allocations = allocation_counts(resource_claims)
        pools.values.map do |pool|
          nodes = pool.delete("_nodes").uniq
          pool["nodeName"] = nodes.first if nodes.length == 1 && !nodes.first.to_s.empty?
          pool.delete("nodeName") if pool["nodeName"].nil?
          expected = pool.delete("expectedSliceCount")
          if expected > pool["resourceSliceCount"]
            message = "pool #{pool["driver"]}/#{pool["poolName"]} is incomplete: observed #{pool["resourceSliceCount"]}/#{expected} slices at generation " \
                      "#{pool["generation"]}"
            pool.delete("resourceSliceCount")
            pool.delete("totalDevices")
            pool["validationError"] = message.byteslice(0, 256)
          else
            allocated = allocations[[pool["driver"], pool["poolName"]]] || 0
            pool["allocatedDevices"] = allocated
            pool["unavailableDevices"] = 0
            pool["availableDevices"] = [pool["totalDevices"] - allocated, 0].max
          end
          pool
        end.sort_by { |pool| [pool["driver"].to_s, pool["poolName"].to_s] }
      end

      def pool_name_for(slice)
        spec = Support.spec(slice)
        pool = value_at(spec, "pool")
        return value_at(pool, "name", "poolName").to_s if pool.is_a?(Hash)

        value_at(spec, "poolName", "pool_name").to_s
      end

      def generation_for(slice)
        pool = value_at(Support.spec(slice), "pool")
        value = pool.is_a?(Hash) ? value_at(pool, "generation") : nil
        Support.integer(value, Support.integer(value_at(Support.spec(slice), "generation"), 0))
      end

      def expected_slice_count(slice)
        pool = value_at(Support.spec(slice), "pool")
        value = pool.is_a?(Hash) ? value_at(pool, "resourceSliceCount", "resource_slice_count") : nil
        Support.integer(value, Support.integer(value_at(Support.spec(slice), "resourceSliceCount"), 1))
      end

      def allocation_counts(claims)
        Array(claims).each_with_object(Hash.new(0)) do |claim, counts|
          allocation = value_at(Support.status(claim), "allocation")
          results = allocation.is_a?(Hash) ? value_at(value_at(allocation, "devices") || {}, "results") : nil
          Array(results).each do |entry|
            driver = value_at(entry, "driver").to_s
            pool = value_at(entry, "pool").to_s
            counts[[driver, pool]] += 1 unless driver.empty? || pool.empty?
          end
        end
      end
    end
  end
end
