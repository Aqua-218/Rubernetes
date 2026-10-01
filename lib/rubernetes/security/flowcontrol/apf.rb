# frozen_string_literal: true

require "digest"
require "monitor"

require_relative "../identity"

module Rubernetes
  module Security
    module FlowControl
      class RejectedError < Security::Error
        # reason: apiserver_flowcontrol_rejected_requests_total's label
        # (queue-full, time-out, concurrency-limit).
        attr_reader :retry_after, :reason

        def initialize(message, retry_after: 1, reason: "queue-full")
          @retry_after = retry_after
          @reason = reason
          super(message)
        end
      end

      # k8s.io/apiserver/pkg/util/flowcontrol/request.SeatSeconds: seat-seconds
      # as a fixed-point integer (1e-8 seat-second units, uint64 range), the
      # unit of the queueset's virtual clock R and of a request's work.
      module SeatSeconds
        SCALE = 100_000_000
        MAX = (2**64) - 1
        MIN = 0

        def self.of(seats, seconds) = (seats.to_f * seconds.to_f * SCALE).round.clamp(MIN, MAX)
        def self.to_f(value) = value.to_f / SCALE
        def self.duration_per_seat(value, seats) = value.to_f / seats / SCALE
      end

      # fairqueuing.Integrator: a time-weighted gauge that remembers the
      # moments of its value since the last reset (average, standard
      # deviation, min and max), the seat demand statistics feed on it.
      class Integrator
        Results = Struct.new(:duration, :average, :deviation, :min, :max, keyword_init: true)

        def initialize(clock)
          @clock = clock
          @mutex = Mutex.new
          @last_time = clock.call
          @x = 0.0
          @elapsed = 0.0
          @integral_x = 0.0
          @integral_xx = 0.0
          @min = 0.0
          @max = 0.0
        end

        def value = @mutex.synchronize { @x }

        def set(x)
          @mutex.synchronize do
            update_locked
            @x = x.to_f
            @min = @x if @x < @min
            @max = @x if @x > @max
          end
        end

        def add(delta) = set(value + delta)

        def results
          @mutex.synchronize do
            update_locked
            results_locked
          end
        end

        def reset
          @mutex.synchronize do
            update_locked
            results = results_locked
            @elapsed = @integral_x = @integral_xx = 0.0
            @min = @max = @x
            results
          end
        end

        private

        def update_locked
          now = @clock.call
          dt = [now - @last_time, 0.0].max
          @last_time = now
          @elapsed += dt
          @integral_x += @x * dt
          @integral_xx += @x * @x * dt
        end

        def results_locked
          return Results.new(duration: 0.0, average: Float::NAN, deviation: Float::NAN, min: @min, max: @max) if @elapsed <= 0

          average = @integral_x / @elapsed
          variance = (@integral_xx / @elapsed) - (average * average)
          deviation = variance >= 0 ? Math.sqrt(variance) : 0.0
          Results.new(duration: @elapsed, average: average, deviation: deviation, min: @min, max: @max)
        end
      end

      # shufflesharding.Dealer: deal handSize distinct cards out of deckSize
      # from the flow hash (the queues a flow may use).
      class Dealer
        MAX_HASH_BITS = 60

        attr_reader :deck_size, :hand_size

        def self.required_entropy_bits(deck_size, hand_size) = (Math.log2(deck_size) * hand_size).ceil

        def initialize(deck_size, hand_size)
          raise ArgumentError, "deckSize #{deck_size} or handSize #{hand_size} is not positive" if deck_size <= 0 || hand_size <= 0
          raise ArgumentError, "handSize #{hand_size} is greater than deckSize #{deck_size}" if hand_size > deck_size
          raise ArgumentError, "deckSize #{deck_size} is impractically large" if deck_size > (1 << 26)
          if self.class.required_entropy_bits(deck_size, hand_size) > MAX_HASH_BITS
            raise ArgumentError, "required entropy bits of deckSize #{deck_size} and handSize #{hand_size} is greater than #{MAX_HASH_BITS}"
          end

          @deck_size = deck_size
          @hand_size = hand_size
        end

        def deal(hash_value)
          remainders = Array.new(@hand_size)
          @hand_size.times do |i|
            divisor = @deck_size - i
            next_value = hash_value / divisor
            remainders[i] = hash_value - (divisor * next_value)
            hash_value = next_value
          end
          hand = []
          @hand_size.times do |i|
            card = remainders[i]
            i.downto(1) { |j| card += 1 if card >= remainders[j - 1] }
            hand << card
          end
          hand
        end
      end

      # request.WorkEstimate: the seats a request occupies while it runs
      # (initial), the seats it keeps afterwards while its watch events are
      # delivered (final) and for how long.
      WorkEstimate = Struct.new(:initial_seats, :final_seats, :additional_latency, keyword_init: true) do
        def initialize(initial_seats: 1, final_seats: 0, additional_latency: 0.0)
          super(initial_seats: Integer(initial_seats), final_seats: Integer(final_seats), additional_latency: additional_latency.to_f)
        end

        def max_seats = [initial_seats, final_seats].max
      end

      # request.StorageObjectCountTracker: per resource ("pods",
      # "deployments.apps") the object count and average size, refreshed from
      # the store at most once a minute (etcd's count monitor period) and
      # stale after three minutes.
      class ObjectCountTracker
        REFRESH_SECONDS = 60.0
        STALE_SECONDS = 180.0
        Stats = Struct.new(:count, :average_bytes, :updated_at, keyword_init: true)

        class NotFound < StandardError
        end

        class Stale < StandardError
        end

        # +source+: -> { {"pods" => [count, total_bytes], ...} }
        def initialize(source: nil, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
          @source = source
          @clock = clock
          @mutex = Mutex.new
          @counts = {}
          @refreshed_at = nil
        end

        def set(resource, count, average_bytes)
          @mutex.synchronize do
            @counts[resource.to_s] = Stats.new(count: count.to_i, average_bytes: average_bytes.to_i, updated_at: @clock.call)
          end
        end

        # [count, average_bytes]; raises NotFound / Stale like upstream.
        def get(resource)
          refresh_if_due
          now = @clock.call
          stats = @mutex.synchronize { @counts[resource.to_s] }
          raise NotFound, resource if stats.nil?
          raise Stale, resource if now - stats.updated_at > STALE_SECONDS

          [stats.count, stats.average_bytes]
        end

        def refresh_if_due
          return unless @source

          now = @clock.call
          due = @mutex.synchronize do
            next false if @refreshed_at && now - @refreshed_at < REFRESH_SECONDS

            @refreshed_at = now
            true
          end
          return unless due

          snapshot = @source.call
          return unless snapshot.is_a?(Hash)

          snapshot.each do |resource, (count, total_bytes)|
            average = count.to_i.positive? ? (total_bytes.to_i / count.to_i) : 0
            set(resource, count, average)
          end
        rescue StandardError
          nil
        end
      end

      # flowcontrol.WatchTracker: how many watches would receive the events
      # a mutating request produces (all watches of the resource, plus the
      # namespaced and named ones); Pod watches pinned to one spec.nodeName
      # are not counted against every Pod write.
      class WatchTracker
        READ_ONLY_VERBS = %w[get list watch proxy].freeze
        BUILTIN_INDEXES = {"pods" => "spec.nodeName"}.freeze
        Identifier = Struct.new(:api_group, :resource, :namespace, :name)

        def initialize
          @mutex = Mutex.new
          @counts = Hash.new(0)
        end

        # Returns the forget callable, or nil for a non-watch.
        def register(attributes, field_selector: nil)
          return nil unless attributes.verb.to_s == "watch" && attributes.resource_request?

          identifier = Identifier.new(attributes.api_group.to_s, attributes.resource.to_s, attributes.namespace.to_s, attributes.name.to_s)
          counted = if (field = BUILTIN_INDEXES[identifier.resource])
                      exact_match_value(field_selector, field).to_s.empty?
                    else
                      true
                    end
          @mutex.synchronize { @counts[identifier] += 1 } if counted
          lambda do
            @mutex.synchronize do
              next unless counted

              @counts[identifier] -= 1
              @counts.delete(identifier) if @counts[identifier] <= 0
            end
          end
        end

        def interested_watch_count(attributes)
          return 0 if attributes.nil? || READ_ONLY_VERBS.include?(attributes.verb.to_s) || !attributes.resource_request?

          @mutex.synchronize do
            identifier = Identifier.new(attributes.api_group.to_s, attributes.resource.to_s, "", "")
            total = @counts[identifier]
            unless attributes.namespace.to_s.empty?
              identifier = Identifier.new(identifier.api_group, identifier.resource, attributes.namespace.to_s, "")
              total += @counts[identifier]
            end
            unless attributes.name.to_s.empty?
              identifier = Identifier.new(identifier.api_group, identifier.resource, identifier.namespace, attributes.name.to_s)
              total += @counts[identifier]
            end
            total
          end
        end

        def size = @mutex.synchronize { @counts.values.sum }

        private

        def exact_match_value(selector, field)
          return nil if selector.to_s.empty?

          selector.to_s.split(",").each do |term|
            key, value = term.split("=", 2)
            next if key.nil? || value.nil?
            next if key.end_with?("!")
            return value.delete_prefix("=") if key.strip == field
          end
          nil
        end
      end

      # request.WorkEstimator: list requests by the memory they load (with
      # SizeBasedListCostEstimate), mutating ones by the watchers that get
      # the event, everything else one seat.
      class WorkEstimator
        MINIMUM_SEATS = 1
        MAXIMUM_LIST_SEATS_LIMIT = 100
        MAXIMUM_MUTATING_SEATS_LIMIT = 10
        OBJECTS_PER_SEAT = 100.0
        WATCHES_PER_SEAT = 10.0
        EVENT_ADDITIONAL_SECONDS = 0.005
        BYTES_PER_SEAT = 100_000
        CACHE_WITH_STREAMING_MAX_MEMORY = 1_000_000
        MAX_OBJECT_SIZE = 1_500_000
        INFINITE_OBJECT_COUNT = 1_000_000_000
        MUTATING_VERBS = %w[create update patch delete].freeze

        attr_reader :object_counts, :watch_tracker

        def initialize(object_counts:, watch_tracker:, max_seats:, watch_count_observer: nil, minimum_seats: MINIMUM_SEATS,
                       maximum_list_seats: MAXIMUM_LIST_SEATS_LIMIT, maximum_mutating_seats: MAXIMUM_MUTATING_SEATS_LIMIT)
          @object_counts = object_counts
          @watch_tracker = watch_tracker
          @max_seats = max_seats
          @watch_count_observer = watch_count_observer
          @minimum_seats = minimum_seats
          @maximum_list_seats = maximum_list_seats
          @maximum_mutating_seats = maximum_mutating_seats
        end

        # +query+: the request's query parameters (a Hash of strings).
        def estimate(attributes, query, flow_schema, priority_level)
          case attributes.verb.to_s
          when "list" then list_estimate(attributes, query || {}, priority_level)
          when "watch"
            send_initial = %w[true 1].include?(query.to_h["sendInitialEvents"].to_s)
            legacy = ["", "0"].include?(query.to_h["resourceVersion"].to_s)
            if send_initial || legacy
              list_estimate(attributes, query || {},
                            priority_level)
            else
              WorkEstimate.new(initial_seats: @minimum_seats)
            end
          when *MUTATING_VERBS then mutating_estimate(attributes, flow_schema, priority_level)
          else WorkEstimate.new(initial_seats: @minimum_seats)
          end
        end

        def self.resource_key(attributes)
          group = attributes.api_group.to_s
          group.empty? ? attributes.resource.to_s : "#{attributes.resource}.#{group}"
        end

        private

        def level_max_seats(priority_level, limit)
          value = @max_seats.call(priority_level).to_i
          value.zero? || value > limit ? limit : value
        end

        def list_estimate(attributes, query, priority_level)
          max_seats = level_max_seats(priority_level, @maximum_list_seats)
          matches_single = !attributes.name.to_s.empty?
          limit = query["limit"].to_i
          resource_version = query["resourceVersion"].to_s
          list_from_storage = case query["resourceVersionMatch"].to_s
                              when "Exact" then true
                              when "NotOlderThan" then false
                              when ""
                                # A continue token or an exact positive-limit RV goes to storage;
                                # ConsistentListFromCache: RV "" is served from the cache.
                                !query["continue"].to_s.empty? ||
                                (limit.positive? && !resource_version.empty? && resource_version != "0")
                              else true
                              end
          list_from_cache = attributes.verb.to_s == "watch" || !list_from_storage
          count, average = begin
            @object_counts.get(self.class.resource_key(attributes))
          rescue ObjectCountTracker::NotFound
            return WorkEstimate.new(initial_seats: @minimum_seats)
          rescue StandardError
            [INFINITE_OBJECT_COUNT, MAX_OBJECT_SIZE]
          end
          average = MAX_OBJECT_SIZE if average <= 0 && count != 0
          limited = count
          limited = limit if limit.positive? && limit < count
          selected = !query["fieldSelector"].to_s.empty? || !query["labelSelector"].to_s.empty?
          loaded = if matches_single then 1
                   elsif list_from_cache then limited
                   elsif selected then [limited, count / 2].max
                   else limited
                   end
          memory = loaded * average
          memory = [memory, CACHE_WITH_STREAMING_MAX_MEMORY].min if list_from_cache
          seats = (memory.to_f / BYTES_PER_SEAT).ceil
          WorkEstimate.new(initial_seats: seats.clamp(@minimum_seats, max_seats))
        end

        def mutating_estimate(attributes, flow_schema, priority_level)
          max_seats = level_max_seats(priority_level, @maximum_mutating_seats)
          if attributes.resource.to_s == "serviceaccounts" && attributes.subresource.to_s == "token"
            return WorkEstimate.new(initial_seats: @minimum_seats, final_seats: 0, additional_latency: 0.0)
          end

          watch_count = @watch_tracker.interested_watch_count(attributes)
          @watch_count_observer&.call(priority_level, flow_schema, watch_count)
          final_seats = 0
          additional_latency = 0.0
          if watch_count >= WATCHES_PER_SEAT
            final_seats = (watch_count / WATCHES_PER_SEAT).ceil
            final_work = SeatSeconds.of(final_seats, EVENT_ADDITIONAL_SECONDS)
            final_seats = max_seats if final_seats > max_seats
            additional_latency = SeatSeconds.duration_per_seat(final_work, final_seats)
          end
          WorkEstimate.new(initial_seats: 1, final_seats: final_seats, additional_latency: additional_latency)
        end
      end

      # fairqueuing/queueset: one priority level's queues.  Every queue has a
      # virtual start time (next_dispatch_r) on the level's virtual clock R,
      # which advances at the rate of seats the level can use divided by the
      # active queues; the queue whose oldest request would finish first in
      # virtual time is served next, so flows with little work are not stuck
      # behind a flood from another flow.  Waiting callers block in
      # +wait+ until dispatched or their deadline passes.
      class QueueSet
        ESTIMATED_SERVICE_SECONDS = 0.003
        R_DECREMENT = SeatSeconds::MAX / 2
        HIGH_R = R_DECREMENT + (R_DECREMENT / 2)

        class Request
          attr_reader :flow_schema, :distinguisher, :arrival_time, :work, :total_work, :final_work, :queue
          attr_accessor :arrival_r, :start_time, :decision, :queue_position, :waiting_seats_released

          def initialize(flow_schema:, distinguisher:, arrival_time:, arrival_r:, work:, total_work:, final_work:, queue:)
            @flow_schema = flow_schema
            @distinguisher = distinguisher
            @arrival_time = arrival_time
            @arrival_r = arrival_r
            @work = work
            @total_work = total_work
            @final_work = final_work
            @queue = queue
            @decision = :pending
            @start_time = nil
          end

          def max_seats = @work.max_seats
          def initial_seats = @work.initial_seats
        end

        class Queue
          attr_accessor :index, :next_dispatch_r, :seats_in_use
          attr_reader :waiting, :executing

          def initialize(index)
            @index = index
            @waiting = []
            @executing = Set.new
            @next_dispatch_r = 0
            @seats_in_use = 0
            @initial_seats_sum = 0
            @max_seats_sum = 0
            @total_work_sum = 0
          end

          def sums = {initial: @initial_seats_sum, max: @max_seats_sum, total_work: @total_work_sum}

          def enqueue(request)
            @waiting << request
            @initial_seats_sum += request.initial_seats
            @max_seats_sum += request.max_seats
            @total_work_sum += request.total_work
          end

          def remove(request)
            return nil unless @waiting.delete(request)

            @initial_seats_sum -= request.initial_seats
            @max_seats_sum -= request.max_seats
            @total_work_sum -= request.total_work
            request
          end

          def peek = @waiting.first
          def active? = !@waiting.empty? || !@executing.empty?
        end

        attr_reader :name, :queues, :current_r, :concurrency_limit, :concurrency_denominator, :desired_queues,
                    :total_waiting, :total_executing, :total_seats_in_use, :total_seats_waiting, :queue_length_limit, :hand_size

        # +desired_queues+: > 0 queue, 0 reject on saturation, < 0 exempt.
        # +observer+ receives the metrics callbacks (a PriorityLevel).
        # +after+: -> (seconds, &block) schedules the release of lingering seats.
        def initialize(name:, desired_queues:, queue_length_limit:, hand_size:, concurrency_limit:, concurrency_denominator:, clock:,
                       observer: nil, after: nil)
          @name = name
          @clock = clock
          @observer = observer
          @after = after || lambda { |seconds, &block|
            Thread.new do
              sleep(seconds)
              block.call
            end
          }
          @monitor = Monitor.new
          @condition = @monitor.new_cond
          @queues = []
          @current_r = 0
          @last_real_time = clock.call
          @robin_index = 0
          @total_waiting = 0
          @total_executing = 0
          @total_seats_in_use = 0
          @total_seats_waiting = 0
          @enqueues = 0
          @executing_without_queue = Set.new
          @dispatched = 0
          @rejected = 0
          @timed_out = 0
          @desired_queues = 0
          @queue_length_limit = 1
          @hand_size = 1
          @dealer = nil
          configure(desired_queues: desired_queues, queue_length_limit: queue_length_limit, hand_size: hand_size,
                    concurrency_limit: concurrency_limit, concurrency_denominator: concurrency_denominator)
        end

        def configure(concurrency_limit:, concurrency_denominator:, desired_queues: nil, queue_length_limit: nil, hand_size: nil)
          @monitor.synchronize do
            sync_time
            if desired_queues
              @desired_queues = desired_queues
              if desired_queues.positive?
                @queue_length_limit = queue_length_limit || @queue_length_limit
                @hand_size = hand_size || @hand_size
                @dealer = Dealer.new(desired_queues, [@hand_size, desired_queues].min)
                if desired_queues > @queues.length
                  @queues.concat(Array.new(desired_queues - @queues.length) do |i|
                    Queue.new(@queues.length + i)
                  end)
                end
              end
            end
            @concurrency_limit = concurrency_limit.to_i
            @concurrency_denominator = concurrency_denominator.to_i
            waiting_limit = [@queue_length_limit, 1].max
            waiting_limit *= @desired_queues if @desired_queues.positive?
            @observer&.set_denominators(waiting: waiting_limit, executing: @concurrency_denominator)
            dispatch_as_much_as_possible
          end
        end

        def idle? = @monitor.synchronize { @total_waiting.zero? && @total_executing.zero? }

        def stats
          @monitor.synchronize do
            {"waiting" => @total_waiting, "executing" => @total_executing, "seats_in_use" => @total_seats_in_use,
             "seats_waiting" => @total_seats_waiting, "dispatched" => @dispatched, "rejected" => @rejected, "timed_out" => @timed_out,
             "current_r" => SeatSeconds.to_f(@current_r), "queues" => @queues.count(&:active?)}
          end
        end

        # StartRequest: returns the Request (dispatched or queued) or raises
        # RejectedError.
        def start_request(work:, hash_value:, distinguisher:, flow_schema:)
          @monitor.synchronize do
            sync_time
            if @desired_queues < 1
              unless can_accommodate?(work.max_seats)
                @rejected += 1
                @observer&.add_reject(flow_schema, "concurrency-limit")
                raise RejectedError.new("concurrency limit of priority level #{@name} reached", retry_after: 1, reason: "concurrency-limit")
              end
              return dispatch_without_queue(work, distinguisher, flow_schema)
            end
            request = shuffle_shard_and_enqueue(work, hash_value, distinguisher, flow_schema)
            if request.nil?
              @rejected += 1
              @observer&.add_reject(flow_schema, "queue-full")
              raise RejectedError.new("too many requests queued for priority level #{@name}", retry_after: 1, reason: "queue-full")
            end
            dispatch_as_much_as_possible
            request
          end
        end

        # Block until the request executes; false when the deadline passed
        # (the request is ejected and counted as a time-out).
        def wait(request, deadline:)
          @monitor.synchronize do
            loop do
              return true if request.decision == :execute

              remaining = deadline - @clock.call
              if remaining <= 0
                eject(request)
                return false
              end
              @condition.wait([remaining, 0.25].min)
            end
          end
        end

        def finish(request)
          @monitor.synchronize do
            sync_time
            finish_locked(request)
            dispatch_as_much_as_possible
          end
        end

        # Test hook: the virtual clock, in seat-seconds units.
        def current_r=(value)
          @monitor.synchronize { @current_r = Integer(value) }
        end

        def sync_time
          real_now = @clock.call
          since_last = real_now - @last_real_time
          @last_real_time = real_now
          previous = @current_r
          increment = SeatSeconds.of(virtual_time_ratio, since_last)
          @current_r = previous + increment
          advance_epoch if @current_r >= HIGH_R
          @observer&.set_current_r(SeatSeconds.to_f(@current_r))
        end

        private

        def advance_epoch
          @current_r -= R_DECREMENT
          success = true
          @queues.each do |queue|
            unless queue.active?
              queue.next_dispatch_r = 0
              next
            end
            queue.next_dispatch_r -= R_DECREMENT
            if queue.next_dispatch_r.negative?
              success = false
              queue.next_dispatch_r = 0
            end
            queue.waiting.each do |request|
              request.arrival_r -= R_DECREMENT
              next unless request.arrival_r.negative?

              success = false
              request.arrival_r = 0
            end
          end
          @observer&.add_epoch_advance(success)
        end

        def virtual_time_ratio
          active = 0
          seats_requested = 0
          @queues.each do |queue|
            seats_requested += queue.seats_in_use + queue.sums[:max]
            active += 1 if queue.active?
          end
          return 0.0 if active.zero?

          [seats_requested, @concurrency_limit].min.to_f / active
        end

        def complete(work)
          initial = SeatSeconds.of(work.initial_seats, ESTIMATED_SERVICE_SECONDS)
          final = SeatSeconds.of(work.final_seats, work.additional_latency)
          [initial + final, final]
        end

        def shuffle_shard_and_enqueue(work, hash_value, distinguisher, flow_schema)
          queue = @queues[shuffle_shard(hash_value)]
          total_work, final_work = complete(work)
          request = Request.new(flow_schema: flow_schema, distinguisher: distinguisher, arrival_time: @clock.call, arrival_r: @current_r,
                                work: work, total_work: total_work, final_work: final_work, queue: queue)
          if @total_seats_in_use >= @concurrency_limit && queue.waiting.length >= @queue_length_limit
            bound_next_dispatch(queue)
            return nil
          end
          queue.next_dispatch_r = @current_r unless queue.active?
          queue.enqueue(request)
          @total_waiting += 1
          @total_seats_waiting += request.max_seats
          @observer&.add_requests_in_queues(flow_schema, 1)
          @observer&.add_seats_in_queues(flow_schema, request.max_seats)
          @observer&.requests_waiting(1)
          @observer&.seat_demand(@total_seats_in_use + @total_seats_waiting)
          @observer&.observe_queue_length(flow_schema, queue.waiting.length)
          bound_next_dispatch(queue)
          request
        end

        def shuffle_shard(hash_value)
          hand = @dealer.deal(hash_value)
          offset = @enqueues % hand.length
          @enqueues += 1
          best = nil
          best_work = nil
          hand.length.times do |i|
            index = hand[(offset + i) % hand.length]
            work = @queues[index].sums[:total_work]
            if best_work.nil? || work < best_work
              best_work = work
              best = index
            end
          end
          best
        end

        def dispatch_without_queue(work, distinguisher, flow_schema)
          now = @clock.call
          total_work, final_work = complete(work)
          request = Request.new(flow_schema: flow_schema, distinguisher: distinguisher, arrival_time: now, arrival_r: @current_r,
                                work: work, total_work: total_work, final_work: final_work, queue: nil)
          request.decision = :execute
          request.start_time = now
          @total_executing += 1
          @total_seats_in_use += request.max_seats
          @executing_without_queue << request
          @dispatched += 1
          @observer&.add_requests_executing(flow_schema, 1)
          @observer&.add_seat_concurrency_in_use(flow_schema, request.max_seats)
          @observer&.requests_executing(1)
          @observer&.exec_seats(request.max_seats)
          @observer&.seat_demand(@total_seats_in_use + @total_seats_waiting)
          request
        end

        def dispatch_as_much_as_possible
          nil while @total_waiting.positive? && @total_seats_in_use < @concurrency_limit && dispatch_one
        end

        def dispatch_one
          queue, request = find_dispatch_queue
          return false if queue.nil? || request.nil?

          @total_waiting -= 1
          @total_seats_waiting -= request.max_seats
          @observer&.add_requests_in_queues(request.flow_schema, -1)
          @observer&.add_seats_in_queues(request.flow_schema, -request.max_seats)
          @observer&.requests_waiting(-1)
          request.decision = :execute
          request.start_time = @clock.call
          @total_executing += 1
          @total_seats_in_use += request.max_seats
          queue.executing << request
          queue.seats_in_use += request.max_seats
          @dispatched += 1
          @observer&.add_requests_executing(request.flow_schema, 1)
          @observer&.add_seat_concurrency_in_use(request.flow_schema, request.max_seats)
          @observer&.requests_executing(1)
          @observer&.exec_seats(request.max_seats)
          @observer&.seat_demand(@total_seats_in_use + @total_seats_waiting)
          queue.next_dispatch_r += request.total_work
          bound_next_dispatch(queue)
          @condition.broadcast
          true
        end

        def can_accommodate?(seats)
          return true if @desired_queues.negative?
          return @total_executing.zero? if seats > @concurrency_limit

          @total_seats_in_use + seats <= @concurrency_limit
        end

        def find_dispatch_queue
          min_virtual_finish = nil
          s_min = ds_min = SeatSeconds::MAX
          s_max = ds_max = SeatSeconds::MIN
          min_queue = nil
          min_index = nil
          count = @queues.length
          count.times do
            @robin_index = (@robin_index + 1) % count
            queue = @queues[@robin_index]
            oldest = queue.peek
            next if oldest.nil?

            s_min = [s_min, queue.next_dispatch_r].min
            s_max = [s_max, queue.next_dispatch_r].max
            in_progress = SeatSeconds.of(queue.seats_in_use, ESTIMATED_SERVICE_SECONDS)
            ds_min = [ds_min, queue.next_dispatch_r - in_progress].min
            ds_max = [ds_max, queue.next_dispatch_r - in_progress].max
            virtual_finish = queue.next_dispatch_r + oldest.total_work
            next unless min_virtual_finish.nil? || virtual_finish < min_virtual_finish

            min_virtual_finish = virtual_finish
            min_queue = queue
            min_index = @robin_index
          end
          return [nil, nil] if min_queue.nil?

          oldest = min_queue.peek
          unless can_accommodate?(oldest.max_seats)
            @observer&.add_dispatch_with_no_accommodation(oldest.flow_schema)
            return [nil, nil]
          end
          min_queue.remove(oldest)
          if oldest.work.final_seats > @concurrency_limit
            final_seats = @concurrency_limit
            oldest.work.additional_latency = SeatSeconds.duration_per_seat(oldest.final_work, final_seats)
            oldest.work.final_seats = final_seats
          end
          @robin_index = min_index
          @observer&.set_dispatch_metrics(SeatSeconds.to_f(@current_r), SeatSeconds.to_f(min_queue.next_dispatch_r),
                                          SeatSeconds.to_f(s_min), SeatSeconds.to_f(s_max), SeatSeconds.to_f(ds_min), SeatSeconds.to_f(ds_max))
          [min_queue, oldest]
        end

        def eject(request)
          queue = request.queue
          return unless queue && queue.remove(request)

          request.decision = :cancel
          @total_waiting -= 1
          @total_seats_waiting -= request.max_seats
          @rejected += 1
          @timed_out += 1
          @observer&.add_reject(request.flow_schema, "time-out")
          @observer&.add_requests_in_queues(request.flow_schema, -1)
          @observer&.add_seats_in_queues(request.flow_schema, -request.max_seats)
          @observer&.requests_waiting(-1)
          @observer&.seat_demand(@total_seats_in_use + @total_seats_waiting)
          bound_next_dispatch(queue)
        end

        def finish_locked(request)
          now = @clock.call
          @total_executing -= 1
          @observer&.add_requests_executing(request.flow_schema, -1)
          @observer&.requests_executing(-1)
          actual_service = now - (request.start_time || now)
          release_seats = lambda do
            @total_seats_in_use -= request.max_seats
            @observer&.add_seat_concurrency_in_use(request.flow_schema, -request.max_seats)
            @observer&.exec_seats(-request.max_seats)
            @observer&.seat_demand(@total_seats_in_use + @total_seats_waiting)
            request.queue.seats_in_use -= request.max_seats if request.queue
            remove_queue_if_empty(request)
          end
          if request.queue
            request.queue.executing.delete(request)
            request.queue.next_dispatch_r -= SeatSeconds.of(request.initial_seats, ESTIMATED_SERVICE_SECONDS - actual_service)
            request.queue.next_dispatch_r = 0 if request.queue.next_dispatch_r.negative?
            bound_next_dispatch(request.queue)
          else
            @executing_without_queue.delete(request)
          end
          if request.work.additional_latency <= 0
            release_seats.call
          else
            # The final seats linger while the watch events go out.
            @after.call(request.work.additional_latency) do
              @monitor.synchronize do
                sync_time
                release_seats.call
                dispatch_as_much_as_possible
              end
            end
          end
        end

        def bound_next_dispatch(queue)
          oldest = queue.peek
          return if oldest.nil?

          queue.next_dispatch_r = oldest.arrival_r if queue.next_dispatch_r < oldest.arrival_r
        end

        def remove_queue_if_empty(request)
          queue = request.queue
          return if queue.nil?
          return unless @queues.length > @desired_queues && !queue.active?

          @queues.delete(queue)
          @queues.each_with_index { |remaining, index| remaining.index = index }
          @robin_index -= 1 if @robin_index >= queue.index && @robin_index.positive?
        end
      end

      # API Priority and Fairness (spec 5.1.4; k8s.io/apiserver/pkg/util/flowcontrol).
      # FlowSchemas classify a request by subject and rules; the matching
      # PriorityLevelConfiguration owns a share of the server's seats and,
      # when Limited with queuing, a QueueSet of fair queues.  A request's
      # seats come from the work estimator; a priority level's current limit
      # moves between its lower and upper bounds every ten seconds as the
      # levels lend and borrow seats according to their measured demand.
      class Controller
        DEFAULT_QUEUES = 64
        DEFAULT_HAND_SIZE = 8
        DEFAULT_QUEUE_LENGTH_LIMIT = 50
        DEFAULT_REQUEST_WAIT_LIMIT = 60.0
        DEFAULT_READ_SEATS = 400
        DEFAULT_MUTATING_SEATS = 200
        BORROWING_ADJUSTMENT_SECONDS = 10.0
        SEAT_DEMAND_SMOOTHING_COEFFICIENT = 0.977
        PRIORITY_LEVEL_MAX_SEATS_PERCENT = 0.15
        LONG_RUNNING_VERBS = %w[watch].freeze
        LONG_RUNNING_SUBRESOURCES = %w[exec attach portforward proxy log].freeze
        NON_MUTATING_VERBS = %w[get list watch].freeze
        WAIT_BUCKETS = [0, 0.005, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30].freeze
        MIN_TARGET = 0.001
        EPSILON = 0.0000001

        Ticket = Struct.new(:priority_level, :flow_schema, :queue_index, :seats, :queued_seconds, :exempt, :dispatched_at, :mutating, :watch,
                            :request, :forget_watch, :work, keyword_init: true)

        # One PriorityLevelConfiguration: its seat bounds, queue set, seat
        # demand statistics and the metrics callbacks the queue set makes.
        class PriorityLevel
          attr_reader :name, :queues, :hand_size, :queue_length_limit, :wait_limit, :exempt, :reject, :queue_set,
                      :nominal_seats, :min_seats, :max_seats, :current_seats, :seat_demand_integrator, :seat_demand_stats,
                      :nominal_shares, :lendable_percent, :borrowing_limit_percent, :estimator_max_seats

          SeatDemandStats = Struct.new(:average, :stdev, :high_watermark, :smoothed, keyword_init: true)

          def initialize(controller:, name:, spec:, clock:, after: nil)
            @controller = controller
            @name = name
            @clock = clock
            @exempt = spec["type"] == "Exempt"
            limited = spec["limited"] || spec["exempt"] || {}
            @nominal_shares = @exempt ? (limited["nominalConcurrencyShares"] || 0).to_i : (limited["nominalConcurrencyShares"] || 30).to_i
            @lendable_percent = limited["lendablePercent"]
            @borrowing_limit_percent = @exempt ? nil : limited["borrowingLimitPercent"]
            queuing = limited.dig("limitResponse", "queuing")
            @reject = !@exempt && limited.dig("limitResponse", "type") == "Reject"
            @queues = if @exempt
                        -1
                      else
                        (queuing ? (queuing["queues"] || DEFAULT_QUEUES).to_i : 0)
                      end
            @hand_size = queuing ? (queuing["handSize"] || DEFAULT_HAND_SIZE).to_i : 1
            @queue_length_limit = queuing ? (queuing["queueLengthLimit"] || DEFAULT_QUEUE_LENGTH_LIMIT).to_i : 0
            @wait_limit = DEFAULT_REQUEST_WAIT_LIMIT
            @nominal_seats = @min_seats = @max_seats = @current_seats = 0
            @estimator_max_seats = 0
            @seat_demand_integrator = Integrator.new(clock)
            @seat_demand_stats = SeatDemandStats.new(average: 0.0, stdev: 0.0, high_watermark: 0, smoothed: 0.0)
            @queue_set = QueueSet.new(name: name, desired_queues: @queues, queue_length_limit: @queue_length_limit, hand_size: @hand_size,
                                      concurrency_limit: 0, concurrency_denominator: 1, clock: clock, observer: self, after: after)
          end

          # The seats this level owns by its shares (nominal_limit_seats).
          def seats = @exempt ? Float::INFINITY : @nominal_seats
          def inflight = @queue_set.total_executing
          def waiting = @queue_set.total_waiting

          def stats
            @queue_set.stats.merge("name" => @name, "seats" => @nominal_seats, "current_seats" => @current_seats, "inflight" => inflight,
                                   "queued" => waiting, "exempt" => @exempt)
          end

          # finishQueueSetReconfigsLocked: the bounds from the shares.
          def configure_bounds!(server_seats, share_sum)
            @nominal_seats = @exempt ? 0 : (server_seats.to_f * @nominal_shares / [share_sum, 1.0].max).ceil
            lendable = @lendable_percent.nil? ? 0 : go_round(@nominal_seats * @lendable_percent.to_f / 100)
            borrowing = @borrowing_limit_percent.nil? ? server_seats : go_round(@nominal_seats * @borrowing_limit_percent.to_f / 100)
            @min_seats = @nominal_seats - lendable
            @max_seats = @nominal_seats + borrowing
            @estimator_max_seats = if @queues.positive?
                                     [1,
                                      [(@nominal_seats * PRIORITY_LEVEL_MAX_SEATS_PERCENT).ceil,
                                       @nominal_seats / [@hand_size, 1].max].min].max
                                   else
                                     0
                                   end
            @current_seats = @nominal_seats - (lendable / 2) if @current_seats.zero?
            @controller.set_priority_level_configuration(@name, @nominal_seats, @min_seats, @max_seats, exempt: @exempt)
          end

          def apply_current_seats!(current, denominator)
            @current_seats = current
            @queue_set.configure(concurrency_limit: current, concurrency_denominator: denominator)
            @controller.set_demand_denominator(@name, denominator)
          end

          def go_round(value) = value.negative? ? -((-value) + 0.5).floor : (value + 0.5).floor

          # seatDemandStats.update on the integrator's reset.
          def update_seat_demand_stats!
            results = @seat_demand_integrator.reset
            stats = @seat_demand_stats
            stats.high_watermark = results.max.round
            return stats if results.duration <= 0

            deviation = results.deviation.nan? ? 0.0 : results.deviation
            stats.average = results.average.nan? ? 0.0 : results.average
            stats.stdev = deviation
            envelope = stats.average + deviation
            stats.smoothed = [envelope,
                              (SEAT_DEMAND_SMOOTHING_COEFFICIENT * stats.smoothed) + ((1 - SEAT_DEMAND_SMOOTHING_COEFFICIENT) * envelope)].max
            stats
          end

          # -- QueueSet observer callbacks (the metrics upstream's queueset records) --

          def labels(flow_schema) = {"flow_schema" => flow_schema.to_s, "priority_level" => @name}
          def add_requests_in_queues(flow_schema, delta) = @controller.note_queued(labels(flow_schema), delta)

          def add_seats_in_queues(flow_schema, delta)
            @controller.adjust("apiserver_flowcontrol_current_inqueue_seats", labels(flow_schema), delta)
          end

          def observe_queue_length(flow_schema, length)
            @controller.observe("apiserver_flowcontrol_request_queue_length_after_enqueue", length, labels(flow_schema))
          end

          def add_requests_executing(flow_schema, delta) = @controller.note_executing(labels(flow_schema), delta)

          def add_seat_concurrency_in_use(flow_schema, delta)
            @controller.adjust("apiserver_flowcontrol_current_executing_seats", labels(flow_schema), delta)
          end

          def add_reject(flow_schema, reason) = @controller.note_rejected(labels(flow_schema), reason)
          def set_current_r(r) = @controller.set("apiserver_flowcontrol_current_r", r, {"priority_level" => @name})

          def add_dispatch_with_no_accommodation(flow_schema)
            @controller.adjust("apiserver_flowcontrol_request_dispatch_no_accommodation_total", labels(flow_schema), 1)
          end

          def add_epoch_advance(success)
            @controller.adjust("apiserver_flowcontrol_epoch_advance_total", {"priority_level" => @name, "success" => success.to_s}, 1)
          end

          def set_dispatch_metrics(r, s, s_min, s_max, ds_min, ds_max)
            level = {"priority_level" => @name}
            @controller.set("apiserver_flowcontrol_dispatch_r", r, level)
            @controller.set("apiserver_flowcontrol_latest_s", s, level)
            @controller.set("apiserver_flowcontrol_next_s_bounds", s_min, level.merge("bound" => "min"))
            @controller.set("apiserver_flowcontrol_next_s_bounds", s_max, level.merge("bound" => "max"))
            @controller.set("apiserver_flowcontrol_next_discounted_s_bounds", ds_min, level.merge("bound" => "min"))
            @controller.set("apiserver_flowcontrol_next_discounted_s_bounds", ds_max, level.merge("bound" => "max"))
          end

          def requests_waiting(delta) = @controller.ratio(@name, :waiting)&.add(delta)
          def requests_executing(delta) = @controller.ratio(@name, :executing)&.add(delta)
          def exec_seats(delta) = @controller.ratio(@name, :seats)&.add(delta)

          def seat_demand(value)
            @seat_demand_integrator.set(value)
            @controller.ratio(@name, :demand)&.set(value)
          end

          def set_denominators(waiting:, executing:)
            @controller.ratio(@name, :waiting)&.set_denominator(waiting)
            @controller.ratio(@name, :executing)&.set_denominator(executing)
            @controller.ratio(@name, :seats)&.set_denominator(executing)
          end
        end

        attr_reader :priority_levels, :flow_schemas, :server_seats, :work_estimator, :watch_tracker, :object_counts

        # +object_stats+: -> { {"pods" => [count, total_bytes], ...} } for the
        # list work estimator (the store's counts, polled once a minute).
        def initialize(flow_schemas:, priority_level_configurations:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                       read_seats: DEFAULT_READ_SEATS, mutating_seats: DEFAULT_MUTATING_SEATS, object_stats: nil, after: nil,
                       borrowing_adjustment_seconds: BORROWING_ADJUSTMENT_SECONDS)
          @clock = clock
          @mutex = Mutex.new
          @ratios = {}
          @read_write = nil
          @metrics = nil
          @fair_frac = 0.0
          @targets = {}
          @flow_schemas = Array(flow_schemas).sort_by do |schema|
            [schema.dig("spec", "matchingPrecedence").to_i, schema.dig("metadata", "name").to_s]
          end
          @server_seats = read_seats + mutating_seats
          @borrowing_adjustment_seconds = borrowing_adjustment_seconds
          @priority_levels = Array(priority_level_configurations).each_with_object({}) do |plc, levels|
            name = plc.dig("metadata", "name").to_s
            levels[name] = PriorityLevel.new(controller: self, name: name, spec: plc["spec"] || {}, clock: clock, after: after)
          end
          @share_sum = @priority_levels.values.reject(&:exempt).sum(&:nominal_shares).to_f
          @priority_levels.each_value { |level| level.configure_bounds!(@server_seats, @share_sum) }
          @nominal_sum = @priority_levels.values.sum(&:nominal_seats)
          @watch_tracker = WatchTracker.new
          @object_counts = ObjectCountTracker.new(source: object_stats, clock: clock)
          @work_estimator = WorkEstimator.new(object_counts: @object_counts, watch_tracker: @watch_tracker,
                                              max_seats: ->(level_name) { @priority_levels[level_name]&.estimator_max_seats.to_i },
                                              watch_count_observer: lambda { |level_name, schema, count|
                                                observe("apiserver_flowcontrol_watch_count_samples", count, {"flow_schema" => schema.to_s, "priority_level" => level_name.to_s})
                                              })
          @borrowing_thread = nil
          adjust_borrowing!
        end

        def long_running?(attributes)
          LONG_RUNNING_VERBS.include?(attributes.verb) || LONG_RUNNING_SUBRESOURCES.include?(attributes.subresource.to_s)
        end

        # apiserver/pkg/util/flowcontrol/metrics.
        def metrics=(registry)
          @metrics = registry
          return unless registry

          {"apiserver_flowcontrol_dispatched_requests_total" => [:counter, "Number of requests executed by API Priority and Fairness subsystem"],
           "apiserver_flowcontrol_rejected_requests_total" => [:counter,
                                                               "Number of requests rejected by API Priority and Fairness subsystem"],
           "apiserver_flowcontrol_current_executing_requests" => [:gauge,
                                                                  "Number of requests in initial (for a WATCH) or any (for a non-WATCH) execution stage in the API Priority and Fairness subsystem"],
           "apiserver_flowcontrol_current_inqueue_requests" => [:gauge,
                                                                "Number of requests currently pending in queues of the API Priority and Fairness subsystem"],
           "apiserver_flowcontrol_nominal_limit_seats" => [:gauge,
                                                           "Nominal number of execution seats configured for each priority level"]}.each do |name, (type, help)|
            registry.register(name, type: type, help: help) unless registry.registered?(name)
          end
          unless registry.registered?("apiserver_flowcontrol_request_wait_duration_seconds")
            registry.register("apiserver_flowcontrol_request_wait_duration_seconds", type: :histogram, buckets: WAIT_BUCKETS,
                                                                                     help: "Length of time a request spent waiting in its queue")
          end
          register_seat_metrics(registry)
          @priority_levels.each_value do |level|
            set_priority_level_configuration(level.name, level.nominal_seats, level.min_seats, level.max_seats, exempt: level.exempt)
            level.queue_set.configure(concurrency_limit: level.current_seats, concurrency_denominator: [level.current_seats, 1].max)
          end
          record_borrowing_metrics
        end

        # The per-level TimingRatioHistograms (utilisation of the waiting and
        # executing limits, seat utilisation, seat demand) and the server's
        # read-vs-write ones.
        def register_seat_metrics(registry)
          max_waiting = 0
          max_executing = 0
          @priority_levels.each do |name, level|
            next if level.exempt

            labels = {"priority_level" => name}
            waiting_limit = [level.queue_length_limit, 1].max * [level.queues, 1].max
            max_waiting += level.queue_length_limit * [level.queues, 0].max
            max_executing += level.nominal_seats
            @ratios[name] = {
              waiting: registry.ratio_gauge("apiserver_flowcontrol_priority_level_request_utilization", labels.merge("phase" => "waiting"),
                                            denominator: waiting_limit, clock: @clock),
              executing: registry.ratio_gauge("apiserver_flowcontrol_priority_level_request_utilization", labels.merge("phase" => "executing"),
                                              denominator: [level.current_seats, 1].max, clock: @clock),
              seats: registry.ratio_gauge("apiserver_flowcontrol_priority_level_seat_utilization", labels.merge("phase" => "executing"),
                                          denominator: [level.current_seats, 1].max, clock: @clock),
              demand: registry.ratio_gauge("apiserver_flowcontrol_demand_seats", labels, denominator: [level.current_seats, 1].max,
                                                                                         clock: @clock)
            }
          end
          @read_write = %w[waiting executing].product(%w[readOnly mutating]).to_h do |phase, kind|
            [[phase, kind], registry.ratio_gauge("apiserver_flowcontrol_read_vs_write_current_requests", {"phase" => phase, "request_kind" => kind},
                                                 denominator: [phase == "waiting" ? max_waiting : max_executing, 1].max, clock: @clock)]
          end
        end

        def ratio(level_name, key) = @ratios&.dig(level_name, key)

        # Classify, estimate and admit; returns a Ticket to release later.
        # +request+ (optional): the HTTP request, for the list options the
        # work estimator reads.
        def enter(attributes, request: nil)
          start_borrowing_adjustments
          schema = classify(attributes)
          raise RejectedError.new("no FlowSchema matches the request", retry_after: 1) if schema.nil?

          level_name = schema.dig("spec", "priorityLevelConfiguration", "name")
          level = @priority_levels[level_name]
          raise RejectedError.new("priority level #{level_name} is not configured", retry_after: 1) if level.nil?

          schema_name = schema.dig("metadata", "name").to_s
          labels = {"flow_schema" => schema_name, "priority_level" => level_name.to_s}
          query = query_of(request)
          if long_running?(attributes)
            # Long-running requests hold no seat; a watch is remembered so
            # the mutating work estimator knows who receives its events.
            forget = @watch_tracker.register(attributes, field_selector: query["fieldSelector"] || attributes.field_selector)
            record_dispatch(labels, 0.0)
            return Ticket.new(priority_level: level_name, flow_schema: schema_name, queue_index: nil, seats: 0, queued_seconds: 0.0, exempt: true,
                              forget_watch: forget, watch: attributes.verb.to_s == "watch")
          end
          work = @work_estimator.estimate(attributes, query, schema_name, level_name)
          observe("apiserver_flowcontrol_work_estimated_seats", work.max_seats, labels)
          mutating = !NON_MUTATING_VERBS.include?(attributes.verb.to_s)
          started = @clock.call
          begin
            queue_request = level.queue_set.start_request(work: work, hash_value: flow_hash(schema, attributes),
                                                          distinguisher: distinguisher(schema, attributes), flow_schema: schema_name)
            unless queue_request.decision == :execute
              note_read_write("waiting", mutating, 1)
              begin
                executed = level.queue_set.wait(queue_request, deadline: started + level.wait_limit)
              ensure
                note_read_write("waiting", mutating, -1)
              end
              unless executed
                raise RejectedError.new("request waited #{level.wait_limit}s for priority level #{level_name}", retry_after: [level.wait_limit.ceil, 1].max,
                                                                                                                reason: "time-out")
              end
            end
          rescue RejectedError
            observe("apiserver_flowcontrol_request_wait_duration_seconds", 0.0, labels.merge("execute" => "false"))
            raise
          end
          waited = @clock.call - started
          record_dispatch(labels, waited)
          note_read_write("executing", mutating, 1)
          Ticket.new(priority_level: level_name, flow_schema: schema_name, queue_index: queue_request.queue&.index, seats: work.max_seats,
                     queued_seconds: waited, exempt: level.exempt, dispatched_at: Process.clock_gettime(Process::CLOCK_MONOTONIC),
                     mutating: mutating, watch: attributes.verb.to_s == "watch", request: queue_request, work: work)
        end

        def release(ticket)
          return if ticket.nil?

          ticket.forget_watch&.call
          return if ticket.request.nil?

          labels = {"flow_schema" => ticket.flow_schema.to_s, "priority_level" => ticket.priority_level.to_s}
          note_read_write("executing", ticket.mutating, -1)
          if @metrics && ticket.dispatched_at
            observe("apiserver_flowcontrol_request_execution_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - ticket.dispatched_at,
                    labels.merge("type" => ticket.watch ? "watch" : "regular"))
          end
          @priority_levels[ticket.priority_level]&.queue_set&.finish(ticket.request)
        end

        def stats
          @priority_levels.values.map(&:stats)
        end

        def classify(attributes)
          @flow_schemas.find { |schema| matches?(schema, attributes) }
        end

        # -- borrowing (apf_controller.updateBorrowingLocked) ----------------

        def start_borrowing_adjustments
          return if @borrowing_thread&.alive? || @borrowing_adjustment_seconds.nil?

          @mutex.synchronize do
            return if @borrowing_thread&.alive?

            @borrowing_thread = Thread.new do
              Thread.current.name = "apf-borrowing"
              loop do
                sleep(@borrowing_adjustment_seconds)
                begin
                  adjust_borrowing!
                rescue StandardError
                  nil
                end
              end
            end
          end
        end

        def stop
          @borrowing_thread&.kill
          @borrowing_thread = nil
        end

        # One adjustment period: each level's seat demand statistics, then
        # the concurrency allocation between the levels' bounds.
        def adjust_borrowing!
          @mutex.synchronize do
            items = []
            non_exempt = []
            min_current_of_exempt = {}
            min_sum = 0
            min_current_sum = 0
            remaining = @nominal_sum
            @priority_levels.each_value do |level|
              stats = level.update_seat_demand_stats!
              if level.exempt
                min_current = [level.min_seats, stats.high_watermark].max
                min_current_of_exempt[level.name] = min_current
                remaining -= min_current
              else
                min_current = [level.min_seats, [level.nominal_seats, stats.high_watermark].min].max
                non_exempt << [level, min_current]
                items << {lower: min_current.to_f, upper: level.max_seats.to_f, target: [min_current.to_f, stats.smoothed].max}
                min_sum += level.min_seats
                min_current_sum += min_current
              end
            end
            return if items.empty? && @nominal_sum.positive?

            allocations = nil
            share_frac = 0.0
            @fair_frac = 0.0
            if remaining <= min_sum
              nil
            elsif remaining <= min_current_sum
              share_frac = (remaining - min_sum).to_f / (min_current_sum - min_sum)
            else
              begin
                allocations, @fair_frac = self.class.compute_concurrency_allocation(@nominal_sum, items)
              rescue ArgumentError
                allocations = non_exempt.map { |level, _| level.current_seats.to_f }
              end
            end
            @targets = {}
            @priority_levels.each_value do |level|
              index = non_exempt.index { |candidate, _| candidate.equal?(level) }
              current = if index.nil? then min_current_of_exempt[level.name]
                        elsif remaining <= min_sum then level.min_seats
                        elsif remaining <= min_current_sum then level.min_seats + ((non_exempt[index][1] - level.min_seats) * share_frac).round
                        else allocations[index].round
                        end
              denominator = current.positive? ? current : [1, (@server_seats / 10.0).round].max
              @targets[level.name] = index ? items[index][:target] : nil
              level.apply_current_seats!(current, denominator)
            end
            record_borrowing_metrics
          end
        end

        # conc_alloc.computeConcurrencyAllocation: split +required_sum+ among
        # classes in proportion to their targets, each within its bounds.
        # Returns [allocations, fair proportion].
        def self.compute_concurrency_allocation(required_sum, classes)
          raise ArgumentError, "negative sums are not supported" if required_sum.negative?

          required = required_sum.to_f
          low_sum = high_sum = target_sum = 0.0
          ub_min = lb_min = Float::MAX
          ub_max = lb_max = -Float::MAX
          relative = classes.each_with_index.map do |item, index|
            target = item[:target]
            if item[:lower].negative?
              raise ArgumentError,
                    "lower bound #{index} is #{item[:lower]} but negative lower bounds are not allowed"
            end
            raise ArgumentError, "target #{index} is #{target}, which is below its lower bound of #{item[:lower]}" if target < item[:lower]
            if item[:upper] < item[:lower]
              raise ArgumentError,
                    "upper bound #{index} is #{item[:upper]} but should not be less than the lower bound #{item[:lower]}"
            end

            target = MIN_TARGET if target < MIN_TARGET
            low_sum += item[:lower]
            high_sum += item[:upper]
            target_sum += target
            entry = {target: target, lower: item[:lower] / target, upper: item[:upper] / target}
            ub_min = [ub_min, entry[:upper]].min
            ub_max = [ub_max, entry[:upper]].max
            lb_min = [lb_min, entry[:lower]].min
            lb_max = [lb_max, entry[:lower]].max
            entry
          end
          if lb_max > 1
            raise ArgumentError,
                  "lbRange.max-1=#{lb_max - 1}, which is impossible because lbRange.max can not be greater than 1"
          end
          if low_sum - required > EPSILON
            raise ArgumentError,
                  "lower bounds sum to #{low_sum}, which is higher than the required sum of #{required_sum}"
          end
          if required - high_sum > EPSILON
            raise ArgumentError,
                  "upper bounds sum to #{high_sum}, which is lower than the required sum of #{required_sum}"
          end

          answer = Array.new(classes.length, 0.0)
          return [answer, 0.0] if required_sum.zero?
          return [classes.map { |item| item[:lower] }, lb_min] if low_sum - required > -EPSILON
          return [classes.map { |item| item[:upper] }, ub_max] if required - high_sum > -EPSILON

          fair_prop = required / target_sum
          return [relative.map { |entry| entry[:target] * fair_prop }, fair_prop] if fair_prop.between?(lb_max, ub_min)

          # Bounds matter: walk the bounds in ascending order.
          bounds = []
          relative.each_with_index do |entry, index|
            bounds << [entry[:lower], index, true]
            bounds << [entry[:upper], index, false]
          end
          bounds.sort_by!(&:first)
          sum_so_far = low_sum
          fair_prop = lb_min
          sensitive_target_sum = 0.0
          delta_sensitive_target_sum = 0.0
          sensitive_classes = 0
          delta_sensitive_classes = 0
          next_index = 0
          while sum_so_far < required
            next_bound = nil
            loop do
              sensitive_target_sum += delta_sensitive_target_sum
              sensitive_classes += delta_sensitive_classes
              raise ArgumentError, "impossible: ran out of bounds to consider in bound-constrained problem" if next_index >= bounds.length

              next_bound, item_index, lower = bounds[next_index]
              if lower
                delta_sensitive_classes = 1
                delta_sensitive_target_sum = relative[item_index][:target]
              else
                delta_sensitive_classes = -1
                delta_sensitive_target_sum = -relative[item_index][:target]
              end
              next_index += 1
              break if next_bound > fair_prop
            end
            if sensitive_classes.zero?
              fair_prop = next_bound
              next
            end
            delta_fair_prop = (required - sum_so_far) / sensitive_target_sum
            next_prop = fair_prop + delta_fair_prop
            if next_prop <= next_bound
              fair_prop = next_prop
              break
            end
            sum_so_far += (next_bound - fair_prop) * sensitive_target_sum
            fair_prop = next_bound
          end
          allocations = classes.each_with_index.map do |item, index|
            [item[:lower], [item[:upper], fair_prop * relative[index][:target]].min].max
          end
          [allocations, fair_prop]
        end

        # -- metrics plumbing (called by the levels and queue sets) ----------

        def set_priority_level_configuration(name, nominal, min, max, exempt: false)
          return unless @metrics

          labels = {"priority_level" => name}
          set("apiserver_flowcontrol_nominal_limit_seats", nominal, labels)
          set("apiserver_flowcontrol_request_concurrency_limit", nominal, labels)
          set("apiserver_flowcontrol_lower_limit_seats", min, labels)
          set("apiserver_flowcontrol_upper_limit_seats", max, labels)
          _ = exempt
        end

        def set_demand_denominator(name, denominator)
          ratio(name, :demand)&.set_denominator(denominator)
        end

        def record_borrowing_metrics
          return unless @metrics

          set("apiserver_flowcontrol_seat_fair_frac", @fair_frac || 0.0)
          @priority_levels.each_value do |level|
            labels = {"priority_level" => level.name}
            stats = level.seat_demand_stats
            set("apiserver_flowcontrol_demand_seats_high_watermark", stats.high_watermark, labels)
            set("apiserver_flowcontrol_demand_seats_average", stats.average, labels)
            set("apiserver_flowcontrol_demand_seats_stdev", stats.stdev, labels)
            set("apiserver_flowcontrol_demand_seats_smoothed", stats.smoothed, labels)
            set("apiserver_flowcontrol_target_seats", @targets&.dig(level.name) || 0.0, labels) unless level.exempt
            set("apiserver_flowcontrol_current_limit_seats", level.current_seats, labels)
          end
        end

        def record_dispatch(labels, waited)
          return unless @metrics

          @metrics.increment("apiserver_flowcontrol_dispatched_requests_total", labels)
          observe("apiserver_flowcontrol_request_wait_duration_seconds", waited.to_f, labels.merge("execute" => "true"))
        rescue StandardError
          nil
        end

        def note_queued(labels, delta)
          adjust("apiserver_flowcontrol_current_inqueue_requests", labels, delta)
        end

        def note_executing(labels, delta)
          adjust("apiserver_flowcontrol_current_executing_requests", labels, delta)
        end

        def note_rejected(labels, reason)
          adjust("apiserver_flowcontrol_rejected_requests_total", labels.merge("reason" => reason.to_s), 1)
        end

        # apiserver_current_inqueue_requests{request_kind} and the server's
        # read-vs-write utilisation, by phase.
        def note_read_write(phase, mutating, delta)
          kind = mutating ? "mutating" : "readOnly"
          adjust("apiserver_current_inqueue_requests", {"request_kind" => kind}, delta) if phase == "waiting"
          @read_write&.[]([phase, kind])&.add(delta)
        rescue StandardError
          nil
        end

        def adjust(name, labels, delta)
          @metrics&.increment(name, labels, by: delta)
        rescue StandardError
          nil
        end

        def set(name, value, labels = {})
          @metrics&.set(name, value, labels)
        rescue StandardError
          nil
        end

        def observe(name, value, labels = {})
          @metrics&.observe(name, value, labels)
        rescue StandardError
          nil
        end

        private

        def query_of(request)
          return {} unless request.respond_to?(:query_value)

          %w[limit continue resourceVersion resourceVersionMatch labelSelector fieldSelector
             sendInitialEvents].each_with_object({}) do |name, query|
            value = request.query_value(name)
            query[name] = value unless value.nil?
          end
        rescue StandardError
          {}
        end

        def distinguisher(schema, attributes)
          case schema.dig("spec", "distinguisherMethod", "type")
          when "ByUser" then attributes.user.name.to_s
          when "ByNamespace" then attributes.namespace.to_s
          else ""
          end
        end

        # hashFlowID: sha256(fsName + NUL + distinguisher), first eight bytes little-endian.
        def flow_hash(schema, attributes)
          Digest::SHA256.digest("#{schema.dig("metadata", "name")}\0#{distinguisher(schema, attributes)}").unpack1("Q<")
        end

        def matches?(schema, attributes)
          Array(schema.dig("spec", "rules")).any? do |rule|
            subject_matches?(rule, attributes.user) && rule_matches?(rule, attributes)
          end
        end

        def subject_matches?(rule, user)
          Array(rule["subjects"]).any? do |subject|
            case subject["kind"]
            when "User" then subject.dig("user", "name") == "*" || subject.dig("user", "name") == user.name
            when "Group" then subject.dig("group", "name") == "*" || user.groups.include?(subject.dig("group", "name"))
            when "ServiceAccount"
              namespace = subject.dig("serviceAccount", "namespace")
              name = subject.dig("serviceAccount", "name")
              user.service_account? && user.service_account_namespace == namespace &&
                (name == "*" || user.name == "#{UserInfo::SERVICE_ACCOUNT_USERNAME_PREFIX}#{namespace}:#{name}")
            else false
            end
          end
        end

        def rule_matches?(rule, attributes)
          if attributes.resource_request?
            Array(rule["resourceRules"]).any? do |resource_rule|
              verbs = Array(resource_rule["verbs"])
              groups = Array(resource_rule["apiGroups"])
              resources = Array(resource_rule["resources"])
              namespaces = Array(resource_rule["namespaces"])
              (verbs.include?("*") || verbs.include?(attributes.verb)) &&
                (groups.include?("*") || groups.include?(attributes.api_group)) &&
                (resources.include?("*") || resources.include?(attributes.resource) || resources.include?(attributes.resource_with_subresource)) &&
                (attributes.namespace.empty? ? (resource_rule["clusterScope"] == true || namespaces.include?("*")) : (namespaces.include?("*") || namespaces.include?(attributes.namespace)))
            end
          else
            Array(rule["nonResourceRules"]).any? do |non_resource_rule|
              verbs = Array(non_resource_rule["verbs"])
              urls = Array(non_resource_rule["nonResourceURLs"])
              (verbs.include?("*") || verbs.include?(attributes.verb)) &&
                urls.any? do |url|
                  url == "*" || url == attributes.path || (url.end_with?("*") && attributes.path.to_s.start_with?(url.delete_suffix("*")))
                end
            end
          end
        end
      end
    end
  end
end
