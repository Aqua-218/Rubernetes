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

      # API Priority and Fairness (spec 5.1.4).  FlowSchemas classify a
      # request by subject and rules; the matching PriorityLevelConfiguration
      # owns a fixed number of seats and, when Limited, a set of queues.  Each
      # flow (schema + distinguisher) is shuffle-sharded onto `handSize`
      # queues and enqueued on the shortest; a request waits at most the
      # configured wait limit or is rejected with 429 + Retry-After.  Watches
      # are counted as long-running and are not seated.
      class Controller
        DEFAULT_QUEUES = 64
        DEFAULT_HAND_SIZE = 8
        DEFAULT_QUEUE_LENGTH_LIMIT = 50
        DEFAULT_REQUEST_WAIT_LIMIT = 60.0
        DEFAULT_READ_SEATS = 400
        DEFAULT_MUTATING_SEATS = 200
        LONG_RUNNING_VERBS = %w[watch].freeze
        LONG_RUNNING_SUBRESOURCES = %w[exec attach portforward proxy log].freeze

        Ticket = Struct.new(:priority_level, :flow_schema, :queue_index, :seats, :queued_seconds, :exempt, :dispatched_at, :mutating, :watch,
                            keyword_init: true)

        class PriorityLevel
          attr_reader :name, :seats, :queues, :hand_size, :queue_length_limit, :wait_limit, :exempt, :inflight

          def initialize(name:, seats:, queues:, hand_size:, queue_length_limit:, wait_limit:, exempt:, reject: false)
            @reject = reject
            @name = name
            @seats = seats
            @queues = queues
            @hand_size = hand_size
            @queue_length_limit = queue_length_limit
            @wait_limit = wait_limit
            @exempt = exempt
            @inflight = 0
            @queue_lengths = Array.new(queues) { 0 }
            @monitor = Monitor.new
            @condition = @monitor.new_cond
            @rejected = 0
            @dispatched = 0
          end

          def stats
            @monitor.synchronize { {"name" => @name, "seats" => @seats, "inflight" => @inflight, "queued" => @queue_lengths.sum, "rejected" => @rejected, "dispatched" => @dispatched, "exempt" => @exempt} }
          end

          # Returns the queue index or raises RejectedError.
          def admit(flow_hash, clock, on_queue: nil)
            return [nil, 0.0] if @exempt

            @monitor.synchronize do
              queue_index = shuffle_shard(flow_hash)
              started = clock.call
              if @inflight < @seats && @queue_lengths[queue_index].zero?
                @inflight += 1
                @dispatched += 1
                return [queue_index, 0.0]
              end
              if @queue_lengths[queue_index] >= @queue_length_limit
                @rejected += 1
                raise RejectedError.new("too many requests queued for priority level #{@name}", retry_after: 1,
                                                                                                  reason: @reject ? "concurrency-limit" : "queue-full")
              end
              @queue_lengths[queue_index] += 1
              on_queue&.call(1, @queue_lengths[queue_index])
              deadline = started + @wait_limit
              begin
                loop do
                  remaining = deadline - clock.call
                  if remaining <= 0
                    @rejected += 1
                    raise RejectedError.new("request waited #{@wait_limit}s for priority level #{@name}", retry_after: [@wait_limit.ceil, 1].max,
                                                                                                         reason: "time-out")
                  end
                  break if @inflight < @seats && oldest_waiting?(queue_index)

                  @condition.wait([remaining, 0.05].min)
                end
              ensure
                @queue_lengths[queue_index] -= 1
                on_queue&.call(-1, @queue_lengths[queue_index])
              end
              @inflight += 1
              @dispatched += 1
              [queue_index, clock.call - started]
            end
          end

          def release
            return if @exempt

            @monitor.synchronize do
              @inflight -= 1 if @inflight.positive?
              @condition.broadcast
            end
          end

          private

          # Round-robin fairness approximation: the queue with waiters that is
          # also the shortest gets the seat; ties resolve by index.
          def oldest_waiting?(queue_index)
            waiting = @queue_lengths.each_index.select { |index| @queue_lengths[index].positive? }
            shortest = waiting.min_by { |index| [@queue_lengths[index], index] }
            shortest.nil? || shortest == queue_index
          end

          # Shuffle sharding: derive hand_size candidate queues from the flow
          # hash and pick the shortest.
          def shuffle_shard(flow_hash)
            return 0 if @queues <= 1

            candidates = []
            value = flow_hash
            [@hand_size, @queues].min.times do
              index = value % @queues
              value /= @queues
              index = (index + 1) % @queues while candidates.include?(index)
              candidates << index
            end
            candidates.min_by { |index| [@queue_lengths[index], index] }
          end
        end

        attr_reader :priority_levels, :flow_schemas

        def initialize(flow_schemas:, priority_level_configurations:, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) },
                       read_seats: DEFAULT_READ_SEATS, mutating_seats: DEFAULT_MUTATING_SEATS)
          @clock = clock
          @flow_schemas = Array(flow_schemas).sort_by { |schema| [schema.dig("spec", "matchingPrecedence").to_i, schema.dig("metadata", "name").to_s] }
          total_shares = Array(priority_level_configurations).sum { |plc| plc.dig("spec", "limited", "nominalConcurrencyShares").to_i }
          total_seats = read_seats + mutating_seats
          @priority_levels = Array(priority_level_configurations).each_with_object({}) do |plc, levels|
            name = plc.dig("metadata", "name")
            spec = plc["spec"] || {}
            exempt = spec["type"] == "Exempt"
            limited = spec["limited"] || {}
            shares = limited["nominalConcurrencyShares"].to_i
            seats = exempt ? Float::INFINITY : [((shares.to_f / [total_shares, 1].max) * total_seats).floor, 1].max
            queuing = limited.dig("limitResponse", "queuing") || {}
            reject = limited.dig("limitResponse", "type") == "Reject"
            levels[name] = PriorityLevel.new(name: name, seats: seats, queues: reject ? 1 : (queuing["queues"] || DEFAULT_QUEUES).to_i,
                                             hand_size: (queuing["handSize"] || DEFAULT_HAND_SIZE).to_i,
                                             queue_length_limit: reject ? 0 : (queuing["queueLengthLimit"] || DEFAULT_QUEUE_LENGTH_LIMIT).to_i,
                                             wait_limit: DEFAULT_REQUEST_WAIT_LIMIT, exempt: exempt, reject: reject)
          end
        end

        def long_running?(attributes)
          LONG_RUNNING_VERBS.include?(attributes.verb) || LONG_RUNNING_SUBRESOURCES.include?(attributes.subresource.to_s)
        end

        WAIT_BUCKETS = [0, 0.005, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30].freeze

        # apiserver/pkg/util/flowcontrol/metrics.
        def metrics=(registry)
          @metrics = registry
          return unless registry

          registry.register("apiserver_flowcontrol_dispatched_requests_total", type: :counter,
                                                                               help: "Number of requests executed by API Priority and Fairness subsystem")
          registry.register("apiserver_flowcontrol_rejected_requests_total", type: :counter,
                                                                             help: "Number of requests rejected by API Priority and Fairness subsystem")
          registry.register("apiserver_flowcontrol_current_executing_requests", type: :gauge,
                                                                                help: "Number of requests in initial (for a WATCH) or any (for a non-WATCH) execution stage in the API Priority and Fairness subsystem")
          registry.register("apiserver_flowcontrol_current_inqueue_requests", type: :gauge,
                                                                              help: "Number of requests currently pending in queues of the API Priority and Fairness subsystem")
          registry.register("apiserver_flowcontrol_request_wait_duration_seconds", type: :histogram, buckets: WAIT_BUCKETS,
                                                                                   help: "Length of time a request spent waiting in its queue")
          registry.register("apiserver_flowcontrol_nominal_limit_seats", type: :gauge,
                                                                         help: "Nominal number of execution seats configured for each priority level")
          @priority_levels.each do |name, level|
            registry.set("apiserver_flowcontrol_nominal_limit_seats", level.exempt ? 0 : level.seats, {"priority_level" => name})
          end
          register_seat_metrics(registry)
        end

        # A request's seats (one: there is no work estimator), its limits
        # and the time-integrated utilisation ratios of each Limited level
        # (queueset's reqsGaugePair, execSeatsGauge and seatDemandIntegrator)
        # and of the whole server by read-only / mutating kind.  A level's
        # current limit is its nominal one -- seats are neither lent nor
        # borrowed.
        def register_seat_metrics(registry)
          @ratios = {}
          max_waiting = 0
          max_executing = 0
          @priority_levels.each do |name, level|
            next if level.exempt

            labels = {"priority_level" => name}
            registry.set("apiserver_flowcontrol_current_limit_seats", level.seats, labels)
            waiting_limit = [level.queue_length_limit, 1].max * level.queues
            max_waiting += level.queue_length_limit * level.queues
            max_executing += level.seats
            @ratios[name] = {
              waiting: registry.ratio_gauge("apiserver_flowcontrol_priority_level_request_utilization", labels.merge("phase" => "waiting"),
                                            denominator: waiting_limit, clock: @clock),
              executing: registry.ratio_gauge("apiserver_flowcontrol_priority_level_request_utilization", labels.merge("phase" => "executing"),
                                              denominator: level.seats, clock: @clock),
              # ConstLabels: phase="executing".
              seats: registry.ratio_gauge("apiserver_flowcontrol_priority_level_seat_utilization", labels.merge("phase" => "executing"),
                                          denominator: level.seats, clock: @clock),
              demand: registry.ratio_gauge("apiserver_flowcontrol_demand_seats", labels, denominator: level.seats, clock: @clock)
            }
          end
          @read_write = %w[waiting executing].product(%w[readOnly mutating]).to_h do |phase, kind|
            [[phase, kind], registry.ratio_gauge("apiserver_flowcontrol_read_vs_write_current_requests", {"phase" => phase, "request_kind" => kind},
                                                 denominator: [phase == "waiting" ? max_waiting : max_executing, 1].max, clock: @clock)]
          end
        end

        NON_MUTATING_VERBS = %w[get list watch].freeze

        # Classify and admit; returns a Ticket to release later.
        def enter(attributes)
          schema = classify(attributes)
          raise RejectedError.new("no FlowSchema matches the request", retry_after: 1) if schema.nil?

          level_name = schema.dig("spec", "priorityLevelConfiguration", "name")
          level = @priority_levels[level_name]
          raise RejectedError.new("priority level #{level_name} is not configured", retry_after: 1) if level.nil?

          schema_name = schema.dig("metadata", "name")
          labels = {"flow_schema" => schema_name.to_s, "priority_level" => level_name.to_s}
          if long_running?(attributes) || level.exempt
            record_dispatch(labels, 0.0, executing: false)
            return Ticket.new(priority_level: level_name, flow_schema: schema_name, queue_index: nil, seats: 0, queued_seconds: 0.0, exempt: true)
          end
          mutating = !NON_MUTATING_VERBS.include?(attributes.verb.to_s)
          on_queue = @metrics ? ->(delta, length) { note_queued(labels, mutating, delta, length) } : nil
          @metrics&.observe("apiserver_flowcontrol_work_estimated_seats", 1, labels)
          begin
            queue_index, waited = level.admit(flow_hash(schema, attributes), @clock, on_queue: on_queue)
          rescue RejectedError => error
            if @metrics
              @metrics.increment("apiserver_flowcontrol_rejected_requests_total", labels.merge("reason" => error.reason.to_s))
              @metrics.observe("apiserver_flowcontrol_request_wait_duration_seconds", 0.0, labels.merge("execute" => "false"))
            end
            raise
          end
          record_dispatch(labels, waited, executing: true)
          note_executing(labels, mutating, 1)
          Ticket.new(priority_level: level_name, flow_schema: schema_name, queue_index: queue_index, seats: 1, queued_seconds: waited, exempt: false,
                     dispatched_at: @metrics ? Process.clock_gettime(Process::CLOCK_MONOTONIC) : nil, mutating: mutating,
                     watch: attributes.verb.to_s == "watch")
        end

        def release(ticket)
          return if ticket.nil? || ticket.exempt

          labels = {"flow_schema" => ticket.flow_schema.to_s, "priority_level" => ticket.priority_level.to_s}
          adjust("apiserver_flowcontrol_current_executing_requests", labels, -1)
          note_executing(labels, ticket.mutating, -1)
          if @metrics && ticket.dispatched_at
            @metrics.observe("apiserver_flowcontrol_request_execution_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - ticket.dispatched_at,
                             labels.merge("type" => ticket.watch ? "watch" : "regular"))
          end
          @priority_levels[ticket.priority_level]&.release
        end

        def stats
          @priority_levels.values.map(&:stats)
        end

        def classify(attributes)
          @flow_schemas.find { |schema| matches?(schema, attributes) }
        end

        private

        def record_dispatch(labels, waited, executing:)
          return unless @metrics

          @metrics.increment("apiserver_flowcontrol_dispatched_requests_total", labels)
          @metrics.observe("apiserver_flowcontrol_request_wait_duration_seconds", waited.to_f, labels.merge("execute" => "true"))
          adjust("apiserver_flowcontrol_current_executing_requests", labels, 1) if executing
        rescue StandardError
          nil
        end

        # AddRequestsInQueues / AddSeatsInQueues, ObserveQueueLength on
        # enqueue, and the waiting ratios.
        def note_queued(labels, mutating, delta, length)
          adjust("apiserver_flowcontrol_current_inqueue_requests", labels, delta)
          adjust("apiserver_flowcontrol_current_inqueue_seats", labels, delta)
          @metrics.observe("apiserver_flowcontrol_request_queue_length_after_enqueue", length, labels) if delta.positive?
          ratios = @ratios&.[](labels["priority_level"])
          ratios&.fetch(:waiting)&.add(delta)
          ratios&.fetch(:demand)&.add(delta)
          @read_write&.[](["waiting", mutating ? "mutating" : "readOnly"])&.add(delta)
        rescue StandardError
          nil
        end

        # AddSeatConcurrencyInUse and the executing ratios.
        def note_executing(labels, mutating, delta)
          return unless @metrics

          adjust("apiserver_flowcontrol_current_executing_seats", labels, delta)
          ratios = @ratios&.[](labels["priority_level"])
          %i[executing seats demand].each { |key| ratios&.fetch(key)&.add(delta) }
          @read_write&.[](["executing", mutating ? "mutating" : "readOnly"])&.add(delta)
        rescue StandardError
          nil
        end

        def adjust(name, labels, delta)
          @metrics&.increment(name, labels, by: delta)
        rescue StandardError
          nil
        end

        def flow_hash(schema, attributes)
          method = schema.dig("spec", "distinguisherMethod", "type")
          distinguisher = case method
                          when "ByUser" then attributes.user.name
                          when "ByNamespace" then attributes.namespace.to_s
                          else ""
                          end
          Digest::SHA256.hexdigest("#{schema.dig("metadata", "name")}\0#{distinguisher}").to_i(16)
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
                urls.any? { |url| url == "*" || url == attributes.path || (url.end_with?("*") && attributes.path.to_s.start_with?(url.delete_suffix("*"))) }
            end
          end
        end
      end
    end
  end
end
