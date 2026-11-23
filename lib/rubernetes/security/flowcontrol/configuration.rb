# frozen_string_literal: true

module Rubernetes
  module Security
    module FlowControl
      module Configuration
        REQUIRED_NAMES = %w[exempt catch-all].freeze
        FLOW_SCHEMA_HEADER = "x-kubernetes-pf-flowschema-uid"
        PRIORITY_LEVEL_HEADER = "x-kubernetes-pf-prioritylevel-uid"

        def self.response_headers(schema_uid, level_uid)
          {FLOW_SCHEMA_HEADER => schema_uid, PRIORITY_LEVEL_HEADER => level_uid}.compact
        end

        # Use stored objects, but keep the mandatory fallback and exempt rules
        # effective while their real objects are absent. Existing queue sets
        # continue dispatching requests under their new bounds.
        def replace_configuration(flow_schemas:, priority_level_configurations:)
          schemas = named_definitions(flow_schemas)
          levels = named_definitions(priority_level_configurations)
          @mutex.synchronize do
            schemas = @fallback_schemas.merge(schemas)
            levels = @fallback_levels.merge(levels)
            next if @definitions == [schemas, levels] && @priority_levels.size == levels.size

            configure_levels(levels)
            @flow_schemas = schemas.values.select do |schema|
              levels.key?(schema.dig("spec", "priorityLevelConfiguration", "name"))
            end.sort_by { |schema| [schema.dig("spec", "matchingPrecedence").to_i, schema.dig("metadata", "name")] }.freeze
            @definitions = [schemas, levels]
          end
        end

        private

        def initialize_configuration(flow_schemas, levels, after)
          @after = after
          @pending = Hash.new(0)
          @priority_levels = {}.freeze
          @fallback_schemas = named_definitions(flow_schemas).slice(*REQUIRED_NAMES)
          @fallback_levels = named_definitions(levels).slice(*REQUIRED_NAMES)
          replace_configuration(flow_schemas: flow_schemas, priority_level_configurations: levels)
        end

        def named_definitions(objects)
          Array(objects).to_h do |object|
            metadata = object.fetch("metadata")
            [metadata.fetch("name"), {"metadata" => metadata.slice("name", "uid"), "spec" => object.fetch("spec", {})}]
          end
        end

        def configure_levels(definitions)
          previous = @priority_levels
          configured = definitions.to_h do |name, plc|
            level = previous[name] || Controller::PriorityLevel.new(controller: self, name: name, spec: plc.fetch("spec"), clock: @clock, after: @after)
            level.reconfigure!(plc.fetch("spec"), plc.dig("metadata", "uid"))
            [name, level]
          end
          # A removed level stops receiving new requests, but still receives
          # a share of seats until its pending classifications and queue drain.
          draining = previous.except(*configured.keys).reject { |_, level| idle_level?(level) }
          @priority_levels = configured.merge(draining).freeze
          @share_sum = @priority_levels.values.reject(&:exempt).sum(&:nominal_shares).to_f
          @priority_levels.each_value { |level| level.configure_bounds!(@server_seats, @share_sum) }
          @nominal_sum = @priority_levels.values.sum(&:nominal_seats)
          register_seat_metrics(@metrics) if @metrics
          adjust_borrowing!
          (previous.keys - @priority_levels.keys).each { |name| forget_level_limits(name) }
        end

        def idle_level?(level)
          @pending[level].zero? && level.queue_set.idle?
        end

        def reserve_flow(attributes)
          @mutex.synchronize do
            schema = classify(attributes)
            level = @priority_levels[schema&.dig("spec", "priorityLevelConfiguration", "name")]
            @pending[level] += 1 if level
            [schema, level, level&.uid]
          end
        end

        def release_reservation(level)
          return unless level

          @mutex.synchronize do
            @pending[level] -= 1
            @pending.delete(level) if @pending[level].zero?
            reap_idle_level(level.name)
          end
        end

        def reap_idle_level(name)
          return if @definitions.last.key?(name)

          @mutex.synchronize do
            definitions = @definitions.last
            level = @priority_levels[name]
            configure_levels(definitions) if level && !definitions.key?(name) && idle_level?(level)
          end
        end

        def forget_level_limits(name)
          %w[nominal_limit_seats request_concurrency_limit lower_limit_seats upper_limit_seats current_limit_seats target_seats].each do |suffix|
            @metrics&.delete("apiserver_flowcontrol_#{suffix}", {"priority_level" => name})
          end
        end
      end

      module PriorityLevelConfiguration
        attr_reader :uid

        def reconfigure!(spec, uid)
          @uid = uid
          return if @spec == spec

          load_spec(spec)
          @queue_set.configure(concurrency_limit: @current_seats, concurrency_denominator: [@current_seats, 1].max,
                               desired_queues: @queues, queue_length_limit: @queue_length_limit, hand_size: @hand_size)
        end

        private

        def load_spec(spec)
          @spec = spec
          @exempt = spec["type"] == "Exempt"
          limited = spec["limited"] || spec["exempt"] || {}
          @nominal_shares = limited.fetch("nominalConcurrencyShares", @exempt ? 0 : Controller::DEFAULT_NOMINAL_SHARES).to_i
          @lendable_percent = limited["lendablePercent"]
          @borrowing_limit_percent = @exempt ? nil : limited["borrowingLimitPercent"]
          queuing = limited.dig("limitResponse", "queuing")
          @reject = !@exempt && limited.dig("limitResponse", "type") == "Reject"
          @queues = if @exempt
                      -1
                    else
                      (queuing ? queuing.fetch("queues", Controller::DEFAULT_QUEUES).to_i : 0)
                    end
          @hand_size = queuing ? queuing.fetch("handSize", Controller::DEFAULT_HAND_SIZE).to_i : 1
          @queue_length_limit = queuing ? queuing.fetch("queueLengthLimit", Controller::DEFAULT_QUEUE_LENGTH_LIMIT).to_i : 0
        end
      end
    end
  end
end
