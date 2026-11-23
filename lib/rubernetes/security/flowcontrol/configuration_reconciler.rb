# frozen_string_literal: true

require "time"

module Rubernetes
  module Security
    module FlowControl
      # Each serving apiserver follows the shared storage collection so writes
      # through any replica refresh the classifier and the queue sets.
      class ConfigurationReconciler
        GROUP = "flowcontrol.apiserver.k8s.io"
        VERSION = "v1"
        RELIST_SECONDS = 30

        def initialize(controller:, store:, key_for:, clock:, logger: nil)
          @controller = controller
          @store = store
          @key_for = key_for
          @clock = clock
          @logger = logger
          @prefix = key_for.call(GROUP, VERSION, "", nil, nil)
        end

        def start
          return if @thread&.alive?

          @stopping = false
          @thread = Thread.new do
            Thread.current.name = "apf-configuration"
            run
          end
        end

        def stop
          @stopping = true
          @stream&.close
          @thread&.join(2)
          @controller.stop
        end

        private

        def run
          until @stopping
            begin
              watch_configuration
            rescue Rubernetes::Storage::Error, Rubernetes::Consensus::Error => error
              @logger&.warn("flow_control.configuration_retry", error: error.message)
              sleep(1) unless @stopping
            end
          end
        end

        def watch_configuration
          revision = apply_snapshot
          @stream = @store.watch(@prefix, resource_version: revision)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + RELIST_SECONDS
          until @stopping || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
            event = @stream.next(timeout: 0.5)
            break if event&.type.to_s == "ERROR"

            next unless event && %w[ADDED MODIFIED DELETED].include?(event.type.to_s)

            revision = apply_snapshot if event.revision.to_i > revision.to_i
          end
        ensure
          @stream&.close
          @stream = nil
        end

        def apply_snapshot
          snapshot = @store.list(@prefix)
          schemas = snapshot.items.select { |object| object["kind"] == "FlowSchema" }
          levels = snapshot.items.select { |object| object["kind"] == "PriorityLevelConfiguration" }
          @controller.replace_configuration(flow_schemas: schemas, priority_level_configurations: levels)
          level_names = levels.to_set { |level| level.dig("metadata", "name") }
          schemas.each { |schema| reconcile_condition(schema, level_names) }
          snapshot.resource_version
        end

        def reconcile_condition(schema, level_names)
          existing = Array(schema.dig("status", "conditions"))
          level = schema.dig("spec", "priorityLevelConfiguration", "name")
          found = level_names.include?(level)
          condition = {"type" => "Dangling", "status" => found ? "False" : "True", "reason" => found ? "Found" : "NotFound",
                       "message" => "This FlowSchema references the PriorityLevelConfiguration object named #{level.to_s.inspect} " \
                                    "#{found ? "and it exists" : "but there is no such object"}"}
          old = existing.find { |item| item["type"] == "Dangling" }
          return if old && old.slice(*condition.keys) == condition

          key = @key_for.call(GROUP, VERSION, "flowschemas", :cluster, schema.dig("metadata", "name"))
          conditions = existing.reject { |item| item["type"] == "Dangling" }
          conditions << condition.merge("lastTransitionTime" => @clock.call.utc.iso8601)
          status = (schema["status"] || {}).merge("conditions" => conditions)
          @store.update(key, schema.merge("status" => status), resource_version: schema.dig("metadata", "resourceVersion"))
        rescue Rubernetes::Storage::Conflict, Rubernetes::Storage::NotFound
          # A newer snapshot or the next watch event owns the new condition.
          nil
        end
      end
    end
  end
end
