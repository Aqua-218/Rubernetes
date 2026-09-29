# frozen_string_literal: true

require "securerandom"
require "thread"
require "time"

require_relative "canonical"
require_relative "errors"
require_relative "state_machine"

module Rubernetes
  module Runtime
    # Durable operation and resource ownership ledger.  Every externally
    # visible mutation is represented by a WAL event before the in-memory view
    # is changed, so replay never invents an ownership result.
    class ResourceLedger
      Operation = Struct.new(:id, :request_id, :action, :target_id, :owner,
                            :config_digest, :state, :resources, :result,
                            :error, :cleanup_errors, :metadata, keyword_init: true) do
        def to_h
          {
            "id" => id,
            "request_id" => request_id,
            "action" => action,
            "target_id" => target_id,
            "owner" => owner,
            "config_digest" => config_digest,
            "state" => state,
            "resources" => Array(resources),
            "result" => result,
            "error" => error,
            "cleanup_errors" => Array(cleanup_errors),
            "metadata" => metadata
          }
        end
      end

      Resource = Struct.new(:kind, :id, :identity, :owner, :state, :metadata, :sequence,
                            keyword_init: true) do
        alias stable_identity identity

        def [](key)
          return identity if key.to_s == "stable_identity"

          to_h.fetch(key.to_s)
        end

        def fetch(key, *arguments)
          return identity if key.to_s == "stable_identity"

          to_h.fetch(key.to_s, *arguments)
        end

        def to_h
          {
            "kind" => kind,
            "id" => id,
            "identity" => identity,
            "owner" => owner,
            "state" => state,
            "metadata" => metadata,
            "sequence" => sequence
          }
        end
      end

      ACTIVE_STATES = (StateMachine::STATES - ["Removed"]).freeze
      RELEASEABLE_OPERATION_STATES = %w[Stopped Removed RollingBack CleanupPending StateUnknown].freeze

      def initialize(wal: nil, journal: nil, clock: -> { Time.now.utc })
        @wal = wal || journal
        raise ArgumentError, "resource ledger requires a durable WAL" unless @wal
        @clock = clock
        @mutex = Mutex.new
        @operations = {}
        @resources = {}
        @request_index = {}
        replay!
      end

      attr_reader :wal

      def begin_operation(operation_id: nil, request_id: nil, action: "unknown", owner:, config_digest:, target_id: nil, metadata: {})
        operation_id ||= request_id || SecureRandom.uuid
        request_id ||= operation_id
        request_id = identifier(request_id, "request_id")
        operation_id ||= request_id
        operation_id = identifier(operation_id, "operation_id")
        @mutex.synchronize do
          existing_id = @request_index[request_id]
          if existing_id
            existing = @operations.fetch(existing_id)
            ensure_same_request!(existing, action: action, owner: owner,
                                 config_digest: config_digest, target_id: target_id)
            return immutable_operation(existing)
          end
          if @operations.key?(operation_id)
            raise OwnershipConflict, "operation #{operation_id} is already present"
          end

          operation = Operation.new(
            id: operation_id,
            request_id: request_id,
            action: String(action),
            target_id: target_id && String(target_id),
            owner: identifier(owner, "owner"),
            config_digest: identifier(config_digest, "config_digest"),
            state: "New",
            resources: [],
            result: nil,
            error: nil,
            cleanup_errors: [],
            metadata: Canonical.immutable(metadata)
          )
          append!(operation.id, "operation_started", operation.to_h)
          @operations[operation.id] = operation
          @request_index[request_id] = operation.id
          immutable_operation(operation)
        end
      end

      alias start_operation begin_operation

      def operation_for_request(request_id)
        @mutex.synchronize do
          operation_id = @request_index[String(request_id)]
          operation_id && immutable_operation(@operations.fetch(operation_id))
        end
      end

      def operation(operation_id)
        @mutex.synchronize { @operations[String(operation_id)] && immutable_operation(@operations[String(operation_id)]) }
      end

      def operations
        @mutex.synchronize { @operations.values.map { |operation| immutable_operation(operation) }.freeze }
      end

      def set_result(operation_id, result)
        @mutex.synchronize do
          operation = operation!(operation_id)
          updated = update_operation(operation, result: Canonical.immutable(result))
          append!(operation.id, "operation_result", updated.to_h)
          @operations[operation.id] = updated
        end
      end

      def transition(operation_id:, to:, from: nil, resources: nil, state: nil, config_digest: nil)
        @mutex.synchronize do
          operation = operation!(operation_id)
          from ||= operation.state
          from = String(from)
          to = String(to)
          raise InvalidTransition, "transition source #{from.inspect} does not match #{operation.state.inspect}" unless from == operation.state

          if from == to
            raise InvalidTransition, "workload gate can only be released once" if to == "Running"

            return immutable_operation(operation)
          end

          StateMachine.validate!(from, to)
          if state && String(state) != to
            raise InvalidTransition, "state #{state.inspect} disagrees with transition target #{to.inspect}"
          end
          resource_keys = resources ? Array(resources).map { |resource| key_for(resource) } : operation.resources
          resource_keys.each do |resource_key|
            raise OwnershipConflict, "resource #{resource_key} is not owned" unless @resources.key?(resource_key)
          end
          updated = update_operation(operation, state: to, resources: resource_keys,
                                     config_digest: config_digest || operation.config_digest)
          append!(operation.id, "state_transition", {
            "from" => from,
            "to" => to,
            "operation" => updated.to_h,
            "owned_resources" => resource_keys,
            "operation_id" => operation.id,
            "config_digest" => updated.config_digest
          })
          @operations[operation.id] = updated
          immutable_operation(updated)
        end
      end

      def claim(operation_id:, kind:, id:, identity: nil, stable_identity: nil, metadata: {})
        identity ||= stable_identity
        @mutex.synchronize do
          operation = operation!(operation_id)
          resource_kind = identifier(kind, "resource kind")
          resource_id = identifier(id, "resource id")
          resource_identity = identifier(identity, "resource identity")
          resource_key = key_for(resource_kind, resource_id)
          existing = @resources[resource_key]
          if existing
            if existing.identity != resource_identity
              raise IdentityMismatch, "resource #{resource_key} identity changed"
            end
            if existing.owner != operation.owner || existing.state == "Released"
              raise OwnershipConflict, "resource #{resource_key} cannot be reused after release"
            end
            return immutable_resource(existing)
          end

          resource = Resource.new(kind: resource_kind, id: resource_id,
                                  identity: resource_identity, owner: operation.owner,
                                  state: "Owned", metadata: Canonical.immutable(metadata),
                                  sequence: @resources.values.map(&:sequence).compact.max.to_i + 1)
          updated = update_operation(operation, resources: (operation.resources + [resource_key]).uniq)
          append!(operation.id, "resource_claimed", resource.to_h)
          append!(operation.id, "operation_resources", updated.to_h)
          @resources[resource_key] = resource
          @operations[operation.id] = updated
          immutable_resource(resource)
        end
      end

      def resources(operation_id: nil, owner: nil, include_released: false)
        @mutex.synchronize do
          values = @resources.values
          if operation_id
            operation = @operations[String(operation_id)]
            values = operation ? operation.resources.filter_map { |resource_key| @resources[resource_key] } : []
          end
          values = values.select { |resource| resource.owner == String(owner) } if owner
          values = values.reject { |resource| resource.state == "Released" } unless include_released
          values.sort_by(&:sequence).map { |resource| immutable_resource(resource) }.freeze
        end
      end

      def resource(kind:, id:)
        @mutex.synchronize { @resources[key_for(kind, id)] && immutable_resource(@resources[key_for(kind, id)]) }
      end

      def owned?(kind:, id:, identity:, owner: nil)
        @mutex.synchronize do
          resource = @resources[key_for(kind, id)]
          resource && resource.state != "Released" && resource.identity == String(identity) &&
            (owner.nil? || resource.owner == String(owner))
        end
      end

      # force is the teardown path.  Releasing a resource this operation no
      # longer holds is what a repeated teardown looks like -- the entry was
      # released by an earlier attempt, or its kernel name (a veth is named
      # from a hash, and names get reused) has since been claimed by a later
      # sandbox.  Neither is a failure, and neither may touch an entry this
      # operation does not own: refusing both left the Pod in CleanupPending,
      # so the node never issued its final delete and the Pod stayed
      # Terminating in the API for ever.  Outside teardown the check stays
      # strict, because there a mismatch really is a bug.
      def release(operation_id:, kind:, id:, identity: nil, stable_identity: nil, force: false)
        identity ||= stable_identity
        @mutex.synchronize do
          operation = operation!(operation_id)
          resource_key = key_for(kind, id)
          resource = @resources[resource_key]
          return resource if resource && resource.state == "Released"
          unless resource
            raise OwnershipConflict, "resource #{resource_key} is not owned" unless force

            return nil
          end
          unless resource.owner == operation.owner && resource.identity == String(identity)
            raise IdentityMismatch, "resource #{resource_key} identity or owner mismatch" unless force

            return nil
          end
          unless force || RELEASEABLE_OPERATION_STATES.include?(operation.state)
            raise InvalidTransition, "cannot release #{resource_key} while operation is #{operation.state}"
          end

          released = Resource.new(**resource.to_h.transform_keys(&:to_sym).merge(state: "Released"))
          append!(operation.id, "resource_released", released.to_h)
          @resources[resource_key] = released
          immutable_resource(released)
        end
      end

      def record_cleanup_error(operation_id, resource_key:, error:)
        @mutex.synchronize do
          operation = operation!(operation_id)
          entry = {"resource" => String(resource_key), "error" => error_string(error), "at" => timestamp}
          updated = update_operation(operation, cleanup_errors: operation.cleanup_errors + [entry])
          append!(operation.id, "cleanup_error", entry.merge("operation" => updated.to_h))
          @operations[operation.id] = updated
        end
      end

      def fail(operation_id, error:)
        @mutex.synchronize do
          operation = operation!(operation_id)
          entry = error_hash(error)
          updated = update_operation(operation, error: entry)
          append!(operation.id, "operation_failed", updated.to_h)
          @operations[operation.id] = updated
        end
      end

      def recovery_candidates
        @mutex.synchronize do
          @operations.values.select { |operation| StateMachine.cleanup_state?(operation.state) }
                               .map { |operation| immutable_operation(operation) }.freeze
        end
      end

      def finish(operation_id, state: "Removed")
        transition(operation_id: operation_id, to: state)
      end

      def active_resource_keys(operation_id)
        @mutex.synchronize do
          operation = operation!(operation_id)
          operation.resources.select { |resource_key| @resources.fetch(resource_key).state != "Released" }.freeze
        end
      end

      def snapshot_state
        @mutex.synchronize do
          {
            "operations" => @operations.values.map(&:to_h),
            "resources" => @resources.values.map(&:to_h)
          }
        end
      end

      private

      def replay!
        @wal.each do |record|
          payload = record.to_h.fetch("payload")
          case record.event
          when "operation_started"
            operation = operation_from(payload)
            @operations[operation.id] = operation
            @request_index[operation.request_id] = operation.id
          when "operation_result", "operation_failed", "operation_resources"
            operation = operation_from(payload)
            @operations[operation.id] = operation
            @request_index[operation.request_id] = operation.id
          when "resource_claimed", "resource_released"
            resource = resource_from(payload)
            @resources[key_for(resource.kind, resource.id)] = resource
            if record.operation_id && (operation = @operations[record.operation_id])
              unless operation.resources.include?(key_for(resource.kind, resource.id))
                @operations[operation.id] = update_operation(
                  operation,
                  resources: operation.resources + [key_for(resource.kind, resource.id)]
                )
              end
            elsif record.event == "resource_claimed"
              raise JournalCorruption, "resource references unknown operation #{record.operation_id}"
            end
          when "state_transition"
            operation = operation_from(payload.fetch("operation"))
            @operations[operation.id] = operation
            @request_index[operation.request_id] = operation.id
          when "cleanup_error"
            operation = operation_from(payload.fetch("operation"))
            @operations[operation.id] = operation
            @request_index[operation.request_id] = operation.id
          end
        end
        validate_replayed_ownership!
      rescue KeyError, TypeError, ArgumentError => error
        raise JournalCorruption, "runtime ledger replay failed: #{error.message}"
      end

      def validate_replayed_ownership!
        @operations.each_value do |operation|
          operation.resources.each do |resource_key|
            raise JournalCorruption, "operation #{operation.id} references unknown resource #{resource_key}" unless @resources.key?(resource_key)
          end
        end
      end

      def append!(operation_id, event, payload)
        @wal.append(operation_id: operation_id, event: event, payload: payload, timestamp: @clock.call)
      end

      def operation!(operation_id)
        @operations.fetch(String(operation_id)) { raise OwnershipConflict, "unknown operation #{operation_id}" }
      end

      def ensure_same_request!(existing, action:, owner:, config_digest:, target_id:)
        fields_match = existing.action == String(action) && existing.owner == String(owner) &&
          existing.config_digest == String(config_digest) && existing.target_id == (target_id && String(target_id))
        raise OwnershipConflict, "request #{existing.request_id} was replayed with different intent" unless fields_match
      end

      def update_operation(operation, **changes)
        Operation.new(**operation.to_h.transform_keys(&:to_sym).merge(changes))
      end

      def operation_from(value)
        hash = value.transform_keys(&:to_s)
        Operation.new(
          id: String(hash.fetch("id")), request_id: String(hash.fetch("request_id")),
          action: String(hash.fetch("action")), target_id: hash["target_id"]&.to_s,
          owner: String(hash.fetch("owner")), config_digest: String(hash.fetch("config_digest")),
          state: String(hash.fetch("state")), resources: Array(hash.fetch("resources")).map(&:to_s),
          result: hash["result"], error: hash["error"], cleanup_errors: Array(hash["cleanup_errors"]),
          metadata: Canonical.immutable(hash.fetch("metadata", {}))
        )
      end

      def resource_from(value)
        hash = value.transform_keys(&:to_s)
        Resource.new(kind: String(hash.fetch("kind")), id: String(hash.fetch("id")),
                     identity: String(hash.fetch("identity") { hash.fetch("stable_identity") }),
                     owner: String(hash.fetch("owner")), state: String(hash.fetch("state")),
                     metadata: Canonical.immutable(hash.fetch("metadata", {})),
                     sequence: Integer(hash.fetch("sequence", 0)))
      end

      def immutable_operation(operation)
        Operation.new(**operation.to_h.transform_keys(&:to_sym).merge(
          resources: operation.resources.dup.freeze,
          result: Canonical.immutable(operation.result),
          cleanup_errors: operation.cleanup_errors.map { |entry| Canonical.immutable(entry) }.freeze,
          metadata: Canonical.immutable(operation.metadata)
        )).freeze
      end

      def immutable_resource(resource)
        Resource.new(**resource.to_h.transform_keys(&:to_sym).merge(metadata: Canonical.immutable(resource.metadata))).freeze
      end

      def key_for(kind_or_resource, id = nil)
        if id.nil?
          resource = kind_or_resource.respond_to?(:to_h) ? kind_or_resource.to_h : kind_or_resource
          return "#{resource.fetch("kind") { resource.fetch(:kind) }}:#{resource.fetch("id") { resource.fetch(:id) }}"
        end
        "#{kind_or_resource}:#{id}"
      end

      def identifier(value, name)
        string = String(value)
        raise ArgumentError, "#{name} must not be empty" if string.empty? || string.include?("\0")

        string
      end

      def timestamp
        value = @clock.call
        value.is_a?(Time) ? value.utc.iso8601(6) : Time.iso8601(value.to_s).utc.iso8601(6)
      end

      def error_hash(error)
        return error.transform_keys(&:to_s) if error.is_a?(Hash)

        {"class" => error.class.name, "message" => error.message}
      end

      def error_string(error)
        "#{error.class}: #{error.message}"
      end
    end

    OwnershipLedger = ResourceLedger
    ResourceOwnership = ResourceLedger
    Ledger = ResourceLedger
  end
end
