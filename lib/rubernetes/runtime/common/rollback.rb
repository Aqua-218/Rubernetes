# frozen_string_literal: true

require_relative "errors"
require_relative "state_machine"

module Rubernetes
  module Runtime
    # Performs reverse-order, identity-checked cleanup.  A cleanup operation is
    # safe to retry after a crash because released ledger entries are skipped.
    class RollbackExecutor
      NOT_FOUND = :not_found

      def initialize(ledger:, adapter: nil, observer: nil)
        @ledger = ledger
        @adapter = adapter
        @observer = observer
      end

      def execute(operation_id:, operation_error:, mark_failed: true)
        operation = @ledger.operation(operation_id)
        raise OwnershipConflict, "unknown operation #{operation_id}" unless operation

        if operation.state == "CleanupPending"
          @ledger.transition(operation_id: operation_id, to: "RollingBack")
        elsif !%w[RollingBack Stopped Removed].include?(operation.state)
          @ledger.transition(operation_id: operation_id, to: "RollingBack")
        end
        errors = []
        resources = @ledger.resources(operation_id: operation_id, include_released: false).sort_by(&:sequence).reverse
        resources.each do |resource|
          begin
            cleanup(resource)
            @ledger.release(operation_id: operation_id, kind: resource.kind, id: resource.id,
                            identity: resource.identity, force: true)
          rescue StandardError => error
            entry = {"resource" => "#{resource.kind}:#{resource.id}",
                     "error" => "#{error.class}: #{error.message}"}
            errors << entry
            @ledger.record_cleanup_error(operation_id, resource_key: entry.fetch("resource"), error: error)
          end
        end

        current = @ledger.operation(operation_id)
        if errors.empty?
          if current.state == "RollingBack"
            @ledger.transition(operation_id: operation_id, to: "Stopped")
          end
        elsif current.state == "RollingBack"
          @ledger.transition(operation_id: operation_id, to: "CleanupPending")
        end
        @ledger.fail(operation_id, error: operation_error) if mark_failed
        result = @ledger.operation(operation_id)
        {"operation_id" => operation_id, "state" => result.state,
         "error" => result.error, "cleanup_errors" => result.cleanup_errors}.freeze
      end

      private

      def cleanup(resource)
        observed = observe(resource)
        if observed && !same_identity?(resource, observed)
          raise IdentityMismatch, "resource #{resource.kind}:#{resource.id} identity changed before cleanup"
        end

        response = invoke_cleanup(resource)
        raise Error, "cleanup returned false for #{resource.kind}:#{resource.id}" if response == false
        if response == NOT_FOUND || response == :missing
          observed_after = observe(resource)
          if observed_after && !same_identity?(resource, observed_after)
            raise IdentityMismatch, "not-found cleanup observed a different resource identity"
          end
        end
        response
      end

      def observe(resource)
        source = @observer || @adapter
        return nil unless source

        if source.respond_to?(:observe_resource)
          source.observe_resource(resource)
        elsif source.respond_to?(:lookup_resource)
          source.lookup_resource(resource.kind, resource.id)
        elsif source.respond_to?(:resource_identity)
          identity = source.resource_identity(resource.kind, resource.id)
          identity && {"identity" => identity, "owner" => resource.owner}
        end
      end

      def same_identity?(expected, observed)
        value = observed.respond_to?(:to_h) ? observed.to_h : observed
        identity = value["identity"] || value[:identity] || value["stable_identity"] || value[:stable_identity]
        owner = value["owner"] || value[:owner]
        identity.to_s == expected.identity.to_s && (owner.nil? || owner.to_s == expected.owner.to_s)
      end

      def invoke_cleanup(resource)
        return nil unless @adapter

        if @adapter.respond_to?(:cleanup_resource)
          return call_method(:cleanup_resource, resource)
        end
        if @adapter.respond_to?(:release_resource)
          return call_method(:release_resource, resource)
        end

        method_name = {
          "workspace" => :remove_workspace,
          "namespace" => :remove_isolation,
          "isolation" => :remove_isolation,
          "cgroup" => :remove_cgroup,
          "network" => :detach_resources,
          "container" => :remove_container,
          "process" => :stop_process
        }.fetch(resource.kind, nil)
        method_name && @adapter.respond_to?(method_name) ? call_method(method_name, resource) : nil
      end

      def call_method(method_name, resource)
        method = @adapter.method(method_name)
        parameters = method.parameters
        positional = parameters.select { |kind, _| %i[req opt].include?(kind) }
        keyword = parameters.select { |kind, _| %i[key keyreq keyrest].include?(kind) }
        if keyword.any?
          values = {
            kind: resource.kind,
            id: resource.id,
            identity: resource.identity,
            stable_identity: resource.identity,
            owner: resource.owner,
            resource: resource
          }
          arguments = positional.each_with_index.map { |(_kind, name), index| values[name] || values.values[index] }
          keywords = keyword.any? { |kind, _| kind == :keyrest } ? values : values.select { |key, _| keyword.map(&:last).include?(key) }
          method.call(*arguments, **keywords)
        else
          case method.arity
          when 0 then method.call
          when 1 then method.call(resource)
          else method.call(resource.id, resource.identity)
          end
        end
      end

      def resource_key(resource)
        "#{resource.kind}:#{resource.id}"
      end
    end

    # Immutable cleanup order generated from the acquisition order.
    class RollbackPlan
      def initialize(resources = nil, entries: nil, **options)
        resources = options[:resources] if resources.is_a?(Hash) && options.empty? && resources.key?(:resources)
        resources ||= entries
        @resources = Array(resources).freeze
      end

      def resources
        @resources
      end

      alias entries resources

      def each(&block)
        return enum_for(__method__) unless block

        @resources.each(&block)
      end

      def reverse
        @resources.reverse
      end

      def empty?
        @resources.empty?
      end
    end

    Rollback = RollbackExecutor
  end
end
