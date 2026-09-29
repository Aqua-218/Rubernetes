# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "runtime"

module Rubernetes
  module Controller
    # Shared, deliberately small primitives for the built-in controllers that
    # reconcile core API resources rather than workload templates.  The
    # methods keep storage access behind StoreAdapter and make every planner
    # operate on immutable informer snapshots.
    module SecondarySupport
      ENDPOINT_SLICE_LIMIT = 1_000

      protected

      def adapter_for(store)
        candidate = store || self.store
        return nil unless candidate

        candidate.is_a?(StoreAdapter) ? candidate : StoreAdapter.new(candidate)
      end

      def list_for(adapter, descriptor, namespace: :all)
        return [] unless adapter

        adapter.list(descriptor, namespace: namespace)
      end

      def find_for(adapter, descriptor, name, namespace: nil)
        return nil unless adapter

        adapter.find(descriptor, name: name, namespace: namespace)
      end

      # status_first splits the write into its own batch ahead of everything
      # else.  A controller that reports WHY its writes are failing has to get
      # the report out before it retries the write that fails: with one batch
      # the status update sits behind the refused Pod create and is rolled back
      # with it, so the ReplicaFailure condition never reaches the API.
      def result_for(resource, operations, status: nil, events: [], key: nil, batches: nil,
                     status_first: false)
        operations = Array(operations).compact
        status_operation = nil
        if status && resource
          status_operation = operation_status(resource, status,
                                              descriptor: ResourceDescriptor.parse(resource),
                                              reason: "controller status reconciliation")
        end
        if status_first && status_operation
          operations = [status_operation] + operations
          batches ||= [[status_operation], operations[1..]].reject(&:empty?)
        elsif status_operation
          operations << status_operation
        end
        ReconcileResult.new(operations: operations, batches: batches, status: status,
                            events: events, controller: name,
                            key: key || [Support.namespace(resource), Support.name(resource)].compact.join("/"))
      end

      def object_key_for(object)
        [Support.namespace(object), Support.name(object)].compact.join("/")
      end

      def namespaced_objects(adapter, namespace)
        return [] unless adapter

        adapter.all.select { |object| Support.namespace(object).to_s == namespace.to_s }
      end

      def owner_matches?(owner, dependent, controller: true)
        Support.owner_reference_matches?(owner, dependent, controller: controller)
      end

      def owner_ref(owner, controller: true, block_owner_deletion: true)
        Support.owner_reference(owner, controller: controller, block_owner_deletion: block_owner_deletion)
      end

      def ensure_owner_reference(object, owner, controller: true, block_owner_deletion: true)
        candidate = Support.deep_copy(object)
        metadata = candidate["metadata"] = Support.deep_copy(Support.metadata(candidate))
        references = Array(Support.value(metadata, "ownerReferences", [])).map { |reference| Support.deep_copy(reference) }
        desired = owner_ref(owner, controller: controller, block_owner_deletion: block_owner_deletion)
        owner_uid = Support.uid(owner).to_s
        references.reject! do |reference|
          (owner_uid != "" && Support.value(reference, "uid", nil).to_s == owner_uid) ||
            (Support.value(reference, "kind", "").to_s == Support.kind(owner) &&
             Support.value(reference, "name", "").to_s == Support.name(owner))
        end
        references << desired
        metadata["ownerReferences"] = references
        candidate
      end

      def ready_condition_status(object)
        condition = Support.condition(object, "Ready")
        return %w[true True].include?(Support.value(Support.status(object), "ready", false).to_s) if condition.nil?

        Support.value(condition, "status", "").to_s == "True"
      end

      def terminal_pod?(pod)
        %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
      end

      def quantity_to_base(value)
        return value.to_f if value.is_a?(Numeric)

        text = value.to_s.strip
        return 0.0 if text.empty?
        return text.to_f if text.match?(/\A-?(?:\d+(?:\.\d+)?|\.\d+)\z/)

        suffixes = {
          "Ki" => 1024.0, "Mi" => 1024.0**2, "Gi" => 1024.0**3, "Ti" => 1024.0**4,
          "Pi" => 1024.0**5, "Ei" => 1024.0**6, "n" => 1e-9, "u" => 1e-6,
          "m" => 1e-3, "k" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12,
          "P" => 1e15, "E" => 1e18
        }
        suffix, multiplier = suffixes.find { |candidate, _| text.end_with?(candidate) }
        return text.to_f unless suffix

        text.delete_suffix(suffix).to_f * multiplier
      end

      def quantity_for(value, unit)
        base = quantity_to_base(value)
        return base if unit.nil? || unit.empty?
        return (base * 1_000).round if unit == "m"
        return (base * 1_024**2).round if unit == "Mi"
        return (base * 1_024**3).round if unit == "Gi"
        base
      end

      def format_quantity(value, template)
        text = template.to_s
        if text.end_with?("m")
          return "#{Integer(value.round)}m"
        elsif text.end_with?("Ki")
          return format_binary_quantity(value, 1024.0, "Ki")
        elsif text.end_with?("Mi")
          return format_binary_quantity(value, 1024.0**2, "Mi")
        elsif text.end_with?("Gi")
          return format_binary_quantity(value, 1024.0**3, "Gi")
        end

        return value.round if template.is_a?(Numeric)
        return value.round.to_s if value.to_f.round == value.to_f

        value.to_f.to_s
      end

      def format_binary_quantity(value, unit, suffix)
        scaled = value.to_f / unit
        return "#{Integer(scaled.round)}#{suffix}" if scaled.round == scaled
        return "#{Integer((value.to_f / (1024.0**2)).round)}Mi" if unit > 1024.0**2 && (value.to_f / (1024.0**2)).round == value.to_f / (1024.0**2)
        return "#{Integer((value.to_f / 1024.0).round)}Ki" if unit > 1024.0 && (value.to_f / 1024.0).round == value.to_f / 1024.0

        "#{scaled.round(6)}#{suffix}"
      end

      def resource_descriptor_for(value)
        ResourceDescriptor.parse(value)
      end

      def canonical_hash(value)
        Support.digest(value)
      end

      def deep_status(object)
        Support.deep_copy(Support.status(object))
      end
    end
  end
end
