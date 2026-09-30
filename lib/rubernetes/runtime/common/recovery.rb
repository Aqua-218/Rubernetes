# frozen_string_literal: true

require "time"

require_relative "errors"

module Rubernetes
  module Runtime
    # Startup reconciliation compares stable identities rather than names.
    # It never promotes an observed resource into ownership and never cleans a
    # mismatched identity.
    class StartupReconciler
      Report = Struct.new(:ledger_only, :kernel_only, :identity_mismatch, :orphans,
                          :released, :cleaned_orphans, :errors, :audit, keyword_init: true) do
        def to_h
          {
            "ledger_only" => ledger_only,
            "kernel_only" => kernel_only,
            "identity_mismatch" => identity_mismatch,
            "orphans" => orphans,
            "released" => released,
            "cleaned_orphans" => cleaned_orphans,
            "errors" => errors,
            "audit" => audit
          }
        end

        alias_method :released_ledger_resources, :released
      end

      Result = Report

      def initialize(ledger:, observer:, cleaner: nil, orphan_predicate: nil, audit: nil)
        @ledger = ledger
        @observer = observer
        @cleaner = cleaner
        @orphan_predicate = orphan_predicate || method(:default_orphan?)
        @audit = audit
      end

      def reconcile
        ledger_resources = @ledger.resources(include_released: false).map do |resource|
          resource.respond_to?(:to_h) ? resource.to_h : resource
        end
        observed_resources = normalize_observed(observe)
        ledger_by_key = ledger_resources.to_h { |resource| [resource_key(resource), resource] }
        observed_by_key = observed_resources.to_h { |resource| [resource_key(resource), resource] }

        ledger_only_keys = ledger_by_key.keys - observed_by_key.keys
        kernel_only_keys = observed_by_key.keys - ledger_by_key.keys
        common_keys = ledger_by_key.keys & observed_by_key.keys
        identity_mismatch_keys = common_keys.select do |key|
          expected = ledger_by_key.fetch(key)
          actual = observed_by_key.fetch(key)
          expected.fetch("identity") != actual.fetch("identity") ||
            (!actual.fetch("owner", "").to_s.empty? && expected.fetch("owner") != actual.fetch("owner"))
        end

        ledger_only = ledger_only_keys.map { |key| ledger_by_key.fetch(key) }
        kernel_only = kernel_only_keys.map { |key| observed_by_key.fetch(key) }
        identity_mismatch = identity_mismatch_keys.map do |key|
          {"resource" => key, "ledger" => ledger_by_key.fetch(key), "observed" => observed_by_key.fetch(key)}
        end
        orphans = kernel_only.select { |resource| @orphan_predicate.call(resource) }
        released = []
        cleaned_orphans = []
        errors = []
        audit = []

        ledger_only.each do |resource|
          audit << audit_entry("ledger_only", resource_key(resource))
          begin
            operation = @ledger.operation(resource.fetch("owner")) || operation_for_resource(resource)
            if operation
              @ledger.release(operation_id: operation.id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                              identity: resource.fetch("identity"), force: true)
            end
            released << resource_key(resource)
          rescue StandardError => error
            errors << error_entry(resource_key(resource), error)
          end
        end

        kernel_only.each { |resource| audit << audit_entry(orphans.include?(resource) ? "orphan" : "kernel_only", resource_key(resource)) }
        identity_mismatch.each { |entry| audit << audit_entry("identity_mismatch", entry.fetch("resource")) }

        orphans.each do |resource|
          next unless @cleaner

          begin
            @cleaner.call(resource)
            cleaned_orphans << resource_key(resource)
          rescue StandardError => error
            errors << error_entry(resource_key(resource), error)
          end
        end

        emit_audit(audit)
        Report.new(ledger_only: freeze_value(ledger_only), kernel_only: freeze_value(kernel_only),
                   identity_mismatch: freeze_value(identity_mismatch), orphans: freeze_value(orphans),
                   released: released.freeze, cleaned_orphans: cleaned_orphans.freeze,
                   errors: errors.freeze, audit: audit.freeze).freeze
      end

      alias recover reconcile

      private

      def observe
        source = @observer
        return source.call if source.respond_to?(:call)
        return source.list_resources if source.respond_to?(:list_resources)
        return source.observe if source.respond_to?(:observe)
        return source.resources if source.respond_to?(:resources)

        raise ArgumentError, "runtime observer must respond to call, list_resources, observe, or resources"
      end

      def normalize_observed(value)
        Array(value).map do |resource|
          hash = resource.respond_to?(:to_h) ? resource.to_h : resource
          {
            "kind" => String(fetch_value(hash, "kind")),
            "id" => String(fetch_value(hash, "id")),
            "identity" => String(fetch_value(hash, "identity", "stable_identity")),
            "owner" => String(fetch_value(hash, "owner", default: "")),
            "metadata" => fetch_value(hash, "metadata", default: {})
          }
        end
      end

      def fetch_value(hash, *keys, default: nil)
        keys.each do |key|
          return hash[key] if hash.respond_to?(:key?) && hash.key?(key)

          symbol = key.to_sym
          return hash[symbol] if hash.respond_to?(:key?) && hash.key?(symbol)
        end
        return default unless default.nil?

        raise KeyError, "missing observed resource field #{keys.join("/")}"
      end

      def resource_key(resource)
        "#{resource.fetch("kind")}:#{resource.fetch("id")}"
      end

      def default_orphan?(resource)
        !resource.fetch("owner", "").to_s.empty?
      end

      def operation_for_resource(resource)
        @ledger.operations.find do |operation|
          operation.resources.include?(resource_key(resource))
        end
      end

      def freeze_value(value)
        value.map do |entry|
          case entry
          when Hash then entry.transform_values { |child| child.is_a?(Hash) ? child.dup.freeze : child }.freeze
          else entry
          end
        end.freeze
      end

      def audit_entry(kind, resource)
        {"kind" => kind, "resource" => resource, "at" => Time.now.utc.iso8601(6)}.freeze
      end

      def error_entry(resource, error)
        {"resource" => resource, "error" => "#{error.class}: #{error.message}"}.freeze
      end

      def emit_audit(entries)
        entries.each { |entry| @audit.call(entry) } if @audit
      end
    end

    Recovery = StartupReconciler
    Reconciler = StartupReconciler
  end
end
