# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Ensures that every active Namespace has its conventional "default"
    # ServiceAccount.  The object is intentionally not owner-referenced to the
    # Namespace: namespace deletion owns lifecycle cleanup for all namespaced
    # resources, matching the upstream controller's API behavior.
    class ServiceAccountController < BaseController
      NAMESPACE = ResourceDescriptor.parse("Namespace")
      SERVICE_ACCOUNT = ResourceDescriptor.parse("ServiceAccount")

      include SecondarySupport

      def plan(resource, store: nil, namespaces: nil, service_accounts: nil, **_options)
        adapter = adapter_for(store)
        namespace = namespace_for(resource, adapter, namespaces)
        return empty_result(resource) unless namespace
        return empty_result(namespace) if terminating?(namespace)

        service_accounts ||= list_for(adapter, SERVICE_ACCOUNT, namespace: Support.name(namespace))
        service_accounts ||= []
        default = Array(service_accounts).find { |account| Support.name(account) == "default" }
        operations = []
        if default.nil?
          candidate = {
            "apiVersion" => "v1", "kind" => "ServiceAccount",
            "metadata" => {"name" => "default", "namespace" => Support.name(namespace)}
          }
          operations << operation_create(candidate, descriptor: SERVICE_ACCOUNT,
                                          reason: "default service account creation")
          default = candidate
        end
        status = {"secrets" => Array(Support.value(default, "secrets", [])).map { |reference| Support.deep_copy(reference) }}
        events = operations.empty? ? [] : [{"type" => "Normal", "reason" => "ServiceAccountCreated",
                                             "message" => "default ServiceAccount created in #{Support.name(namespace)}"}]
        ReconcileResult.new(operations: operations, status: status, events: events,
                            controller: name, key: object_key_for(namespace))
      end

      # Upstream's serviceaccounts controller enqueues the namespace when the
      # default ServiceAccount is deleted, so it comes straight back.  A key
      # that names a deleted object reconciles nothing without this hook.
      def plan_orphans(key, store: nil)
        namespace, _, name = key.to_s.partition("/")
        return nil if namespace.empty?
        return nil unless name.empty? || name == "default"

        adapter = adapter_for(store)
        return nil if adapter.nil?
        # Only a namespace that still exists gets its ServiceAccount back; the
        # same key names a namespace that was just torn down.
        known = list_for(adapter, NAMESPACE, namespace: :all).find { |value| Support.name(value) == namespace }
        return nil if known.nil? || terminating?(known)

        plan({"apiVersion" => "v1", "kind" => "ServiceAccount",
              "metadata" => {"name" => "default", "namespace" => namespace}}, store: store)
      end

      private

      def namespace_for(resource, adapter, namespaces)
        return resource if Support.kind(resource) == "Namespace"

        namespace_name = Support.namespace(resource)
        return nil if namespace_name.to_s.empty?

        known = namespaces || (adapter ? list_for(adapter, NAMESPACE, namespace: :all) : nil)
        found = Array(known).find { |namespace| Support.name(namespace) == namespace_name }
        return found if found
        # A namespace the cache does not hold is gone.  Synthesising one anyway
        # plans a ServiceAccount the API answers 404 for, and the key is then
        # retried for ever -- which is what starved the reconcile loop of the
        # namespaces that DO exist and left them without a default
        # ServiceAccount for minutes.
        return nil unless known.nil?

        {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace_name}}
      end

      def terminating?(namespace)
        !Support.value(Support.metadata(namespace), "deletionTimestamp", nil).nil?
      end

      def empty_result(resource)
        ReconcileResult.new(operations: [], status: Support.deep_copy(Support.status(resource)),
                            controller: name, key: resource && object_key_for(resource))
      end
    end
  end
end
