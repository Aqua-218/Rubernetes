# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "effect_journal"

module Rubernetes
  module Controller
    # Adapter around both MemoryStore implementations and small test doubles.
    # Controllers only use this contract, which keeps control-loop policy out
    # of storage and makes the same planner usable without a live API server.
    class StoreAdapter
      PLURAL_OVERRIDES = {
        "Endpoints" => "endpoints", "EndpointSlice" => "endpointslices",
        "ReplicaSet" => "replicasets", "StatefulSet" => "statefulsets",
        "DaemonSet" => "daemonsets", "ControllerRevision" => "controllerrevisions",
        "PersistentVolumeClaim" => "persistentvolumeclaims", "PersistentVolume" => "persistentvolumes",
        "ServiceAccount" => "serviceaccounts", "ResourceQuota" => "resourcequotas",
        "PodDisruptionBudget" => "poddisruptionbudgets", "HorizontalPodAutoscaler" => "horizontalpodautoscalers",
        "CertificateSigningRequest" => "certificatesigningrequests", "VolumeAttributesClass" => "volumeattributesclasses"
      }.freeze

      attr_reader :store, :effect_journal

      def initialize(store, effect_journal: nil, component: nil, identity: nil)
        raise ArgumentError, "store is required" unless store

        @store = store
        @effect_journal = effect_journal || EffectJournal.from_env(component: component, identity: identity)
      end

      def list(descriptor_or_kind, namespace: :all, selector: nil, fresh: false)
        descriptor = descriptor(descriptor_or_kind)
        candidates = list_all(selector: nil)
        candidates.select! { |object| matches_descriptor?(object, descriptor) }
        unless namespace == :all || namespace.nil?
          candidates.select! do |object|
            if descriptor.cluster_scoped?
              true
            else
              Support.namespace(object).to_s == namespace.to_s
            end
          end
        end
        candidates.select! { |object| Support.selector_matches?(selector, object) } if selector
        candidates.sort_by { |object| [Support.namespace(object).to_s, Support.name(object)] }
      end

      alias list_objects list

      def all(selector: nil)
        list_all(selector: selector)
      end

      # Every object that lives inside `namespace`.  The in-process store
      # holds one flat corpus, so this is #all filtered; the API-backed
      # adapter overrides it with per-resource scoped lists.  See
      # NamespaceController for why the distinction matters.
      def namespaced_contents(namespace, selector: nil)
        name = namespace.to_s
        all(selector: selector).select do |object|
          Support.kind(object) != "Namespace" && Support.namespace(object).to_s == name
        end
      end

      # Prefer the store's own point lookup when it has one: a scan of every
      # object in the store for a single name is what makes a controller
      # manager spend its time listing instead of reconciling.
      def find(descriptor_or_kind, name:, namespace: nil)
        descriptor = descriptor(descriptor_or_kind)
        if @store.respond_to?(:get) && !@store.equal?(self)
          begin
            found = @store.get(key_for_name(descriptor, name: name, namespace: namespace))
            return Support.deep_copy(found) if found.is_a?(Hash) && !found.empty?
          rescue ArgumentError, NotImplementedError
            nil
          rescue StandardError => error
            raise unless error.class.name.to_s.end_with?("NotFound") || error.class.name.to_s.end_with?("Gone")
          end
        end
        list(descriptor, namespace: namespace || :all).find do |object|
          Support.name(object) == name.to_s && (namespace.nil? || Support.namespace(object).to_s == namespace.to_s)
        end
      end

      # Same key layout as key_for, addressed by name rather than by object.
      def key_for_name(descriptor, name:, namespace:)
        scope = descriptor.cluster_scoped? ? "_cluster" : (namespace.nil? || namespace == :all ? nil : namespace.to_s)
        raise ArgumentError, "namespaced lookup requires a namespace" if scope.nil?

        "registry/#{descriptor.api_version}/#{descriptor.resource}/#{scope}/#{name}"
      end

      alias get find

      def exists?(descriptor_or_kind, name:, namespace: nil)
        !find(descriptor_or_kind, name: name, namespace: namespace).nil?
      end

      def create(object, descriptor: nil, fence: nil)
        descriptor ||= self.class.descriptor(object)
        ensure_descriptor_matches!(object, descriptor)
        fence&.call
        result = @store.create(key_for(descriptor, object), Support.deep_copy(object))
        record_effect!(descriptor: descriptor, object: object, action: :create, response: result)
        result
      rescue ArgumentError => error
        return call_create_fallback(object, descriptor, error, fence: fence) if error.message.include?("wrong number") || error.message.include?("keyword")

        raise
      end

      # effect_action distinguishes a status-subresource write from a spec
      # update in the effect journal: upstream issues them as two different
      # API calls (PUT resource, PUT resource/status), so they are two
      # different semantic effects even when they touch the same object.
      def update(object, descriptor: nil, existing: nil, fence: nil, effect_action: :update)
        descriptor ||= self.class.descriptor(object)
        ensure_descriptor_matches!(object, descriptor)
        current = existing || find(descriptor, name: Support.name(object), namespace: Support.namespace(object))
        ensure_uid_matches!(current, object)
        return current if current && current == object
        key = key_for(descriptor, object)
        if @store.respond_to?(:update)
          fence&.call
          result = @store.update(key, Support.deep_copy(object), resource_version: Support.value(Support.metadata(current || {}), "resourceVersion", nil))
          record_effect!(descriptor: descriptor, object: object, action: effect_action, response: result)
          result
        elsif @store.respond_to?(:replace)
          fence&.call
          result = @store.replace(key, Support.deep_copy(object))
          record_effect!(descriptor: descriptor, object: object, action: effect_action, response: result)
          result
        else
          raise StoreError, "store does not implement update or replace"
        end
      rescue ArgumentError => error
        return call_update_fallback(object, descriptor, current, error, fence: fence, effect_action: effect_action) if error.message.include?("wrong number") || error.message.include?("keyword") || error.message.include?("unknown update")

        raise
      end

      def delete(object_or_descriptor, name: nil, namespace: nil, descriptor: nil, fence: nil)
        if object_or_descriptor.is_a?(Hash)
          object = object_or_descriptor
          descriptor ||= self.class.descriptor(object)
          ensure_descriptor_matches!(object, descriptor)
          key = key_for(descriptor, object)
          existing = find(descriptor, name: Support.name(object), namespace: Support.namespace(object))
          return nil unless existing
          ensure_uid_matches!(existing, object)
          key = key_for(descriptor, existing)
          expected = Support.value(Support.metadata(existing), "resourceVersion", nil)
        else
          descriptor ||= self.class.descriptor(object_or_descriptor)
          object = find(descriptor, name: name, namespace: namespace)
          return nil unless object
          key = key_for(descriptor, object)
          expected = Support.value(Support.metadata(object), "resourceVersion", nil)
        end
        fence&.call
        result = @store.delete(key, resource_version: expected)
        record_effect!(descriptor: descriptor, object: object, action: :delete, response: result)
        result
      rescue ArgumentError => error
        return call_delete_fallback(key, expected, error, fence: fence) if error.message.include?("wrong number") || error.message.include?("keyword") || error.message.include?("unknown delete")

        raise
      end

      def apply(operation, fence: nil)
        result = apply_operation(operation, fence: fence)
        operation.notify(true) if operation.respond_to?(:notify)
        result
      rescue StandardError => error
        operation.notify(false, error) if operation.respond_to?(:notify)
        # Every upstream controller that creates objects ignores a create the
        # API server refused because the namespace is being deleted
        # (apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause)): all
        # later creates there fail too, and the rest of the sync -- a Job
        # removing its Pods' tracking finalizers -- must still happen.
        # Raising here aborted the batch before those writes, the Pod kept
        # its finalizer, and the namespace stayed Terminating for ever.
        raise unless operation.create? && self.class.namespace_terminating?(error)

        nil
      end

      NAMESPACE_TERMINATING_CAUSE = "NamespaceTerminating"

      def self.namespace_terminating?(error)
        status = error.respond_to?(:status_object) ? error.status_object : nil
        status ||= error.details if error.respond_to?(:details) && error.details.is_a?(Hash)
        causes = status.is_a?(Hash) ? Array(Support.value(Support.value(status, "details", status), "causes", [])) : []
        return true if causes.any? { |cause| Support.value(cause, "reason", "").to_s == NAMESPACE_TERMINATING_CAUSE }

        error.message.to_s.include?("because it is being terminated")
      end

      def apply_operation(operation, fence: nil)
        case operation.action
        when :create
          apply_create(operation, fence: fence)
        when :update
          apply_update(operation, fence: fence)
        when :patch
          apply_patch(operation, fence: fence)
        when :status_update
          apply_status(operation, fence: fence)
        when :status_merge
          apply_status_merge(operation, fence: fence)
        when :delete
          apply_delete(operation, fence: fence)
        else
          raise StoreError, "unsupported controller operation #{operation.action.inspect}"
        end
      end

      # Apply one deterministic batch while retaining a fence immediately
      # before each storage mutation.  Stores may override this boundary with
      # a native bulk primitive without changing controller planning.
      def apply_batch(operations, fence: nil)
        Array(operations).map { |operation| apply(operation, fence: fence) }
      end

      def self.descriptor(value)
        value.is_a?(ResourceDescriptor) ? value : ResourceDescriptor.parse(value)
      end

      private

      def descriptor(value)
        self.class.descriptor(value)
      end

      def list_all(selector: nil)
        raw = if @store.respond_to?(:list)
                begin
                  @store.list("", selector: selector)
                rescue ArgumentError
                  @store.list("")
                end
              else
                raise StoreError, "store does not implement list"
              end
        items = if raw.respond_to?(:items)
                  raw.items
                elsif raw.respond_to?(:to_ary) && raw.to_ary.is_a?(Array) && raw.to_ary.first.is_a?(Array)
                  raw.to_ary.first
                elsif raw.is_a?(Hash)
                  raw["items"] || raw[:items] || []
                else
                  raw
                end
        Array(items).map { |item| Support.deep_copy(item) }
      rescue StandardError => error
        raise unless error.class.name.to_s.end_with?("NotFound") || error.class.name.to_s.end_with?("Gone")

        []
      end

      def matches_descriptor?(object, descriptor)
        kind = Support.kind(object)
        return false unless kind == descriptor.kind
        raw_api = Support.api_version(object)
        return true if raw_api.nil? || raw_api.to_s.empty?

        raw_api.to_s == descriptor.api_version
      end

      def key_for(descriptor, object)
        namespace = descriptor.cluster_scoped? ? "_cluster" : (Support.namespace(object) || "default")
        "registry/#{descriptor.api_version}/#{descriptor.resource}/#{namespace}/#{Support.name(object)}"
      end

      def call_create_fallback(object, descriptor, original_error, fence: nil)
        if @store.method(:create).arity.abs >= 2
          fence&.call
          result = @store.create(key_for(descriptor, object), Support.deep_copy(object))
          record_effect!(descriptor: descriptor, object: object, action: :create, response: result)
          result
        else
          raise original_error
        end
      end

      def call_update_fallback(object, descriptor, current, original_error, fence: nil, effect_action: :update)
        expected = Support.value(Support.metadata(current || {}), "resourceVersion", nil)
        begin
          fence&.call
          result = @store.update(key_for(descriptor, object), Support.deep_copy(object), prec: expected)
          record_effect!(descriptor: descriptor, object: object, action: effect_action, response: result)
          result
        rescue ArgumentError
          begin
            fence&.call
            result = @store.update(key_for(descriptor, object), Support.deep_copy(object))
            record_effect!(descriptor: descriptor, object: object, action: effect_action, response: result)
            result
          rescue StandardError
            raise original_error
          end
        end
      end

      def call_delete_fallback(key, expected, original_error, fence: nil)
        begin
          fence&.call
          result = @store.delete(key, prec: expected)
          record_effect!(descriptor: descriptor_for_key(key), object: nil, action: :delete, response: result,
                         reconcile_key: key)
          result
        rescue ArgumentError
          begin
            fence&.call
            result = @store.delete(key)
            record_effect!(descriptor: nil, object: nil, action: :delete, response: result, reconcile_key: key)
            result
          rescue StandardError
            raise original_error
          end
        end
      end

      def apply_create(operation, fence: nil)
        existing = find(operation.resource, name: Support.name(operation.object), namespace: Support.namespace(operation.object))
        return existing if existing && existing == operation.object
        return create(operation.object, descriptor: operation.resource, fence: fence) unless existing

        raise StoreError, "create conflict for #{operation.resource.identifier}/#{Support.name(operation.object)}"
      end

      def apply_update(operation, fence: nil)
        existing = find(operation.resource, name: Support.name(operation.object), namespace: Support.namespace(operation.object))
        ensure_uid_matches!(existing, operation.object)
        return existing if existing && existing == operation.object
        update(operation.object, descriptor: operation.resource, existing: existing, fence: fence)
      end

      def apply_patch(operation, fence: nil)
        existing = find(operation.resource, name: Support.name(operation.object || {}), namespace: Support.namespace(operation.object || {}))
        raise StoreError, "patch target not found" unless existing
        candidate = Support.merge_hash(existing, operation.patch || {})
        update(candidate, descriptor: operation.resource, existing: existing, fence: fence)
      end

      def apply_status(operation, fence: nil)
        existing = find(operation.resource, name: Support.name(operation.object), namespace: Support.namespace(operation.object))
        return nil unless existing
        candidate = Support.deep_copy(existing)
        candidate["status"] = Support.deep_copy(operation.patch || operation.object["status"] || {})
        update(candidate, descriptor: operation.resource, existing: existing, fence: fence, effect_action: :status_update)
      end

      def apply_status_merge(operation, fence: nil)
        existing = find(operation.resource, name: Support.name(operation.object), namespace: Support.namespace(operation.object))
        return nil unless existing

        status = Support.deep_copy(Support.status(existing))
        (operation.patch || {}).each { |key, value| value.nil? ? status.delete(key.to_s) : status[key.to_s] = Support.deep_copy(value) }
        return existing if status == Support.status(existing)

        candidate = Support.deep_copy(existing)
        candidate["status"] = status
        update(candidate, descriptor: operation.resource, existing: existing, fence: fence, effect_action: :status_update)
      end

      def apply_delete(operation, fence: nil)
        object = find(operation.resource, name: Support.name(operation.object || {}), namespace: Support.namespace(operation.object || {}))
        return nil unless object
        ensure_uid_matches!(object, operation.object)
        if operation.patch && method(:delete).parameters.any? { |_, name| name == :options }
          return delete(object, descriptor: operation.resource, fence: fence, options: operation.patch)
        end

        delete(object, descriptor: operation.resource, fence: fence)
      end

      def ensure_uid_matches!(current, candidate)
        return unless current && candidate

        current_uid = Support.uid(current)
        candidate_uid = Support.uid(candidate)
        return if current_uid.nil? || current_uid.empty? || candidate_uid.nil? || candidate_uid.empty?
        return if current_uid == candidate_uid

        raise StoreError, "resource UID precondition failed for #{Support.kind(candidate)}/#{Support.name(candidate)}"
      end

      def ensure_descriptor_matches!(object, descriptor)
        return if matches_descriptor?(object, descriptor)

        raise StoreError, "resource #{Support.kind(object)}/#{Support.name(object)} does not match #{descriptor.identifier}"
      end

      def record_effect!(descriptor:, object:, action:, response:, reconcile_key: nil)
        return unless @effect_journal

        key = reconcile_key || begin
          namespace = descriptor&.cluster_scoped? ? "_cluster" : (Support.namespace(object) || "default")
          [descriptor&.api_version, descriptor&.resource, namespace, Support.name(object)].compact.join("/")
        end
        @effect_journal.record(effect_type: action.to_s, reconcile_key: key, action: action,
                               object: object, response: response)
      end

      def descriptor_for_key(_key)
        nil
      end
    end
  end
end
