# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"
require_relative "effect_journal"
require_relative "../api/status"
require_relative "../api/patch"

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

      def self.wrap(store)
        store.is_a?(StoreAdapter) ? store : new(store)
      end

      def initialize(store, effect_journal: nil, component: nil, identity: nil)
        raise ArgumentError, "store is required" unless store

        @store = store
        @effect_journal = effect_journal || EffectJournal.from_env(component: component, identity: identity)
      end

      def selector_candidates(descriptor, object)
        list(descriptor, namespace: Support.namespace(object) || :all)
      end

      def list(descriptor_or_kind, namespace: :all, selector: nil, fresh: false)
        descriptor = descriptor(descriptor_or_kind)
        matches = Support.selector_predicate(selector) if selector
        items = list_all.select do |object|
          matches_descriptor?(object, descriptor) &&
            (namespace == :all || namespace.nil? || descriptor.cluster_scoped? || Support.namespace(object).to_s == namespace.to_s) &&
            (!matches || matches.call(object))
        end
        items.sort_by! { |object| [Support.namespace(object).to_s, Support.name(object)] }
        items.map! { |object| Support.deep_copy(object) }
      end

      alias list_objects list

      def custom_resource_collections = {}
      def custom_resource_descriptors = []

      def all(selector: nil)
        list_all(selector: selector).map { |item| Support.deep_copy(item) }
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
            raise unless error.class.name.to_s.end_with?("NotFound", "Gone")
          end
        end
        list(descriptor, namespace: namespace || :all).find do |object|
          Support.name(object) == name.to_s && (namespace.nil? || Support.namespace(object).to_s == namespace.to_s)
        end
      end

      # Same key layout as key_for, addressed by name rather than by object.
      def key_for_name(descriptor, name:, namespace:)
        scope = if descriptor.cluster_scoped?
                  "_cluster"
                else
                  (namespace.nil? || namespace == :all ? nil : namespace.to_s)
                end
        raise ArgumentError, "namespaced lookup requires a namespace" if scope.nil?

        "registry/#{descriptor.api_version}/#{descriptor.resource}/#{scope}/#{name}"
      end

      alias get find

      def fetch_scale(descriptor, name:, namespace:)
        find(descriptor, name: name, namespace: namespace)
      end

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
      end

      # effect_action distinguishes a status-subresource write from a spec
      # update in the effect journal: upstream issues them as two different
      # API calls (PUT resource, PUT resource/status), so they are two
      # different semantic effects even when they touch the same object.
      def update(object, descriptor: nil, existing: nil, fence: nil, effect_action: :update, subresource: nil)
        descriptor ||= self.class.descriptor(object)
        ensure_descriptor_matches!(object, descriptor)
        current = existing || find(descriptor, name: Support.name(object), namespace: Support.namespace(object))
        ensure_uid_matches!(current, object)
        return current if current && current == object

        key = key_for(descriptor, object)
        payload = Support.deep_copy(object)
        result = if @store.respond_to?(:update)
                   version = Support.value(Support.metadata(current), "resourceVersion")
                   options = version_options(:update, 2, version)
                   fence&.call
                   @store.update(key, payload, **options)
                 elsif @store.respond_to?(:replace)
                   fence&.call
                   @store.replace(key, payload)
                 else
                   raise StoreError, "store does not implement update or replace"
                 end
        record_effect!(descriptor: descriptor, object: object, action: effect_action, response: result)
        result
      end

      def delete(object_or_descriptor, name: nil, namespace: nil, descriptor: nil, fence: nil)
        requested = object_or_descriptor if object_or_descriptor.is_a?(Hash)
        descriptor ||= self.class.descriptor(object_or_descriptor)
        if requested
          ensure_descriptor_matches!(requested, descriptor)
          name = Support.name(requested)
          namespace = Support.namespace(requested)
        end
        existing = find(descriptor, name: name, namespace: namespace)
        return nil unless existing

        ensure_uid_matches!(existing, requested) if requested
        key = key_for(descriptor, existing)
        expected = Support.value(Support.metadata(existing), "resourceVersion")
        options = version_options(:delete, 1, expected)
        fence&.call
        result = @store.delete(key, **options)
        if options.key?(:resource_version)
          record_effect!(descriptor: descriptor, object: requested || existing, action: :delete, response: result)
        else
          record_effect!(descriptor: nil, object: nil, action: :delete, response: result, reconcile_key: key)
        end
        result
      end

      def apply(operation, fence: nil)
        notify = operation.method(:notify) if operation.respond_to?(:notify)
        result = apply_operation(operation, fence: fence)
        notify&.call(true)
        result
      rescue StandardError => error
        notify&.call(false, error)
        # Every upstream controller that creates objects ignores a create the
        # API server refused because the namespace is being deleted
        # (apierrors.HasStatusCause(err, v1.NamespaceTerminatingCause)): all
        # later creates there fail too, and the rest of the sync -- a Job
        # removing its Pods' tracking finalizers -- must still happen.
        # Raising here aborted the batch before those writes, the Pod kept
        # its finalizer, and the namespace stayed Terminating for ever.
        raise unless operation.action == :create && self.class.namespace_terminating?(error)

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
        when :strategic_patch
          apply_strategic_patch(operation, fence: fence)
        when :json_patch
          apply_json_patch(operation, fence: fence)
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
        Array(items)
      rescue StandardError => error
        raise unless error.class.name.to_s.end_with?("NotFound", "Gone")

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

      # Both in-tree stores accept resource_version. Older adapters name the
      # precondition prec or only take positional arguments. Choose before
      # calling the fence so a write that raised afterwards is never replayed.
      def version_options(action, argument_count, version)
        parameters = @store.method(action).parameters
        keywords = parameters.filter_map { |type, name| name if %i[key keyreq].include?(type) }
        return {resource_version: version} if keywords.include?(:resource_version)
        return {prec: version} if keywords.include?(:prec)
        return {} if parameters.assoc(:nokey)

        takes_options = parameters.any? { |type, _| %i[keyrest rest].include?(type) } ||
                        parameters.count { |type, _| %i[opt req].include?(type) } > argument_count
        takes_options ? {resource_version: version} : {}
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

        options = {descriptor: operation.resource, existing: existing, fence: fence}
        options[:subresource] = operation.subresource if operation.respond_to?(:subresource) && operation.subresource
        update(operation.object, **options)
      end

      def apply_patch(operation, fence: nil)
        existing = find(operation.resource, name: Support.name(operation.object || {}),
                                            namespace: Support.namespace(operation.object || {}))
        raise StoreError, "patch target not found" unless existing

        candidate = Support.merge_hash(existing, operation.patch || {})
        update(candidate, descriptor: operation.resource, existing: existing, fence: fence)
      end

      def apply_strategic_patch(operation, fence: nil)
        object = operation.object
        existing = find(operation.resource, name: Support.name(object), namespace: Support.namespace(object))
        return nil unless existing

        ensure_uid_matches!(existing, object)
        candidate = API::Patch.apply(existing, operation.patch, type: :strategic, resource: operation.resource)
        return existing if candidate == existing

        update(candidate, descriptor: operation.resource, existing: existing, fence: fence, effect_action: :patch)
      end

      def apply_json_patch(operation, fence: nil)
        object = operation.object
        existing = find(operation.resource, name: Support.name(object), namespace: Support.namespace(object))
        return nil unless existing

        candidate = API::Patch.apply(existing, operation.patch, type: :json, resource: operation.resource)
        return existing if candidate == existing

        update(candidate, descriptor: operation.resource, existing: existing, fence: fence, effect_action: :patch)
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
    end
  end
end
