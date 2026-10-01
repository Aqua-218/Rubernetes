# frozen_string_literal: true

require_relative "errors"
require_relative "support"

module Rubernetes
  module Controller
    # Resource identity used by the DSL.  It deliberately contains both GVK
    # and REST information so scope and watch paths are validated once, before
    # a controller starts.
    class ResourceDescriptor
      attr_reader :group, :version, :kind, :resource, :scope

      KNOWN = {
        "Pod" => ["", "v1", "pods", :namespaced],
        "Service" => ["", "v1", "services", :namespaced],
        "Endpoints" => ["", "v1", "endpoints", :namespaced],
        "EndpointSlice" => ["discovery.k8s.io", "v1", "endpointslices", :namespaced],
        "Node" => ["", "v1", "nodes", :cluster],
        "Namespace" => ["", "v1", "namespaces", :cluster],
        "Lease" => ["coordination.k8s.io", "v1", "leases", :namespaced],
        "ConfigMap" => ["", "v1", "configmaps", :namespaced],
        "Secret" => ["", "v1", "secrets", :namespaced],
        "PersistentVolume" => ["", "v1", "persistentvolumes", :cluster],
        "PersistentVolumeClaim" => ["", "v1", "persistentvolumeclaims", :namespaced],
        "StorageClass" => ["storage.k8s.io", "v1", "storageclasses", :cluster],
        "Deployment" => ["apps", "v1", "deployments", :namespaced],
        "ReplicaSet" => ["apps", "v1", "replicasets", :namespaced],
        "StatefulSet" => ["apps", "v1", "statefulsets", :namespaced],
        "DaemonSet" => ["apps", "v1", "daemonsets", :namespaced],
        "ControllerRevision" => ["apps", "v1", "controllerrevisions", :namespaced],
        "Job" => ["batch", "v1", "jobs", :namespaced],
        "CronJob" => ["batch", "v1", "cronjobs", :namespaced],
        "ReplicationController" => ["", "v1", "replicationcontrollers", :namespaced],
        "ResourceQuota" => ["", "v1", "resourcequotas", :namespaced],
        "ServiceAccount" => ["", "v1", "serviceaccounts", :namespaced],
        "PodDisruptionBudget" => ["policy", "v1", "poddisruptionbudgets", :namespaced],
        "HorizontalPodAutoscaler" => ["autoscaling", "v2", "horizontalpodautoscalers", :namespaced],
        "CertificateSigningRequest" => ["certificates.k8s.io", "v1", "certificatesigningrequests", :cluster],
        "PodCertificateRequest" => ["certificates.k8s.io", "v1beta1", "podcertificaterequests", :namespaced],
        "ClusterTrustBundle" => ["certificates.k8s.io", "v1beta1", "clustertrustbundles", :cluster],
        "ClusterRole" => ["rbac.authorization.k8s.io", "v1", "clusterroles", :cluster],
        "ClusterRoleBinding" => ["rbac.authorization.k8s.io", "v1", "clusterrolebindings", :cluster],
        "Role" => ["rbac.authorization.k8s.io", "v1", "roles", :namespaced],
        "RoleBinding" => ["rbac.authorization.k8s.io", "v1", "rolebindings", :namespaced],
        "VolumeAttributesClass" => ["storage.k8s.io", "v1", "volumeattributesclasses", :cluster],
        "VolumeAttachment" => ["storage.k8s.io", "v1", "volumeattachments", :cluster],
        "CSINode" => ["storage.k8s.io", "v1", "csinodes", :cluster],
        "CSIDriver" => ["storage.k8s.io", "v1", "csidrivers", :cluster],
        "CSIStorageCapacity" => ["storage.k8s.io", "v1", "csistoragecapacities", :namespaced],
        "ResourceClaim" => ["resource.k8s.io", "v1", "resourceclaims", :namespaced],
        "ResourceSlice" => ["resource.k8s.io", "v1", "resourceslices", :cluster],
        "ResourceClaimTemplate" => ["resource.k8s.io", "v1", "resourceclaimtemplates", :namespaced],
        "DeviceClass" => ["resource.k8s.io", "v1", "deviceclasses", :cluster],
        "DeviceTaintRule" => ["resource.k8s.io", "v1beta2", "devicetaintrules", :cluster],
        "ResourcePoolStatusRequest" => ["resource.k8s.io", "v1alpha3", "resourcepoolstatusrequests", :cluster],
        "PodGroup" => ["scheduling.k8s.io", "v1alpha2", "podgroups", :namespaced],
        "IPAddress" => ["networking.k8s.io", "v1", "ipaddresses", :cluster],
        "ServiceCIDR" => ["networking.k8s.io", "v1", "servicecidrs", :cluster],
        "ValidatingAdmissionPolicy" => ["admissionregistration.k8s.io", "v1", "validatingadmissionpolicies", :cluster],
        "ValidatingAdmissionPolicyBinding" => ["admissionregistration.k8s.io", "v1", "validatingadmissionpolicybindings", :cluster],
        "StorageVersionMigration" => ["storagemigration.k8s.io", "v1beta1", "storageversionmigrations", :cluster],
        "StorageVersion" => ["internal.apiserver.k8s.io", "v1alpha1", "storageversions", :cluster]
      }.freeze

      def self.parse(value, scope: nil, group: nil, version: nil, kind: nil, resource: nil)
        if value.is_a?(self)
          return value if scope.nil? && group.nil? && version.nil? && kind.nil? && resource.nil?

          return new(group: group || value.group, version: version || value.version,
                     kind: kind || value.kind, resource: resource || value.resource,
                     scope: scope || value.scope)
        end

        if value.is_a?(Hash)
          raw_api_version = Support.value(value, "apiVersion", nil) || Support.value(value, "api_version", nil)
          raw_kind = Support.value(value, "kind", nil) || kind
          raw_group, raw_version = split_api_version(raw_api_version)
          return new(group: group || raw_group, version: version || raw_version,
                     kind: raw_kind, resource: resource, scope: scope,
                     allow_unknown: true)
        end

        text = value.respond_to?(:name) && !value.is_a?(String) ? value.name.to_s : value.to_s
        text = text.split("::").last if text.include?("::")
        if text.include?(", Kind=")
          api, parsed_kind = text.split(", Kind=", 2)
          parsed_group, parsed_version = split_api_version(api)
          return new(group: group || parsed_group, version: version || parsed_version,
                     kind: kind || parsed_kind, resource: resource, scope: scope,
                     allow_unknown: true)
        end

        parts = text.split("/")
        if parts.length >= 3
          parsed_kind = parts[-1]
          parsed_version = parts[-2]
          parsed_group = parts[0...-2].join("/")
          return new(group: group || parsed_group, version: version || parsed_version,
                     kind: kind || parsed_kind, resource: resource, scope: scope,
                     allow_unknown: true)
        end

        known = KNOWN[text]
        new(group: group || known&.[](0), version: version || known&.[](1),
            kind: kind || text, resource: resource || known&.[](2),
            scope: scope || known&.[](3), allow_unknown: true)
      end

      def self.split_api_version(api_version)
        text = api_version.to_s
        return ["", "v1"] if text.empty?
        return ["", text] unless text.include?("/")

        text.split("/", 2)
      end

      def initialize(kind:, group: nil, version: nil, resource: nil, scope: nil, allow_unknown: false)
        kind = kind.to_s
        raise UnknownGVKError, "resource kind must not be empty" if kind.empty?

        known = KNOWN[kind]
        # The legacy core group is the empty string on the wire: "core" is a
        # display alias only.  Normalising it here keeps every consumer -- REST
        # paths above all -- from building "/apis/core/v1/...", which 404s.
        @group = self.class.normalize_group(group.nil? ? (known&.[](0) || "") : group)
        @version = (version.nil? ? (known&.[](1) || "v1") : version).to_s
        @resource = (resource || known&.[](2) || self.class.pluralize(kind)).to_s
        @scope = normalize_scope(scope || known&.[](3) || :namespaced)
        @kind = kind
        raise UnknownGVKError, "unknown GVK #{identifier}" if !allow_unknown && known.nil?
        raise UnknownGVKError, "resource version must not be empty" if @version.empty?

        freeze
      end

      CORE_GROUP_ALIASES = ["core", "core/"].freeze

      def self.normalize_group(value)
        text = value.to_s
        CORE_GROUP_ALIASES.include?(text.downcase) ? "" : text
      end

      def self.pluralize(kind)
        word = kind.gsub(/([a-z\d])([A-Z])/, '\\1-\\2').downcase
        return "#{word[0...-1]}ies" if word.end_with?("y")
        return "#{word}es" if word.end_with?("s", "x", "z", "ch", "sh")

        "#{word}s"
      end

      def api_version
        group.empty? ? version : "#{group}/#{version}"
      end

      alias group_version api_version

      def gvk
        [group, version, kind].freeze
      end

      def gvr
        [group, version, resource].freeze
      end

      def namespaced?
        scope == :namespaced
      end

      def cluster_scoped?
        !namespaced?
      end

      def identifier
        "#{group.empty? ? "core" : group}/#{version}/#{kind}"
      end

      def to_s
        identifier
      end

      def ==(other)
        other.respond_to?(:gvk) && other.gvk == gvk
      end
      alias eql? ==

      def hash
        gvk.hash
      end

      def to_h
        {"group" => group, "version" => version, "kind" => kind,
         "resource" => resource, "scope" => scope.to_s, "apiVersion" => api_version}
      end

      private

      def normalize_scope(value)
        normalized = value.to_s.downcase.tr("-", "_")
        return :namespaced if %w[namespaced namespace].include?(normalized)
        return :cluster if %w[cluster clusterscoped cluster_scoped].include?(normalized)

        raise ScopeMismatchError, "resource scope must be :namespaced or :cluster"
      end
    end

    # `route` decides what a foreign-kind event addresses.  :fan_out (the
    # default) reconciles the controller's own existing resources -- right for
    # a watch that merely invalidates them, and wrong for a controller whose
    # job is to *create* its first own-kind object in response to the foreign
    # one, because there is nothing to fan out to yet.  :self routes the
    # observed object itself through the watch's declared queue key.
    ROUTES = %i[fan_out self namespace].freeze
    WatchSpec = Struct.new(:resource, :via, :predicate, :index_name, :queue_key, :scope, :route,
                           :selector_source, keyword_init: true) do
      # `selector_source` names the kind that carries the label selector for a
      # `:label` watch when the controller's own kind does not.  An Endpoints
      # or EndpointSlice has no selector of its own -- the Service it is named
      # after owns it -- so without this a Pod becoming ready reached no key
      # and the Service kept the empty Endpoints it was created with.
      def initialize(resource:, via: :owner_reference, predicate: nil, index_name: nil, queue_key: nil,
                     scope: nil, route: :fan_out, selector_source: nil)
        normalized_route = route.to_sym
        raise ArgumentError, "watch route must be one of #{ROUTES.join(", ")}" unless ROUTES.include?(normalized_route)

        super(resource: resource, via: via.to_sym, predicate: predicate,
              index_name: index_name&.to_s, queue_key: queue_key, scope: scope&.to_sym,
              route: normalized_route, selector_source: selector_source)
        freeze
      end

      def to_h
        {resource: resource.to_h, via: via, index_name: index_name, scope: scope,
         predicate: predicate, queue_key: queue_key, route: route,
         selector_source: selector_source&.to_h}.freeze
      end
    end

    OwnershipEdge = Struct.new(:owner, :dependent, :controller, :block_owner_deletion, keyword_init: true) do
      def initialize(owner:, dependent:, controller: true, block_owner_deletion: true)
        super(owner: owner, dependent: dependent, controller: !!controller,
              block_owner_deletion: !!block_owner_deletion)
        freeze
      end

      def to_h
        {owner: owner.to_h, dependent: dependent.to_h, controller: controller,
         block_owner_deletion: block_owner_deletion}.freeze
      end
    end

    class Operation
      attr_reader :action, :resource, :key, :object, :patch, :owner, :reason, :observer

      # +observer+: ->(succeeded, error) once the operation was applied (a
      # controller's own metrics of what its writes did).
      def initialize(action:, resource:, key: nil, object: nil, patch: nil, owner: nil, reason: nil, observer: nil)
        @action = action.to_sym
        @resource = resource
        @key = key&.to_s
        @object = object.nil? ? nil : Support.immutable_copy(object)
        @patch = patch.nil? ? nil : Support.immutable_copy(patch)
        @owner = owner.nil? ? nil : Support.immutable_copy(owner)
        @reason = reason&.to_s
        @observer = observer
        freeze
      end

      # The same operation, reporting its outcome to +block+.
      def observed(&block)
        Operation.new(action: action, resource: resource, key: key, object: object, patch: patch, owner: owner, reason: reason,
                      observer: block)
      end

      def notify(succeeded, error = nil)
        @observer&.call(succeeded, error)
      rescue StandardError
        nil
      end

      def create?
        action == :create
      end

      def delete?
        action == :delete
      end

      def update?
        %i[update patch status_update status_merge].include?(action)
      end

      def to_h
        {action: action, resource: resource.to_h, key: key, object: object,
         patch: patch, owner: owner, reason: reason}.freeze
      end
    end

    class ReconcileResult
      attr_reader :operations, :batches, :status, :events, :controller, :key, :applied, :requeue_after

      # requeue_after is the controller's own timer (Job pod backoff, Deployment
      # progress deadline).  Upstream expresses it as queue.AddAfter; here the
      # planner stays pure and the Manager schedules the delayed re-sync.
      def initialize(operations: [], batches: nil, status: nil, events: [], controller: nil, key: nil, applied: false,
                     requeue_after: nil)
        @operations = Array(operations).freeze
        @batches = normalize_batches(@operations, batches)
        @status = status.nil? ? nil : Support.immutable_copy(status)
        @events = Support.immutable_copy(Array(events)).freeze
        @controller = controller&.to_s
        @key = key&.to_s
        @applied = !!applied
        @requeue_after = normalize_requeue_after(requeue_after)
        freeze
      end

      def changed?
        operations.any?
      end

      alias change? changed?

      def creates
        operations.select(&:create?)
      end

      def updates
        operations.select(&:update?)
      end

      def deletes
        operations.select(&:delete?)
      end

      def to_h
        {controller: controller, key: key, changed: changed?, applied: applied,
         status: status, events: events, operations: operations.map(&:to_h),
         batches: batches.map { |batch| batch.map(&:to_h) }, requeue_after: requeue_after}.freeze
      end

      # The same result with each operation replaced by the block's (an
      # observed copy), batches kept as they were.
      def map_operations
        replaced = {}.compare_by_identity
        operations = @operations.map { |operation| replaced[operation] = yield(operation) }
        batches = @batches.map { |batch| batch.map { |operation| replaced.fetch(operation) { operation } } }
        ReconcileResult.new(operations: operations, batches: batches, status: @status, events: @events, controller: @controller, key: @key,
                            applied: @applied, requeue_after: @requeue_after)
      end

      private

      def normalize_requeue_after(value)
        return nil if value.nil?

        seconds = Float(value)
        raise ArgumentError, "requeue_after must be finite and non-negative" unless seconds.finite? && seconds >= 0

        seconds
      end

      def normalize_batches(operations, batches)
        return [operations].freeze if batches.nil?

        normalized = Array(batches).map { |batch| Array(batch).freeze }
        covered = normalized.flat_map(&:to_a).to_h { |operation| [operation, true] }.compare_by_identity
        remainder = operations.reject { |operation| covered[operation] }
        normalized += remainder.map { |operation| [operation].freeze }
        normalized.freeze
      end
    end

    class ControllerDefinition
      attr_reader :name, :kind, :owner, :owns, :watches, :reconcile_block,
                  :feature_gates, :startup_conditions, :sync_targets,
                  :status_fields, :events, :implementation, :incomplete_reasons

      METADATA_FIELDS = %i[feature_gates startup_conditions sync_targets status_fields events].freeze
      WATCH_RELATIONSHIPS = %i[owner_reference label selector all].freeze

      def initialize(name:, kind:, owns: [], watches: [], reconcile_block: nil,
                     feature_gates: [], startup_conditions: [], sync_targets: [], status_fields: [],
                     events: [], implementation: nil, incomplete_reasons: [])
        @name = name.to_s.freeze
        @kind = kind
        @owner = kind
        @owns = Array(owns).freeze
        @watches = Array(watches).freeze
        @reconcile_block = reconcile_block
        @feature_gates = Array(feature_gates).map(&:to_s).freeze
        @startup_conditions = Array(startup_conditions).map(&:to_s).freeze
        @sync_targets = Array(sync_targets).map(&:to_s).freeze
        @status_fields = Array(status_fields).map(&:to_s).freeze
        @events = Array(events).map(&:to_s).freeze
        @implementation = implementation
        @incomplete_reasons = Array(incomplete_reasons).map(&:to_s).reject(&:empty?).uniq.freeze
        freeze
      end

      # Validate the immutable declaration before a registry can expose it to
      # a controller manager.  The C1-C7 behavioral properties still require
      # runtime/property tests, but malformed ownership, watch wiring, and
      # corpus metadata must fail before any reconcile loop starts.
      def validate!(corpus_entry: nil)
        raise ValidationError, "controller name must not be empty" if name.empty?
        raise ValidationError, "controller name must not contain surrounding whitespace" unless name == name.strip
        raise ValidationError, "controller kind must be a ResourceDescriptor" unless kind.is_a?(ResourceDescriptor)
        raise ValidationError, "controller owner must match controller kind" unless owner == kind

        validate_reconcile_block!
        validate_metadata!
        validate_ownership!
        validate_watches!
        validate_implementation!
        validate_corpus_metadata!(corpus_entry) if corpus_entry
        self
      end

      def implemented?
        !implementation.nil?
      end

      def complete?
        implemented? && completeness_reasons.empty?
      end

      def implementation_name
        return nil unless implementation

        implementation.respond_to?(:name) ? implementation.name.to_s : implementation.class.name.to_s
      end

      def incomplete?
        !complete?
      end

      def completeness_reasons
        reasons = incomplete_reasons.dup
        reasons.concat(implementation_contract_errors)
        reasons.reject(&:empty?).uniq.freeze
      end

      def with_incomplete_reasons(reasons)
        self.class.new(
          name: name, kind: kind, owns: owns, watches: watches,
          reconcile_block: reconcile_block, feature_gates: feature_gates,
          startup_conditions: startup_conditions, sync_targets: sync_targets,
          status_fields: status_fields, events: events, implementation: implementation,
          incomplete_reasons: Array(reasons)
        )
      end

      def reconcile(resource, context = nil)
        raise MissingReconcileError, "controller #{name} has no reconcile block" unless reconcile_block

        if reconcile_block.arity == 1
          reconcile_block.call(resource)
        else
          reconcile_block.call(resource, context)
        end
      end

      def to_h
        {name: name, kind: kind.to_h, owns: owns.map(&:to_h), watches: watches.map(&:to_h),
         feature_gates: feature_gates, startup_conditions: startup_conditions,
         sync_targets: sync_targets, status_fields: status_fields, events: events,
         implementation: implementation_name, incomplete_reasons: completeness_reasons}.freeze
      end

      private

      def validate_reconcile_block!
        raise MissingReconcileError, "controller #{name} has no callable reconcile block" unless reconcile_block.respond_to?(:call)

        return if reconcile_block.arity.negative? || [1, 2].include?(reconcile_block.arity)

        raise MissingReconcileError, "controller #{name} reconcile block must accept resource and optional context"
      end

      def validate_implementation!
        # Custom, non-corpus DSL definitions may intentionally defer their
        # implementation.  They remain incomplete in the registry report but
        # are still valid declarations while require_corpus is false.
        return if implementation.nil?

        errors = implementation_contract_errors
        return if errors.empty?

        raise ValidationError, "controller #{name} concrete implementation contract is invalid: #{errors.join("; ")}"
      end

      def implementation_contract_errors
        return ["concrete implementation is missing"] if implementation.nil?

        klass = implementation.is_a?(Class) ? implementation : implementation.class
        errors = []
        errors << "implementation must be a class or expose #plan" unless implementation.is_a?(Class) || implementation.respond_to?(:plan)
        errors << "implementation must expose #plan" unless klass.public_method_defined?(:plan) || klass.protected_method_defined?(:plan)
        errors << "BaseController is abstract" if defined?(BaseController) && klass == BaseController
        errors
      end

      def validate_metadata!
        METADATA_FIELDS.each do |field|
          values = public_send(field)
          unless values.all? { |value| value.is_a?(String) && !value.empty? && value == value.strip }
            raise ValidationError, "controller #{name} #{field} must contain non-empty strings"
          end
          raise ValidationError, "controller #{name} #{field} must not contain duplicates" unless values.length == values.uniq.length
        end
      end

      def validate_ownership!
        seen = {}
        owns.each do |edge|
          raise ValidationError, "controller #{name} owns must contain OwnershipEdge instances" unless edge.is_a?(OwnershipEdge)
          unless edge.owner.is_a?(ResourceDescriptor) && edge.dependent.is_a?(ResourceDescriptor)
            raise ValidationError, "controller #{name} ownership edges must use ResourceDescriptor values"
          end
          raise ValidationError, "controller #{name} may only declare ownership from #{kind.identifier}" unless edge.owner == kind
          raise OwnershipCycleError, "controller #{name} cannot own itself (#{edge.owner.identifier})" if edge.owner == edge.dependent

          key = [edge.owner.gvk, edge.dependent.gvk, edge.controller, edge.block_owner_deletion]
          raise ValidationError, "controller #{name} declares duplicate ownership edge" if seen[key]

          seen[key] = true
        end
      end

      def validate_watches!
        seen = {}
        watches.each do |watch|
          raise ValidationError, "controller #{name} watches must contain WatchSpec instances" unless watch.is_a?(WatchSpec)
          raise ValidationError, "controller #{name} watch resource must be a ResourceDescriptor" unless watch.resource.is_a?(ResourceDescriptor)
          raise InvalidWatchError, "unsupported watch relationship #{watch.via.inspect}" unless WATCH_RELATIONSHIPS.include?(watch.via)
          if watch.scope && watch.scope != watch.resource.scope
            raise ScopeMismatchError, "watch scope #{watch.scope.inspect} conflicts with #{watch.resource.identifier}"
          end
          raise InvalidWatchError, "controller #{name} watch predicate must be callable" if watch.predicate && !watch.predicate.respond_to?(:call)
          raise InvalidWatchError, "controller #{name} watch queue key must be callable" if watch.queue_key && !watch.queue_key.respond_to?(:call)
          if watch.index_name && (watch.index_name.empty? || watch.index_name != watch.index_name.strip)
            raise InvalidWatchError, "controller #{name} watch index name must be a non-empty static name"
          end

          key = [watch.resource.gvk, watch.via, watch.index_name, watch.scope]
          raise ValidationError, "controller #{name} declares duplicate watch" if seen[key]

          seen[key] = true
        end
      end

      def validate_corpus_metadata!(entry)
        expected_kind = if entry.respond_to?(:descriptor)
                          entry.descriptor
                        else
                          ResourceDescriptor.parse(entry.kind)
                        end
        raise ValidationError, "controller #{name} does not match corpus entry #{entry.name.inspect}" unless entry.name == name && expected_kind == kind

        METADATA_FIELDS.each do |field|
          expected = Array(entry.public_send(field)).map(&:to_s)
          actual = public_send(field)
          next if actual == expected

          raise ValidationError, "controller #{name} #{field} does not match corpus entry"
        end
      end
    end
  end
end
