# frozen_string_literal: true

module Rubernetes
  module Controller
    # Registration metadata stays next to concrete implementations so registry
    # integration can avoid a CorpusController fallback. register! is explicit
    # and never runs while this file is merely required.
    module InfrastructureStorageControllerFactory
      VERSION = "v1.36.2"
      NAMES = %w[
        taint-eviction-controller device-taint-eviction-controller service-lb-controller
        node-route-controller cloud-node-lifecycle-controller persistentvolume-binder-controller
        persistent-volume-attach-detach-controller persistent-volume-expander-controller
        clusterrole-aggregation-controller
      ].freeze
      CONTROLLER_NAMES = NAMES

      IMPLEMENTATIONS = {
        "taint-eviction-controller" => TaintEvictionController,
        "device-taint-eviction-controller" => DeviceTaintEvictionController,
        "service-lb-controller" => ServiceLBController,
        "node-route-controller" => NodeRouteController,
        "cloud-node-lifecycle-controller" => CloudNodeLifecycleController,
        "persistentvolume-binder-controller" => PersistentVolumeBinderController,
        "persistent-volume-attach-detach-controller" => PersistentVolumeAttachDetachController,
        "persistent-volume-expander-controller" => PersistentVolumeExpanderController,
        "clusterrole-aggregation-controller" => ClusterRoleAggregationController
      }.freeze

      METADATA = {
        "taint-eviction-controller" => {
          kind: "Node", feature_gates: ["SeparateTaintEvictionController"],
          startup_conditions: ["API server available"], sync_targets: %w[Node Pod],
          status_fields: ["taints"], events: ["TaintManagerEviction"]
        },
        "device-taint-eviction-controller" => {
          kind: "Node", feature_gates: ["DynamicResourceAllocation"],
          startup_conditions: ["API server available"], sync_targets: %w[Node Pod],
          status_fields: ["taints"], events: ["DeviceTaintEviction"]
        },
        "service-lb-controller" => {
          kind: "Service", feature_gates: [], startup_conditions: ["cloud provider configured"],
          sync_targets: %w[Service Node LoadBalancer], status_fields: ["loadBalancer"],
          events: %w[EnsuringLoadBalancer EnsuredLoadBalancer DeletingLoadBalancer]
        },
        "node-route-controller" => {
          kind: "Node", feature_gates: [], startup_conditions: ["cloud provider configured"],
          sync_targets: %w[Node Route], status_fields: ["routes"],
          events: %w[RouteCreated RouteDeleted]
        },
        "cloud-node-lifecycle-controller" => {
          kind: "Node", feature_gates: [], startup_conditions: ["cloud provider configured"],
          sync_targets: ["Node"], status_fields: ["conditions"], events: ["CloudNodeNotReady"]
        },
        "persistentvolume-binder-controller" => {
          kind: "PersistentVolumeClaim", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: %w[PersistentVolume PersistentVolumeClaim], status_fields: %w[phase capacity],
          events: %w[ProvisioningSucceeded ProvisioningFailed]
        },
        "persistent-volume-attach-detach-controller" => {
          kind: "PersistentVolume", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: %w[PersistentVolume Node VolumeAttachment], status_fields: ["attached"],
          events: %w[SuccessfulAttachVolume FailedAttachVolume]
        },
        "persistent-volume-expander-controller" => {
          kind: "PersistentVolumeClaim", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: %w[PersistentVolumeClaim PersistentVolume], status_fields: %w[capacity conditions],
          events: %w[VolumeResizeSuccessful VolumeResizeFailed]
        },
        "clusterrole-aggregation-controller" => {
          kind: "ClusterRole", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: ["ClusterRole"], status_fields: ["rules"], events: ["ClusterRoleAggregated"]
        }
      }.freeze
      METADATA.each_value do |entry|
        entry.each_value { |value| value.freeze if value.is_a?(Array) }
        entry.freeze
      end

      module_function

      def implementation(name)
        IMPLEMENTATIONS.fetch(name.to_s)
      end

      def entries
        if defined?(BuiltinControllerCorpus)
          NAMES.map do |name|
            BuiltinControllerCorpus.fetch(name) ||
              raise(ValidationError, "missing pinned corpus entry #{name.inspect}")
          end.freeze
        else
          NAMES.map do |name|
            local = METADATA.fetch(name)
            {"name" => name, "kind" => local.fetch(:kind),
             "startupConditions" => local.fetch(:startup_conditions),
             "featureGates" => local.fetch(:feature_gates), "syncTargets" => local.fetch(:sync_targets),
             "statusFields" => local.fetch(:status_fields), "events" => local.fetch(:events),
             "aliases" => [],
             "cloudProvider" => %w[service-lb-controller node-route-controller cloud-node-lifecycle-controller].include?(name)}.freeze
          end.freeze
        end
      end

      def metadata(name = nil)
        return entries.map(&:to_h).freeze if name.nil?

        Support.immutable_copy(METADATA.fetch(name.to_s))
      end

      def names
        NAMES
      end

      def definitions(registry: nil)
        NAMES.map { |name| definition(name, registry: registry) }.freeze
      end

      def definition(name, registry: nil)
        name = name.to_s
        metadata = METADATA.fetch(name)
        implementation = IMPLEMENTATIONS.fetch(name)
        kind = usable_descriptor(ResourceDescriptor.parse(metadata.fetch(:kind)), registry)
        definition = nil
        mutex = Mutex.new
        instance = nil
        reconcile = lambda do |resource, context = nil|
          context = {} unless context.is_a?(Hash)
          controller = context[:controller] || context["controller"]
          controller ||= mutex.synchronize do
            instance ||= implementation.new(store: context[:store] || context["store"], definition: definition)
          end
          options = context[:options] || context["options"] || {}
          options = options.dup if options.is_a?(Hash)
          options[:store] = context[:store] || context["store"] if options.is_a?(Hash) && !options.key?(:store) && !options.key?("store")
          controller.plan(resource, **(options.is_a?(Hash) ? options : {}))
        end
        ControllerDefinition.new(
          name: name, kind: kind, owns: [], watches: watch_specs(name, registry: registry),
          reconcile_block: reconcile, feature_gates: metadata.fetch(:feature_gates),
          startup_conditions: metadata.fetch(:startup_conditions), sync_targets: metadata.fetch(:sync_targets),
          status_fields: metadata.fetch(:status_fields), events: metadata.fetch(:events),
          implementation: implementation
        )
      end

      def register!(registry)
        definitions(registry: registry).each { |definition| registry.register(definition) }
        registry
      end
      alias register register!

      def reconcile_block(implementation)
        lambda do |resource, context = nil|
          context = {} unless context.is_a?(Hash)
          controller = context[:controller] || context["controller"]
          options = context[:options] || context["options"] || {}
          options = options.dup if options.is_a?(Hash)
          if controller
            controller.plan(resource, **options)
          else
            implementation.new(store: context[:store] || context["store"], definition: nil).plan(resource, **options)
          end
        end
      end

      alias build_definitions definitions

      def usable_descriptor(descriptor, registry)
        return descriptor unless registry

        registry.validate_descriptor!(descriptor)
        descriptor
      rescue UnknownGVKError
        ResourceDescriptor.parse(descriptor.kind)
      end

      NODE_KEYED_POD_WATCHERS = %w[taint-eviction-controller device-taint-eviction-controller].freeze
      # The Node a Pod is bound to, the only node key its events concern.
      POD_NODE_KEY = lambda do |pod|
        node = Support.value(Support.spec(pod), "nodeName", nil).to_s
        node.empty? ? nil : node
      end

      def watch_specs(name, registry: nil)
        specs = watched_descriptors(name).map do |descriptor|
          descriptor = usable_descriptor(descriptor, registry)
          if NODE_KEYED_POD_WATCHERS.include?(name) && descriptor.kind == "Pod"
            # A Pod event concerns the node it is bound to and no other: the
            # fan-out reconciled every node for every Pod event, which is
            # what a mass Pod deletion then queued up behind.
            next WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                               index_name: "infrastructure/#{name}/#{descriptor.identifier}/node",
                               predicate: ->(_object) { true }, route: :self,
                               queue_key: POD_NODE_KEY)
          end
          WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                        index_name: "infrastructure/#{name}/#{descriptor.identifier}",
                        predicate: ->(_object) { true },
                        queue_key: ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") })
        end
        specs.concat(binder_volume_watches(name, registry)) if name == "persistentvolume-binder-controller"
        specs
      end

      # The kinds whose events re-plan each controller.
      def watched_descriptors(name)
        case name
        when "taint-eviction-controller", "device-taint-eviction-controller"
          [ResourceDescriptor.parse("Node"), ResourceDescriptor.parse("Pod")]
        when "service-lb-controller"
          [ResourceDescriptor.parse("Service"), ResourceDescriptor.parse("Node")]
        when "node-route-controller", "cloud-node-lifecycle-controller"
          [ResourceDescriptor.parse("Node")]
        when "persistentvolume-binder-controller"
          [ResourceDescriptor.parse("PersistentVolume"), ResourceDescriptor.parse("PersistentVolumeClaim"),
           ResourceDescriptor.parse("StorageClass")]
        when "persistent-volume-attach-detach-controller"
          [ResourceDescriptor.parse("PersistentVolume"), ResourceDescriptor.parse("PersistentVolumeClaim"),
           ResourceDescriptor.parse("Pod"), ResourceDescriptor.parse("Node"),
           ResourceDescriptor.parse({"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment"},
                                    resource: "volumeattachments", scope: :cluster)]
        when "persistent-volume-expander-controller"
          [ResourceDescriptor.parse("PersistentVolumeClaim"), ResourceDescriptor.parse("PersistentVolume")]
        when "clusterrole-aggregation-controller"
          [ResourceDescriptor.parse("ClusterRole")]
        else
          []
        end
      end

      # The binder's extra routes from an event to a PersistentVolume's own key.
      def binder_volume_watches(name, registry)
        # The volume queue: a PersistentVolume event also syncs the volume
        # itself (syncVolume), besides re-syncing the claims.
        descriptor = usable_descriptor(ResourceDescriptor.parse("PersistentVolume"), registry)
        volume_watch = WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                                     index_name: "infrastructure/#{name}/#{descriptor.identifier}/self",
                                     predicate: ->(_object) { true }, route: :self,
                                     queue_key: ->(object) { Support.name(object).to_s })
        # deleteClaim (and updateClaim): a claim event also syncs the volume
        # the claim names.  A deleted claim has nothing left to sync under
        # its own key, and without this its volume stayed Bound to it --
        # never Released, never reclaimed -- until something else touched
        # the volume.
        claims = usable_descriptor(ResourceDescriptor.parse("PersistentVolumeClaim"), registry)
        claim_watch = WatchSpec.new(resource: claims, via: :all, scope: claims.scope,
                                    index_name: "infrastructure/#{name}/#{claims.identifier}/volume",
                                    predicate: ->(_object) { true }, route: :self,
                                    queue_key: ->(object) { Support.value(Support.spec(object), "volumeName", nil) })
        [volume_watch, claim_watch]
      end
      private_class_method :watched_descriptors, :binder_volume_watches
    end
  end
end
