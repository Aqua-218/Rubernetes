# frozen_string_literal: true

require_relative "../builtin_factory"

module Rubernetes
  module Controller
    # Registration metadata stays next to concrete implementations so registry
    # integration can avoid a CorpusController fallback. register! is explicit
    # and never runs while this file is merely required.
    module InfrastructureStorageControllerFactory
      include BuiltinFactory

      VERSION = "v1.36.2"
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
      NAMES = IMPLEMENTATIONS.keys.freeze
      CONTROLLER_NAMES = NAMES

      ENTRIES = NAMES.map { |name| BuiltinControllerCorpus.fetch(name) }.freeze
      METADATA = ENTRIES.to_h { |entry| [entry.name, entry.metadata] }.freeze
      private_constant :ENTRIES

      module_function :register!, :usable_descriptor
      alias register register!

      module_function

      def names = CONTROLLER_NAMES

      def implementation(name)
        IMPLEMENTATIONS.fetch(name.to_s)
      end

      def entries
        return ENTRIES if defined?(ControllerRegistry)

        # Standalone callers receive the original metadata hashes.
        ENTRIES.map { |entry| entry.to_h.except("apiVersion", "resource", "scope").freeze }.freeze
      end

      def metadata(name = nil)
        return entries.map(&:to_h).freeze if name.nil?

        Support.immutable_copy(METADATA.fetch(name.to_s))
      end

      def definitions(registry: nil)
        NAMES.map { |name| definition(name, registry: registry) }.freeze
      end

      def definition(name, registry: nil)
        name = name.to_s
        implementation = IMPLEMENTATIONS.fetch(name)
        entry = BuiltinControllerCorpus.fetch(name)
        kind = usable_descriptor(ResourceDescriptor.parse(entry.kind), registry)
        entry.build_controller(implementation, kind: kind, watches: watch_specs(name, registry: registry)) do |_definition, store|
          implementation.new(store: store, definition: nil)
        end
      end

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

      NODE_KEYED_POD_WATCHERS = %w[taint-eviction-controller device-taint-eviction-controller].freeze
      # The Node a Pod is bound to, the only node key its events concern.
      POD_NODE_KEY = lambda do |pod|
        node = Support.value(Support.spec(pod), "nodeName", nil).to_s
        node.empty? ? nil : node
      end
      ATTACHMENT_NODE_KEYS = lambda do |attachment, store|
        [Support.spec(attachment)["nodeName"], *store.list(ResourceDescriptor.parse("Node"), namespace: :all).map { |node| Support.name(node) }]
          .compact.uniq
      end
      ATTACHMENT_VOLUME_SOURCES = (%w[persistentVolumeClaim ephemeral] + ::Rubernetes::Volume::CSIMigration::DRIVERS.keys).freeze
      ATTACHMENT_POD = lambda do |pod|
        Array(Support.spec(pod)["volumes"]).any? { |volume| ATTACHMENT_VOLUME_SOURCES.any? { |source| volume.key?(source) } }
      end

      def watch_specs(name, registry: nil)
        specs = watched_descriptors(name).map do |descriptor|
          descriptor = usable_descriptor(descriptor, registry)
          attach_detach = name == "persistent-volume-attach-detach-controller"
          if (NODE_KEYED_POD_WATCHERS.include?(name) || attach_detach) && descriptor.kind == "Pod"
            # A Pod event concerns the node it is bound to and no other: the
            # fan-out reconciled every node for every Pod event, which is
            # what a mass Pod deletion then queued up behind.
            next WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                               index_name: "infrastructure/#{name}/#{descriptor.identifier}/node",
                               predicate: attach_detach ? ATTACHMENT_POD : ->(_object) { true }, route: :self,
                               queue_key: POD_NODE_KEY)
          end
          if attach_detach && descriptor.kind == "VolumeAttachment"
            # Visit a missing node to remove its attachments after restart, as
            # well as the live nodes that might now acquire an exclusive volume.
            next WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope, route: :self,
                               index_name: "infrastructure/#{name}/attachment-nodes", queue_key: ATTACHMENT_NODE_KEYS)
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
           ResourceDescriptor.parse("CSIDriver"),
           ResourceDescriptor.parse("VolumeAttachment")]
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
