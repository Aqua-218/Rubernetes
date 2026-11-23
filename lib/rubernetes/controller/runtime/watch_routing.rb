# frozen_string_literal: true

module Rubernetes
  module Controller
    # Resource, owner and selector watches fan out to their reconcile keys.
    module WatchRouting
      GARBAGE_COLLECTOR_SWEEP_KEY = "garbage-collector/sweep"

      private

      def routing_identity(object)
        metadata = Support.metadata(object)
        [Support.namespace(object), Support.name(object), Support.uid(object), Support.labels(object),
         Support.value(metadata, "ownerReferences", nil)]
      end

      def queue_keys_for(controller, watch, object)
        if watch.via == :owner_reference
          direct_reference = Support.owner_references(object).find do |reference|
            controller_flag = Support.ref_value(reference, "controller", false)
            (controller_flag == true || controller_flag.to_s.casecmp("true").zero?) &&
              valid_owner_reference?(controller, object, reference)
          end
          if direct_reference
            direct = owner_watch_queue_key(watch, object, direct_reference)
            return normalize_queue_keys(direct)
          end

          ancestor = ownership_ancestor(controller, object)
          return normalize_queue_keys([Support.namespace(ancestor), Support.name(ancestor)].compact.join("/")) if ancestor

          return []
        end

        return matching_controller_keys(controller, object, selector_source: watch.selector_source) if %i[label selector].include?(watch.via)

        # A Namespace controller's relation to a namespaced object is plain
        # containment: the object's own namespace is the only key worth
        # reconciling.  Falling through to the fan-out below made every event
        # on any namespaced object re-sweep every namespace in the cluster,
        # so one namespace deletion cost a full content sweep per namespace
        # per event.
        if watch.via == :all && controller.resource_descriptor.kind == "Namespace" &&
           watch.resource.kind != "Namespace"
          return normalize_queue_keys(Support.namespace(object))
        end

        # A foreign `:all` watch has no owner identity in the observed object.
        # Queueing its namespace/name would either address a controller with
        # the wrong kind or silently drop a cluster-scoped event (for example,
        # a Node change watched by every DaemonSet). Fan the event out to the
        # controller's own resources; self-watches still use their declared
        # queue key below so same-GVK routing remains precise.
        # route: :namespace confines the fan-out to the controller's objects
        # in the observed object's namespace: a quota only ever counts its
        # own namespace, and fanning every Pod event in the cluster out to
        # every quota made each quota recompute dozens of times a minute --
        # often in the window between admission charging it for a new object
        # and that object being stored, which erased the charge.
        if watch.via == :all && watch.route == :namespace && watch.resource.gvk != controller.resource_descriptor.gvk
          return controller_keys(controller, namespace: Support.namespace(object))
        end

        if watch.via == :all && watch.resource.gvk != controller.resource_descriptor.gvk &&
           !%i[self mapped].include?(watch.route)
          # The collector watches foreign objects but has no persisted kind
          # of its own to fan out to. Its work is one coalesced sweep.
          return [GARBAGE_COLLECTOR_SWEEP_KEY] if garbage_collector?(controller)

          return controller_keys(controller)
        end

        queue_key = watch.queue_key
        keys = queue_key && (queue_key.arity == 2 ? queue_key.call(object, store_adapter) : queue_key.call(object))
        normalize_queue_keys(keys)
      end
    end
  end
end
