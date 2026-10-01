# frozen_string_literal: true

require_relative "errors"
require_relative "support"
require_relative "types"

module Rubernetes
  module Controller
    # Secondary index for ownerReferences.  Matching requires the owner's UID
    # whenever one is available; names alone are not an ownership identity.
    class OwnerReferenceIndex
      attr_reader :edges

      def initialize
        @edges = {}
      end

      def register(owner, dependent, controller: true, block_owner_deletion: true)
        edge = OwnershipEdge.new(owner: descriptor(owner), dependent: descriptor(dependent),
                                 controller: controller, block_owner_deletion: block_owner_deletion)
        @edges[[edge.owner.identifier, edge.dependent.identifier]] = edge
        edge
      end

      alias add register

      def registered?(owner, dependent)
        @edges.key?([descriptor(owner).identifier, descriptor(dependent).identifier])
      end

      def owned?(owner, dependent, controller: nil)
        Support.owner_reference_matches?(owner, dependent, controller: controller)
      end

      def children(owner, objects, dependent: nil, controller: nil)
        descriptor = dependent && self.class.descriptor(dependent)
        Array(objects).select do |object|
          next false if descriptor && descriptor.kind != Support.kind(object)

          owned?(owner, object, controller: controller)
        end
      end

      def index(objects)
        result = Hash.new { |hash, key| hash[key] = [] }
        Array(objects).each do |object|
          Support.owner_references(object).each do |reference|
            key = [Support.ref_value(reference, "kind", "").to_s,
                   Support.ref_value(reference, "name", "").to_s,
                   Support.ref_value(reference, "uid", "").to_s,
                   Support.namespace(object)]
            result[key] << Support.immutable_copy(object)
          end
        end
        result.each_value(&:freeze)
        result.freeze
      end

      def to_h
        @edges.transform_values(&:to_h).freeze
      end

      def self.descriptor(value)
        value.is_a?(ResourceDescriptor) ? value : ResourceDescriptor.parse(value)
      end

      private

      def descriptor(value)
        self.class.descriptor(value)
      end
    end

    # Ownership graph builder and delete planner.  The planner has no hidden
    # state: a restart with the same object snapshot produces byte-identical
    # operations and events.
    class GarbageCollector
      attr_reader :index, :known_kinds, :owner_lookup

      def initialize(store: nil, index: OwnerReferenceIndex.new, event_sink: nil,
                     known_kinds: nil, owner_lookup: nil, dependent_lookup: nil)
        @store = store
        @index = index
        @event_sink = event_sink
        @known_kinds = normalize_known_kinds(known_kinds)
        @owner_lookup = owner_lookup
        @dependent_lookup = dependent_lookup
      end

      # The kinds this collector is allowed to reason about the ABSENCE of.
      # Upstream resolves an owner with a live GET through the REST mapper and
      # only collects the dependent on a definitive 404
      # (pkg/controller/garbagecollector/garbagecollector.go
      # attemptToDeleteItem -> classifyReferences); it never concludes "gone"
      # from a cache that does not cover the kind.  Without this set the
      # collector scanned a fixed corpus of built-in kinds and treated every
      # owner outside it -- a custom resource above all -- as deleted, so it
      # would have deleted every Pod, Job and Secret owned by a CR the moment
      # it was enabled.
      def normalize_known_kinds(value)
        return nil if value.nil?

        Array(value).flat_map do |item|
          if item.respond_to?(:kind) && item.respond_to?(:api_version)
            ["#{item.api_version}/#{item.kind}", item.kind.to_s]
          else
            [item.to_s]
          end
        end.reject(&:empty?).uniq.freeze
      end

      def graph(objects)
        values = Array(objects)
        by_uid = {}
        values.each do |object|
          by_uid[Support.uid(object)] = object if Support.uid(object) && !Support.uid(object).empty?
        end
        values.each_with_object({}) do |object, result|
          key = node_key(object)
          result[key] = Support.owner_references(object).filter_map do |reference|
            owner = owner_for(reference, by_uid, dependent: object)
            owner && node_key(owner)
          end.freeze
        end.freeze
      end

      def cycles(objects)
        adjacency = graph(objects)
        visiting = {}
        visited = {}
        found = []
        walk = lambda do |node, path|
          if visiting[node]
            start = path.index(node) || 0
            found << path[start..].freeze
            return
          end
          return if visited[node]

          visiting[node] = true
          adjacency.fetch(node, []).each { |parent| walk.call(parent, path + [parent]) }
          visiting.delete(node)
          visited[node] = true
        end
        adjacency.keys.each { |node| walk.call(node, [node]) }
        found.uniq.freeze
      end

      def plan(objects, deleted: [], propagation_policy: :background)
        values = Array(objects)
        deleted_objects = Array(deleted)
        policy = propagation_policy.to_s.downcase.to_sym
        raise ArgumentError, "propagation policy must be :background, :foreground, or :orphan" unless %i[background foreground orphan].include?(policy)

        cycle_paths = cycles(values)
        events = cycle_paths.map do |path|
          {"type" => "Warning", "reason" => "OwnerReferenceCycle",
           "message" => "ownership cycle prevents garbage collection: #{path.join(" -> ")}"}
        end
        # An ownership cycle is REPORTED, not fatal: the objects inside it keep
        # each other alive, but everything else in the cluster must still be
        # collected.  Refusing the whole plan meant one deliberate cycle --
        # "[sig-api-machinery] Garbage collector should not be blocked by
        # dependency circle" creates one -- stopped garbage collection
        # cluster-wide for the rest of the run, so orphaned EndpointSlices,
        # ReplicaSets and Pods were never reclaimed.  Deleting one member of a
        # cycle by hand breaks it, and the next sweep collects the rest.

        # Orphan propagation deletes the requested owner while leaving its
        # dependents in place.  Returning an empty plan here silently retains
        # the owner and makes the policy indistinguishable from a no-op.
        if policy == :orphan
          operations = deleted_objects.map do |object|
            Operation.new(action: :delete, resource: descriptor_for(object),
                          key: object_key(object), object: object,
                          reason: "orphan deletion")
          end
          return ReconcileResult.new(operations: operations, events: events,
                                     controller: "garbage-collector-controller")
        end

        by_uid = {}
        values.each do |object|
          by_uid[Support.uid(object)] = object if Support.uid(object)
        end
        missing_owner_objects = values.select do |object|
          refs = Support.owner_references(object)
          # A dependent is collected only when it has owner references and
          # every one of them is KNOWN to be gone; one live owner keeps it
          # (the GC spec "should not delete dependents that have both a valid
          # owner and an owner waiting for deletion"), and so does one owner
          # whose kind this collector cannot observe -- an unverifiable owner
          # is never assumed dead.
          !refs.empty? && refs.all? do |reference|
            owner_state(reference, by_uid, dependent: object) == :absent
          end
        end
        # attemptToDeleteItem re-reads the dependent before acting on it.  The
        # sweep's corpus is listed kind by kind, so a Pod can be read before an
        # orphaning delete releases it and its owner read after the owner is
        # gone: the stale copy still names the owner, and collecting it deleted
        # Pods the delete had just promised to keep ("[sig-api-machinery]
        # Garbage collector should orphan pods created by rc if delete options
        # say so" kept 60 of 100).  Decide on the live object.
        missing_owner_objects = missing_owner_objects.select do |object|
          still_dangling?(object, by_uid)
        end
        targets = (missing_owner_objects + deleted_objects).uniq { |object| node_key(object) }
        operations = []
        if policy == :foreground
          descendants = descendants_of(targets, values)
          (descendants.reverse + targets).uniq { |object| node_key(object) }.each do |object|
            operations << Operation.new(action: :delete, resource: descriptor_for(object),
                                        key: object_key(object), object: object,
                                        reason: "foreground deletion")
          end
        else
          targets.each do |object|
            operations << Operation.new(action: :delete, resource: descriptor_for(object),
                                        key: object_key(object), object: object,
                                        reason: "background deletion")
          end
        end
        ReconcileResult.new(operations: operations, events: events,
                            controller: "garbage-collector-controller")
      end

      alias reconcile plan

      def deletion_plan(owner, objects, propagation_policy: :background)
        plan(objects, deleted: [owner], propagation_policy: propagation_policy)
      end

      private

      # :present, :absent or :unknown.  Only :absent lets the dependent be
      # collected.
      def owner_state(reference, by_uid, dependent: nil)
        uid = Support.ref_value(reference, "uid", nil)&.to_s
        # An ownerReference without a UID names no object the collector could
        # ever find; API validation rejects one, so an object carrying it was
        # written before the field was required and holds no live edge.
        return :absent if uid.nil? || uid.empty?
        return :present if owner_for(reference, by_uid, dependent: dependent)
        # The UID is present in the scanned corpus but the reference does not
        # describe that object: a stale edge, not a live owner.
        return :absent if by_uid.key?(uid)

        # A live read decides it when one is available.  The scanned corpus is
        # an informer cache, and a cache that has not yet seen a freshly
        # created owner would otherwise make its dependent look orphaned --
        # upstream re-reads the owner from the API server before deleting
        # anything for exactly this reason (garbagecollector.go
        # attemptToDeleteItem: "always get the latest owner").
        state = lookup_owner_state(reference, dependent: dependent)
        return state unless state == :unknown

        authoritative_reference?(reference) ? :absent : :unknown
      end

      # True when the scan covered this reference's kind, so "not in the scan"
      # really does mean "not in the cluster".  With no known-kind set the
      # caller has declared the corpus complete (an in-memory store holding
      # every object), which is how the planner is used in tests.
      def authoritative_reference?(reference)
        return true if @known_kinds.nil?

        api_version = Support.ref_value(reference, "apiVersion", "").to_s
        kind = Support.ref_value(reference, "kind", "").to_s
        return false if kind.empty?

        @known_kinds.include?("#{api_version}/#{kind}") || @known_kinds.include?(kind)
      end

      # A kind outside the scan gets one live lookup.  The callable answers
      # true (owner exists), false (the API server says it is gone) or nil
      # (it could not tell) -- and nil keeps the dependent.
      def still_dangling?(object, by_uid)
        return true unless @dependent_lookup

        live = @dependent_lookup.call(object)
        return false if live.nil? || live == false
        return false unless Support.uid(live).to_s == Support.uid(object).to_s

        refs = Support.owner_references(live)
        !refs.empty? && refs.all? { |reference| owner_state(reference, by_uid, dependent: live) == :absent }
      rescue StandardError
        false
      end

      def lookup_owner_state(reference, dependent: nil)
        return :unknown unless @owner_lookup

        namespace = dependent && Support.namespace(dependent)
        answer = @owner_lookup.call(reference, namespace)
        case answer
        when true then :present
        when false then :absent
        else :unknown
        end
      rescue StandardError
        :unknown
      end

      def owner_for(reference, by_uid, dependent: nil)
        uid = Support.ref_value(reference, "uid", nil)&.to_s
        # UID is mandatory for a safe ownership edge.  Falling back to
        # kind/name would allow a recreated owner to claim an old child.
        return nil if uid.nil? || uid.empty?

        owner = by_uid[uid]
        return nil unless owner
        return nil unless Support.kind(owner) == Support.ref_value(reference, "kind", "").to_s
        return nil unless Support.name(owner) == Support.ref_value(reference, "name", "").to_s

        if dependent
          owner_namespace = Support.namespace(owner)
          dependent_namespace = Support.namespace(dependent)
          return nil if owner_namespace && dependent_namespace.nil?
          return nil if owner_namespace && owner_namespace != dependent_namespace
        end

        owner
      end

      def descendants_of(roots, objects)
        result = []
        pending = Array(roots).dup
        until pending.empty?
          root = pending.shift
          children = Array(objects).select { |object| Support.owner_reference_matches?(root, object) }
          children.each do |child|
            next if result.any? { |known| node_key(known) == node_key(child) }

            result << child
            pending << child
          end
        end
        result
      end

      def node_key(object)
        [Support.kind(object), Support.namespace(object), Support.name(object), Support.uid(object)].compact.join("/")
      end

      def descriptor_for(object)
        ResourceDescriptor.parse(object)
      end

      def object_key(object)
        [Support.api_version(object) || "v1", descriptor_for(object).resource,
         Support.namespace(object) || "_cluster", Support.name(object)].join("/")
      end
    end
  end
end
