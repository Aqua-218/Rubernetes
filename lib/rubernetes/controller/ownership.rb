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

      def self.dependents_by_uid(objects)
        by_owner = Hash.new { |children, uid| children[uid] = [] }
        objects.each do |object|
          Support.owner_references(object).each { |ref| by_owner[Support.ref_value(ref, "uid").to_s] << object }
        end
        by_owner
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
                     known_kinds: nil, owner_lookup: nil, dependent_lookup: nil, descriptor_lookup: nil)
        @index = index
        @known_kinds = normalize_known_kinds(known_kinds)
        @owner_lookup = owner_lookup
        @dependent_lookup = dependent_lookup
        @descriptor_lookup = descriptor_lookup
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

        Array(value).map do |item|
          if item.respond_to?(:kind) && item.respond_to?(:api_version)
            "#{item.api_version}/#{item.kind}"
          else
            item.to_s
          end
        end.reject(&:empty?).uniq.freeze
      end

      def graph(objects)
        values = Array(objects)
        owner_graph(values, owners_by_uid(values))
      end

      def cycles(objects)
        cycle_paths(graph(objects))
      end

      def plan(objects, deleted: [], propagation_policy: :background)
        values = Array(objects)
        deleted_objects = Array(deleted)
        policy = propagation_policy.to_s.downcase.to_sym
        raise ArgumentError, "propagation policy must be :background, :foreground, or :orphan" unless %i[background foreground orphan].include?(policy)

        by_uid = owners_by_uid(values)
        events = cycle_paths(owner_graph(values, by_uid)).map do |path|
          {"type" => "Warning", "reason" => "OwnerReferenceCycle",
           "message" => "ownership cycle prevents garbage collection: #{path.join(" -> ")}"}
        end
        targets = deleted_objects
        unless policy == :orphan
          dangling = values.select { |object| dangling?(object, by_uid) }
          dangling.select! { |object| still_dangling?(object, by_uid) }
          targets = (dangling + targets).uniq { |object| node_key(object) }
          if policy == :foreground
            descendants = descendants_of(targets, values)
            targets = (descendants.reverse + targets).uniq { |object| node_key(object) }
          end
        end
        reason = "#{policy} deletion".freeze
        operations = targets.map do |object|
          descriptor = descriptor_for(object)
          key = [Support.api_version(object) || "v1", descriptor.resource, Support.namespace(object) || "_cluster", Support.name(object)]
          Operation.new(action: :delete, resource: descriptor, key: key.join("/"), object: object, reason: reason)
        end
        ReconcileResult.new(operations: operations, events: events,
                            controller: "garbage-collector-controller")
      end

      alias reconcile plan

      def deletion_plan(owner, objects, propagation_policy: :background)
        plan(objects, deleted: [owner], propagation_policy: propagation_policy)
      end

      private

      def owners_by_uid(objects)
        objects.each_with_object({}) do |object, owners|
          uid = Support.uid(object)
          owners[uid] = object unless uid.to_s.empty?
        end
      end

      def owner_graph(values, by_uid)
        values.each_with_object({}) do |object, result|
          key = node_key(object)
          result[key] = Support.owner_references(object).filter_map do |reference|
            owner = owner_for(reference, by_uid, dependent: object)
            owner && node_key(owner)
          end.freeze
        end.freeze
      end

      # Track the current DFS path explicitly so deep ownership chains do not
      # depend on the Ruby call stack. Only copy a path when reporting a cycle.
      def cycle_paths(adjacency)
        found = []
        visited = {}
        active = {}
        path = []
        adjacency.each_key do |root|
          next if visited[root]

          stack = [[root, :enter]]
          until stack.empty?
            node, step = stack.pop
            if step == :leave
              active.delete(path.pop)
            elsif active.key?(node)
              found << (path[active.fetch(node)..] + [node]).freeze
            elsif !visited[node]
              visited[node] = true
              active[node] = path.size
              path << node
              stack << [node, :leave]
              adjacency.fetch(node).reverse_each { |parent| stack << [parent, :enter] }
            end
          end
        end
        found.uniq.freeze
      end

      def dangling?(object, by_uid)
        refs = Support.owner_references(object)
        !refs.empty? && refs.all? { |reference| owner_state(reference, by_uid, dependent: object) == :absent }
      end

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

        dangling?(live, by_uid)
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
        return [] if roots.empty?

        by_owner = OwnerReferenceIndex.dependents_by_uid(objects)
        descendants = {}
        pending = roots.dup
        pending.each do |parent|
          by_owner.fetch(Support.uid(parent), []).each do |child|
            next unless Support.owner_reference_matches?(parent, child)

            key = node_key(child)
            next if descendants.key?(key)

            descendants[key] = child
            pending << child
          end
        end
        descendants.values
      end

      def node_key(object)
        [Support.kind(object), Support.namespace(object), Support.name(object), Support.uid(object)].compact.join("/")
      end

      def descriptor_for(object)
        @descriptor_lookup&.call(object) || ResourceDescriptor.parse(object)
      end
    end
  end
end
