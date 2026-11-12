# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class GarbageCollectorController < BaseController
        # garbagecollector.go processDeletingDependentsItem: an owner deleted
        # with propagationPolicy=Foreground keeps the foregroundDeletion
        # finalizer while it has dependents.  Each sweep deletes the ones not
        # yet going, releases the ones another live owner still holds, and
        # once none is left removes the finalizer, which lets the API server
        # finish the removal.  A creation batch its controller had already
        # started when the owner was marked can still land Pods for a moment,
        # so an owner marked less than FOREGROUND_SETTLE_SECONDS ago is not
        # released even when it looks empty.
        FOREGROUND_FINALIZER = "foregroundDeletion"
        FOREGROUND_SETTLE_SECONDS = 5.0

        def with_foreground_operations(result, objects, now: Time.now.utc, live: nil)
          operations = foreground_operations(objects, now, live: live)
          return result if operations.empty?

          ReconcileResult.new(operations: Array(result.operations) + operations,
                              batches: Array(result.batches) + operations.zip,
                              status: result.status, events: result.events,
                              controller: result.controller, key: result.key)
        end

        # `live` re-reads a dependent from the API before it is acted on, as
        # attemptToDeleteItem does (garbagecollector.go: "the latest object
        # is fetched").  The sweep works from informer caches, and the copy
        # of a Pod patched with a second owner a moment ago still named only
        # the owner being deleted: ten of fifty such Pods were deleted
        # ("Garbage collector should not delete dependents that have both
        # valid owner and owner that's waiting for dependents to be deleted"
        # expected 50 pods, got 40).

        def foreground_operations(objects, now, live: nil)
          owners = objects.select { |object| foreground_owner?(object) }
          return [] if owners.empty?

          by_uid = objects.to_h { |object| [Support.uid(object).to_s, object] }
          dependents_of = Hash.new { |hash, key| hash[key] = [] }
          objects.each do |object|
            Support.owner_references(object).each do |reference|
              dependents_of[Support.ref_value(reference, "uid", "").to_s] << object
            end
          end
          owners.flat_map do |owner|
            uid = Support.uid(owner).to_s
            dependents = dependents_of[uid].select { |dependent| same_scope?(owner, dependent) }
            dependents = current_dependents(dependents, live, uid)
            if dependents.empty?
              next [] if marked_seconds_ago(owner, now) < FOREGROUND_SETTLE_SECONDS

              candidate = Support.deep_copy(owner)
              candidate["metadata"]["finalizers"] = Array(candidate["metadata"]["finalizers"]) - [FOREGROUND_FINALIZER]
              next [operation_update(owner, candidate, descriptor: ResourceDescriptor.parse(owner),
                                                       reason: "foreground deletion: dependents gone")]
            end

            dependents.filter_map do |dependent|
              next nil if Support.value(Support.metadata(dependent), "deletionTimestamp", nil)

              if other_live_owner?(dependent, uid, by_uid)
                candidate = Support.deep_copy(dependent)
                candidate["metadata"]["ownerReferences"] = Support.owner_references(dependent).reject do |reference|
                  Support.ref_value(reference, "uid", "").to_s == uid
                end
                operation_update(dependent, candidate, descriptor: ResourceDescriptor.parse(dependent),
                                                       reason: "foreground deletion: released to its other owner")
              else
                operation_delete(dependent, descriptor: ResourceDescriptor.parse(dependent),
                                            reason: "foreground deletion of #{Support.name(owner)}")
              end
            end
          end
        end

        # The live copies of the owner's dependents: one the API no longer has,
        # or that no longer names the owner (already released), drops out, so
        # an owner whose dependents are all gone or released is seen as empty
        # and its finalizer removed.  A read that fails keeps the cached copy
        # rather than dropping the dependent: dropping it left the owner with
        # dependents in the cache and none to act on, so no operation and no
        # finalizer removal for the whole 90 s the GC spec allows.  The reads
        # run on this thread (they reuse its kept-alive connection); a
        # thread per read opened a hundred TLS connections per sweep.
        def current_dependents(dependents, live, owner_uid)
          return dependents if live.nil?

          dependents.filter_map do |dependent|
            next dependent if Support.value(Support.metadata(dependent), "deletionTimestamp", nil)

            current = begin
              live.call(dependent)
            rescue StandardError
              dependent
            end
            next nil unless current.is_a?(Hash)
            next nil unless Support.owner_references(current).any? { |reference| Support.ref_value(reference, "uid", "").to_s == owner_uid }

            current
          end
        end

        def foreground_owner?(object)
          metadata = Support.metadata(object)
          !Support.value(metadata, "deletionTimestamp", nil).nil? &&
            Array(Support.value(metadata, "finalizers", [])).include?(FOREGROUND_FINALIZER)
        end

        def same_scope?(owner, dependent)
          owner_namespace = Support.namespace(owner).to_s
          owner_namespace.empty? || Support.namespace(dependent).to_s == owner_namespace
        end

        def other_live_owner?(dependent, uid, by_uid)
          Support.owner_references(dependent).any? do |reference|
            other = Support.ref_value(reference, "uid", "").to_s
            next false if other == uid

            owner = by_uid[other]
            owner && Support.value(Support.metadata(owner), "deletionTimestamp", nil).nil?
          end
        end

        def marked_seconds_ago(owner, now)
          marked = Support.parse_time(Support.value(Support.metadata(owner), "deletionTimestamp", nil))
          marked ? now - marked : Float::INFINITY
        end
      end
    end
  end
end
