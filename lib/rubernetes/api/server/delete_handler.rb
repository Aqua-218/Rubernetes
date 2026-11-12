# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # DELETE of a resource or a collection: delete options and preconditions,
      # graceful deletion, finalizers, and the removal itself.
      module DeleteHandler
        private

        def delete_response(request, route)
          namespace = storage_namespace(route, operation: :delete)
          existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
          delete_options = delete_options_for(request)
          expected = ensure_delete_preconditions!(request, existing, delete_options)
          admit_mutating(request, route, "DELETE", nil, existing, namespace)
          admit_validating(request, route, "DELETE", nil, existing, namespace)
          if @crd_manager && crd_resource?(route.resource)
            marked = mark_crd_terminating(route, existing, namespace)
            schedule_crd_finalizer(metadata_value(existing, "name"))
            return json_response(marked)
          end
          # A dry-run DELETE reports what would go without removing anything.
          return json_response(deletion_status(route, existing)) if dry_run?(request) || !Array(delete_options["dryRun"]).empty?

          pending = deferred_deletion(route, namespace, existing, delete_options)
          return json_response(pending) if pending

          existing, expected, waiting = propagate_deletion(route, namespace, existing, expected, delete_options)
          return json_response(existing) if waiting

          remove_deleted_object(route, namespace, existing, expected)
          json_response(deletion_status(route, existing))
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route))
        end

        def delete_collection_response(request, route)
          namespace = storage_namespace(route, operation: :list)
          selectors = selectors_from(request)
          result = @store.list(resource: route.resource, namespace: namespace, selectors: selectors)
          deleted = []
          result.items.each do |object|
            name = metadata_value(object, "name")
            begin
              admit_mutating(request, route, "DELETE", nil, object, namespace, name: name)
              admit_validating(request, route, "DELETE", nil, object, namespace, name: name)
              deleted << delete_one(route.resource, namespace, name, object, pin_version: false)
            rescue MemoryStore::NotFound
              # A concurrent delete has already achieved the requested state.
            end
          end
          json_response(Status.success(
            message: "deleted #{deleted.length} #{route.resource.resource}",
            details: {"group" => route.resource.group, "kind" => route.resource.kind,
                      "names" => deleted.map { |object| metadata_value(object, "name") }}
          ))
        end

        # The resourceVersion and UID preconditions of the query string and
        # DeleteOptions.  Returns the resourceVersion the client pinned, if any.
        def ensure_delete_preconditions!(request, existing, delete_options)
          preconditions = hash_value(delete_options, "preconditions")
          expected = query(request, "resourceVersion")
          expected = hash_value(preconditions, "resourceVersion") if expected.to_s.empty?
          ensure_expected_version!(existing, expected) unless expected.to_s.empty?
          expected_uid = hash_value(preconditions, "uid")
          unless expected_uid.to_s.empty? || expected_uid.to_s == metadata_value(existing, "uid").to_s
            raise Status::Conflict.new(
              "Precondition failed: UID in precondition: #{expected_uid}, " \
              "UID in object meta: #{metadata_value(existing, "uid")}"
            )
          end
          expected
        end

        def deletion_status(route, existing)
          Status.success(details: resource_details(route).merge("uid" => metadata_value(existing, "uid").to_s))
        end

        # Graceful deletion (registry/core/pod/strategy.go#CheckGracefulDelete):
        # a scheduled, non-terminal Pod is not removed on DELETE.  Its
        # deletionTimestamp and deletionGracePeriodSeconds are set, the kubelet
        # stops the containers, and only then is the object removed -- which is
        # why the DELETED watch event carries a deletionTimestamp, as
        # "[sig-node] Pods should be submitted and removed" requires
        # (pods.go:333).  Deleting the object outright skipped all of that.
        #
        # An object with finalizers is likewise only marked.  Returns the
        # object a DELETE that does not remove it yet answers with, nil when
        # it is to be removed now.
        def deferred_deletion(route, namespace, existing, delete_options)
          grace = graceful_deletion_seconds(route.resource, existing, delete_options)
          if grace&.positive? && !metadata_value(existing, "deletionTimestamp")
            object = deep_copy(existing)
            object["metadata"]["deletionTimestamp"] = (@clock.call.utc + grace).iso8601(6)
            object["metadata"]["deletionGracePeriodSeconds"] = grace
            bump_pod_generation_on_delete(route.resource, object)
            return marked_for_deletion(route, namespace, object, existing)
          end

          return nil unless blocking_finalizers(route.resource, existing).any?
          return existing if metadata_value(existing, "deletionTimestamp")

          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] ||= @clock.call.utc.iso8601(6)
          object["status"] = (object["status"] || {}).merge("phase" => "Terminating") if namespace_resource?(route.resource)
          marked_for_deletion(route, namespace, object, existing)
        end

        def marked_for_deletion(route, namespace, object, existing)
          updated = mark_for_deletion_with_retry(route, namespace, object, existing)
          after_commit(route.resource, updated)
          updated
        end

        # Upstream pins the stored resourceVersion ONLY when the client sent
        # Preconditions (registry/generic/registry/store.go#Delete).  Pinning
        # the version this handler happened to read turns an ordinary DELETE of
        # an object something else is updating -- a CronJob whose status the
        # controller is writing, a Pod whose status the kubelet is writing --
        # into "expected resourceVersion N, current is M", which is not an
        # error the client can act on and which no upstream cluster returns.
        def remove_deleted_object(route, namespace, existing, expected)
          begin
            @store.delete(resource: route.resource, namespace: namespace, name: route.name,
                          resource_version: expected.to_s.empty? ? nil : expected)
          rescue MemoryStore::NotFound
            # Once marked as being deleted (before its dependents were
            # released or removed), the object has a deletionTimestamp and no
            # finalizers, so the next write to it -- its own controller's status
            # update, typically -- completes the removal.  This request asked
            # for exactly that; reporting 404 for it made the client believe the
            # delete failed ("failed to delete the rc: ... not found").
            raise unless metadata_value(existing, "deletionTimestamp")
          end
          after_commit(route.resource, existing, deleted: true)
          release_registry_allocations(route.resource, existing)
        end

        # DeleteOptions as the client sent them.  A body wins; a DELETE without
        # one still carries its options in the query string, which is what
        # upstream's ParameterCodec decodes when the body is empty
        # (endpoints/handlers/delete.go: "if len(body) > 0 ... else ...
        # DecodeParameters(req.URL.Query(), ...)").  Reading the body alone meant
        # ?gracePeriodSeconds=0 was ignored, so the DELETE that is supposed to
        # remove an already-terminating object just restarted its grace period.
        DELETE_OPTION_PARAMETERS = %w[gracePeriodSeconds propagationPolicy orphanDependents dryRun].freeze

        def delete_options_for(request)
          # A body or a parameter that cannot be decoded leaves the DELETE
          # without any options.
          best_effort { decoded_delete_options(request) } || {}
        end

        def decoded_delete_options(request)
          body = request_body(request)
          options = body.is_a?(Hash) ? stringify_keys(body) : {}
          DELETE_OPTION_PARAMETERS.each do |name|
            next if options.key?(name)

            value = query(request, name)
            next if value.nil? || value.to_s.empty?

            options[name] = case name
                            when "gracePeriodSeconds" then Integer(value)
                            when "orphanDependents" then %w[true 1].include?(value.to_s.downcase)
                            when "dryRun" then value.to_s.split(",")
                            else value.to_s
                            end
          end
          options
        end

        # nil when the kind has no graceful deletion at all; otherwise the number
        # of seconds the object gets, 0 meaning "remove now".
        GRACEFUL_DELETION_KINDS = %w[Pod].freeze

        def graceful_deletion_seconds(resource, existing, options)
          return nil unless GRACEFUL_DELETION_KINDS.include?(resource.kind.to_s)

          requested = hash_value(options, "gracePeriodSeconds")
          period = if requested.nil?
                     value = Controller::Support.value(Controller::Support.spec(existing), "terminationGracePeriodSeconds", nil)
                     value.nil? ? 0 : Integer(value)
                   else
                     Integer(requested)
                   end
          # An unscheduled or already terminal Pod goes immediately.
          period = 0 if Controller::Support.value(Controller::Support.spec(existing), "nodeName", "").to_s.empty?
          phase = Controller::Support.value(Controller::Support.status(existing), "phase", "").to_s
          period = 0 if %w[Succeeded Failed].include?(phase)
          period = 1 if period.negative?
          period
        rescue ArgumentError, TypeError
          nil
        end

        # Marking an object for deletion is a read-modify-write, so it races with
        # whatever else writes the object.  Upstream's registry retries the whole
        # cycle on a conflict; surfacing it would fail an ordinary DELETE.
        MARK_DELETION_ATTEMPTS = 5

        def mark_owner_deleting(route, namespace, existing, finalizer: nil)
          return existing if metadata_value(existing, "deletionTimestamp")

          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] = @clock.call.utc.iso8601(6)
          add_finalizer(object, finalizer)
          updated = mark_for_deletion_with_retry(route, namespace, object, existing)
          after_commit(route.resource, updated)
          updated
        end

        # The client's resourceVersion precondition was checked before the
        # mark; the mark itself moved the version.  A client that pinned one
        # keeps its optimistic concurrency by pinning the version the mark
        # wrote, so a write landing between the mark and the removal still
        # conflicts.  A plain DELETE pins nothing, as upstream.
        def repin_after_mark(expected, marked)
          return nil if expected.to_s.empty?

          metadata_value(marked, "resourceVersion")
        end

        def add_finalizer(object, finalizer)
          return if finalizer.nil?

          finalizers = Array(object["metadata"]["finalizers"])
          object["metadata"]["finalizers"] = finalizers + [finalizer] unless finalizers.include?(finalizer)
        end

        def mark_for_deletion_with_retry(route, namespace, object, existing)
          attempts = 0
          current = existing
          candidate = object
          begin
            attempts += 1
            @store.update(resource: route.resource, namespace: namespace, name: route.name,
                          object: candidate, resource_version: metadata_value(current, "resourceVersion"))
          rescue MemoryStore::Conflict
            raise if attempts >= MARK_DELETION_ATTEMPTS

            current = @store.get(resource: route.resource, namespace: namespace, name: route.name)
            return current if metadata_value(current, "deletionTimestamp")

            candidate = deep_copy(current)
            candidate["metadata"]["deletionTimestamp"] ||= metadata_value(object, "deletionTimestamp")
            add_finalizer(candidate, FOREGROUND_FINALIZER) if Array(metadata_value(object, "finalizers")).include?(FOREGROUND_FINALIZER)
            if metadata_value(object, "deletionGracePeriodSeconds")
              candidate["metadata"]["deletionGracePeriodSeconds"] ||= metadata_value(object, "deletionGracePeriodSeconds")
              bump_pod_generation_on_delete(route.resource, candidate)
            end
            candidate["status"] = (candidate["status"] || {}).merge("phase" => "Terminating") if namespace_resource?(route.resource)
            retry
          end
        end

        # registry/core/pod/strategy.go (PodObservedGenerationTracking): setting
        # a Pod's deletionTimestamp is a change to its desired state, so the
        # generation moves -- "[sig-node] Pods Extended Pod Generation
        # custom-set generation on new pods and graceful delete" reads 2 after
        # a graceful DELETE.
        def bump_pod_generation_on_delete(resource, object)
          return unless resource.group.to_s.empty? && resource.resource == "pods"

          object["metadata"]["generation"] = object["metadata"]["generation"].to_i + 1
        end

        # +pin_version+: a DELETE of a collection deletes each listed item by
        # name (store.go DeleteCollection calls Delete per item with the
        # client's options, which carry no resourceVersion); pinning the
        # version the listing happened to read turned a Deployment whose status
        # the controller was writing into "expected resourceVersion N, current
        # is M" ("[sig-apps] Deployment should run the lifecycle of a
        # Deployment" deletes via collection).
        def delete_one(resource, namespace, name, object, pin_version: true)
          expected = pin_version ? metadata_value(object, "resourceVersion") : nil
          finalizers = Array(metadata_value(object, "finalizers"))
          if finalizers.any?
            updated = deep_copy(object)
            updated["metadata"]["deletionTimestamp"] ||= @clock.call.utc.iso8601(6)
            @store.update(resource: resource, namespace: namespace, name: name, object: updated,
                          resource_version: expected)
          else
            @store.delete(resource: resource, namespace: namespace, name: name, resource_version: expected)
            release_registry_allocations(resource, object)
          end
        end

        # AfterDelete: allocations return to their pools.
        def release_registry_allocations(resource, object)
          return unless @service_allocator && @service_allocator.service?(resource)

          # The object is gone either way; an allocation that could not be
          # returned is left to the allocator's repair loop.
          best_effort { @service_allocator.release(object) }
        end

        # Namespaces carry their finalizers in spec, not metadata (the legacy
        # shape predates metadata.finalizers), so both lists gate removal.
        def blocking_finalizers(resource, object)
          list = Array(metadata_value(object, "finalizers"))
          list += Array(object.dig("spec", "finalizers")) if namespace_resource?(resource) && object.is_a?(Hash)
          list
        end

        # Once the last finalizer is gone from an object already marked for
        # deletion, the object itself is removed.  That rule belongs to EVERY
        # kind, not just Namespace: registry/generic/registry/store.go
        # updateForGracefulDeletionAndFinalizers deletes immediately when "the
        # object has a deletionTimestamp and no finalizers", and the generic
        # store is what every resource is served from.
        #
        # Restricting it to namespaces left every other finalizer-protected
        # object in the API for ever after its controller had done its work: a
        # PersistentVolumeClaim whose pvc-protection finalizer had been removed
        # stayed Terminating, and every spec that waits for one to disappear
        # timed out.
        def finalize_object_removal(resource, namespace, updated)
          return updated unless metadata_value(updated, "deletionTimestamp")
          return updated unless blocking_finalizers(resource, updated).empty?

          begin
            @store.delete(resource: resource, namespace: namespace, name: metadata_value(updated, "name"),
                          resource_version: metadata_value(updated, "resourceVersion"))
            after_commit(resource, updated, deleted: true)
          rescue MemoryStore::NotFound, MemoryStore::Conflict
            nil
          end
          updated
        end
      end
    end
  end
end
