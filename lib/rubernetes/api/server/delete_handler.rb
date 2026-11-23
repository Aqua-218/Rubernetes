# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # DELETE of a resource or a collection: delete options and preconditions,
      # graceful deletion, finalizers, and the removal itself.
      module DeleteHandler
        UNSAFE_DELETE_OPTION = "ignoreStoreReadErrorWithClusterBreakingPotential"
        UNSAFE_DELETE_VERB = "unsafe-delete-ignore-read-errors"
        UNSAFE_DELETE_ANNOTATION = "apiserver.k8s.io/unsafe-delete-ignore-read-error"

        private

        def delete_response(request, route)
          namespace = storage_namespace(route, operation: :delete)
          delete_options = delete_options_for(request)
          return unsafe_delete_response(request, route, namespace, delete_options) if unsafe_delete?(delete_options)

          delete_member(request, route, namespace, delete_options)
        rescue MemoryStore::NotFound
          raise missing_resource(route)
        end

        # A UID-only precondition follows the same object through concurrent
        # writes. Bind the final remove to its observed revision and check the
        # UID again after a conflict so a replacement cannot be removed.
        def delete_member(request, route, namespace, options, collection: false)
          attempts = 0
          begin
            attempts += 1
            existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
            expected = ensure_delete_preconditions!(request, existing, options, collection: collection)
            uid_only = !options.dig("preconditions", "uid").nil? && expected.to_s.empty?
            expected = metadata_value(existing, "resourceVersion") if uid_only
            delete_existing(request, route, namespace, existing, options, expected, uid_only: uid_only)
          rescue MemoryStore::Conflict
            retry if uid_only && attempts < MARK_DELETION_ATTEMPTS

            raise
          end
        end

        def delete_existing(request, route, namespace, existing, options, expected, uid_only:)
          preview = Array(options["dryRun"]).include?("All")
          admit_mutating(request, route, "DELETE", nil, existing, namespace, dry_run: preview)
          admit_validating(request, route, "DELETE", nil, existing, namespace, dry_run: preview)
          pending_status = options["orphanDependents"] == false ? 202 : 200
          if @crd_manager && crd_resource?(route.resource) && !metadata_value(existing, "deletionTimestamp")
            marked = mark_crd_terminating(route, existing, namespace, dry_run: preview)
            schedule_crd_finalizer(route.name) unless preview
            return json_response(marked, status: pending_status)
          end

          newly_deleting = !metadata_value(existing, "deletionTimestamp")
          existing, pending = prepare_deletion(route, namespace, existing, options, dry_run: preview, expected: expected)
          if pending
            process_gc_dependents(route, namespace, existing) if newly_deleting && !preview
            return json_response(existing, status: pending_status)
          end
          return json_response(deleted_view(route, existing)) if preview

          expected = repin_after_mark(expected, existing)
          existing, expected = propagate_background_deletion(route, namespace, existing, expected)

          removed = remove_deleted_object(route, namespace, existing, expected, uid_only: uid_only)
          json_response(deleted_view(route, removed, from_storage: true))
        end

        def delete_collection_response(request, route)
          options = delete_options_for(request)
          raise invalid_unsafe_delete("is not allowed with DELETECOLLECTION, try again after removing the option") if unsafe_delete?(options)

          namespace = storage_namespace(route, operation: :list)
          selectors = selectors_from(request)
          validate_list_options!(request)
          result = list_page(request, route, namespace, selectors)
          result.items.each do |object|
            member = route.dup
            member.name = metadata_value(object, "name")
            member_namespace = route.resource.namespaced? ? metadata_value(object, "namespace") : namespace
            begin
              delete_member(request, member, member_namespace, options, collection: true)
            rescue MemoryStore::NotFound
              # A concurrent delete has already removed this member.
            end
          end
          json_response(list_payload(route, result, selectors))
        end

        def unsafe_delete?(options)
          return false unless feature_gate_enabled?("AllowUnsafeMalformedObjectDeletion")

          value = options[UNSAFE_DELETE_OPTION]
          raise Status::BadRequest.new("#{UNSAFE_DELETE_OPTION} must be a boolean") if !value.nil? && value != true && value != false

          value == true
        end

        def unsafe_delete_response(request, route, namespace, options)
          conflicts = %w[propagationPolicy orphanDependents gracePeriodSeconds preconditions].reject { |key| options[key].nil? }
          conflicts << "dryRun" unless Array(options["dryRun"]).empty?
          conflicts << "resourceVersion" unless query(request, "resourceVersion").to_s.empty?
          raise invalid_unsafe_delete(conflicts.map { |field| "cannot be set together with .#{field}" }) unless conflicts.empty?

          Thread.current[AUDIT_KEY]&.annotate(UNSAFE_DELETE_ANNOTATION, "")
          authorize_unsafe_delete!(request)
          @store.delete_corrupt(resource: route.resource, namespace: namespace, name: route.name)
          json_response(Status.success(details: resource_details(route)))
        rescue Rubernetes::Storage::ObjectNotCorrupt
          raise invalid_unsafe_delete("is exclusively used to delete corrupt object(s), try again by removing this option", route: route)
        end

        def authorize_unsafe_delete!(request)
          attributes = request.attributes
          authorizer = @security&.authorizer
          decision = if authorizer && attributes&.resource_request? && attributes.subresource.empty?
                       best_effort { authorizer.authorize(attributes.with_verb(UNSAFE_DELETE_VERB)) }
                     end
          return if decision&.allowed?

          raise Status::Forbidden.new(%(not permitted to do "#{UNSAFE_DELETE_VERB}" on this resource))
        end

        def invalid_unsafe_delete(messages, route: nil)
          details = route ? resource_details(route).merge("name" => route.name) : {"group" => "meta.k8s.io", "kind" => "DeleteOptions"}
          causes = Array(messages).map do |message|
            {"reason" => "FieldValueInvalid", "field" => UNSAFE_DELETE_OPTION, "message" => "Invalid value: true: #{message}"}
          end
          message = causes.map { |cause| "#{cause.fetch("field")}: #{cause.fetch("message")}" }.join(", ")
          Status::Invalid.new(message, details: details.merge("causes" => causes))
        end

        # The resourceVersion and UID preconditions of the query string and
        # DeleteOptions.  Returns the resourceVersion the client pinned, if any.
        def ensure_delete_preconditions!(request, existing, delete_options, collection:)
          preconditions = hash_value(delete_options, "preconditions")
          expected = query(request, "resourceVersion") unless collection
          expected = hash_value(preconditions, "resourceVersion") if expected.to_s.empty?
          ensure_expected_version!(existing, expected) unless expected.to_s.empty?
          expected_uid = hash_value(preconditions, "uid")
          unless expected_uid.nil? || expected_uid == metadata_value(existing, "uid")
            raise Status::Conflict.new(
              "Precondition failed: UID in precondition: #{expected_uid}, " \
              "UID in object meta: #{metadata_value(existing, "uid")}"
            )
          end
          expected
        end

        # Registry stores with ReturnDeletedObject set return the removed API
        # object even for an immediate delete. Other stores return a Status.
        RETURN_DELETED_OBJECT = {
          "" => %w[namespaces persistentvolumeclaims persistentvolumes pods podtemplates resourcequotas serviceaccounts services],
          "resource.k8s.io" => %w[deviceclasses devicetaintrules resourceclaims resourceclaimtemplates resourcepoolstatusrequests resourceslices],
          "storage.k8s.io" => %w[csidrivers csinodes storageclasses volumeattachments volumeattributesclasses]
        }.freeze

        def deleted_view(route, existing, from_storage: false)
          if RETURN_DELETED_OBJECT.fetch(route.resource.group.to_s, []).include?(route.resource.resource)
            return from_storage ? @store.convert_out(route.resource, existing) : existing
          end

          Status.success(details: resource_details(route).merge("uid" => metadata_value(existing, "uid").to_s))
        end

        # The registry's two phases are visible to both ordinary and dry-run
        # clients. A force delete still returns the newly marked Pod.
        def prepare_deletion(route, namespace, existing, options, dry_run:, expected:)
          attempts = 0
          original_uid = metadata_value(existing, "uid")
          begin
            attempts += 1
            candidate, pending = deletion_state(route.resource, existing, options)
            return [candidate, pending] if dry_run || candidate.equal?(existing)

            updated = @store.update(resource: route.resource, namespace: namespace, name: route.name, object: candidate,
                                    resource_version: metadata_value(existing, "resourceVersion"))
            after_commit(route.resource, updated)
            [updated, pending]
          rescue MemoryStore::Conflict
            raise if attempts >= MARK_DELETION_ATTEMPTS || !expected.to_s.empty?

            existing = @store.get(resource: route.resource, namespace: namespace, name: route.name)
            raise Status::Conflict.new("object was replaced during deletion") unless metadata_value(existing, "uid") == original_uid

            retry
          end
        end

        def deletion_state(resource, existing, options)
          existing = with_gc_finalizers(resource, existing, options) unless metadata_value(existing, "deletionTimestamp")
          protected = blocking_finalizers(resource, existing).any?
          if GRACEFUL_DELETION_KINDS.include?(resource.kind.to_s) && resource.group.to_s.empty?
            object, waiting = pod_deletion_state(resource, existing, options)
            return [object, waiting || protected]
          end
          return [existing, false] unless protected
          return [existing, true] if metadata_value(existing, "deletionTimestamp")

          object = deep_copy(existing)
          metadata = object.fetch("metadata")
          metadata["deletionTimestamp"] = @clock.call.utc.iso8601
          if namespace_resource?(resource)
            object["status"] = (object["status"] || {}).merge("phase" => "Terminating")
          else
            metadata["deletionGracePeriodSeconds"] = 0
            metadata["generation"] += 1 if metadata["generation"].to_i.positive?
          end
          [object, true]
        end

        def pod_deletion_state(resource, existing, options)
          now = @clock.call.utc
          timestamp = metadata_value(existing, "deletionTimestamp")
          if timestamp
            original = metadata_value(existing, "deletionGracePeriodSeconds").to_i
            return [existing, false] if original.zero?

            requested = options["gracePeriodSeconds"]
            return [existing, true] if requested.nil? || requested >= original

            period = requested.negative? ? 1 : requested
            deadline = Time.iso8601(timestamp) - original + period
            if deadline < now
              deadline = now
              period = 1 if period.positive?
            end
          else
            period = graceful_deletion_seconds(resource, existing, options)
            deadline = now + period
          end
          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] = deadline.iso8601
          object["metadata"]["deletionGracePeriodSeconds"] = period
          bump_pod_generation_on_delete(resource, object) unless timestamp
          [object, period.positive?]
        end

        # Upstream pins the stored resourceVersion ONLY when the client sent
        # Preconditions (registry/generic/registry/store.go#Delete).  Pinning
        # the version this handler happened to read turns an ordinary DELETE of
        # an object something else is updating -- a CronJob whose status the
        # controller is writing, a Pod whose status the kubelet is writing --
        # into "expected resourceVersion N, current is M", which is not an
        # error the client can act on and which no upstream cluster returns.
        def remove_deleted_object(route, namespace, existing, expected, uid_only: false)
          removed = delete_pinned_object(route, namespace, existing, expected, uid_only: uid_only)
          after_commit(route.resource, removed, deleted: true)
          release_registry_allocations(route.resource, removed)
          removed
        end

        def delete_pinned_object(route, namespace, existing, expected, uid_only:)
          attempts = 0
          begin
            attempts += 1
            @store.delete(resource: route.resource, namespace: namespace, name: route.name,
                          resource_version: expected.to_s.empty? ? nil : expected)
          rescue MemoryStore::Conflict
            raise unless uid_only && metadata_value(existing, "deletionTimestamp") && attempts < MARK_DELETION_ATTEMPTS

            current = @store.get(resource: route.resource, namespace: namespace, name: route.name)
            raise unless metadata_value(current, "uid") == metadata_value(existing, "uid") && blocking_finalizers(route.resource, current).empty?

            expected = metadata_value(current, "resourceVersion")
            retry
          end
        rescue MemoryStore::NotFound
          # A status write can move the revision and then finish removing
          # the marked owner before this request re-reads it. The original
          # deletion has completed, even when the first storage attempt
          # reported a conflict rather than NotFound.
          raise unless metadata_value(existing, "deletionTimestamp")

          existing
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
          options = if request.body.nil? || request.body == ""
                      delete_query_options(request)
                    else
                      body = request_body(request)
                      raise Status::BadRequest.new("request body must be a DeleteOptions object") unless body.is_a?(Hash)

                      stringify_keys(body)
                    end
          options.delete(UNSAFE_DELETE_OPTION) unless feature_gate_enabled?("AllowUnsafeMalformedObjectDeletion")
          validate_delete_options!(options)
          options
        end

        def validate_delete_options!(options)
          validate_delete_option_types!(options)
          issues = Schema::KubernetesValidator.delete_options_errors(options)
          invalid_write_options!("DeleteOptions", issues.map { |issue| delete_options_cause(options, issue) })
        end

        def validate_delete_option_types!(options)
          version = options["apiVersion"]
          raise Status::BadRequest.new("apiVersion must be a string") unless version.nil? || version.is_a?(String)

          kind = options["kind"]
          raise Status::BadRequest.new("decoded object cannot be converted to DeleteOptions") unless kind.nil? || kind == "" || kind == "DeleteOptions"

          dry_run = options["dryRun"]
          raise Status::BadRequest.new("dryRun must be an array of strings") unless dry_run.nil? || (dry_run.is_a?(Array) && dry_run.all?(String))

          policy = options["propagationPolicy"]
          raise Status::BadRequest.new("propagationPolicy must be a string") unless policy.nil? || policy.is_a?(String)

          grace = options["gracePeriodSeconds"]
          unless grace.nil? || (grace.is_a?(Integer) && grace.between?(-(2**63), (2**63) - 1))
            raise Status::BadRequest.new("gracePeriodSeconds must be an int64")
          end

          orphan = options["orphanDependents"]
          raise Status::BadRequest.new("orphanDependents must be a boolean") unless [nil, true, false].include?(orphan)

          preconditions = options["preconditions"]
          return if preconditions.nil?
          return if preconditions.is_a?(Hash) && preconditions.values_at("uid", "resourceVersion").all? { |value| value.nil? || value.is_a?(String) }

          raise Status::BadRequest.new("preconditions must be an object with string uid and resourceVersion")
        end

        def delete_query_options(request)
          parameters = DELETE_OPTION_PARAMETERS
          parameters = [*parameters, UNSAFE_DELETE_OPTION] if feature_gate_enabled?("AllowUnsafeMalformedObjectDeletion")
          parameters.each_with_object({}) do |name, options|
            value = query(request, name)
            next if value.nil?

            options[name] = case name
                            when "gracePeriodSeconds" then Integer(value, 10)
                            when "orphanDependents", UNSAFE_DELETE_OPTION
                              raise Status::BadRequest.new("#{name} must be a boolean") unless WriteOptions::GO_BOOLS.include?(value.to_s)

                              %w[1 t true].include?(value.to_s.downcase)
                            when "dryRun" then Array(request.query_values(name))
                            else value.to_s
                            end
          end
        rescue ArgumentError
          raise Status::BadRequest.new("gracePeriodSeconds must be an integer")
        end

        # nil when the kind has no graceful deletion at all; otherwise the number
        # of seconds the object gets, 0 meaning "remove now".
        GRACEFUL_DELETION_KINDS = %w[Pod].freeze

        def graceful_deletion_seconds(resource, existing, options)
          return nil unless GRACEFUL_DELETION_KINDS.include?(resource.kind.to_s)

          requested = hash_value(options, "gracePeriodSeconds")
          period = if requested.nil?
                     value = existing.dig("spec", "terminationGracePeriodSeconds")
                     value.nil? ? 0 : Integer(value)
                   else
                     Integer(requested)
                   end
          # An unscheduled or already terminal Pod goes immediately.
          period = 0 if existing.dig("spec", "nodeName").to_s.empty?
          phase = existing.dig("status", "phase").to_s
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

        def mark_owner_deleting(route, namespace, existing, expected:, finalizer: nil)
          return existing if metadata_value(existing, "deletionTimestamp")

          object = deep_copy(existing)
          object["metadata"]["deletionTimestamp"] = @clock.call.utc.iso8601(6)
          add_finalizer(object, finalizer)
          updated = mark_for_deletion_with_retry(route, namespace, object, existing, expected: expected)
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

        def mark_for_deletion_with_retry(route, namespace, object, existing, expected:)
          attempts = 0
          current = existing
          candidate = object
          begin
            attempts += 1
            @store.update(resource: route.resource, namespace: namespace, name: route.name,
                          object: candidate, resource_version: metadata_value(current, "resourceVersion"))
          rescue MemoryStore::Conflict
            # UID-pinned requests re-enter delete_member, where the UID is
            # checked again. An explicit version is never advanced by a retry.
            raise if attempts >= MARK_DELETION_ATTEMPTS || !expected.to_s.empty?

            current = @store.get(resource: route.resource, namespace: namespace, name: route.name)
            raise Status::Conflict.new("object was replaced during deletion") unless metadata_value(current, "uid") == metadata_value(existing, "uid")
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
        def finalize_object_removal(resource, namespace, updated, existing)
          return updated unless metadata_value(existing, "deletionTimestamp")
          return updated if metadata_value(existing, "deletionGracePeriodSeconds").to_i.positive?
          return updated unless blocking_finalizers(resource, updated).empty?

          begin
            removed = @store.delete(resource: resource, namespace: namespace, name: metadata_value(updated, "name"),
                                    resource_version: metadata_value(updated, "resourceVersion"))
            after_commit(resource, updated, deleted: true)
            release_registry_allocations(resource, removed)
          rescue MemoryStore::NotFound, MemoryStore::Conflict
            nil
          end
          updated
        end
      end
    end
  end
end
