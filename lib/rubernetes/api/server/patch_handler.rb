# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # PATCH of a resource: JSON, merge and strategic patches and server-side
      # apply, including the create an apply to a missing object turns into.
      module PatchHandler
        private

        # kube-apiserver retries a patch whose document carries no
        # resourceVersion when the object changed between the read and the
        # write (MaxRetryWhenPatchConflicts = 5): the patch is re-applied to the
        # fresh object.  This matters for a replicated store, where the read
        # and the compare-and-swap are not one atomic section.
        MAX_PATCH_CONFLICT_RETRIES = 5

        def patch_response(request, route)
          namespace = storage_namespace(route, operation: :update)
          patch_type = Patch.type_for(request.content_type)
          allowed = supported_patch_types(route.resource)
          unless allowed.value?(patch_type)
            message = "the body of the request was in an unknown format - accepted media types include: #{allowed.keys.join(", ")}"
            raise Status::UnsupportedMediaType.new(message)
          end

          patch_type = :apply if patch_type == :apply_cbor

          validate_write_options!(request, "PatchOptions", patch_type: patch_type)
          patch_document = patch_document(request, patch_type)
          attempts = 0
          begin
            attempts += 1
            apply_patch_once(request, route, namespace, patch_type, patch_document)
          rescue MemoryStore::Conflict => error
            retry if attempts < MAX_PATCH_CONFLICT_RETRIES && !patch_carries_resource_version?(patch_document, patch_type)

            raise stale_update(route), cause: error
          end
        rescue MemoryStore::NotFound
          raise missing_resource(route)
        rescue MemoryStore::AlreadyExists
          raise existing_resource(route, route.name)
        end

        def supported_patch_types(resource)
          Patch::CONTENT_TYPES.reject do |_media_type, type|
            (type == :strategic && resource.custom?) || (type == :apply_cbor && !feature_gate_enabled?("CBORServingAndStorage"))
          end
        end

        # FieldManager.Apply for an apply patch: [merged object, managedFields].
        # A failure that is not an API status is an internal error, as the
        # handler reports it.
        def server_side_apply(request, route, existing, document)
          @field_managers.field_manager(route.resource, route.subresource)
            .apply(live: existing, config: document, manager: query(request, "fieldManager").to_s,
                   force: truthy?(query(request, "force")))
        rescue ManagedFields::FieldManager::Error, ManagedFields::TypedValue::Error, ManagedFields::FieldPath::DecodeError => error
          raise Status::InternalError.new(error.message)
        end

        def patch_carries_resource_version?(patch_document, patch_type)
          if patch_type == :json
            return patch_document.is_a?(Array) && patch_document.any? { |operation| operation.is_a?(Hash) && operation["path"] == "/metadata/resourceVersion" }
          end

          patch_document.is_a?(Hash) && !metadata_value(patch_document, "resourceVersion").to_s.empty?
        end

        def apply_patch_once(request, route, namespace, patch_type, patch_document)
          existing = existing_for_patch(route, namespace, patch_type)
          return scale_patch_response(request, route, existing, namespace, patch_type, patch_document) if route.subresource == "scale"

          patch_document = normalize_apply_document(patch_document, route) if patch_type == :apply
          object, managed_fields = patched_object(request, route, existing, patch_type, patch_document)
          validate_wire_identity!(request, route.resource, object)
          uid = metadata_value(object, "uid")
          if !existing && !uid.to_s.empty?
            raise resource_conflict(route, "uid mismatch: the provided object specified uid #{uid}, and no existing object was found")
          end

          match_request_namespace!(object, route)
          check_update_name!(object, route)
          check_patch_version!(route, existing, object)
          object = preserve_metadata(object, existing) if existing
          object = with_managed_fields(object, managed_fields) if patch_type == :apply
          with_registry_allocations(route) do |allocation|
            object = admitted_for_patch(request, route, existing, object, namespace, patch_type, patch_document, allocation: allocation)
            if dry_run?(request)
              return json_response(written_view(route, dry_run_view(object, namespace)), status: existing ? 200 : 201)
            end

            store_patched(route, namespace, existing, object, allocation: allocation)
          end
        end

        def existing_for_patch(route, namespace, patch_type)
          @store.get(resource: route.resource, namespace: namespace, name: route.name)
        rescue MemoryStore::NotFound
          # handlers/patch.go sets forceAllowCreate for an apply patch, so an
          # apply to a missing object creates it -- but only through the main
          # resource.  A subresource has no create path (the status store's
          # Update never creates), and kube-apiserver answers 404.  Creating
          # here resurrected every namespace the e2e suite had just deleted:
          # the controller manager's status apply for the stale cached
          # Namespace arrived after the finalizer removal had deleted it, and
          # the namespace came back Active with a new uid.  463 of them were
          # left after one conformance round.
          raise missing_resource(route) unless patch_type == :apply && route.subresource.nil?

          nil
        end

        # A patch of /scale is applied to the Scale the parent projects.
        def scale_patch_response(request, route, existing, namespace, patch_type, patch_document)
          raise missing_resource(route) if existing.nil?
          return scale_apply_response(request, route, existing, namespace, patch_document) if patch_type == :apply

          scale_patch_type = patch_type == :strategic ? :merge : patch_type
          patched = Patch.apply(scale_view(existing, route.resource, for_update: true), patch_document,
                                type: scale_patch_type, resource: route.resource)
          scale_update_response(request, route, existing, namespace, patched)
        end

        # [the patched object, the managedFields an apply produced (nil for
        # the other patch types)].
        def patched_object(request, route, existing, patch_type, patch_document)
          object, managed_fields = if patch_type == :apply
                                     server_side_apply(request, route, existing, patch_document)
                                   else
                                     # The Update entry is recorded from the patched
                                     # object's diff below, once it is defaulted.
                                     [Patch.apply(existing, patch_document, type: patch_type, resource: route.resource), nil]
                                   end
          raise Status::Invalid.new("patch must produce a resource object") unless object.is_a?(Hash)

          # The patched document is decoded into the typed object upstream, so
          # a JSON null a merge or strategic patch leaves inside a replaced
          # list (Helm renders `annotations: null` / `selector: null` in a
          # StatefulSet's volumeClaimTemplates) is absent there.  Kept as nil,
          # it made ValidateStatefulSetUpdate see a changed template and refuse
          # every `helm upgrade` of a chart with a StatefulSet.
          if patch_type != :apply
            if route.resource.custom?
              drop_null_fields!(object["metadata"]) if object["metadata"].is_a?(Hash)
            else
              object = SecretData.normalize_request(object) if SecretData.resource?(route.resource)
              Schema::JobSelector.normalize_label_values!(object) if Schema::JobSelector.resource?(route.resource)
              drop_null_fields!(object)
            end
          end
          [object, managed_fields]
        end

        def check_patch_version!(route, existing, object)
          version = metadata_value(object, "resourceVersion")
          current = existing && metadata_value(existing, "resourceVersion")
          return if current && current == version

          expected = parse_update_version(version)
          object.fetch("metadata")["resourceVersion"] = checked_update_version!(route, existing, expected) if existing
        end

        # The patched object as it will be stored, through the same schema,
        # admission and validation steps as a PUT (or a POST when it creates).
        def admitted_for_patch(request, route, existing, object, namespace, patch_type, patch_document, allocation:)
          # fieldValidation applies to PATCH too (handlers/patch.go:162): a strict
          # patch that introduces an unknown field must be refused, exactly as a
          # strict PUT is.  Skipping it here let a patch smuggle in fields that
          # the same body would have been rejected for on update.
          # An apply is validated against the applied configuration, not the
          # merged result: the merged object also carries server-owned fields
          # (status on a resource whose schema does not declare it) that the
          # client never sent and is not answerable for.
          unknown_mode = enforce_field_validation(route.resource, object, request,
                                                  duplicates: request_duplicate_fields(request),
                                                  apply: patch_type == :apply,
                                                  document: patch_type == :apply ? patch_document : nil)
          inherited_labels = Schema::JobSelector.inherited_labels(object) if existing.nil? && Schema::JobSelector.resource?(route.resource)
          object = apply_pre_validation_defaults(route.resource, object) if existing.nil?
          object = default_schema_for_write(route.resource, object, unknown_fields: unknown_mode, old: existing)
          before_mutation = object
          unless patch_type == :apply
            object = before_mutation = with_managed_fields(object,
                                                           record_managed_update(request, route, existing, object))
          end
          object = admit_mutating(request, route, existing ? "UPDATE" : "CREATE", object, existing, namespace)
          object = redefault_after_mutation(route.resource, object, before_mutation, unknown_fields: unknown_mode, operation: existing ? :update : :create)
          return finish_admitted_update(request, route, existing, object, namespace, allocation: allocation) if existing

          candidate = finish_admitted_create(request, route, object, namespace, allocation: allocation, inherited_job_labels: inherited_labels)
          ensure_namespace_exists!(route.resource, namespace)
          candidate
        end

        def store_patched(route, namespace, existing, object, allocation:)
          preconditions = allocation&.write_preconditions || {}
          if existing
            updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                    object: object, resource_version: metadata_value(existing, "resourceVersion"), **preconditions)
            allocation&.commit!
            after_commit(route.resource, updated) if route.subresource.nil?
            finalize_object_removal(route.resource, namespace, updated, existing)
            json_response(written_view(route, updated))
          else
            created = @store.create(resource: route.resource, namespace: namespace, object: object, **preconditions)
            allocation&.commit!
            after_commit(route.resource, created)
            json_response(created, status: 201)
          end
        end

        def patch_document(request, patch_type)
          body = request_body(request)
          raise Status::Invalid.new("JSON Patch body must be an array") if patch_type == :json && !body.is_a?(Array)

          body
        end

        def normalize_apply_document(document, route)
          raise Status::Invalid.new("server-side apply body must be a JSON/YAML object") unless document.is_a?(Hash)

          result = stringify_keys(document)
          validate_route_identity!(result, route)
          result["apiVersion"] ||= route_identity(route).fetch(:api_version)
          result["kind"] ||= route_identity(route).fetch(:kind)
          result["metadata"] = stringify_keys(result["metadata"] || {})
          normalize_null_container_resources!(route.resource, result)
          result
        end
      end
    end
  end
end
