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
          content_type = request.content_type
          patch_type = Patch.type_for(content_type)
          raise Status::UnsupportedMediaType.new("unsupported patch content type #{content_type.inspect}") if patch_type.nil? || patch_type == :apply_cbor

          validate_write_options!(request, "PatchOptions", patch_type: patch_type)
          patch_document = patch_document(request, patch_type)
          attempts = 0
          begin
            attempts += 1
            apply_patch_once(request, route, namespace, patch_type, patch_document)
          rescue MemoryStore::Conflict => error
            retry if attempts < MAX_PATCH_CONFLICT_RETRIES && !patch_carries_resource_version?(patch_document, patch_type)

            raise Status::Conflict.new("#{route.resource.kind} #{route.name.inspect} changed during patch",
                                       details: resource_details(route)), cause: error
          end
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                     details: resource_details(route))
        rescue MemoryStore::AlreadyExists
          raise Status::AlreadyExists.new("#{route.resource.resource} #{route.name.inspect} already exists",
                                          details: resource_details(route))
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
          return false unless patch_document.is_a?(Hash)

          if patch_type == :json
            Array(patch_document).any? { |operation| operation.is_a?(Hash) && operation["path"].to_s == "/metadata/resourceVersion" }
          else
            value = patch_document.dig("metadata", "resourceVersion")
            !(value.nil? || value.to_s.empty?)
          end
        end

        def apply_patch_once(request, route, namespace, patch_type, patch_document)
          existing = existing_for_patch(route, namespace, patch_type)
          return scale_patch_response(request, route, existing, namespace, patch_type, patch_document) if route.subresource == "scale"

          patch_document = normalize_apply_document(patch_document, route) if patch_type == :apply
          object, managed_fields = patched_object(request, route, existing, patch_type, patch_document)
          ensure_name!(object, route.name)
          if existing.nil? && namespace != :cluster && namespace != :all
            object["metadata"] ||= {}
            object["metadata"]["namespace"] = namespace
          end
          ensure_patch_preconditions!(existing, object, patch_document)
          object = preserve_metadata(object, existing) if existing
          object = with_managed_fields(object, managed_fields) if patch_type == :apply
          object = prepare_patch_create(route, object) if existing.nil?
          object = apply_subresource_strategy(route, existing, object) if existing
          object = admitted_for_patch(request, route, existing, object, namespace, patch_type, patch_document)
          if dry_run?(request)
            return json_response(written_view(route, dry_run_view(object, namespace)), status: existing ? 200 : 201)
          end

          store_patched(route, namespace, existing, object)
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
          unless patch_type == :apply && route.subresource.nil?
            raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                       details: resource_details(route))
          end
          nil
        end

        # A patch of /scale is applied to the Scale the parent projects.
        def scale_patch_response(request, route, existing, namespace, patch_type, patch_document)
          if existing.nil?
            raise Status::NotFound.new("#{route.resource.resource} #{route.name.inspect} not found",
                                       details: resource_details(route))
          end
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
              drop_null_fields!(object)
            end
          end
          [object, managed_fields]
        end

        def ensure_patch_preconditions!(existing, object, patch_document)
          patch_resource_version = metadata_value(object, "resourceVersion")
          if existing && patch_resource_version && patch_resource_version.to_s != metadata_value(existing, "resourceVersion").to_s
            raise Status::Conflict.new("resourceVersion #{patch_resource_version.inspect} does not match current " \
                                       "#{metadata_value(existing, "resourceVersion").inspect}")
          end

          # A patch that names a metadata.uid is a precondition on the object's
          # identity (upstream: "Precondition failed: UID in precondition ...",
          # 409).  A node's status report for a Pod it was starting otherwise
          # landed on the NEXT Pod of the same name: a StatefulSet recreating
          # ss-0 every 300 ms had each new incarnation marked Failed by its
          # predecessor's report and deleted again, 776 times in four minutes.
          patch_uid = patch_document.is_a?(Hash) ? patch_document.dig("metadata", "uid") : nil
          return unless existing && patch_uid && !patch_uid.to_s.empty? && patch_uid.to_s != metadata_value(existing, "uid").to_s

          raise Status::Conflict.new(
            "Precondition failed: UID in precondition: #{patch_uid}, UID in object meta: #{metadata_value(existing, "uid")}"
          )
        end

        def prepare_patch_create(route, object)
          object = prepare_created_metadata(object, resource: route.resource)
          # Server-side apply and a patch that creates take the same registry
          # PrepareForCreate hooks as POST; skipping them here made an applied
          # object differ from a posted one.
          object = prepare_registry_create(route.resource, object)
          merge_label_keys!(object) if pod_resource?(route.resource)
          object
        end

        # The patched object as it will be stored, through the same schema,
        # admission and validation steps as a PUT (or a POST when it creates).
        def admitted_for_patch(request, route, existing, object, namespace, patch_type, patch_document)
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
          object = apply_schema(route.resource, object,
                                operation: existing ? :update : :create, old: existing,
                                unknown_fields: unknown_mode, subresource: route.subresource)
          object = prepare_registry_update(route.resource, existing, object) if existing && route.subresource.nil?
          before_mutation = object
          unless patch_type == :apply
            object = before_mutation = with_managed_fields(object,
                                                           record_managed_update(request, route, existing, object))
          end
          object = admit_mutating(request, route, existing ? "UPDATE" : "CREATE", object, existing, namespace)
          object = redefault_after_mutation(route.resource, object, before_mutation, unknown_fields: unknown_mode)
          object = inject_csr_requester(request, route.resource, object) if existing.nil?
          authorize_resource_claim_status!(request, route, existing, object) if existing
          validate_object!(route.resource, object, old: existing) unless route.subresource == "status"
          admit_validating(request, route, existing ? "UPDATE" : "CREATE", object, existing, namespace)
          ensure_namespace_exists!(route.resource, namespace) if existing.nil?
          apply_generation(object, existing, subresource: route.subresource, resource: route.resource)
        end

        def store_patched(route, namespace, existing, object)
          if existing
            updated = @store.update(resource: route.resource, namespace: namespace, name: route.name,
                                    object: object, resource_version: metadata_value(existing, "resourceVersion"))
            after_commit(route.resource, updated) if route.subresource.nil?
            finalize_object_removal(route.resource, namespace, updated)
            json_response(written_view(route, updated))
          else
            created = @store.create(resource: route.resource, namespace: namespace, object: object)
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
          result["metadata"]["name"] ||= route.name
          result
        end
      end
    end
  end
end
