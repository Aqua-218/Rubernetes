# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Defaulting and validation of an object against its resource's schema, the
      # ObjectMeta invariants, and the managedFields a write is recorded with.
      module SchemaApplication
        private

        # ObjectMeta and core invariants beyond the OpenAPI schema; the Status
        # matches apierrors.NewInvalid.
        def validate_object!(resource, object, old: nil)
          kind = resource.kind
          causes = ObjectValidation.validate(kind, object, old: old, namespaced: resource.namespaced?)
          return object if causes.empty?

          name = metadata_value(object, "name")
          details = {
            "name" => name, "group" => resource.group.to_s, "kind" => kind,
            "causes" => causes.map { |cause| {"reason" => cause.reason, "message" => cause.message, "field" => cause.field} }
          }
          raise Status::Invalid.new(ObjectValidation.status_message(kind, name, causes), details: details)
        end

        # Not every schema contract accepts a field-validation directive; the ones
        # that do drop undeclared fields, the ones that do not keep their own default.
        def apply_defaulting(target, object, unknown_fields, old = nil)
          if old && target.method(:default).parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :old }
            return target.default(object, unknown_fields: unknown_fields, old: old)
          end

          target.default(object, unknown_fields: unknown_fields)
        rescue ArgumentError
          target.default(object)
        end

        # A mutating webhook adds fields the client never sent -- a whole
        # container, in the conformance spec "should mutate pod and apply
        # defaults after mutation" -- and upstream defaults the patched object
        # again before anything else looks at it
        # (admission/plugin/webhook/mutating/patch.go).  Without that the added
        # container has no terminationMessagePolicy, no imagePullPolicy and no
        # resources.
        def redefault_after_mutation(resource, object, before, unknown_fields: :preserve)
          return object unless object.is_a?(Hash) && object != before

          apply_defaults_only(resource, object, unknown_fields: unknown_fields)
        end

        def apply_defaults_only(resource, object, unknown_fields: :preserve, old: nil)
          schema = resource.schema
          defaulting = schema_hash_defaulting(schema)
          if defaulting
            defaulting.apply_hash(object, unknown_fields: unknown_fields, kubernetes_admission_defaults: true, old: old)
          elsif schema_defaults?(schema)
            apply_defaulting(schema, object, unknown_fields, old)
          else
            object
          end
        end

        def apply_schema(resource, object, operation: nil, old: nil, unknown_fields: :preserve, subresource: nil)
          # Only a stored object in this very version is a defaulted baseline:
          # a view converted from another storage version was defaulted
          # against that version's schema.
          baseline = if operation.to_s.casecmp?("update") && old.is_a?(Hash) && old.frozen?
                       wanted = resource.group.to_s.empty? ? resource.version.to_s : "#{resource.group}/#{resource.version}"
                       old if old["apiVersion"].to_s == wanted
                     end
          result = apply_defaults_only(resource, object, unknown_fields: unknown_fields, old: baseline)
          validator = schema_validator(resource.schema)
          return result unless validator

          validation = validator.validate(result, unknown_fields: :preserve,
                                                  operation: operation, old: old, subresource: subresource)
          raise Status::Invalid.new("resource validation failed") if validation == false
          raise invalid_resource(resource, result, validation) if validation.is_a?(Array) && !validation.empty?

          result
        end

        # apierrors.NewInvalid for the causes a schema validator reported.
        def invalid_resource(resource, object, validation)
          causes = validation.map { |cause| validation_cause(cause, object) }
          rendered = causes.map { |cause| [cause["field"], cause["message"]].compact.join(": ") }
          name = metadata_value(object, "name")
          body = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
          qualified = resource.group.to_s.empty? ? resource.kind : "#{resource.kind}.#{resource.group}"
          Status::Invalid.new("#{qualified} #{name.to_s.inspect} is invalid: #{body}",
                              details: {"name" => name, "group" => resource.group.to_s, "kind" => resource.kind,
                                        "causes" => causes})
        end

        # fieldmanager.UpdateNoErrors for a write that is not an apply: the
        # managed fields the object is stored with (nil for none), from the
        # live object and the one written -- decoded and defaulted, before
        # mutating admission, where upstream's handlers run it.
        def record_managed_update(request, route, existing, object)
          @field_managers.field_manager(route.resource, route.subresource)
            .update(live: existing, new_object: object, manager: update_manager(request))
        end

        # The object with +managed_fields+ as its metadata.managedFields (none
        # when empty).  Stored objects are frozen, so nothing is changed in place.
        def with_managed_fields(object, managed_fields)
          return object unless object.is_a?(Hash)

          metadata = object["metadata"].is_a?(Hash) ? object["metadata"] : {}
          metadata = if managed_fields.nil? || managed_fields.empty?
                       metadata.except("managedFields")
                     else
                       metadata.merge("managedFields" => managed_fields)
                     end
          object.merge("metadata" => metadata)
        end
      end
    end
  end
end
