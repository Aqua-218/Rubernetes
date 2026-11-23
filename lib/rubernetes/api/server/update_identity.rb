# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # A replacement carries a storage precondition. A patch builds its
      # candidate from the live object and the registry validates its UID.
      module UpdateIdentity
        private

        CORE_STORAGE_PREFIXES = {"replicationcontrollers" => "controllers", "endpoints" => "services/endpoints",
                                 "nodes" => "minions", "services" => "services/specs"}.freeze

        def update_storage_key(route)
          resource = route.resource
          prefix = if resource.custom?
                     "#{resource.group}/#{resource.resource}"
                   elsif resource.group.to_s.empty?
                     CORE_STORAGE_PREFIXES.fetch(resource.resource, resource.resource)
                   elsif resource.group == "networking.k8s.io" && resource.resource == "ingresses"
                     "ingress"
                   else
                     resource.resource
                   end
          File.join("/", *[prefix, route.namespace, route.name].compact)
        end

        def check_storage_uid!(route, existing, object)
          conflict = uid_mismatch(existing, object)
          return unless conflict

          detail = "StorageError: invalid object, Code: 4, Key: #{update_storage_key(route)}, ResourceVersion: 0, AdditionalErrorMsg: #{conflict}"
          raise resource_conflict(route, detail)
        end

        def check_scale_uid!(route, existing, scale)
          conflict = uid_mismatch(existing, scale)
          return unless conflict

          raise resource_conflict(route, conflict, subresource: "scale")
        end

        def uid_mismatch(existing, candidate)
          uid = metadata_value(candidate, "uid")
          current = metadata_value(existing, "uid")
          return if uid.to_s.empty? || uid == current

          "Precondition failed: UID in precondition: #{uid}, UID in object meta: #{current}"
        end

        def immutable_uid_causes(old, object)
          uid = metadata_value(object, "uid")
          return if uid.to_s.empty? || uid == metadata_value(old, "uid")

          message = "Invalid value: #{ManagedFields::Value.go_quote(uid.to_s)}: field is immutable"
          cause = {"reason" => "FieldValueInvalid", "field" => "metadata.uid", "message" => message}
          # BeforeUpdate runs both common and strategy metadata validation.
          [cause, cause]
        end
      end
    end
  end
end
