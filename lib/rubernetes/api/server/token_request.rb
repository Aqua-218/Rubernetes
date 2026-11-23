# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Short-lived credentials issued by the ServiceAccount token subresource.
      module TokenRequest
        private

        # pkg/registry/core/serviceaccount/storage/token.go: TokenRequest on the
        # serviceaccounts/token subresource.  The service account must exist,
        # a bound object must exist with the given UID, and the issuer signs a
        # bound token whose expiration is returned in status.
        def token_request_response(request, route)
          raise Status::NotFound.new("the server could not find the requested resource") if @service_account_issuer.nil?

          namespace = storage_namespace(route, operation: :get)
          validate_write_options!(request, "CreateOptions")
          document = decode_token_request(request)
          match_request_namespace!(document, route)
          options = {gvk: %w[authentication.k8s.io v1 TokenRequest], name: route.name}
          document = admit_mutating(request, route, "CREATE", document, nil, namespace, **options)
          match_request_namespace!(document, route)
          name = metadata_value(document, "name")
          if !name.to_s.empty? && name != route.name
            invalid_token_request!("metadata.name", name, "must match the service account name if specified", name: route.name)
          end

          account = @store.get(resource: route.resource, namespace: namespace, name: route.name)
          ensure_token_request_uid!(document, account, route)
          created_at = default_token_request!(document, account, route)
          admit_validating(request, route, "CREATE", document, nil, namespace, **options)
          spec = document.fetch("spec")
          bound_object = token_bound_object(spec["boundObjectRef"], namespace, route.name)
          requested = spec.fetch("expirationSeconds")
          capped = @service_account_issuer.limit_expiration_seconds(requested)
          if capped < requested
            request_warnings(request) << "requested expiration of #{requested} seconds shortened to #{capped} seconds"
            spec["expirationSeconds"] = capped
          end
          begin
            token, = @service_account_issuer.issue(namespace: namespace, service_account_name: route.name,
                                                   service_account_uid: metadata_value(account, "uid").to_s,
                                                   audiences: spec["audiences"], expiration_seconds: requested,
                                                   bound_object: bound_object)
          rescue ArgumentError => error
            raise Status::Invalid.new("TokenRequest is invalid: #{error.message}")
          end
          expiration = created_at + capped
          document["status"] = {"token" => token, "expirationTimestamp" => expiration.iso8601}
          json_response(document, status: 201)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("serviceaccounts #{route.name.inspect} not found", details: resource_details(route))
        end

        def decode_token_request(request)
          body = request_body(request)
          raise Status::BadRequest.new("request body must be a TokenRequest") unless body.is_a?(Hash)

          document = stringify_keys(body)
          identity = {kind: "TokenRequest", api_version: "authentication.k8s.io/v1"}
          document["kind"] = identity[:kind] if document["kind"].to_s.empty?
          document["apiVersion"] = identity[:api_version] if document["apiVersion"].to_s.empty?
          reject_mismatched_builtin!(document, identity) unless document["kind"] == identity[:kind] && document["apiVersion"] == identity[:api_version]
          resource = @token_request_resource ||= typed_subresource("authentication.k8s.io", "v1", "TokenRequest", "tokenrequests")
          mode = enforce_field_validation(resource, document, request, duplicates: request_duplicate_fields(request))
          deep_copy(resource.schema.defaulting.apply_hash(document, unknown_fields: mode))
        end

        def default_token_request!(document, account, route)
          metadata = document.fetch("metadata")
          metadata["name"] = route.name
          metadata["uid"] = metadata_value(account, "uid") if metadata["uid"].to_s.empty?
          created_at = @clock.call.utc
          metadata["creationTimestamp"] = created_at.iso8601
          spec = document["spec"] ||= {}
          raise Status::BadRequest.new("spec must be an object") unless spec.is_a?(Hash)

          spec["audiences"] = @service_account_issuer.api_audiences if Array(spec["audiences"]).empty?
          seconds = spec["expirationSeconds"] ||= Security::Authentication::ServiceAccount::DEFAULT_EXPIRATION_SECONDS
          raise Status::BadRequest.new("spec.expirationSeconds must be an integer") unless seconds.is_a?(Integer)

          invalid_token_request!("spec.expirationSeconds", seconds, "may not specify a duration less than 10 minutes") if seconds < 600
          if seconds > Security::Authentication::ServiceAccount::MAX_EXPIRATION_SECONDS
            invalid_token_request!("spec.expirationSeconds", seconds, "may not specify a duration larger than 2^32 seconds")
          end
          spec["boundObjectRef"] ||= nil
          document.delete("status")
          created_at
        end

        # TokenRequestServiceAccountUIDValidation (Beta, on): a request for
        # another incarnation of the ServiceAccount is a conflict.
        def ensure_token_request_uid!(body, account, route)
          requested_uid = body.dig("metadata", "uid").to_s
          account_uid = metadata_value(account, "uid").to_s
          return if requested_uid.empty? || requested_uid == account_uid

          detail = "the UID in the token request (#{requested_uid}) does not match the UID of the service account (#{account_uid})"
          raise Status::Conflict.new(%(Operation cannot be fulfilled on TokenRequest.authentication.k8s.io "#{route.name}": #{detail}),
                                     details: {"name" => route.name, "group" => "authentication.k8s.io", "kind" => "TokenRequest"})
        end

        # The Pod, Secret or Node a token is bound to, as the issuer takes it:
        # the object must exist, with the UID the request names.  nil for a
        # token bound to nothing.
        def token_bound_object(bound, namespace, account_name)
          return nil if bound.nil?

          kind = bound["kind"].to_s
          version = bound["apiVersion"].to_s
          if version.include?("/") || !%w[Pod Secret Node].include?(kind)
            gvk = version.include?("/") ? version : "/#{version}"
            raise Status::BadRequest.new("cannot bind token to object of type #{gvk}, Kind=#{kind}")
          end
          raise Status::BadRequest.new("Name parameter required.") if bound["name"].to_s.empty?

          bound_resource = @registry.find_gvk(group: "", version: "v1", kind: kind)
          object = begin
            @store.get(resource: bound_resource, namespace: kind == "Node" ? :cluster : namespace, name: bound["name"])
          rescue MemoryStore::NotFound
            details = {"name" => bound["name"], "kind" => bound_resource.resource}
            raise Status::NotFound.new("#{bound_resource.resource} #{bound["name"].inspect} not found", details: details)
          end
          if kind == "Pod" && object.dig("spec", "serviceAccountName") != account_name
            raise Status::BadRequest.new("cannot bind token for serviceaccount #{account_name.inspect} to pod running with different serviceaccount name.")
          end
          if bound["uid"] && !bound["uid"].to_s.empty? && metadata_value(object, "uid").to_s != bound["uid"].to_s
            raise Status::Conflict.new("the UID in the bound object reference (#{bound["uid"]}) does not match the UID in record. The object might have " \
                                       "been deleted and then recreated")
          end

          bound_object = {"kind" => kind, "name" => bound["name"], "uid" => metadata_value(object, "uid").to_s}
          # A pod-bound token also names the pod's node, with its UID when the
          # node still exists (pkg/registry/core/serviceaccount/storage/
          # token.go), so TokenReview can report authentication.kubernetes.io/
          # node-name and node-uid.
          node_name = kind == "Pod" ? object.dig("spec", "nodeName").to_s : ""
          unless node_name.empty?
            node = begin
              @store.get(resource: @registry.find_gvk(group: "", version: "v1", kind: "Node"), namespace: :cluster, name: node_name)
            rescue MemoryStore::NotFound
              nil
            end
            bound_object["node"] = {"name" => node_name, "uid" => node && metadata_value(node, "uid").to_s}.compact
          end
          bound_object
        end

        def invalid_token_request!(field, value, detail, name: "")
          message = "Invalid value: #{value.inspect}: #{detail}"
          cause = {"reason" => "FieldValueInvalid", "field" => field, "message" => message}
          details = {"group" => "authentication.k8s.io", "kind" => "TokenRequest", "causes" => [cause]}
          details["name"] = name unless name.empty?
          raise Status::Invalid.new("TokenRequest.authentication.k8s.io #{name.inspect} is invalid: #{field}: #{message}", details: details)
        end
      end
    end
  end
end
