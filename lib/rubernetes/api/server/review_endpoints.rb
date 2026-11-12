# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The virtual authentication and authorization resources: TokenReview,
      # SelfSubjectReview, the SubjectAccessReview family, serviceaccounts/token and
      # the OpenID discovery documents.
      module ReviewEndpoints
        private

        # The object a review handler receives: decoded, defaulted and validated
        # exactly like a stored object, without the storage metadata pass.
        def review_request_object(request, route)
          object = normalize_object(request, route)
          object = apply_schema(route.resource, object, operation: :create)
          validate_object!(route.resource, object)
          object
        end

        def review_response_object(request, route, object, sections)
          result = {"kind" => route.resource.kind, "apiVersion" => route.resource.api_version}
          metadata = object["metadata"].is_a?(Hash) ? deep_copy(object["metadata"]) : {}
          managed_fields = record_managed_update(request, route, nil, object)
          managed_fields.nil? ? metadata.delete("managedFields") : metadata["managedFields"] = managed_fields
          result["metadata"] = metadata
          sections.each { |key, value| result[key] = value }
          result
        end

        # pkg/registry/authentication/tokenreview/storage.go: the handler rejects
        # an empty token before any schema validation of the request object.
        def token_review_response(request, route)
          raw = request_body(request)
          raw_token = raw.is_a?(Hash) ? stringify_keys(raw).dig("spec", "token").to_s : ""
          raise Status::BadRequest.new("token is required for TokenReview in authentication") if raw_token.empty?

          object = review_request_object(request, route)
          spec = object["spec"].is_a?(Hash) ? object["spec"] : {}
          token = spec["token"].to_s

          identity = authenticate_token(token)
          status = if identity
                     requested = Array(spec["audiences"]).map(&:to_s)
                     matched = identity_audiences(identity)
                     audiences = if !matched.empty?
                                   requested.empty? ? matched : (requested & matched)
                                 elsif requested.empty?
                                   @api_audiences.dup
                                 else
                                   requested & @api_audiences
                                 end
                     {"authenticated" => true, "user" => user_info(identity), "audiences" => audiences}
                   else
                     {"user" => {}, "error" => "invalid bearer token"}
                   end
          json_response(review_response_object(request, route, object, "spec" => deep_copy(spec), "status" => status), status: 201)
        end

        # pkg/registry/authentication/selfsubjectreview/rest.go
        def self_subject_review_response(request, route)
          object = review_request_object(request, route)
          identity = request_identity(request)
          response = review_response_object(request, route, object, "status" => {"userInfo" => user_info(identity)})
          response["metadata"]["creationTimestamp"] = @clock.call.utc.iso8601
          json_response(response, status: 201)
        end

        # pkg/registry/authorization/selfsubjectrulesreview/rest.go with the
        # AlwaysAllow authorization mode (every verb on every resource and path).
        def self_subject_rules_review_response(request, route)
          object = review_request_object(request, route)
          namespace = object.dig("spec", "namespace").to_s
          raise Status::BadRequest.new("no namespace on request") if namespace.empty?

          rules = if authorizer_lists_rules?
                    @authorizer.rules_for(request_identity(request), namespace)
                  else
                    {"resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"]}],
                     "nonResourceRules" => [{"verbs" => ["*"], "nonResourceURLs" => ["*"]}], "incomplete" => false}
                  end
          json_response({"kind" => route.resource.kind, "apiVersion" => route.resource.api_version,
                         "metadata" => {}, "spec" => {}, "status" => rules}, status: 201)
        end

        # pkg/registry/authorization/{subjectaccessreview,selfsubjectaccessreview,localsubjectaccessreview}
        def subject_access_review_response(request, route)
          object = review_request_object(request, route)
          decision = if authorizer_reviews_access?
                       @authorizer.authorize(request_identity(request), object["spec"])
                     else
                       {"allowed" => true}
                     end
          response = review_response_object(request, route, object, "spec" => deep_copy(object["spec"] || {}), "status" => decision)
          json_response(response, status: 201)
        end

        # pkg/registry/core/serviceaccount/storage/token.go: TokenRequest on the
        # serviceaccounts/token subresource.  The service account must exist,
        # a bound object must exist with the given UID, and the issuer signs a
        # bound token whose expiration is returned in status.
        def token_request_response(request, route)
          raise Status::NotFound.new("the server could not find the requested resource") if @service_account_issuer.nil?

          namespace = storage_namespace(route, operation: :get)
          account = @store.get(resource: route.resource, namespace: namespace, name: route.name)
          body = request_body(request)
          raise Status::BadRequest.new("request body must be a TokenRequest") unless body.is_a?(Hash) && (body["kind"].nil? || body["kind"] == "TokenRequest")

          ensure_token_request_uid!(body, account, route)
          spec = body["spec"] || {}
          bound_object = token_bound_object(spec["boundObjectRef"], namespace)
          begin
            token, expiration = @service_account_issuer.issue(namespace: namespace, service_account_name: route.name,
                                                              service_account_uid: metadata_value(account, "uid").to_s,
                                                              audiences: spec["audiences"], expiration_seconds: spec["expirationSeconds"],
                                                              bound_object: bound_object)
          rescue ArgumentError => error
            raise Status::Invalid.new("TokenRequest is invalid: #{error.message}")
          end
          json_response(token_request_document(route, namespace, spec, bound_object, token, expiration), status: 201)
        rescue MemoryStore::NotFound
          raise Status::NotFound.new("serviceaccounts #{route.name.inspect} not found", details: resource_details(route))
        end

        # TokenRequestServiceAccountUIDValidation (Beta, on): a request for
        # another incarnation of the ServiceAccount is a conflict.
        def ensure_token_request_uid!(body, account, route)
          requested_uid = body.dig("metadata", "uid").to_s
          account_uid = metadata_value(account, "uid").to_s
          return if requested_uid.empty? || requested_uid == account_uid

          raise Status::Conflict.new(%(Operation cannot be fulfilled on TokenRequest.authentication.k8s.io "#{route.name}": ) +
                                     "the UID in the token request (#{requested_uid}) does not match the UID of the service account (#{account_uid})")
        end

        # The Pod, Secret or Node a token is bound to, as the issuer takes it:
        # the object must exist, with the UID the request names.  nil for a
        # token bound to nothing.
        def token_bound_object(bound, namespace)
          return nil unless bound.is_a?(Hash) && !bound["name"].to_s.empty?

          kind = bound["kind"].to_s
          raise Status::BadRequest.new("cannot bind token to object of type #{kind}") unless %w[Pod Secret Node].include?(kind)

          bound_resource = @registry.find_gvk(group: "", version: "v1", kind: kind)
          object = begin
            @store.get(resource: bound_resource, namespace: kind == "Node" ? :cluster : namespace, name: bound["name"])
          rescue MemoryStore::NotFound
            raise Status::NotFound.new("#{kind.downcase}s #{bound["name"].inspect} not found")
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

        def token_request_document(route, namespace, spec, bound_object, token, expiration)
          {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenRequest",
           "metadata" => {"name" => route.name, "namespace" => namespace, "creationTimestamp" => @clock.call.utc.iso8601},
           "spec" => {"audiences" => Array(spec["audiences"]).empty? ? @service_account_issuer.api_audiences : Array(spec["audiences"]),
                      "expirationSeconds" => spec["expirationSeconds"] || Security::Authentication::ServiceAccount::DEFAULT_EXPIRATION_SECONDS,
                      "boundObjectRef" => bound_object && {"kind" => bound_object["kind"], "apiVersion" => "v1",
                                                           "name" => bound_object["name"], "uid" => bound_object["uid"]}}.compact,
           "status" => {"token" => token, "expirationTimestamp" => expiration.iso8601}}
        end

        # OpenID discovery for service account tokens
        # (pkg/serviceaccount/openidmetadata.go).
        def openid_response(_request, route)
          raise Status::NotFound.new("the requested API path #{route.path.inspect} was not found") if @service_account_issuer.nil?

          document = route.path == "/openid/v1/jwks" ? @service_account_issuer.jwks : @service_account_issuer.openid_configuration
          content_type = route.path == "/openid/v1/jwks" ? "application/jwk-set+json" : "application/json"
          Response.new(status: 200, headers: {"content-type" => content_type, "cache-control" => "public, max-age=3600"},
                       body: JSON.generate(document))
        end
      end
    end
  end
end
