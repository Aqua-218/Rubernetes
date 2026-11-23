# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # The virtual authentication and authorization resources: TokenReview,
      # SelfSubjectReview, the SubjectAccessReview family and
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
          status = token_review_status(spec)
          json_response(review_response_object(request, route, object, "spec" => deep_copy(spec), "status" => status), status: 201)
        end

        def token_review_status(spec)
          requested = Array(spec["audiences"]).map(&:to_s)
          requested = @api_audiences if requested.empty?
          identity = authenticate_token(spec["token"].to_s, requested)
          return {"user" => {}, "error" => "invalid bearer token"} unless identity

          accepted = identity_audiences(identity)
          accepted = @api_audiences if accepted.empty?
          matched = requested & accepted
          return {"user" => {}, "error" => "invalid bearer token"} if matched.empty?

          {"authenticated" => true, "user" => user_info(identity), "audiences" => matched}
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
