# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Who a request is from when no security pipeline ran: the identity resolver,
      # legacy impersonation, and the UserInfo rendering the review endpoints share.
      module RequestIdentity
        private

        def request_identity(request)
          identity = authenticate_request(request).identity
          identity.nil? ? {"username" => "system:anonymous", "groups" => %w[system:unauthenticated]} : identity
        end

        def user_info(identity)
          # An authenticator returns an AuthenticationResult wrapping the
          # UserInfo, not the UserInfo itself.  Reading username/uid/groups off
          # the wrapper found nothing, so TokenReview answered
          # `authenticated: true` with an EMPTY user -- no username, no groups.
          # Upstream's TokenReview status carries the full UserInfo
          # (pkg/registry/authentication/tokenreview/storage.go), which is what
          # [sig-auth] ServiceAccounts "should mount an API token into pods"
          # checks at service_accounts.go:132, and what every authenticating
          # webhook client relies on.
          identity = authenticated_user(identity)
          info = {}
          username = identity_attribute(identity, "username") || identity_attribute(identity, "name")
          info["username"] = username.to_s unless username.to_s.empty?
          uid = identity_attribute(identity, "uid")
          info["uid"] = uid.to_s unless uid.to_s.empty?
          groups = Array(identity_attribute(identity, "groups")).map(&:to_s)
          info["groups"] = groups unless groups.empty?
          extra = identity_attribute(identity, "extra")
          info["extra"] = stringify_keys(extra) if extra.is_a?(Hash) && !extra.empty?
          info
        end

        def authenticate_request(request)
          return impersonate(request) unless request.identity.nil? && @identity_resolver

          identity = invoke_identity_resolver(request)
          impersonate(request.with(identity: identity))
        rescue Status::Error
          raise
        rescue StandardError => error
          raise Status::Unauthorized.new("request authentication failed"), cause: error
        end

        # Impersonation without the security pipeline (a server given only an
        # identity resolver and an authorizer): the legacy `impersonate` filter
        # of k8s.io/apiserver/pkg/endpoints/filters/impersonation.  With the
        # pipeline, impersonation already happened there and the Impersonate-*
        # headers are gone.
        def impersonate(request)
          return request unless Security::Impersonation.requested?(request)

          filter = (@legacy_impersonation ||= Security::Impersonation::Filter.new(ImpersonationAuthorizer.new(@impersonation_authorizer),
                                                                                  constrained: false))
          wanted = filter.wanted_user(request)
          return request unless wanted

          requester = request.identity
          raise Status::Unauthorized.new("impersonation requires an authenticated request") if requester.nil?

          requester = requester.is_a?(String) ? Security::UserInfo.new(name: requester) : Security::UserInfo.from_h(requester)
          attributes = Security::Authorization::Attributes.new(user: requester, verb: "", path: request.path, resource_request: false)
          result = filter.impersonate(wanted, attributes)
          Security::Impersonation.strip_headers(request).with(identity: result.user.to_h)
        rescue Security::Impersonation::BadRequest => error
          raise Status::BadRequest.new(error.message)
        rescue Security::Impersonation::Forbidden => error
          raise Status::Forbidden.new(error.message, details: error.details)
        end
      end
    end
  end
end
