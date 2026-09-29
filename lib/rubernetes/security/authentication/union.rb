# frozen_string_literal: true

require_relative "../identity"
require_relative "request_context"

module Rubernetes
  module Security
    module Authentication
      # Ordered union of request authenticators (spec 5.1.2).  Every
      # authenticator that applies to the request is consulted; if more than
      # one succeeds with different identities the request is rejected, as the
      # specification requires.  An authenticator error is a 401.  When no
      # authenticator applies and anonymous access is enabled for the path,
      # the anonymous user is returned.
      class Union
        Anonymous = Struct.new(:enabled, :conditions, keyword_init: true) do
          def allows?(path)
            return false unless enabled
            return true if conditions.nil? || conditions.empty?

            conditions.any? { |condition| condition["path"] == path }
          end
        end

        attr_reader :authenticators, :anonymous

        def initialize(authenticators:, anonymous: Anonymous.new(enabled: true, conditions: nil))
          @authenticators = Array(authenticators)
          @anonymous = anonymous
        end

        # Returns an AuthenticationResult or raises AuthenticationError.
        def authenticate(context)
          results = []
          @authenticators.each do |authenticator|
            result = authenticator.authenticate(context)
            results << result if result
          end
          if results.length > 1
            distinct = results.map { |result| result.user }.uniq
            raise AuthenticationError, "conflicting identities from #{results.map(&:authenticator).join(", ")}" if distinct.length > 1
          end
          return results.first if results.any?
          # A bearer token that no authenticator recognises is an invalid
          # credential (kube-apiserver's bearertoken.Authenticator returns
          # "invalid bearer token"), never an anonymous request.
          raise AuthenticationError, "invalid bearer token" if context.bearer_token
          return AuthenticationResult.new(user: UserInfo.anonymous, authenticator: "anonymous") if @anonymous.allows?(context.path)

          raise AuthenticationError, "no credentials were presented"
        end

        # Token-only path used by TokenReview.
        def authenticate_token(token, audiences)
          results = @authenticators.filter_map do |authenticator|
            next unless authenticator.respond_to?(:authenticate_token)

            authenticator.authenticate_token(token, audiences)
          end
          raise AuthenticationError, "conflicting identities" if results.map(&:user).uniq.length > 1

          results.first
        end
      end
    end
  end
end
