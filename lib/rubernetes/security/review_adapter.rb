# frozen_string_literal: true

require_relative "identity"
require_relative "authorization"

module Rubernetes
  module Security
    # Presents the authorization union through the small contract the API
    # server's SubjectAccessReview / SelfSubjectRulesReview handlers and the
    # Pod streaming subresource bridge consume.
    class ReviewAdapter
      def initialize(authorizer)
        @authorizer = authorizer
      end

      # SubjectAccessReview spec -> status.
      def authorize(identity, spec)
        spec ||= {}
        user = if spec.key?("user") || spec.key?("groups") || spec.key?("uid") || spec.key?("extra")
                 UserInfo.new(name: spec["user"].to_s, uid: spec["uid"], groups: spec["groups"] || [], extra: spec["extra"] || {})
               else
                 UserInfo.from_h(identity)
               end
        attributes = if spec["resourceAttributes"].is_a?(Hash)
                       ra = spec["resourceAttributes"]
                       Authorization::Attributes.new(user: user, verb: ra["verb"].to_s, namespace: ra["namespace"], api_group: ra["group"],
                                                     api_version: ra["version"], resource: ra["resource"].to_s, subresource: ra["subresource"],
                                                     name: ra["name"], resource_request: true)
                     else
                       nra = spec["nonResourceAttributes"] || {}
                       Authorization::Attributes.new(user: user, verb: nra["verb"].to_s, path: nra["path"].to_s, resource_request: false)
                     end
        decision = @authorizer.authorize(attributes)
        status = {"allowed" => decision.allowed?}
        status["denied"] = true if decision.denied?
        status["reason"] = decision.reason if decision.reason
        status
      end

      # Pod streaming subresource bridge contract: {user, verb, resource, ...} hash.
      def call(context)
        if context.is_a?(Hash) && (context.key?(:spec) || context.key?("spec"))
          return authorize(context[:identity] || context["identity"],
                           context[:spec] || context["spec"])
        end

        authorize(context, {})
      end

      def rules_for(identity, namespace)
        user = UserInfo.from_h(identity)
        resource_rules, non_resource_rules, incomplete = @authorizer.rules_for(user, namespace)
        {"resourceRules" => resource_rules, "nonResourceRules" => non_resource_rules, "incomplete" => incomplete == true}
      end
    end
  end
end
