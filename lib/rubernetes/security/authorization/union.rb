# frozen_string_literal: true

require_relative "attributes"

module Rubernetes
  module Security
    module Authorization
      class AlwaysAllow
        NAME = "AlwaysAllow"
        def name = NAME
        def authorize(_attributes) = Decision.allow("AlwaysAllow", authorizer: NAME)
      end

      class AlwaysDeny
        NAME = "AlwaysDeny"
        def name = NAME
        def authorize(_attributes) = Decision.deny("Everything is forbidden", authorizer: NAME)
      end

      # Ordered union (spec 5.1.3): authorizers are consulted in configured
      # order; the first Allow or Deny decides, NoOpinion continues; the end
      # of the chain is a 403.  Requests by system:masters are allowed first
      # as in kube-apiserver's privileged-group authorizer.
      class Union
        attr_reader :authorizers

        def initialize(authorizers:, privileged_groups: [UserInfo::MASTERS_GROUP])
          @authorizers = Array(authorizers).freeze
          @privileged_groups = Array(privileged_groups)
        end

        # --authorization-config reload: the chain is swapped in place, so
        # every holder of this union (the pipeline, SubjectAccessReview)
        # sees the new authorizers at once.
        def reload(authorizers)
          @authorizers = Array(authorizers).freeze
          self
        end

        def modes
          @authorizers.map(&:name)
        end

        def authorize(attributes)
          user = attributes.user
          return Decision.allow("privileged group", authorizer: "PrivilegedGroups") if user && (user.groups & @privileged_groups).any?

          @authorizers.each do |authorizer|
            decision = authorizer.authorize(attributes)
            return decision unless decision.no_opinion?
          end
          Decision.no_opinion("no authorizer allowed the request", authorizer: "union")
        end

        def rules_for(user, namespace)
          resource_rules = []
          non_resource_rules = []
          incomplete = false
          @authorizers.each do |authorizer|
            if authorizer.respond_to?(:rules_for)
              resources, non_resources = authorizer.rules_for(user, namespace)
              resource_rules.concat(resources)
              non_resource_rules.concat(non_resources)
            else
              incomplete = true
            end
          end
          [resource_rules, non_resource_rules, incomplete]
        end
      end
    end
  end
end
