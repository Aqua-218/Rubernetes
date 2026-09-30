# frozen_string_literal: true

module Rubernetes
  module Security
    module Audit
      LEVELS = %w[None Metadata Request RequestResponse].freeze
      STAGES = %w[RequestReceived ResponseStarted ResponseComplete Panic].freeze

      # audit.k8s.io/v1 Policy evaluation (k8s.io/apiserver/pkg/audit/policy).
      # The first matching rule decides the level and the omitted stages;
      # no match means the request is not audited.
      class Policy
        Rule = Struct.new(:level, :users, :user_groups, :verbs, :resources, :namespaces, :non_resource_urls, :omit_stages,
                          :omit_managed_fields, keyword_init: true)

        def self.from_h(document)
          unless document["kind"] == "Policy" && document["apiVersion"] == "audit.k8s.io/v1"
            raise ConfigurationError,
                  "audit policy must be audit.k8s.io/v1 Policy"
          end

          rules = Array(document["rules"]).map do |rule|
            level = rule["level"].to_s
            raise ConfigurationError, "audit rule level #{level.inspect} is invalid" unless LEVELS.include?(level)

            Rule.new(level: level, users: Array(rule["users"]), user_groups: Array(rule["userGroups"]), verbs: Array(rule["verbs"]),
                     resources: Array(rule["resources"]), namespaces: Array(rule["namespaces"]), non_resource_urls: Array(rule["nonResourceURLs"]),
                     omit_stages: Array(rule["omitStages"]), omit_managed_fields: rule["omitManagedFields"])
          end
          new(rules: rules, omit_stages: Array(document["omitStages"]), omit_managed_fields: document["omitManagedFields"] == true)
        end

        attr_reader :rules

        def initialize(rules:, omit_stages: [], omit_managed_fields: false)
          @rules = rules
          @omit_stages = omit_stages
          @omit_managed_fields = omit_managed_fields
        end

        # Returns [level, omitted_stages, omit_managed_fields].
        def evaluate(attributes)
          @rules.each do |rule|
            next unless matches?(rule, attributes)

            omit = rule.omit_managed_fields.nil? ? @omit_managed_fields : rule.omit_managed_fields
            return [rule.level, (@omit_stages + rule.omit_stages).uniq, omit]
          end
          ["None", STAGES, @omit_managed_fields]
        end

        private

        def matches?(rule, attributes)
          user = attributes.user
          return false unless rule.users.empty? || rule.users.include?(user.name)
          return false unless rule.user_groups.empty? || (rule.user_groups & user.groups).any?
          return false unless rule.verbs.empty? || rule.verbs.include?(attributes.verb)

          if attributes.resource_request?
            return false unless rule.non_resource_urls.empty?
            return false unless rule.namespaces.empty? || rule.namespaces.include?(attributes.namespace) ||
                                (attributes.namespace.empty? && rule.namespaces.include?(""))
            return false unless rule.resources.empty? || rule.resources.any? { |group_rule| resource_rule_matches?(group_rule, attributes) }
          else
            return false unless rule.resources.empty? && rule.namespaces.empty?
            return false unless rule.non_resource_urls.empty? || rule.non_resource_urls.any? do |pattern|
              url_matches?(pattern, attributes.path)
            end
          end
          true
        end

        def resource_rule_matches?(group_rule, attributes)
          group = group_rule["group"].to_s
          return false unless group == attributes.api_group

          resources = Array(group_rule["resources"])
          resource_ok = resources.empty? || resources.any? do |candidate|
            candidate == attributes.resource || candidate == attributes.resource_with_subresource ||
              (candidate.end_with?("/*") && candidate.delete_suffix("/*") == attributes.resource) || candidate == "*/#{attributes.subresource}"
          end
          return false unless resource_ok

          names = Array(group_rule["resourceNames"])
          names.empty? || names.include?(attributes.name)
        end

        def url_matches?(pattern, path)
          pattern == path || (pattern.end_with?("*") && path.to_s.start_with?(pattern.delete_suffix("*")))
        end
      end
    end
  end
end
