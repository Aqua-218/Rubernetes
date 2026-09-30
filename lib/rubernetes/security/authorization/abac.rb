# frozen_string_literal: true

require "json"

require_relative "attributes"

module Rubernetes
  module Security
    module Authorization
      # ABAC authorizer (pkg/auth/authorizer/abac): a JSON-lines policy file of
      # abac.authorization.kubernetes.io/v1beta1 Policy objects.
      class ABAC
        NAME = "ABAC"

        def self.load(path)
          new(parse(File.read(path)))
        end

        def self.parse(text)
          text.each_line.with_index(1).filter_map do |line, number|
            stripped = line.strip
            next if stripped.empty? || stripped.start_with?("#")

            policy = JSON.parse(stripped)
            unless policy.is_a?(Hash) && policy["kind"] == "Policy"
              raise ConfigurationError,
                    "abac policy line #{number} must be a Policy object"
            end
            unless policy["apiVersion"] == "abac.authorization.kubernetes.io/v1beta1"
              raise ConfigurationError,
                    "abac policy line #{number} must be v1beta1"
            end

            policy["spec"] || {}
          rescue JSON::ParserError => error
            raise ConfigurationError, "abac policy line #{number} is not valid JSON: #{error.message}"
          end
        end

        def initialize(policies)
          @policies = policies
        end

        def name
          NAME
        end

        def authorize(attributes)
          @policies.each do |policy|
            return Decision.allow("ABAC: policy matched", authorizer: NAME) if matches?(policy, attributes)
          end
          Decision.no_opinion("ABAC: no policy matched", authorizer: NAME)
        end

        private

        def matches?(policy, attributes)
          user = attributes.user
          subject_ok = (policy["user"] && (policy["user"] == "*" || policy["user"] == user.name)) ||
                       (policy["group"] && (policy["group"] == "*" || user.groups.include?(policy["group"])))
          return false unless subject_ok
          return false if policy["readonly"] == true && !%w[get list watch].include?(attributes.verb)

          if attributes.resource_request?
            return false unless glob(policy["apiGroup"], attributes.api_group)
            return false unless glob(policy["resource"], attributes.resource)
            return false unless glob(policy["namespace"], attributes.namespace)

            true
          else
            path = policy["nonResourcePath"]
            return false if path.nil?

            path == "*" || path == attributes.path || (path.end_with?("*") && attributes.path.to_s.start_with?(path.delete_suffix("*")))
          end
        end

        def glob(pattern, value)
          return value.to_s.empty? if pattern.nil? || pattern == ""
          return true if pattern == "*"

          pattern == value.to_s
        end
      end
    end
  end
end
