# frozen_string_literal: true

require "yaml"

module Rubernetes
  module Security
    module Authentication
      # apiserver.config.k8s.io AuthenticationConfiguration
      # (--authentication-config): the structured JWT authenticators and the
      # anonymous authenticator's settings.  Validation follows
      # k8s.io/apiserver/pkg/apis/apiserver/validation; each JWT entry is
      # also checked by JWTAuthenticator itself when built.
      class Configuration
        class InvalidError < Error; end

        API_VERSIONS = %w[apiserver.config.k8s.io/v1 apiserver.config.k8s.io/v1beta1 apiserver.config.k8s.io/v1alpha1].freeze

        attr_reader :jwt, :anonymous, :document

        def self.load(path, disallowed_issuers: [])
          from_bytes(File.binread(path), disallowed_issuers: disallowed_issuers)
        end

        def self.from_bytes(bytes, disallowed_issuers: [])
          document = YAML.safe_load(bytes.to_s, permitted_classes: [], aliases: false)
          raise InvalidError, "authentication configuration must be a YAML/JSON object" unless document.is_a?(Hash)

          new(document, disallowed_issuers: disallowed_issuers)
        rescue Psych::Exception => error
          raise InvalidError, "authentication configuration is not valid YAML: #{error.message}"
        end

        def self.from_h(document, disallowed_issuers: []) = new(document, disallowed_issuers: disallowed_issuers)

        def initialize(document, disallowed_issuers: [])
          @document = document
          errors = []
          kind = document["kind"].to_s
          errors << "kind must be AuthenticationConfiguration, got #{kind.inspect}" unless kind == "AuthenticationConfiguration"
          api_version = document["apiVersion"].to_s
          errors << "apiVersion #{api_version.inspect} is not one of #{API_VERSIONS.join(", ")}" unless API_VERSIONS.include?(api_version)
          @jwt = validate_jwt(document["jwt"], Array(disallowed_issuers).map(&:to_s), errors)
          @anonymous = validate_anonymous(document["anonymous"], errors)
          raise InvalidError, errors.join("; ") unless errors.empty?

          @normalized = {"jwt" => @jwt, "anonymous" => @anonymous}.freeze
          freeze
        end

        def ==(other)
          other.is_a?(Configuration) && @normalized == other.instance_variable_get(:@normalized)
        end
        alias eql? ==
        def hash = @normalized.hash

        private

        def validate_jwt(list, disallowed_issuers, errors)
          return [] if list.nil?

          unless list.is_a?(Array)
            errors << "jwt: must be a list"
            return []
          end
          urls = Set.new
          discovery_urls = Set.new
          list.each_with_index.filter_map do |raw, index|
            path = "jwt[#{index}]"
            unless raw.is_a?(Hash)
              errors << "#{path}: must be an object"
              next
            end
            issuer = raw["issuer"].is_a?(Hash) ? raw["issuer"] : {}
            url = issuer["url"].to_s
            if url.empty?
              errors << "#{path}.issuer.url: Required value"
            else
              errors << "#{path}.issuer.url: Duplicate value: #{url.inspect}" unless urls.add?(url)
              if disallowed_issuers.include?(url)
                errors << "#{path}.issuer.url: Invalid value: URL must not overlap with disallowed issuers: #{disallowed_issuers.join(", ")}"
              end
              begin
                parsed = URI.parse(url)
                errors << "#{path}.issuer.url: Invalid value: URL scheme must be https" unless parsed.scheme == "https"
                errors << "#{path}.issuer.url: Invalid value: URL must not contain a username or password" if parsed.userinfo
                errors << "#{path}.issuer.url: Invalid value: URL must not contain a query" if parsed.query
                errors << "#{path}.issuer.url: Invalid value: URL must not contain a fragment" if parsed.fragment
              rescue URI::InvalidURIError => error
                errors << "#{path}.issuer.url: Invalid value: #{error.message}"
              end
            end
            discovery = issuer["discoveryURL"].to_s
            unless discovery.empty?
              errors << "#{path}.issuer.discoveryURL: Invalid value: discoveryURL must be different from URL" if discovery == url
              errors << "#{path}.issuer.discoveryURL: Duplicate value: #{discovery.inspect}" unless discovery_urls.add?(discovery)
            end
            audiences = Array(issuer["audiences"]).map(&:to_s)
            errors << "#{path}.issuer.audiences: Required value: at least one issuer.audiences is required" if audiences.empty?
            errors << "#{path}.issuer.audiences: Required value" if audiences.any?(&:empty?)
            errors << "#{path}.issuer.audiences: Duplicate value" unless audiences.uniq.length == audiences.length
            policy = issuer["audienceMatchPolicy"].to_s
            if audiences.length > 1 && policy != "MatchAny"
              errors << "#{path}.issuer.audienceMatchPolicy: Invalid value: audienceMatchPolicy must be MatchAny for multiple audiences"
            elsif audiences.length == 1 && !policy.empty? && policy != "MatchAny"
              errors << "#{path}.issuer.audienceMatchPolicy: Invalid value: audienceMatchPolicy must be empty or MatchAny for single audience"
            end
            mappings = raw["claimMappings"].is_a?(Hash) ? raw["claimMappings"] : {}
            username = mappings["username"].is_a?(Hash) ? mappings["username"] : {}
            if username["claim"].to_s.empty? && username["expression"].to_s.empty?
              errors << "#{path}.claimMappings.username: Required value: claim or expression is required"
            elsif !username["claim"].to_s.empty? && !username["expression"].to_s.empty?
              errors << "#{path}.claimMappings.username: Invalid value: claim and expression can't both be set"
            elsif !username["claim"].to_s.empty? && username["prefix"].nil?
              errors << "#{path}.claimMappings.username.prefix: Required value: prefix is required when claim is set. It can be set to an empty string to disable prefixing"
            end
            raw
          end
        end

        def validate_anonymous(raw, errors)
          return nil if raw.nil?

          unless raw.is_a?(Hash)
            errors << "anonymous: must be an object"
            return nil
          end
          enabled = raw["enabled"]
          errors << "anonymous.enabled: Required value" unless [true, false].include?(enabled)
          conditions = Array(raw["conditions"])
          errors << "anonymous.conditions: Invalid value: enabled should be set to true when conditions are defined" if !conditions.empty? && enabled != true
          conditions.each_with_index do |condition, index|
            errors << "anonymous.conditions[#{index}].path: Required value" unless condition.is_a?(Hash) && !condition["path"].to_s.empty?
          end
          {"enabled" => enabled == true, "conditions" => conditions.map do |condition|
            {"path" => condition.is_a?(Hash) ? condition["path"].to_s : ""}
          end}
        end
      end
    end
  end
end
