# frozen_string_literal: true

require "yaml"
require "json"

module Rubernetes
  module Security
    module Authorization
      # k8s.io/apiserver/pkg/authorization/cel: the webhook authorizer's
      # matchConditions, CEL expressions over `request` (the
      # SubjectAccessReview spec).  All true: the webhook is called; one
      # false: the webhook is skipped (an exclusion); an error and no false:
      # the webhook's failure policy decides.
      class MatchConditions
        Result = Struct.new(:matches, :error, keyword_init: true)

        attr_reader :expressions, :authorizer_name, :authorizer_type

        def initialize(expressions:, cel:, authorizer_name:, authorizer_type: "Webhook")
          @expressions = Array(expressions).map(&:to_s).freeze
          @cel = cel
          @authorizer_name = authorizer_name.to_s
          @authorizer_type = authorizer_type.to_s
          raise Error, "matchConditions need a CEL evaluator" if @cel.nil? && !@expressions.empty?

          @programs = @expressions.map { |expression| [expression, @cel.compile(expression)] }
        end

        def empty? = @expressions.empty?

        # CELMatcher.Eval.
        def evaluate(review_spec)
          return Result.new(matches: true, error: nil) if empty?

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          errors = []
          variables = {"request" => review_spec}
          @programs.each do |expression, _program|
            value = begin
              @cel.evaluate(expression, variables)
            rescue StandardError => error
              errors << "cel evaluation error: expression '#{expression}' resulted in error: #{error.message}"
              next
            end
            unless [true, false].include?(value)
              errors << "cel evaluation error: expression '#{expression}' eval result type should be bool but got #{value.class}"
              next
            end
            next if value

            record_exclusion
            record_evaluation(started, errors)
            return Result.new(matches: false, error: nil)
          end
          record_evaluation(started, errors)
          return Result.new(matches: true, error: nil) if errors.empty?

          Result.new(matches: false, error: Error.new(errors.join("; ")))
        end

        class << self
          def registry
            return nil unless defined?(Rubernetes::Observability::Metrics)

            Rubernetes::Observability::Metrics.global
          end
        end

        private

        def labels = {"name" => @authorizer_name, "type" => @authorizer_type}

        def record_evaluation(started, errors)
          metrics = self.class.registry
          return unless metrics

          unless metrics.registered?("apiserver_authorization_match_condition_evaluation_seconds")
            metrics.register("apiserver_authorization_match_condition_evaluation_seconds",
                             type: :histogram)
          end
          metrics.observe("apiserver_authorization_match_condition_evaluation_seconds",
                          Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
          return if errors.empty?

          unless metrics.registered?("apiserver_authorization_match_condition_evaluation_errors_total")
            metrics.register("apiserver_authorization_match_condition_evaluation_errors_total",
                             type: :counter)
          end
          metrics.increment("apiserver_authorization_match_condition_evaluation_errors_total", labels)
        rescue StandardError
          nil
        end

        def record_exclusion
          metrics = self.class.registry
          return unless metrics

          unless metrics.registered?("apiserver_authorization_match_condition_exclusions_total")
            metrics.register("apiserver_authorization_match_condition_exclusions_total",
                             type: :counter)
          end
          metrics.increment("apiserver_authorization_match_condition_exclusions_total", labels)
        rescue StandardError
          nil
        end
      end

      # apiserver.config.k8s.io AuthorizationConfiguration (--authorization-config):
      # an ordered list of named authorizers, Webhook entries with their
      # connection, TTLs, failure policy and matchConditions.  Validation is
      # k8s.io/apiserver/pkg/apis/apiserver/validation's.
      class Configuration
        class InvalidError < Error; end

        API_VERSIONS = %w[apiserver.config.k8s.io/v1 apiserver.config.k8s.io/v1beta1 apiserver.config.k8s.io/v1alpha1].freeze
        KNOWN_TYPES = %w[AlwaysAllow AlwaysDeny ABAC Webhook RBAC Node].freeze
        REPEATABLE_TYPES = %w[Webhook].freeze
        FAILURE_POLICIES = %w[NoOpinion Deny].freeze
        CONNECTION_TYPES = %w[KubeConfigFile InClusterConfig].freeze
        DNS_SUBDOMAIN = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/
        DURATION = /\A(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)\z/
        DURATION_UNITS = {"ns" => 1e-9, "us" => 1e-6, "µs" => 1e-6, "ms" => 1e-3, "s" => 1.0, "m" => 60.0, "h" => 3600.0}.freeze

        Authorizer = Struct.new(:type, :name, :webhook, keyword_init: true)
        Webhook = Struct.new(:authorized_ttl, :unauthorized_ttl, :timeout, :subject_access_review_version,
                             :match_condition_version, :failure_policy, :connection_type, :kubeconfig_file, :match_conditions, keyword_init: true)

        attr_reader :authorizers, :document

        def self.load(path, cel: nil, require_non_webhook_types: nil)
          from_bytes(File.binread(path), cel: cel, require_non_webhook_types: require_non_webhook_types)
        end

        def self.from_bytes(bytes, cel: nil, require_non_webhook_types: nil)
          document = YAML.safe_load(bytes.to_s, permitted_classes: [], aliases: false)
          raise InvalidError, "authorization configuration must be a YAML/JSON object" unless document.is_a?(Hash)

          from_h(document, cel: cel, require_non_webhook_types: require_non_webhook_types)
        rescue Psych::Exception => error
          raise InvalidError, "authorization configuration is not valid YAML: #{error.message}"
        end

        def self.from_h(document, cel: nil, require_non_webhook_types: nil)
          new(document, cel: cel, require_non_webhook_types: require_non_webhook_types)
        end

        # Go's time.ParseDuration for metav1.Duration strings ("30s", "1m30s").
        def self.parse_duration(value, field)
          text = value.to_s.strip
          raise InvalidError, "#{field}: Required value" if text.empty?

          negative = text.start_with?("-")
          text = text.delete_prefix("-").delete_prefix("+")
          return 0.0 if text == "0"

          total = 0.0
          rest = text
          until rest.empty?
            match = rest.match(/\A(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/)
            raise InvalidError, "#{field}: Invalid value: #{value.inspect}: invalid duration" unless match

            total += Float(match[1]) * DURATION_UNITS.fetch(match[2])
            rest = rest[match[0].length..]
          end
          negative ? -total : total
        end

        def initialize(document, cel: nil, require_non_webhook_types: nil)
          @document = document
          @cel = cel
          errors = []
          kind = document["kind"].to_s
          errors << "kind must be AuthorizationConfiguration, got #{kind.inspect}" unless kind == "AuthorizationConfiguration"
          api_version = document["apiVersion"].to_s
          errors << "apiVersion #{api_version.inspect} is not one of #{API_VERSIONS.join(", ")}" unless API_VERSIONS.include?(api_version)
          @authorizers = validate_authorizers(document["authorizers"], errors)
          if require_non_webhook_types
            present = @authorizers.map(&:type).reject { |type| type == "Webhook" }.to_set
            wanted = require_non_webhook_types.to_set
            unless present == wanted
              errors << "authorizers: non-webhook authorizer types must not change on reload (want #{wanted.to_a.sort.join(", ")}, got #{present.to_a.sort.join(", ")})"
            end
          end
          raise InvalidError, errors.join("; ") unless errors.empty?

          @normalized = @authorizers.map(&:to_h).freeze
          freeze
        end

        def non_webhook_types = @authorizers.map(&:type).reject { |type| type == "Webhook" }.uniq

        def ==(other)
          other.is_a?(Configuration) && @normalized == other.instance_variable_get(:@normalized)
        end
        alias eql? ==
        def hash = @normalized.hash

        # +factory+: {"RBAC" => -> { authorizer }, "Node" => ..., "ABAC" => ->(entry) {}, "Webhook" => ->(entry, match_conditions) {}}.
        def build(factory)
          @authorizers.map do |entry|
            builder = factory.fetch(entry.type) { raise Error, "no builder for authorizer type #{entry.type}" }
            if entry.type == "Webhook"
              conditions = MatchConditions.new(expressions: entry.webhook.match_conditions, cel: @cel, authorizer_name: entry.name)
              builder.call(entry, conditions)
            elsif builder.arity.zero?
              builder.call
            else
              builder.call(entry)
            end
          end
        end

        private

        def validate_authorizers(list, errors)
          unless list.is_a?(Array) && !list.empty?
            errors << "authorizers: Required value: at least one authorization mode must be defined"
            return []
          end
          seen_types = Set.new
          seen_names = Set.new
          list.each_with_index.filter_map do |raw, index|
            path = "authorizers[#{index}]"
            unless raw.is_a?(Hash)
              errors << "#{path}: must be an object"
              next
            end
            type = raw["type"].to_s
            if type.empty?
              errors << "#{path}.type: Required value"
            elsif !KNOWN_TYPES.include?(type)
              errors << "#{path}.type: Unsupported value: #{type.inspect}: supported values: #{KNOWN_TYPES.join(", ")}"
            elsif seen_types.include?(type) && !REPEATABLE_TYPES.include?(type)
              errors << "#{path}.type: Duplicate value: #{type.inspect}"
            end
            seen_types << type
            name = raw["name"].to_s
            if name.empty?
              errors << "#{path}.name: Required value"
            elsif seen_names.include?(name)
              errors << "#{path}.name: Duplicate value: #{name.inspect}"
            elsif name.length > 253 || !DNS_SUBDOMAIN.match?(name)
              errors << "#{path}.name: Invalid value: #{name.inspect}: authorizer name is invalid: must be a lowercase RFC 1123 subdomain"
            end
            seen_names << name
            webhook = nil
            if type == "Webhook"
              if raw["webhook"].is_a?(Hash)
                webhook = validate_webhook(raw["webhook"], "#{path}.webhook", errors)
              else
                errors << "#{path}.webhook: Required value: required when type=Webhook"
              end
            elsif raw.key?("webhook") && !raw["webhook"].nil?
              errors << "#{path}.webhook: Invalid value: \"non-null\": may only be specified when type=Webhook"
            end
            Authorizer.new(type: type, name: name, webhook: webhook)
          end
        end

        def validate_webhook(raw, path, errors)
          timeout = duration(raw["timeout"], "#{path}.timeout", errors)
          errors << "#{path}.timeout: Invalid value: must be > 0s and <= 30s" if timeout && (timeout <= 0 || timeout > 30)
          authorized = duration(raw["authorizedTTL"], "#{path}.authorizedTTL", errors)
          errors << "#{path}.authorizedTTL: Invalid value: must be > 0s" if authorized && authorized <= 0
          unauthorized = duration(raw["unauthorizedTTL"], "#{path}.unauthorizedTTL", errors)
          errors << "#{path}.unauthorizedTTL: Invalid value: must be > 0s" if unauthorized && unauthorized <= 0
          sar_version = raw["subjectAccessReviewVersion"].to_s
          if sar_version.empty?
            errors << "#{path}.subjectAccessReviewVersion: Required value"
          elsif !%w[v1 v1beta1].include?(sar_version)
            errors << "#{path}.subjectAccessReviewVersion: Unsupported value: #{sar_version.inspect}: supported values: v1, v1beta1"
          end
          conditions = Array(raw["matchConditions"])
          mc_version = raw["matchConditionSubjectAccessReviewVersion"].to_s
          if mc_version.empty?
            unless conditions.empty?
              errors << "#{path}.matchConditionSubjectAccessReviewVersion: Required value: required if match conditions are specified"
            end
          elsif mc_version != "v1"
            errors << "#{path}.matchConditionSubjectAccessReviewVersion: Unsupported value: #{mc_version.inspect}: supported values: v1"
          end
          failure_policy = raw["failurePolicy"].to_s
          if failure_policy.empty?
            errors << "#{path}.failurePolicy: Required value"
          elsif !FAILURE_POLICIES.include?(failure_policy)
            errors << "#{path}.failurePolicy: Unsupported value: #{failure_policy.inspect}: supported values: NoOpinion, Deny"
          end
          connection = raw["connectionInfo"].is_a?(Hash) ? raw["connectionInfo"] : {}
          connection_type = connection["type"].to_s
          kubeconfig_file = connection["kubeConfigFile"]
          case connection_type
          when "" then errors << "#{path}.connectionInfo.type: Required value"
          when "InClusterConfig"
            unless kubeconfig_file.nil?
              errors << "#{path}.connectionInfo.kubeConfigFile: Invalid value: can only be set when type=KubeConfigFile"
            end
          when "KubeConfigFile"
            if kubeconfig_file.to_s.empty?
              errors << "#{path}.connectionInfo.kubeConfigFile: Required value"
            elsif !kubeconfig_file.to_s.start_with?("/")
              errors << "#{path}.connectionInfo.kubeConfigFile: Invalid value: must be an absolute path"
            elsif !File.exist?(kubeconfig_file.to_s)
              errors << "#{path}.connectionInfo.kubeConfigFile: Invalid value: error loading file: no such file"
            elsif !File.file?(kubeconfig_file.to_s)
              errors << "#{path}.connectionInfo.kubeConfigFile: Invalid value: must be a regular file"
            end
          else
            errors << "#{path}.connectionInfo.type: Unsupported value: #{connection_type.inspect}: supported values: KubeConfigFile, InClusterConfig"
          end
          expressions = conditions.each_with_index.filter_map do |condition, index|
            expression = condition.is_a?(Hash) ? condition["expression"].to_s.strip : ""
            if expression.empty?
              errors << "#{path}.matchConditions[#{index}].expression: Required value"
              next
            end
            if @cel.nil?
              errors << "#{path}.matchConditions[#{index}].expression: no CEL evaluator is configured"
              next
            end
            begin
              @cel.compile(expression)
            rescue StandardError => error
              errors << "#{path}.matchConditions[#{index}].expression: Invalid value: compilation failed: #{error.message}"
              next
            end
            expression
          end
          Webhook.new(authorized_ttl: authorized, unauthorized_ttl: unauthorized, timeout: timeout,
                      subject_access_review_version: sar_version, match_condition_version: mc_version,
                      failure_policy: failure_policy, connection_type: connection_type,
                      kubeconfig_file: kubeconfig_file&.to_s, match_conditions: expressions.freeze)
        end

        def duration(value, field, errors)
          if value.nil? || value.to_s.strip.empty?
            errors << "#{field}: Required value"
            return nil
          end
          seconds = self.class.parse_duration(value, field)
          if seconds.zero?
            errors << "#{field}: Required value"
            return nil
          end
          seconds
        rescue InvalidError => error
          errors << error.message
          nil
        end
      end
    end
  end
end
