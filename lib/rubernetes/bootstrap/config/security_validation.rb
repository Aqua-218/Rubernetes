# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Config
      module SecurityValidation
        private

        def validate_security!(value)
          context = "rubernetes-apiserver.security"
          validate_mapping!(value, context)
          reject_unknown_keys!(value, SECURITY_KEYS, context)
          validate_apiserver_authentication!(value["authentication"], context) if value.key?("authentication")
          validate_apiserver_authorization!(value["authorization"], context) if value.key?("authorization")
          validate_apiserver_admission!(value["admission"], context) if value.key?("admission")
          validate_apiserver_audit!(value["audit"], context) if value.key?("audit")
          validate_apiserver_flow_control!(value["flow_control"], context) if value.key?("flow_control")
          validate_apiserver_feature_gates!(value["feature_gates"], context) if value.key?("feature_gates")
        end

        def validate_service_account!(sa, context)
          validate_mapping!(sa, "#{context}.authentication.service_account")
          reject_unknown_keys!(sa, SERVICE_ACCOUNT_KEYS, "#{context}.authentication.service_account")
          validate_non_empty_string!(sa["issuer"], "#{context}.authentication.service_account.issuer")
          if sa.key?("signing_endpoint")
            # --service-account-signing-endpoint: the external signer owns the keys.
            validate_absolute_path!(sa["signing_endpoint"], "#{context}.authentication.service_account.signing_endpoint")
            %w[signing_key_file key_files].each do |key|
              raise Error, "#{context}.authentication.service_account.#{key} cannot be combined with signing_endpoint" if sa.key?(key)
            end
            if sa.key?("allow_signing_with_non_oidc_keys") && ![true, false].include?(sa["allow_signing_with_non_oidc_keys"])
              raise Error, "#{context}.authentication.service_account.allow_signing_with_non_oidc_keys must be true or false"
            end
          else
            validate_absolute_path!(sa["signing_key_file"], "#{context}.authentication.service_account.signing_key_file")
          end
          validate_service_account_expiration!(sa, "#{context}.authentication.service_account")
          Array(sa["key_files"]).each { |path| validate_absolute_path!(path, "#{context}.authentication.service_account.key_files[]") }
          return unless sa.key?("api_audiences") && !(sa["api_audiences"].is_a?(Array) && !sa["api_audiences"].empty?)

          raise Error,
                "#{context}.authentication.service_account.api_audiences must be a non-empty list"
        end

        def validate_service_account_expiration!(settings, context)
          if settings.key?("extend_expiration") && ![true, false].include?(settings["extend_expiration"])
            raise Error, "#{context}.extend_expiration must be a boolean"
          end
          return unless settings.key?("max_expiration_seconds")

          maximum = settings["max_expiration_seconds"]
          return if maximum.is_a?(Integer) && (maximum.zero? || maximum.between?(3600, 1 << 32))

          raise Error, "#{context}.max_expiration_seconds must be zero or between 3600 and 2^32 seconds"
        end

        def validate_apiserver_authentication!(authn, context)
          validate_mapping!(authn, "#{context}.authentication")
          reject_unknown_keys!(authn, AUTHENTICATION_KEYS, "#{context}.authentication")
          if authn.key?("config_file")
            # --authentication-config is mutually exclusive with the flag-style
            # JWT (--oidc-*) and --anonymous-auth settings.
            validate_absolute_path!(authn["config_file"], "#{context}.authentication.config_file")
            %w[jwt anonymous].each do |key|
              if authn.key?(key)
                raise Error,
                      "#{context}.authentication.#{key} cannot be combined with config_file (the AuthenticationConfiguration file owns it)"
              end
            end
          end
          %w[client_ca_file token_file].each do |key|
            validate_absolute_path!(authn[key], "#{context}.authentication.#{key}") if authn.key?(key)
          end
          validate_service_account!(authn["service_account"], context) if authn.key?("service_account")
          if authn.key?("bootstrap_tokens") && ![true, false].include?(authn["bootstrap_tokens"])
            raise Error, "#{context}.authentication.bootstrap_tokens must be a boolean"
          end

          if authn.key?("request_header")
            rh = authn["request_header"]
            validate_mapping!(rh, "#{context}.authentication.request_header")
            reject_unknown_keys!(rh, REQUEST_HEADER_KEYS, "#{context}.authentication.request_header")
            validate_absolute_path!(rh["ca_file"], "#{context}.authentication.request_header.ca_file")
          end
          if authn.key?("jwt")
            raise Error, "#{context}.authentication.jwt must be a list of JWT authenticator configurations" unless authn["jwt"].is_a?(Array)

            authn["jwt"].each { |entry| validate_mapping!(entry, "#{context}.authentication.jwt[]") }
          end
          if authn.key?("webhook")
            hook = authn["webhook"]
            validate_mapping!(hook, "#{context}.authentication.webhook")
            reject_unknown_keys!(hook, AUTHENTICATION_WEBHOOK_KEYS, "#{context}.authentication.webhook")
            validate_non_empty_string!(hook["url"], "#{context}.authentication.webhook.url")
          end
          return unless authn.key?("anonymous")

          anon = authn["anonymous"]
          validate_mapping!(anon, "#{context}.authentication.anonymous")
          raise Error, "#{context}.authentication.anonymous.enabled must be a boolean" unless [true, false].include?(anon["enabled"])
        end

        def validate_apiserver_authorization!(authz, context)
          validate_mapping!(authz, "#{context}.authorization")
          reject_unknown_keys!(authz, AUTHORIZATION_KEYS, "#{context}.authorization")
          if authz.key?("config_file")
            # --authorization-config is mutually exclusive with --authorization-mode and --authorization-webhook-*.
            validate_absolute_path!(authz["config_file"], "#{context}.authorization.config_file")
            %w[modes webhook abac_policy_file].each do |key|
              if authz.key?(key)
                raise Error,
                      "#{context}.authorization.#{key} cannot be combined with config_file (the AuthorizationConfiguration file owns it)"
              end
            end
          else
            modes = authz["modes"]
            raise Error, "#{context}.authorization.modes must be a non-empty list" unless modes.is_a?(Array) && !modes.empty?

            unknown = modes - %w[AlwaysAllow AlwaysDeny ABAC Webhook RBAC Node]
            raise Error, "#{context}.authorization.modes contains unknown modes #{unknown.join(", ")}" unless unknown.empty?
            raise Error, "#{context}.authorization.modes must be unique" unless modes.uniq.length == modes.length

            validate_absolute_path!(authz["abac_policy_file"], "#{context}.authorization.abac_policy_file") if modes.include?("ABAC")
            if modes.include?("Webhook")
              hook = authz["webhook"]
              validate_mapping!(hook, "#{context}.authorization.webhook")
              reject_unknown_keys!(hook, AUTHORIZATION_WEBHOOK_KEYS, "#{context}.authorization.webhook")
              validate_non_empty_string!(hook["url"], "#{context}.authorization.webhook.url")
            end
          end
        end

        def validate_apiserver_admission!(admission, context)
          validate_mapping!(admission, "#{context}.admission")
          reject_unknown_keys!(admission, ADMISSION_KEYS, "#{context}.admission")
          %w[enable disable].each do |key|
            next unless admission.key?(key)
            next if admission[key].is_a?(Array) && admission[key].all?(String)

            raise Error,
                  "#{context}.admission.#{key} must be a list of plugin names"
          end
          validate_mapping!(admission["config"], "#{context}.admission.config") if admission.key?("config")
        end

        def validate_apiserver_audit!(audit, context)
          validate_mapping!(audit, "#{context}.audit")
          reject_unknown_keys!(audit, AUDIT_KEYS, "#{context}.audit")
          validate_absolute_path!(audit["policy_file"], "#{context}.audit.policy_file")
          validate_absolute_path!(audit["log_path"], "#{context}.audit.log_path") if audit.key?("log_path")
          validate_positive_integer!(audit["max_queue"], "#{context}.audit.max_queue") if audit.key?("max_queue")
          return unless audit.key?("webhook")

          webhook = audit["webhook"]
          validate_mapping!(webhook, "#{context}.audit.webhook")
          reject_unknown_keys!(webhook, AUDIT_WEBHOOK_KEYS, "#{context}.audit.webhook")
          validate_non_empty_string!(webhook["url"], "#{context}.audit.webhook.url")
          if webhook.key?("mode") && !%w[batch blocking blocking-strict].include?(webhook["mode"].to_s)
            raise Error, "#{context}.audit.webhook.mode must be batch, blocking or blocking-strict"
          end

          validate_absolute_path!(webhook["ca_file"], "#{context}.audit.webhook.ca_file") if webhook.key?("ca_file")
          validate_absolute_path!(webhook["token_file"], "#{context}.audit.webhook.token_file") if webhook.key?("token_file")
        end

        def validate_apiserver_flow_control!(apf, context)
          validate_mapping!(apf, "#{context}.flow_control")
          reject_unknown_keys!(apf, FLOW_CONTROL_KEYS, "#{context}.flow_control")
          raise Error, "#{context}.flow_control.enabled must be a boolean" if apf.key?("enabled") && ![true, false].include?(apf["enabled"])

          %w[read_seats mutating_seats].each do |key|
            validate_positive_integer!(apf[key], "#{context}.flow_control.#{key}") if apf.key?(key)
          end
        end

        def validate_apiserver_feature_gates!(gates, context)
          validate_mapping!(gates, "#{context}.feature_gates")
          gates.each do |gate, enabled|
            raise Error, "#{context}.feature_gates.#{gate} must be a boolean" unless [true, false].include?(enabled)
          end
          validate_feature_gate_dependencies!(gates, "#{context}.feature_gates")
          spread_keys = "MatchLabelKeysInPodTopologySpread"
          spread_merge = "MatchLabelKeysInPodTopologySpreadSelectorMerge"
          raise Error, "#{context}.feature_gates.#{spread_merge} requires #{spread_keys}" if gates[spread_keys] == false && gates.fetch(spread_merge, true)
          if gates["StorageVersionAPI"] == true && gates["APIServerIdentity"] == false
            raise Error, "#{context}.feature_gates.StorageVersionAPI requires APIServerIdentity"
          end
          return unless gates["DeclarativeValidation"] == false

          raise Error, "#{context}.feature_gates.DeclarativeValidation is locked to true in Kubernetes v1.36.2"
        end
      end
    end
  end
end
