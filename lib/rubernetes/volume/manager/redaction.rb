# frozen_string_literal: true

# Keeping secrets out of durable state and diagnostics: what is stripped from a
# spec, an operation payload, a CSI response or an error message before it is
# persisted or reported.
module Rubernetes
  module Volume
    class Manager
      module Redaction
        # Preserve the primary lifecycle error while making failed compensation
        # durable and explicitly ambiguous. Recovery must reconcile both the
        # original effect and every cleanup failure before allowing reuse.
        def with_cleanup_errors(error, cleanup_errors)
          failures = Array(cleanup_errors).compact
          return error if failures.empty?

          details = {
            "primaryError" => {"class" => error.class.name, "message" => error.message.to_s},
            "cleanupErrors" => failures.map do |failure|
              child = Capability.hash_like?(failure) ? failure.to_h : nil
              {
                "class" => failure.class.name,
                "message" => failure.message.to_s,
                "details" => if Capability.detailed?(failure)
                               sanitize_for_persistence(failure.details)
                             else
                               child && child["details"]
                             end
              }.compact
            end
          }
          CleanupError.new(
            "#{error.message}; cleanup failed: #{failures.map(&:message).join("; ")}",
            operation: Capability.names_operation?(error) ? error.operation : nil,
            resource_id: Capability.names_resource?(error) ? error.resource_id : nil,
            details: details,
            cleanup_errors: failures
          )
        end

        # Persisted operation payloads are reconciliation hints, never a secret
        # transport. The original fingerprint still detects token misuse while
        # this redacted copy remains safe for disk and diagnostic collection.
        def operation_payload(payload)
          payload = persisted_spec(payload) if payload.is_a?(Hash) && %w[projected secret].include?(Types.key(payload, "backend").to_s)
          sanitize_for_persistence(payload || {})
        end

        def persistence_error(error)
          message = redact_secret_text(error.message.to_s)
          details = Capability.detailed?(error) ? sanitize_for_persistence(error.details) : nil
          return error if message == error.message.to_s && (!Capability.detailed?(error) || details == error.details)

          replacement = if error.is_a?(CSIError)
                          CSIError.new(message, ambiguous: error.ambiguous?, operation: error.operation,
                                                resource_id: error.resource_id, details: details)
                        elsif error.is_a?(Error)
                          error.class.new(message, operation: error.operation, resource_id: error.resource_id,
                                                   details: details)
                        else
                          Error.new(message, details: details)
                        end
          replacement.set_backtrace(error.backtrace)
          replacement
        end

        def redact_secret_text(value)
          redactions = @csi_secret_mutex.synchronize { @secret_redactions }
          redactions.each_with_object(value.to_s.dup) do |secret, text|
            text.gsub!(secret, "[REDACTED]") unless secret.empty?
          end
        end

        def sanitize_for_persistence(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, child), result|
              text = key.to_s
              next if %w[secrets stringData token tokenRotator podCertificateProvider].include?(text) && !text.end_with?("Ref", "Reference")

              result[redact_secret_text(text)] = sanitize_for_persistence(child)
            end
          when Array
            value.map { |child| sanitize_for_persistence(child) }
          when String
            redact_secret_text(value)
          else
            Types.deep_copy(value)
          end
        end

        def persisted_spec(spec)
          backend = Types.key(spec, "backend", "").to_s
          spec = compact_projected_pod(spec) if backend.casecmp?("projected")
          copy = Types.deep_copy(spec)
          if backend.casecmp?("csi")
            had_secrets = Types.present?(Types.key(copy, "secrets"))
            references = copy.delete("secretRefs")
            copy = sanitize_for_persistence(copy)
            copy["secretRefs"] = references if references
            copy["csiSecrets"] = {"redacted" => true, "resolverRequiredAfterRestart" => true} if had_secrets
            return copy
          end
          if backend.casecmp?("projected")
            copy.delete("tokenRotator")
            copy.delete("podCertificateProvider")
          end
          secret = backend.casecmp?("secret") ||
                   (backend.casecmp?("projected") && secret_projection_present?(Types.key(copy, "sources", [])))
          return copy unless secret

          copy = redact_projected_secret_payload(copy, secret_context: backend.casecmp?("secret"))
          copy["secretProjection"] = {"redacted" => true}
          copy
        end

        COMPACT_PROJECTION_SOURCES = %w[configMap secret serviceAccountToken clusterTrustBundle].freeze

        # Kubelet-resolved files already carry their data. Built-in credentials
        # need the bound token identity and file ownership during recovery.
        # Raw sources and injected providers can inspect other Pod fields.
        def compact_projected_pod(spec)
          pod = Types.key(spec, "pod")
          return spec unless pod.is_a?(Hash) && Types.key(spec, "projector").nil?

          sources = Array(Types.key(spec, "sources"))
          return spec unless sources.all? { |source| source.is_a?(Hash) && (source.keys.map(&:to_s) - COMPACT_PROJECTION_SOURCES).empty? }

          token = ProjectedBackend.service_account_token_source?(sources)
          return spec if token && !@token_provider.instance_of?(ServiceAccountTokenProvider)

          compact = spec.reject { |key, _| key.to_s == "pod" }
          ownership = Types.key(spec, "credentialOwnership") || ProjectedBackend.credential_ownership(pod)
          compact["credentialOwnership"] = ownership unless ownership.empty?
          compact["pod"] = ServiceAccountTokenProvider.pod_context(pod) if token
          compact
        end
        private :compact_projected_pod

        SECRET_PROJECTION_SOURCE_KEYS = %w[secret serviceAccountToken service_account_token].freeze
        SECRET_PROJECTION_PAYLOAD_KEYS = %w[data binaryData binary_data stringData string_data files binaryFiles token tokenRotator token_rotator
                                            podCertificateProvider pod_certificate_provider].freeze

        def secret_projection_present?(value)
          case value
          when Hash
            value.any? do |key, child|
              SECRET_PROJECTION_SOURCE_KEYS.include?(key.to_s) || secret_projection_present?(child)
            end
          when Array
            value.any? { |child| secret_projection_present?(child) }
          else
            false
          end
        end

        def redact_projected_secret_payload(value, secret_context: false)
          case value
          when Hash
            value.each_with_object({}) do |(key, child), result|
              text = key.to_s
              nested_secret = secret_context || SECRET_PROJECTION_SOURCE_KEYS.include?(text)
              next if nested_secret && SECRET_PROJECTION_PAYLOAD_KEYS.include?(text)

              result[Types.deep_copy(key)] = redact_projected_secret_payload(child, secret_context: nested_secret)
            end
          when Array
            value.map { |child| redact_projected_secret_payload(child, secret_context: secret_context) }
          else
            Types.deep_copy(value)
          end
        end
      end
    end
  end
end
