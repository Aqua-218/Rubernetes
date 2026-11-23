# frozen_string_literal: true

require_relative "../kubernetes_csi_secret_resolver"

# CSI secrets, which never touch disk: the ones a create call supplied are held
# in memory, the rest are resolved on demand through the injected resolver, and
# every resolved value is registered for redaction.
module Rubernetes
  module Volume
    class Manager
      module CSISecrets
        SECRET_SCOPES = {
          node_stage: "nodeStage",
          node_publish: "nodePublish",
          node_expand: "nodeExpand",
          controller_publish: "controllerPublish",
          controller_unpublish: "controllerPublish",
          expand: "controllerExpand"
        }.freeze

        def normalize_csi_secret_references(spec)
          references = Types.key(spec, "secretRefs")
          return if references.nil?
          raise ValidationError, "CSI Secret references must be a map" unless references.is_a?(Hash)

          spec["secretRefs"] = references.to_h do |purpose, reference|
            key = purpose.to_s
            raise ValidationError, "unknown CSI Secret reference purpose" unless SECRET_SCOPES.value?(key)

            [key, KubernetesCSISecretResolver.normalize_reference(reference)]
          end
          spec.delete(:secretRefs)
          spec.delete("secret_refs")
          spec.delete(:secret_refs)
        end

        def remember_csi_secrets(id, spec)
          return true unless Types.key(spec, "backend").to_s.casecmp?("csi")

          secrets = Types.key(spec, "secrets")
          return true unless secrets
          raise ValidationError, "CSI secrets must be a map" unless Capability.hash_like?(secrets)

          normalized = secrets.to_h.each_with_object({}) do |(key, value), result|
            raise TypeError if value.is_a?(Hash) || value.is_a?(Array)

            result[String(key)] = String(value)
          rescue TypeError
            raise ValidationError, "CSI secret keys and values must be strings"
          end.freeze
          @csi_secret_mutex.synchronize { @volatile_csi_secrets[id.to_s] = normalized }
          record_csi_secret_redactions(normalized)
          true
        end

        def forget_csi_secrets(id)
          @csi_secret_mutex.synchronize { @volatile_csi_secrets.delete(id.to_s) }
          true
        end

        private

        # Populate the redaction registry before any recovery observation RPC.
        # A plugin is untrusted and may echo a secret in a ListVolumes or
        # pagination error, so a resolver failure must fence all CSI
        # observations rather than allowing a raw error to enter the report.
        def prime_csi_secret_redactions!
          failures = []
          volume_store.values.each do |record|
            next unless record.backend.to_s.casecmp?("csi")
            next unless csi_secret_reference_present?(record.spec)

            begin
              references = Types.key(record.spec, "secretRefs")
              if Types.present?(references)
                references.values.uniq.each do |reference|
                  resolve_csi_secret_reference(reference, id: record.id, purpose: :recovery_redaction)
                end
              else
                resolve_csi_secrets(record.id, record.spec, purpose: :recovery_redaction)
              end
            rescue StandardError
              failures << {
                "kind" => "csi-secret-redaction",
                "volumeId" => record.id.to_s,
                "error" => "CSI recovery secret redaction preflight failed"
              }
            end
          end
          [failures.empty?, failures]
        end

        def csi_secret_reference_present?(spec)
          Types.present?(Types.key(spec, "secretRef", Types.key(spec, "secretsRef"))) ||
            Types.present?(Types.key(spec, "secretRefs")) ||
            Types.present?(Types.key(spec, "csiSecrets")) ||
            Types.present?(Types.key(spec, "secrets"))
        end

        def resolve_csi_secrets(id, spec, purpose:)
          scoped = Types.key(spec, "secretRefs")
          if Types.present?(scoped)
            reference = scoped[SECRET_SCOPES[purpose]]
            return reference ? resolve_csi_secret_reference(reference, id: id, purpose: purpose) : {}
          end

          volatile = @csi_secret_mutex.synchronize { @volatile_csi_secrets[id.to_s] }
          return Types.deep_copy(volatile) if volatile

          reference = Types.key(spec, "secretRef", Types.key(spec, "secretsRef"))
          required = Types.present?(reference) || Types.present?(Types.key(spec, "csiSecrets"))
          return {} unless required

          resolve_csi_secret_reference(reference, id: id, purpose: purpose)
        end

        def resolve_csi_secret_reference(reference, id:, purpose:)
          raise CSIUnavailable, "CSI secret resolver is not configured for volume #{id}" unless @secret_resolver

          value = call_secret_resolver(reference, volume_id: id.to_s, purpose: purpose.to_s)
          hash = Capability.hash_like?(value) ? value.to_h : nil
          raise CSIUnavailable, "CSI secret resolver returned a non-map for volume #{id}" unless hash

          resolved = hash.each_with_object({}) do |(key, child), result|
            raise TypeError if child.is_a?(Hash) || child.is_a?(Array)

            result[String(key)] = String(child)
          rescue TypeError
            raise CSIUnavailable, "CSI secret resolver returned non-string data for volume #{id}"
          end
          record_csi_secret_redactions(resolved)
          resolved
        end

        def record_csi_secret_redactions(secrets)
          @csi_secret_mutex.synchronize { @secret_redactions |= secrets.values }
        end

        # The resolver is an object with #resolve or any callable, taking the
        # options either as keywords or as one trailing hash.
        def call_secret_resolver(reference, **resolver_options)
          resolves = Capability.resolver_object?(@secret_resolver)
          raise CSIUnavailable, "CSI secret resolver must implement resolve or call" unless resolves || Capability.callable?(@secret_resolver)

          resolver_method = @secret_resolver.method(resolves ? :resolve : :call)
          resolver_parameters = if !resolves && Capability.declares_parameters?(@secret_resolver)
                                  @secret_resolver.parameters
                                else
                                  resolver_method.parameters
                                end
          if resolver_parameters.any? { |kind, _| %i[key keyreq keyrest].include?(kind) }
            resolver_method.call(Types.deep_copy(reference), **resolver_options)
          else
            resolver_method.call(Types.deep_copy(reference), resolver_options)
          end
        end
      end
    end
  end
end
