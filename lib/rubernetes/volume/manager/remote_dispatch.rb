# frozen_string_literal: true

# How RemoteBackend issues one CSI RPC: the secrets resolved for its purpose,
# the effect boundary around a mutation, the keywords the adapter accepts, and
# the sanitizing of what comes back.
module Rubernetes
  module Volume
    class RemoteBackend < Backend
      module Dispatch
        private

        def with_secrets(context, purpose)
          Types.deep_copy(context).merge("secrets" => secrets_for(purpose))
        end

        def secrets_for(purpose)
          value = @secret_provider ? @secret_provider.call(purpose) : {}
          hash = Capability.hash_like?(value) ? value.to_h : nil
          raise CSIUnavailable, "CSI secret resolver returned a non-map for #{purpose}" unless hash

          hash.each_with_object({}) do |(key, child), result|
            result[String(key)] = String(child)
          rescue TypeError
            raise CSIUnavailable, "CSI secret resolver returned a non-string value for #{purpose}"
          end
        end

        def invoke_remote_mutation(effect_boundary)
          effect_boundary&.call
          yield
        rescue CSIError => error
          effect_boundary&.call(:rejected) unless error.ambiguous?
          sanitized = sanitize_error(error)
          raise if sanitized.equal?(error)

          raise sanitized, cause: error
        rescue CSIUnavailable => error
          effect_boundary&.call(:rejected)
          sanitized = sanitize_error(error)
          raise if sanitized.equal?(error)

          raise sanitized, cause: error
        end

        # Keep compatibility with narrow injected test adapters while passing
        # every CSI context keyword to the real UDS client.
        def invoke_csi(method_name, *, **kwargs)
          method = @csi.method(method_name)
          parameters = method.parameters
          return method.call(*, **kwargs) if parameters.any? { |kind, _| kind == :keyrest }

          accepted = kwargs.select do |key, _|
            parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name.to_sym == key.to_sym }
          end
          method.call(*, **accepted)
        rescue NoMethodError
          raise CSIUnavailable, "CSI adapter does not implement #{method_name}"
        end

        def sanitize_response(value)
          return AdapterSupport.result_hash(value) unless @persistence_sanitizer

          @persistence_sanitizer.call(AdapterSupport.result_hash(value))
        end

        def sanitize_error(error)
          @error_sanitizer ? @error_sanitizer.call(error) : error
        end

        def ambiguous_remote_error?(error)
          return false unless error
          return true if Capability.reports_ambiguity?(error) && error.ambiguous?

          error.class.name.to_s.match?(/Unknown|Ambiguous|Timeout|EOF|ConnectionReset|BrokenPipe/)
        end
      end
    end
  end
end
