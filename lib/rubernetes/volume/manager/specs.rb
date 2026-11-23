# frozen_string_literal: true

# Turning what a caller hands in -- a volume spec, a Pod's volume entry -- into
# the normalized spec a volume is created from: backend detection, the volume
# id, CSI clone sources and the Pod-bound token rotator.
module Rubernetes
  module Volume
    class Manager
      module Specs
        def resolve_csi_content_sources(spec)
          copy = Types.deep_copy(spec)
          return copy unless Types.key(copy, "backend").to_s.casecmp?("csi")

          source_id = Types.key(copy, "cloneSourceId")
          return copy unless Types.present?(source_id) && volume_store[source_id.to_s]

          source = volume_store.fetch(source_id.to_s)
          driver_id = csi_driver_id(source)
          raise StateUnknownError, "CSI clone source #{source_id} has no durable driver volume id mapping" unless Types.present?(driver_id)

          copy["cloneSourceId"] = driver_id
          copy
        end

        def volume_id_for(spec)
          supplied = Types.key(spec, "id", Types.key(spec, "volumeId"))
          return Types.identifier(supplied, "volume id") if supplied

          name = Types.key(spec, "name") || Types.key(Types.key(spec, "metadata", {}), "name")
          digest = Types.digest(spec)
          name && !name.to_s.empty? ? "vol-#{name}-#{digest[0, 16]}" : "vol-#{digest[0, 24]}"
        end

        def normalize_spec(value)
          hash = Capability.hash_like?(value) ? Types.deep_copy(value.to_h) : {}
          raise ValidationError, "volume spec must be a map" unless Capability.hash_like?(value)

          backend = detect_backend(hash)
          if csi_source_present?(hash) && backend && !backend.to_s.casecmp?("csi")
            raise ValidationError, "CSI volume source cannot be combined with backend #{backend.inspect}"
          end

          if backend
            nested = Types.key(hash, backend, {})
            hash = nested.to_h.merge(hash.reject { |key, _| key.to_s.casecmp?(backend.to_s) }) if Capability.hash_like?(nested) && !nested.is_a?(String)
          end
          hash["backend"] = backend || Types.key(hash, "backend", "emptyDir").to_s
          normalize_csi_secret_references(hash) if hash["backend"].casecmp?("csi")
          hash["capacityBytes"] = Types.parse_capacity(Types.key(hash, "capacityBytes", Types.key(hash, "capacity", 1)))
          hash["accessModes"] = Types.normalize_access_modes(Types.key(hash, "accessModes")) if Types.key(hash, "accessModes")
          hash
        end

        # The rotator that mints and refreshes a projected ServiceAccount token
        # for one Pod (TokenRequest through the node's API client); nil when
        # the manager has no token provider, in which case a projected
        # serviceAccountToken source cannot be served.
        def token_rotator_for(pod)
          return nil unless @token_provider

          provider = Capability.per_pod_provider?(@token_provider) ? @token_provider.for_pod(pod.to_h) : @token_provider
          Projection::TokenRotator.new(provider: provider, clock: @clock)
        end

        private

        def detect_backend(hash)
          explicit = Types.key(hash, "backend")
          return explicit.to_s if explicit && !explicit.to_s.empty?

          typed = Types.key(hash, "type")
          return "csi" if typed && typed.to_s.casecmp?("csi")
          return typed.to_s if typed && (BUILTIN_BACKENDS.key?(typed.to_s) || BUILTIN_BACKENDS.key?(typed.to_s.downcase))
          return "csi" if csi_source_present?(hash)

          BUILTIN_BACKENDS.keys.find { |name| hash.key?(name) || hash.key?(name.to_sym) }
        end

        def csi_source_present?(hash)
          hash.key?("csi") || hash.key?(:csi)
        end

        def normalize_pod_volume(volume, pod)
          hash = Capability.hash_like?(volume) ? Types.deep_copy(volume.to_h) : {}
          name = Types.key(hash, "name") || SecureRandom.hex(4)
          source = hash.reject { |key, _| key.to_s == "name" }
          source["name"] = name
          source["pod"] = pod.to_h
          source["podUid"] = pod_identifier(pod)
          # A projected serviceAccountToken source is refused outright without a
          # rotator; the node cannot mint tokens itself, so it carries one bound
          # to this pod that asks the TokenRequest API.
          source["tokenRotator"] = token_rotator_for(pod) if @token_provider && projected_service_account_token?(source)
          source
        end

        def projected_service_account_token?(source)
          Array(Types.key(Types.key(source, "projected", {}), "sources", [])).any? do |entry|
            hash = Capability.hash_like?(entry) ? entry.to_h : {}
            hash.key?("serviceAccountToken") || hash.key?(:serviceAccountToken)
          end
        end

        def pod_identifier(pod)
          metadata = Types.key(pod.to_h, "metadata", {})
          Types.key(metadata, "uid", Types.key(metadata, "name", "pod")).to_s
        end
      end
    end
  end
end
