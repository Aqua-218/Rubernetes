# frozen_string_literal: true

# Building the backend object behind a volume record: a built-in backend or a
# RemoteBackend bound to its CSI adapter, at create time, on demand, and for
# every stored record at startup (fencing the ones that cannot be rebuilt).
module Rubernetes
  module Volume
    class Manager
      module BackendFactory
        def backend_for(id)
          return backends[id.to_s] if backends.key?(id.to_s)

          record = fetch_record(id)
          ensure_known!(record)
          begin
            backend = build_backend(id.to_s, record.spec)
            backends[id.to_s] = backend
            backend
          rescue StandardError => error
            mark_unknown(id)
            raise StateUnknownError,
                  "volume #{id} backend reconstruction failed; recover before mutation: #{redact_secret_text(error.message.to_s)}"
          end
        end

        # The kubelet's CSI plugin registry, used when no single CSI adapter
        # was configured.
        def csi_registry=(registry)
          return if @csi || registry.nil?

          @csi = registry
          # As at construction with csi:, CSI dispatch needs descriptor-safe
          # targets.
          @path_security = descriptor_path_security if @default_path_security
          recover_unconfigured_csi_backends!
        end

        # Volumes whose backend could not be rebuilt only because no CSI
        # adapter existed at recovery get their backend and state back.
        def recover_unconfigured_csi_backends!
          volume_store.values.each do |record|
            operation = record.operation || {}
            next unless record.state == "Unknown" && Types.key(operation, "csiUnconfigured", false) == true

            with_volume_lock(record.id) do
              @backends[record.id] = build_backend(record.id, record.spec)
              previous = Types.key(operation, "previousState", "").to_s
              volume_store[record.id] = record.with(state: previous.empty? ? "Unknown" : previous, operation: nil,
                                                    generation: record.generation + 1)
            end
          rescue StandardError
            next
          end
        end

        def build_backend(id, spec)
          backend_name = Types.key(spec, "backend", "emptyDir").to_s
          return build_remote_backend(id, spec) if backend_name.casecmp?("csi")

          klass = BUILTIN_BACKENDS[backend_name] || BUILTIN_BACKENDS[backend_name.downcase] ||
                  raise(UnsupportedError, "unsupported volume backend #{backend_name.inspect}")
          klass.new(id: id, spec: spec, adapter: @adapter, root: @root, path_security: @path_security,
                    mount_adapter: @mount_adapter, device_adapter: @device_adapter,
                    require_real_readback: @require_real_readback)
        end

        private

        def build_remote_backend(id, spec)
          csi = @csi || csi_adapter_from_spec(spec)
          # A kubelet plugin registry resolves the node plugin registered
          # under the volume's driver name.
          registered = Capability.plugin_registry?(csi)
          csi = RegisteredCSIDriver.new(csi, Types.key(spec, "driver").to_s) if registered
          raise CSIUnavailable, "CSI adapter is not configured; initialize Manager with csi:" unless csi && Capability.csi_adapter?(csi)

          # A registered plugin is looked up by the driver name itself.
          validate_csi_driver!(spec, csi) unless registered

          RemoteBackend.new(id: id, spec: spec, adapter: @adapter, root: @root, path_security: @path_security,
                            mount_adapter: @mount_adapter, device_adapter: @device_adapter,
                            # A native node agent must independently
                            # observe CSI effects in its own mount
                            # namespace.  Test-profile adapters remain
                            # explicitly non-native and may use their
                            # injected lifecycle identities.
                            require_real_readback: @require_real_readback, csi: csi,
                            secret_provider: ->(purpose) { resolve_csi_secrets(id, spec, purpose: purpose) },
                            persistence_sanitizer: method(:sanitize_for_persistence),
                            error_sanitizer: method(:persistence_error))
        end

        def csi_adapter_from_spec(spec)
          candidate = Types.key(spec, "csi")
          return nil if candidate.nil? || candidate.is_a?(Hash)

          candidate
        end

        def validate_csi_driver!(spec, csi)
          requested = Types.key(spec, "driver").to_s
          return true if requested.empty?
          unless Capability.reports_identity?(csi)
            raise CSIUnavailable, "CSI adapter identity is unavailable; cannot verify requested driver #{requested.inspect}"
          end

          identity = csi.identity
          actual = if Capability.named?(identity)
                     identity.name.to_s
                   else
                     Types.key(Capability.hash_like?(identity) ? identity.to_h : {}, "name").to_s
                   end
          raise CSIUnavailable, "CSI adapter returned an empty plugin identity" if actual.empty?
          return true if actual == requested

          raise CSIUnavailable, "CSI driver mismatch: volume requests #{requested.inspect}, configured plugin is #{actual.inspect}"
        end

        def recover_backends_from_store!
          volume_store.each_value do |record|
            @backends[record.id] = build_backend(record.id, record.spec)
          rescue StandardError => error
            # A corrupt/incomplete record remains visible but is fenced.  The
            # old behavior swallowed the reconstruction failure, allowing a
            # later mutation to hit a missing backend and fail open as a
            # generic KeyError.
            previous_state = record.state
            mark_unknown(record.id)
            operation = {"status" => "unknown", "reason" => "backend reconstruction failed",
                         "error" => redact_secret_text(error.message.to_s), "previousState" => previous_state}
            # No CSI adapter yet: a kubelet plugin registry attached later
            # (csi_registry=) reconstructs the volume.
            operation["csiUnconfigured"] = true if error.is_a?(CSIUnavailable) && @csi.nil?
            volume_store[record.id] = volume_store[record.id].with(operation: operation)
          end
        end
      end
    end
  end
end
