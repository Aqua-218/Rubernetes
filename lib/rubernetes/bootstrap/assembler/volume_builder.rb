# frozen_string_literal: true

module Rubernetes
  module Bootstrap
    class Assembler
      # The node's volume manager: mount and device adapters for the profile,
      # path security, and the CSI plugin validated at startup.
      module VolumeBuilder
        private

        def build_volume(process, adapters: {}, client: nil)
          injected = adapters[:volume] || adapters["volume"]
          return injected if injected

          options = process["volume"]
          return nil unless options

          config = options.to_h
          runtime_profile = process.fetch("runtime_profile", "pure").to_s.downcase.tr("-", "_").to_sym
          volume_profile = config["profile"]&.then { |value| value.to_s.downcase.tr("-", "_") }
          native_profile = %i[host_integration kernel_isolation l3].include?(runtime_profile) || volume_profile == "native"
          raise Config::Error, "native runtime profiles require the native volume profile" if native_profile && %w[test fake_io].include?(volume_profile)

          mount_adapter = adapters[:mount_adapter] || adapters["mount_adapter"]
          device_adapter = adapters[:device_adapter] || adapters["device_adapter"]
          volume_adapter = adapters[:volume_adapter] || adapters["volume_adapter"]
          if !native_profile && volume_profile.nil? && runtime_profile != :fake_io &&
             [mount_adapter, device_adapter, volume_adapter].all?(&:nil?)
            raise Config::Error, "volume.profile must explicitly select test for the fake volume adapter"
          end

          if native_profile
            uuid_resolver = adapters[:filesystem_uuid_resolver] || adapters["filesystem_uuid_resolver"]
            uuid_resolver ||= Volume::FilesystemUuidResolver.new
            mount_adapter ||= Volume::NativeMountAdapter.new(filesystem_uuid_resolver: uuid_resolver)
            device_adapter ||= Volume::NativeDeviceAdapter.new
            volume_adapter ||= mount_adapter
          end
          csi = build_volume_csi(config["csi"], adapters: adapters)
          path_security = adapters[:volume_path_security] || adapters["volume_path_security"] ||
                          volume_path_security(config, adapters[:volume_resolver] || adapters["volume_resolver"])
          Volume::Manager.new(
            data_dir: config.fetch("data_dir"),
            root: config.fetch("root", File.join(config.fetch("data_dir"), "volumes")),
            adapter: volume_adapter,
            mount_adapter: mount_adapter,
            device_adapter: device_adapter,
            path_security: path_security,
            csi: csi,
            secret_resolver: adapters[:csi_secret_resolver] || adapters["csi_secret_resolver"],
            token_provider: adapters[:volume_token_provider] || adapters["volume_token_provider"] ||
                            (client && Volume::ServiceAccountTokenProvider.new(client: client)),
            require_real_readback: native_profile,
            fsync: config.fetch("fsync", true)
          )
        end

        def volume_path_security(config, resolver)
          root = config.fetch("root", File.join(config.fetch("data_dir"), "volumes")) if resolver
          return Volume::PathSecurity.new(root: root, resolver: resolver) if resolver
          raise Config::Error, "volume path security requires the Linux openat2 resolver" unless defined?(Rubernetes::Platform::Linux::Openat2)

          openat2 = Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true)
          Volume::PathSecurity.new(root: "/", adapter: openat2, require_openat2: true)
        end

        def build_volume_csi(config, adapters: {})
          injected = adapters[:csi] || adapters["csi"]
          return injected unless config

          options = config.to_h
          csi = injected || Volume::CSIBridge.new(
            socket: options.fetch("socket"),
            timeout: options.fetch("timeout", 30),
            expected_socket_uid: options.fetch("socket_uid", Process.euid),
            expected_socket_gid: options.fetch("socket_gid", Process.egid),
            expected_socket_mode: options["socket_mode"],
            expected_peer_uid: options.fetch("peer_uid", Process.euid),
            expected_peer_gid: options.fetch("peer_gid", Process.egid)
          )

          identity = normalize_csi_identity(csi.identity)
          verify_csi_identity!(identity, options["identity"]) if options["identity"]
          raise Config::Error, "CSI plugin #{identity.name} is not ready" if options.fetch("probe", true) && !csi.ready?

          csi
        rescue Config::Error
          raise
        rescue StandardError => error
          socket = options && options["socket"]
          raise Config::Error.new("CSI startup validation failed for #{socket || "injected adapter"}: #{error.message}"), cause: error
        end

        def verify_csi_identity!(identity, expected)
          expected_name = expected.fetch("name")
          expected_vendor = expected["vendor_version"] || expected["vendorVersion"]
          return if identity.name == expected_name && (!expected_vendor || identity.vendor_version == expected_vendor)

          actual = "#{identity.name}@#{identity.vendor_version}"
          wanted = expected_vendor ? "#{expected_name}@#{expected_vendor}" : expected_name
          raise Config::Error, "CSI identity mismatch: expected #{wanted}, got #{actual}"
        end

        # A bridge answers with a Volume::Identity; a plugin's raw
        # GetPluginInfo response is a mapping.
        def normalize_csi_identity(value)
          return value if value.is_a?(Volume::Identity)

          hash = value.to_h
          name = hash["name"] || hash[:name] || hash["pluginName"] || hash[:pluginName]
          vendor = hash["vendorVersion"] || hash[:vendorVersion] || hash["vendor_version"] || hash[:vendor_version]
          raise Config::Error, "CSI identity response must include name and vendor version" if name.to_s.empty? || vendor.to_s.empty?

          Volume::Identity.new(name: name, vendor_version: vendor)
        end
      end
    end
  end
end
