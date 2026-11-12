# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        # Executes trusted stream helpers in an existing Pod.  Exec joins the
        # live container's namespaces (§5.8.10) and reapplies the container
        # security plan; port-forward and probes join only the holder's network
        # namespace with a host-owned static helper or an in-process socket.
        class NamespaceConnector
          include CapabilityContract

          BUSYBOX_CANDIDATES = %w[/usr/bin/busybox /bin/busybox].freeze

          def initialize(process_adapter:, cgroup_adapter:, namespace_adapter: nil)
            @process = process_adapter
            @cgroup = cgroup_adapter
            @namespace_adapter = namespace_adapter
          end

          def native_capabilities
            process_capabilities = @process.native_capabilities.to_h
            process_ready = process_capabilities[:process_gate] == true && process_capabilities[:child_exec] == true
            {
              namespace_exec_streams: process_ready,
              namespace_port_forward: process_ready && !busybox_path.nil?,
              namespace_probe: !@namespace_adapter.nil?
            }.freeze
          end

          def validate_native_capabilities!
            capabilities = native_capabilities
            require_capability!(capabilities.fetch(:namespace_exec_streams), "namespace exec stream helper is unavailable")
            require_capability!(capabilities.fetch(:namespace_port_forward), "static namespace port-forward helper is unavailable")
            true
          end

          SYSCTL_NAMESPACES = {"net" => :network, "kernel" => :ipc, "fs" => :ipc}.freeze

          # Namespaced sysctls (net.* in the network namespace, kernel.shm*/
          # msg*/sem and fs.mqueue.* in the IPC namespace) are written to
          # /proc/sys by a helper joined to the sandbox's namespaces; /proc/sys
          # reflects the writer's own namespaces.
          def apply_sysctls(sandbox:, sysctls:, **_options)
            raise EffectError, "sysctls require a namespace adapter" unless @namespace_adapter

            handle = sandbox.namespace.adapter_handle
            entries = Array(sysctls).map do |entry|
              name = String(entry["name"] || entry[:name]).tr("/", ".")
              raise EffectError, "invalid sysctl name #{name.inspect}" unless name.match?(/\A[a-z0-9_.-]+\z/i) && !name.include?("..")

              family = name.split(".").first
              namespace = SYSCTL_NAMESPACES[family]
              raise EffectError, "sysctl #{name.inspect} is not namespaced" unless namespace

              [name, String(entry["value"] || entry[:value]), namespace]
            end
            entries.group_by(&:last).each do |namespace, group|
              @namespace_adapter.within_namespaces(handle, only: [namespace], timeout: 10.0) do
                group.map do |name, value, _|
                  path = File.join("/proc/sys", name.tr(".", "/"))
                  File.write(path, value)
                  name
                end
              end
            end
            entries.map { |name, value, _| "#{name}=#{value}" }
          end

          private

          def busybox_path
            @busybox_path ||= BUSYBOX_CANDIDATES.find do |path|
              File.executable?(path) && File.binread(path, 4) == "\x7FELF".b
            rescue SystemCallError
              false
            end
          end
        end
      end
    end
  end
end
