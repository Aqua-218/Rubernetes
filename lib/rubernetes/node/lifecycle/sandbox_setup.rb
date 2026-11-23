# frozen_string_literal: true

require_relative "../volume_groups"

module Rubernetes
  module Node
    class Lifecycle
      # The Pod sandbox and what is attached to it: the sandbox itself, its
      # network and host ports, sysctls, and the Pod's own files.
      module SandboxSetup
        attr_writer :pod_cgroup_manager

        private

        def with_native_pod_cgroup(pod, &)
          return yield unless @pod_cgroup_manager

          runtime = runtime_for_pod(pod)
          return yield unless runtime.is_a?(Runtime::Native)

          qos = Runtime::Native::Resources.qos_class(pod)
          @pod_cgroup_manager.with_pod_cgroup(pod.dig("metadata", "uid"), qos, &)
        end

        def create_sandbox(pod, record)
          event(record, "sandbox.create")
          spec = Helpers.key(pod, "spec", {})
          runtime_class = pod_runtime_class(pod)
          runtime_input = pod
          unless record[:images].empty?
            runtime_input = Helpers.deep_copy(pod)
            runtime_input["resolved_images"] = record[:images].map { |image| image_to_hash(image) }
            runtime_input["image_digest"] = record[:image_digest]
            runtime_input["lowerdirs"] = record[:images].filter_map do |image|
              image_to_hash(image)["rootfs"]
            end.uniq
          end
          if @container_spec && Helpers.key(spec, "hostNetwork", false) != true
            runtime_input = Helpers.deep_copy(runtime_input) if runtime_input.equal?(pod)
            # kubelet: the UTS hostname is spec.hostname or the Pod name.
            runtime_input["hostname"] = @container_spec.pod_hostname(pod)
          end
          if @pod_files.is_a?(PodFiles)
            record[:dns_config] = @pod_files.dns_config(pod, host_network: spec["hostNetwork"] == true, node_ips: @host_ips) do |scope, reason, message|
              event(record, "dns.warning", scope: scope, reason: reason, message: message)
            end
            runtime_input = runtime_input.merge("dns_config" => record[:dns_config])
          end
          security = Helpers.key(spec, "securityContext", {}) || {}
          with_volume_groups = VolumeGroups.apply(security, record[:volume])
          unless with_volume_groups.equal?(security)
            runtime_input = Helpers.deep_copy(runtime_input) if runtime_input.equal?(pod)
            runtime_input["spec"] = spec.merge("securityContext" => with_volume_groups)
          end
          if %w[rubernetes-firecracker rubernetes-firecracker-restricted].include?(runtime_class)
            block_volumes = sandbox_block_volumes(pod, record[:volume])
            unless block_volumes.empty?
              runtime_input = Helpers.deep_copy(runtime_input) if runtime_input.equal?(pod)
              runtime_input["block_volumes"] = block_volumes
            end
          end
          invoke(@runtime, :run_sandbox, runtime_input, runtime_class: runtime_class)
        rescue PodHostname::Error, PodFiles::Error => error
          record[:reason] = "FailedCreatePodSandBox"
          raise LifecycleError, "Failed to create pod sandbox: #{error.message}"
        end

        def pod_runtime_class(pod)
          return @runtime_class_resolver.call(pod) if @runtime_class_resolver

          Helpers.key(Helpers.key(pod, "spec", {}), "runtimeClassName", nil)
        end

        def runtime_for_pod(pod)
          return @runtime unless defined?(Runtime::Multiplexer) && @runtime.is_a?(Runtime::Multiplexer)

          @runtime.backend_for(@runtime.handler_for(pod, runtime_class: pod_runtime_class(pod)))
        end

        def cri_runtime_for_pod?(pod)
          defined?(Runtime::CRI::Backend) && runtime_for_pod(pod).is_a?(Runtime::CRI::Backend)
        end

        def sandbox_block_volumes(pod, handle)
          return {} unless handle.is_a?(Hash) && handle["mounts"].is_a?(Hash)

          spec = Helpers.key(pod, "spec", {})
          names = %w[initContainers containers ephemeralContainers].flat_map do |group|
            Array(Helpers.key(spec, group, [])).flat_map do |container|
              Array(Helpers.key(container, "volumeDevices", [])).map { |entry| Helpers.key(entry, "name").to_s }
            end
          end
          handle["mounts"].slice(*names).filter_map do |name, volume|
            [name, {"source" => volume.fetch("path"), "readonly" => volume["readonly"] == true}] if volume["volumeMode"] == "Block"
          end.to_h
        end

        def native_runtime?
          defined?(Rubernetes::Runtime::Native) && @runtime.is_a?(Rubernetes::Runtime::Native)
        end

        def network_sandbox_context(record)
          sandbox_id = record.fetch(:sandbox_id)
          context = if runtime_supports?(:network_sandbox_context)
                      invoke(@runtime, :network_sandbox_context, sandbox_id)
                    else
                      record[:sandbox_context]
                    end
          context = context.to_h if hash_convertible?(context)
          return sandbox_id unless context.is_a?(Hash)

          value = Helpers.string_keys(context)
          value["sandbox_id"] ||= sandbox_id.to_s
          return sandbox_id if value.keys == ["sandbox_id"]

          record[:sandbox_context] = Helpers.deep_copy(value)
          value
        rescue StandardError => error
          # A stored descriptor remains valid recovery input only when the
          # runtime cannot expose a live descriptor. If a live lookup exists
          # and fails, do not silently target the host namespace.
          if runtime_supports?(:network_sandbox_context)
            # The runtime no longer holds the sandbox at all (startup recovery
            # released it: its namespace and links are gone with it).  That is
            # not a lookup that might land on the host namespace; it is the
            # answer "nothing left to enter", which the caller handles.
            raise SandboxGone, "sandbox #{sandbox_id} is gone: #{Helpers.failure_message(error)}" if Helpers.failure_message(error).include?("unknown sandbox")

            raise LifecycleError,
                  "sandbox network namespace lookup failed: #{Helpers.failure_message(error)}"
          end

          record[:sandbox_context] || sandbox_id
        end

        def connect_network(pod, record)
          event(record, "network.connect", sandbox_id: record[:sandbox_id])
          unless @network
            refresh_runtime_pod_ips(record)
            return nil
          end

          sandbox = network_sandbox_context(record)

          result = invoke(@network, :add, sandbox, pod)
          record[:network] = Helpers.string_keys(result.to_h) if hash_convertible?(result)
          publish_host_ports(pod, record)
          result
        end

        # With no node network configured, the runtime's CNI owns the Pod
        # network. Keep the addresses without claiming the network resource.
        def refresh_runtime_pod_ips(record)
          return false if @network || !record[:sandbox_id] || !runtime_supports?(:sandbox_network_ips)
          return false if record[:runtime_pod_ips]&.any? || record.dig(:pod, "spec", "hostNetwork") == true

          ips = best_effort { invoke(@runtime, :sandbox_network_ips, record[:sandbox_id]) }
          return false if ips.nil? || ips.empty?

          record[:runtime_pod_ips] = ips
          true
        end

        # containerPort.hostPort has to be programmed on the node once the Pod
        # has an address; nothing did, so a Pod with a hostPort was scheduled and
        # then unreachable.
        def publish_host_ports(pod, record)
          return if @host_ports.nil? || Helpers.key(Helpers.key(pod, "spec", {}), "hostNetwork", false) == true

          mappings = Network::HostPort.mappings_for(pod)
          return if mappings.empty?

          ips = pod_ips(record)
          return if ips.empty?

          ips.each do |ip|
            family = ip.include?(":") ? :ipv6 : :ipv4
            published = @host_ports.ensure!(pod_uid: record[:uid], pod_ip: ip, pod: pod, family: family)
            next if published.nil? || published.empty?

            event(record, "network.host_ports_published",
                  ports: published.map { |mapping| "#{mapping.protocol}/#{mapping.host_port}->#{mapping.container_port}" })
          end
        rescue StandardError => error
          raise LifecycleError, "host port publication failed: #{Helpers.failure_message(error)}"
        end

        def withdraw_host_ports(record)
          return if @host_ports.nil?

          # A rule that is already gone, or a firewall that cannot be reached
          # while the Pod is being torn down, does not keep the Pod from
          # finishing; the next Pod claiming the port programs it afresh.
          best_effort { %i[ipv4 ipv6].each { |family| @host_ports.remove!(pod_uid: record[:uid], family: family) } }
        end

        # kubelet applies spec.securityContext.sysctls to the sandbox's network
        # and IPC namespaces once they exist; admission already refused unsafe
        # ones.
        def apply_sysctls(pod, record)
          sysctls = Array(Helpers.key(Helpers.key(Helpers.key(pod, "spec", {}), "securityContext", {}) || {}, "sysctls", []))
          sysctls = sysctls.map { |entry| Helpers.string_keys(entry) }.reject { |entry| entry["name"].to_s == "" }
          return if sysctls.empty?
          raise LifecycleError, "runtime does not apply sysctls" unless runtime_supports?(:apply_sysctls)

          event(record, "sysctls.apply", sysctls: sysctls.map { |entry| "#{entry["name"]}=#{entry["value"]}" })
          invoke(@runtime, :apply_sysctls, record[:sandbox_id], sysctls)
        end

        # /etc/hosts, /etc/hostname and /etc/resolv.conf for the Pod, plus a
        # second pass over downward API projections now that the Pod IP exists.
        def prepare_pod_files(pod, record)
          return unless @pod_root

          directory = File.join(pod_directory(record), "etc")
          host_network = Helpers.key(Helpers.key(pod, "spec", {}), "hostNetwork", false) == true
          ips = pod_ips(record)
          begin
            options = {directory: directory, pod_ips: ips, host_network: host_network, hostname: @container_spec&.pod_hostname(pod)}
            options[:dns_config] = record[:dns_config] if record[:dns_config]
            record[:pod_files] = @pod_files.write(pod, **options)
          rescue PodFiles::Error => error
            record[:reason] = "CreateContainerConfigError"
            raise LifecycleError, error.message
          end
          event(record, "pod.files", files: record[:pod_files].keys)
          return unless @pod_volumes && record[:volume].is_a?(Hash)

          @pod_volumes.refresh(pod, record[:volume], pod_ips: ips, host_ip: @host_ip)
        end
      end
    end
  end
end
