# frozen_string_literal: true

require "ipaddr"
require_relative "../../platform/linux/pidfd"
require_relative "../../platform/linux/native_adapters/contract"

module Rubernetes
  module Runtime
    module CRI
      module PodSandboxes
        def run_sandbox(pod, runtime_class: nil, **_options)
          pod = stringify(pod)
          @user_namespaces.with_options(pod) { |options| create_pod_sandbox(pod, options) }
        end

        def stop_sandbox(sandbox, timeout: nil)
          @client.runtime("StopPodSandbox", {"pod_sandbox_id" => key(sandbox)})
          true
        end

        def remove_sandbox(sandbox)
          id = key(sandbox)
          remove_cri_sandbox(id)
          existing = @mutex.synchronize { @sandboxes[id] }
          if existing&.dig(:config, "linux", "security_context", "namespace_options", "userns_options", "mode") == "POD"
            @user_namespaces.release(existing.dig(:config, "metadata", "uid"))
          end
          entry = @mutex.synchronize do
            @containers.delete_if { |_container, value| value[:sandbox] == id }
            @network_holders.delete(id)&.fetch(:descriptor)&.close
            @sandboxes.delete(id)
          end
          remove_pod_cgroup(entry[:cgroup]) if entry && entry[:cgroup]
          true
        end

        def cri_log_pods(node_name:) = @pod_logs.api_pods(node_name: node_name)

        def remove_pod_logs(pod)
          metadata = pod.fetch("metadata", {})
          @pod_logs.remove(metadata, node_name: pod.dig("spec", "nodeName")) do
            uid = metadata.fetch("uid")
            filter = {"label_selector" => {"io.kubernetes.pod.uid" => uid}}
            active = Array(@client.runtime("ListPodSandbox", {"filter" => filter})["items"])
            raise Backend::Error, "Pod #{uid} still has a CRI sandbox" if active.any? { |sandbox| sandbox.dig("metadata", "uid") == uid }
          end
        end

        # determinePodSandboxIPs: the runtime's primary address comes first.
        def sandbox_network_ips(sandbox)
          network = @client.runtime("PodSandboxStatus", {"pod_sandbox_id" => key(sandbox)}).dig("status", "network")
          return [] unless network

          addresses = Array(network["additional_ips"]).map { |entry| entry["ip"] }
          primary = network["ip"]
          addresses.unshift(primary) unless primary.to_s.empty?
          return nil unless addresses.all? { |address| address.is_a?(String) && address.match?(/\A[0-9a-fA-F:.]+\z/) }

          addresses.each { |address| IPAddr.new(address) }
          addresses
        rescue IPAddr::Error
          nil
        end

        def sandbox_container_ids(sandbox)
          id = key(sandbox)
          response = @client.runtime("ListContainers", {"filter" => {"pod_sandbox_id" => id}})
          Array(response["containers"]).filter_map { |entry| entry["id"] if entry["pod_sandbox_id"] == id }
        end

        def sandbox_state(sandbox)
          id = key(sandbox)
          status = @client.runtime("PodSandboxStatus", {"pod_sandbox_id" => id})["status"]
          return unless status && status["id"] == id

          case status["state"]
          when "SANDBOX_READY" then :ready
          when "SANDBOX_NOTREADY" then :stopped
          end
        rescue Client::Error => error
          raise unless error.code == Client::NOT_FOUND

          :stopped
        end

        # The node opens the namespace through a verified pause-process
        # identity. Hold the pidfd until sandbox cleanup finishes.
        def network_sandbox_context(sandbox)
          id = key(sandbox)
          status = @client.runtime("PodSandboxStatus", {"pod_sandbox_id" => id, "verbose" => true})
          pid = sandbox_network_pid(id, status)
          path = "/proc/#{pid}/ns/net"
          holder = network_holder(id, pid, path)
          {"sandbox_id" => id,
           "netns" => {"handle" => "cri:#{id}", "path" => path, "inode" => holder.fetch(:inode), "pid" => pid,
                       "pidfd" => holder.fetch(:descriptor).fileno, "start_time" => holder.fetch(:start_time)}}
        rescue Client::Error => error
          raise unless error.code == Client::NOT_FOUND

          raise Backend::Error, "unknown sandbox #{id}"
        rescue JSON::ParserError, Platform::Linux::Error, SystemCallError, IOError, ArgumentError => error
          raise Backend::Error, "sandbox #{id} network namespace is unavailable: #{error.message}"
        end

        private

        # ListPodSandbox does not include Linux namespace options. Restore the
        # setting from real sandbox status before creating another container.
        def sandbox_namespace_options(id, entry)
          security = entry.fetch(:config).fetch("linux").fetch("security_context")
          return security["namespace_options"] if security["namespace_options"]

          status = @client.runtime("PodSandboxStatus", {"pod_sandbox_id" => id})["status"]
          options = @user_namespaces.recover_options(status) if status && status["id"] == id
          raise Backend::Error, "sandbox #{id} has no recoverable namespace options" unless options

          security["namespace_options"] = options
        end

        def sandbox_network_pid(id, status)
          info = JSON.parse(status.dig("info", "info") || "{}")
          pid = Integer(info["pid"] || 0)
          return pid if pid.positive?

          config = @mutex.synchronize { @sandboxes[id]&.fetch(:config) }
          network = config&.dig("linux", "security_context", "namespace_options", "network") ||
                    status.dig("status", "linux", "namespaces", "options", "network")
          raise Backend::Error, "sandbox #{id} reports no pause process" unless network == "NODE"

          Process.pid
        end

        def network_holder(id, pid, path)
          @mutex.synchronize do
            raise Backend::Error, "unknown sandbox #{id}" unless @sandboxes.key?(id)

            @pidfds ||= Platform::Linux::Pidfd.new
            previous = @network_holders[id]
            return previous if previous && previous[:pid] == pid && @pidfds.alive?(pidfd: previous.fetch(:descriptor).fileno)

            @network_holders[id] = open_network_holder(pid, path)
            previous&.fetch(:descriptor)&.close
            @network_holders.fetch(id)
          end
        end

        def open_network_holder(pid, path)
          identity = Platform::Linux::NativeAdapters::ProcessIdentity
          start_time = identity.process_start_time(pid)
          descriptor = IO.for_fd(@pidfds.open(pid: pid))
          inode = File.stat(path).ino
          if identity.process_start_time(pid) != start_time || !@pidfds.alive?(pidfd: descriptor.fileno)
            raise Backend::Error, "sandbox network pause process changed while opening its pidfd"
          end

          {pid: pid, descriptor: descriptor, inode: inode, start_time: start_time}
        rescue StandardError
          descriptor&.close
          raise
        end

        def remove_cri_sandbox(id)
          @client.runtime("StopPodSandbox", {"pod_sandbox_id" => id})
          @client.runtime("RemovePodSandbox", {"pod_sandbox_id" => id})
        rescue Client::Error => error
          raise unless error.code == Client::NOT_FOUND
        end

        # A sandbox learned from the runtime (after a restart): its config is
        # rebuilt from what CreateContainer needs.
        def remember_sandbox(id, status)
          metadata = status["metadata"] || {}
          options = @user_namespaces.recover_options(status)
          cgroup = pod_cgroup_path(metadata["uid"])
          cgroup = nil unless cgroup && File.directory?(File.join(@cgroup_root, cgroup))
          @mutex.synchronize do
            @sandboxes[id] ||= {config: {"metadata" => metadata, "labels" => status["labels"] || {},
                                         "linux" => {"security_context" => {"namespace_options" => options}, "cgroup_parent" => cgroup}.compact,
                                         "log_directory" => File.join(@log_root, "#{metadata["namespace"]}_#{metadata["name"]}_#{metadata["uid"]}")},
                                pod: {"metadata" => metadata}, cgroup: cgroup}
          end
        end

        def create_pod_sandbox(pod, userns_options)
          @log_manager&.start
          config = sandbox_config(pod)
          @user_namespaces.record_options(config, userns_options)
          @pod_logs.prepare(pod.fetch("metadata"), node_name: pod.dig("spec", "nodeName"))
          cgroup = create_pod_cgroup(pod)
          config["linux"]["cgroup_parent"] = cgroup if cgroup
          response = @client.runtime("RunPodSandbox", {"config" => config, "runtime_handler" => @handler}, timeout: 240)
          id = response.fetch("pod_sandbox_id")
          @mutex.synchronize { @sandboxes[id] = {config: config, pod: pod, cgroup: cgroup} }
          id
        end
      end
    end
  end
end
