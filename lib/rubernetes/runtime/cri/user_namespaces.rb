# frozen_string_literal: true

module Rubernetes
  module Runtime
    module CRI
      # The CRI's runtime-wide feature and its selected handler's ability to
      # set up user namespaces are both needed for host-networked Pods.
      class UserNamespaces
        RUNTIME_FEATURE = "userNamespacesHostNetwork"
        OPTIONS_ANNOTATION = "io.rubernetes.internal/user-namespace-options"

        # All handlers of one endpoint share the allocator and serialize
        # sandbox creation with release of a Pod's last mapping.
        class Allocations
          def initialize(allocator)
            @allocator_factory = allocator
            @mutex = Mutex.new
          end

          def with_mapping(uid)
            @mutex.synchronize { yield allocator.allocate(identity(uid)) }
          end

          def release_if_unused(uid)
            return if uid.to_s.empty?

            @mutex.synchronize { allocator.release(identity(uid)) if yield }
          end

          def lookup(uid)
            @mutex.synchronize { allocator.lookup(identity(uid)) }
          end

          private

          def allocator = (@allocator ||= @allocator_factory.call)

          def identity(uid) = "cri-pod-#{uid}"
        end

        def initialize(client:, handler:, allocations:, host_network_enabled:)
          @client = client
          @handler = handler
          @allocations = allocations
          @host_network_enabled = host_network_enabled
        end

        def runtime_features
          return {} unless @host_network_enabled && @allocations

          status = runtime_status
          {RUNTIME_FEATURE => status.dig("features", "user_namespaces_host_network") == true && handler_supports_user_namespaces?(status)}
        end

        def with_options(pod)
          spec = pod.fetch("spec", {})
          return yield nil unless spec["hostUsers"] == false

          status = runtime_status
          unless @allocations && handler_supports_user_namespaces?(status)
            raise Backend::Error, "CRI runtime handler #{@handler.inspect} does not support user namespaces"
          end
          if spec["hostNetwork"] == true && !(@host_network_enabled && status.dig("features", "user_namespaces_host_network") == true)
            raise Backend::Error, "CRI runtime handler #{@handler.inspect} does not support user namespaces with host networking"
          end
          raise Backend::Error, "CRI user namespaces cannot share the host PID or IPC namespace" if spec["hostPID"] == true || spec["hostIPC"] == true

          uid = pod.dig("metadata", "uid").to_s
          raise Backend::Error, "a Pod UID is required to allocate a user namespace" if uid.empty?

          @allocations.with_mapping(uid) do |mapping|
            yield mapping_options(mapping)
          end
        end

        def release(uid)
          @allocations&.release_if_unused(uid) do
            filter = {"label_selector" => {"io.kubernetes.pod.uid" => uid}}
            Array(@client.runtime("ListPodSandbox", {"filter" => filter})["items"]).empty?
          end
        end

        def record_options(config, userns)
          annotations = config.fetch("annotations")
          annotations.delete(OPTIONS_ANNOTATION)
          return unless userns

          namespace = config.dig("linux", "security_context", "namespace_options")
          namespace["userns_options"] = userns
          annotations[OPTIONS_ANNOTATION] = JSON.generate(namespace)
        end

        def recover_options(status)
          annotation = status.dig("annotations", OPTIONS_ANNOTATION)
          return status.dig("linux", "namespaces", "options") if annotation.nil?

          options = JSON.parse(annotation)
          mapping = @allocations&.lookup(status.dig("metadata", "uid"))
          unless mapping && options.is_a?(Hash) && options["userns_options"] == mapping_options(mapping)
            raise Backend::Error, "CRI sandbox user namespace does not match the local Pod mapping"
          end

          options
        rescue JSON::ParserError
          raise Backend::Error, "CRI sandbox has invalid persisted user namespace options"
        end

        def configure_container(config, namespace)
          return unless namespace

          config.fetch("linux").fetch("security_context")["namespace_options"] = namespace
          userns = namespace["userns_options"]
          return unless userns && userns["mode"] == "POD"

          config.fetch("mounts").each do |mount|
            # These two fields are camelCase in the CRI proto itself.
            mount["uidMappings"] = userns.fetch("uids")
            mount["gidMappings"] = userns.fetch("gids")
          end
        end

        private

        def runtime_status
          @runtime_status ||= @client.runtime("Status", {}, timeout: 5)
        rescue Client::Error
          {}
        end

        def handler_supports_user_namespaces?(status)
          handler = Array(status["runtime_handlers"]).find { |item| item["name"].to_s == @handler }
          handler&.dig("features", "user_namespaces") == true
        end

        def id_mapping(base, size)
          {"host_id" => base, "container_id" => 0, "length" => size}
        end

        def mapping_options(mapping)
          {"mode" => "POD", "uids" => [id_mapping(mapping.uid_base, mapping.size)], "gids" => [id_mapping(mapping.gid_base, mapping.size)]}
        end
      end
    end
  end
end
