# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      # Validation and normalization of what callers hand the runtime: sandbox
      # input, the container's security context, mounts, command line and
      # environment.  Nothing here has an effect outside the process.
      module ContainerSpec
        # A plan is a pure function of the security context and the host probe
        # (Security#plan validates the context, compiles the seccomp program and
        # orders the steps), and every container of a burst carries the same
        # context, so the plan and its digest are computed once per distinct
        # context.  Plans are frozen Data values shared safely between
        # containers; an invalid context raises every time and is never cached.
        SECURITY_PLAN_CACHE_LIMIT = 256

        DEFAULT_EXEC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

        private

        def validate_runtime_class!(value)
          return if String(value) == config.runtime_class

          raise ConfigurationError,
                "Native backend received unsupported runtime class #{value.inspect}"
        end

        def validate_sandbox_input!(input)
          validate_runtime_class!(input["runtime_class"] || input[:runtime_class]) if input["runtime_class"] || input[:runtime_class]
          digest = input["image_digest"] || input[:image_digest] || config.image["digest"]
          validate_rootfs_path!(input["rootfs_path"]) if input["rootfs_path"]
          Array(input["lowerdirs"] || input[:lowerdirs]).each { |path| validate_rootfs_path!(path) }
          if input["rootfs_entries"]
            input["rootfs_entries"].each do |entry|
              Filesystem.new.validate_entry!(entry.fetch("path") do
                entry.fetch(:path)
              end, type: entry["type"] || entry[:type] || :file, link_target: entry["link_target"] || entry[:link_target])
            end
          end
          raise Filesystem::DigestMismatch, "image digest must be sha256:<64 hex characters>" if digest && !String(digest).match?(/\Asha256:[0-9a-fA-F]{64}\z/)

          true
        end

        def validate_rootfs_path!(path)
          value = String(path)
          raise Filesystem::UnsafeEntry, "rootfs path contains NUL" if value.include?("\0")

          expanded = File.expand_path(value)
          unless File.directory?(expanded) && !File.symlink?(expanded)
            raise Filesystem::UnsafeEntry,
                  "rootfs path must be a regular directory"
          end

          expanded
        end

        # The container security context arrives either in the runtime's own
        # snake_case form or as the Pod container's `securityContext`; the Node
        # merges Pod- and container-level fields before handing it over.  An
        # absent context falls back to the runtime configuration default.
        def container_security_context(input)
          return config.security_context unless input.is_a?(Hash)

          value = input["security_context"] || input[:security_context] || input["securityContext"] || input[:securityContext]
          value.nil? ? config.security_context : value
        end

        # securityContext.readOnlyRootFilesystem is a CONTAINER-level field, and
        # the workspace mount is what enforces it.  Reading it only from the top
        # of the container spec meant a Pod that asked for a read-only root got a
        # writable one -- "[sig-node] Kubelet when scheduling a read only busybox
        # container should not write to root filesystem" writes a file and
        # expects the write to be refused.
        def read_only_root_filesystem?(input)
          return true if input.is_a?(Hash) &&
                         (input["read_only_root_filesystem"] || input[:read_only_root_filesystem]) == true

          context = container_security_context(input)
          return false unless context.is_a?(Hash)

          %w[readOnlyRootFilesystem read_only_root_filesystem].any? do |field|
            (context[field] || context[field.to_sym]) == true
          end
        end

        def security_plan_for(security_context)
          key = digest(security_context)
          cached = @security_plan_mutex.synchronize { @security_plans[key] }
          return cached if cached

          plan = @security.plan(security_context, probe: @security_probe)
          entry = [plan, digest(plan.to_h)].freeze
          @security_plan_mutex.synchronize do
            @security_plans.clear if @security_plans.length >= SECURITY_PLAN_CACHE_LIMIT
            @security_plans[key] = entry
          end
          entry
        end

        # Bind mounts the container receives beneath its rootfs (volumes,
        # projections, termination log, /etc files).  Only shape is checked
        # here; the host source must exist at start time and the destination is
        # resolved inside the rootfs by the adapter.
        def normalize_mounts(value)
          raise ConfigurationError, "container mounts must be an array" unless value.is_a?(Array)

          value.each_with_index.map do |entry, index|
            mount = normalize_hash(entry)
            source = mount["source"] || mount["host_path"] || mount["hostPath"]
            destination = mount["destination"] || mount["container_path"] || mount["containerPath"] || mount["mountPath"]
            raise ConfigurationError, "mount #{index} requires an absolute source path" unless source.is_a?(String) && source.start_with?("/")
            unless destination.is_a?(String) && destination.start_with?("/")
              raise ConfigurationError,
                    "mount #{index} requires an absolute destination path"
            end
            raise ConfigurationError, "mount #{index} path contains NUL" if source.include?("\0") || destination.include?("\0")

            propagation = (mount["propagation"] || mount["mount_propagation"] || mount["mountPropagation"] || "None").to_s
            unless %w[None HostToContainer Bidirectional].include?(propagation)
              raise ConfigurationError, "mount #{index} has unsupported propagation #{propagation.inspect}"
            end

            {
              "source" => source,
              "destination" => destination,
              "readonly" => mount["readonly"] == true || mount["read_only"] == true || mount["readOnly"] == true,
              "propagation" => propagation,
              "name" => mount["name"].nil? ? nil : String(mount["name"]),
              # Disabled / IfPossible / Enabled (the bootstrap applies it).
              "recursive_readonly" => mount["recursive_readonly"].nil? ? nil : String(mount["recursive_readonly"]),
              # A device node the container is granted (device plugin, CDI):
              # the device cgroup gets a rule with these permissions (CRI
              # Device.permissions verbatim, as containerd passes them; CDI
              # supplies "rwm" by default) for the node found at the source --
              # or the node CDI names explicitly.
              "device" => mount["device"] == true ? true : nil,
              "permissions" => mount["permissions"].nil? ? nil : String(mount["permissions"]),
              "device_type" => mount["device_type"].nil? ? nil : String(mount["device_type"]),
              "major" => mount["major"].nil? ? nil : Integer(mount["major"]),
              "minor" => mount["minor"].nil? ? nil : Integer(mount["minor"])
            }.compact
          end
        end

        def normalize_argv(value, label)
          values = Array(value)
          raise ConfigurationError, "#{label} must be an array" unless value.is_a?(Array)

          values.map do |argument|
            text = String(argument)
            raise ConfigurationError, "#{label} contains NUL" if text.include?("\0")

            text
          end
        rescue TypeError => error
          raise ConfigurationError, "#{label} contains a non-string value: #{error.message}"
        end

        def merge_environment(image_env, container_env)
          result = normalize_environment_hash(image_env)
          return result if container_env.nil?

          if container_env.is_a?(Hash)
            result.merge!(container_env.transform_keys(&:to_s).transform_values(&:to_s))
          elsif container_env.is_a?(Array)
            container_env.each do |entry|
              value = normalize_hash(entry)
              name = value["name"].to_s
              raise ConfigurationError, "container environment variable name is invalid" unless name.match?(/\A[[:print:]&&[^=]]+\z/)
              raise ConfigurationError, "valueFrom environment entries are unsupported by Native" if value["valueFrom"]

              result[name] = value.fetch("value", "").to_s
            end
          else
            raise ConfigurationError, "container env must be an object or array"
          end
          result
        end

        def normalize_environment_hash(value)
          return {} unless value
          raise ConfigurationError, "image env must be an object" unless value.is_a?(Hash)

          value.each_with_object({}) do |(name, content), result|
            key = name.to_s
            raise ConfigurationError, "image environment variable name is invalid" unless key.match?(/\A[^=\0]+\z/)

            result[key] = content.to_s
          end
        end

        def validate_command!(command)
          values = Array(command).map(&:to_s)
          raise ConfigurationError, "container command must not be empty" if values.empty?
          raise ConfigurationError, "container executable must not be empty" if values.first.empty?
          raise ConfigurationError, "container command must not contain NUL" if values.any? { |value| value.include?("\0") }

          values
        end

        # runc semantics: an executable containing no "/" is looked up on PATH
        # *inside the container's rootfs*; one that contains a slash is used as
        # given.  Requiring an absolute path instead rejects the overwhelmingly
        # common `command: ["sh", "-c", ...]`, which no image is obliged to
        # spell out.
        def resolve_executable(command, rootfs:, env: {})
          values = Array(command).map(&:to_s)
          program = values.first.to_s
          return values if program.start_with?("/") || program.include?("/")
          return values if rootfs.nil?

          # The image is mounted into the container's own mount namespace, so the
          # host view of the workspace root is empty at this point and cannot be
          # searched.  Resolve here only when the rootfs really is populated on
          # the host; otherwise hand the bare name to the child, which performs
          # the PATH lookup inside the container where the image is visible.
          search = environment_value(env, "PATH") || DEFAULT_EXEC_PATH
          resolved = search.split(":").filter_map do |directory|
            next if directory.empty?

            candidate = File.join(directory, program)
            host_path = File.join(rootfs.to_s, candidate)
            candidate if File.file?(host_path) && File.executable?(host_path)
          end.first
          return values unless resolved

          [resolved] + values[1..]
        end

        def environment_value(env, name)
          case env
          when Hash
            env[name] || env[name.to_sym]
          when Array
            entry = env.map(&:to_s).find { |value| value.start_with?("#{name}=") }
            entry&.split("=", 2)&.last
          end
        end
      end
    end
  end
end
