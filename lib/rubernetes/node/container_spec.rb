# frozen_string_literal: true

require_relative "oom_score"
require_relative "host_resources"

require "digest"
require "fileutils"

require_relative "status"
require_relative "field_ref"
require_relative "pod_hostname"
require_relative "env_file"

module Rubernetes
  module Node
    # Builds the runtime container specification for one Pod container the
    # way kubelet's generateContainerConfig does: the environment (service
    # links, envFrom, valueFrom, `$(VAR)` expansion), the effective security
    # context (Pod and container fields merged), volume mounts translated to
    # host bind mounts, the termination message file, and the Pod-level
    # files (/etc/hosts, /etc/hostname, /etc/resolv.conf).
    #
    # The output keeps the original container definition (probes, lifecycle
    # hooks, ports and image reference are read from it later) and adds the
    # runtime keys: command, args, env, cwd, security_context, mounts,
    # termination_message, hostname.
    class ContainerSpec
      class Error < StandardError; end
      # kubelet reports these as CreateContainerConfigError: the Pod stays
      # Pending and the sync retries until the dependency appears.
      class ConfigError < Error; end

      DEFAULT_TERMINATION_MESSAGE_PATH = "/dev/termination-log"
      TERMINATION_MESSAGE_POLICIES = %w[File FallbackToLogsOnError].freeze
      # RelaxedEnvironmentVariableValidation: any printable ASCII except '='
      # ("1-data-1", "ABC_x" ... are all valid names in 1.32+).
      ENV_NAME = /\A[[:print:]&&[^=]]+\z/
      # kubelet: the maximum size of the environment for one container is
      # bounded by the API validation of the referenced objects; this bound
      # keeps a hostile ConfigMap from exhausting the agent.
      MAX_ENV_BYTES = 4 * 1024 * 1024

      Context = Struct.new(:pod, :volumes, :pod_ip, :pod_ips, :host_ip, :node_name, :node_allocatable,
                           :reader, :pod_files, :pod_directory, :cluster_domain, :enable_service_links,
                           keyword_init: true)

      def initialize(reader: nil, node_name: nil, node_allocatable: nil, cluster_domain: "cluster.local",
                     pod_volumes: nil, memory_capacity: nil)
        @memory_capacity = memory_capacity
        @reader = reader
        @node_name = node_name.to_s
        @node_allocatable = node_allocatable || {}
        @cluster_domain = cluster_domain.to_s
        @pod_volumes = pod_volumes
      end

      # `volumes` is the PodVolumes handle ({"mounts" => {name => {...}}});
      # `pod_files` maps container paths (/etc/hosts ...) to prepared host
      # files.  `resolved_image` carries the image config (User, Env, ...).
      def build(pod:, container:, category:, resolved_image: nil, volumes: nil, pod_files: {}, pod_ips: [],
                host_ip: nil, pod_directory: nil, index: 0)
        object = Helpers.string_keys(pod)
        definition = Helpers.deep_copy(Helpers.string_keys(container))
        image = resolved_image ? Helpers.string_keys(resolved_image) : {}
        context = Context.new(pod: object, volumes: volumes || {}, pod_ip: Array(pod_ips).first, pod_ips: Array(pod_ips),
                              host_ip: host_ip, node_name: @node_name, node_allocatable: @node_allocatable,
                              reader: @reader, pod_files: pod_files, pod_directory: pod_directory,
                              cluster_domain: @cluster_domain,
                              enable_service_links: Helpers.key(Helpers.key(object, "spec", {}), "enableServiceLinks", true) != false)

        environment = build_environment(definition, context, image_env: Helpers.key(image, "env", {}))
        mapping = environment.to_h { |entry| [entry.fetch("name"), entry.fetch("value")] }
        command, args = build_command(definition, image, mapping)
        definition["command"] = command unless command.nil?
        definition["args"] = args unless args.nil?
        definition["env"] = environment
        definition["cwd"] = expand(Helpers.key(definition, "workingDir", nil), mapping) if Helpers.key(definition, "workingDir", nil)
        definition["security_context"] = effective_security_context(object, definition, image)
        definition["env"] = with_home(definition["env"], definition["security_context"], image)
        definition["mounts"] = build_mounts(definition, context, category: category, index: index, mapping: mapping)
        definition["termination_message"] = termination_message(definition, context)
        definition["mounts"] << termination_mount(definition["termination_message"]) if definition["termination_message"]["host_path"]
        definition["hostname"] = pod_hostname(object)
        definition["category"] = category.to_s
        capacity = memory_capacity
        definition["oom_score_adj"] = OOMScore.container_adjust(object, definition, memory_capacity: capacity) if capacity
        definition
      end

      # runc libcontainer setupUser: a process whose environment carries no
      # HOME (or an empty one) gets the /etc/passwd home directory of its
      # user, "/" when the user has no entry.  Neither the image nor the Pod
      # sets HOME for GitLab's toolbox; its entrypoint copied into
      # "$HOME/.s3cfg" -> "/.s3cfg" and died with EACCES as uid 1000.
      def with_home(environment, security_context, image)
        return environment if environment.any? { |entry| entry["name"] == "HOME" && !entry["value"].to_s.empty? }

        home = passwd_home(Helpers.key(security_context, "runAsUser", nil), Helpers.key(image, "rootfs", nil))
        environment.reject { |entry| entry["name"] == "HOME" } + [{"name" => "HOME", "value" => home}]
      end

      def passwd_home(uid, rootfs)
        uid = Integer(uid.nil? ? 0 : uid)
        path = rootfs.nil? ? nil : File.join(rootfs, "etc", "passwd")
        if path && File.file?(path)
          File.foreach(path) do |line|
            fields = line.chomp.split(":")
            next unless fields[2].to_s.match?(/\A\d+\z/) && Integer(fields[2]) == uid

            return fields[5].to_s.empty? ? "/" : fields[5]
          end
        end
        "/"
      rescue SystemCallError, ArgumentError
        "/"
      end

      # machineInfo.MemoryCapacity: the node's memory in bytes (MemTotal).
      def memory_capacity
        return @memory_capacity if @memory_capacity

        kib = HostResources.memory_kib("/proc/meminfo")
        @memory_capacity = kib.positive? ? kib * 1024 : nil
      rescue StandardError
        nil
      end

      # ---------------------------------------------------------------- environment

      # kubelet makeEnvironmentVariables: service environment first, then
      # envFrom, then env (which may reference earlier values with $(VAR)).
      def build_environment(definition, context, image_env: {})
        namespace = Helpers.key(Helpers.key(context.pod, "metadata", {}), "namespace", "default").to_s
        service_env = service_environment(namespace, context)
        tmp_env = {}
        Array(Helpers.key(definition, "envFrom", [])).each do |source|
          entry = Helpers.string_keys(source)
          prefix = Helpers.key(entry, "prefix", "").to_s
          values = if (reference = Helpers.key(entry, "configMapRef", nil))
                     object = read_optional(context, "configmaps", Helpers.key(reference, "name"), namespace, optional: Helpers.key(reference, "optional", false))
                     object.nil? ? {} : Helpers.key(object, "data", {}).to_h.transform_values(&:to_s)
                   elsif (reference = Helpers.key(entry, "secretRef", nil))
                     object = read_optional(context, "secrets", Helpers.key(reference, "name"), namespace, optional: Helpers.key(reference, "optional", false))
                     object.nil? ? {} : decode_secret(object)
                   else
                     {}
                   end
          values.each do |key, value|
            name = "#{prefix}#{key}"
            # kubelet skips keys that are not valid environment names and
            # records an event; the container still starts.
            next unless name.match?(ENV_NAME)

            tmp_env[name] = value.to_s
          end
        end

        Array(Helpers.key(definition, "env", [])).each do |item|
          entry = Helpers.string_keys(item)
          name = Helpers.key(entry, "name", "").to_s
          raise ConfigError, "environment variable name #{name.inspect} is invalid" unless name.match?(ENV_NAME)

          value = if entry.key?("valueFrom") && !entry["valueFrom"].nil?
                    resolve_value_from(entry["valueFrom"], definition, context, namespace)
                  else
                    expand(Helpers.key(entry, "value", "").to_s, tmp_env.merge(service_env) { |_k, left, _right| left })
                  end
          next if value.nil?

          tmp_env[name] = value
        end

        # Image ENV is the base layer; anything from the Pod overrides it.
        result = image_env.to_h.each_with_object({}) { |(key, value), env| env[key.to_s] = value.to_s }
        service_env.each { |key, value| result[key] = value }
        tmp_env.each { |key, value| result[key] = value }
        # containerd CRI (container_create.go buildLinuxSpec): HOSTNAME is
        # appended last, set to the sandbox hostname, for every container.
        # Gitaly's config template reads .Env.HOSTNAME and failed without it.
        result["HOSTNAME"] = pod_hostname(context.pod)
        total = result.sum { |key, value| key.bytesize + value.bytesize + 2 }
        raise ConfigError, "container environment exceeds #{MAX_ENV_BYTES} bytes" if total > MAX_ENV_BYTES

        result.map { |key, value| {"name" => key, "value" => value} }
      end

      def resolve_value_from(value_from, definition, context, namespace)
        source = Helpers.string_keys(value_from)
        if (field = Helpers.key(source, "fieldRef", nil))
          FieldRef.resolve_field(Helpers.key(field, "fieldPath").to_s, context.pod, pod_ip: context.pod_ips.empty? ? context.pod_ip : context.pod_ips,
                                                                        host_ip: context.host_ip, env: true)
        elsif (resource = Helpers.key(source, "resourceFieldRef", nil))
          container_name = Helpers.key(resource, "containerName", nil)
          target = container_name.nil? || container_name.to_s == Helpers.key(definition, "name", "").to_s ? definition : FieldRef.find_container(context.pod, container_name)
          raise ConfigError, "resourceFieldRef container #{container_name.inspect} not found" if target.nil?

          FieldRef.resolve_resource(Helpers.key(resource, "resource").to_s, target, divisor: Helpers.key(resource, "divisor", "1"),
                                    node_allocatable: context.node_allocatable)
        elsif (reference = Helpers.key(source, "configMapKeyRef", nil))
          optional = Helpers.key(reference, "optional", false) == true
          object = read_optional(context, "configmaps", Helpers.key(reference, "name"), namespace, optional: optional)
          return nil if object.nil?

          key = Helpers.key(reference, "key").to_s
          data = Helpers.key(object, "data", {}) || {}
          unless data.key?(key)
            return nil if optional

            raise ConfigError, "couldn't find key #{key} in ConfigMap #{namespace}/#{Helpers.key(reference, "name")}"
          end
          data.fetch(key).to_s
        elsif (reference = Helpers.key(source, "secretKeyRef", nil))
          optional = Helpers.key(reference, "optional", false) == true
          object = read_optional(context, "secrets", Helpers.key(reference, "name"), namespace, optional: optional)
          return nil if object.nil?

          key = Helpers.key(reference, "key").to_s
          data = decode_secret(object)
          unless data.key?(key)
            return nil if optional

            raise ConfigError, "couldn't find key #{key} in Secret #{namespace}/#{Helpers.key(reference, "name")}"
          end
          data.fetch(key)
        elsif (reference = Helpers.key(source, "fileKeyRef", nil))
          resolve_file_key_ref(reference, context)
        else
          raise ConfigError, "valueFrom must specify one of fieldRef, resourceFieldRef, configMapKeyRef, secretKeyRef or fileKeyRef"
        end
      rescue FieldRef::Error => error
        raise ConfigError, error.message
      end

      # kubelet makeEnvironmentVariables, FileKeyRef: the key's value in
      # <volume host path>/<path> (SecureJoin); a key the file does not set
      # is skipped when optional, an error otherwise.  An unreadable or
      # malformed file is an error either way.
      def resolve_file_key_ref(reference, context)
        volume_name = Helpers.key(reference, "volumeName", "").to_s
        key = Helpers.key(reference, "key", "").to_s
        volume = Helpers.key(Helpers.key(context.volumes, "mounts", {}) || {}, volume_name, nil)
        host_path = volume && Helpers.key(volume, "path", nil)
        raise ConfigError, "cannot find the volume #{volume_name.inspect} referenced by FileKeyRef" if host_path.to_s.empty?

        path = EnvFile.secure_join(host_path.to_s, Helpers.key(reference, "path", "").to_s)
        value = begin
          EnvFile.parse(path, key)
        rescue EnvFile::Error
          raise ConfigError, "couldn't parse env file"
        end
        return value unless value.empty?
        return nil if Helpers.key(reference, "optional", false) == true

        raise ConfigError, "environment variable key #{key.inspect} not found in file #{path.inspect}"
      end

      # kubelet getServiceEnvVarMap: every Service of the namespace when
      # enableServiceLinks, plus the "kubernetes" master Service always.
      def service_environment(namespace, context)
        return {} if context.reader.nil?

        services = []
        master = context.reader.get("services", "kubernetes", namespace: "default")
        services << master if master
        if context.enable_service_links
          context.reader.list("services", namespace: namespace).each do |service|
            next if namespace == "default" && Helpers.key(Helpers.key(service, "metadata", {}), "name", "") == "kubernetes"

            services << service
          end
        end
        services.each_with_object({}) { |service, env| env.merge!(service_variables(service)) }
      rescue StandardError => error
        raise ConfigError, "service environment could not be built: #{error.message}"
      end

      # pkg/kubelet/envvars.FromServices
      def service_variables(service)
        spec = Helpers.key(service, "spec", {}) || {}
        cluster_ip = Helpers.key(spec, "clusterIP", "").to_s
        return {} if cluster_ip.empty? || cluster_ip == "None"
        return {} if Helpers.key(spec, "type", "").to_s == "ExternalName"

        ports = Array(Helpers.key(spec, "ports", []))
        return {} if ports.empty?

        name = Helpers.key(Helpers.key(service, "metadata", {}), "name", "").to_s.upcase.tr("-", "_")
        env = {}
        env["#{name}_SERVICE_HOST"] = cluster_ip
        first = Helpers.string_keys(ports.first)
        env["#{name}_SERVICE_PORT"] = Helpers.key(first, "port").to_s
        ports.each do |entry|
          port = Helpers.string_keys(entry)
          port_name = Helpers.key(port, "name", "").to_s
          env["#{name}_SERVICE_PORT_#{port_name.upcase.tr("-", "_")}"] = Helpers.key(port, "port").to_s unless port_name.empty?
        end
        protocol = Helpers.key(first, "protocol", "TCP").to_s
        env["#{name}_PORT"] = "#{protocol.downcase}://#{cluster_ip}:#{Helpers.key(first, "port")}"
        ports.each do |entry|
          port = Helpers.string_keys(entry)
          number = Helpers.key(port, "port").to_s
          proto = Helpers.key(port, "protocol", "TCP").to_s
          prefix = "#{name}_PORT_#{number}_#{proto.upcase}"
          env[prefix] = "#{proto.downcase}://#{cluster_ip}:#{number}"
          env["#{prefix}_PROTO"] = proto.downcase
          env["#{prefix}_PORT"] = number
          env["#{prefix}_ADDR"] = cluster_ip
        end
        env
      end

      # third_party/forked/golang/expansion.Expand: `$(VAR)` is replaced when
      # VAR is known, left verbatim otherwise; `$$` yields a literal `$`.
      def expand(input, mapping)
        return nil if input.nil?

        text = input.to_s
        output = +""
        index = 0
        while index < text.length
          char = text[index]
          if char == "$" && index + 1 < text.length
            following = text[index + 1]
            if following == "$"
              output << "$"
              index += 2
              next
            elsif following == "("
              close = text.index(")", index + 2)
              if close
                name = text[(index + 2)...close]
                if mapping.key?(name)
                  output << mapping.fetch(name).to_s
                else
                  output << text[index..close]
                end
                index = close + 1
                next
              end
            end
          end
          output << char
          index += 1
        end
        output
      end

      # ---------------------------------------------------------------- command

      def build_command(definition, image, mapping)
        command = definition["command"]
        args = definition["args"]
        entrypoint = Array(Helpers.key(image, "entrypoint", []))
        image_cmd = Array(Helpers.key(image, "cmd", []))
        resolved_command = if command.nil? || Array(command).empty?
                             entrypoint
                           else
                             Array(command).map { |value| expand(value.to_s, mapping) }
                           end
        resolved_args = if args.nil?
                          command.nil? || Array(command).empty? ? image_cmd : []
                        else
                          Array(args).map { |value| expand(value.to_s, mapping) }
                        end
        full = resolved_command + resolved_args
        raise ConfigError, "container has no command: neither the Pod nor the image config provides one" if full.empty? && !image.empty?

        [full.empty? ? nil : full, nil]
      end

      # ---------------------------------------------------------------- security

      # securitycontext.DetermineEffectiveSecurityContext: container fields
      # win; Pod-only fields (fsGroup, supplementalGroups, sysctls) come from
      # the Pod; the image USER applies when no runAsUser is set.
      def effective_security_context(pod, definition, image)
        pod_context = Helpers.key(Helpers.key(pod, "spec", {}), "securityContext", {}) || {}
        container_context = Helpers.key(definition, "securityContext", {}) || {}
        merged = {}
        %w[runAsUser runAsGroup runAsNonRoot seLinuxOptions seccompProfile appArmorProfile windowsOptions].each do |field|
          value = container_context.key?(field) ? container_context[field] : pod_context[field]
          merged[field] = value unless value.nil?
        end
        %w[fsGroup supplementalGroups sysctls fsGroupChangePolicy supplementalGroupsPolicy].each do |field|
          merged[field] = pod_context[field] unless pod_context[field].nil?
        end
        %w[capabilities privileged allowPrivilegeEscalation procMount readOnlyRootFilesystem].each do |field|
          merged[field] = container_context[field] unless container_context[field].nil?
        end
        merged["privileged"] = false unless merged.key?("privileged")
        merged["allowPrivilegeEscalation"] = merged["privileged"] == true unless merged.key?("allowPrivilegeEscalation")
        merged["capabilities"] ||= {}
        merged["capabilities"] = {"add" => Array(Helpers.key(merged["capabilities"], "add", [])), "drop" => Array(Helpers.key(merged["capabilities"], "drop", []))}
        merged["seccompProfile"] ||= {"type" => "RuntimeDefault"}

        image_user = Helpers.key(Helpers.key(image, "config", {}) || {}, "config", {}) || {}
        image_user = Helpers.key(image_user, "User", nil)
        image_user = Helpers.key(image, "user", nil) if image_user.nil? || image_user.to_s.empty?
        if merged["runAsUser"].nil? && image_user && !image_user.to_s.empty?
          uid, gid = resolve_image_user(image_user.to_s, Helpers.key(image, "rootfs", nil))
          merged["runAsUser"] = uid unless uid.nil?
          merged["runAsGroup"] = gid if merged["runAsGroup"].nil? && !gid.nil?
          merged["imageUser"] = image_user.to_s
        end
        merge_image_groups!(merged, image_user, Helpers.key(image, "rootfs", nil))
        if merged["runAsNonRoot"] == true
          if merged["runAsUser"].nil?
            raise ConfigError, "container has runAsNonRoot and image has non-numeric user (#{image_user.inspect}), cannot verify user is non-root" if image_user && !image_user.to_s.match?(/\A\d+/)
            raise ConfigError, "container has runAsNonRoot and image will run as root"
          end
          raise ConfigError, "container's runAsUser breaks non-root policy (pod: #{pod_identity(pod)}, container: #{Helpers.key(definition, "name")})" if Integer(merged["runAsUser"]).zero?
        end
        merged
      end

      # SupplementalGroupsPolicy Merge (the default): the groups the image's
      # /etc/group lists the container's user in join supplementalGroups,
      # as the runtime's WithAdditionalGIDs does; Strict takes only the Pod's.
      def merge_image_groups!(merged, image_user, rootfs)
        return if merged["supplementalGroupsPolicy"].to_s == "Strict" || rootfs.nil?

        name = image_user_name(merged["runAsUser"], image_user, rootfs)
        return if name.nil?

        gids = image_group_memberships(name, rootfs)
        return if gids.empty?

        merged["imageSupplementalGroups"] = gids
        merged["supplementalGroups"] = (Array(merged["supplementalGroups"]).map { |gid| Integer(gid) } + gids).uniq
      end

      # The user's name: the image USER when it names one, else the
      # /etc/passwd entry of the uid.
      def image_user_name(uid, image_user, rootfs)
        user = image_user.to_s.split(":", 2).first.to_s
        return user if !user.empty? && !user.match?(/\A\d+\z/) && (uid.nil? || numeric_or_lookup(user, rootfs, "passwd") == Integer(uid))

        uid = Integer(uid.nil? ? 0 : uid)
        path = File.join(rootfs, "etc", "passwd")
        return nil unless File.file?(path)

        File.foreach(path) do |line|
          fields = line.chomp.split(":")
          return fields[0] if fields[2].to_s.match?(/\A\d+\z/) && Integer(fields[2]) == uid
        end
        nil
      rescue SystemCallError, ArgumentError, ConfigError
        nil
      end

      def image_group_memberships(name, rootfs)
        path = File.join(rootfs, "etc", "group")
        return [] unless File.file?(path)

        File.foreach(path).filter_map do |line|
          fields = line.chomp.split(":")
          next unless fields[2].to_s.match?(/\A\d+\z/) && fields[3].to_s.split(",").include?(name)

          Integer(fields[2])
        end
      rescue SystemCallError
        []
      end

      # The image USER field is `user[:group]` where either may be a name
      # resolved through the image's own /etc/passwd and /etc/group.
      def resolve_image_user(value, rootfs)
        user, group = value.split(":", 2)
        uid = numeric_or_lookup(user, rootfs, "passwd")
        gid = group.nil? ? nil : numeric_or_lookup(group, rootfs, "group")
        if gid.nil? && !user.to_s.empty? && rootfs && !user.match?(/\A\d+\z/)
          gid = passwd_primary_group(user, rootfs)
        end
        [uid, gid]
      end

      def numeric_or_lookup(name, rootfs, database)
        return nil if name.nil? || name.empty?
        return Integer(name) if name.match?(/\A\d+\z/)
        return nil if rootfs.nil?

        path = File.join(rootfs, "etc", database)
        return nil unless File.file?(path)

        File.foreach(path) do |line|
          fields = line.chomp.split(":")
          return Integer(fields[2]) if fields[0] == name && fields[2].to_s.match?(/\A\d+\z/)
        end
        raise ConfigError, "unable to find user #{name} in the image"
      rescue SystemCallError
        nil
      end

      def passwd_primary_group(user, rootfs)
        path = File.join(rootfs, "etc", "passwd")
        return nil unless File.file?(path)

        File.foreach(path) do |line|
          fields = line.chomp.split(":")
          return Integer(fields[3]) if fields[0] == user && fields[3].to_s.match?(/\A\d+\z/)
        end
        nil
      rescue SystemCallError
        nil
      end

      # ---------------------------------------------------------------- mounts

      def build_mounts(definition, context, category:, index:, mapping:)
        mounts = []
        volumes = Helpers.key(context.volumes, "mounts", {}) || {}
        container_name = Helpers.key(definition, "name", "").to_s
        Array(Helpers.key(definition, "volumeMounts", [])).each_with_index do |item, position|
          mount = Helpers.string_keys(item)
          name = Helpers.key(mount, "name", "").to_s
          volume = Helpers.key(volumes, name, nil)
          raise ConfigError, "volume #{name.inspect} is not defined in the Pod" if volume.nil?

          destination = Helpers.key(mount, "mountPath", "").to_s
          raise ConfigError, "volumeMount #{name.inspect} has no mountPath" if destination.empty?

          readonly = Helpers.key(mount, "readOnly", false) == true || Helpers.key(volume, "readonly", false) == true
          sub_path = Helpers.key(mount, "subPath", nil)
          sub_path_expr = Helpers.key(mount, "subPathExpr", nil)
          sub_path = expand(sub_path_expr, mapping) if sub_path.nil? && sub_path_expr
          source = if sub_path && !sub_path.to_s.empty?
                     raise ConfigError, "subPath requires the pod volume manager" if @pod_volumes.nil?

                     @pod_volumes.sub_path(context.pod, context.volumes, volume_name: name, sub_path: sub_path,
                                           container_name: container_name, index: position, readonly: readonly)
                   else
                     Helpers.key(volume, "path")
                   end
          mounts << {
            "name" => name,
            "source" => source,
            "destination" => destination,
            "readonly" => readonly,
            "propagation" => Helpers.key(mount, "mountPropagation", "None").to_s,
            "recursive_readonly" => Helpers.key(mount, "recursiveReadOnly", nil)
          }.compact
        end
        # Pod-level files come last so a volume mounted over /etc does not
        # hide the managed hosts/resolv.conf the way kubelet orders them.
        (context.pod_files || {}).each do |destination, host_path|
          next if mounts.any? { |mount| mount["destination"] == destination }

          mounts << {"name" => "pod-file:#{File.basename(destination)}", "source" => host_path, "destination" => destination,
                     "readonly" => false, "propagation" => "None"}
        end
        mounts
      end

      # ---------------------------------------------------------------- termination message

      def termination_message(definition, context)
        path = Helpers.key(definition, "terminationMessagePath", DEFAULT_TERMINATION_MESSAGE_PATH).to_s
        policy = Helpers.key(definition, "terminationMessagePolicy", "File").to_s
        raise ConfigError, "unsupported terminationMessagePolicy #{policy.inspect}" unless TERMINATION_MESSAGE_POLICIES.include?(policy)

        result = {"path" => path, "policy" => policy}
        return result if path.empty? || context.pod_directory.nil?

        # kubelet keeps the file on the host under the pod directory and
        # bind-mounts it at the container path; its content is read after
        # the container exits.
        name = Helpers.key(definition, "name", "container").to_s
        digest = Digest::SHA256.hexdigest("#{name}\0#{path}")[0, 16]
        host_path = File.join(context.pod_directory, "containers", name, digest)
        FileUtils.mkdir_p(File.dirname(host_path))
        # kubelet makeMounts chmods the file to 0666: the container writes it
        # as whatever uid it runs as ("... TerminationMessagePath is set as
        # non-root user and at a non-default path" runs as uid 10000, and a
        # 0644 root-owned file left it with "Permission denied" and Failed).
        File.open(host_path, File::WRONLY | File::CREAT, 0o666) {} unless File.exist?(host_path)
        File.chmod(0o666, host_path)
        result.merge("host_path" => host_path)
      end

      def termination_mount(message)
        {"name" => "termination-message", "source" => message.fetch("host_path"), "destination" => message.fetch("path"),
         "readonly" => false, "propagation" => "None"}
      end

      # ---------------------------------------------------------------- helpers

      # The UTS hostname (PodHostname.kernel_hostname: hostnameOverride,
      # spec.hostname or the Pod name; the FQDN with setHostnameAsFQDN).
      def pod_hostname(pod)
        PodHostname.kernel_hostname(pod, cluster_domain: @cluster_domain)
      end

      def pod_identity(pod)
        metadata = Helpers.key(pod, "metadata", {})
        "#{Helpers.key(metadata, "namespace", "default")}/#{Helpers.key(metadata, "name", "")}"
      end

      def read_optional(context, resource, name, namespace, optional:)
        raise ConfigError, "#{resource} #{name.inspect} cannot be read: the node has no API reader" if context.reader.nil?

        object = context.reader.get(resource, name, namespace: namespace)
        return object unless object.nil?
        return nil if optional == true

        raise ConfigError, "#{resource == "secrets" ? "secret" : "configmap"} \"#{name}\" not found"
      end

      def decode_secret(secret)
        data = Helpers.key(secret, "data", {}) || {}
        data.each_with_object({}) do |(key, value), result|
          result[key.to_s] = Base64.strict_decode64(value.to_s)
        end.merge((Helpers.key(secret, "stringData", {}) || {}).to_h.transform_values(&:to_s))
      rescue ArgumentError => error
        raise ConfigError, "secret data is not valid base64: #{error.message}"
      end
    end
  end
end
