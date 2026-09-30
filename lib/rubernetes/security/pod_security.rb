# frozen_string_literal: true

module Rubernetes
  module Security
    # k8s.io/pod-security-admission (v1.36.2) api and policy: levels,
    # versions, namespace policies and the versioned Pod Security Standards
    # checks, evaluated on Pod metadata and specs as the API serves them
    # (Hashes; an absent or null field is Go's nil).
    module PodSecurity
      LEVELS = %w[privileged baseline restricted].freeze
      LABEL_PREFIX = "pod-security.kubernetes.io/"
      ENFORCE_LEVEL_LABEL = "#{LABEL_PREFIX}enforce".freeze
      ENFORCE_VERSION_LABEL = "#{LABEL_PREFIX}enforce-version".freeze
      AUDIT_LEVEL_LABEL = "#{LABEL_PREFIX}audit".freeze
      AUDIT_VERSION_LABEL = "#{LABEL_PREFIX}audit-version".freeze
      WARN_LEVEL_LABEL = "#{LABEL_PREFIX}warn".freeze
      WARN_VERSION_LABEL = "#{LABEL_PREFIX}warn-version".freeze
      EXEMPTION_REASON_ANNOTATION = "exempt"
      AUDIT_VIOLATIONS_ANNOTATION = "audit-violations"
      ENFORCED_POLICY_ANNOTATION = "enforce-policy"

      # api.Version: v1.<minor>, or latest (newer than any number).
      class Version
        include Comparable

        attr_reader :major, :minor

        def self.latest = LATEST
        def self.of(major, minor) = new(major, minor, false)

        def initialize(major, minor, latest)
          @major = major
          @minor = minor
          @latest = latest
          freeze
        end

        def latest? = @latest
        def to_s = @latest ? "latest" : "v#{@major}.#{@minor}"

        # Version.Older.
        def older?(other)
          return false if latest?
          return true if other.latest?
          return @major < other.major if @major != other.major

          @minor < other.minor
        end

        def <=>(other)
          return 0 if eql?(other)

          older?(other) ? -1 : 1
        end

        def eql?(other) = other.is_a?(Version) && other.latest? == latest? && (latest? || (other.major == @major && other.minor == @minor))
        alias == eql?
        def hash = latest? ? :latest.hash : [@major, @minor].hash
        def next_minor = latest? ? self : Version.of(@major, @minor + 1)

        LATEST = new(0, 0, true)
      end

      # The API's own version (GetAPIVersion).
      API_VERSION = Version.of(1, 36)

      LevelVersion = Struct.new(:level, :version) do
        def to_s = "#{level}:#{version}"

        def equivalent?(other)
          (level == "privileged" && other.level == "privileged") || (level == other.level && version == other.version)
        end
      end

      Policy = Struct.new(:enforce, :audit, :warn) do
        def fully_privileged? = [enforce, audit, warn].all? { |lv| lv.level == "privileged" }

        def equivalent?(other)
          enforce.equivalent?(other.enforce) && audit.equivalent?(other.audit) && warn.equivalent?(other.warn)
        end
      end

      module_function

      def parse_level(level)
        return [level, nil] if LEVELS.include?(level)

        ["restricted", "must be one of #{LEVELS.join(", ")}"]
      end

      def parse_version(version)
        return [Version.latest, nil] if version == "latest"

        match = /\Av1\.([0-9]|[1-9][0-9]*)\z/.match(version.to_s)
        return [Version.latest, %(must be "latest" or "v1.x")] unless match

        [Version.of(1, match[1].to_i), nil]
      end

      def compare_levels(a, b)
        return 0 if a == b
        return -1 if a == "privileged"
        return 1 if a == "restricted"

        b == "privileged" ? 1 : -1
      end

      # api.PolicyToEvaluate: the policy namespace labels select over the
      # defaults, and the label errors (field.Invalid on metadata.labels[..]).
      def policy_to_evaluate(labels, defaults)
        policy = Policy.new(defaults.enforce.dup, defaults.audit.dup, defaults.warn.dup)
        errors = []
        labels = {} unless labels.is_a?(Hash)
        return [policy, errors] if labels.empty?

        record = lambda do |error, label, value|
          errors << {"field" => "metadata.labels[#{label}]", "value" => value, "message" => error} if error
        end
        has_enforce_level = false
        if labels.key?(ENFORCE_LEVEL_LABEL)
          value = labels[ENFORCE_LEVEL_LABEL].to_s
          policy.enforce.level, error = parse_level(value)
          has_enforce_level = error.nil?
          record.call(error, ENFORCE_LEVEL_LABEL, value)
        end
        if labels.key?(ENFORCE_VERSION_LABEL)
          value = labels[ENFORCE_VERSION_LABEL].to_s
          policy.enforce.version, error = parse_version(value)
          record.call(error, ENFORCE_VERSION_LABEL, value)
        end
        if labels.key?(AUDIT_LEVEL_LABEL)
          value = labels[AUDIT_LEVEL_LABEL].to_s
          policy.audit.level, error = parse_level(value)
          record.call(error, AUDIT_LEVEL_LABEL, value)
          policy.audit.level = "privileged" if error
        end
        if labels.key?(AUDIT_VERSION_LABEL)
          value = labels[AUDIT_VERSION_LABEL].to_s
          policy.audit.version, error = parse_version(value)
          record.call(error, AUDIT_VERSION_LABEL, value)
        end
        has_warn_level = labels.key?(WARN_LEVEL_LABEL)
        if has_warn_level
          value = labels[WARN_LEVEL_LABEL].to_s
          policy.warn.level, error = parse_level(value)
          record.call(error, WARN_LEVEL_LABEL, value)
          policy.warn.level = "privileged" if error
        end
        has_warn_version = labels.key?(WARN_VERSION_LABEL)
        if has_warn_version
          value = labels[WARN_VERSION_LABEL].to_s
          policy.warn.version, error = parse_version(value)
          record.call(error, WARN_VERSION_LABEL, value)
        end
        if !has_warn_level && has_enforce_level && compare_levels(policy.enforce.level, policy.warn.level).positive?
          policy.warn.level = policy.enforce.level
          policy.warn.version = policy.enforce.version unless has_warn_version
        end
        [policy, errors]
      end

      # ---- policy/checks.go ---------------------------------------------------

      CheckResult = Struct.new(:allowed, :reason, :detail)
      ALLOWED = CheckResult.new(true, nil, nil).freeze

      AggregateResult = Struct.new(:allowed, :reasons, :details) do
        def forbidden_reason = reasons.join(", ")

        def forbidden_detail
          reasons.each_with_index.map do |reason, index|
            details[index].to_s.empty? ? reason : "#{reason} (#{details[index]})"
          end.join(", ")
        end
      end

      def aggregate(results)
        reasons = []
        details = []
        Array(results).each do |result|
          next if result.allowed

          reasons << (result.reason.to_s.empty? ? "unknown forbidden reason" : result.reason)
          details << result.detail.to_s
        end
        AggregateResult.new(reasons.empty?, reasons, details)
      end

      Check = Struct.new(:id, :level, :versions)
      VersionedCheck = Struct.new(:minimum, :check, :overrides)

      # ---- helpers and visitor ------------------------------------------------

      def join_quote(items) = items.empty? ? "" : %("#{items.join('", "')}")
      def pluralize(singular, plural, count) = count == 1 ? singular : plural

      def value(hash, *path)
        path.reduce(hash) { |node, key| node.is_a?(Hash) ? node[key] : nil }
      end

      # initContainers, containers, then ephemeralContainers.
      def containers(spec)
        Array(spec["initContainers"]) + Array(spec["containers"]) + Array(spec["ephemeralContainers"])
      end

      def windows?(spec) = value(spec, "os", "name") == "windows"
      def relax_for_user_namespace?(spec) = spec.is_a?(Hash) && spec["hostUsers"] == false

      # fmt's %q.
      def go_quote(text)
        escaped = text.to_s.each_char.map do |char|
          case char
          when '"' then '\\"'
          when "\\" then "\\\\"
          when "\n" then "\\n"
          when "\t" then "\\t"
          when "\r" then "\\r"
          else char.ord < 0x20 || char.ord == 0x7f ? format("\\x%02x", char.ord) : char
          end
        end
        %("#{escaped.join}")
      end

      def setters_detail(bad_setters, containers, suffix)
        setters = bad_setters.dup
        setters << "#{pluralize("container", "containers", containers.length)} #{join_quote(containers)}" if containers.any?
        "#{setters.join(" and ")}#{suffix}"
      end

      # ---- the checks -----------------------------------------------------------

      def allow_privilege_escalation_1_8(_meta, spec)
        bad = containers(spec).reject { |c| value(c, "securityContext", "allowPrivilegeEscalation") == false }.map { |c| c["name"].to_s }
        return ALLOWED if bad.empty?

        CheckResult.new(false, "allowPrivilegeEscalation != false",
                        "#{pluralize("container", "containers", bad.length)} #{join_quote(bad)} must set securityContext.allowPrivilegeEscalation=false")
      end

      def allow_privilege_escalation_1_25(meta, spec)
        windows?(spec) ? ALLOWED : allow_privilege_escalation_1_8(meta, spec)
      end

      APPARMOR_ANNOTATION_PREFIX = "container.apparmor.security.beta.kubernetes.io/"

      def app_armor_profile_1_0(meta, spec)
        bad_setters = []
        bad_values = []
        pod_type = value(spec, "securityContext", "appArmorProfile")
        if pod_type.is_a?(Hash) && !%w[RuntimeDefault Localhost].include?(pod_type["type"])
          bad_setters << "pod"
          bad_values << pod_type["type"].to_s
        end
        bad = []
        containers(spec).each do |c|
          profile = value(c, "securityContext", "appArmorProfile")
          next unless profile.is_a?(Hash) && !%w[RuntimeDefault Localhost].include?(profile["type"])

          bad << c["name"].to_s
          bad_values << profile["type"].to_s
        end
        bad_setters << "#{pluralize("container", "containers", bad.length)} #{join_quote(bad)}" if bad.any?
        forbidden = (meta["annotations"] || {}).filter_map do |key, annotation|
          next unless key.to_s.start_with?(APPARMOR_ANNOTATION_PREFIX)

          text = annotation.to_s
          next if text.empty? || text == "runtime/default" || text.start_with?("localhost/")

          "#{key}=#{go_quote(text)}"
        end
        values = bad_values.uniq.sort
        if forbidden.any?
          values += forbidden.sort
          bad_setters << pluralize("annotation", "annotations", forbidden.length)
        end
        return ALLOWED if bad_setters.empty?

        CheckResult.new(false, pluralize("forbidden AppArmor profile", "forbidden AppArmor profiles", values.length),
                        "#{bad_setters.join(" and ")} must not set AppArmor profile type to #{join_quote(values)}")
      end

      CAPABILITIES_BASELINE = %w[AUDIT_WRITE CHOWN DAC_OVERRIDE FOWNER FSETID KILL MKNOD NET_BIND_SERVICE SETFCAP SETGID SETPCAP
                                 SETUID SYS_CHROOT].freeze

      def capabilities_baseline_1_0(_meta, spec)
        bad = []
        forbidden = []
        containers(spec).each do |c|
          capabilities = value(c, "securityContext", "capabilities")
          next unless capabilities.is_a?(Hash)

          extra = Array(capabilities["add"]).map(&:to_s).reject { |cap| CAPABILITIES_BASELINE.include?(cap) }
          next if extra.empty?

          forbidden.concat(extra)
          bad << c["name"].to_s
        end
        return ALLOWED if bad.empty?

        CheckResult.new(false, "non-default capabilities",
                        "#{pluralize("container", "containers", bad.length)} #{join_quote(bad)} must not include " \
                        "#{join_quote(forbidden.uniq.sort)} in securityContext.capabilities.add")
      end

      def capabilities_restricted_1_22(_meta, spec)
        missing_drop = []
        adding = []
        forbidden = []
        containers(spec).each do |c|
          capabilities = value(c, "securityContext", "capabilities")
          unless capabilities.is_a?(Hash)
            missing_drop << c["name"].to_s
            next
          end
          missing_drop << c["name"].to_s unless Array(capabilities["drop"]).include?("ALL")
          extra = Array(capabilities["add"]).map(&:to_s).reject { |cap| cap == "NET_BIND_SERVICE" }
          next if extra.empty?

          forbidden.concat(extra)
          adding << c["name"].to_s
        end
        details = []
        if missing_drop.any?
          details << %(#{pluralize("container", "containers",
                                   missing_drop.length)} #{join_quote(missing_drop)} must set securityContext.capabilities.drop=["ALL"])
        end
        if adding.any?
          details << "#{pluralize("container", "containers", adding.length)} #{join_quote(adding)} must not include " \
                     "#{join_quote(forbidden.uniq.sort)} in securityContext.capabilities.add"
        end
        return ALLOWED if details.empty?

        CheckResult.new(false, "unrestricted capabilities", details.join("; "))
      end

      def capabilities_restricted_1_25(meta, spec)
        windows?(spec) ? ALLOWED : capabilities_restricted_1_22(meta, spec)
      end

      def host_namespaces_1_0(_meta, spec)
        found = []
        found << "hostNetwork=true" if spec["hostNetwork"] == true
        found << "hostPID=true" if spec["hostPID"] == true
        found << "hostIPC=true" if spec["hostIPC"] == true
        return ALLOWED if found.empty?

        CheckResult.new(false, "host namespaces", found.join(", "))
      end

      def host_path_volumes_1_0(_meta, spec)
        volumes = Array(spec["volumes"]).select do |volume|
          volume.is_a?(Hash) && !volume["hostPath"].nil?
        end.map { |volume| volume["name"].to_s }
        return ALLOWED if volumes.empty?

        CheckResult.new(false, "hostPath volumes", "#{pluralize("volume", "volumes", volumes.length)} #{join_quote(volumes)}")
      end

      def host_ports_1_0(_meta, spec)
        bad = []
        ports = []
        containers(spec).each do |c|
          used = Array(c["ports"]).map { |port| port["hostPort"].to_i }.reject(&:zero?)
          next if used.empty?

          bad << c["name"].to_s
          ports.concat(used.map(&:to_s))
        end
        return ALLOWED if bad.empty?

        unique = ports.uniq.sort
        CheckResult.new(false, "hostPort",
                        "#{pluralize("container", "containers", bad.length)} #{join_quote(bad)} #{pluralize("uses", "use", bad.length)} " \
                        "#{pluralize("hostPort", "hostPorts", unique.length)} #{unique.join(", ")}")
      end

      def forbidden_hosts(handler)
        return [] unless handler.is_a?(Hash)

        hosts = []
        hosts << handler.dig("httpGet", "host").to_s unless handler.dig("httpGet", "host").to_s.empty?
        hosts << handler.dig("tcpSocket", "host").to_s unless handler.dig("tcpSocket", "host").to_s.empty?
        hosts
      end

      def host_probes_and_host_lifecycle_1_34(_meta, spec)
        bad = []
        hosts = []
        containers(spec).each do |c|
          found = %w[livenessProbe readinessProbe startupProbe].flat_map { |probe| forbidden_hosts(c[probe]) }
          lifecycle = c["lifecycle"]
          found += %w[postStart preStop].flat_map { |hook| forbidden_hosts(lifecycle[hook]) } if lifecycle.is_a?(Hash)
          next if found.empty?

          bad << c["name"].to_s
          hosts.concat(found)
        end
        return ALLOWED if bad.empty?

        names = bad.uniq.sort
        unique = hosts.uniq.sort
        CheckResult.new(false, "probe or lifecycle host",
                        "#{pluralize("container", "containers", names.length)} #{join_quote(names)} #{pluralize("uses", "use", names.length)} " \
                        "#{pluralize("probe or lifecycle host", "probe or lifecycle hosts", unique.length)} #{join_quote(unique)}")
      end

      def privileged_1_0(_meta, spec)
        bad = containers(spec).select { |c| value(c, "securityContext", "privileged") == true }.map { |c| c["name"].to_s }
        return ALLOWED if bad.empty?

        CheckResult.new(false, "privileged",
                        "#{pluralize("container", "containers", bad.length)} #{join_quote(bad)} must not set securityContext.privileged=true")
      end

      def proc_mount_1_0(_meta, spec)
        bad = []
        types = []
        containers(spec).each do |c|
          mount = value(c, "securityContext", "procMount")
          next if mount.nil? || mount == "Default"

          bad << c["name"].to_s
          types << mount.to_s
        end
        return ALLOWED if bad.empty?

        CheckResult.new(false, "procMount",
                        "#{pluralize("container", "containers", bad.length)} #{join_quote(bad)} must not set securityContext.procMount to " \
                        "#{join_quote(types.uniq.sort)}")
      end

      def proc_mount_1_35_baseline(meta, spec)
        relax_for_user_namespace?(spec) ? ALLOWED : proc_mount_1_0(meta, spec)
      end

      ALLOWED_VOLUME_SOURCES = %w[configMap csi downwardAPI emptyDir ephemeral image persistentVolumeClaim projected secret].freeze
      RESTRICTED_VOLUME_TYPES = %w[hostPath gcePersistentDisk awsElasticBlockStore gitRepo nfs iscsi glusterfs rbd flexVolume cinder
                                   cephfs flocker fc azureFile vsphereVolume quobyte azureDisk photonPersistentDisk portworxVolume
                                   scaleIO storageos].freeze

      def restricted_volumes_1_0(_meta, spec)
        bad = []
        types = []
        Array(spec["volumes"]).each do |volume|
          next unless volume.is_a?(Hash)
          next if ALLOWED_VOLUME_SOURCES.any? { |source| !volume[source].nil? }

          bad << volume["name"].to_s
          types << (RESTRICTED_VOLUME_TYPES.find { |type| !volume[type].nil? } || "unknown")
        end
        return ALLOWED if bad.empty?

        unique = types.uniq.sort
        CheckResult.new(false, "restricted volume types",
                        "#{pluralize("volume", "volumes", bad.length)} #{join_quote(bad)} #{pluralize("uses", "use", bad.length)} " \
                        "#{pluralize("restricted volume type", "restricted volume types", unique.length)} #{join_quote(unique)}")
      end

      def run_as_non_root_1_0(_meta, spec)
        bad_setters = []
        pod_non_root = false
        pod_value = value(spec, "securityContext", "runAsNonRoot")
        unless pod_value.nil?
          pod_value == false ? bad_setters << "pod" : pod_non_root = true
        end
        explicit = []
        implicit = []
        containers(spec).each do |c|
          own = value(c, "securityContext", "runAsNonRoot")
          if !own.nil?
            explicit << c["name"].to_s if own == false
          elsif !pod_non_root
            implicit << c["name"].to_s
          end
        end
        if bad_setters.any? || explicit.any?
          return CheckResult.new(false, "runAsNonRoot != true",
                                 setters_detail(bad_setters, explicit, " must not set securityContext.runAsNonRoot=false"))
        end
        return ALLOWED if implicit.empty?

        CheckResult.new(false, "runAsNonRoot != true",
                        "pod or #{pluralize("container", "containers", implicit.length)} #{join_quote(implicit)} must set securityContext.runAsNonRoot=true")
      end

      def run_as_non_root_1_35(meta, spec)
        relax_for_user_namespace?(spec) ? ALLOWED : run_as_non_root_1_0(meta, spec)
      end

      def run_as_user_1_23(_meta, spec)
        bad_setters = value(spec, "securityContext", "runAsUser") == 0 ? ["pod"] : []
        explicit = containers(spec).select { |c| value(c, "securityContext", "runAsUser") == 0 }.map { |c| c["name"].to_s }
        return ALLOWED if bad_setters.empty? && explicit.empty?

        CheckResult.new(false, "runAsUser=0", setters_detail(bad_setters, explicit, " must not set runAsUser=0"))
      end

      def run_as_user_1_35(meta, spec)
        relax_for_user_namespace?(spec) ? ALLOWED : run_as_user_1_23(meta, spec)
      end

      SECCOMP_POD_ANNOTATION = "seccomp.security.alpha.kubernetes.io/pod"
      SECCOMP_CONTAINER_ANNOTATION_PREFIX = "container.seccomp.security.alpha.kubernetes.io/"

      def valid_seccomp?(type) = %w[Localhost RuntimeDefault].include?(type)

      def valid_seccomp_annotation?(text)
        text == "runtime/default" || text == "docker/default" || text.start_with?("localhost/")
      end

      def seccomp_profile_baseline_1_0(meta, spec)
        annotations = meta["annotations"] || {}
        forbidden = []
        if annotations.key?(SECCOMP_POD_ANNOTATION) && !valid_seccomp_annotation?(annotations[SECCOMP_POD_ANNOTATION].to_s)
          forbidden << "#{SECCOMP_POD_ANNOTATION}=#{go_quote(annotations[SECCOMP_POD_ANNOTATION])}"
        end
        containers(spec).each do |c|
          key = "#{SECCOMP_CONTAINER_ANNOTATION_PREFIX}#{c["name"]}"
          next unless annotations.key?(key) && !valid_seccomp_annotation?(annotations[key].to_s)

          forbidden << "#{key}=#{go_quote(annotations[key])}"
        end
        return ALLOWED if forbidden.empty?

        unique = forbidden.uniq.sort
        CheckResult.new(false, "seccompProfile", "forbidden #{pluralize("annotation", "annotations", unique.length)} #{unique.join(", ")}")
      end

      def seccomp_setters(spec, implicit_when_unset:)
        bad_setters = []
        bad_values = []
        pod_set = false
        pod_profile = value(spec, "securityContext", "seccompProfile")
        if pod_profile.is_a?(Hash)
          if valid_seccomp?(pod_profile["type"])
            pod_set = true
          else
            bad_setters << "pod"
            bad_values << pod_profile["type"].to_s
          end
        end
        explicit = []
        implicit = []
        containers(spec).each do |c|
          profile = value(c, "securityContext", "seccompProfile")
          if profile.is_a?(Hash)
            unless valid_seccomp?(profile["type"])
              explicit << c["name"].to_s
              bad_values << profile["type"].to_s
            end
          elsif implicit_when_unset && !pod_set
            implicit << c["name"].to_s
          end
        end
        [bad_setters, explicit, implicit, bad_values.uniq.sort]
      end

      def seccomp_profile_baseline_1_19(_meta, spec)
        bad_setters, explicit, _implicit, values = seccomp_setters(spec, implicit_when_unset: false)
        return ALLOWED if bad_setters.empty? && explicit.empty?

        CheckResult.new(false, "seccompProfile",
                        setters_detail(bad_setters, explicit, " must not set securityContext.seccompProfile.type to #{join_quote(values)}"))
      end

      def seccomp_profile_restricted_1_19(_meta, spec)
        bad_setters, explicit, implicit, values = seccomp_setters(spec, implicit_when_unset: true)
        if bad_setters.any? || explicit.any?
          return CheckResult.new(false, "seccompProfile",
                                 setters_detail(bad_setters, explicit, " must not set securityContext.seccompProfile.type to #{join_quote(values)}"))
        end
        return ALLOWED if implicit.empty?

        CheckResult.new(false, "seccompProfile",
                        "pod or #{pluralize("container", "containers", implicit.length)} #{join_quote(implicit)} must set " \
                        'securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost"')
      end

      def seccomp_profile_restricted_1_25(meta, spec)
        windows?(spec) ? ALLOWED : seccomp_profile_restricted_1_19(meta, spec)
      end

      SELINUX_TYPES_1_0 = ["", "container_t", "container_init_t", "container_kvm_t"].freeze
      SELINUX_TYPES_1_31 = (SELINUX_TYPES_1_0 + ["container_engine_t"]).freeze

      def se_linux_options(spec, allowed)
        bad_types = []
        set_user = false
        set_role = false
        valid = lambda do |options|
          ok = true
          type = options["type"].to_s
          unless allowed.include?(type)
            ok = false
            bad_types << type
          end
          unless options["user"].to_s.empty?
            ok = false
            set_user = true
          end
          unless options["role"].to_s.empty?
            ok = false
            set_role = true
          end
          ok
        end
        bad_setters = []
        pod_options = value(spec, "securityContext", "seLinuxOptions")
        bad_setters << "pod" if pod_options.is_a?(Hash) && !valid.call(pod_options)
        bad = containers(spec).select do |c|
          options = value(c, "securityContext", "seLinuxOptions")
          options.is_a?(Hash) && !valid.call(options)
        end.map { |c| c["name"].to_s }
        return ALLOWED if bad_setters.empty? && bad.empty?

        data = []
        unique = bad_types.uniq.sort
        data << "#{pluralize("type", "types", unique.length)} #{join_quote(unique)}" if unique.any?
        data << "user may not be set" if set_user
        data << "role may not be set" if set_role
        CheckResult.new(false, "seLinuxOptions",
                        setters_detail(bad_setters, bad, " set forbidden securityContext.seLinuxOptions: #{data.join("; ")}"))
      end

      def se_linux_options_1_0(_meta, spec) = se_linux_options(spec, SELINUX_TYPES_1_0)
      def se_linux_options_1_31(_meta, spec) = se_linux_options(spec, SELINUX_TYPES_1_31)

      SYSCTLS_1_0 = %w[kernel.shm_rmid_forced net.ipv4.ip_local_port_range net.ipv4.tcp_syncookies net.ipv4.ping_group_range
                       net.ipv4.ip_unprivileged_port_start].freeze
      SYSCTLS_1_27 = (SYSCTLS_1_0 + %w[net.ipv4.ip_local_reserved_ports]).freeze
      SYSCTLS_1_29 = (SYSCTLS_1_27 + %w[net.ipv4.tcp_keepalive_time net.ipv4.tcp_fin_timeout net.ipv4.tcp_keepalive_intvl
                                        net.ipv4.tcp_keepalive_probes]).freeze
      SYSCTLS_1_32 = (SYSCTLS_1_29 + %w[net.ipv4.tcp_rmem net.ipv4.tcp_wmem]).freeze

      def sysctls(spec, allowed)
        forbidden = Array(value(spec, "securityContext", "sysctls")).map do |sysctl|
          sysctl["name"].to_s
        end.reject { |name| allowed.include?(name) }
        return ALLOWED if forbidden.empty?

        CheckResult.new(false, "forbidden sysctls", forbidden.join(", "))
      end

      def windows_host_process_1_0(_meta, spec)
        bad = containers(spec).select do |c|
          value(c, "securityContext", "windowsOptions", "hostProcess") == true
        end.map { |c| c["name"].to_s }
        setters = value(spec, "securityContext", "windowsOptions", "hostProcess") == true ? ["pod"] : []
        return ALLOWED if bad.empty? && setters.empty?

        CheckResult.new(false, "hostProcess", setters_detail(setters, bad, " must not set securityContext.windowsOptions.hostProcess=true"))
      end

      V = ->(major, minor) { Version.of(major, minor) }
      M = ->(name) { PodSecurity.method(name) }

      # DefaultChecks.
      CHECKS = [
        Check.new("allowPrivilegeEscalation", "restricted",
                  [VersionedCheck.new(V.call(1, 8), M.call(:allow_privilege_escalation_1_8), []),
                   VersionedCheck.new(V.call(1, 25), M.call(:allow_privilege_escalation_1_25), [])]),
        Check.new("appArmorProfile", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:app_armor_profile_1_0), [])]),
        Check.new("capabilities_baseline", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:capabilities_baseline_1_0), [])]),
        Check.new("capabilities_restricted", "restricted",
                  [VersionedCheck.new(V.call(1, 22), M.call(:capabilities_restricted_1_22), ["capabilities_baseline"]),
                   VersionedCheck.new(V.call(1, 25), M.call(:capabilities_restricted_1_25), ["capabilities_baseline"])]),
        Check.new("hostNamespaces", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:host_namespaces_1_0), [])]),
        Check.new("hostPathVolumes", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:host_path_volumes_1_0), [])]),
        Check.new("hostPorts", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:host_ports_1_0), [])]),
        Check.new("hostProbesAndHostLifecycle", "baseline",
                  [VersionedCheck.new(V.call(1, 34), M.call(:host_probes_and_host_lifecycle_1_34), [])]),
        Check.new("privileged", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:privileged_1_0), [])]),
        Check.new("procMount", "baseline",
                  [VersionedCheck.new(V.call(1, 0), M.call(:proc_mount_1_0), []),
                   VersionedCheck.new(V.call(1, 35), M.call(:proc_mount_1_35_baseline), [])]),
        Check.new("procMount_restricted", "restricted", [VersionedCheck.new(V.call(1, 35), M.call(:proc_mount_1_0), ["procMount"])]),
        Check.new("restrictedVolumes", "restricted",
                  [VersionedCheck.new(V.call(1, 0), M.call(:restricted_volumes_1_0), ["hostPathVolumes"])]),
        Check.new("runAsNonRoot", "restricted",
                  [VersionedCheck.new(V.call(1, 0), M.call(:run_as_non_root_1_0), []),
                   VersionedCheck.new(V.call(1, 35), M.call(:run_as_non_root_1_35), [])]),
        Check.new("runAsUser", "restricted",
                  [VersionedCheck.new(V.call(1, 23), M.call(:run_as_user_1_23), []),
                   VersionedCheck.new(V.call(1, 35), M.call(:run_as_user_1_35), [])]),
        Check.new("seLinuxOptions", "baseline",
                  [VersionedCheck.new(V.call(1, 0), M.call(:se_linux_options_1_0), []),
                   VersionedCheck.new(V.call(1, 31), M.call(:se_linux_options_1_31), [])]),
        Check.new("seccompProfile_baseline", "baseline",
                  [VersionedCheck.new(V.call(1, 0), M.call(:seccomp_profile_baseline_1_0), []),
                   VersionedCheck.new(V.call(1, 19), M.call(:seccomp_profile_baseline_1_19), [])]),
        Check.new("seccompProfile_restricted", "restricted",
                  [VersionedCheck.new(V.call(1, 19), M.call(:seccomp_profile_restricted_1_19), ["seccompProfile_baseline"]),
                   VersionedCheck.new(V.call(1, 25), M.call(:seccomp_profile_restricted_1_25), ["seccompProfile_baseline"])]),
        Check.new("sysctls", "baseline",
                  [VersionedCheck.new(V.call(1, 0), ->(_m, s) { PodSecurity.sysctls(s, SYSCTLS_1_0) }, []),
                   VersionedCheck.new(V.call(1, 27), ->(_m, s) { PodSecurity.sysctls(s, SYSCTLS_1_27) }, []),
                   VersionedCheck.new(V.call(1, 29), ->(_m, s) { PodSecurity.sysctls(s, SYSCTLS_1_29) }, []),
                   VersionedCheck.new(V.call(1, 32), ->(_m, s) { PodSecurity.sysctls(s, SYSCTLS_1_32) }, [])]),
        Check.new("windowsHostProcess", "baseline", [VersionedCheck.new(V.call(1, 0), M.call(:windows_host_process_1_0), [])])
      ].freeze

      # policy/registry.go checkRegistry: every version from v1.0 to the
      # newest check version, with the checks that apply to it in ID order
      # (baseline first); a restricted check's overrides replace the baseline
      # checks they name.
      class Evaluator
        attr_reader :max_version

        def initialize(checks = CHECKS, emulation_version: nil)
          @baseline = {}
          @restricted = {}
          @max_version = Version.of(0, 0)
          checks.each do |check|
            last = check.versions.last.minimum
            @max_version = last if @max_version.older?(last)
          end
          restricted_versions = {}
          baseline_versions = {}
          checks.each do |check|
            inflate(check, check.level == "restricted" ? restricted_versions : baseline_versions)
          end
          baseline_ids = checks.select { |check| check.level == "baseline" }.map(&:id).sort
          restricted_ids = checks.select { |check| check.level == "restricted" }.map(&:id).sort
          ordered = baseline_ids + restricted_ids
          version = Version.of(1, 0)
          while version.older?(@max_version.next_minor)
            overrides = (restricted_versions[version] || {}).values.flat_map(&:overrides)
            (baseline_versions[version] || {}).each do |id, versioned|
              next if overrides.include?(id)

              (restricted_versions[version] ||= {})[id] = versioned
            end
            @restricted[version] = ordered.filter_map { |id| restricted_versions[version]&.[](id)&.check }
            @baseline[version] = ordered.filter_map { |id| baseline_versions[version]&.[](id)&.check }
            version = version.next_minor
          end
          @max_version = emulation_version if emulation_version && emulation_version.older?(@max_version)
        end

        def evaluate(level_version, metadata, spec)
          return [] if level_version.level == "privileged"

          version = level_version.version
          version = @max_version if @max_version.older?(version)
          checks = level_version.level == "baseline" ? @baseline[version] : @restricted[version]
          Array(checks).map { |check| check.call(metadata || {}, spec || {}) }
        end

        private

        def inflate(check, versions)
          check.versions.each_with_index do |versioned, index|
            following = check.versions[index + 1]&.minimum || @max_version.next_minor
            version = versioned.minimum
            while version.older?(following)
              (versions[version] ||= {})[check.id] = versioned
              version = version.next_minor
            end
          end
        end
      end
    end
  end
end
