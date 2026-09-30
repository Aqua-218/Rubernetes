# frozen_string_literal: true

require "securerandom"

module Rubernetes
  module Volume
    # pkg/volume/util/selinux.go + the volume manager's desired state of
    # world: the SELinux file label a Pod's containers imply for each volume,
    # whether the volume can be mounted with that label (-o context=), and
    # the KEP-1710 checks (all containers of a Pod agree on a label, all Pods
    # using a volume agree on a label).  A disagreement is an error for a
    # volume whose access mode is SELinux-mounted (ReadWriteOncePod, or every
    # PV when the SELinuxMount gate is on) and a warning otherwise, counted
    # in volume_manager_selinux_*_{errors,warnings}_total.
    module SELinux
      class Error < Volume::Error; end

      # label.InitLabels failed to build a context (unreachable in practice).
      class TranslationError < Error; end

      # One volume, several containers, different SELinux labels.
      class MultipleLabelsError < Error
        attr_reader :labels

        def initialize(labels)
          @labels = labels.sort
          super("volume is used with more than one SELinux label in the pod: #{@labels.join(", ")}")
        end
      end

      # A second Pod wants the same volume with another label.
      class ConflictError < Error; end

      FEATURE_SELINUX_MOUNT = "SELinuxMount"
      FEATURE_SELINUX_MOUNT_RWOP = "SELinuxMountReadWriteOncePod" # GA, locked on in 1.36
      FEATURE_SELINUX_CHANGE_POLICY = "SELinuxChangePolicy" # GA, locked on in 1.36

      # opencontainers/selinux label.InitLabels: the container file context is
      # the distribution's lxc_contexts "file" entry with the user and the
      # MCS level from the Pod's seLinuxOptions applied; without a level a
      # unique MCS pair is allocated (ContainerLabels does that).
      class Translator
        SELINUXFS = "/sys/fs/selinux"
        CONFIG = "/etc/selinux/config"
        DEFAULT_FILE_CONTEXT = "system_u:object_r:container_file_t:s0"
        DEFAULT_PROCESS_CONTEXT = "system_u:system_r:container_t:s0"

        def initialize(selinuxfs: SELINUXFS, config: CONFIG, random: SecureRandom)
          @selinuxfs = selinuxfs
          @config = config
          @random = random
        end

        # selinux.GetEnabled: selinuxfs is mounted and the policy is not disabled.
        def enabled?
          return false unless File.exist?(File.join(@selinuxfs, "enforce"))

          mode = File.exist?(@config) ? File.read(@config)[/^SELINUX=(\w+)/, 1].to_s.downcase : ""
          mode != "disabled"
        rescue SystemCallError
          false
        end

        # The file label for a container's effective SELinuxOptions ("" when
        # SELinux is off or no option is set).
        def file_label(options)
          return "" unless enabled?
          return "" if options.nil? || options.empty?

          user = options["user"].to_s
          level = options["level"].to_s
          type = options["type"].to_s
          role = options["role"].to_s
          return "" if user.empty? && level.empty? && type.empty? && role.empty?

          file = split(file_context)
          file[:user] = user unless user.empty?
          file[:level] = level.empty? ? unique_mcs_level : level
          join(file)
        rescue ArgumentError => error
          raise TranslationError, error.message
        end

        private

        def file_context
          policy = File.exist?(@config) ? File.read(@config)[/^SELINUXTYPE=(\w+)/, 1].to_s : ""
          path = "/etc/selinux/#{policy}/contexts/lxc_contexts"
          if !policy.empty? && File.exist?(path)
            entry = File.read(path)[/^file\s*=\s*"([^"]+)"/, 1]
            return entry if entry
          end
          DEFAULT_FILE_CONTEXT
        rescue SystemCallError
          DEFAULT_FILE_CONTEXT
        end

        def split(context)
          user, role, type, level = context.split(":", 4)
          raise ArgumentError, "malformed SELinux context #{context.inspect}" if user.nil? || role.nil? || type.nil?

          {user: user, role: role, type: type, level: level.to_s}
        end

        def join(parts)
          [parts[:user], parts[:role], parts[:type], parts[:level]].reject { |part| part.to_s.empty? }.join(":")
        end

        # uniqMcs: s0:cX,cY with X < Y from 1024 categories.
        def unique_mcs_level
          first = @random.random_number(1024)
          second = @random.random_number(1024)
          second = (second + 1) % 1024 if second == first
          first, second = second, first if first > second
          "s0:c#{first},c#{second}"
        end
      end

      # util.NewFakeSELinuxLabelTranslator: SELinux "enabled", labels built
      # from the options alone with fixed defaults, no MCS allocation.
      class FakeTranslator
        def initialize(enabled: true)
          @enabled = enabled
        end

        def enabled? = @enabled

        def file_label(options)
          return "" unless @enabled
          return "" if options.nil? || options.empty?

          user = options["user"].to_s.empty? ? "system_u" : options["user"].to_s
          role = options["role"].to_s.empty? ? "object_r" : options["role"].to_s
          type = options["type"].to_s.empty? ? "container_file_t" : options["type"].to_s
          level = options["level"].to_s
          return "" if level.empty?

          "#{user}:#{role}:#{type}:#{level}"
        end
      end

      module_function

      # GetPodVolumeNames' seLinuxContainerContexts: for every volume, the
      # effective SELinuxOptions (container's, else the Pod's) of each
      # container that mounts it -- init, regular and ephemeral containers.
      def container_contexts(pod)
        spec = pod["spec"] || {}
        pod_options = spec.dig("securityContext", "seLinuxOptions")
        contexts = Hash.new { |hash, key| hash[key] = [] }
        (Array(spec["initContainers"]) + Array(spec["containers"]) + Array(spec["ephemeralContainers"])).each do |container|
          options = container.dig("securityContext", "seLinuxOptions") || pod_options
          next if options.nil?

          Array(container["volumeMounts"]).each do |mount|
            contexts[mount["name"].to_s] << options
          end
        end
        contexts
      end

      # VolumeSupportsSELinuxMount: PersistentVolumes only; every access mode
      # with the SELinuxMount gate, otherwise a volume whose only access mode
      # is ReadWriteOncePod.
      def volume_supports_mount?(spec, feature_gates = {})
        return false unless spec["persistentVolume"]
        return true if gate_enabled?(feature_gates, FEATURE_SELINUX_MOUNT, default: false)

        Array(spec["accessModes"]).map(&:to_s) == ["ReadWriteOncePod"]
      end

      # plugin.SupportsSELinuxContextMount: a CSI driver that declares
      # spec.seLinuxMount; the in-tree plugins this node has (hostPath, local,
      # emptyDir, configMap, secret, downwardAPI, projected, image) do not.
      def plugin_supports_context_mount?(spec, csi_driver: nil)
        return false unless spec["csi"]

        driver = csi_driver.respond_to?(:call) ? csi_driver.call(spec.dig("csi", "driver").to_s) : csi_driver
        driver.is_a?(Hash) && driver.dig("spec", "seLinuxMount") == true
      end

      # getVolumeAccessMode: the "highest" of the PV's modes, or "inline".
      def access_mode(spec)
        return "inline" unless spec["persistentVolume"]

        modes = Array(spec["accessModes"]).map(&:to_s)
        return "RWX" if modes.include?("ReadWriteMany")
        return "ROX" if modes.include?("ReadOnlyMany")
        return "RWO" if modes.include?("ReadWriteOnce")
        return "RWOP" if modes.include?("ReadWriteOncePod")

        ""
      end

      # In-tree plugin names by the manager's backend kind (kubelet's
      # VOLUME_PLUGIN_NAMES table, kept here so the volume layer does not
      # depend on the node).
      PLUGIN_NAMES = {
        "emptyDir" => "kubernetes.io/empty-dir", "hostPath" => "kubernetes.io/host-path", "configMap" => "kubernetes.io/configmap",
        "secret" => "kubernetes.io/secret", "downwardAPI" => "kubernetes.io/downward-api", "projected" => "kubernetes.io/projected",
        "csi" => "kubernetes.io/csi", "local" => "kubernetes.io/local-volume", "image" => "kubernetes.io/image"
      }.freeze

      # getVolumePluginNameWithDriver: the plugin name, with the CSI driver
      # appended for a CSI volume, as the metrics label.
      def plugin_label(spec)
        return "kubernetes.io/csi:#{spec.dig("csi", "driver")}" if spec["csi"]

        PLUGIN_NAMES[spec["backend"].to_s] || spec["backend"].to_s
      end

      def gate_enabled?(feature_gates, name, default:)
        gates = feature_gates || {}
        value = gates.key?(name) ? gates[name] : gates[name.to_sym]
        value.nil? ? default : value != false
      end

      # AddSELinuxMountOption: the mount flag the CSI driver receives.
      def mount_option(label)
        "context=\"#{label}\""
      end

      # The desired state of world's SELinux bookkeeping: per volume, the
      # label the first Pod brought and every Pod using it.  admit returns
      # the label the volume is mounted with (nil: mount without -o context).
      class Tracker
        Info = Struct.new(:mount_label, :original_label, :plugin_supports, keyword_init: true)

        def initialize(translator: nil, metrics: nil, feature_gates: {}, csi_driver_reader: nil, logger: nil)
          @translator = translator || Translator.new
          @metrics = metrics
          @feature_gates = feature_gates || {}
          @csi_driver_reader = csi_driver_reader
          @logger = logger
          @mutex = Mutex.new
          @volumes = {}
        end

        attr_reader :translator

        def volumes
          @mutex.synchronize { @volumes.transform_values { |entry| {label: entry[:label], pods: entry[:pods].to_a} } }
        end

        # +contexts+: the container SELinuxOptions that mount this volume.
        # Raises ConflictError / MultipleLabelsError / TranslationError when
        # the volume's access mode makes the mismatch an error.
        def admit(pod_uid:, volume_name:, spec:, contexts:)
          return nil unless @translator.enabled?

          access_mode = SELinux.access_mode(spec)
          supported = SELinux.volume_supports_mount?(spec, @feature_gates)
          plugin = SELinux.plugin_label(spec)
          info = label_info(spec, contexts, access_mode, supported)
          label = info.original_label
          mount_label = supported ? info.mount_label : ""
          unique = unique_name(pod_uid, volume_name, spec)
          @mutex.synchronize do
            existing = @volumes[unique]
            if existing.nil?
              @volumes[unique] = {label: label, pods: Set[pod_uid]}
              @metrics.selinux_volume_admitted(plugin, access_mode) if @metrics && !label.empty?
            else
              existing[:pods] << pod_uid
              if info.plugin_supports && label != existing[:label]
                error = ConflictError.new("conflicting SELinux labels of volume #{volume_name}: #{existing[:label].inspect} and #{label.inspect}")
                @metrics&.selinux_volume_context_mismatch(plugin, access_mode, error: supported)
                raise error if supported

                warn("volume", error)
              end
            end
          end
          mount_label.empty? ? nil : mount_label
        end

        def forget(pod_uid:, volume_name:, spec: nil, unique_name: nil)
          unique = unique_name || self.unique_name(pod_uid, volume_name, spec || {})
          @mutex.synchronize do
            entry = @volumes[unique]
            next unless entry

            entry[:pods].delete(pod_uid)
            @volumes.delete(unique) if entry[:pods].empty?
          end
          nil
        end

        # uniqueVolumeName: one PV is one volume however many Pods use it; an
        # inline volume belongs to its Pod.
        def unique_name(pod_uid, volume_name, spec)
          pv = spec["persistentVolume"]
          pv ? "pv/#{pv}" : "pod/#{pod_uid}/#{volume_name}"
        end

        private

        # GetMountSELinuxLabel with the desired state's metric handling.
        def label_info(spec, contexts, access_mode, supported)
          plugin_supports = SELinux.plugin_supports_context_mount?(spec, csi_driver: @csi_driver_reader)
          labels = Set.new
          begin
            Array(contexts).each { |options| labels << @translator.file_label(options) }
          rescue TranslationError => error
            @metrics&.selinux_container_context(access_mode, error: supported)
            raise error if supported

            warn("container", error)
            return Info.new(mount_label: "", original_label: "", plugin_supports: plugin_supports)
          end
          if labels.length > 1
            error = MultipleLabelsError.new(labels.to_a)
            @metrics&.selinux_pod_context_mismatch(access_mode, error: supported)
            raise error if supported

            warn("pod", error)
            return Info.new(mount_label: "", original_label: "", plugin_supports: false)
          end
          label = labels.first.to_s
          mount_label = label
          mount_label = "" if spec.dig("pod", "spec", "securityContext",
                                       "seLinuxChangePolicy") == "Recursive" || spec["seLinuxChangePolicy"] == "Recursive"
          mount_label = "" unless plugin_supports
          Info.new(mount_label: mount_label, original_label: label, plugin_supports: plugin_supports)
        end

        def warn(kind, error)
          return unless @logger.respond_to?(:warn)

          @logger.warn("volume.selinux_#{kind}_context_mismatch", error: error.message,
                                                                  note: "not an error yet: https://github.com/kubernetes/enhancements/issues/1710")
        end
      end
    end
  end
end
