# frozen_string_literal: true

require_relative "../resource_helpers"
require_relative "quantity"

require "digest"

module Rubernetes
  module Schema
    class DefaultingError < StandardError; end

    # Applies declarative defaults as a pure transformation.
    class Defaulting
      UNKNOWN_MODES = %i[preserve prune reject].freeze

      attr_reader :definition, :unknown_fields

      def self.apply(definition, value = nil, **options)
        new(definition, unknown_fields: options.delete(:unknown_fields, :preserve)).apply(value, **options)
      end

      class << self
        alias call apply
      end

      def initialize(definition, unknown_fields: :preserve, unknown: nil)
        @definition = definition.is_a?(Definition) ? definition : Definition.new(definition)
        @unknown_fields = (unknown || unknown_fields).to_sym
        return if UNKNOWN_MODES.include?(@unknown_fields)

        raise ArgumentError, "unknown_fields must be :preserve, :prune, or :reject"
      end

      # Hash input remains a frozen wire-format Hash; ValueObject input remains typed.
      # +old+: the stored object an update replaces.  Defaulting is
      # idempotent and the stored object was defaulted when written, so a
      # field whose value equals the stored one takes the stored (frozen,
      # defaulted) value as is instead of being walked and copied again.
      def apply(value = nil, as: nil, unknown_fields: @unknown_fields, unknown: nil,
                kubernetes_admission_defaults: false, old: nil, **keyword_value)
        value = keyword_value if value.nil? && !keyword_value.empty?
        value ||= {}
        mode = (unknown || unknown_fields).to_sym
        raise ArgumentError, "unknown_fields must be :preserve, :prune, or :reject" unless UNKNOWN_MODES.include?(mode)

        output_as = as || (value.is_a?(ValueObject) ? :value : :hash)
        case output_as.to_sym
        when :value, :object
          object = value.is_a?(ValueObject) ? value.to_h : value
          @definition.value_class.new(
            apply_object_hash(object, @definition, [], mode, kubernetes_admission_defaults)
          )
        when :hash, :wire
          DeepFreeze.call(
            apply_object_hash(
              value.is_a?(ValueObject) ? value.to_h : value,
              @definition,
              [],
              mode,
              kubernetes_admission_defaults,
              old.is_a?(Hash) ? old : nil
            )
          )
        else
          raise ArgumentError, "defaulting output must be :value or :hash"
        end
      end

      alias call apply

      def apply_value(value = nil, **)
        apply(value, as: :value, **)
      end

      def apply_hash(value = nil, **)
        apply(value, as: :hash, **)
      end

      def changed?(value = nil, **)
        before = value.is_a?(ValueObject) ? value.to_h : value
        after = apply(value, **)
        after_hash = after.is_a?(ValueObject) ? after.to_h : after
        before != after_hash
      end

      private

      # A union type (JSONSchemaPropsOrArray/OrBool/OrStringArray) carries no
      # fields of its own: upstream custom-marshals it as either the target
      # object or a scalar/array.  Without resolving it here the pruner saw a
      # field-less object and emptied it, which silently truncated every CRD
      # schema containing `items` (the CRD then failed the structural check
      # and was never Established).
      def union_object_definition(object_definition)
        return nil unless object_definition.respond_to?(:metadata) && object_definition.metadata.is_a?(Hash)

        name = object_definition.metadata[:union_object_schema] || object_definition.metadata["union_object_schema"]
        return nil unless name.is_a?(String) && defined?(Rubernetes::Generated) && Rubernetes::Generated.respond_to?(:definition_for)

        Rubernetes::Generated.definition_for(name)
      rescue StandardError
        nil
      end

      def apply_object_hash(value, object_definition, path, mode, kubernetes_admission_defaults, old = nil)
        union_target = union_object_definition(object_definition)
        if union_target && value.respond_to?(:each_pair)
          return apply_object_hash(value, union_target, path, mode, kubernetes_admission_defaults, old)
        end

        old = nil unless old.is_a?(Hash)

        raise DefaultingError, "expected an object at #{display_path(path)}, got #{value.class}" unless value.respond_to?(:each_pair)

        result = {}
        supplied = {}
        value.each_pair do |key, item|
          field = field_for_key(object_definition, key)
          if field
            canonical = field.name
            raise DefaultingError, "field #{path_for(path, field.json_name)} was supplied more than once" if supplied.key?(canonical)

            supplied[canonical] = true
            prior = old && old[field.json_name]
            if !prior.nil? && prior.frozen? && prior == item
              result[field.json_name] = prior
              next
            end

            result[field.json_name] = apply_field(
              item,
              field,
              path + [field.json_name],
              mode,
              kubernetes_admission_defaults,
              prior
            )
          else
            key = key.to_s
            if mode == :reject && !object_definition.preserve_unknown_fields
              raise DefaultingError, "unknown field #{path_for(path, key)} is not allowed"
            end

            result[key] = deep_copy(item) if mode == :preserve || object_definition.preserve_unknown_fields
          end
        end

        object_definition.fields.each_value do |field|
          next if supplied.key?(field.name)
          next unless field.has_default?

          result[field.json_name] = apply_field(
            default_value(field),
            field,
            path + [field.json_name],
            mode,
            kubernetes_admission_defaults
          )
        end
        apply_kubernetes_defaults(
          result,
          object_definition,
          kubernetes_admission_defaults: kubernetes_admission_defaults
        )
        DeepFreeze.call(result)
      end

      # A small set of upstream API defaults are procedural rather than
      # OpenAPI field defaults.  Keep them attached to the schema kind so the
      # same behavior applies to a root object, a nested value, and list
      # items, without encoding per-fixture or per-resource exceptions.
      def apply_kubernetes_defaults(result, object_definition, kubernetes_admission_defaults: false)
        if object_definition.kind == "ServiceReference" && object_definition.name.start_with?("io.k8s.") && !(result.key?("port") && !result["port"].nil?)
          # Admissionregistration, apiextensions, and kube-aggregator all
          # register this upstream default for their versioned ServiceReference
          # value.  A nil pointer is defaulted; an explicitly supplied port is
          # retained, including zero, just as Scheme.Default does.
          result["port"] = 443
        end

        apply_kubernetes_admission_defaults(result, object_definition) if kubernetes_admission_defaults
        apply_group_defaults(result, object_definition) if kubernetes_admission_defaults
        apply_kubernetes_scheme_defaults(result, object_definition)
      end

      # pkg/apis/core/v1/defaults.go SetDefaults_Volume: a Volume whose source
      # is entirely unset is an emptyDir.  The list is VolumeSource's own
      # pointer fields, which is what ptr.AllPtrFieldsNil inspects.
      VOLUME_SOURCE_FIELDS = %w[
        awsElasticBlockStore azureDisk azureFile cephfs cinder configMap csi
        downwardAPI emptyDir ephemeral fc flexVolume flocker gcePersistentDisk
        gitRepo glusterfs hostPath image iscsi nfs persistentVolumeClaim
        photonPersistentDisk portworxVolume projected quobyte rbd scaleIO
        secret storageos vsphereVolume
      ].freeze

      RBAC_GROUP = "rbac.authorization.k8s.io"

      # The upstream defaults that the generated OpenAPI corpus cannot carry:
      # everything in pkg/apis/<group>/<version>/defaults.go plus the handful of
      # `+default=` markers that survive only in the Go types.  They are keyed by
      # schema kind so the same rule fires for a root object, a nested value and
      # a list item alike.
      def apply_kubernetes_admission_defaults(result, object_definition)
        # Only a top-level kind carries its full API group; a nested schema type
        # is named after the Go package ("storage", "rbac"), so match on the
        # first label, which both spellings share.
        group = object_definition.group.to_s.split(".").first.to_s
        case "#{group}/#{object_definition.kind}"
        when "/Container", "/EphemeralContainer"
          # These defaults are applied by the apiserver's pod strategy rather
          # than represented as OpenAPI field defaults. Controllers observe
          # the defaulted pod template, so retain the same wire shape here.
          result["imagePullPolicy"] ||= image_pull_policy(result["image"].to_s)
          result["resources"] = {} unless result.key?("resources")
          result["terminationMessagePath"] ||= "/dev/termination-log"
          result["terminationMessagePolicy"] ||= "File"
        when "/ContainerPort"
          # staging/src/k8s.io/api/core/v1/types.go ContainerPort.Protocol
          # carries `+default="TCP"`.
          result["protocol"] = "TCP" if result["protocol"].to_s.empty?
        when "/ServicePort"
          # pkg/apis/core/v1/defaults.go SetDefaults_ServicePort: an unset
          # targetPort means "the same as port".  intstr's zero value is the
          # integer 0, so an omitted targetPort is stored as 0 unless it is
          # defaulted -- and a Service port of 0 is not a port at all.  A
          # StatefulSet's headless governing Service declares `port: 80` and no
          # targetPort, so every one of them was stored with targetPort 0, and
          # kube-proxy refused the whole Service list over it: every Service
          # created after the first such one was unreachable.
          result["protocol"] = "TCP" if result["protocol"].to_s.empty?
          target = result["targetPort"]
          result["targetPort"] = result["port"] if (target.nil? || target == 0 || target == "") && !result["port"].nil?
        when "/Volume"
          result["emptyDir"] = {} unless VOLUME_SOURCE_FIELDS.any? { |name| !result[name].nil? }
          image = result["image"]
          if image.is_a?(Hash) && image["pullPolicy"].to_s.empty?
            copy = deep_copy(image)
            copy["pullPolicy"] = image_pull_policy(copy["reference"].to_s)
            result["image"] = copy
          end
        when "/Probe"
          # SetDefaults_Probe compares against the zero value, so an explicit 0
          # is defaulted just like an absent field.
          result["timeoutSeconds"] = 1 if result["timeoutSeconds"].to_i.zero?
          result["periodSeconds"] = 10 if result["periodSeconds"].to_i.zero?
          result["successThreshold"] = 1 if result["successThreshold"].to_i.zero?
          result["failureThreshold"] = 3 if result["failureThreshold"].to_i.zero?
        when "/HTTPGetAction"
          result["path"] = "/" if result["path"].to_s.empty?
          result["scheme"] = "HTTP" if result["scheme"].to_s.empty?
        when "/GRPCAction"
          result["service"] = "" if result["service"].nil?
        when "/SecretVolumeSource", "/ConfigMapVolumeSource",
             "/DownwardAPIVolumeSource", "/ProjectedVolumeSource"
          result["defaultMode"] = 420 if result["defaultMode"].nil?
        when "/ServiceAccountTokenProjection"
          result["expirationSeconds"] = 3600 if result["expirationSeconds"].nil?
        when "/ObjectFieldSelector"
          result["apiVersion"] = "v1" if result["apiVersion"].to_s.empty?
        when "/HostPathVolumeSource"
          # HostPathUnset is the empty string, not a missing field.
          result["type"] = "" if result["type"].nil?
        when "/ISCSIVolumeSource", "/ISCSIPersistentVolumeSource"
          result["iscsiInterface"] = "default" if result["iscsiInterface"].to_s.empty?
        when "/FileKeySelector"
          result["optional"] = false if result["optional"].nil?
        when "/Secret"
          result["type"] = "Opaque" if result["type"].to_s.empty?
        when "/EndpointPort"
          # SetDefaults_Endpoints walks every subset port.
          result["protocol"] = "TCP" if result["protocol"].to_s.empty?
        when "/PersistentVolumeSpec"
          result["persistentVolumeReclaimPolicy"] = "Retain" if result["persistentVolumeReclaimPolicy"].to_s.empty?
          result["volumeMode"] = "Filesystem" if result["volumeMode"].nil?
        when "/PersistentVolumeClaimSpec"
          result["volumeMode"] = "Filesystem" if result["volumeMode"].nil?
        when "/NamespaceStatus"
          result["phase"] = "Active" if result["phase"].to_s.empty?
        when "/NodeStatus"
          result["allocatable"] = deep_copy(result["capacity"]) if result["allocatable"].nil? && result["capacity"].is_a?(Hash)
        when "/LimitRangeItem"
          apply_limit_range_item_defaults(result)
        when "/Namespace"
          apply_namespace_name_label(result)
        when "/ReplicationController"
          apply_replication_controller_defaults(result)
        when "/ReplicationControllerSpec"
          # staging/src/k8s.io/api/core/v1/types.go carries `+default=1` here.
          result["replicas"] = 1 if result["replicas"].nil?
        when "/PodSpec"
          result["dnsPolicy"] ||= "ClusterFirst"
          result["restartPolicy"] ||= "Always"
          result["schedulerName"] ||= "default-scheduler"
          result["securityContext"] = {} unless result.key?("securityContext")
          result["terminationGracePeriodSeconds"] = 30 unless result.key?("terminationGracePeriodSeconds")
        when "/Pod"
          apply_pod_defaults(result)
        when "apps/DeploymentSpec"
          result["replicas"] = 1 if result["replicas"].nil?
          result["progressDeadlineSeconds"] = 600 if result["progressDeadlineSeconds"].nil?
          result["revisionHistoryLimit"] = 10 if result["revisionHistoryLimit"].nil?
          result["strategy"] = rolling_update_strategy(result["strategy"], "maxUnavailable" => "25%",
                                                                           "maxSurge" => "25%")
        when "apps/ReplicaSetSpec"
          result["replicas"] = 1 if result["replicas"].nil?
        when "apps/StatefulSetSpec"
          result["replicas"] = 1 if result["replicas"].nil?
          result["revisionHistoryLimit"] = 10 if result["revisionHistoryLimit"].nil?
          result["podManagementPolicy"] = "OrderedReady" if result["podManagementPolicy"].to_s.empty?
          result["updateStrategy"] = stateful_set_update_strategy(result["updateStrategy"])
          retention = result["persistentVolumeClaimRetentionPolicy"]
          retention = retention.is_a?(Hash) ? deep_copy(retention) : {}
          retention["whenDeleted"] = "Retain" if retention["whenDeleted"].to_s.empty?
          retention["whenScaled"] = "Retain" if retention["whenScaled"].to_s.empty?
          result["persistentVolumeClaimRetentionPolicy"] = retention
        when "apps/DaemonSetSpec"
          result["revisionHistoryLimit"] = 10 if result["revisionHistoryLimit"].nil?
          result["updateStrategy"] = rolling_update_strategy(result["updateStrategy"], "maxUnavailable" => 1,
                                                                                       "maxSurge" => 0)
        when "batch/Job"
          apply_job_defaults(result)
        when "batch/PodFailurePolicyOnPodConditionsPattern"
          result["status"] = "True" if result["status"].to_s.empty?
        when "batch/CronJobSpec"
          result["concurrencyPolicy"] = "Allow" if result["concurrencyPolicy"].to_s.empty?
          result["failedJobsHistoryLimit"] = 1 if result["failedJobsHistoryLimit"].nil?
          result["successfulJobsHistoryLimit"] = 3 if result["successfulJobsHistoryLimit"].nil?
          result["suspend"] = false if result["suspend"].nil?
        when "discovery/EndpointPort"
          result["name"] = "" if result["name"].nil?
          result["protocol"] = "TCP" if result["protocol"].nil?
        when "networking/NetworkPolicyPort"
          result["protocol"] = "TCP" if result["protocol"].nil?
        when "networking/NetworkPolicySpec"
          if !result["policyTypes"].is_a?(Array) || result["policyTypes"].empty?
            types = ["Ingress"]
            types << "Egress" if result["egress"].is_a?(Array) && !result["egress"].empty?
            result["policyTypes"] = types
          end
        when "networking/IngressClassParametersReference"
          result["scope"] = "Cluster" if result["scope"].nil?
        when "scheduling/PriorityClass"
          result["preemptionPolicy"] = "PreemptLowerPriority" if result["preemptionPolicy"].nil?
        when "storage/StorageClass"
          result["reclaimPolicy"] = "Delete" if result["reclaimPolicy"].nil?
          result["volumeBindingMode"] = "Immediate" if result["volumeBindingMode"].nil?
        when "storage/CSIDriverSpec"
          result["attachRequired"] = true if result["attachRequired"].nil?
          result["podInfoOnMount"] = false if result["podInfoOnMount"].nil?
          result["storageCapacity"] = false if result["storageCapacity"].nil?
          result["fsGroupPolicy"] = "ReadWriteOnceWithFSType" if result["fsGroupPolicy"].nil?
          result["requiresRepublish"] = false if result["requiresRepublish"].nil?
          result["seLinuxMount"] = false if result["seLinuxMount"].nil?
          modes = result["volumeLifecycleModes"]
          result["volumeLifecycleModes"] = ["Persistent"] if !modes.is_a?(Array) || modes.empty?
        when "rbac/RoleBinding", "rbac/ClusterRoleBinding"
          reference = result["roleRef"]
          if reference.is_a?(Hash) && reference["apiGroup"].to_s.empty?
            copy = deep_copy(reference)
            copy["apiGroup"] = RBAC_GROUP
            result["roleRef"] = copy
          end
        when "rbac/Subject"
          if result["apiGroup"].to_s.empty?
            case result["kind"].to_s
            when "ServiceAccount" then result["apiGroup"] = ""
            when "User", "Group" then result["apiGroup"] = RBAC_GROUP
            end
          end
        end
      end

      # pkg/util/parsers.ParseImageName treats a reference with no tag as
      # :latest, so both an untagged image and an explicit :latest pull Always.
      def image_pull_policy(image)
        reference = image.split("@", 2).first.to_s.split("/", 2).last.to_s
        tag = reference.include?(":") ? reference.split(":", 2).last.to_s : ""
        tag.empty? || tag == "latest" ? "Always" : "IfNotPresent"
      end

      # SetDefaults_Deployment and SetDefaults_DaemonSet share this shape: an
      # absent type is RollingUpdate, and a RollingUpdate type always carries a
      # fully populated rollingUpdate block.
      def rolling_update_strategy(strategy, defaults)
        strategy = strategy.is_a?(Hash) ? deep_copy(strategy) : {}
        strategy["type"] = "RollingUpdate" if strategy["type"].to_s.empty?
        return strategy unless strategy["type"] == "RollingUpdate"

        rolling = strategy["rollingUpdate"].is_a?(Hash) ? deep_copy(strategy["rollingUpdate"]) : {}
        defaults.each { |field, value| rolling[field] = value if rolling[field].nil? }
        strategy["rollingUpdate"] = rolling
        strategy
      end

      # SetDefaults_StatefulSet differs from the other two: the rollingUpdate
      # block is materialised only when the type itself was defaulted, so an
      # explicit `type: RollingUpdate` with no block keeps none.
      def stateful_set_update_strategy(strategy)
        strategy = strategy.is_a?(Hash) ? deep_copy(strategy) : {}
        if strategy["type"].to_s.empty?
          strategy["type"] = "RollingUpdate"
          strategy["rollingUpdate"] = {} unless strategy["rollingUpdate"].is_a?(Hash)
        end
        if strategy["type"] == "RollingUpdate" && strategy["rollingUpdate"].is_a?(Hash)
          rolling = deep_copy(strategy["rollingUpdate"])
          rolling["partition"] = 0 if rolling["partition"].nil?
          strategy["rollingUpdate"] = rolling
        end
        strategy
      end

      def default_pod_level_resources(pod, spec)
        resources = spec["resources"]
        requests = resources["requests"].is_a?(Hash) ? resources["requests"] : nil
        limits = resources["limits"].is_a?(Hash) ? resources["limits"] : nil
        return if (limits.nil? || limits.empty?) && (requests.nil? || requests.empty?)

        helpers = Rubernetes::ResourceHelpers
        # defaultHugePagePodLimits: a hugepage limit set only on containers
        # becomes the pod's, unless the pod requests that hugepage size.
        pod_limits = limits ? limits.dup : {}
        helpers.aggregate_container_limits(pod).each do |name, quantity|
          next unless name.start_with?(helpers::HUGE_PAGES_PREFIX)
          next if requests&.key?(name) || pod_limits.key?(name)

          pod_limits[name] = quantity.to_s
        end
        resources["limits"] = pod_limits unless pod_limits.empty?
        return if pod_limits.empty?

        # defaultPodRequests: overcommittable requests default to the
        # containers' aggregate, anything else to the pod-level limit.
        pod_requests = requests ? requests.dup : {}
        helpers.aggregate_container_requests(pod).each do |name, quantity|
          next unless helpers.supported_pod_level_resource?(name) && !name.start_with?(helpers::HUGE_PAGES_PREFIX)

          pod_requests[name] = quantity.to_s unless pod_requests.key?(name)
        end
        pod_limits.each do |name, value|
          pod_requests[name] = value if !pod_requests.key?(name) && helpers.supported_pod_level_resource?(name)
        end
        resources["requests"] = pod_requests unless pod_requests.empty?
      end

      # SetDefaults_LimitRangeItem: container limits cascade max -> default ->
      # defaultRequest, with min filling any request the default did not.
      def apply_limit_range_item_defaults(result)
        return unless result["type"].to_s == "Container"

        limits = result["default"].is_a?(Hash) ? deep_copy(result["default"]) : {}
        requests = result["defaultRequest"].is_a?(Hash) ? deep_copy(result["defaultRequest"]) : {}
        maximum = result["max"].is_a?(Hash) ? result["max"] : {}
        minimum = result["min"].is_a?(Hash) ? result["min"] : {}
        maximum.each { |name, value| limits[name] = value unless limits.key?(name) }
        limits.each { |name, value| requests[name] = value unless requests.key?(name) }
        minimum.each { |name, value| requests[name] = value unless requests.key?(name) }
        result["default"] = limits
        result["defaultRequest"] = requests
      end

      # SetDefaults_Namespace stamps the namespace's own name as a label so
      # namespaceSelector can address a namespace without the author having to
      # label it first.  The registry's Canonicalize repeats this for
      # generateName, where the name is not known until the name is assigned.
      def apply_namespace_name_label(result)
        name = result.dig("metadata", "name").to_s
        return if name.empty?

        labels = result.dig("metadata", "labels")
        return if labels.is_a?(Hash) && labels["kubernetes.io/metadata.name"] == name

        metadata = result["metadata"].is_a?(Hash) ? deep_copy(result["metadata"]) : {}
        metadata["labels"] = (labels.is_a?(Hash) ? deep_copy(labels) : {})
          .merge("kubernetes.io/metadata.name" => name)
        result["metadata"] = metadata
      end

      # SetDefaults_ReplicationController: the template's labels stand in for
      # both an absent selector and absent object labels.
      def apply_replication_controller_defaults(result)
        labels = result.dig("spec", "template", "metadata", "labels")
        return unless labels.is_a?(Hash) && !labels.empty?

        selector = result.dig("spec", "selector")
        if !selector.is_a?(Hash) || selector.empty?
          spec = deep_copy(result["spec"])
          spec["selector"] = deep_copy(labels)
          result["spec"] = spec
        end
        existing = result.dig("metadata", "labels")
        return if existing.is_a?(Hash) && !existing.empty?

        metadata = result["metadata"].is_a?(Hash) ? deep_copy(result["metadata"]) : {}
        metadata["labels"] = deep_copy(labels)
        result["metadata"] = metadata
      end

      # SetDefaults_Job plus the batch strategy's generateSelectorIfNeeded.
      # Upstream aliases obj.Labels to the very map the generator then adds the
      # controller-uid labels to, so a Job that supplied template labels ends up
      # carrying the generated ones on the object as well.
      def apply_job_defaults(result)
        spec = result["spec"]
        return unless spec.is_a?(Hash)

        spec = deep_copy(spec)
        supplied_labels = spec.dig("template", "metadata", "labels")
        alias_labels = supplied_labels.is_a?(Hash)
        existing = result.dig("metadata", "labels")
        alias_labels &&= !(existing.is_a?(Hash) && !existing.empty?)

        if spec["completions"].nil? && spec["parallelism"].nil?
          spec["completions"] = 1
          spec["parallelism"] = 1
        end
        spec["parallelism"] = 1 if spec["parallelism"].nil?
        if spec["backoffLimit"].nil?
          spec["backoffLimit"] = spec["backoffLimitPerIndex"].nil? ? 6 : 2_147_483_647
        end
        spec["completionMode"] = "NonIndexed" if spec["completionMode"].nil?
        spec["manualSelector"] = false if spec["manualSelector"].nil?
        spec["suspend"] = false if spec["suspend"].nil?
        if spec["podReplacementPolicy"].nil?
          spec["podReplacementPolicy"] = spec["podFailurePolicy"].nil? ? "TerminatingOrFailed" : "Failed"
        end

        uid = result.dig("metadata", "uid").to_s
        # generateSelectorIfNeeded (pkg/registry/batch/job/strategy.go): the
        # generated selector and its labels are added ONLY when the user has not
        # taken over the selector with manualSelector.
        if !uid.empty? && !spec.key?("selector") && spec["manualSelector"] != true
          spec["selector"] = {"matchLabels" => {"batch.kubernetes.io/controller-uid" => uid}}
          template = spec["template"].is_a?(Hash) ? deep_copy(spec["template"]) : {}
          template["metadata"] = template["metadata"].is_a?(Hash) ? deep_copy(template["metadata"]) : {}
          labels = template["metadata"]["labels"].is_a?(Hash) ? deep_copy(template["metadata"]["labels"]) : {}
          labels["batch.kubernetes.io/controller-uid"] = uid
          labels["batch.kubernetes.io/job-name"] = result.dig("metadata", "name")
          labels["controller-uid"] = uid
          labels["job-name"] = result.dig("metadata", "name")
          template["metadata"]["labels"] = labels
          spec["template"] = template
        end
        result["spec"] = spec

        return unless alias_labels

        metadata = result["metadata"].is_a?(Hash) ? deep_copy(result["metadata"]) : {}
        metadata["labels"] = deep_copy(spec.dig("template", "metadata", "labels"))
        result["metadata"] = metadata
      end

      # SetDefaults_Pod: the defaults that materialise only on a Pod, never on
      # a bare PodSpec carried inside a workload template.
      def apply_pod_defaults(result)
        spec = result["spec"].is_a?(Hash) ? deep_copy(result["spec"]) : nil
        return unless spec

        spec["enableServiceLinks"] = true unless spec.key?("enableServiceLinks")
        spec["preemptionPolicy"] ||= "PreemptLowerPriority"
        spec["priority"] = 0 unless spec.key?("priority")
        spec["serviceAccount"] ||= "default"
        spec["serviceAccountName"] ||= "default"
        tolerations = Array(spec["tolerations"]).map { |entry| deep_copy(entry) }
        %w[node.kubernetes.io/not-ready node.kubernetes.io/unreachable].each do |key|
          next if tolerations.any? do |entry|
            entry.is_a?(Hash) && entry["key"] == key && entry["effect"] == "NoExecute"
          end

          tolerations << {"effect" => "NoExecute", "key" => key, "operator" => "Exists",
                          "tolerationSeconds" => 300}
        end
        spec["tolerations"] = tolerations

        # A container limit without a matching request defaults the request to
        # the limit.  This is deliberately a Pod-only rule upstream, so a
        # Deployment's pod template keeps the author's sparse resources.
        %w[containers initContainers].each do |field|
          next unless spec[field].is_a?(Array)

          spec[field].each do |container|
            next unless container.is_a?(Hash) && container["resources"].is_a?(Hash)

            limits = container["resources"]["limits"]
            next unless limits.is_a?(Hash) && !limits.empty?

            requests = container["resources"]["requests"].is_a?(Hash) ? container["resources"]["requests"] : {}
            limits.each { |name, value| requests[name] = value unless requests.key?(name) }
            container["resources"]["requests"] = requests
          end
        end

        # SetDefaults_Pod (PodLevelResources): after the container defaults,
        # defaultHugePagePodLimits then defaultPodRequests fill a partly
        # specified spec.resources.
        default_pod_level_resources({"spec" => spec}, spec) if spec["resources"].is_a?(Hash)

        # defaultHostNetworkPorts: on the host network every container port is
        # also a host port, and the kubelet's port bookkeeping reads hostPort.
        if spec["hostNetwork"] == true
          %w[containers initContainers].each do |field|
            next unless spec[field].is_a?(Array)

            spec[field].each do |container|
              next unless container.is_a?(Hash) && container["ports"].is_a?(Array)

              container["ports"].each do |port|
                next unless port.is_a?(Hash)

                port["hostPort"] = port["containerPort"] if port["hostPort"].to_i.zero? && port["containerPort"]
              end
            end
          end
        end

        result["spec"] = spec
        # The ServiceAccount token projection is injected by the ServiceAccount
        # ADMISSION plugin, which is the only place that can read the
        # ServiceAccount and honour its automountServiceAccountToken.  Injecting
        # it here ran before admission and left the plugin's early-out ("a token
        # volume is already present") to skip the decision entirely, so a
        # ServiceAccount with automountServiceAccountToken: false still got one.
      end

      # pkg/apis/resource/{v1,v1beta2,v1beta1}/defaults.go.
      RESOURCE_REQUEST_KINDS = %w[ExactDeviceRequest DeviceSubRequest].freeze

      def apply_resource_scheme_defaults(result, kind)
        case kind
        when *RESOURCE_REQUEST_KINDS, "DeviceRequest"
          # v1beta1's flat DeviceRequest is defaulted only when it names a
          # class (a request with firstAvailable has none); v1 and v1beta2
          # DeviceRequest carry no allocationMode at all.
          return if kind == "DeviceRequest" && (!result.key?("deviceClassName") || result["deviceClassName"].to_s.empty?)

          result["allocationMode"] = "ExactCount" if result["allocationMode"].to_s.empty?
          result["count"] = 1 if result["allocationMode"] == "ExactCount" && result["count"].to_i.zero?
        when "DeviceTaint"
          result["timeAdded"] = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ") if result["timeAdded"].nil?
        when "Device", "BasicDevice"
          mappings = result["nodeAllocatableResourceMappings"]
          if mappings.is_a?(Hash)
            result["nodeAllocatableResourceMappings"] = mappings.to_h do |name, mapping|
              mapping = deep_copy(mapping)
              mapping["allocationMultiplier"] = "1" if mapping.is_a?(Hash) && mapping["allocationMultiplier"].nil?
              [name, mapping]
            end
          end
        end
      end

      # pkg/apis/autoscaling/v2/defaults.go (v1 defaults only minReplicas).
      HPA_SCALE_UP_RULES = {"stabilizationWindowSeconds" => 0, "selectPolicy" => "Max",
                            "policies" => [{"type" => "Pods", "value" => 4, "periodSeconds" => 15},
                                           {"type" => "Percent", "value" => 100, "periodSeconds" => 15}]}.freeze
      HPA_SCALE_DOWN_RULES = {"selectPolicy" => "Max", "policies" => [{"type" => "Percent", "value" => 100, "periodSeconds" => 15}]}.freeze

      def apply_hpa_defaults(result, version)
        spec = result["spec"]
        return unless spec.is_a?(Hash)

        spec = deep_copy(spec)
        spec["minReplicas"] = 1 if spec["minReplicas"].nil?
        if version.to_s.start_with?("v2")
          if spec["metrics"].nil? || spec["metrics"].empty?
            spec["metrics"] = [{"type" => "Resource",
                                "resource" => {"name" => "cpu", "target" => {"type" => "Utilization", "averageUtilization" => 80}}}]
          end
          if spec["behavior"].is_a?(Hash)
            behavior = spec["behavior"]
            behavior["scaleUp"] = hpa_scaling_rules(behavior["scaleUp"], HPA_SCALE_UP_RULES)
            behavior["scaleDown"] = hpa_scaling_rules(behavior["scaleDown"], HPA_SCALE_DOWN_RULES)
          end
        end
        result["spec"] = spec
      end

      # copyHPAScalingRules over the defaults.
      def hpa_scaling_rules(from, defaults)
        rules = deep_copy(defaults)
        return rules unless from.is_a?(Hash)

        %w[selectPolicy stabilizationWindowSeconds policies tolerance].each do |key|
          rules[key] = deep_copy(from[key]) unless from[key].nil?
        end
        rules
      end

      # pkg/apis/{autoscaling,resource}/<version>/defaults.go: registered by
      # the apiserver's scheme, not by the k8s.io/api types, so they apply
      # with the other admission-path defaults.
      def apply_group_defaults(result, object_definition)
        if object_definition.kind == "HorizontalPodAutoscaler" && object_definition.group.to_s == "autoscaling"
          apply_hpa_defaults(result, object_definition.version)
        elsif object_definition.group.to_s.split(".").first == "resource"
          apply_resource_scheme_defaults(result, object_definition.kind)
        end
      end

      def apply_kubernetes_scheme_defaults(result, object_definition)
        case [object_definition.group, object_definition.kind]
        when ["apiextensions.k8s.io", "CustomResourceDefinition"]
          spec = result["spec"].is_a?(Hash) ? deep_copy(result["spec"]) : result["spec"]
          status = result["status"].is_a?(Hash) ? deep_copy(result["status"]) : result["status"]
          if spec.is_a?(Hash) && status.is_a?(Hash)
            stored_versions = status["storedVersions"]
            versions = spec["versions"]
            if (!stored_versions.is_a?(Array) || stored_versions.empty?) && versions.is_a?(Array)
              storage_version = versions.find do |version|
                version.is_a?(Hash) && version["storage"] == true
              end
              status["storedVersions"] = [storage_version["name"]] if storage_version && !storage_version["name"].nil?
            end
            result["spec"] = spec
            result["status"] = status
          end
        when [object_definition.group, "CustomResourceDefinitionSpec"]
          names = result["names"].is_a?(Hash) ? deep_copy(result["names"]) : result["names"]
          if names.is_a?(Hash)
            kind = names["kind"].to_s
            names["singular"] = kind.downcase if names["singular"].to_s.empty?
            names["listKind"] = "#{kind}List" if names["listKind"].to_s.empty? && !kind.empty?
            result["names"] = names
          end
          result["conversion"] = {"strategy" => "None"} unless result.key?("conversion") && !result["conversion"].nil?
        end
      end

      def apply_field(value, field, path, mode, kubernetes_admission_defaults, old = nil)
        return nil if value.nil?

        if field.array?
          raise DefaultingError, "expected an array at #{display_path(path)}, got #{value.class}" unless value.is_a?(Array)

          old = nil unless old.is_a?(Array)
          return value.each_with_index.map do |item, index|
            prior = old && old[index]
            next prior if !prior.nil? && prior.frozen? && prior == item

            apply_item(item, field.items, path, mode, kubernetes_admission_defaults, prior)
          end
        end

        nested = nested_definition(field)
        return apply_object_hash(value, nested, path, mode, kubernetes_admission_defaults, old) if nested && value.respond_to?(:each_pair)
        if value.respond_to?(:each_pair) && field.additional_properties && field.additional_properties != true
          return value.each_pair.to_h do |key, item|
            [
              deep_copy(key),
              apply_item(
                item,
                field.additional_properties,
                path + [key.to_s],
                mode,
                kubernetes_admission_defaults
              )
            ]
          end
        end
        return canonical_quantity(value) if quantity_field?(field)

        deep_copy(value)
      end

      QUANTITY_SCHEMA = "io.k8s.apimachinery.pkg.api.resource.Quantity"

      def quantity_field?(field)
        metadata = field.respond_to?(:metadata) ? field.metadata : nil
        metadata.is_a?(Hash) && (metadata[:schema_reference] || metadata["schema_reference"]) == QUANTITY_SCHEMA
      end

      # resource.Quantity.UnmarshalJSON + MarshalJSON: every built-in
      # object stores a quantity in its canonical form ("1000m" -> "1",
      # 1 -> "1").  Keeping the client's spelling made the stored object
      # differ from kube-apiserver's and every string comparison of two
      # equal quantities (QoS, resize, diff) fail.  An unparsable value is
      # left for validation to report.
      def canonical_quantity(value)
        return deep_copy(value) unless value.is_a?(String) || value.is_a?(Numeric)

        Quantity.from_json(value).to_s
      rescue Quantity::ParseError
        deep_copy(value)
      end

      def apply_item(value, item, path, mode, kubernetes_admission_defaults, old = nil)
        return nil if value.nil?
        return apply_field(value, item, path, mode, kubernetes_admission_defaults, old) if item.is_a?(Field)
        if item.is_a?(Definition) && value.respond_to?(:each_pair)
          return apply_object_hash(value, item, path, mode, kubernetes_admission_defaults, old)
        end
        if item.is_a?(Reference) && value.respond_to?(:each_pair)
          return apply_object_hash(value, item.resolve, path, mode, kubernetes_admission_defaults, old)
        end

        deep_copy(value)
      end

      def default_value(field)
        value = field.default_value
        value = value.call if value.respond_to?(:call)
        deep_copy(value)
      end

      def field_for_key(object_definition, key)
        name = key.to_s
        object_definition.fields[name] || object_definition.fields.values.find do |field|
          field.json_name == name || field.ruby_name == name
        end
      end

      def nested_definition(field)
        return field.type if field.type.is_a?(Definition)
        return field.type.resolve if field.type.is_a?(Reference)
        return nil unless field.object? && !field.properties.empty?

        Definition.new(
          name: "#{definition.kind}#{field.name.capitalize}",
          group: definition.group,
          version: definition.version,
          kind: "#{definition.kind}#{field.name.capitalize}",
          resource: "#{definition.resource}-#{field.name}",
          scope: definition.scope,
          fields: field.properties,
          preserve_unknown_fields: field.preserve_unknown_fields
        )
      end

      def path_for(path, key)
        (path + [key]).map { |item| item.to_s }.join(".").then { |item| item.empty? ? "$" : item }
      end

      def display_path(path)
        path_for(path, nil).sub(/\.$/, "")
      end

      def deep_copy(value)
        case value
        when ValueObject
          value.to_h
        when Hash
          value.each_with_object({}) { |(key, item), result| result[deep_copy(key)] = deep_copy(item) }
        when Array
          value.map { |item| deep_copy(item) }
        else
          value.dup
        end
      rescue TypeError
        value
      end
    end
  end
end
