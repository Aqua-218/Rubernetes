# frozen_string_literal: true

require_relative "formats"

module Rubernetes
  module Schema
    # What each strategy reports when the request omits the object's root
    # section (usually `spec`): upstream validates the zero-value Go struct,
    # which OpenAPI requiredness cannot express.
    module KubernetesValidator
      module_function

      RESTART_POLICY_REQUIRED = "valid values: \"OnFailure\", \"Never\""
      SELECTOR_LABELS_MISMATCH = "`selector` does not match template `labels`"
      # DaemonSet's zero-value strategy path validates the template
      # directly and does not emit selector.Required when spec itself is
      # absent.  Other controller strategies do.
      ZERO_VALUE_TEMPLATE_ISSUES = [
        [%w[spec template metadata labels], :invalid, SELECTOR_LABELS_MISMATCH],
        [%w[spec template spec containers], :required, ""]
      ].freeze
      ZERO_VALUE_CONTROLLER_ISSUES = [[%w[spec selector], :required, ""], *ZERO_VALUE_TEMPLATE_ISSUES].freeze

      # kind => [path, code, message] of every issue a missing `spec` yields,
      # in upstream's order.  A kind that is absent here either reports
      # nothing or depends on the rest of the object (missing_root_errors):
      #   Event         Legacy core/v1 Events carry their namespace under
      #                 metadata.namespace and may omit eventTime.  The
      #                 generated schema already validates the wire fields;
      #                 applying the events.k8s.io required-field rules here
      #                 rejected valid controller-manager Events before they
      #                 could be persisted.
      #   StorageClass  storage_class_errors reports the missing provisioner.
      ZERO_VALUE_SPEC_ISSUES = {
        "ValidatingAdmissionPolicyBinding" => [
          [%w[spec policyName], :required, ""],
          [%w[spec validationActions], :required, "at least one validation action is required"]
        ],
        "DaemonSet" => ZERO_VALUE_TEMPLATE_ISSUES,
        "Deployment" => ZERO_VALUE_CONTROLLER_ISSUES,
        "ReplicaSet" => ZERO_VALUE_CONTROLLER_ISSUES,
        "StatefulSet" => ZERO_VALUE_CONTROLLER_ISSUES,
        "ReplicationController" => [[%w[spec selector], :required, ""], [%w[spec template], :required, ""]],
        "HorizontalPodAutoscaler" => [
          [%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`"],
          [%w[spec maxReplicas], :required, "must be set and greater than 0"],
          [%w[spec scaleTargetRef apiVersion], :invalid, "apiVersion must specify API group"],
          [%w[spec scaleTargetRef kind], :required, ""],
          [%w[spec scaleTargetRef name], :required, ""]
        ],
        "CronJob" => [
          [%w[spec jobTemplate spec template spec containers], :required, ""],
          [%w[spec jobTemplate spec template spec restartPolicy], :required, RESTART_POLICY_REQUIRED],
          [%w[spec schedule], :required, ""]
        ],
        "Job" => [
          [%w[spec template spec containers], :required, ""],
          [%w[spec template spec restartPolicy], :required, RESTART_POLICY_REQUIRED]
        ],
        "CertificateSigningRequest" => [
          [%w[spec request], :invalid, "PEM block type must be CERTIFICATE REQUEST"],
          [%w[spec signerName], :required, ""],
          [%w[spec usages], :required, ""]
        ],
        "ClusterTrustBundle" => [[%w[spec trustBundle], :invalid, "at least one trust anchor must be provided"]],
        "LeaseCandidate" => [
          [%w[spec binaryVersion], :required, ""], [%w[spec leaseName], :required, ""], [%w[spec strategy], :required, ""]
        ],
        "PersistentVolume" => [
          [%w[spec], :required, "must specify a volume type"],
          [%w[spec accessModes], :required, ""],
          [%w[spec capacity], :required, ""],
          [%w[spec capacity], :unsupported, "supported values: \"storage\""]
        ],
        "Pod" => [[%w[spec containers], :required, ""]],
        "PriorityLevelConfiguration" => [[%w[spec type], :unsupported, "supported values: \"Exempt\", \"Limited\""]],
        "FlowSchema" => [[%w[spec priorityLevelConfiguration name], :required, "must reference a priority level"]],
        "Ingress" => [[%w[spec], :invalid, "either `defaultBackend` or `rules` must be specified"]],
        "IngressClass" => [[%w[spec controller], :required, ""]],
        "ServiceCIDR" => [[%w[spec cidrs], :required, "at least one CIDR required"]],
        "VolumeAttachment" => [
          [%w[spec attacher], :required, ""],
          [%w[spec nodeName], :invalid, DNS1123_SUBDOMAIN_MSG],
          [%w[spec source], :required, "must specify exactly one of inlineVolumeSpec and persistentVolumeName"]
        ],
        "StorageVersionMigration" => [[%w[spec resource resource], :required, "resource is required to be set"]],
        "APIService" => [
          [%w[spec group], :required, "only v1 may have an empty group and it better be legacy kube"],
          [%w[spec groupPriorityMinimum], :invalid, "must be positive and less than 20000"],
          [%w[spec version], :invalid, DNS1035_LABEL_MSG],
          [%w[spec versionPriority], :invalid, "must be positive and less than 1000"]
        ]
      }.freeze

      # Strategy validation still runs against a zero-value API struct when
      # the fixture omits an optional root section.  OpenAPI requiredness does
      # not encode those semantic checks, so model the reusable zero-value
      # families here.  These paths/messages are taken from the v1.36.2
      # Validate* functions and are deliberately grouped by rule family.
      def missing_root_errors(root, kind)
        return [issue(%w[data], :required, "data is mandatory")] if kind == "ControllerRevision" && !root.key?("data") && !root.key?("revision")
        return [] if root.key?("spec")

        fixed = ZERO_VALUE_SPEC_ISSUES[kind]
        return fixed.map { |path, code, message| issue(path, code, message) } if fixed

        specless_kind_errors(root, kind)
      end

      # The kinds whose rules read fields outside `spec`.
      def specless_kind_errors(root, kind)
        case kind
        when "Service"
          external_name_service?(fetch(root, "spec") || {}) ? [] : [issue(%w[spec ports], :required, "")]
        when "ResourceSlice" then resource_slice_missing_errors
        when "PodTemplate"
          root.key?("template") ? [] : [issue(%w[template spec containers], :required, "")]
        when "ClusterRoleBinding", "RoleBinding" then role_ref_errors(root, kind)
        when "VolumeAttributesClass" then volume_attributes_class_errors(root)
        else []
        end
      end

      def volume_attributes_class_errors(root)
        issues = []
        issues << issue(%w[driverName], :required, "") if blank?(fetch(root, "driverName"))
        parameters = fetch(root, "parameters")
        unless parameters.is_a?(Hash) && !parameters.empty?
          issues << issue(%w[parameters], :required,
                          "must contain at least one key/value pair")
        end
        issues
      end

      def resource_slice_missing_errors
        [
          issue(%w[spec], :required, "exactly one of `nodeName`, `nodeSelector`, `allNodes`, `perDeviceNodeSelection` is required"),
          issue(%w[spec driver], :required, ""),
          issue(%w[spec pool name], :required, ""),
          issue(%w[spec pool resourceSliceCount], :invalid, "must be greater than zero")
        ]
      end

      private_class_method :specless_kind_errors, :volume_attributes_class_errors
    end
  end
end
