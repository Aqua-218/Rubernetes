# frozen_string_literal: true

require_relative "kubernetes_validator"
require_relative "declarative_resource_coverage"
require_relative "declarative_resource_preparation"

module Rubernetes
  module Schema
    # Compares generated and handwritten findings for strategies whose
    # migration annotations have been mapped. Only CoveredByDeclarative
    # handwritten findings participate.
    module DeclarativeValidation
      RUNTIME_CLASS = "io.k8s.api.node.v1.RuntimeClass"
      STORAGE_CLASS = "io.k8s.api.storage.v1.StorageClass"
      ENDPOINT_SLICE = "io.k8s.api.discovery.v1.EndpointSlice"
      INGRESS_CLASS = "io.k8s.api.networking.v1.IngressClass"
      NETWORK_POLICY = "io.k8s.api.networking.v1.NetworkPolicy"
      VOLUME_ATTACHMENT = "io.k8s.api.storage.v1.VolumeAttachment"
      CRON_JOB = "io.k8s.api.batch.v1.CronJob"
      ADMISSION_BINDING = "io.k8s.api.admissionregistration.v1.ValidatingAdmissionPolicyBinding"
      HPA_TYPES = %w[io.k8s.api.autoscaling.v1.HorizontalPodAutoscaler io.k8s.api.autoscaling.v2.HorizontalPodAutoscaler].freeze
      SCALE = "io.k8s.api.autoscaling.v1.Scale"
      REPLICATION_CONTROLLER = "io.k8s.api.core.v1.ReplicationController"
      CSR = "io.k8s.api.certificates.v1.CertificateSigningRequest"
      PRIORITY_LEVEL = "io.k8s.api.flowcontrol.v1.PriorityLevelConfiguration"
      RESOURCE_SCHEMAS = %w[v1 v1beta1 v1beta2].flat_map do |version|
        %w[DeviceClass ResourceClaim ResourceSlice].map { |kind| "io.k8s.api.resource.#{version}.#{kind}" }
      end.freeze
      CSR_SUBRESOURCES = %w[approval status].freeze
      CLAIM_SUBRESOURCES = %w[status].freeze
      RBAC_TYPES = %w[Role RoleBinding ClusterRole ClusterRoleBinding].map { |kind| "io.k8s.api.rbac.v1.#{kind}" }.freeze
      IP_ADDRESSES = %w[io.k8s.api.networking.v1.IPAddress io.k8s.api.networking.v1beta1.IPAddress].freeze
      SHADOWED_SCHEMAS = [RUNTIME_CLASS, STORAGE_CLASS, ENDPOINT_SLICE, INGRESS_CLASS, NETWORK_POLICY, VOLUME_ATTACHMENT,
                          CRON_JOB, ADMISSION_BINDING, SCALE, REPLICATION_CONTROLLER, CSR, PRIORITY_LEVEL,
                          *RESOURCE_SCHEMAS, *IP_ADDRESSES, *RBAC_TYPES, *HPA_TYPES].freeze

      module_function

      def shadowed?(schema, subresource)
        return SHADOWED_SCHEMAS.include?(schema) if subresource.to_s.empty?
        return CSR_SUBRESOURCES.include?(subresource) if schema == CSR

        RESOURCE_SCHEMAS.include?(schema) && schema.end_with?(".ResourceClaim") && CLAIM_SUBRESOURCES.include?(subresource)
      end

      def mismatches(schema, object, old, operation, options: [], subresource: nil)
        return runtime_class_mismatches(object, old, operation) if schema == RUNTIME_CLASS

        if RESOURCE_SCHEMAS.include?(schema)
          expected = DeclarativeResourceCoverage.new(schema, object, old).errors(schema.split(".").last, operation, subresource)
          return compare_identities(schema, expected, object, old, operation, options)
        end
        if schema == CSR
          conditions = csr_conflict?(object) && !csr_conflict?(old) ? [[:invalid, %w[status conditions], "zeroOrOneOf"]] : []
          return compare_identities(schema, conditions, object, old, operation, options)
        end

        handwritten = covered_errors(schema, object, old, operation, options)
        origin = "format=k8s-long-name-caseless" if schema == VOLUME_ATTACHMENT
        origin = "minimum" if [SCALE, REPLICATION_CONTROLLER].include?(schema) || HPA_TYPES.include?(schema)
        compare(schema, handwritten, object, old, operation, options: options, invalid_origin: origin)
      end

      def csr_conflict?(object)
        conditions = KubernetesValidator.value_at_path(object, %w[status conditions])
        types = Array(conditions).map { |condition| KubernetesValidator.fetch(condition, "type") }
        types.include?("Approved") && types.include?("Denied")
      end

      def covered_errors(schema, object, old, operation, options)
        case schema
        when STORAGE_CLASS
          KubernetesValidator.storage_class_errors(object, operation, old).select do |issue|
            (issue.code == :required && issue.path == ["provisioner"]) || issue.message == "field is immutable"
          end
        when ENDPOINT_SLICE
          KubernetesValidator.endpoint_slice_errors(object, operation, old)
        when *IP_ADDRESSES
          KubernetesValidator.ip_address_errors(object, old, operation).select do |issue|
            issue.code == :required || issue.message == "field is immutable"
          end
        when INGRESS_CLASS
          KubernetesValidator.ingress_class_errors(object, old, operation).select do |issue|
            issue.code == :required && issue.path[0, 2] == %w[spec parameters]
          end
        when NETWORK_POLICY
          KubernetesValidator.network_policy_errors(object, operation, old).select do |issue|
            issue.code == :required && issue.path.last(2) == %w[ipBlock cidr]
          end
        when VOLUME_ATTACHMENT
          KubernetesValidator.volume_attachment_errors(object, old, operation).select do |issue|
            issue.path == %w[spec attacher] || issue.message == "field is immutable"
          end
        when CRON_JOB
          schedule = KubernetesValidator.value_at_path(object, %w[spec schedule])
          schedule.to_s.empty? ? [KubernetesValidator.issue(%w[spec schedule], :required, "")] : []
        when ADMISSION_BINDING
          object = object.merge("spec" => {}) unless object["spec"].is_a?(Hash)
          KubernetesValidator.policy_binding_errors(object).select do |issue|
            issue.code == :required && [%w[spec policyName], %w[spec validationActions]].include?(issue.path)
          end
        when *RBAC_TYPES
          covered_rbac_errors(schema.split(".").last, object)
        when *HPA_TYPES
          issues = []
          spec = KubernetesValidator.fetch(object, "spec")
          KubernetesValidator.hpa_replica_bound_errors(spec, issues, options)
          issues.reject { |issue| issue.message.include?("`minReplicas`") }
        when SCALE
          KubernetesValidator.scale_errors(object)
        when REPLICATION_CONTROLLER
          name = KubernetesValidator.value_at_path(object, %w[metadata name]).to_s
          issues = KubernetesValidator.replication_controller_count_errors(object)
          issues.concat(KubernetesValidator.invalid_messages(%w[metadata name], KubernetesValidator.dns1123_subdomain_messages(name))) unless name.empty?
          issues
        when PRIORITY_LEVEL
          priority_level_covered_errors(object)
        end
      end

      def priority_level_covered_errors(object)
        spec = KubernetesValidator.fetch(object, "spec")
        limited = KubernetesValidator.fetch(spec, "limited")
        exempt = KubernetesValidator.fetch(spec, "exempt")
        case KubernetesValidator.fetch(spec, "type")
        when "Exempt"
          limited.nil? ? [] : [KubernetesValidator.issue(%w[spec limited], :forbidden, "")]
        when "Limited"
          issues = []
          issues << KubernetesValidator.issue(%w[spec exempt], :forbidden, "") unless exempt.nil?
          return issues << KubernetesValidator.issue(%w[spec limited], :required, "") if limited.nil?

          response = KubernetesValidator.fetch(limited, "limitResponse")
          queuing = KubernetesValidator.fetch(response, "queuing")
          type = KubernetesValidator.fetch(response, "type")
          path = %w[spec limited limitResponse queuing]
          issues << KubernetesValidator.issue(path, :required, "") if type == "Queue" && queuing.nil?
          issues << KubernetesValidator.issue(path, :forbidden, "") if type == "Reject" && !queuing.nil?
          issues
        else []
        end
      end

      def covered_rbac_errors(kind, object)
        issues = KubernetesValidator.rbac_errors(object, kind)
        issues.concat(KubernetesValidator.role_ref_errors(object, kind)) if kind.end_with?("Binding")
        issues.select { |issue| issue.code == :required && %w[verbs name].include?(issue.path.last) }
      end

      def runtime_class_mismatches(object, old, operation)
        return 0 unless object["handler"].nil? || object["handler"].is_a?(String)

        compare(RUNTIME_CLASS, KubernetesValidator.runtime_class_handler_errors(object, old, operation),
                object, old, operation, invalid_origin: "format=k8s-short-name")
      end

      def compare(schema, handwritten, object, old, operation, options: [], invalid_origin: nil)
        expected = handwritten.map do |issue|
          origin = if issue.message == "field is immutable"
                     "immutable"
                   elsif schema == REPLICATION_CONTROLLER && issue.path == %w[metadata name]
                     "format=k8s-long-name"
                   elsif issue.code == :too_many
                     "maxItems"
                   elsif issue.code == :too_long
                     "maxLength"
                   elsif issue.code == :invalid
                     invalid_origin
                   end
          [issue.code, issue.path, origin]
        end
        compare_identities(schema, expected, object, old, operation, options)
      end

      def compare_identities(schema, expected, object, old, operation, options)
        expected = expected.uniq
        declared = DeclarativeRules.new(operation: operation, options: options).evaluate(schema, object, old).map(&:identity)
        matches = (expected & declared).reject { |code, _, origin| code == :invalid && origin.nil? }
        (expected - matches).length + (declared - matches).length
      end
    end
  end
end
