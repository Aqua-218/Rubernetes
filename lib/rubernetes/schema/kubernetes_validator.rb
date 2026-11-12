# frozen_string_literal: true

require "json"
require_relative "quantity"

module Rubernetes
  module Schema
    # Observable validation shared by the Kubernetes REST strategies.
    #
    # The generated OpenAPI definitions deliberately describe wire shape, not
    # the strategy layer.  Kubernetes v1.36.2 adds operation-sensitive object
    # metadata checks and a small set of cross-field invariants in the
    # generated validation packages.  This adapter keeps those checks in one
    # place so reusable schema references do not accidentally acquire resource
    # semantics.
    #
    # This file is the entry point: it decides which definitions are
    # validated and in which order each kind's rules run.  The rules live in
    # kubernetes_validator/, one file per API group or concern, all reopening
    # this module.
    module KubernetesValidator
      KUBERNETES_VERSION = "v1.36.2"

      # Request objects validated inside a REST Create handler rather than a
      # strategy (pkg/registry/**/rest.go, storage.go): their ObjectMeta is
      # not validated upstream, only the request-specific fields.
      HANDLER_REQUEST_KINDS = %w[
        TokenRequest SubjectAccessReview SelfSubjectAccessReview LocalSubjectAccessReview Scale Binding
      ].freeze
      IS_NEGATIVE_ERROR_MSG = "must be greater than or equal to 0"

      # These are the resource kinds with REST strategy validation in the
      # v1.36.2 built-in registry.  List and request/helper types are excluded
      # because they are not accepted by a resource strategy.
      VALIDATED_KINDS = %w[
        TokenRequest SubjectAccessReview SelfSubjectAccessReview LocalSubjectAccessReview Scale Binding
        APIService CertificateSigningRequest ClusterRole ClusterRoleBinding
        ClusterTrustBundle ConfigMap ControllerRevision CronJob CSIDriver
        CSINode CSIStorageCapacity DeviceClass DaemonSet Deployment EndpointSlice
        Endpoints Event FlowSchema HorizontalPodAutoscaler Ingress IngressClass
        IPAddress Job Lease LeaseCandidate LimitRange MutatingAdmissionPolicyBinding
        MutatingWebhookConfiguration Namespace NetworkPolicy Node PersistentVolume
        PersistentVolumeClaim Pod PodDisruptionBudget PodTemplate PriorityClass
        PriorityLevelConfiguration ReplicaSet ReplicationController ResourceQuota
        ResourceSlice Role RoleBinding RuntimeClass Secret Service ServiceAccount
        ServiceCIDR StatefulSet StorageClass StorageVersion
        StorageVersionMigration ValidatingAdmissionPolicyBinding
        ValidatingWebhookConfiguration VolumeAttachment VolumeAttributesClass
        Workload MutatingAdmissionPolicy ValidatingAdmissionPolicy
        CustomResourceDefinition PodCertificateRequest ResourceClaim
        ResourceClaimTemplate DeviceTaintRule PodGroup ResourcePoolStatusRequest
      ].freeze

      WEBHOOK_KINDS = %w[MutatingWebhookConfiguration ValidatingWebhookConfiguration].freeze

      module_function

      def errors(definition, value, operation: :create, old: nil, strategy_prepare: false, subresource: nil)
        # metav1.DeleteOptions carries no ObjectMeta; ValidateDeleteOptions
        # (apimachinery/pkg/apis/meta/v1/validation) runs in the delete handler.
        return delete_options_errors(plain_object(value)) if definition.kind == "DeleteOptions" && object_like?(value)
        return [] unless resource_definition?(definition)
        return [] unless object_like?(value)

        root = plain_object(value)
        kind = definition.kind
        issues = []
        issues.concat(metadata_errors(definition, root, kind, operation))
        issues.concat(cross_field_errors(root, kind, operation, old, strategy_prepare: strategy_prepare, definition: definition, subresource: subresource))
        issues
      end

      # Some upstream strategies deliberately validate a zero-value spec (or
      # return their request-context error before touching the spec) even
      # though the generated OpenAPI object marks the field as required.  The
      # REST strategy is the source of truth for create/update observations.
      def optional_spec_strategy?(kind)
        %w[CSIDriver CSINode DeviceClass ResourceClaim ResourceClaimTemplate].include?(kind)
      end

      # kube-apiserver always supplies RequestInfo to a strategy; no served
      # kind reports the missing-context InternalError on a real request.
      def internal_request_context_strategy?(_kind)
        false
      end

      def resource_definition?(definition)
        return false unless %w[apiVersion kind metadata].all? { |name| definition.fields.key?(name) }
        # Handler request kinds (TokenRequest, the access reviews, Scale,
        # Binding) are subresource or virtual bodies without a registry
        # resource of their own.
        return true if HANDLER_REQUEST_KINDS.include?(definition.kind)

        VALIDATED_KINDS.include?(definition.kind) && !registry_entry(definition).nil? &&
          registry_type_matches?(definition)
      end

      # Every strategy rule that is not ObjectMeta.  The steps run in the
      # order upstream appends to its field.ErrorList; that order is
      # observable (the Go oracle compares it), so a rule may not move to
      # another step.
      def cross_field_errors(root, kind, operation, old, strategy_prepare: false, definition: nil, subresource: nil)
        return handler_request_errors(root, kind) if HANDLER_REQUEST_KINDS.include?(kind)

        # The tree walkers below find Pod templates wherever an owner embeds
        # them.  A CRD's OpenAPI schemas are maps of property NAMES, not
        # objects: a schema for a Pod-shaped resource spells
        # `postStart.properties.{exec,httpGet,tcpSocket,sleep}`, which the
        # walkers read as a probe with four handlers, and a `restartPolicy`
        # property as a Job restart policy.  apiextensions validates those
        # schemas structurally only; Argo Workflows' CRDs were refused here.
        walk_root = schema_free_root(root, kind)
        walk_old = schema_free_root(old, kind)
        stateful_set_update = kind == "StatefulSet" && operation == :update

        issues = missing_root_errors(root, kind)
        issues << issue([], :internal, "could not find requestInfo in context") if internal_request_context_strategy?(kind)
        issues.concat(kind_errors_before_pod_template(root, kind, operation, old))
        issues.concat(pod_template_errors(root, walk_root, walk_old, kind, operation))
        # ValidateStatefulSetUpdate skips pod-template validation when the
        # retained old template is already invalid.  The zero-value semantic
        # fixture exercises that compatibility path; selector/template
        # metadata rules still run below.
        drop_stateful_set_template_issues!(issues) if stateful_set_update
        issues.concat(workload_template_errors(walk_root, kind, operation))
        issues.concat(pod_change_errors(root, walk_root, walk_old, kind, operation, old: old, subresource: subresource))
        issues.concat(kind_errors_after_pod_template(root, kind, operation, old, definition: definition, subresource: subresource))
        issues.concat(job_strategy_prepare_errors(root, operation)) if kind == "Job" && strategy_prepare
        repeat_single_pass_job_spec_issues!(issues) if kind == "Job" && operation == :update
        # StatefulSet update validation deliberately skips the retained pod
        # template.  Keep this as a final guard because helpers below the
        # strategy family can discover template fields after the main
        # compatibility branch has run.
        drop_stateful_set_template_issues!(issues) if stateful_set_update
        issues
      end

      # Kind rules upstream reports before it descends into a Pod template.
      def kind_errors_before_pod_template(root, kind, operation, old)
        issues = []
        issues.concat(webhook_errors(root, kind, operation)) if WEBHOOK_KINDS.include?(kind)
        issues.concat(policy_binding_errors(root)) if kind == "ValidatingAdmissionPolicyBinding"
        issues.concat(resource_slice_errors(root, operation)) if kind == "ResourceSlice"
        issues.concat(certificate_signing_request_errors(root, operation)) if kind == "CertificateSigningRequest"
        issues.concat(cluster_trust_bundle_errors(root, operation)) if kind == "ClusterTrustBundle"
        issues.concat(lease_candidate_errors(root)) if kind == "LeaseCandidate"
        issues.concat(node_errors(root, operation)) if kind == "Node"
        issues.concat(node_update_errors(root, old, operation)) if kind == "Node"
        issues.concat(persistent_volume_update_errors(root, old, operation)) if kind == "PersistentVolume"
        issues.concat(stateful_set_update_errors(root, old, operation)) if kind == "StatefulSet"
        issues.concat(job_completions_update_errors(root, old, operation)) if kind == "Job"
        issues.concat(job_template_update_errors(root, old, operation)) if kind == "Job"
        issues.concat(ingress_class_errors(root)) if kind == "IngressClass"
        issues.concat(hpa_errors(root, operation)) if kind == "HorizontalPodAutoscaler"
        issues.concat(flow_schema_errors(root, operation)) if kind == "FlowSchema"
        issues.concat(priority_level_errors(root, operation)) if kind == "PriorityLevelConfiguration"
        issues.concat(endpoint_slice_errors(root, operation)) if kind == "EndpointSlice"
        issues.concat(endpoints_errors(root, operation)) if kind == "Endpoints"
        issues.concat(device_class_errors(root)) if kind == "DeviceClass"
        issues.concat(storage_version_migration_errors(root)) if kind == "StorageVersionMigration"
        issues.concat(data_key_errors(root, kind)) if %w[Secret ConfigMap].include?(kind)
        issues.concat(secret_type_errors(root)) if kind == "Secret"
        issues
      end

      # PodSpec rules, for a Pod and for every kind that embeds a template.
      def pod_template_errors(root, walk_root, walk_old, kind, operation)
        issues = probe_errors(walk_root)
        issues.concat(common_pod_errors(walk_root, operation, walk_old))
        issues.concat(pod_resources_errors(walk_root))
        issues.concat(pod_nested_errors(root, operation)) if kind == "Pod"
        issues
      end

      # Selector, pod failure policy and Job/CronJob rules of the controllers
      # that own a Pod template.
      def workload_template_errors(walk_root, kind, operation)
        issues = selector_errors(walk_root, kind)
        issues.concat(enum_and_one_of_errors(walk_root, kind))
        issues.concat(job_family_errors(walk_root, kind))
        issues.concat(job_restart_policy_errors(walk_root, kind))
        issues.concat(job_update_errors(walk_root, kind, operation))
        issues
      end

      # The pods/resize strategy validates with ValidatePodResize, the main
      # resource with ValidatePodUpdate; the status and ephemeralcontainers
      # strategies take the rest of the spec from the stored Pod.
      def pod_change_errors(root, walk_root, walk_old, kind, operation, old:, subresource:)
        return pod_resize_errors(root, old) if kind == "Pod" && operation == :update && subresource.to_s == "resize"
        return pod_update_errors(walk_root, kind, operation, walk_old) if subresource.to_s.empty?

        []
      end

      # Kind rules upstream reports after the Pod template.
      def kind_errors_after_pod_template(root, kind, operation, old, definition:, subresource:)
        issues = []
        issues.concat(ingress_errors(root)) if kind == "Ingress"
        issues.concat(service_errors(root)) if kind == "Service"
        issues.concat(service_update_errors(root, old, operation)) if kind == "Service"
        issues.concat(pvc_errors(root, operation)) if kind == "PersistentVolumeClaim"
        issues.concat(pvc_update_errors(root, old, operation)) if kind == "PersistentVolumeClaim"
        issues.concat(immutable_field_errors(root, old, kind, operation))
        issues.concat(immutable_data_errors(root, old, kind, operation))
        issues.concat(event_errors(root, operation, old, events_group: events_group_definition?(definition))) if kind == "Event"
        issues.concat(mutating_admission_policy_errors(root)) if kind == "MutatingAdmissionPolicy"
        issues.concat(validating_admission_policy_errors(root)) if kind == "ValidatingAdmissionPolicy"
        issues.concat(mutating_policy_binding_errors(root)) if kind == "MutatingAdmissionPolicyBinding"
        issues.concat(custom_resource_definition_errors(root, operation)) if kind == "CustomResourceDefinition"
        issues.concat(pod_group_errors(root)) if kind == "PodGroup"
        issues.concat(pod_disruption_budget_errors(root)) if kind == "PodDisruptionBudget"
        issues.concat(resource_pool_status_request_errors(root)) if kind == "ResourcePoolStatusRequest"
        # ValidateResourceClaimUpdate / ValidateResourceClaimTemplateUpdate only
        # validate ObjectMeta and the immutable spec; the spec is validated on create.
        issues.concat(resource_claim_errors(root, %w[spec])) if kind == "ResourceClaim" && operation == :create
        issues.concat(indexed_job_hostname_errors(root)) if kind == "Job"
        issues.concat(pod_container_set_errors(root, operation)) if kind == "Pod"
        issues.concat(resource_claim_errors(root, %w[spec spec])) if kind == "ResourceClaimTemplate" && operation == :create
        issues.concat(workload_errors(root)) if kind == "Workload"
        issues.concat(pod_certificate_request_errors(root)) if kind == "PodCertificateRequest" && operation == :create
        issues.concat(device_taint_rule_errors(root, old)) if kind == "DeviceTaintRule"
        issues.concat(storage_version_errors(root)) if kind == "StorageVersion"
        issues.concat(service_cidr_errors(root, operation)) if kind == "ServiceCIDR"
        issues.concat(volume_attachment_errors(root)) if kind == "VolumeAttachment"
        issues.concat(volume_errors(root, kind, operation)) if %w[PersistentVolume VolumeAttachment].include?(kind)
        issues.concat(limit_range_errors(root)) if kind == "LimitRange"
        issues.concat(storage_class_errors(root, operation)) if kind == "StorageClass"
        issues.concat(csi_storage_capacity_errors(root)) if kind == "CSIStorageCapacity"
        issues.concat(network_policy_errors(root, operation, old)) if kind == "NetworkPolicy"
        issues.concat(resource_quota_errors(root, operation, old, subresource)) if kind == "ResourceQuota"
        issues.concat(label_keys_errors(root, kind, operation, old)) unless subresource.to_s == "status"
        issues.concat(ip_field_errors(root, kind, old))
        issues.concat(resource_claim_status_errors(root, old)) if kind == "ResourceClaim" && subresource.to_s == "status"
        issues.concat(rbac_errors(root, kind)) if %w[ClusterRole ClusterRoleBinding Role RoleBinding].include?(kind)
        issues.concat(api_service_errors(root)) if kind == "APIService"
        issues.concat(csi_node_errors(root)) if kind == "CSINode"
        issues
      end

      def registry_entry(definition)
        registry_index.fetch([definition.group, definition.version, definition.kind])
      rescue KeyError
        nil
      end

      def registry_type_matches?(definition)
        type = registry_types.fetch(definition.name)
        Array(type.fetch("fields")).sort == definition.fields.keys.map(&:to_s).sort
      rescue KeyError
        false
      end

      def registry_index
        @registry_index ||= begin
          document = registry_document
          Array(document["resources"]).to_h do |entry|
            [[entry.fetch("group", ""), entry.fetch("version"), entry.fetch("kind")], entry]
          end
        rescue KeyError
          {}
        end
      end

      def registry_types
        @registry_types ||= Array(registry_document["types"]).to_h { |type| [type.fetch("schema"), type] }
      end

      def registry_document
        @registry_document ||= begin
          path = File.expand_path("../../../generated/schema/registry.json", __dir__)
          JSON.parse(File.read(path))
        rescue Errno::ENOENT, JSON::ParserError
          {"resources" => [], "types" => []}
        end
      end

      private_class_method :kind_errors_before_pod_template, :pod_template_errors, :workload_template_errors, :pod_change_errors,
                           :kind_errors_after_pod_template
    end
  end
end

# Shared helpers first, then one file per API group or concern.
require_relative "kubernetes_validator/field_access"
require_relative "kubernetes_validator/formats"
require_relative "kubernetes_validator/object_meta"
require_relative "kubernetes_validator/handler_requests"
require_relative "kubernetes_validator/zero_value_roots"
require_relative "kubernetes_validator/config_data"
require_relative "kubernetes_validator/nodes"
require_relative "kubernetes_validator/events"
require_relative "kubernetes_validator/limit_range"
require_relative "kubernetes_validator/networking"
require_relative "kubernetes_validator/storage"
require_relative "kubernetes_validator/pod_spec"
require_relative "kubernetes_validator/pod_nested"
require_relative "kubernetes_validator/workloads"
require_relative "kubernetes_validator/jobs"
require_relative "kubernetes_validator/autoscaling"
require_relative "kubernetes_validator/flowcontrol"
require_relative "kubernetes_validator/admission_webhooks"
require_relative "kubernetes_validator/admission_policies"
require_relative "kubernetes_validator/admission_bindings"
require_relative "kubernetes_validator/custom_resource_definition"
require_relative "kubernetes_validator/rbac"
require_relative "kubernetes_validator/certificates"
require_relative "kubernetes_validator/dynamic_resources"
require_relative "kubernetes_validator/resource_claim_spec"
require_relative "kubernetes_validator/scheduling"
require_relative "kubernetes_validator/control_plane"
require_relative "kubernetes_validator/pod_resources"
require_relative "kubernetes_validator/pod_resize"
require_relative "kubernetes_validator/pod_update"
require_relative "kubernetes_validator/admission_policy_cel"
require_relative "kubernetes_validator/resource_quota"
require_relative "kubernetes_validator/label_keys"
require_relative "kubernetes_validator/ip_fields"
require_relative "kubernetes_validator/resource_claim_status"
