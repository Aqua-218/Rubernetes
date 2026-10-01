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
    module KubernetesValidator
      KUBERNETES_VERSION = "v1.36.2"

      # These are the resource kinds with REST strategy validation in the
      # v1.36.2 built-in registry.  List and request/helper types are excluded
      # because they are not accepted by a resource strategy.
      # Request objects validated inside a REST Create handler rather than a
      # strategy (pkg/registry/**/rest.go, storage.go): their ObjectMeta is
      # not validated upstream, only the request-specific fields.
      HANDLER_REQUEST_KINDS = %w[
        TokenRequest SubjectAccessReview SelfSubjectAccessReview LocalSubjectAccessReview Scale Binding
      ].freeze
      # Handler kinds whose validation function never touches ObjectMeta
      # (ValidateScale does: ValidateObjectMeta with a required namespace).
      METADATA_EXEMPT_KINDS = %w[TokenRequest SubjectAccessReview SelfSubjectAccessReview LocalSubjectAccessReview Binding].freeze
      DELETE_PROPAGATION_POLICIES = %w[Foreground Background Orphan].freeze
      IS_NEGATIVE_ERROR_MSG = "must be greater than or equal to 0"

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

      # The operation matrix is derived from the v1.36.2 validation functions
      # under pkg/apis/*/validation and the corresponding registry strategies.
      # In particular, ValidateObjectMetaUpdate is not uniform: some REST
      # strategies intentionally validate name, while others only require a
      # resourceVersion (or permit unconditional updates).
      UPDATE_NAME_KINDS = %w[
        APIService CertificateSigningRequest ClusterRole ClusterRoleBinding
        ClusterTrustBundle ConfigMap ControllerRevision DeviceClass EndpointSlice
        Endpoints FlowSchema Ingress IngressClass IPAddress Job LimitRange
        MutatingWebhookConfiguration Namespace Node PersistentVolume
        PersistentVolumeClaim Pod PriorityLevelConfiguration Role
        RoleBinding RuntimeClass Secret ServiceAccount StorageClass
        StorageVersionMigration ValidatingAdmissionPolicyBinding
        ValidatingWebhookConfiguration VolumeAttachment VolumeAttributesClass
        CSIStorageCapacity CSINode MutatingAdmissionPolicy ValidatingAdmissionPolicy
        MutatingAdmissionPolicyBinding ResourceClaim
      ].freeze

      # Kinds whose registry strategy answers AllowUnconditionalUpdate with
      # false (pkg/registry/**/strategy.go, plus apiextensions): only these
      # reject an update without metadata.resourceVersion.  Every other
      # built-in kind treats it as an unconditional update.
      UPDATE_RESOURCE_VERSION_REQUIRED = %w[
        Lease LeaseCandidate ValidatingAdmissionPolicy ValidatingAdmissionPolicyBinding
        MutatingAdmissionPolicy MutatingAdmissionPolicyBinding ValidatingWebhookConfiguration
        MutatingWebhookConfiguration CSIStorageCapacity CSIDriver CSINode VolumeAttachment
        PodDisruptionBudget StorageVersion PodCertificateRequest ResourcePoolStatusRequest
        RuntimeClass ClusterTrustBundle StorageVersionMigration CustomResourceDefinition
      ].freeze

      UPDATE_NAMESPACE_KINDS = %w[
        ConfigMap ControllerRevision EndpointSlice Endpoints Ingress Job LimitRange Pod
        PersistentVolumeClaim Role RoleBinding Secret ServiceAccount CSIStorageCapacity
        ValidatingAdmissionPolicyBinding ResourceClaim
      ].freeze

      # k8s.io/apimachinery/pkg/util/validation message texts.
      DNS1123_SUBDOMAIN_MSG = "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"
      DNS1123_LABEL_MSG = "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an " \
                          "alphanumeric character (e.g. 'my-name',  or '123-abc', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')"
      DNS1035_LABEL_MSG = "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an " \
                          "alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')"
      QUALIFIED_NAME_PART_MSG = "name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character " \
                                "(e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"
      QUALIFIED_NAME_FULL_MSG = "a qualified name must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]') with an optional DNS subdomain prefix and '/' (e.g. 'example.com/MyName')"
      LABEL_VALUE_MSG = "a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"
      ADMISSION_MATCH_RESOURCE_OPERATIONS = %w[* CONNECT CREATE DELETE UPDATE].freeze
      ADMISSION_MUTATING_OPERATIONS = %w[* CONNECT CREATE UPDATE].freeze
      POD_CERTIFICATE_REQUEST_DEFAULT_MAX_EXPIRATION = 86_400

      WEBHOOK_KINDS = %w[MutatingWebhookConfiguration ValidatingWebhookConfiguration].freeze
      PROBE_HANDLERS = %w[exec httpGet tcpSocket grpc sleep].freeze
      PROBE_HANDLER_DETAIL = "may not specify more than 1 handler type"
      SUPPORTED_APPARMOR = %w[Localhost RuntimeDefault Unconfined].freeze
      SUPPORTED_SECCOMP = %w[Localhost RuntimeDefault Unconfined].freeze
      SUPPORTED_OS = %w[linux windows].freeze
      SUPPORTED_METRIC_TYPES = %w[ContainerResource External Object Pods Resource].freeze
      SUPPORTED_POD_FAILURE_ACTIONS = %w[Count FailIndex FailJob Ignore].freeze
      SUPPORTED_POD_FAILURE_OPERATORS = %w[In NotIn].freeze
      FLOWCONTROL_VERBS = %w[create delete deletecollection get list patch proxy update watch].freeze
      SUPPORTED_RESOURCE_SLICE_PLACEMENT = %w[nodeName nodeSelector allNodes perDeviceNodeSelection].freeze

      module_function

      def errors(definition, value, operation: :create, old: nil, strategy_prepare: false, subresource: nil)
        # metav1.DeleteOptions carries no ObjectMeta; ValidateDeleteOptions
        # (apimachinery/pkg/apis/meta/v1/validation) runs in the delete handler.
        return delete_options_errors(plain_object(value)) if definition.respond_to?(:kind) && definition.kind == "DeleteOptions" && object_like?(value)
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
        return false unless definition.respond_to?(:fields) && definition.respond_to?(:kind)
        return false unless %w[apiVersion kind metadata].all? { |name| definition.fields.key?(name) }
        # Handler request kinds (TokenRequest, the access reviews, Scale,
        # Binding) are subresource or virtual bodies without a registry
        # resource of their own.
        return true if HANDLER_REQUEST_KINDS.include?(definition.kind)

        VALIDATED_KINDS.include?(definition.kind) && !registry_entry(definition).nil? &&
          registry_type_matches?(definition)
      rescue StandardError
        false
      end

      # ValidateOwnerReferences: only one ownerReference may set controller:true
      # (apimachinery objectmeta.go:92-107).  Nothing checked it, so an object
      # could carry two controllers and the garbage collector would follow
      # whichever it saw first.
      def owner_reference_errors(metadata)
        refs = Array(fetch(metadata, "ownerReferences"))
        controllers = refs.select { |ref| ref.is_a?(Hash) && fetch(ref, "controller") == true }
        return [] if controllers.length <= 1

        names = controllers.map { |ref| "#{fetch(ref, "kind")}/#{fetch(ref, "name")}" }
        [issue(%w[metadata ownerReferences], :invalid,
               "Only one reference can have Controller set to true. Found \"true\" in references for " \
               "#{names.first} and #{names[1]}")]
      end

      # ValidateAnnotations (apimachinery objectmeta.go:44): every annotation
      # key is a qualified name (case-insensitive), and the annotations of one
      # object may not exceed 256 kB in total.  Neither was checked, so an
      # object could carry an unbounded annotation payload.
      TOTAL_ANNOTATION_SIZE_LIMIT = 256 * 1024

      def object_annotation_errors(metadata)
        annotations = fetch(metadata, "annotations")
        return [] unless annotations.is_a?(Hash)

        issues = annotations.keys.flat_map do |key|
          qualified_name_messages(key.to_s.downcase).map do |message|
            issue(["metadata", "annotations", key.to_s], :invalid, message)
          end
        end
        total = annotations.sum { |key, value| key.to_s.bytesize + value.to_s.bytesize }
        if total > TOTAL_ANNOTATION_SIZE_LIMIT
          issues << issue(%w[metadata annotations], :invalid,
                          "must have at most #{TOTAL_ANNOTATION_SIZE_LIMIT} bytes")
        end
        issues
      end

      # ValidateLabels (apimachinery meta/v1/validation:113) runs over every
      # object's metadata.labels: the KEY must be a qualified name and the
      # VALUE a valid label value (<=63 chars, alphanumeric with -_. inside).
      # Only selector requirement keys were checked, so an object could be
      # stored with a label no selector can ever match.
      LABEL_VALUE_PATTERN = /\A(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?\z/

      def object_label_errors(metadata)
        labels = fetch(metadata, "labels")
        return [] unless labels.is_a?(Hash)

        labels.flat_map do |key, value|
          path = ["metadata", "labels", key.to_s]
          issues = label_key_errors(key.to_s, path)
          text = value.to_s
          if text.length > 63
            issues += [issue(path, :invalid, "must be no more than 63 characters")]
          elsif !text.match?(LABEL_VALUE_PATTERN)
            issues += [issue(path, :invalid,
                             "a valid label must be an empty string or consist of alphanumeric characters, " \
                             "'-', '_' or '.', and must start and end with an alphanumeric character")]
          end
          issues
        end
      end

      # ValidateFinalizerName (apimachinery objectmeta.go:111): every finalizer
      # must be a qualified name.  Nothing checked it, so an object could be
      # stored with a finalizer nothing can ever match and become undeletable.
      def finalizer_name_errors(metadata)
        Array(fetch(metadata, "finalizers")).each_with_index.flat_map do |value, index|
          qualified_name_messages(value.to_s).map do |message|
            issue(["metadata", "finalizers", index.to_s], :invalid, message)
          end
        end
      end

      def metadata_errors(definition, root, kind, operation)
        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        issues = []
        namespaced = (registry_entry(definition) || {"scope" => (definition.kind == "Scale" ? "Namespaced" : "Cluster")}).fetch("scope",
                                                                                                                                "Namespaced") == "Namespaced"

        # core/v1 Event requests only run legacyValidateEvent; ObjectMeta is
        # validated for events.k8s.io requests (pkg/apis/core/validation/events.go).
        return issues if kind == "Event" && !events_group_definition?(definition)

        issues.concat(owner_reference_errors(metadata))
        issues.concat(finalizer_name_errors(metadata))
        issues.concat(object_label_errors(metadata))
        issues.concat(object_annotation_errors(metadata))

        if name_required?(kind, operation) && blank?(fetch(metadata, "name")) && blank?(fetch(metadata, "generateName"))
          issues << issue(%w[metadata name], :required, "name or generateName is required")
        end
        issues.concat(kind_name_format_errors(kind, fetch(metadata, "name").to_s, root)) unless blank?(fetch(metadata, "name"))
        issues << issue(%w[metadata namespace], :required, "") if namespaced && namespace_required?(kind, operation) && blank?(fetch(metadata, "namespace"))
        if operation == :update && resource_version_required?(kind) && blank?(fetch(metadata, "resourceVersion"))
          issues << issue(%w[metadata resourceVersion], :invalid, "must be specified for an update")
        end
        if kind == "PersistentVolume" && operation == :update && blank?(fetch(metadata, "name"))
          issues << issue(%w[metadata name], :required, "name or generateName is required")
        end
        issues.concat(managed_fields_errors(metadata))
        issues
      end

      def name_required?(kind, operation)
        return false if kind == "PodDisruptionBudget"
        return false if METADATA_EXEMPT_KINDS.include?(kind)
        # LimitRange's create strategy validates the limits before object
        # metadata and accepts the zero-value name.  Update still uses the
        # normal object-meta name requirement.
        return false if kind == "LimitRange" && operation != :update
        return true unless operation == :update

        UPDATE_NAME_KINDS.include?(kind)
      end

      def namespace_required?(kind, operation)
        # PDB strategy validation runs before the request namespace is
        # injected, so an empty ObjectMeta namespace is accepted here.
        return false if kind == "PodDisruptionBudget"
        return false if METADATA_EXEMPT_KINDS.include?(kind)

        return true if operation == :create

        UPDATE_NAMESPACE_KINDS.include?(kind)
      end

      def resource_version_required?(kind)
        UPDATE_RESOURCE_VERSION_REQUIRED.include?(kind) && !HANDLER_REQUEST_KINDS.include?(kind)
      end

      def managed_fields_errors(metadata)
        managed = fetch(metadata, "managedFields")
        return [] unless managed.is_a?(Array)
        # [{}] asks the field manager to strip the set; upstream consumes it
        # before ObjectMeta is validated.
        return [] if managed.length == 1 && managed.first.is_a?(Hash) && managed.first.empty?

        managed.each_with_index.filter_map do |entry, index|
          next unless entry.is_a?(Hash)
          next unless blank?(fetch(entry, "operation")) || !%w[Apply Update].include?(fetch(entry, "operation").to_s)

          issue(["metadata", "managedFields", index.to_s, "operation"], :invalid, "must be `Apply` or `Update`")
        end
      end

      def cross_field_errors(root, kind, operation, old, strategy_prepare: false, definition: nil, subresource: nil)
        return handler_request_errors(root, kind) if HANDLER_REQUEST_KINDS.include?(kind)

        issues = missing_root_errors(root, kind)
        issues << issue([], :internal, "could not find requestInfo in context") if internal_request_context_strategy?(kind)
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
        issues.concat(probe_errors(root))
        issues.concat(common_pod_errors(root, operation, old))
        issues.concat(pod_resources_errors(root))
        issues.concat(pod_nested_errors(root, operation)) if kind == "Pod"
        if kind == "StatefulSet" && operation == :update
          # ValidateStatefulSetUpdate skips pod-template validation when the
          # retained old template is already invalid.  The zero-value semantic
          # fixture exercises that compatibility path; selector/template
          # metadata rules still run below.
          issues.reject! do |candidate|
            candidate.path.length >= 4 &&
              candidate.path[0, 3] == %w[spec template spec]
          end
        end
        issues.concat(selector_errors(root, kind))
        issues.concat(enum_and_one_of_errors(root, kind))
        issues.concat(job_family_errors(root, kind))
        issues.concat(job_restart_policy_errors(root, kind))
        issues.concat(job_update_errors(root, kind, operation))
        # The pods/resize strategy validates with ValidatePodResize, the main
        # resource with ValidatePodUpdate; the status and ephemeralcontainers
        # strategies take the rest of the spec from the stored Pod.
        if kind == "Pod" && operation == :update && subresource.to_s == "resize"
          issues.concat(pod_resize_errors(root, old))
        elsif subresource.to_s.empty?
          issues.concat(pod_update_errors(root, kind, operation, old))
        end
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
        # Job's REST PrepareForCreate/PrepareForUpdate generates the
        # controller selector before ValidateJob runs.  The generated
        # selector is invalid without the server UID, so the pinned oracle
        # observes metadata.uid Required on the prepared fixture.  Keep this
        # opt-in: public create/update validation must not require the
        # server-assigned UID from an ordinary client request.
        job_spec = fetch(root, "spec")
        manual_selector = job_spec.is_a?(Hash) && fetch(job_spec, "manualSelector") == true
        if kind == "Job" && strategy_prepare && !manual_selector
          metadata = fetch(root, "metadata")
          metadata = {} unless metadata.is_a?(Hash)
          if operation == :create
            issues << issue(%w[metadata uid], :required, "") if blank?(fetch(metadata, "uid"))
          elsif operation == :update
            issues.concat(job_prepared_update_errors(root, metadata))
          end
        end
        if kind == "Job" && operation == :update
          # ValidateJobUpdate validates the desired and retained Job specs.
          # Helpers that already model both passes (selector, restartPolicy,
          # and image) are left untouched; the remaining single-pass spec
          # issues need one retained-object copy.
          counts = issues.group_by(&:path).transform_values(&:length)
          issues.concat(issues.select do |candidate|
            candidate.path.first == "spec" &&
              !candidate.path.include?("labels") &&
              counts.fetch(candidate.path, 0) == 1
          end)
        end
        # StatefulSet update validation deliberately skips the retained pod
        # template.  Keep this as a final guard because helpers below the
        # strategy family can discover template fields after the main
        # compatibility branch has run.
        if kind == "StatefulSet" && operation == :update
          issues.reject! do |candidate|
            candidate.path.length >= 4 && candidate.path[0, 3] == %w[spec template spec]
          end
        end
        issues
      end

      # ValidateJobUpdate observes the generated selector/labels only after
      # PrepareForUpdate.  Empty semantic fixtures split into two upstream
      # branches: a zero selector is checked for generated labels, while a
      # missing selector emits the parent Required/Invalid pair twice (the
      # strategy validates both old and new Job specs).  This helper is only
      # called by the explicit oracle preparation lane; ordinary client
      # validation never assumes a server UID or generated labels.
      # ---- REST Create handler request validation --------------------------

      def handler_request_errors(root, kind)
        case kind
        when "TokenRequest" then token_request_errors(root)
        when "SubjectAccessReview" then subject_access_review_errors(root, self_review: false, local: false)
        when "SelfSubjectAccessReview" then subject_access_review_errors(root, self_review: true, local: false)
        when "LocalSubjectAccessReview" then subject_access_review_errors(root, self_review: false, local: true)
        when "Scale" then scale_errors(root)
        when "Binding" then binding_errors(root)
        else []
        end
      end

      # pkg/apis/authentication/validation ValidateTokenRequest.  The token
      # REST handler receives the request after the versioned decoder applied
      # SetDefaults_TokenRequestSpec (expirationSeconds 3600 when absent).
      def token_request_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        seconds = fetch(spec, "expirationSeconds")
        seconds = 3600 if seconds.nil?
        issues = []
        return issues unless seconds.is_a?(Integer)

        issues << issue(%w[spec expirationSeconds], :invalid, "may not specify a duration less than 10 minutes") if seconds < 600
        issues << issue(%w[spec expirationSeconds], :invalid, "may not specify a duration larger than 2^32 seconds") if seconds > (1 << 32)
        issues
      end

      # pkg/apis/authorization/validation ValidateSubjectAccessReviewSpec /
      # ValidateSelfSubjectAccessReviewSpec / ValidateLocalSubjectAccessReview
      def subject_access_review_errors(root, self_review:, local:)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        resource = fetch(spec, "resourceAttributes")
        non_resource = fetch(spec, "nonResourceAttributes")
        issues = []
        if resource.is_a?(Hash) && non_resource.is_a?(Hash)
          issues << issue(%w[spec nonResourceAttributes], :invalid, "cannot be specified in combination with resourceAttributes")
        end
        if !resource.is_a?(Hash) && !non_resource.is_a?(Hash)
          issues << issue(%w[spec resourceAttributes], :invalid,
                          "exactly one of nonResourceAttributes or resourceAttributes must be specified")
        end
        if !self_review && blank?(fetch(spec, "user")) && Array(fetch(spec, "groups")).empty?
          issues << issue(%w[spec user], :invalid, "at least one of user or group must be specified")
        end
        issues.concat(resource_attributes_errors(resource))
        unless local
          # ValidateSubjectAccessReview / ValidateSelfSubjectAccessReview:
          # ObjectMeta must be the zero value.
          metadata = fetch(root, "metadata")
          metadata = {} unless metadata.is_a?(Hash)
          extra = metadata.reject { |_key, value| blank?(value) || (value.respond_to?(:empty?) && value.empty?) }
          issues << issue(%w[metadata], :invalid, "must be empty") unless extra.empty?
        end
        if local
          issues << issue(%w[spec nonResourceAttributes], :invalid, "disallowed on this kind of request") if non_resource.is_a?(Hash)
          metadata = fetch(root, "metadata")
          metadata = {} unless metadata.is_a?(Hash)
          extra = metadata.reject do |key, value|
            %w[namespace managedFields].include?(key.to_s) || blank?(value) || (value.respond_to?(:empty?) && value.empty?)
          end
          issues << issue(%w[metadata], :invalid, "must be empty except for namespace") unless extra.empty?
          if resource.is_a?(Hash) && fetch(resource, "namespace").to_s != fetch(metadata, "namespace").to_s
            issues << issue(%w[spec resourceAttributes namespace], :invalid, "must match metadata.namespace")
          end
        end
        issues
      end

      def resource_attributes_errors(resource)
        return [] unless resource.is_a?(Hash)

        issues = []
        {"fieldSelector" => :field, "labelSelector" => :label}.each do |name, flavor|
          selector = fetch(resource, name)
          next unless selector.is_a?(Hash)

          path = ["spec.resourceAttributes", name]
          raw = fetch(selector, "rawSelector").to_s
          requirements = Array(fetch(selector, "requirements"))
          if !raw.empty? && !requirements.empty?
            issues << issue(path + ["rawSelector"], :invalid,
                            "may not specified at the same time as requirements")
          end
          if raw.empty? && requirements.empty?
            issues << issue(path + ["requirements"], :required,
                            "when #{path.join(".")} is specified, requirements or rawSelector is required")
          end
          requirements.each_with_index do |requirement, index|
            next unless requirement.is_a?(Hash)

            requirement_path = path + ["requirements", index.to_s]
            issues << issue(requirement_path + ["key"], :required, "must be specified") if blank?(fetch(requirement, "key"))
            operator = fetch(requirement, "operator").to_s
            values = Array(fetch(requirement, "values"))
            case operator
            when "In", "NotIn"
              if values.empty?
                issues << issue(requirement_path + ["values"], :required,
                                "must be specified when `operator` is 'In' or 'NotIn'")
              end
            when "Exists", "DoesNotExist"
              unless values.empty?
                issues << issue(requirement_path + ["values"], :forbidden,
                                "may not be specified when `operator` is 'Exists' or 'DoesNotExist'")
              end
            end
            if flavor == :label && !blank?(fetch(requirement, "key"))
              issues.concat(label_key_errors(fetch(requirement, "key").to_s, requirement_path + ["key"]))
            end
          end
        end
        issues
      end

      def label_key_errors(key, path)
        if key.match?(%r{\A(?:[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z}) &&
           key.split("/").last.length <= 63
          return []
        end

        [issue(path, :invalid,
               "name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')")]
      end

      # pkg/apis/autoscaling/validation ValidateScale
      def scale_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        replicas = fetch(spec, "replicas")
        return [] unless replicas.is_a?(Integer) && replicas.negative?

        [issue(%w[spec replicas], :invalid, IS_NEGATIVE_ERROR_MSG)]
      end

      # pkg/apis/core/validation ValidatePodBinding
      def binding_errors(root)
        target = fetch(root, "target")
        target = {} unless target.is_a?(Hash)
        issues = []
        kind = fetch(target, "kind").to_s
        issues << issue(%w[target kind], :unsupported, "supported values: \"Node\", \"<empty>\"") unless kind.empty? || kind == "Node"
        issues << issue(%w[target name], :required, "") if blank?(fetch(target, "name"))
        issues
      end

      # staging/src/k8s.io/apimachinery/pkg/apis/meta/v1/validation ValidateDeleteOptions
      def delete_options_errors(root)
        issues = []
        orphan = fetch(root, "orphanDependents")
        policy = fetch(root, "propagationPolicy")
        issues << issue(%w[propagationPolicy], :invalid, "orphanDependents and deletionPropagation cannot be both set") if !orphan.nil? && !policy.nil?
        if !policy.nil? && !DELETE_PROPAGATION_POLICIES.include?(policy.to_s)
          issues << issue(%w[propagationPolicy], :unsupported, "supported values: \"Foreground\", \"Background\", \"Orphan\", \"nil\"")
        end
        dry_run = Array(fetch(root, "dryRun"))
        issues << issue(%w[dryRun], :unsupported, "supported values: \"All\"") unless dry_run.all? { |value| value.to_s == "All" }
        if fetch(root, "ignoreStoreReadErrorWithClusterBreakingPotential") == true
          path = %w[ignoreStoreReadErrorWithClusterBreakingPotential]
          issues << issue(path, :invalid, "cannot be set together with .dryRun") unless dry_run.empty?
          issues << issue(path, :invalid, "cannot be set together with .propagationPolicy") unless policy.nil?
          issues << issue(path, :invalid, "cannot be set together with .orphanDependents") unless orphan.nil?
          issues << issue(path, :invalid, "cannot be set together with .gracePeriodSeconds") unless fetch(root, "gracePeriodSeconds").nil?
        end
        issues
      end

      def job_prepared_update_errors(root, metadata)
        issues = []
        spec = fetch(root, "spec")
        # pkg/registry/batch/job generateSelector runs only for jobs without
        # manualSelector; a manual selector is validated as supplied.
        return issues if spec.is_a?(Hash) && fetch(spec, "manualSelector") == true

        if spec.is_a?(Hash) && spec.key?("selector")
          issues << issue(%w[metadata uid], :required, "") if blank?(fetch(metadata, "uid"))
          labels = fetch(fetch(fetch(spec, "template"), "metadata"), "labels")
          if !labels.is_a?(Hash) || labels.empty?
            %w[controller-uid job-name].each do |name|
              expected = name == "job-name" ? fetch(metadata, "name").to_s : ""
              issues << issue(["spec", "template", "metadata", "labels", "[#{name}]"], :required, "must be '#{expected}'")
            end
          end
        else
          2.times do
            issues << issue(%w[spec selector], :required, "")
            issues << issue(%w[spec template metadata labels], :invalid,
                            "`selector` does not match template `labels`")
          end
        end
        issues
      end

      # Strategy validation still runs against a zero-value API struct when
      # the fixture omits an optional root section.  OpenAPI requiredness does
      # not encode those semantic checks, so model the reusable zero-value
      # families here.  These paths/messages are taken from the v1.36.2
      # Validate* functions and are deliberately grouped by rule family.
      def missing_root_errors(root, kind)
        return [issue(%w[data], :required, "data is mandatory")] if kind == "ControllerRevision" && !root.key?("data") && !root.key?("revision")
        return [] if root.key?("spec")

        issues = []
        case kind
        when "ValidatingAdmissionPolicyBinding"
          issues << issue(%w[spec policyName], :required, "")
          issues << issue(%w[spec validationActions], :required, "at least one validation action is required")
        when "DaemonSet", "Deployment", "ReplicaSet", "StatefulSet"
          # DaemonSet's zero-value strategy path validates the template
          # directly and does not emit selector.Required when spec itself is
          # absent.  Other controller strategies do.
          issues << issue(%w[spec selector], :required, "") unless kind == "DaemonSet"
          issues << issue(%w[spec template metadata labels], :invalid, "`selector` does not match template `labels`")
          issues << issue(%w[spec template spec containers], :required, "")
        when "ReplicationController"
          issues << issue(%w[spec selector], :required, "")
          issues << issue(%w[spec template], :required, "")
        when "HorizontalPodAutoscaler"
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`")
          issues << issue(%w[spec maxReplicas], :required, "must be set and greater than 0")
          issues << issue(%w[spec scaleTargetRef apiVersion], :invalid, "apiVersion must specify API group")
          issues << issue(%w[spec scaleTargetRef kind], :required, "")
          issues << issue(%w[spec scaleTargetRef name], :required, "")
        when "CronJob"
          issues << issue(%w[spec jobTemplate spec template spec containers], :required, "")
          issues << issue(%w[spec jobTemplate spec template spec restartPolicy], :required,
                          "valid values: \"OnFailure\", \"Never\"")
          issues << issue(%w[spec schedule], :required, "")
        when "Job"
          issues << issue(%w[spec template spec containers], :required, "")
          issues << issue(%w[spec template spec restartPolicy], :required,
                          "valid values: \"OnFailure\", \"Never\"")
        when "CertificateSigningRequest"
          issues << issue(%w[spec request], :invalid, "PEM block type must be CERTIFICATE REQUEST")
          issues << issue(%w[spec signerName], :required, "")
          issues << issue(%w[spec usages], :required, "")
        when "ClusterTrustBundle"
          issues << issue(%w[spec trustBundle], :invalid, "at least one trust anchor must be provided")
        when "LeaseCandidate"
          %w[binaryVersion leaseName strategy].each { |name| issues << issue(["spec", name], :required, "") }
        when "PersistentVolume"
          issues << issue(%w[spec], :required, "must specify a volume type")
          issues << issue(%w[spec accessModes], :required, "")
          issues << issue(%w[spec capacity], :required, "")
          issues << issue(%w[spec capacity], :unsupported, "supported values: \"storage\"")
        when "Pod"
          issues << issue(%w[spec containers], :required, "")
        when "Service"
          issues << issue(%w[spec ports], :required, "") unless external_name_service?(fetch(root, "spec") || {})
        when "Event"
          # Legacy core/v1 Events carry their namespace under
          # metadata.namespace and may omit eventTime.  The generated schema
          # already validates the wire fields; applying the events.k8s.io
          # required-field rules here rejected valid controller-manager
          # Events before they could be persisted.
        when "PersistentVolumeClaim"
          issues << issue(%w[spec accessModes], :required, "at least 1 access mode is required")
          issues << issue(%w[spec resources [storage]], :required, "")
        when "ResourceSlice"
          issues.concat(resource_slice_missing_errors)
        when "PodTemplate"
          issues << issue(%w[template spec containers], :required, "") unless root.key?("template")
        when "StorageClass"
          # storage_class_errors reports the missing provisioner.
        when "EndpointSlice"
          # A present empty value is handled by endpoint_slice_errors; this
          # branch covers an actually omitted root field only.
          issues << issue(%w[addressType], :required, "") unless root.key?("addressType")
        when "PriorityLevelConfiguration"
          issues << issue(%w[spec type], :unsupported, "supported values: \"Exempt\", \"Limited\"")
        when "FlowSchema"
          issues << issue(%w[spec priorityLevelConfiguration name], :required, "must reference a priority level")
        when "IPAddress"
          issues << issue(%w[spec parentRef], :required, "")
        when "Ingress"
          issues << issue(%w[spec], :invalid, "either `defaultBackend` or `rules` must be specified")
        when "IngressClass"
          issues << issue(%w[spec controller], :required, "")
        when "ServiceCIDR"
          issues << issue(%w[spec cidrs], :required, "at least one CIDR required")
        when "RuntimeClass"
          issues << issue(%w[handler], :required, "") if blank?(fetch(root, "handler"))
        when "ClusterRoleBinding", "RoleBinding"
          # pkg/apis/rbac/validation ValidateRoleBinding/ValidateClusterRoleBinding
          role_ref = fetch(root, "roleRef")
          role_ref = {} unless role_ref.is_a?(Hash)
          allowed = kind == "ClusterRoleBinding" ? %w[ClusterRole] : %w[Role ClusterRole]
          issues << issue(%w[roleRef apiGroup], :unsupported, "supported values: \"rbac.authorization.k8s.io\"") if !blank?(fetch(role_ref,
                                                                                                                                  "apiGroup")) && fetch(
                                                                                                                                    role_ref, "apiGroup"
                                                                                                                                  ).to_s != "rbac.authorization.k8s.io"
          unless allowed.include?(fetch(role_ref, "kind").to_s)
            issues << issue(%w[roleRef kind], :unsupported, "supported values: #{allowed.map do |value|
              "\"#{value}\""
            end.join(", ")}")
          end
          issues << issue(%w[roleRef name], :required, "") if blank?(fetch(role_ref, "name"))
        when "VolumeAttachment"
          issues << issue(%w[spec attacher], :required, "")
          issues << issue(%w[spec nodeName], :invalid,
                          "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')")
          issues << issue(%w[spec source], :required, "must specify exactly one of inlineVolumeSpec and persistentVolumeName")
        when "VolumeAttributesClass"
          issues << issue(%w[driverName], :required, "") if blank?(fetch(root, "driverName"))
          parameters = fetch(root, "parameters")
          unless parameters.is_a?(Hash) && !parameters.empty?
            issues << issue(%w[parameters], :required,
                            "must contain at least one key/value pair")
          end
        when "StorageVersionMigration"
          issues << issue(%w[spec resource resource], :required, "resource is required to be set")
        when "APIService"
          issues << issue(%w[spec group], :required, "only v1 may have an empty group and it better be legacy kube")
          issues << issue(%w[spec groupPriorityMinimum], :invalid, "must be positive and less than 20000")
          issues << issue(%w[spec version], :invalid,
                          "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')")
          issues << issue(%w[spec versionPriority], :invalid, "must be positive and less than 1000")
        end
        issues
      end

      # ValidateSecret / ValidateConfigMap run IsConfigMapKey over every data
      # key (pkg/apis/core/validation/validation.go): a key must match
      # [-._a-zA-Z0-9]+, be at most 253 characters, and must not be "." or ".."
      # or start with "..".  An empty key is therefore rejected -- the
      # conformance spec "should fail to create secret due to empty secret key"
      # creates exactly that and requires the creation to fail.
      DATA_KEY_PATTERN = /\A[-._a-zA-Z0-9]+\z/
      DATA_KEY_MAX_LENGTH = 253
      DATA_KEY_MESSAGE = "a valid config key must consist of alphanumeric characters, '-', '_' or '.' " \
                         "(e.g. 'key.name', or 'KEY_NAME', or 'key-name', regex used for validation is " \
                         "'[-._a-zA-Z0-9]+')"

      # MaxSecretSize (pkg/apis/core/types.go:6626): a Secret's data, and a
      # ConfigMap's, may not exceed 1 MiB in total.  Nothing checked it, so an
      # object larger than any kubelet will project could be stored.
      MAX_SECRET_SIZE = 1 * 1024 * 1024

      def data_key_errors(root, kind)
        issues = []
        total = 0
        %w[data stringData binaryData].each do |section|
          values = fetch(root, section)
          next unless values.is_a?(Hash)

          total += values.sum { |_key, value| value.to_s.bytesize }
        end
        issues << issue(%w[data], :invalid, "must have at most #{MAX_SECRET_SIZE} bytes") if total > MAX_SECRET_SIZE
        %w[data stringData binaryData].each do |section|
          values = fetch(root, section)
          next unless values.is_a?(Hash)

          values.each_key do |raw_key|
            key = raw_key.to_s
            path = [section, "[#{key}]"]
            issues << issue(path, :invalid, "must be no more than #{DATA_KEY_MAX_LENGTH} characters") if key.length > DATA_KEY_MAX_LENGTH
            issues << issue(path, :invalid, DATA_KEY_MESSAGE) unless key.match?(DATA_KEY_PATTERN)
            issues << issue(path, :invalid, "must not be '.'") if key == "."
            issues << issue(path, :invalid, "must not be '..'") if key == ".."
            issues << issue(path, :invalid, "must not start with '..'") if key.start_with?("..") && key != ".."
          end
        end
        _ = kind
        issues
      end

      # ValidateSecret (validation.go:7781-7811): each built-in Secret type
      # requires its own keys.  Nothing checked them, so a
      # kubernetes.io/tls Secret with no certificate was accepted and every
      # consumer failed at use instead of at creation.
      SECRET_TYPE_REQUIRED_KEYS = {
        "kubernetes.io/dockercfg" => [".dockercfg"],
        "kubernetes.io/dockerconfigjson" => [".dockerconfigjson"],
        "kubernetes.io/basic-auth" => %w[username password],
        "kubernetes.io/ssh-auth" => ["ssh-privatekey"],
        "kubernetes.io/tls" => ["tls.crt", "tls.key"]
      }.freeze

      def secret_type_errors(root)
        type = fetch(root, "type").to_s
        required_keys = SECRET_TYPE_REQUIRED_KEYS[type]
        issues = []
        if type == "kubernetes.io/service-account-token"
          annotations = fetch(fetch(root, "metadata"), "annotations")
          name = annotations.is_a?(Hash) ? fetch(annotations, "kubernetes.io/service-account.name") : nil
          issues << issue(["metadata", "annotations", "kubernetes.io/service-account.name"], :required, "") if blank?(name)
        end
        return issues if required_keys.nil?

        data = fetch(root, "data")
        string_data = fetch(root, "stringData")
        required_keys.each do |key|
          present = (data.is_a?(Hash) && data.key?(key)) || (string_data.is_a?(Hash) && string_data.key?(key))
          issues << issue(["data", key], :required, "") unless present
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

      def webhook_errors(root, _kind, operation = :create)
        webhooks = fetch(root, "webhooks")
        return [] unless webhooks.is_a?(Array)

        webhooks.each_with_index.flat_map do |webhook, index|
          next [] unless webhook.is_a?(Hash)

          path = ["webhooks", index.to_s]
          errors = []
          versions = fetch(webhook, "admissionReviewVersions")
          if !versions.is_a?(Array) || versions.empty?
            errors << issue(path + ["admissionReviewVersions"], :required,
                            "must specify one of v1, v1beta1")
          end
          if versions.is_a?(Array) && !versions.empty?
            accepted_version = versions.any? { |version| %w[v1 v1beta1].include?(version.to_s) }
            if operation == :create && !accepted_version
              errors << issue(path + ["admissionReviewVersions"], :invalid,
                              "must include at least one of v1, v1beta1")
            end
            versions.each_with_index do |version, version_index|
              next if version.is_a?(String) && version.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)

              errors << issue(path + ["admissionReviewVersions", version_index.to_s], :invalid,
                              "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')")
            end
          end
          client = fetch(webhook, "clientConfig")
          if client.is_a?(Hash)
            url = fetch(client, "url")
            service = fetch(client, "service")
            if (blank?(url) && blank?(service)) || (!blank?(url) && !blank?(service))
              errors << issue(path + ["clientConfig"], :required, "exactly one of url or service is required")
            end
          else
            errors << issue(path + ["clientConfig"], :required, "exactly one of url or service is required")
          end
          name = fetch(webhook, "name")
          if blank?(name)
            errors << issue(path + ["name"], :required, "")
          elsif name.to_s.split(".").length < 3
            errors << issue(path + ["name"], :invalid, "should be a domain with at least three segments separated by dots")
          end
          side_effects = fetch(webhook, "sideEffects")
          allowed_side_effects = operation == :update ? %w[None NoneOnDryRun Some Unknown] : %w[None NoneOnDryRun]
          if blank?(side_effects)
            errors << issue(path + ["sideEffects"], :required,
                            "must specify one of #{allowed_side_effects.join(", ")}")
          elsif !allowed_side_effects.include?(side_effects.to_s)
            errors << issue(path + ["sideEffects"], :unsupported,
                            "supported values: #{allowed_side_effects.map { |value| JSON.generate(value) }.join(", ")}")
          end
          conditions = fetch(webhook, "matchConditions")
          if operation != :update && conditions.is_a?(Array)
            conditions.each_with_index do |condition, condition_index|
              next unless condition.is_a?(Hash)

              expression = fetch(condition, "expression")
              next unless expression.is_a?(String) && !expression.strip.empty?

              # validateMatchConditionsExpression: the trimmed expression,
              # compiled by the strict stateless compiler (no params).
              expression_path = path + ["matchConditions", condition_index.to_s, "expression"]
              compile_issue = cel_compile_issue(expression_path, expression.strip, compiler: policy_expression_compiler,
                                                                                   return_types: cel_return_types(:bool), has_params: false, has_authorizer: true)
              errors << compile_issue if compile_issue
            end
          end
          rules = fetch(webhook, "rules")
          if rules.is_a?(Array)
            rules.each_with_index do |rule, rule_index|
              next unless rule.is_a?(Hash)

              rule_path = path + ["rules", rule_index.to_s]
              %w[apiGroups apiVersions operations resources].each do |field|
                value = fetch(rule, field)
                errors << issue(rule_path + [field], :required, "") unless value.is_a?(Array) && !value.empty?
              end
            end
          end
          errors
        end
      end

      def policy_binding_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        required(spec, "policyName", ["spec"], issues)
        actions = fetch(spec, "validationActions")
        if !actions.is_a?(Array) || actions.empty?
          issues << issue(%w[spec validationActions], :required, "at least one validation action is required")
        else
          actions.each_with_index do |action, index|
            next if %w[Deny Warn Audit].include?(action.to_s)

            issues << issue(["spec", "validationActions", index.to_s], :unsupported,
                            "supported values: \"Audit\", \"Deny\", \"Warn\"")
          end
        end

        match_resources = fetch(spec, "matchResources")
        if match_resources.is_a?(Hash)
          %w[matchResourceRules excludeResourceRules].each do |collection|
            rules = fetch(match_resources, collection)
            next unless rules.is_a?(Array)

            rules.each_with_index do |rule, index|
              next unless rule.is_a?(Hash)

              base = ["spec", "matchResources", collection, index.to_s]
              %w[apiGroups apiVersions operations resources].each do |field|
                value = fetch(rule, field)
                issues << issue(base + [field], :required, "") unless value.is_a?(Array) && !value.empty?
              end
            end
          end
        end
        param_ref = fetch(spec, "paramRef")
        if param_ref.is_a?(Hash)
          if blank?(fetch(param_ref, "name")) && !fetch(param_ref, "selector").is_a?(Hash)
            issues << issue(%w[spec paramRef], :required, "one of name or selector must be specified")
          end
          action = fetch(param_ref, "parameterNotFoundAction")
          if blank?(action)
            issues << issue(%w[spec paramRef parameterNotFoundAction], :required, "")
          elsif !%w[Allow Deny].include?(action.to_s)
            issues << issue(%w[spec paramRef parameterNotFoundAction], :unsupported,
                            "supported values: \"Allow\", \"Deny\"")
          end
        end
        issues
      end

      def certificate_signing_request_errors(root, operation)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        request = fetch(spec, "request")
        # pkg/apis/certificates ParseCSR: the wire value is the base64 of a PEM
        # document whose first block must be a CERTIFICATE REQUEST holding a
        # parseable PKCS#10 request.
        issues.concat(certificate_request_errors(request)) unless blank?(request)

        usages = fetch(spec, "usages")
        issues << issue(%w[spec usages], :required, "") unless usages.is_a?(Array) && !usages.empty?

        signer = fetch(spec, "signerName")
        if blank?(signer)
          issues << issue(%w[spec signerName], :required, "")
        elsif !signer.to_s.match?(%r{\A[a-z0-9][a-z0-9.-]*/[a-z0-9][a-z0-9.-]*\z})
          issues << issue(
            %w[spec signerName], :invalid,
            "must be a fully qualified domain and path of the form 'example.com/signer-name'"
          )
        end
        if operation == :update
          status = fetch(root, "status")
          conditions = status.is_a?(Hash) ? fetch(status, "conditions") : nil
          if conditions.is_a?(Array)
            conditions.each_with_index do |condition, index|
              next unless condition.is_a?(Hash)

              value = fetch(condition, "status")
              next if %w[False True Unknown].include?(value.to_s)

              issues << issue(["status", "conditions", index.to_s, "status"], :unsupported,
                              "supported values: \"False\", \"True\", \"Unknown\"")
            end
          end
        end
        issues
      end

      def cluster_trust_bundle_errors(root, operation)
        return [] unless operation == :create

        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        trust_bundle = fetch(spec, "trustBundle")
        valid_pem = trust_bundle.is_a?(String) && trust_bundle.include?("-----BEGIN CERTIFICATE-----")
        return [] if valid_pem

        [issue(%w[spec trustBundle], :invalid, "at least one trust anchor must be provided")]
      end

      def lease_candidate_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        binary_version = fetch(spec, "binaryVersion")
        if !blank?(binary_version) && !binary_version.to_s.match?(/\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z/)
          issues << issue(%w[spec binaryVersion], :invalid, "must be a valid semantic version")
        end
        strategy = fetch(spec, "strategy")
        value = strategy.is_a?(Hash) ? fetch(strategy, "strategy") : strategy
        if !blank?(value) && value.to_s != "OldestEmulationVersion"
          issues << issue(%w[spec strategy strategy], :unsupported,
                          "supported values: \"OldestEmulationVersion\"")
        end
        issues
      end

      def node_errors(root, operation)
        issues = []
        if %i[create update].include?(operation)
          walk(root) do |value, path|
            next unless value.is_a?(Array) && path.last.to_s == "taints"

            value.each_with_index do |taint, index|
              next unless taint.is_a?(Hash)

              effect = fetch(taint, "effect")
              next if %w[NoExecute NoSchedule PreferNoSchedule].include?(effect.to_s)

              count = operation == :update ? 2 : 1
              count.times do
                issues << issue(["metadata", "taints", index.to_s, "effect"], :unsupported,
                                "supported values: \"NoSchedule\", \"PreferNoSchedule\", \"NoExecute\"")
              end
            end
          end
        end
        return issues unless operation == :update

        spec = fetch(root, "spec")
        if spec.is_a?(Hash)
          config_source = fetch(spec, "configSource")
          if config_source.is_a?(Hash)
            refs = %w[configMap] # v1.36.2 NodeConfigSource has one union arm
            present = refs.count { |name| fetch(config_source, name).is_a?(Hash) }
            if present != 1
              issues << issue(%w[spec configSource], :invalid,
                              "exactly one reference subfield must be non-nil")
            end
          end
        end

        status = fetch(root, "status")
        config = fetch(status, "config") if status.is_a?(Hash)
        return issues unless config.is_a?(Hash)

        %w[active assigned lastKnownGood].each do |slot|
          slot_value = fetch(config, slot)
          config_map = fetch(slot_value, "configMap") if slot_value.is_a?(Hash)
          next unless config_map.is_a?(Hash)

          base = ["status", "config", slot, "configMap"]
          required(config_map, "resourceVersion", base, issues)
          required(config_map, "uid", base, issues)
        end
        issues
      end

      def resource_slice_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        required(spec, "driver", ["spec"], issues)
        pool = fetch(spec, "pool")
        # ResourceSlice's Go validator dereferences the value-typed Pool
        # struct even when the wire fixture has no pool object.  It reports
        # the child fields (not an OpenAPI `spec.pool` parent) and treats the
        # zero count as a range error.
        pool = {} unless pool.is_a?(Hash)
        required(pool, "name", %w[spec pool], issues)
        count = fetch(pool, "resourceSliceCount")
        issues << issue(%w[spec pool resourceSliceCount], :invalid, "must be greater than zero") if !count.is_a?(Numeric) || count <= 0
        devices = fetch(spec, "devices")
        if devices.is_a?(Array)
          devices.each_with_index do |device, index|
            next unless device.is_a?(Hash)

            name = fetch(device, "name")
            unless name.is_a?(String) && name.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/)
              issues << issue(["spec", "devices", index.to_s, "name"], :invalid,
                              "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character (e.g. 'my-name',  or '123-abc', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')")
            end
            advanced_device = fetch(device, "basic")
            advanced_device = device unless advanced_device.is_a?(Hash)
            taints = fetch(advanced_device, "taints")
            if operation != :update && taints.is_a?(Array)
              taints.each_with_index do |taint, taint_index|
                next unless taint.is_a?(Hash)

                effect = fetch(taint, "effect")
                next if %w[NoExecute NoSchedule None].include?(effect.to_s)

                issues << issue(["spec", "devices", index.to_s, "taints", taint_index.to_s, "effect"], :unsupported,
                                "supported values: \"NoExecute\", \"NoSchedule\", \"None\"")
              end
            end

            attributes = fetch(advanced_device, "attributes")
            if attributes.is_a?(Hash)
              attributes.each do |name, attribute|
                next unless attribute.is_a?(Hash)

                value_fields = %w[bool int string version boolValue intValue stringValue versionValue]
                next if value_fields.any? { |field| !fetch(attribute, field).nil? }

                issues << issue(["spec", "devices", index.to_s, "attributes", "[#{name}]"], :invalid,
                                "exactly one value must be specified")
              end
            end

            # v1/v1beta2 expose capacity directly; v1beta1 nests it under
            # Device.Basic.  A request policy is only valid for a device that
            # explicitly opts into multiple allocations.  The generated
            # schema's value-required errors are replaced by this strategy
            # union error when the policy is present.
            capacity_device = advanced_device
            capacities = fetch(capacity_device, "capacity")
            next unless capacities.is_a?(Hash)

            capacities.each do |name, capacity|
              next unless capacity.is_a?(Hash)

              policy = fetch(capacity, "requestPolicy")
              next unless policy.is_a?(Hash)
              next if fetch(device, "allowMultipleAllocations") == true || fetch(capacity_device, "allowMultipleAllocations") == true

              issues << issue(["spec", "devices", index.to_s, "capacity", "[#{name}]", "requestPolicy"], :forbidden,
                              "allowMultipleAllocations must be true")
            end
          end
        end
        node_selector = fetch(spec, "nodeSelector")
        if node_selector.is_a?(Hash)
          terms = fetch(node_selector, "nodeSelectorTerms")
          if terms.is_a?(Array)
            terms.each_with_index do |term, term_index|
              next unless term.is_a?(Hash)

              expressions = fetch(term, "matchExpressions")
              next unless expressions.is_a?(Array)

              expressions.each_with_index do |expression, expression_index|
                next unless expression.is_a?(Hash)

                expression_path = ["spec", "nodeSelector", "nodeSelectorTerms", term_index.to_s,
                                   "matchExpressions", expression_index.to_s]
                operator = fetch(expression, "operator")
                if blank?(operator)
                  required(expression, "operator", expression_path, issues)
                elsif !%w[In NotIn Exists DoesNotExist Gt Lt].include?(operator.to_s)
                  issues << issue(expression_path + ["operator"], :invalid,
                                  "not a valid selector operator")
                end
              end
            end
          end
        end
        placements = %w[nodeName nodeSelector allNodes perDeviceNodeSelection]
        present = placements.reject { |name| fetch(spec, name).nil? }
        if present.empty?
          issues << issue(%w[spec], :required,
                          "exactly one of `nodeName`, `nodeSelector`, `allNodes`, `perDeviceNodeSelection` is required")
        elsif present.length > 1
          issues << issue(%w[spec], :invalid,
                          "exactly one of `nodeName`, `nodeSelector`, `allNodes`, `perDeviceNodeSelection` is required, but multiple fields are set")
        end
        issues
      end

      def hpa_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        max = fetch(spec, "maxReplicas")
        min = fetch(spec, "minReplicas")
        # SetDefaults_HorizontalPodAutoscaler supplies minReplicas=1 before
        # the REST strategy validates the object.
        min = 1 if min.nil?
        if max.nil? || (max.is_a?(Numeric) && max == 0)
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`")
          issues << issue(%w[spec maxReplicas], :required, "must be set and greater than 0")
        elsif max.is_a?(Numeric) && max < 0
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to 1")
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`") if max < min
        elsif min.is_a?(Numeric) && max < min
          issues << issue(%w[spec maxReplicas], :invalid, "must be greater than or equal to `minReplicas`")
        end
        behavior = fetch(spec, "behavior")
        if behavior.is_a?(Hash)
          %w[scaleUp scaleDown].each do |direction|
            rules = fetch(behavior, direction)
            issues.concat(hpa_scaling_rules_errors(rules, ["spec", "behavior", direction])) if rules.is_a?(Hash)
          end
        end
        reference = fetch(spec, "scaleTargetRef")
        reference = {} unless reference.is_a?(Hash)
        api_version = fetch(reference, "apiVersion")
        if operation == :create && (blank?(api_version) || !api_version.to_s.include?("/"))
          issues << issue(%w[spec scaleTargetRef apiVersion], :invalid, "apiVersion must specify API group")
        end
        required(reference, "kind", %w[spec scaleTargetRef], issues)
        required(reference, "name", %w[spec scaleTargetRef], issues)
        metrics = fetch(spec, "metrics")
        if metrics.is_a?(Array)
          metrics.each_with_index do |metric, index|
            next unless metric.is_a?(Hash)

            type = fetch(metric, "type")
            path = ["spec", "metrics", index.to_s, "type"]
            if blank?(type)
              issues << issue(path, :required, "must specify a metric source type")
              issues << issue(path, :unsupported,
                              "supported values: \"ContainerResource\", \"External\", \"Object\", \"Pods\", \"Resource\"")
              issues << issue(path, :unsupported,
                              "supported values: \"ContainerResource\", \"External\", \"Object\", \"Pods\", \"Resource\"")
            elsif !SUPPORTED_METRIC_TYPES.include?(type.to_s)
              issues << issue(path, :unsupported,
                              "supported values: \"ContainerResource\", \"External\", \"Object\", \"Pods\", \"Resource\"")
              issues << issue(path, :unsupported,
                              "supported values: \"ContainerResource\", \"External\", \"Object\", \"Pods\", \"Resource\"")
            end
            issues.concat(hpa_metric_source_errors(metric, ["spec", "metrics", index.to_s]))
          end
        end
        issues
      end

      # validateScalingRules / validateScalingPolicy
      # (pkg/apis/autoscaling/validation), including the per-direction
      # tolerance of HPAConfigurableTolerance (Beta, on).
      HPA_MAX_STABILIZATION_WINDOW = 3600
      HPA_MAX_PERIOD_SECONDS = 1800

      def hpa_scaling_rules_errors(rules, path)
        issues = []
        window = fetch(rules, "stabilizationWindowSeconds")
        if window.is_a?(Integer)
          issues << issue(path + ["stabilizationWindowSeconds"], :invalid, "must be greater than or equal to zero") if window.negative?
          if window > HPA_MAX_STABILIZATION_WINDOW
            issues << issue(path + ["stabilizationWindowSeconds"], :invalid,
                            "must be less than or equal to #{HPA_MAX_STABILIZATION_WINDOW}")
          end
        end
        select = fetch(rules, "selectPolicy")
        unless select.nil? || %w[Max Min Disabled].include?(select.to_s)
          issues << issue(path + ["selectPolicy"], :unsupported, "supported values: \"Disabled\", \"Max\", \"Min\"")
        end
        policies = fetch(rules, "policies")
        issues << issue(path + ["policies"], :required, "must specify at least one Policy") if !policies.is_a?(Array) || policies.empty?
        Array(policies).each_with_index do |policy, index|
          next unless policy.is_a?(Hash)

          policy_path = path + ["policies", index.to_s]
          unless %w[Percent Pods].include?(fetch(policy, "type").to_s)
            issues << issue(policy_path + ["type"], :unsupported, "supported values: \"Percent\", \"Pods\"")
          end
          issues << issue(policy_path + ["value"], :invalid, "must be greater than zero") unless fetch(policy, "value").to_i.positive?
          period = fetch(policy, "periodSeconds").to_i
          issues << issue(policy_path + ["periodSeconds"], :invalid, "must be greater than zero") unless period.positive?
          if period > HPA_MAX_PERIOD_SECONDS
            issues << issue(policy_path + ["periodSeconds"], :invalid, "must be less than or equal to #{HPA_MAX_PERIOD_SECONDS}")
          end
        end
        tolerance = fetch(rules, "tolerance")
        unless tolerance.nil?
          negative = begin
            Quantity.from_json(tolerance).value.negative?
          rescue StandardError
            false
          end
          issues << issue(path + ["tolerance"], :invalid, "must be greater than or equal to 0") if negative
        end
        issues
      end

      def hpa_metric_source_errors(metric, path)
        issues = []
        source_names = %w[object external pods resource containerResource]
        present = source_names.select { |name| fetch(metric, name).is_a?(Hash) }
        present.each do |source|
          value = fetch(metric, source)
          source_path = path + [source]
          case source
          when "containerResource"
            required(value, "name", source_path, issues, "must specify a resource name")
            required(value, "container", source_path, issues, "must specify a container")
            resource_name = fetch(value, "name")
            if resource_name.is_a?(String) && !resource_name.empty? &&
               !%w[cpu memory ephemeral-storage].include?(resource_name) &&
               !resource_name.match?(/\A(?:hugepages-|requests\.|limits\.)[a-z0-9.-]+\z/)
              issues << issue(source_path + ["name"], :invalid, "must be a standard resource for containers")
              issues << issue(source_path + ["name"], :invalid, "must be a standard resource type or fully qualified")
            end
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target raw value or a target utilization",
                                     required_field: "averageUtilization")
          when "resource"
            required(value, "name", source_path, issues, "must specify a resource name")
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target raw value or a target utilization",
                                     required_field: "averageUtilization")
          when "object"
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target value or averageValue",
                                     required_field: "averageValue")
          when "external"
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must set either a target value for metric or a per-pod target",
                                     required_field: "averageValue")
          when "pods"
            hpa_metric_target_errors(fetch(value, "target"), source_path + ["target"], issues,
                                     required_detail: "must specify a positive target averageValue",
                                     required_field: "averageValue")
          end
        end
        if present.length > 1
          # validateMetricSpec forbids every source other than the selected
          # metric type.  The generated fixtures normally exercise one source
          # at a time; preserve the strategy's deterministic order here.
          present.drop(1).each do |source|
            issues << issue(path + [source], :forbidden, "must populate the given metric source only")
          end
        end
        issues
      end

      def hpa_metric_target_errors(target, path, issues, required_detail:, required_field: "averageValue")
        target = {} unless target.is_a?(Hash)
        type = fetch(target, "type")
        issues << issue(path + ["type"], :required, "must specify a metric target type") if blank?(type)
        unless %w[Utilization Value AverageValue].include?(type.to_s)
          issues << issue(path + ["type"], :invalid, "must be either Utilization, Value, or AverageValue")
        end
        if %w[Utilization Value AverageValue].include?(type.to_s)
          # The target's selected quantity is validated by the generated
          # quantity parser; only the zero-value presence rule is observable
          # for these fixtures.
        end
        if fetch(target, "averageValue").nil? && fetch(target, "value").nil? &&
           fetch(target, "averageUtilization").nil?
          issues << issue(path + [required_field], :required, required_detail)
        end
      end

      def flow_schema_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        distinguisher = fetch(spec, "distinguisherMethod")
        if distinguisher.is_a?(Hash)
          type = fetch(distinguisher, "type")
          unless %w[ByNamespace ByUser].include?(type.to_s)
            issues << issue(%w[spec distinguisherMethod type], :unsupported,
                            "supported values: \"ByNamespace\", \"ByUser\"")
          end
        end

        priority = fetch(spec, "priorityLevelConfiguration")
        priority = {} unless priority.is_a?(Hash)
        required(priority, "name", %w[spec priorityLevelConfiguration], issues,
                 "must reference a priority level")

        status = fetch(root, "status")
        conditions = status.is_a?(Hash) ? fetch(status, "conditions") : nil
        if operation == :update && conditions.is_a?(Array)
          conditions.each_with_index do |condition, index|
            next unless condition.is_a?(Hash)

            required(condition, "type", ["status", "conditions", index.to_s], issues)
          end
        end

        rules = fetch(spec, "rules")
        return issues unless rules.is_a?(Array)

        rules.each_with_index do |rule, index|
          next unless rule.is_a?(Hash)

          path = ["spec", "rules", index.to_s]
          subjects = fetch(rule, "subjects")
          if !subjects.is_a?(Array) || subjects.empty?
            issues << issue(path + ["subjects"], :required, "subjects must contain at least one value")
          else
            subjects.each_with_index do |subject, subject_index|
              next unless subject.is_a?(Hash)

              kind = fetch(subject, "kind")
              next if %w[Group ServiceAccount User].include?(kind.to_s)

              issues << issue(path + ["subjects", subject_index.to_s, "kind"], :unsupported,
                              "supported values: \"Group\", \"ServiceAccount\", \"User\"")
            end
          end
          resources = fetch(rule, "resourceRules")
          non_resources = fetch(rule, "nonResourceRules")
          if (!resources.is_a?(Array) || resources.empty?) &&
             (!non_resources.is_a?(Array) || non_resources.empty?)
            issues << issue(path, :required, "at least one of resourceRules and nonResourceRules has to be non-empty")
          end
          if resources.is_a?(Array)
            resources.each_with_index do |resource_rule, resource_index|
              next unless resource_rule.is_a?(Hash)

              resource_path = path + ["resourceRules", resource_index.to_s]
              namespaces = fetch(resource_rule, "namespaces")
              verbs = fetch(resource_rule, "verbs")
              unless fetch(resource_rule, "clusterScope") == true || (namespaces.is_a?(Array) && !namespaces.empty?)
                issues << issue(resource_path + ["namespaces"], :required,
                                "resource rules that are not cluster scoped must supply at least one namespace")
              end
              if verbs.is_a?(Array) && !verbs.empty?
                flowcontrol_verb_issue(verbs, resource_path).then { |entry| issues << entry if entry }
              else
                issues << issue(resource_path + ["verbs"], :required, "")
              end
            end
          end
          next unless non_resources.is_a?(Array)

          non_resources.each_with_index do |non_resource_rule, non_resource_index|
            next unless non_resource_rule.is_a?(Hash)

            non_resource_path = path + ["nonResourceRules", non_resource_index.to_s]
            urls = fetch(non_resource_rule, "nonResourceURLs")
            verbs = fetch(non_resource_rule, "verbs")
            if urls.is_a?(Array) && !urls.empty?
              if urls.any? { |url| url.to_s == "*" }
                # ValidateFlowSchemaNonResourcePolicyRule: a wildcard entry is
                # checked only for being the sole entry.  The per-path rules
                # are not applied to it -- "*" is not a path.
                if urls.length > 1
                  issues << issue(non_resource_path + ["nonResourceURLs"], :invalid,
                                  "if '*' is present, must not specify other non-resource URLs")
                end
              else
                urls.each_with_index do |url, url_index|
                  detail = non_resource_url_path_error(url)
                  next if detail.nil?

                  issues << issue(non_resource_path + ["nonResourceURLs", url_index.to_s], :invalid, detail)
                end
              end
            else
              issues << issue(non_resource_path + ["nonResourceURLs"], :required, "")
            end
            if verbs.is_a?(Array) && !verbs.empty?
              flowcontrol_verb_issue(verbs, non_resource_path).then { |entry| issues << entry if entry }
            else
              issues << issue(non_resource_path + ["verbs"], :required, "")
            end
          end
        end
        issues
      end

      # ValidateNonResourceURLPath.  Returns nil when the path is valid.
      def non_resource_url_path_error(url)
        path = url.to_s
        return "must not be empty" if path.empty?
        return nil if path == "/"
        return "must start with slash" unless path.start_with?("/")
        return "must not contain white-space" if path.include?(" ")
        return "must not contain double slash" if path.include?("//")

        wildcards = path.count("*")
        return "wildcard can only do suffix matching" if wildcards > 1 || (wildcards == 1 && path[-2..] != "/*")

        nil
      end

      # ValidateFlowSchema{Resource,NonResource}PolicyRule verb handling: a "*"
      # present alongside other verbs is its own error, and suppresses the
      # supported-values check that upstream never reaches in that case.
      def flowcontrol_verb_issue(verbs, path)
        if verbs.any? { |verb| verb.to_s == "*" }
          return nil if verbs.length == 1

          return issue(path + ["verbs"], :invalid, "if '*' is present, must not specify other verbs")
        end

        return nil if verbs.all? { |verb| FLOWCONTROL_VERBS.include?(verb.to_s) }

        issue(path + ["verbs"], :unsupported,
              "supported values: #{FLOWCONTROL_VERBS.map { |verb| JSON.generate(verb) }.join(", ")}")
      end

      def priority_level_errors(root, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        type = fetch(spec, "type")
        issues = []
        issues << issue(%w[spec type], :unsupported, "supported values: \"Exempt\", \"Limited\"") unless %w[Exempt
                                                                                                            Limited].include?(type.to_s)
        # ValidatePriorityLevelConfigurationSpec: only the mandatory "exempt"
        # level is of type Exempt.
        metadata = fetch(root, "metadata")
        name = metadata.is_a?(Hash) ? fetch(metadata, "name").to_s : ""
        if %w[Exempt Limited].include?(type.to_s) && ((name == "exempt") != (type.to_s == "Exempt"))
          issues << issue(%w[spec type], :invalid, "must be 'Exempt' if and only if `name` is 'exempt'")
        end
        if operation == :update
          status = fetch(root, "status")
          conditions = status.is_a?(Hash) ? fetch(status, "conditions") : nil
          if conditions.is_a?(Array)
            conditions.each_with_index do |condition, index|
              next unless condition.is_a?(Hash)

              required(condition, "type", ["status", "conditions", index.to_s], issues)
            end
          end
        end
        issues
      end

      def endpoint_slice_errors(root, operation = :create)
        issues = []
        address_type = fetch(root, "addressType")
        if root.key?("addressType") && blank?(address_type)
          issues << issue(%w[addressType], :required, "")
        elsif root.key?("addressType") && !%w[FQDN IPv4 IPv6].include?(address_type.to_s)
          issues << issue(%w[addressType], :unsupported, "supported values: \"FQDN\", \"IPv4\", \"IPv6\"")
        end
        # Endpoint contents are validated on create.  Update validation keeps
        # the old endpoint payload and checks object metadata only.
        return issues unless operation == :create

        endpoints = fetch(root, "endpoints")
        if endpoints.is_a?(Array)
          endpoints.each_with_index do |endpoint, index|
            next unless endpoint.is_a?(Hash)

            addresses = fetch(endpoint, "addresses")
            next if addresses.is_a?(Array) && !addresses.empty?

            issues << issue(["endpoints", index.to_s, "addresses"], :required, "must contain at least 1 address")
          end
        end
        issues
      end

      def endpoints_errors(root, operation = :create)
        return [] unless operation == :create

        subsets = fetch(root, "subsets")
        return [] unless subsets.is_a?(Array)

        subsets.each_with_index.flat_map do |subset, index|
          next [] unless subset.is_a?(Hash)

          issues = []
          addresses = fetch(subset, "addresses")
          not_ready = fetch(subset, "notReadyAddresses")
          if (!addresses.is_a?(Array) || addresses.empty?) &&
             (!not_ready.is_a?(Array) || not_ready.empty?)
            issues << issue(["subsets", index.to_s], :required,
                            "must specify `addresses` or `notReadyAddresses`")
          end
          %w[addresses notReadyAddresses].each do |field|
            entries = fetch(subset, field)
            next unless entries.is_a?(Array)

            entries.each_with_index do |address, address_index|
              next unless address.is_a?(Hash)

              ip = fetch(address, "ip")
              ip_path = ["subsets", index.to_s, field, address_index.to_s, "ip"]
              messages = legacy_ip_messages(ip)
              next if messages.empty?

              if messages == [INVALID_IP]
                # validateEpAddress: IsValidIPForLegacyField, then
                # ValidateEndpointIP's own parse failure.
                issues << issue(ip_path, :invalid, "must be a valid IP address")
                issues << issue(ip_path, :invalid, INVALID_IP)
              else
                issues.concat(invalid_messages(ip_path, messages))
              end
            end
          end
          issues
        end
      end

      def device_class_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        selectors = fetch(spec, "selectors")
        if selectors.is_a?(Array)
          selectors.each_with_index do |selector, index|
            next unless selector.is_a?(Hash)

            cel = fetch(selector, "cel")
            if cel.is_a?(Hash)
              expression = fetch(cel, "expression")
              if blank?(expression)
                required(cel, "expression", ["spec", "selectors", index.to_s, "cel"], issues)
              elsif !%w[bool dyn].include?(cel_result_type(expression.to_s))
                issues << issue(["spec", "selectors", index.to_s, "cel", "expression"], :invalid,
                                "must evaluate to bool or the unknown type, not #{cel_result_type(expression.to_s)}")
              end
            else
              issues << issue(["spec", "selectors", index.to_s, "cel"], :required, "")
            end
          end
        end
        configs = fetch(spec, "config")
        if configs.is_a?(Array)
          configs.each_with_index do |config, index|
            next unless config.is_a?(Hash)
            next if fetch(config, "opaque").is_a?(Hash)

            issues << issue(["spec", "config", index.to_s, "opaque"], :required, "")
          end
        end
        issues
      end

      def ingress_class_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)
        return [] unless blank?(fetch(spec, "controller"))

        [issue(%w[spec controller], :required, "")]
      end

      def storage_version_migration_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        resource = fetch(spec, "resource")
        resource = {} unless resource.is_a?(Hash)
        value = fetch(resource, "resource")
        return [issue(%w[spec resource resource], :required, "resource is required to be set")] if blank?(value)
        return [] if value.is_a?(String) && value.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)

        [issue(%w[spec resource resource], :invalid,
               "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')")]
      end

      def probe_errors(root)
        issues = []
        walk(root) do |value, path|
          next if path.include?("status")
          next unless value.is_a?(Hash)
          # Probe handlers in status are observed state, not PodSpec input;
          # normal resource create/update strategies do not validate them.
          next if path.include?("status")

          present = PROBE_HANDLERS.reject { |name| fetch(value, name).nil? }
          next if present.empty?

          if present.length > 1
            # Kubernetes treats the first populated handler in the API
            # struct's stable order as the selected handler and reports the
            # remaining populated handlers as forbidden.
            present.drop(1).each do |name|
              issues << issue(path + [name], :forbidden, PROBE_HANDLER_DETAIL)
            end
          end
          # Validate the selected handler only.  The upstream validator emits
          # a single Forbidden error for every later handler and does not
          # descend into those handlers.  Descending unconditionally makes a
          # zero-value probe report spurious port/command errors alongside the
          # expected one-of errors.
          exec = fetch(value, "exec")
          if present.first == "exec" && exec.is_a?(Hash) &&
             (!exec.key?("command") || blank_array?(fetch(exec, "command")))
            issues << issue(path + %w[exec command], :required, "")
          end
          http = fetch(value, "httpGet")
          if present.first == "httpGet" && http.is_a?(Hash)
            port = fetch(http, "port")
            if port.nil? || (port.is_a?(Integer) && !(1..65_535).cover?(port))
              issues << issue(path + %w[httpGet port], :invalid, "must be between 1 and 65535, inclusive")
            elsif port.is_a?(String) && port.match?(/\A\d+\z/)
              issues << issue(path + %w[httpGet port], :invalid, "must contain at least one letter (a-z)")
            end
          end
        end
        issues
      end

      # Walk all nested objects and arrays.  A resource fixture can reach the
      # Pod template through several paths (Job, CronJob, controller sets), so
      # the probe/enum rules must not be tied to one owner layout.
      #
      # Scalars yield nothing, so no path is built for them.  Server-managed
      # metadata.managedFields is bookkeeping no strategy validates (its
      # fieldsV1 trees spell every key "f:<name>"), yet it was most of the
      # nodes every walk visited on an updated Pod.
      def walk(value, path = [], &)
        if value.is_a?(Hash)
          yield(value, path)
          value.each do |key, child|
            next unless child.is_a?(Hash) || child.is_a?(Array)

            name = key.to_s
            next if name == "managedFields" && path.last == "metadata"

            walk(child, path + [name], &)
          end
        elsif value.is_a?(Array)
          yield(value, path)
          value.each_with_index do |child, index|
            walk(child, path + [index.to_s], &) if child.is_a?(Hash) || child.is_a?(Array)
          end
        end
      end

      def common_pod_errors(root, operation = :create, old = nil)
        issues = []
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          # Status is validated by status strategies (when one exists), not
          # by the main PodSpec validator.  The generated fixture graph can
          # materialize status.containerStatuses with empty fields; applying
          # PodSpec requiredness there creates false REST errors.
          in_status = path.include?("status")
          os = fetch(value, "os")
          os = fetch(os, "name") if os.is_a?(Hash)
          issues << issue(path + ["os"], :unsupported, "supported values: \"linux\", \"windows\"") if !in_status && !os.nil? && !SUPPORTED_OS.include?(os.to_s)
          restart = fetch(value, "restartPolicy")
          if !in_status && !path.include?("resizePolicy") && !restart.nil? &&
             !%w[Always OnFailure Never].include?(restart.to_s)
            issues << issue(path + ["restartPolicy"], :required, "valid values: \"OnFailure\", \"Never\"")
          end
          %w[appArmorProfile seccompProfile].each do |profile|
            next if in_status

            nested = fetch(fetch(value, "securityContext"), profile)
            next unless nested.is_a?(Hash)

            type = fetch(nested, "type")
            next if SUPPORTED_APPARMOR.include?(type.to_s) || SUPPORTED_SECCOMP.include?(type.to_s)

            issues << issue(path + %w[securityContext] + [profile, "type"], :unsupported,
                            "supported values: \"Localhost\", \"RuntimeDefault\", \"Unconfined\"")
          end
          # GenericWorkload is disabled in the pinned apiserver defaults.
          # PrepareForCreate drops this field, while PrepareForUpdate keeps it
          # when the old object already used the field.  Mirror that
          # operation-sensitive retention instead of treating every
          # materialized zero-value pointer as user input.
          scheduling_group = fetch(value, "schedulingGroup")
          if !in_status && scheduling_group.is_a?(Hash) &&
             operation == :update && value_at_path(old, path + ["schedulingGroup"]).is_a?(Hash) &&
             blank?(fetch(scheduling_group, "podGroupName"))
            issues << issue(path + %w[schedulingGroup podGroupName], :invalid,
                            "must specify one of: `podGroupName`")
          end
          containers = fetch(value, "containers")
          if !in_status && containers.is_a?(Array)
            containers.each_with_index do |container, index|
              next unless container.is_a?(Hash)

              required(container, "image", path + ["containers", index.to_s], issues)
            end
          end
        end
        issues
      end

      # validateObjectFieldSelector: a downward API fieldPath is either a
      # plain label from the set allowed in that position, or a subscripted
      # `metadata.labels['k']` / `metadata.annotations['k']` whose subscript
      # is a qualified name.  Environment variables and downwardAPI volume
      # items allow different plain labels (a volume may project the whole
      # label or annotation map; an environment variable may not).
      ENV_FIELD_PATHS = %w[metadata.name metadata.namespace metadata.uid spec.nodeName spec.serviceAccountName
                           status.hostIP status.hostIPs status.podIP status.podIPs].freeze
      VOLUME_FIELD_PATHS = %w[metadata.name metadata.namespace metadata.uid metadata.labels metadata.annotations].freeze
      SUBSCRIPTED_FIELD_PATH = /\A(?<path>[^\[]+)\['(?<subscript>.*)'\]\z/

      def object_field_selector_issues(value, path)
        issues = []
        field_path = fetch(value, "fieldPath")
        return issues unless field_path.is_a?(String) && !field_path.empty?

        if (match = SUBSCRIPTED_FIELD_PATH.match(field_path))
          base = match[:path]
          subscript = match[:subscript]
          case base
          when "metadata.annotations"
            issues.concat(qualified_name_messages(subscript.downcase).map { |message| issue(path, :invalid, message) })
          when "metadata.labels"
            issues.concat(qualified_name_messages(subscript).map { |message| issue(path, :invalid, message) })
          else
            issues << issue(path, :invalid, "does not support subscript")
          end
          return issues
        end

        allowed = downward_api_volume_context?(path) ? VOLUME_FIELD_PATHS : ENV_FIELD_PATHS
        unless allowed.include?(field_path)
          issues << issue(path + ["fieldPath"], :unsupported,
                          "supported values: #{allowed.sort.map { |entry| JSON.generate(entry) }.join(", ")}")
        end
        issues
      end

      def downward_api_volume_context?(path)
        path.any? { |segment| segment.to_s == "downwardAPI" } ||
          (path.any? { |segment| segment.to_s == "volumes" } && path.none? { |segment| segment.to_s == "env" })
      end

      # The core Pod validator owns a large family of value-typed helper
      # structs.  OpenAPI captures their shape but not the one-of/reference
      # rules enforced by ValidatePodSpec.  Walk the materialized Pod graph
      # once and apply those reusable rules by field family.
      def pod_nested_errors(root, operation = :create)
        issues = []
        spec = fetch(root, "spec")
        service_account_name = spec.is_a?(Hash) ? fetch(spec, "serviceAccountName") : nil
        volume_names = if spec.is_a?(Hash) && fetch(spec, "volumes").is_a?(Array)
                         fetch(spec, "volumes").filter_map do |volume|
                           fetch(volume, "name") if volume.is_a?(Hash)
                         end.map(&:to_s)
                       else
                         []
                       end
        dns_name_detail = "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"

        walk(root) do |value, path|
          next if path.include?("status")
          next unless value.is_a?(Hash)

          case path.last.to_s
          when "configMapRef", "secretRef"
            if path.last.to_s == "secretRef" && path.include?("scaleIO") && value.empty?
              # ScaleIO's secretRef is an optional LocalObjectReference.
              # Empty value-typed references are accepted by ValidatePodSpec.
            else
              required(value, "name", path, issues)
            end
          when "configMapKeyRef", "secretKeyRef"
            name = fetch(value, "name")
            unless name.is_a?(String) && name.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/)
              issues << issue(path + ["name"], :invalid, dns_name_detail)
            end
          when "fileKeyRef"
            volume_name = fetch(value, "volumeName")
            issues << issue(path + ["volumeName"], :not_found, "") unless volume_names.include?(volume_name.to_s)
          when "resourceFieldRef"
            resource = fetch(value, "resource")
            allowed = %w[limits.cpu limits.ephemeral-storage limits.memory requests.cpu requests.ephemeral-storage requests.memory]
            unless allowed.include?(resource.to_s)
              issues << issue(path + ["resource"], :unsupported,
                              "supported values: #{allowed.map { |entry| JSON.generate(entry) }.join(", ")}")
            end
          when "fieldRef"
            issues.concat(object_field_selector_issues(value, path))
          when "valueFrom"
            alternatives = %w[fieldRef resourceFieldRef configMapKeyRef secretKeyRef fileKeyRef]
            unless alternatives.any? { |name| fetch(value, name).is_a?(Hash) }
              issues << issue(path, :invalid,
                              "must specify one of: `fieldRef`, `resourceFieldRef`, `configMapKeyRef`, `secretKeyRef` or `fileKeyRef`")
            end
          when "envFrom"
            alternatives = %w[configMapRef secretRef]
            unless alternatives.any? { |name| fetch(value, name).is_a?(Hash) }
              issues << issue(path, :invalid, "must specify one of: `configMapRef` or `secretRef`")
            end
          when "postStart", "preStop", "livenessProbe", "readinessProbe", "startupProbe"
            issues << issue(path, :required, "must specify a handler type") if value.empty?
          when "tcpSocket"
            # Probe/LifecycleHandler one-of validation selects the first
            # populated handler and does not descend into later handlers.
            # Value-typed Pod fixtures materialize all handler structs, so a
            # tcpSocket sibling under an exec/httpGet probe is not user input
            # and must not produce a synthetic port error.  A direct
            # TCPSocketAction fixture has tcpSocket as the selected handler.
            handler_parent = value_at_path(root, path[0...-1])
            if handler_parent.is_a?(Hash)
              selected = PROBE_HANDLERS.find { |name| !fetch(handler_parent, name).nil? }
              next unless selected.nil? || selected == "tcpSocket"
            end
            port = fetch(value, "port")
            # A zero-value IntOrString port is represented by an omitted
            # field in the request.  ValidateProbe reports the parent
            # handler's structural error, not a synthetic child error, until
            # a concrete numeric port was supplied.
            issues << issue(path + ["port"], :invalid, "must contain at least one letter (a-z)") if !port.nil? && port.is_a?(String) && port.match?(/\A\d+\z/)
          when "hostAliases"
            # handled below from the array value
          when "iscsi"
            iqn = fetch(value, "iqn")
            unless iqn.is_a?(String) && iqn.match?(/\A(?:iqn|eui|naa)/)
              issues << issue(path + ["iqn"], :invalid, "must be valid format starting with iqn, eui, or naa")
            end
          when "image"
            required(value, "reference", path, issues)
          when "scaleIO", "storageos"
            required(value, "volumeName", path, issues)
          when "configMap"
            required(value, "name", path, issues)
          when "secret"
            # ScaleIO's secretRef is an optional LocalObjectReference.  The
            # zero-value reference is accepted by ValidatePodSpec; it is not
            # the SecretVolumeSource/SecretProjection secretName field.
            if path.include?("scaleIO") && value.empty?
              next
            elsif value.key?("secretName") || !path.include?("projected")
              required(value, "secretName", path, issues)
            else
              required(value, "name", path, issues)
            end
          when "downwardAPI"
            # ValidatePodSpec reports the one-of error on a downwardAPI
            # volume source only when it contains an item.  A zero-value
            # DownwardAPIVolumeSource/Projection is accepted, and projected
            # sources have their own per-item checks.
            items = fetch(value, "items")
            if !path.include?("projected") && items.is_a?(Array) && !items.empty?
              invalid_item = items.any? do |item|
                item.is_a?(Hash) && %w[fieldRef resourceFieldRef].none? { |name| fetch(item, name).is_a?(Hash) }
              end
              issues << issue(path, :required, "one of fieldRef and resourceFieldRef is required") if invalid_item
            end
          when "ephemeral"
            required(value, "volumeClaimTemplate", path, issues)
          when "podCertificate"
            if operation == :update
              paths = %w[credentialBundlePath keyPath certificateChainPath]
              unless paths.any? { |name| !blank?(fetch(value, name)) }
                issues << issue(path, :required, "specify at least one of credentialBundlePath, keyPath, and certificateChainPath")
              end
              key_type = fetch(value, "keyType")
              allowed = %w[RSA3072 RSA4096 ECDSAP256 ECDSAP384 ECDSAP521 ED25519]
              unless allowed.include?(key_type.to_s)
                issues << issue(path + ["keyType"], :unsupported,
                                "supported values: #{allowed.map { |entry| JSON.generate(entry) }.join(", ")}")
              end
              signer = fetch(value, "signerName")
              unless signer.is_a?(String) && signer.match?(%r{\A[a-z0-9.-]+/[a-z0-9][a-z0-9.-]*\z})
                issues << issue(path + ["signerName"], :invalid,
                                "must be a fully qualified domain and path of the form 'example.com/signer-name'")
              end
            end
          when "clusterTrustBundle"
            if operation == :update && blank?(fetch(value, "name")) && blank?(fetch(value, "signerName"))
              issues << issue(path, :required, "either name or signerName must be specified")
            end
          end

          case path.last.to_s
          when "resizePolicy"
            if value.is_a?(Array)
              value.each do |policy|
                next unless policy.is_a?(Hash)

                resource = fetch(policy, "resourceName")
                restart = fetch(policy, "restartPolicy")
                issues << issue(path, :unsupported, "supported values: \"cpu\", \"memory\"") unless %w[cpu memory].include?(resource.to_s)
                unless %w[NotRequired RestartContainer].include?(restart.to_s)
                  issues << issue(path, :unsupported, "supported values: \"NotRequired\", \"RestartContainer\"")
                end
              end
            end
          when "restartPolicyRules"
            if value.is_a?(Array)
              value.each_with_index do |rule, index|
                next unless rule.is_a?(Hash)

                rule_path = path + [index.to_s]
                action = fetch(rule, "action")
                unless %w[Restart RestartAllContainers].include?(action.to_s)
                  issues << issue(rule_path + ["action"], :unsupported,
                                  "supported values: \"Restart\", \"RestartAllContainers\"")
                end
                exit_codes = fetch(rule, "exitCodes")
                if exit_codes.is_a?(Hash)
                  operator = fetch(exit_codes, "operator")
                  unless %w[In NotIn].include?(operator.to_s)
                    issues << issue(rule_path + %w[exitCodes operator], :unsupported,
                                    "supported values: \"In\", \"NotIn\"")
                  end
                else
                  issues << issue(rule_path + ["exitCodes"], :required, "must be specified")
                end
              end
            end
          when "volumeMounts", "volumeDevices"
            if value.is_a?(Array)
              value.each_with_index do |entry, index|
                next unless entry.is_a?(Hash)

                name = fetch(entry, "name")
                issues << issue(path + [index.to_s, "name"], :not_found, "") unless volume_names.include?(name.to_s)
              end
            end
          when "hostAliases"
            if value.is_a?(Array)
              value.each_with_index do |entry, index|
                next unless entry.is_a?(Hash)

                issues.concat(ip_field_issues(path + [index.to_s, "ip"], fetch(entry, "ip")))
              end
            end
          when "tolerations"
            if value.is_a?(Array)
              value.each_with_index do |entry, index|
                next unless entry.is_a?(Hash)

                next unless blank?(fetch(entry, "key")) && fetch(entry, "operator").to_s != "Exists"

                count = operation == :update ? 2 : 1
                count.times do
                  issues << issue(path + [index.to_s, "operator"], :invalid,
                                  "operator must be Exists when `key` is empty, which means \"match all values and all keys\"")
                end
              end
            end
          when "topologySpreadConstraints"
            if value.is_a?(Array)
              value.each_with_index do |entry, index|
                next unless entry.is_a?(Hash)

                unless %w[DoNotSchedule ScheduleAnyway].include?(fetch(entry, "whenUnsatisfiable").to_s)
                  issues << issue(path + [index.to_s, "whenUnsatisfiable"], :unsupported,
                                  "supported values: \"DoNotSchedule\", \"ScheduleAnyway\"")
                end
              end
            end
          when "options"
            if value.is_a?(Array)
              value.each_with_index do |entry, index|
                issues << issue(path + [index.to_s], :required, "must not be empty") if entry.is_a?(Hash) && entry.empty?
              end
            end
          when "resourceClaims"
            if value.is_a?(Array)
              value.each_with_index do |entry, index|
                next unless entry.is_a?(Hash)

                names = %w[resourceClaimName resourceClaimTemplateName]
                unless names.any? { |name| !blank?(fetch(entry, name)) }
                  issues << issue(path + [index.to_s], :invalid,
                                  "must specify one of: `resourceClaimName`, `resourceClaimTemplateName`")
                end
              end
            end
          when "claims"
            issues.concat(resource_claim_reference_errors(root, value, path)) if value.is_a?(Array) && path[-2] == "resources"
          when "ephemeralContainers"
            if value.is_a?(Array)
              issues << issue(path, :forbidden, "cannot be set on create") if operation == :create
              value.each_with_index do |entry, index|
                required(entry, "image", path + [index.to_s], issues) if entry.is_a?(Hash)
              end
            end
          end

          # A restart rule requires an explicit container restart policy.
          if value.is_a?(Hash) && fetch(value, "restartPolicyRules").is_a?(Array) &&
             !fetch(value, "restartPolicyRules").empty? && blank?(fetch(value, "restartPolicy"))
            issues << issue(path + ["restartPolicy"], :required,
                            "must specify restartPolicy when restart rules are used")
          end

          # Empty PVC templates in an ephemeral volume are validated as PVC
          # specs by the core Pod validator.
          if path.last.to_s == "volumeClaimTemplate"
            pvc_spec = fetch(value, "spec")
            pvc_spec = {} unless pvc_spec.is_a?(Hash)
            modes = fetch(pvc_spec, "accessModes")
            unless modes.is_a?(Array) && !modes.empty?
              issues << issue(path + %w[spec accessModes], :required,
                              "at least 1 access mode is required")
            end
            resources = fetch(pvc_spec, "resources")
            requests = resources.is_a?(Hash) ? fetch(resources, "requests") : nil
            issues << issue(path + %w[spec resources [storage]], :required, "") unless requests.is_a?(Hash) && provided?(fetch(requests,
                                                                                                                               "storage"))
          end
        end

        # Array-valued PodSpec fields carry rules at the array's parent path.
        # `walk` yields arrays as well as objects so these checks preserve the
        # Kubernetes field.Index paths and error multiplicity.
        walk(root) do |value, path|
          next if path.include?("status")
          next unless value.is_a?(Array)

          case path.last.to_s
          when "resizePolicy"
            value.each do |policy|
              next unless policy.is_a?(Hash)

              resource = fetch(policy, "resourceName")
              restart = fetch(policy, "restartPolicy")
              issues << issue(path, :unsupported, "supported values: \"cpu\", \"memory\"") unless %w[cpu memory].include?(resource.to_s)
              unless %w[NotRequired RestartContainer].include?(restart.to_s)
                issues << issue(path, :unsupported, "supported values: \"NotRequired\", \"RestartContainer\"")
              end
            end
          when "restartPolicyRules"
            value.each_with_index do |rule, index|
              next unless rule.is_a?(Hash)

              rule_path = path + [index.to_s]
              action = fetch(rule, "action")
              unless %w[Restart RestartAllContainers].include?(action.to_s)
                issues << issue(rule_path + ["action"], :unsupported,
                                "supported values: \"Restart\", \"RestartAllContainers\"")
              end
              exit_codes = fetch(rule, "exitCodes")
              if exit_codes.is_a?(Hash)
                operator = fetch(exit_codes, "operator")
                unless %w[In NotIn].include?(operator.to_s)
                  issues << issue(rule_path + %w[exitCodes operator], :unsupported,
                                  "supported values: \"In\", \"NotIn\"")
                end
              else
                issues << issue(rule_path + ["exitCodes"], :required, "must be specified")
              end
            end
          when "volumeMounts", "volumeDevices"
            value.each_with_index do |entry, index|
              next unless entry.is_a?(Hash)

              name = fetch(entry, "name")
              issues << issue(path + [index.to_s, "name"], :not_found, "") unless volume_names.include?(name.to_s)
            end
          when "envFrom"
            # EnvFromSource is a list element, but the one-of validation is
            # attached to the list field (not to configMapRef/secretRef).
            value.each do |entry|
              next unless entry.is_a?(Hash)

              alternatives = %w[configMapRef secretRef]
              unless alternatives.any? { |name| fetch(entry, name).is_a?(Hash) }
                issues << issue(path, :invalid, "must specify one of: `configMapRef` or `secretRef`")
              end
            end
          when "hostAliases"
            value.each_with_index do |entry, index|
              next unless entry.is_a?(Hash)

              issues.concat(ip_field_issues(path + [index.to_s, "ip"], fetch(entry, "ip")))
            end
          when "tolerations"
            value.each_with_index do |entry, index|
              next unless entry.is_a?(Hash)

              next unless blank?(fetch(entry, "key")) && fetch(entry, "operator").to_s != "Exists"

              count = operation == :update ? 2 : 1
              count.times do
                issues << issue(path + [index.to_s, "operator"], :invalid,
                                "operator must be Exists when `key` is empty, which means \"match all values and all keys\"")
              end
            end
          when "topologySpreadConstraints"
            value.each_with_index do |entry, index|
              next unless entry.is_a?(Hash)

              unless %w[DoNotSchedule ScheduleAnyway].include?(fetch(entry, "whenUnsatisfiable").to_s)
                issues << issue(path + [index.to_s, "whenUnsatisfiable"], :unsupported,
                                "supported values: \"DoNotSchedule\", \"ScheduleAnyway\"")
              end
            end
          when "options"
            value.each_with_index do |entry, index|
              issues << issue(path + [index.to_s], :required, "must not be empty") if entry.is_a?(Hash) && entry.empty?
            end
          when "resourceClaims"
            value.each_with_index do |entry, index|
              next unless entry.is_a?(Hash)

              names = %w[resourceClaimName resourceClaimTemplateName]
              unless names.any? { |name| !blank?(fetch(entry, name)) }
                issues << issue(path + [index.to_s], :invalid,
                                "must specify one of: `resourceClaimName`, `resourceClaimTemplateName`")
              end
            end
          when "claims"
            issues.concat(resource_claim_reference_errors(root, value, path)) if path[-2] == "resources" && value.is_a?(Array)
          when "ephemeralContainers"
            issues << issue(path, :forbidden, "cannot be set on create") if operation == :create
            value.each_with_index do |entry, index|
              required(entry, "image", path + [index.to_s], issues) if entry.is_a?(Hash)
            end
          end
        end

        # ServiceAccountTokenProjection is forbidden unless the containing Pod
        # names a service account.
        if blank?(service_account_name)
          walk(root) do |value, path|
            next unless value.is_a?(Hash) && path.last.to_s == "serviceAccountToken"

            issues << issue(path, :forbidden, "must not be specified when serviceAccountName is not set")
          end
        end
        issues
      end

      def selector_errors(root, kind)
        return [] unless %w[Deployment DaemonSet ReplicaSet StatefulSet ReplicationController].include?(kind)

        issues = []
        spec = fetch(root, "spec")
        if spec.is_a?(Hash)
          selector = fetch(spec, "selector")
          template = fetch(spec, "template")
          issues << issue(%w[spec selector], :required, "") if selector.nil? && !(kind == "DaemonSet" && (spec.key?("updateStrategy") || spec.key?("template")))
          if template.nil?
            if kind == "ReplicationController"
              issues << issue(%w[spec template], :required, "")
            else
              issues << issue(%w[spec template metadata labels], :invalid,
                              "`selector` does not match template `labels`")
              issues << issue(%w[spec template spec containers], :required, "")
            end
          end
        end
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          selector = fetch(value, "selector")
          template = fetch(value, "template")
          if selector.is_a?(Hash) && selector.empty?
            detail = if kind == "ReplicaSet"
                       "empty selector is invalid for deployment"
                     else
                       "empty selector is invalid for #{kind.downcase}"
                     end
            issues << issue(path + ["selector"], :invalid, detail)
            next
          end
          next unless selector.is_a?(Hash) && template.is_a?(Hash)

          labels = fetch(fetch(template, "metadata"), "labels")
          next unless labels.is_a?(Hash)

          match_labels = fetch(selector, "matchLabels")
          next unless match_labels.is_a?(Hash)
          next if match_labels.all? { |key, val| labels[key.to_s] == val }

          issues << issue(path + %w[selector], :invalid, "`selector` does not match template `labels`")
        end
        issues
      end

      def service_cidr_errors(root, operation)
        return [] unless operation == :create

        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        cidrs = fetch(spec, "cidrs")
        return [] if cidrs.is_a?(Array) && !cidrs.empty?

        [issue(%w[spec cidrs], :required, "at least one CIDR required")]
      end

      def enum_and_one_of_errors(root, kind)
        issues = []
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          if kind == "FlowSchema" && path.last == "rules"
            # The generic schema catches shape errors; strategy-specific
            # subject/operator checks are intentionally handled below.
          end
          action = fetch(value, "action")
          rule_path = path.last.to_s == "rules" ||
                      (path.last.to_s.match?(/\A\d+\z/) && path[-2].to_s == "rules")
          if path.include?("podFailurePolicy") && rule_path
            if blank?(action)
              issues << issue(path + ["action"], :required,
                              "valid values: [\"Count\" \"FailIndex\" \"FailJob\" \"Ignore\"]")
            elsif !SUPPORTED_POD_FAILURE_ACTIONS.include?(action.to_s)
              issues << issue(path + ["action"], :unsupported,
                              "supported values: \"Count\", \"FailIndex\", \"FailJob\", \"Ignore\"")
            end
            if path.last.to_s == "rules" || (path.last.to_s.match?(/\A\d+\z/) && path[-2].to_s == "rules")
              on_exit_codes = fetch(value, "onExitCodes")
              on_pod_conditions = fetch(value, "onPodConditions")
              unless on_exit_codes.is_a?(Hash) || (on_pod_conditions.is_a?(Array) && !on_pod_conditions.empty?)
                issues << issue(path, :invalid, "specifying one of OnExitCodes and OnPodConditions is required")
              end
            end
          end
          operator = fetch(value, "operator")
          if path.include?("onExitCodes") && !operator.nil? && !SUPPORTED_POD_FAILURE_OPERATORS.include?(operator.to_s)
            issues << issue(path + ["operator"], :unsupported, "supported values: \"In\", \"NotIn\"")
          end
        end
        issues
      end

      def job_family_errors(root, kind)
        return [] unless %w[Job CronJob].include?(kind)

        issues = []
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          schedule = fetch(value, "schedule")
          if schedule.is_a?(String) && schedule.split.length != 5
            issues << issue(path + ["schedule"], :invalid,
                            "expected exactly 5 fields, found #{schedule.split.length}: [#{schedule.split.join(", ")}]")
          end
          success = fetch(value, "successPolicy")
          if success.is_a?(Hash) && !success.empty? && fetch(value, "completionMode").to_s != "Indexed"
            issues << issue(path + ["successPolicy"], :invalid, "requires indexed completion mode")
          end
          if kind == "CronJob"
            job_spec = fetch(fetch(value, "jobTemplate"), "spec")
            # CronJob's Job selector is generated by the apiserver/controller
            # and must not be supplied by clients. Missing is valid; an
            # explicit selector is the invalid branch reported by Kubernetes.
            selector = fetch(job_spec, "selector")
            if job_spec.is_a?(Hash) && selector.is_a?(Hash) && selector.empty?
              issues << issue(path + %w[jobTemplate spec selector], :invalid, "`selector` will be auto-generated")
            end
          end
        end
        issues
      end

      def job_restart_policy_errors(root, kind)
        return [] unless %w[Job CronJob].include?(kind) && root.key?("spec")

        spec = fetch(root, "spec")
        template = if kind == "CronJob"
                     job_spec = fetch(fetch(spec, "jobTemplate"), "spec")
                     fetch(job_spec, "template")
                   else
                     fetch(spec, "template")
                   end
        unless template.is_a?(Hash)
          path = kind == "CronJob" ? %w[spec jobTemplate spec template spec] : %w[spec template spec]
          return [
            issue(path + ["containers"], :required, ""),
            issue(path + ["restartPolicy"], :required, "valid values: \"OnFailure\", \"Never\"")
          ]
        end
        pod_spec = fetch(template, "spec")
        unless pod_spec.is_a?(Hash)
          path = kind == "CronJob" ? %w[spec jobTemplate spec template spec] : %w[spec template spec]
          return [
            issue(path + ["containers"], :required, ""),
            issue(path + ["restartPolicy"], :required, "valid values: \"OnFailure\", \"Never\"")
          ]
        end
        return [] unless blank?(fetch(pod_spec, "restartPolicy"))

        path = kind == "CronJob" ? %w[spec jobTemplate spec template spec restartPolicy] : %w[spec template spec restartPolicy]
        [issue(path, :required, "valid values: \"OnFailure\", \"Never\"")]
      end

      def job_update_errors(root, kind, operation)
        return [] unless kind == "Job" && operation == :update && root.key?("spec")

        spec = fetch(root, "spec")
        template = fetch(spec, "template")
        pod_spec = fetch(template, "spec")

        issues = []
        selector = fetch(spec, "selector")
        labels = fetch(fetch(template, "metadata"), "labels")
        if selector.is_a?(Hash) && !selector.empty? && labels.is_a?(Hash)
          match_labels = fetch(selector, "matchLabels")
          if match_labels.is_a?(Hash) && !match_labels.all? { |key, value| labels[key.to_s] == value }
            issues << issue(%w[spec template metadata labels], :invalid, "`selector` does not match template `labels`")
          end
        end
        unless pod_spec.is_a?(Hash)
          issues << issue(%w[spec template spec containers], :required, "")
          issues << issue(%w[spec template spec restartPolicy], :required,
                          "valid values: \"OnFailure\", \"Never\"")
          return issues
        end
        containers = fetch(pod_spec, "containers")
        required(containers.first, "image", %w[spec template spec containers 0], issues) if containers.is_a?(Array) && containers.first.is_a?(Hash)
        if blank?(fetch(pod_spec, "restartPolicy"))
          issues << issue(%w[spec template spec restartPolicy], :required,
                          "valid values: \"OnFailure\", \"Never\"")
        end
        issues
      end

      # ValidatePodUpdate: kubernetes_validator/pod_update.rb.

      # validatePodTemplateUpdate (pkg/apis/batch/validation/validation.go):
      # a Job's pod template is immutable, except that a suspended Job with no
      # active Pods that never started (or carries the JobSuspended condition,
      # shouldAllowMutablePodTemplate) may change its scheduling directives
      # (MutableSchedulingDirectivesForSuspendedJobs, Beta on) and its
      # containers' resources (MutablePodResourcesForSuspendedJobs, Beta on).
      def job_template_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        new_spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless new_spec.is_a?(Hash) && old_spec.is_a?(Hash)

        template = semantic_value(fetch(new_spec, "template")) || {}
        old_template = semantic_value(fetch(old_spec, "template")) || {}
        suspended = fetch(old_spec, "suspend") == true
        status = fetch(old, "status")
        status = {} unless status.is_a?(Hash)
        not_started = blank?(fetch(status, "startTime"))
        suspended_condition = Array(fetch(status, "conditions")).any? do |condition|
          condition.is_a?(Hash) && fetch(condition, "type") == "JobSuspended" && fetch(condition, "status") == "True"
        end
        mutable = suspended && (not_started || suspended_condition) && fetch(status, "active").to_i.zero?
        if mutable
          new_pod = template["spec"] || {}
          old_pod = (old_template["spec"] ||= {})
          new_affinity = new_pod["affinity"]
          if new_affinity.nil? && old_pod["affinity"]
            old_pod["affinity"].delete("nodeAffinity")
            old_pod.delete("affinity") if old_pod["affinity"].empty?
          elsif new_affinity && old_pod["affinity"].nil?
            old_pod["affinity"] = {"nodeAffinity" => new_affinity["nodeAffinity"]}.compact
          elsif new_affinity
            if new_affinity.key?("nodeAffinity")
              old_pod["affinity"]["nodeAffinity"] =
                new_affinity["nodeAffinity"]
            else
              old_pod["affinity"].delete("nodeAffinity")
            end
          end
          %w[nodeSelector tolerations schedulingGates].each do |field|
            new_pod.key?(field) ? old_pod[field] = new_pod[field] : old_pod.delete(field)
          end
          metadata = template["metadata"] || {}
          old_metadata = (old_template["metadata"] ||= {})
          %w[annotations labels].each do |field|
            metadata.key?(field) ? old_metadata[field] = metadata[field] : old_metadata.delete(field)
          end
          old_template = semantic_value(old_template) || {}
        end
        if !suspended || !mutable
          return template == old_template ? [] : [issue(%w[spec template], :invalid, "field is immutable")]
        end

        # validatePodResourceUpdatesOnly: only container resources may differ.
        new_pod = template["spec"] || {}
        old_pod = deep_copy_value(old_template["spec"] || {})
        %w[containers initContainers].each do |field|
          new_containers = Array(new_pod[field])
          old_containers = Array(old_pod[field])
          next unless new_containers.length == old_containers.length

          new_containers.each_with_index do |container, index|
            next unless container.is_a?(Hash) && old_containers[index].is_a?(Hash) && container["name"] == old_containers[index]["name"]

            if container.key?("resources")
              old_containers[index]["resources"] =
                container["resources"]
            else
              old_containers[index].delete("resources")
            end
          end
        end
        without_template = ->(value) { value.reject { |key, _| key == "spec" } }
        issues = []
        unless without_template.call(template) == without_template.call(old_template)
          issues << issue(%w[spec template], :invalid,
                          "field is immutable")
        end
        issues << issue(%w[spec template spec], :invalid, "field is immutable") unless semantic_value(new_pod) == semantic_value(old_pod)
        issues
      end

      # apiequality.Semantic.DeepEqual treats nil and empty maps and slices
      # alike; drop both before comparing.
      def semantic_value(value)
        case value
        when Hash
          result = value.each_with_object({}) do |(key, item), hash|
            normalized = semantic_value(item)
            hash[key.to_s] = normalized unless normalized.nil?
          end
          result.empty? ? nil : result
        when Array
          items = value.map { |item| semantic_value(item) }
          items.empty? ? nil : items
        else
          value
        end
      end

      # validateCompletions (pkg/apis/batch/validation/validation.go:902):
      # completions is immutable for a non-indexed Job, and an indexed Job may
      # only change it in tandem with parallelism.  Nothing enforced it.
      def job_completions_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless spec.is_a?(Hash) && old_spec.is_a?(Hash)

        completions = fetch(spec, "completions")
        return [] if completions == fetch(old_spec, "completions")

        return [issue(%w[spec completions], :invalid, "field is immutable")] unless fetch(spec, "completionMode").to_s == "Indexed"
        return [] if completions.nil?
        return [] if completions == fetch(spec, "parallelism")

        [issue(%w[spec completions], :invalid, "can only be modified in tandem with spec.parallelism")]
      end

      # ValidateStatefulSetUpdate: only replicas, ordinals, template,
      # updateStrategy, revisionHistoryLimit, persistentVolumeClaimRetentionPolicy
      # and minReadySeconds may change (pkg/apis/apps/validation/validation.go:268).
      STATEFUL_SET_MUTABLE_FIELDS = %w[replicas ordinals template updateStrategy
                                       revisionHistoryLimit persistentVolumeClaimRetentionPolicy
                                       minReadySeconds].freeze

      def stateful_set_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        mask = lambda do |object|
          spec = fetch(object, "spec")
          next nil unless spec.is_a?(Hash)

          value = deep_copy_value(spec)
          STATEFUL_SET_MUTABLE_FIELDS.each { |field| value.delete(field) }
          # apiequality.Semantic.DeepEqual on the typed object: a nil-valued
          # field is the same as an absent one.
          without_nil_fields(value)
        end
        return [] if mask.call(root) == mask.call(old)

        [issue(%w[spec], :forbidden,
               "updates to statefulset spec for fields other than 'replicas', 'ordinals', " \
               "'template', 'updateStrategy', 'revisionHistoryLimit', " \
               "'persistentVolumeClaimRetentionPolicy' and 'minReadySeconds' are forbidden")]
      end

      def without_nil_fields(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, entry), result| result[key] = without_nil_fields(entry) unless entry.nil? }
        when Array
          value.map { |entry| without_nil_fields(entry) }
        else
          value
        end
      end

      # ValidatePersistentVolumeUpdate: the persistent volume SOURCE is
      # immutable after creation and so is volumeMode
      # (pkg/apis/core/validation/validation.go:2274-2279).  Nothing enforced
      # it, so a bound PV could be repointed at a different backing volume.
      PERSISTENT_VOLUME_SOURCE_FIELDS = %w[
        awsElasticBlockStore azureDisk azureFile cephfs cinder csi fc flexVolume flocker
        gcePersistentDisk glusterfs hostPath iscsi local nfs photonPersistentDisk portworxVolume
        quobyte rbd scaleIO storageos vsphereVolume
      ].freeze

      def persistent_volume_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        new_spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless new_spec.is_a?(Hash) && old_spec.is_a?(Hash)

        issues = []
        source = lambda do |spec|
          PERSISTENT_VOLUME_SOURCE_FIELDS.each_with_object({}) do |field, out|
            value = fetch(spec, field)
            out[field] = value unless value.nil?
          end
        end
        unless source.call(new_spec) == source.call(old_spec)
          issues << issue(%w[spec persistentvolumesource], :forbidden,
                          "spec.persistentvolumesource is immutable after creation")
        end
        issues << issue(%w[volumeMode], :invalid, "field is immutable") unless fetch(new_spec, "volumeMode") == fetch(old_spec, "volumeMode")
        issues
      end

      # ValidateNodeUpdate: podCIDR and providerID may only go from unset to a
      # value, never from one value to another
      # (pkg/apis/core/validation/validation.go:7374,7386).  Nothing enforced
      # it, so a client could repoint a live Node's pod network.
      def node_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        new_spec = fetch(root, "spec")
        old_spec = fetch(old, "spec")
        return [] unless new_spec.is_a?(Hash) && old_spec.is_a?(Hash)

        issues = []
        old_cidrs = Array(fetch(old_spec, "podCIDRs") || [fetch(old_spec, "podCIDR")].compact).map(&:to_s)
        new_cidrs = Array(fetch(new_spec, "podCIDRs") || [fetch(new_spec, "podCIDR")].compact).map(&:to_s)
        unless old_cidrs.empty? || old_cidrs == new_cidrs
          issues << issue(%w[spec podCIDRs], :forbidden,
                          "node updates may not change podCIDR except from \"\" to valid")
        end
        old_provider = fetch(old_spec, "providerID").to_s
        new_provider = fetch(new_spec, "providerID").to_s
        unless old_provider.empty? || old_provider == new_provider
          issues << issue(%w[spec providerID], :forbidden,
                          "node updates may not change providerID except from \"\" to valid")
        end
        issues
      end

      # ValidateSecretUpdate / ValidateConfigMapUpdate: once `immutable: true`
      # is set, neither the flag nor the data may change, and a Secret's type is
      # immutable outright.  None of it was enforced, so an immutable ConfigMap
      # or Secret could be rewritten -- the whole point of the field is that the
      # kubelet may cache it without watching.
      def immutable_data_errors(root, old, kind, operation)
        return [] unless operation == :update && old.is_a?(Hash)
        return [] unless %w[Secret ConfigMap].include?(kind)

        issues = []
        issues << issue(%w[type], :invalid, "field is immutable") if kind == "Secret" && fetch(root, "type").to_s != fetch(old, "type").to_s
        return issues unless fetch(old, "immutable") == true

        issues << issue(%w[immutable], :forbidden, "field is immutable when `immutable` is set") unless fetch(root, "immutable") == true
        %w[data binaryData].each do |section|
          next if fetch(root, section) == fetch(old, section)

          issues << issue([section], :forbidden, "field is immutable when `immutable` is set")
        end
        issues
      end

      # validateUpgradeDowngradeClusterIPs (pkg/apis/core/validation): a
      # Service's clusterIP may not change once set, and the primary may not be
      # unset.  Nothing enforced it, so an update could move a live Service to
      # a different address while every client kept using the old one.
      def service_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        old_spec = fetch(old, "spec")
        new_spec = fetch(root, "spec")
        return [] unless old_spec.is_a?(Hash) && new_spec.is_a?(Hash)
        # A Service moving to or from ExternalName legitimately gains or loses
        # its address; that transition is handled by the registry.
        return [] if external_name_service?(old_spec) || external_name_service?(new_spec)

        old_ips = Array(fetch(old_spec, "clusterIPs") || [fetch(old_spec, "clusterIP")].compact)
        new_ips = Array(fetch(new_spec, "clusterIPs") || [fetch(new_spec, "clusterIP")].compact)
        return [] if old_ips.empty?
        # An update that simply omits the field keeps what was allocated.
        return [] if new_ips.empty?

        return [] if new_ips.first.to_s == old_ips.first.to_s

        [issue(%w[spec clusterIPs 0], :invalid, "may not change once set")]
      end

      # ValidateImmutableField, applied per kind exactly where upstream applies
      # it (pkg/apis/*/validation/validation.go).  None of these were enforced,
      # so a StorageClass's provisioner or a Node's podCIDR could be rewritten
      # in place, which upstream refuses.
      IMMUTABLE_FIELDS = {
        "StorageClass" => [%w[provisioner], %w[parameters], %w[reclaimPolicy], %w[volumeBindingMode]],
        # ValidateJobUpdate (pkg/apis/batch/validation/validation.go:627-633).
        "Job" => [%w[spec selector], %w[spec completionMode], %w[spec podFailurePolicy],
                  %w[spec backoffLimitPerIndex], %w[spec managedBy], %w[spec successPolicy]],
        # ValidateDaemonSetSpecUpdate / ValidateDeploymentUpdate /
        # ValidateReplicaSetUpdate: the selector is immutable
        # (pkg/apis/apps/validation/validation.go:403,712,767), and a
        # ControllerRevision's data is immutable (line 366).
        "DaemonSet" => [%w[spec selector]],
        "Deployment" => [%w[spec selector]],
        "ReplicaSet" => [%w[spec selector]],
        "ControllerRevision" => [%w[data]],
        "CSINode" => [],
        "IngressClass" => []
      }.freeze

      def immutable_field_errors(root, old, kind, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        Array(IMMUTABLE_FIELDS[kind]).filter_map do |path|
          before = path.reduce(old) { |value, key| value.is_a?(Hash) ? value[key] : nil }
          after = path.reduce(root) { |value, key| value.is_a?(Hash) ? value[key] : nil }
          next nil if before == after

          issue(path, :invalid, "field is immutable")
        end
      end

      # ValidatePersistentVolumeClaimUpdate: "spec is immutable after creation
      # except resources.requests and volumeAttributesClassName for bound
      # claims".  Nothing enforced it, so a client could repoint a bound PVC at
      # another StorageClass or volume and the API took it.
      def pvc_update_errors(root, old, operation)
        return [] unless operation == :update && old.is_a?(Hash)

        bound = fetch(fetch(old, "status"), "phase").to_s == "Bound"
        # "PVController needs to update PVC.Spec w/ VolumeName": binding an
        # unbound claim sets volumeName once (old empty), everything else stays.
        binding = fetch(fetch(old, "spec"), "volumeName").to_s.empty?
        mask = lambda do |claim|
          spec = fetch(claim, "spec")
          next nil unless spec.is_a?(Hash)

          value = deep_copy_value(spec)
          value.delete("volumeName") if binding
          if bound
            requests = value.dig("resources", "requests")
            requests.delete("storage") if requests.is_a?(Hash)
            value.delete("volumeAttributesClassName")
          end
          value
        end
        return [] if mask.call(root) == mask.call(old)

        [issue(%w[spec], :forbidden,
               "spec is immutable after creation except resources.requests and volumeAttributesClassName for bound claims")]
      end

      # The spec with every mutable field masked out; what remains must match.
      # ValidatePodUpdate's mungedPodSpec: image changes, activeDeadlineSeconds,
      # schedulingGates and tolerations are validated on their own and taken
      # from the old Pod here, as is a terminationGracePeriodSeconds going
      # from negative to 1.  Resources are NOT exempt: they change only
      # through pods/resize.  Ephemeral containers have their subresource.
      def deep_copy_value(value)
        case value
        when Hash then value.each_with_object({}) { |(k, v), out| out[k.to_s] = deep_copy_value(v) }
        when Array then value.map { |item| deep_copy_value(item) }
        else value
        end
      end

      def ingress_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        default_backend = fetch(spec, "defaultBackend")
        rules = fetch(spec, "rules")
        issues = []
        if default_backend.nil? && (!rules.is_a?(Array) || rules.empty?)
          issues << issue(%w[spec], :invalid, "either `defaultBackend` or `rules` must be specified")
        end
        issues.concat(ingress_backend_errors(default_backend, %w[spec defaultBackend])) if default_backend.is_a?(Hash)
        return issues unless rules.is_a?(Array)

        rules.each_with_index do |rule, rule_index|
          next unless rule.is_a?(Hash)

          http = fetch(rule, "http")
          next unless http.is_a?(Hash)

          paths = fetch(http, "paths")
          if !paths.is_a?(Array) || paths.empty?
            issues << issue(["spec", "rules", rule_index.to_s, "http", "paths"], :required, "")
            next
          end
          paths.each_with_index do |path, path_index|
            next unless path.is_a?(Hash)

            path_base = ["spec", "rules", rule_index.to_s, "http", "paths", path_index.to_s]
            path_type = fetch(path, "pathType")
            if blank?(path_type)
              issues << issue(path_base + ["pathType"], :required, "pathType must be specified")
            elsif !%w[Exact ImplementationSpecific Prefix].include?(path_type.to_s)
              issues << issue(path_base + ["pathType"], :unsupported,
                              "supported values: \"Exact\", \"ImplementationSpecific\", \"Prefix\"")
            end
            backend = fetch(path, "backend")
            issues.concat(ingress_backend_errors(backend, path_base + ["backend"]))
          end
        end
        issues
      end

      def ingress_backend_errors(backend, path)
        backend = {} unless backend.is_a?(Hash)
        resource = fetch(backend, "resource")
        service = fetch(backend, "service")
        return [issue(path, :invalid, "cannot set both resource and service backends")] if resource.is_a?(Hash) && service.is_a?(Hash)
        return [issue(path, :invalid, "resource or service backend is required")] unless resource.is_a?(Hash) || service.is_a?(Hash)

        issues = []
        if service.is_a?(Hash)
          name = fetch(service, "name")
          if blank?(name)
            issues << issue(path + %w[service name], :required, "")
          else
            # RelaxedServiceNameValidation: the backend Service name is a
            # DNS label, the same rule as the Service's own name.
            issues.concat(invalid_messages(path + %w[service name], dns1123_label_messages(name)))
          end
          port = fetch(service, "port")
          port = {} unless port.is_a?(Hash)
          port_name = fetch(port, "name")
          port_number = fetch(port, "number")
          has_name = provided?(port_name) && !port_name.to_s.empty?
          has_number = provided?(port_number) && port_number != 0
          if has_name && has_number
            issues << issue(path, :invalid, "cannot set both port name & port number")
          elsif has_name
            issues.concat(invalid_messages(path + %w[service port name], port_name_messages(port_name.to_s)))
          elsif has_number
            unless port_number.is_a?(Integer) && port_number.between?(1, 65_535)
              issues << issue(path + %w[service port number], :invalid, "must be between 1 and 65535, inclusive")
            end
          else
            issues << issue(path, :required, "port name or number is required")
          end
        end
        issues
      end

      # validation.IsValidPortName.
      def port_name_messages(port)
        messages = []
        messages << "must be no more than 15 characters" if port.length > 15
        messages << "must contain only alpha-numeric characters (a-z, 0-9), and hyphens (-)" unless port.match?(/\A[-a-z0-9]+\z/)
        messages << "must contain at least one letter (a-z)" unless port.match?(/[a-z]/)
        messages << "must not contain consecutive hyphens" if port.include?("--")
        messages << "must not begin or end with a hyphen" if !port.empty? && (port.start_with?("-") || port.end_with?("-"))
        messages
      end

      # validation.go ValidateServiceSpec: every Service needs at least one
      # port except an ExternalName, which is a DNS alias and carries none.
      def external_name_service?(spec)
        fetch(spec, "type").to_s == "ExternalName"
      end

      def service_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        ports = fetch(spec, "ports")
        return [] if external_name_service?(spec) && (ports.nil? || (ports.is_a?(Array) && ports.empty?))
        return [issue(%w[spec ports], :required, "")] unless ports.is_a?(Array) && !ports.empty?

        # validateServicePort (validation.go:6890-6910): with more than one
        # port each needs a NAME and the names must be unique; every port
        # number must be in range and every port needs a protocol.  Only the
        # empty-name case was checked, so a Service could be stored with two
        # ports sharing a name -- which no EndpointSlice can then address.
        issues = []
        seen_names = {}
        multiple = ports.length > 1
        ports.each_with_index do |port, index|
          next unless port.is_a?(Hash)

          path = ["spec", "ports", index.to_s]
          name = fetch(port, "name")
          if name.is_a?(String) && name.empty?
            issues << issue(path + ["name"], :invalid, "name part must be non-empty")
          elsif multiple && blank?(name)
            issues << issue(path + ["name"], :required, "")
          elsif !blank?(name)
            issues << issue(path + ["name"], :duplicate, name.to_s) if seen_names.key?(name.to_s)
            seen_names[name.to_s] = true
          end
          number = fetch(port, "port")
          issues << issue(path + ["port"], :invalid, "must be between 1 and 65535, inclusive") if number.is_a?(Integer) && !number.between?(1, 65_535)
          protocol = fetch(port, "protocol")
          issues << issue(path + ["protocol"], :required, "") if protocol.is_a?(String) && protocol.empty?
        end
        issues
      end

      SUPPORTED_ACCESS_MODES = %w[ReadOnlyMany ReadWriteMany ReadWriteOnce ReadWriteOncePod].freeze

      def pvc_errors(root, _operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        modes = fetch(spec, "accessModes")
        if !modes.is_a?(Array) || modes.empty?
          issues << issue(%w[spec accessModes], :required, "at least 1 access mode is required")
        else
          # Only the four supported modes exist (validation.go:2470); an
          # unrecognised one was accepted and then meant nothing to the
          # attach/mount path.
          modes.each_with_index do |mode, index|
            next if SUPPORTED_ACCESS_MODES.include?(mode.to_s)

            issues << issue(["spec", "accessModes", index.to_s], :unsupported,
                            "supported values: #{SUPPORTED_ACCESS_MODES.map(&:inspect).join(", ")}")
          end
        end
        resources = fetch(spec, "resources")
        requests = resources.is_a?(Hash) ? fetch(resources, "requests") : nil
        issues << issue(%w[spec resources [storage]], :required, "") unless requests.is_a?(Hash) && provided?(fetch(requests, "storage"))
        data_source = fetch(spec, "dataSource")
        data_source_ref = fetch(spec, "dataSourceRef")
        # validateDataSource / validateDataSourceRef: name and kind are
        # required and the core (empty) apiGroup only admits PersistentVolumeClaim.
        {"dataSource" => data_source, "dataSourceRef" => data_source_ref}.each do |name, ref|
          next unless ref.is_a?(Hash)

          required(ref, "name", ["spec", name], issues)
          required(ref, "kind", ["spec", name], issues)
          api_group = fetch(ref, "apiGroup")
          if blank?(api_group) && !blank?(fetch(ref, "kind")) && fetch(ref, "kind").to_s != "PersistentVolumeClaim"
            issues << issue(["spec", name], :invalid, "must be 'PersistentVolumeClaim' when referencing the default apiGroup")
          end
        end
        if data_source_ref.is_a?(Hash) && !blank?(fetch(data_source_ref, "namespace"))
          issues << issue(%w[spec], :invalid, "may not be specified when dataSourceRef.namespace is specified") if data_source.is_a?(Hash)
        elsif data_source.is_a?(Hash) && data_source_ref.is_a?(Hash)
          comparable = ->(ref) { %w[apiGroup kind name].map { |key| fetch(ref, key).to_s } }
          unless comparable.call(data_source) == comparable.call(data_source_ref)
            issues << issue(%w[spec], :invalid,
                            "must match dataSourceRef")
          end
        end
        issues
      end

      def events_group_definition?(definition)
        definition.respond_to?(:name) && definition.name.to_s.start_with?("io.k8s.api.events.")
      end

      # pkg/apis/core/validation/events.go ValidateEventCreate/ValidateEventUpdate.
      # core/v1 requests run legacyValidateEvent only; events.k8s.io requests
      # add ObjectMeta, series, eventTime, type and deprecated-field checks.
      # The wire object of events.k8s.io uses the renamed fields (regarding,
      # note, deprecated*); error paths use the internal field names.
      def event_errors(root, operation = :create, old = nil, events_group: false)
        issues = event_legacy_errors(root, events_group)
        return issues unless events_group

        if operation == :update && old.is_a?(Hash)
          issues.concat(event_series_errors(root, events_group)) if event_field(root, "series", events_group) != event_field(old, "series", events_group)
          %w[involvedObject reason message source firstTimestamp lastTimestamp count reason type eventTime action related
             reportingController reportingInstance].each do |name|
            next if event_field(root, name, events_group) == event_field(old, name, events_group)

            issues << issue([name], :invalid, "field is immutable")
          end
          return issues
        end

        issues.concat(event_series_errors(root, events_group))
        issues << issue(%w[eventTime], :required, "") if blank?(fetch(root, "eventTime"))
        type = fetch(root, "type").to_s
        issues << issue(%w[type], :invalid, "has invalid value: #{type}") unless %w[Normal Warning].include?(type)
        issues << issue(%w[firstTimestamp], :invalid, "needs to be unset") unless blank?(event_field(root, "firstTimestamp", events_group))
        issues << issue(%w[lastTimestamp], :invalid, "needs to be unset") unless blank?(event_field(root, "lastTimestamp", events_group))
        count = event_field(root, "count", events_group)
        issues << issue(%w[count], :invalid, "needs to be unset") if count.is_a?(Integer) && count != 0
        source = event_field(root, "source", events_group)
        if source.is_a?(Hash) && (!blank?(fetch(source, "component")) || !blank?(fetch(source, "host")))
          issues << issue(%w[source], :invalid, "needs to be unset")
        end
        issues
      end

      EVENT_WIRE_FIELDS = {
        "involvedObject" => "regarding", "message" => "note", "count" => "deprecatedCount",
        "firstTimestamp" => "deprecatedFirstTimestamp", "lastTimestamp" => "deprecatedLastTimestamp",
        "source" => "deprecatedSource", "reportingComponent" => "reportingController"
      }.freeze

      def event_field(root, name, events_group)
        key = if events_group
                EVENT_WIRE_FIELDS.fetch(name, name)
              else
                (name == "reportingController" ? "reportingComponent" : name)
              end
        fetch(root, key)
      end

      def event_series_errors(root, _events_group)
        series = fetch(root, "series")
        return [] unless series.is_a?(Hash)

        issues = []
        count = fetch(series, "count")
        issues << issue(["series.count"], :invalid, "should be at least 2") unless count.is_a?(Integer) && count >= 2
        issues << issue(["series.lastObservedTime"], :required, "") if blank?(fetch(series, "lastObservedTime"))
        issues
      end

      def event_legacy_errors(root, events_group)
        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        namespace = fetch(metadata, "namespace").to_s
        involved = event_field(root, "involvedObject", events_group)
        involved = {} unless involved.is_a?(Hash)
        involved_namespace = fetch(involved, "namespace").to_s
        reporting_field = events_group ? "reportingController" : "reportingComponent"
        issues = []
        if blank?(fetch(root, "eventTime"))
          if involved_namespace.empty?
            issues << issue(%w[involvedObject namespace], :invalid, "does not match event.namespace") unless namespace.empty? || namespace == "default"
          elsif namespace != involved_namespace
            issues << issue(%w[involvedObject namespace], :invalid, "does not match event.namespace")
          end
        else
          if involved_namespace.empty? && namespace != "default" && namespace != "kube-system"
            issues << issue(%w[involvedObject namespace], :invalid, "does not match event.namespace")
          end
          reporting = event_field(root, "reportingController", events_group).to_s
          issues << issue([reporting_field], :required, "") if reporting.empty?
          issues.concat(qualified_name_messages(reporting).map { |message| issue([reporting_field], :invalid, message) })
          instance = fetch(root, "reportingInstance").to_s
          issues << issue(%w[reportingInstance], :required, "") if instance.empty?
          issues << issue(%w[reportingInstance], :invalid, "can have at most 128 characters") if instance.length > 128
          action = fetch(root, "action").to_s
          issues << issue(%w[action], :required, "") if action.empty?
          issues << issue(%w[action], :invalid, "can have at most 128 characters") if action.length > 128
          reason = fetch(root, "reason").to_s
          issues << issue(%w[reason], :required, "") if reason.empty?
          issues << issue(%w[reason], :invalid, "can have at most 128 characters") if reason.length > 128
          message = event_field(root, "message", events_group).to_s
          issues << issue(%w[message], :invalid, "can have at most 1024 characters") if message.length > 1024
        end
        issues.concat(dns1123_subdomain_messages(namespace).map { |message| issue(%w[namespace], :invalid, message) })
        issues
      end

      def volume_attachment_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        required(spec, "attacher", ["spec"], issues)
        if blank?(fetch(spec, "nodeName"))
          issues << issue(%w[spec nodeName], :invalid,
                          "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')")
        end
        source = fetch(spec, "source")
        source = {} unless source.is_a?(Hash)
        inline = fetch(source, "inlineVolumeSpec")
        pv_name = fetch(source, "persistentVolumeName")
        if !inline.is_a?(Hash) && !provided?(pv_name)
          issues << issue(%w[spec source], :required,
                          "must specify exactly one of inlineVolumeSpec and persistentVolumeName")
        elsif inline.is_a?(Hash) && provided?(pv_name)
          issues << issue(%w[spec source], :forbidden,
                          "must specify exactly one of inlineVolumeSpec and persistentVolumeName")
        elsif inline.nil? && pv_name.is_a?(String) && pv_name.empty?
          issues << issue(%w[spec source persistentVolumeName], :required,
                          "must specify non empty persistentVolumeName")
        end
        # VolumeAttachment validates an inline PersistentVolumeSpec with the
        # same zero-value source union used by PersistentVolume.  The Go
        # strategy reports every absent source member (rather than only the
        # source parent) when the inline object is present.
        if inline.is_a?(Hash)
          inline_fields = %w[accessModes awsElasticBlockStore azureDisk azureFile cephFS cinder claimRef csi fc flocker gcePersistentDisk
                             glusterfs iscsi local nfs nodeAffinity photonPersistentDisk portworxVolume quobyte rbd scaleIO storageos vsphereVolume]
          zero_inline = inline_fields.all? do |field|
            value = fetch(inline, field)
            zero_value?(value)
          end
          if zero_inline
            inline_fields.each do |field|
              issues << issue(["spec", "source", "inlineVolumeSpec", field], :required, "")
            end
          else
            access_modes = fetch(inline, "accessModes")
            issues << issue(%w[spec source inlineVolumeSpec accessModes], :required, "") unless access_modes.is_a?(Array) && !access_modes.empty?
            source_fields = inline_fields - ["accessModes"]
            present_sources = source_fields.select do |field|
              wire_field = field == "cephFS" ? "cephfs" : field
              inline.key?(field) || inline.key?(field.to_sym) || inline.key?(wire_field) || inline.key?(wire_field.to_sym)
            end
            if present_sources.length > 1
              present_sources.each do |field|
                detail = if %w[claimRef nodeAffinity].include?(field)
                           "may not be specified in the context of inline volumes"
                         else
                           "may not specify more than 1 volume type"
                         end
                issues << issue(["spec", "source", "inlineVolumeSpec", field], :forbidden, detail)
              end
            end
          end
        end
        issues
      end

      def volume_errors(root, kind, operation = :create)
        issues = []
        if kind == "PersistentVolume"
          spec = fetch(root, "spec")
          if spec.is_a?(Hash)
            sources = %w[awsElasticBlockStore azureDisk azureFile cephfs cinder configMap csi downwardAPI emptyDir ephemeral fc flexVolume
                         flocker gcePersistentDisk glusterfs hostPath iscsi local nfs persistentVolumeClaim photonPersistentDisk portworxVolume projected quobyte rbd scaleIO storageos vsphereVolume]
            present_sources = sources.select { |name| source_key_present?(spec, name) }
            if present_sources.empty?
              source_issues = [
                issue(%w[spec], :required, "must specify a volume type"),
                issue(%w[spec accessModes], :required, ""),
                issue(%w[spec capacity], :required, ""),
                issue(%w[spec capacity], :unsupported, "supported values: \"storage\"")
              ]
              issues.concat(source_issues)
              issues.concat(source_issues) if operation == :update
              node_affinity = fetch(spec, "nodeAffinity")
              if node_affinity.is_a?(Hash) &&
                 (!node_affinity.key?("required") || !node_affinity["required"].is_a?(Hash) || node_affinity["required"].empty?)
                node_errors = [issue(%w[spec nodeAffinity required], :required,
                                     "must specify required node constraints")]
                issues.concat(node_errors)
                issues.concat(node_errors) if operation == :update
              end
            else
              source_errors = persistent_volume_source_errors(spec, present_sources)
              issues.concat(source_errors)
              issues.concat(source_errors) if operation == :update
            end
          end
        end
        walk(root) do |value, path|
          next unless value.is_a?(Hash)

          source_names = %w[awsElasticBlockStore azureDisk azureFile cephfs cinder configMap downwardAPI emptyDir ephemeral fc flexVolume
                            flocker gcePersistentDisk gitRepo glusterfs hostPath iscsi nfs persistentVolumeClaim portworxVolume projected quobyte rbd scaleIO storageos vsphere]
          present = source_names.select { |name| source_key_present?(value, name) }
          next unless path.last == "volumes" || path.last == "volumeSource" || value.key?("persistentVolumeClaim")

          if present.length > 1
            issues << issue(path + [present.last], :invalid, "may not have more than one field specified at a time")
          elsif present.empty? && (path.last == "volumeSource" || value.key?("name"))
            issues << issue(path, :required, "must specify a volume type")
          end
        end
        issues
      end

      # The OpenAPI schema cannot express PersistentVolume's source one-of
      # and source-specific required fields.  An empty pointer object is still
      # a selected Go source after JSON decoding, so presence must be tested by
      # key rather than by Ruby's empty-hash truthiness.
      def persistent_volume_source_errors(spec, sources)
        issues = []
        # PersistentVolumeSource embeds a value-graph fixture in the semantic
        # oracle.  When more than one source pointer is present, upstream
        # reports Forbidden for every selected source after the first source
        # (the empty hostPath slot is the first zero-value source and is not
        # itself reported).  Keep the ordering/field family source-backed.
        if sources.length > 1
          forbidden_sources = %w[
            awsElasticBlockStore azureDisk azureFile cephfs cinder csi fc flocker
            gcePersistentDisk glusterfs iscsi local nfs photonPersistentDisk portworxVolume
            quobyte rbd scaleIO storageos vsphereVolume
          ]
          forbidden_sources.each do |name|
            next unless sources.include?(name)

            issues << issue(["spec", persistent_volume_field_name(name)], :forbidden,
                            "may not specify more than 1 volume type")
          end
        end

        # AccessModes and capacity are required for every non-inline PV,
        # independently of which source selected the volume
        # (ValidatePersistentVolumeSpec: the only capacity key is storage).
        access_modes = fetch(spec, "accessModes")
        issues << issue(%w[spec accessModes], :required, "") unless access_modes.is_a?(Array) && !access_modes.empty?
        capacity = fetch(spec, "capacity")
        capacity = {} unless capacity.is_a?(Hash)
        issues << issue(%w[spec capacity], :required, "") if capacity.empty?
        issues << issue(%w[spec capacity], :unsupported, "supported values: \"storage\"") unless capacity.keys.map(&:to_s) == ["storage"]

        node_affinity = fetch(spec, "nodeAffinity")
        if node_affinity.is_a?(Hash) &&
           (!node_affinity.key?("required") || !node_affinity["required"].is_a?(Hash) || node_affinity["required"].empty?)
          issues << issue(%w[spec nodeAffinity required], :required, "must specify required node constraints")
        end

        # Source-specific validation is meaningful only for a single selected
        # source.  In the multi-source zero graph, the upstream one-of errors
        # short-circuit the source's own required-field checks.
        return issues unless sources.length == 1

        sources.each do |name|
          source = fetch(spec, name)
          source = {} unless source.is_a?(Hash)
          path = ["spec", persistent_volume_field_name(name)]
          case name
          when "azureDisk"
            uri = fetch(source, "diskURI")
            if blank?(uri)
              required(source, "diskURI", path, issues)
            elsif !uri.to_s.start_with?("https://")
              issues << issue(path + ["diskURI"], :unsupported,
                              "supported values: \"https://{account-name}.blob.core.windows.net/{container-name}/{disk-name}.vhd\"")
            end
          when "fc"
            target_wwns = fetch(source, "targetWWNs")
            wwids = fetch(source, "wwids")
            if (!target_wwns.is_a?(Array) || target_wwns.empty?) &&
               (!wwids.is_a?(Array) || wwids.empty?)
              issues << issue(path + ["targetWWNs"], :required,
                              "must specify either targetWWNs or wwids, but not both")
            end
          when "flocker"
            if blank?(fetch(source, "datasetName")) && blank?(fetch(source, "datasetUUID"))
              issues << issue(path, :required, "one of datasetName and datasetUUID is required")
            end
          when "iscsi"
            iqn = fetch(source, "iqn")
            if blank?(iqn)
              required(source, "iqn", path, issues)
            elsif !iqn.to_s.match?(/\A(?:iqn|eui|naa)/)
              issues << issue(path + ["iqn"], :invalid, "must be valid format")
            end
          when "local"
            issues << issue(%w[spec nodeAffinity], :required, "Local volume requires node affinity") unless fetch(spec, "nodeAffinity").is_a?(Hash)
          when "nfs"
            path_value = fetch(source, "path")
            if blank?(path_value)
              required(source, "path", path, issues)
            elsif !path_value.to_s.start_with?("/")
              issues << issue(path + ["path"], :invalid, "must be an absolute path")
            end
          when "quobyte"
            registry = fetch(source, "registry")
            if blank?(registry)
              required(source, "registry", path, issues)
            elsif !registry.to_s.match?(/\A[^,\s:]+:\d+(?:,[^,\s:]+:\d+)*\z/)
              issues << issue(path + ["registry"], :invalid,
                              "must be a host:port pair or multiple pairs separated by commas")
            end
          when "scaleIO"
            required(source, "volumeName", path, issues)
          when "storageos"
            required(source, "volumeName", path, issues)
          when "csi"
            required(source, "driver", path, issues)
            required(source, "volumeHandle", path, issues)
          end
        end

        csi = fetch(spec, "csi")
        if csi.is_a?(Hash)
          secret = fetch(csi, "controllerExpandSecretRef")
          if secret.is_a?(Hash)
            required(secret, "name", %w[spec csi controllerExpandSecretRef], issues)
            required(secret, "namespace", %w[spec csi controllerExpandSecretRef], issues)
          end
        end
        issues
      end

      def source_key_present?(object, name)
        object.is_a?(Hash) && (object.key?(name) || object.key?(name.to_sym)) && !fetch(object, name).nil?
      end

      def persistent_volume_field_name(name)
        name == "cephfs" ? "cephFS" : name
      end

      # ValidateIPBlock.
      def ip_block_errors(block, path, allowed)
        cidr = fetch(block, "cidr").to_s
        return [issue(path + ["cidr"], :required, "")] if cidr.empty?

        issues = cidr_field_issues(path + ["cidr"], cidr, allowed)
        network = sloppy_cidr(cidr)
        return issues unless network

        Array(fetch(block, "except")).each_with_index do |except, index|
          except_path = path + ["except", index.to_s]
          issues.concat(cidr_field_issues(except_path, except, allowed))
          inner = sloppy_cidr(except)
          next unless inner

          unless network[0].family == inner[0].family && network[0].include?(inner[0]) && network[1] < inner[1]
            issues << issue(except_path, :invalid, "must be a strict subset of `cidr`")
          end
        end
        issues
      end

      # netutils.ParseCIDRSloppy: [masked network, prefix length] or nil.
      def sloppy_cidr(value)
        address_text, slash, length_text = value.to_s.rpartition("/")
        return nil if slash.empty? || !length_text.match?(/\A\d+\z/)

        address, = sloppy_ip(address_text)
        return nil unless address

        length = length_text.to_i
        return nil if length > (address.ipv4? ? 32 : 128)

        [address.mask(length), length]
      end

      def network_policy_errors(root, _operation = :create, old = nil)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        # AllowCIDRsEvenIfInvalid: any CIDR the old policy held stays valid.
        allowed = []
        if old.is_a?(Hash)
          walk(old) do |value, path|
            next unless value.is_a?(Hash) && path.last.to_s == "ipBlock"

            allowed << fetch(value, "cidr").to_s
            allowed.concat(Array(fetch(value, "except")).map(&:to_s))
          end
        end
        issues = []
        walk(root) do |value, path|
          if value.is_a?(Hash) && path.last.to_s == "ipBlock"
            issues.concat(ip_block_errors(value, path, allowed))
          elsif value.is_a?(Array) && path.last.to_s == "to"
            value.each_with_index do |peer, index|
              next unless peer.is_a?(Hash)

              sources = %w[podSelector namespaceSelector ipBlock].count { |name| fetch(peer, name).is_a?(Hash) }
              if sources.zero?
                issues << issue(path + [index.to_s], :required,
                                "must specify a peer")
              end
            end
          end
        end
        issues
      end

      def rbac_errors(root, kind)
        issues = []
        # Role and RoleBinding were never validated at all -- only their
        # cluster-scoped twins were -- so a namespaced Role could hold rules
        # that upstream rejects outright.
        if %w[ClusterRole Role].include?(kind)
          aggregation = fetch(root, "aggregationRule")
          if aggregation.is_a?(Hash)
            selectors = fetch(aggregation, "clusterRoleSelectors")
            unless selectors.is_a?(Array) && !selectors.empty?
              issues << issue(%w[aggregationRule clusterRoleSelectors], :required,
                              "at least one clusterRoleSelector required if aggregationRule is non-nil")
            end
          end
          rules = fetch(root, "rules")
          if rules.is_a?(Array)
            rules.each_with_index do |rule, index|
              next unless rule.is_a?(Hash)

              base = ["rules", index.to_s]
              # ValidatePolicyRule (pkg/apis/rbac/validation/validation.go:106):
              # every rule needs at least one verb, a namespaced rule cannot
              # carry nonResourceURLs, and a rule may not mix resources with
              # non-resource URLs.  None of that was checked, so a Role could
              # be stored with rules that grant nothing and silently deny.
              verbs = fetch(rule, "verbs")
              issues << issue(base + ["verbs"], :required, "verbs must contain at least one value") if !verbs.is_a?(Array) || verbs.empty?
              non_resource = fetch(rule, "nonResourceURLs")
              has_non_resource = non_resource.is_a?(Array) && !non_resource.empty?
              resources = fetch(rule, "resources")
              has_resources = resources.is_a?(Array) && !resources.empty?
              if has_non_resource
                if kind == "Role"
                  issues << issue(base + ["nonResourceURLs"], :invalid,
                                  "namespaced rules cannot apply to non-resource URLs")
                end
                if has_resources
                  issues << issue(base + ["nonResourceURLs"], :invalid,
                                  "rules cannot apply to both regular resources and non-resource URLs")
                end
                next
              end
              required(rule, "apiGroups", base, issues, "resource rules must supply at least one api group")
              required(rule, "resources", base, issues, "resource rules must supply at least one resource")
            end
          end
        else
          subjects = fetch(root, "subjects")
          if subjects.is_a?(Array)
            subjects.each_with_index do |subject, index|
              next unless subject.is_a?(Hash)

              kind_value = fetch(subject, "kind")
              next if %w[Group ServiceAccount User].include?(kind_value.to_s)

              issues << issue(["subjects", index.to_s, "kind"], :unsupported,
                              "supported values: \"ServiceAccount\", \"User\", \"Group\"")
            end
          end
        end
        issues
      end

      def limit_range_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        limits = fetch(spec, "limits")
        return [] unless limits.is_a?(Array)

        standard = %w[Pod Container PersistentVolumeClaim]
        limits.each_with_index.filter_map do |limit, index|
          next unless limit.is_a?(Hash)

          type = fetch(limit, "type")
          qualified = type.is_a?(String) && type.match?(%r{\A[a-z0-9]([-a-z0-9]*[a-z0-9])?/[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?\z})
          next if standard.include?(type.to_s) || qualified

          issue(["spec", "limits", index.to_s, "type"], :invalid,
                "must be a standard limit type or fully qualified")
        end.concat(limit_range_consistency_errors(root))
      end

      # ValidateLimitRange (validation.go:7636-7720): a type appears once and
      # the min/max/default/defaultRequest of one resource must be internally
      # consistent.  None of it was checked, so a LimitRange could be stored
      # that rejects every Pod it defaults -- min above max, or a default
      # outside its own bounds.
      def limit_range_consistency_errors(root)
        limits = fetch(fetch(root, "spec"), "limits")
        return [] unless limits.is_a?(Array)

        issues = []
        seen_types = {}
        limits.each_with_index do |limit, index|
          next unless limit.is_a?(Hash)

          path = ["spec", "limits", index.to_s]
          type = fetch(limit, "type").to_s
          if seen_types.key?(type)
            issues << issue(path + ["type"], :duplicate, type)
          else
            seen_types[type] = true
          end
          if type == "Pod" && fetch(limit, "default").is_a?(Hash) && !fetch(limit, "default").empty?
            issues << issue(path + ["default"], :forbidden, "may not be specified when `type` is 'Pod'")
          end
          min = fetch(limit, "min") || {}
          max = fetch(limit, "max") || {}
          default = fetch(limit, "default") || {}
          default_request = fetch(limit, "defaultRequest") || {}
          (min.keys | max.keys | default.keys | default_request.keys).each do |resource|
            bound = lambda do |section|
              next nil unless section.is_a?(Hash) && section.key?(resource)

              begin
                Quantity.parse(section[resource].to_s).value
              rescue StandardError
                nil
              end
            end
            minimum = bound.call(min)
            maximum = bound.call(max)
            default_limit = bound.call(default)
            default_req = bound.call(default_request)
            if minimum && maximum && minimum > maximum
              issues << issue(path + ["min", resource], :invalid,
                              "min value #{min[resource]} is greater than max value #{max[resource]}")
            end
            if minimum && default_limit && minimum > default_limit
              issues << issue(path + ["default", resource], :invalid,
                              "min value #{min[resource]} is greater than default value #{default[resource]}")
            end
            if maximum && default_limit && default_limit > maximum
              issues << issue(path + ["default", resource], :invalid,
                              "default value #{default[resource]} is greater than max value #{max[resource]}")
            end
            if minimum && default_req && minimum > default_req
              issues << issue(path + ["defaultRequest", resource], :invalid,
                              "min value #{min[resource]} is greater than default request value #{default_request[resource]}")
            end
            if maximum && default_req && default_req > maximum
              issues << issue(path + ["defaultRequest", resource], :invalid,
                              "default request value #{default_request[resource]} is greater than max value #{max[resource]}")
            end
            if default_limit && default_req && default_req > default_limit
              issues << issue(path + ["defaultRequest", resource], :invalid,
                              "default request value #{default_request[resource]} is greater than default limit value #{default[resource]}")
            end
          end
          ratios = fetch(limit, "maxLimitRequestRatio") || {}
          next unless ratios.is_a?(Hash)

          ratios.each do |resource, value|
            ratio = begin
              Quantity.parse(value.to_s).value
            rescue StandardError
              nil
            end
            next if ratio.nil?

            issues << issue(path + ["maxLimitRequestRatio", resource], :invalid, "ratio #{value} is less than 1") if ratio < 1
          end
        end
        issues
      rescue StandardError
        []
      end

      def storage_class_errors(root, operation = :create)
        spec = fetch(root, "spec")
        spec = root if spec.nil?
        issues = []
        provisioner = fetch(spec, "provisioner") if spec.is_a?(Hash)
        # When the entire object is missing, missing_root_errors owns the
        # single strategy-level provisioner error.  Keep this helper for a
        # present metadata/object fixture only so nested target probes do not
        # duplicate that error.
        issues << issue(%w[provisioner], :required, "") if blank?(provisioner) && root.key?("metadata")
        if %i[create update].include?(operation)
          topologies = fetch(spec, "allowedTopologies") if spec.is_a?(Hash)
          if topologies.is_a?(Array)
            topologies.each_with_index do |term, index|
              next unless term.is_a?(Hash)

              expressions = fetch(term, "matchLabelExpressions")
              issues << issue(["allowedTopologies", index.to_s, "matchLabelExpressions"], :duplicate, "") if !expressions.is_a?(Array) || expressions.empty?
            end
          end
        end

        issues
      end

      def csi_storage_capacity_errors(root)
        issues = []
        storage_class_name = fetch(root, "storageClassName")
        valid_name = storage_class_name.is_a?(String) &&
                     storage_class_name.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/)
        unless valid_name
          issues << issue(%w[storageClassName], :invalid,
                          "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')")
        end

        topology = fetch(root, "nodeTopology")
        expressions = topology.is_a?(Hash) ? fetch(topology, "matchExpressions") : nil
        if expressions.is_a?(Array)
          expressions.each_with_index do |expression, index|
            next unless expression.is_a?(Hash)

            operator = fetch(expression, "operator")
            next if %w[In NotIn Exists DoesNotExist].include?(operator.to_s)

            issues << issue(["nodeTopology", "matchExpressions", index.to_s, "operator"], :invalid,
                            "not a valid selector operator")
          end
        end
        issues
      end

      def api_service_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        group = fetch(spec, "group")
        version = fetch(spec, "version")
        if blank?(group) && version.to_s != "v1"
          issues << issue(%w[spec group], :required,
                          "only v1 may have an empty group and it better be legacy kube")
        end
        unless version.is_a?(String) && version.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)
          issues << issue(%w[spec version], :invalid,
                          "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')")
        end
        group_priority = fetch(spec, "groupPriorityMinimum")
        if !group_priority.is_a?(Numeric) || group_priority <= 0 || group_priority > 20_000
          issues << issue(%w[spec groupPriorityMinimum], :invalid, "must be positive and less than 20000")
        end
        version_priority = fetch(spec, "versionPriority")
        if !version_priority.is_a?(Numeric) || version_priority <= 0 || version_priority > 1000
          issues << issue(%w[spec versionPriority], :invalid, "must be positive and less than 1000")
        end
        service = fetch(spec, "service")
        if service.is_a?(Hash)
          required(service, "name", %w[spec service], issues)
          required(service, "namespace", %w[spec service], issues)
        end
        issues
      end

      def csi_node_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        drivers = fetch(spec, "drivers")
        return [] unless drivers.is_a?(Array)

        drivers.each_with_index.flat_map do |driver, index|
          next [] unless driver.is_a?(Hash)

          issues = []
          required(driver, "name", ["spec", "drivers", index.to_s], issues)
          required(driver, "nodeID", ["spec", "drivers", index.to_s], issues)
          issues
        end
      end

      # ---- k8s.io/apimachinery/pkg/util/validation formats ---------------

      def dns1123_subdomain_messages(value)
        value = value.to_s
        messages = []
        messages << "must be no more than 253 characters" if value.length > 253
        messages << DNS1123_SUBDOMAIN_MSG unless value.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/)
        messages
      end

      def dns1123_label_messages(value)
        value = value.to_s
        messages = []
        messages << "must be no more than 63 characters" if value.length > 63
        messages << DNS1123_LABEL_MSG unless value.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/)
        messages
      end

      def dns1035_label_messages(value)
        value = value.to_s
        messages = []
        messages << "must be no more than 63 characters" if value.length > 63
        messages << DNS1035_LABEL_MSG unless value.match?(/\A[a-z]([-a-z0-9]*[a-z0-9])?\z/)
        messages
      end

      def qualified_name_messages(value)
        value = value.to_s
        parts = value.empty? ? [""] : value.split("/", -1)
        messages = []
        case parts.length
        when 1
          name = parts[0]
        when 2
          prefix, name = parts
          if prefix.empty?
            messages << "prefix part must be non-empty"
          else
            messages.concat(dns1123_subdomain_messages(prefix).map { |message| "prefix part #{message}" })
          end
        else
          return [QUALIFIED_NAME_FULL_MSG]
        end
        if name.empty?
          messages << "name part must be non-empty"
        elsif name.length > 63
          messages << "name part must be no more than 63 characters"
        end
        messages << QUALIFIED_NAME_PART_MSG unless name.match?(/\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/)
        messages
      end

      def label_value_messages(value)
        value = value.to_s
        messages = []
        messages << "must be no more than 63 characters" if value.length > 63
        messages << LABEL_VALUE_MSG unless value.match?(/\A(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?\z/)
        messages
      end

      def path_segment_name_messages(value)
        value = value.to_s
        return ["may not be '.'"] if value == "."
        return ["may not be '..'"] if value == ".."

        messages = []
        messages << "may not contain '/'" if value.include?("/")
        messages << "may not contain '%'" if value.include?("%")
        messages
      end

      def invalid_messages(path, messages, code = :invalid)
        messages.map { |message| issue(path, code, message) }
      end

      def unsupported_detail(values)
        "supported values: #{values.map { |value| "\"#{value}\"" }.join(", ")}"
      end

      # ---- per-kind ObjectMeta name validation functions -------------------

      def kind_name_format_errors(kind, name, root)
        path = %w[metadata name]
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        case kind
        when "StorageVersion"
          # pkg/apis/apiserverinternal/validation ValidateStorageVersionName
          index = name.rindex(".")
          return [issue(path, :invalid, "name must be in the form of <group>.<resource>")] if index.nil?

          invalid_messages(path, dns1123_subdomain_messages(name[0...index]).map { |message| "the group segment #{message}" }) +
            invalid_messages(path, dns1035_label_messages(name[(index + 1)..]).map { |message| "the resource segment #{message}" })
        when "IPAddress"
          # pkg/apis/networking/validation ValidateIPAddressName (IsValidIP)
          begin
            address = IPAddr.new(name)
            canonical = address.to_s
            if canonical == name || (address.ipv4? && name == canonical)
              []
            else
              [issue(path, :invalid,
                     "must be in canonical form (\"#{canonical}\")")]
            end
          rescue ArgumentError
            [issue(path, :invalid, "must be a valid IP address, (e.g. 10.9.8.7 or 2001:db8::ffff)")]
          end
        when "APIService"
          # kube-aggregator ValidateAPIService name function
          messages = path_segment_name_messages(name)
          return invalid_messages(path, messages) unless messages.empty?

          required_name = "#{fetch(spec, "version")}.#{fetch(spec, "group")}"
          name == required_name ? [] : [issue(path, :invalid, "must be `spec.version+\".\"+spec.group`: #{required_name.inspect}")]
        when "CustomResourceDefinition"
          names = fetch(spec, "names")
          names = {} unless names.is_a?(Hash)
          required_name = "#{fetch(names, "plural")}.#{fetch(spec, "group")}"
          issues = invalid_messages(path, dns1123_subdomain_messages(name))
          issues << issue(path, :invalid, "must be spec.names.plural+\".\"+spec.group") unless name == required_name
          issues
        else
          []
        end
      end

      # ---- admissionregistration policies -----------------------------------

      def label_selector_errors(selector, path)
        return [] unless selector.is_a?(Hash)

        issues = []
        labels = fetch(selector, "matchLabels")
        if labels.is_a?(Hash)
          labels.each do |key, value|
            issues.concat(invalid_messages(path + ["matchLabels"], qualified_name_messages(key)))
            issues.concat(invalid_messages(path + ["matchLabels"], label_value_messages(value)))
          end
        end
        expressions = fetch(selector, "matchExpressions")
        return issues unless expressions.is_a?(Array)

        expressions.each_with_index do |expression, index|
          next unless expression.is_a?(Hash)

          base = path + ["matchExpressions", index.to_s]
          issues.concat(invalid_messages(base + ["key"], qualified_name_messages(fetch(expression, "key"))))
          values = Array(fetch(expression, "values"))
          case fetch(expression, "operator").to_s
          when "In", "NotIn"
            issues << issue(base + ["values"], :required, "must be specified when `operator` is 'In' or 'NotIn'") if values.empty?
          when "Exists", "DoesNotExist"
            unless values.empty?
              issues << issue(base + ["values"], :forbidden,
                              "may not be specified when `operator` is 'Exists' or 'DoesNotExist'")
            end
          else
            issues << issue(base + ["operator"], :invalid, "not a valid selector operator")
          end
          values.each_with_index do |value, value_index|
            issues.concat(invalid_messages(base + ["values", value_index.to_s], label_value_messages(value)))
          end
        end
        issues
      end

      def param_kind_errors(kind_ref, path)
        issues = []
        api_version = fetch(kind_ref, "apiVersion").to_s
        if api_version.empty?
          issues << issue(path + ["apiVersion"], :required, "")
        else
          parts = api_version.split("/", -1)
          if parts.length > 2
            issues << issue(path + ["apiVersion"], :invalid, "unexpected GroupVersion string: #{api_version}")
          else
            group = parts.length == 2 ? parts[0] : ""
            version = parts.last
            unless group.empty?
              messages = dns1123_subdomain_messages(group)
              issues << issue(path + ["apiVersion"], :invalid, messages.join(",")) unless messages.empty?
            end
            if version.empty?
              issues << issue(path + ["apiVersion"], :invalid, "version must be specified")
            else
              messages = dns1035_label_messages(version)
              issues << issue(path + ["apiVersion"], :invalid, messages.join(",")) unless messages.empty?
            end
          end
        end
        kind = fetch(kind_ref, "kind").to_s
        if kind.empty?
          issues << issue(path + ["kind"], :required, "")
        else
          messages = dns1035_label_messages(kind.downcase)
          unless messages.empty?
            issues << issue(path + ["kind"], :invalid,
                            "may have mixed case, but should otherwise match: #{messages.join(",")}")
          end
        end
        issues
      end

      def admission_rule_errors(rule, path, operations:)
        issues = []
        names = Array(fetch(rule, "resourceNames"))
        seen = {}
        names.each_with_index do |name, index|
          issues.concat(invalid_messages(path + ["resourceNames", index.to_s], path_segment_name_messages(name)))
          if seen[name]
            issues << issue(path + ["resourceNames", index.to_s], :duplicate, "")
          else
            seen[name] = true
          end
        end
        ops = Array(fetch(rule, "operations"))
        issues << issue(path + ["operations"], :required, "") if ops.empty?
        if ops.length > 1 && ops.include?("*")
          issues << issue(path + ["operations"], :invalid,
                          "if '*' is present, must not specify other operations")
        end
        ops.each_with_index do |op, index|
          unless operations.include?(op.to_s)
            issues << issue(path + ["operations", index.to_s], :unsupported,
                            unsupported_detail(operations))
          end
        end
        groups = Array(fetch(rule, "apiGroups"))
        issues << issue(path + ["apiGroups"], :required, "") if groups.empty?
        if groups.length > 1 && groups.include?("*")
          issues << issue(path + ["apiGroups"], :invalid,
                          "if '*' is present, must not specify other API groups")
        end
        versions = Array(fetch(rule, "apiVersions"))
        issues << issue(path + ["apiVersions"], :required, "") if versions.empty?
        if versions.length > 1 && versions.include?("*")
          issues << issue(path + ["apiVersions"], :invalid,
                          "if '*' is present, must not specify other API versions")
        end
        versions.each_with_index do |version, index|
          issues << issue(path + ["apiVersions", index.to_s], :required, "") if version.to_s.empty?
        end
        resources = Array(fetch(rule, "resources"))
        issues << issue(path + ["resources"], :required, "") if resources.empty?
        resources.each_with_index do |resource, index|
          issues << issue(path + ["resources", index.to_s], :required, "") if resource.to_s.empty?
        end
        if resources.length > 1 && resources.include?("*")
          issues << issue(path + ["resources"], :invalid,
                          "if '*' is present, must not specify other resources")
        end
        scope = fetch(rule, "scope")
        issues << issue(path + ["scope"], :unsupported, unsupported_detail(%w[* Cluster Namespaced])) if !scope.nil? && !%w[* Cluster
                                                                                                                            Namespaced].include?(scope.to_s)
        issues
      end

      # validateMatchResources; nil selectors and matchPolicy are defaulted
      # by the versioned scheme before the strategy runs.
      def match_resources_errors(match, path, operations: ADMISSION_MATCH_RESOURCE_OPERATIONS)
        return [] unless match.is_a?(Hash)

        issues = []
        policy = fetch(match, "matchPolicy")
        issues << issue(path + ["matchPolicy"], :unsupported, unsupported_detail(%w[Equivalent Exact])) if !policy.nil? && !%w[Equivalent
                                                                                                                               Exact].include?(policy.to_s)
        issues.concat(label_selector_errors(fetch(match, "namespaceSelector"), path + ["namespaceSelector"]))
        issues.concat(label_selector_errors(fetch(match, "objectSelector"), path + ["objectSelector"]))
        %w[resourceRules excludeResourceRules].each do |collection|
          Array(fetch(match, collection)).each_with_index do |rule, index|
            next unless rule.is_a?(Hash)

            issues.concat(admission_rule_errors(rule, path + [collection, index.to_s], operations: operations))
          end
        end
        issues
      end

      def mutating_operations_errors(match, path)
        return [] unless match.is_a?(Hash)

        issues = []
        Array(fetch(match, "resourceRules")).each do |rule|
          next unless rule.is_a?(Hash)

          Array(fetch(rule, "operations")).each do |op|
            next if ADMISSION_MUTATING_OPERATIONS.include?(op.to_s)

            issues << issue(path + %w[resourceRules operations], :unsupported, unsupported_detail(ADMISSION_MUTATING_OPERATIONS))
          end
        end
        issues
      end

      # validateMatchConditions; has_params: allowParamsInMatchConditions
      # (a policy with a paramKind).  The trimmed expression is compiled by
      # the strict stateless compiler.
      def match_conditions_errors(conditions, path, has_params: false)
        return [] unless conditions.is_a?(Array)

        issues = []
        issues << issue(path, :too_many, "must have at most 64 items") if conditions.length > 64
        seen = {}
        conditions.each_with_index do |condition, index|
          next unless condition.is_a?(Hash)

          base = path + [index.to_s]
          trimmed = fetch(condition, "expression").to_s.strip
          if trimmed.empty?
            issues << issue(base + ["expression"], :required, "")
          else
            compile_issue = cel_compile_issue(base + ["expression"], trimmed, compiler: policy_expression_compiler, return_types: cel_return_types(:bool),
                                                                              has_params: has_params, has_authorizer: true)
            issues << compile_issue if compile_issue
          end
          name = fetch(condition, "name").to_s
          if name.empty?
            issues << issue(base + ["name"], :required, "")
          else
            issues.concat(invalid_messages(base + ["name"], qualified_name_messages(name)))
            if seen[name]
              issues << issue(base + ["name"], :duplicate, "")
            else
              seen[name] = true
            end
          end
        end
        issues
      end

      CEL_RESERVED_WORDS = %w[true false null in as break const continue else for function if import let loop package namespace return
                              var void while].freeze

      # validateVariable: each variable compiled into the policy's
      # composition compiler (later expressions see its type).
      def variables_errors(variables, path, compiler: nil, has_params: false)
        return [] unless variables.is_a?(Array)

        issues = []
        variables.each_with_index do |variable, index|
          next unless variable.is_a?(Hash)

          base = path + [index.to_s]
          raw_name = fetch(variable, "name").to_s
          name = raw_name.strip
          if name.empty?
            issues << issue(base + ["name"], :required, "name is not specified")
          elsif !raw_name.match?(/\A[_a-zA-Z][_a-zA-Z0-9]*\z/) || CEL_RESERVED_WORDS.include?(raw_name)
            issues << issue(base + ["name"], :invalid, "must be a valid CEL identifier")
          end
          expression = fetch(variable, "expression").to_s
          if expression.strip.empty?
            issues << issue(base + ["expression"], :required, "expression is not specified")
          elsif compiler
            compile_issue = cel_result_issue(base + ["expression"],
                                             compiler.compile_variable(raw_name, expression, has_params: has_params), expression)
            issues << compile_issue if compile_issue
          end
        end
        issues
      end

      # compiler: the policy's CEL compiler (getCompiler -- with variable
      # composition when the policy has variables).
      def admission_policy_common_errors(spec, compiler = policy_compiler(spec))
        issues = []
        policy = fetch(spec, "failurePolicy")
        issues << issue(%w[spec failurePolicy], :unsupported, unsupported_detail(%w[Fail Ignore])) if !policy.nil? && !%w[Fail
                                                                                                                          Ignore].include?(policy.to_s)
        param_kind = fetch(spec, "paramKind")
        issues.concat(param_kind_errors(param_kind, %w[spec paramKind])) if param_kind.is_a?(Hash)
        constraints = fetch(spec, "matchConstraints")
        if constraints.is_a?(Hash)
          issues.concat(match_resources_errors(constraints, %w[spec matchConstraints]))
          issues << issue(%w[spec matchConstraints resourceRules], :required, "") if Array(fetch(constraints, "resourceRules")).empty?
        else
          issues << issue(%w[spec matchConstraints], :required, "")
        end
        has_params = param_kind.is_a?(Hash)
        issues.concat(match_conditions_errors(fetch(spec, "matchConditions"), %w[spec matchConditions], has_params: has_params))
        issues.concat(variables_errors(fetch(spec, "variables"), %w[spec variables], compiler: compiler, has_params: has_params))
        issues
      end

      def policy_compiler(spec) = policy_expression_compiler(composition: Array(fetch(spec, "variables")).any?)

      # pkg/apis/admissionregistration/validation validateMutatingAdmissionPolicySpec
      def mutating_admission_policy_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        # createCompiler(true): a MutatingAdmissionPolicy always composes.
        compiler = policy_expression_compiler(composition: true)
        issues = admission_policy_common_errors(spec, compiler)
        issues.concat(mutating_operations_errors(fetch(spec, "matchConstraints"), %w[spec matchConstraints]))
        has_params = fetch(spec, "paramKind").is_a?(Hash)
        mutations = fetch(spec, "mutations")
        if !mutations.is_a?(Array) || mutations.empty?
          issues << issue(%w[spec mutations], :required, "mutations must contain at least one item")
        else
          mutations.each_with_index do |mutation, index|
            next unless mutation.is_a?(Hash)

            base = ["spec", "mutations", index.to_s]
            patch_type = fetch(mutation, "patchType").to_s
            json_patch = fetch(mutation, "jsonPatch")
            apply_configuration = fetch(mutation, "applyConfiguration")
            case patch_type
            when ""
              issues << issue(base + ["patchType"], :required, "")
            when "JSONPatch"
              if json_patch.is_a?(Hash)
                issues.concat(mutation_expression_errors(json_patch, base + %w[jsonPatch expression], compiler, :json_patches, has_params))
              else
                issues << issue(base + ["jsonPatch"], :required, "must be specified when patchType is JSONPatch")
              end
              if apply_configuration.is_a?(Hash)
                issues << issue(base + ["applyConfiguration"], :invalid,
                                "must not be specified when patchType is JSONPatch")
              end
            when "ApplyConfiguration"
              if apply_configuration.is_a?(Hash)
                issues.concat(mutation_expression_errors(apply_configuration, base + %w[applyConfiguration expression], compiler, :object,
                                                         has_params))
              else
                issues << issue(base + ["applyConfiguration"], :required, "must be specified when patchType is ApplyConfiguration")
              end
              if json_patch.is_a?(Hash)
                issues << issue(base + ["jsonPatch"], :invalid,
                                "must not be specified when patchType is ApplyConfiguration")
              end
            else
              issues << issue(base + ["patchType"], :unsupported, unsupported_detail(%w[ApplyConfiguration JSONPatch]))
            end
          end
        end
        reinvocation = fetch(spec, "reinvocationPolicy").to_s
        if reinvocation.empty?
          issues << issue(%w[spec reinvocationPolicy], :required, "")
        elsif !%w[IfNeeded Never].include?(reinvocation)
          issues << issue(%w[spec reinvocationPolicy], :unsupported, unsupported_detail(%w[IfNeeded Never]))
        end
        issues
      end

      # pkg/apis/admissionregistration/validation validateValidatingAdmissionPolicySpec
      def validating_admission_policy_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        metadata = fetch(root, "metadata")
        metadata = {} unless metadata.is_a?(Hash)
        compiler = policy_compiler(spec)
        issues = admission_policy_common_errors(spec, compiler)
        validations = fetch(spec, "validations")
        validations = [] unless validations.is_a?(Array)
        annotations = fetch(spec, "auditAnnotations")
        annotations = [] unless annotations.is_a?(Array)
        if validations.empty? && annotations.empty?
          issues << issue(%w[spec validations], :required, "validations or auditAnnotations must contain at least one item")
          issues << issue(%w[spec auditAnnotations], :required, "validations or auditAnnotations must contain at least one item")
          return issues
        end
        validations.each_with_index do |validation, index|
          next unless validation.is_a?(Hash)

          base = ["spec", "validations", index.to_s]
          has_params = fetch(spec, "paramKind").is_a?(Hash)
          expression = fetch(validation, "expression").to_s
          if expression.strip.empty?
            issues << issue(base + ["expression"], :required, "expression is not specified")
          else
            compile_issue = cel_compile_issue(base + ["expression"], expression, compiler: compiler, return_types: cel_return_types(:bool),
                                                                                 has_params: has_params, has_authorizer: true)
            issues << compile_issue if compile_issue
          end
          message_expression = fetch(validation, "messageExpression").to_s
          if !message_expression.empty? && message_expression.strip.empty?
            issues << issue(base + ["messageExpression"], :required, "must be non-empty if specified")
          elsif !message_expression.strip.empty?
            compile_issue = cel_compile_issue(base + ["messageExpression"], message_expression, compiler: compiler,
                                                                                                return_types: cel_return_types(:string), has_params: has_params, has_authorizer: false)
            issues << compile_issue if compile_issue
          end
          message = fetch(validation, "message").to_s
          if !message.empty? && message.strip.empty?
            issues << issue(base + ["message"], :required, "message must be non-empty if specified")
          elsif message.strip.match?(/[\r\n]/)
            issues << issue(base + ["message"], :invalid, "message must not contain line breaks")
          end
          reason = fetch(validation, "reason")
          if !reason.nil? && !%w[Forbidden Invalid RequestEntityTooLarge].include?(reason.to_s)
            issues << issue(base + ["reason"], :unsupported, unsupported_detail(%w[Forbidden Invalid RequestEntityTooLarge]))
          end
        end
        issues << issue(%w[spec auditAnnotations], :invalid, "must not have more than 20 auditAnnotations") if annotations.length > 20
        seen = {}
        annotations.each_with_index do |annotation, index|
          next unless annotation.is_a?(Hash)

          base = ["spec", "auditAnnotations", index.to_s]
          key = fetch(annotation, "key").to_s
          if blank?(fetch(metadata, "name"))
            issues << issue(base + ["key"], :invalid, "requires metadata.name be non-empty")
          else
            issues.concat(invalid_messages(base + ["key"], qualified_name_messages("#{fetch(metadata, "name")}/#{key}")))
          end
          expression = fetch(annotation, "valueExpression").to_s
          if expression.strip.empty?
            issues << issue(base + ["valueExpression"], :required, "valueExpression is not specified")
          elsif expression.strip.bytesize > 5120
            issues << issue(base + ["valueExpression"], :required, "must not exceed 5120 bytes in length")
          else
            compile_issue = cel_compile_issue(base + ["valueExpression"], expression.strip, value: expression, compiler: compiler,
                                                                                            return_types: cel_return_types(:string_or_null),
                                                                                            has_params: fetch(spec, "paramKind").is_a?(Hash), has_authorizer: true)
            issues << compile_issue if compile_issue
          end
          issues << issue(base + ["key"], :duplicate, "") if seen[key]
          seen[key] = true
        end
        issues
      end

      # pkg/apis/admissionregistration/validation validateParamRef
      def param_ref_errors(ref, path)
        return [] unless ref.is_a?(Hash)

        issues = []
        name = fetch(ref, "name").to_s
        selector = fetch(ref, "selector")
        unless name.empty?
          issues.concat(invalid_messages(path + ["name"], path_segment_name_messages(name)))
          issues << issue(path + ["name"], :forbidden, "name and selector are mutually exclusive") if selector.is_a?(Hash)
        end
        if selector.is_a?(Hash)
          issues.concat(label_selector_errors(selector, path + ["selector"]))
          issues << issue(path + ["selector"], :forbidden, "name and selector are mutually exclusive") unless name.empty?
        end
        issues << issue(path, :required, "one of name or selector must be specified") if name.empty? && !selector.is_a?(Hash)
        action = fetch(ref, "parameterNotFoundAction")
        if !action.nil? && action.to_s.empty?
          issues << issue(path + ["parameterNotFoundAction"], :required, "")
        elsif !action.nil? && !%w[Deny Allow].include?(action.to_s)
          issues << issue(path + ["parameterNotFoundAction"], :unsupported, unsupported_detail(%w[Deny Allow]))
        end
        issues
      end

      # pkg/apis/admissionregistration/validation validateMutatingAdmissionPolicyBindingSpec
      def mutating_policy_binding_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        policy_name = fetch(spec, "policyName").to_s
        if policy_name.empty?
          issues << issue(%w[spec policyName], :required, "")
        else
          issues.concat(invalid_messages(%w[spec policyName], dns1123_subdomain_messages(policy_name)))
        end
        issues.concat(param_ref_errors(fetch(spec, "paramRef"), %w[spec paramRef]))
        issues.concat(match_resources_errors(fetch(spec, "matchResources"), %w[spec matchResources]))
        issues.concat(mutating_operations_errors(fetch(spec, "matchResources"), %w[spec matchResources]))
        issues
      end

      # ---- apiextensions CustomResourceDefinition ----------------------------

      def custom_resource_definition_errors(root, operation = :create)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        if operation == :update
          # ValidateCustomResourceDefinitionUpdate validates the retained
          # status names and stored versions of the stored object.
          status = fetch(root, "status")
          status = {} unless status.is_a?(Hash)
          accepted = fetch(status, "acceptedNames")
          issues.concat(crd_names_errors(accepted, %w[status acceptedNames])) if accepted.is_a?(Hash)
        end
        group = fetch(spec, "group").to_s
        if group.empty?
          issues << issue(%w[spec group], :required, "")
        else
          messages = dns1123_subdomain_messages(group)
          if !messages.empty?
            issues << issue(%w[spec group], :invalid, messages.join(","))
          elsif group.split(".").length < 2
            issues << issue(%w[spec group], :invalid, "should be a domain with at least one dot")
          end
        end
        scope = fetch(spec, "scope").to_s
        if scope.empty?
          issues << issue(%w[spec scope], :required, "")
        elsif !%w[Cluster Namespaced].include?(scope)
          issues << issue(%w[spec scope], :unsupported, unsupported_detail(%w[Cluster Namespaced]))
        end
        versions = fetch(spec, "versions")
        versions = [] unless versions.is_a?(Array)
        storage_count = 0
        names_seen = {}
        unique = true
        versions.each_with_index do |version, index|
          next unless version.is_a?(Hash)

          storage_count += 1 if fetch(version, "storage") == true
          name = fetch(version, "name").to_s
          if names_seen[name]
            unique = false
          else
            names_seen[name] = true
          end
          messages = dns1035_label_messages(name)
          unless messages.empty?
            issues << issue(["spec", "versions", index.to_s, "name"], :invalid, messages.join(","))
            # The v1 conversion mirrors the first version name into the
            # internal spec.version field, which is validated as well.
            issues << issue(%w[spec version], :invalid, messages.join(",")) if index.zero? && !name.empty?
          end
          schema = fetch(version, "schema")
          if !schema.is_a?(Hash) || !fetch(schema, "openAPIV3Schema").is_a?(Hash)
            issues << issue(["spec", "versions", index.to_s, "schema", "openAPIV3Schema"], :required, "")
          end
          issues.concat(crd_subresources_errors(fetch(version, "subresources"), ["spec", "versions", index.to_s, "subresources"]))
          Array(fetch(version, "additionalPrinterColumns")).each_with_index do |column, column_index|
            next unless column.is_a?(Hash)

            issues.concat(crd_column_errors(column, ["spec", "versions", index.to_s, "additionalPrinterColumns", column_index.to_s]))
          end
        end
        issues << issue(%w[spec versions], :invalid, "must contain unique version names") unless unique
        issues << issue(%w[spec versions], :invalid, "must have exactly one version marked as storage version") unless storage_count == 1
        names = fetch(spec, "names")
        names = {} unless names.is_a?(Hash)
        %w[plural singular kind listKind].each do |field|
          issues << issue(["spec", "names", field], :required, "") if fetch(names, field).to_s.empty?
        end
        issues.concat(crd_names_errors(names, %w[spec names]))
        issues.concat(crd_conversion_errors(fetch(spec, "conversion"), %w[spec conversion]))
        # PrepareForCreate derives status.storedVersions from the storage
        # version; ValidateCustomResourceDefinitionStoredVersions then runs.
        stored = versions.select { |version| version.is_a?(Hash) && fetch(version, "storage") == true }
        issues << issue(%w[status storedVersions], :invalid, "must have at least one stored version") if stored.empty?
        issues
      end

      def crd_names_errors(names, path)
        issues = []
        %w[plural singular].each do |field|
          value = fetch(names, field).to_s
          next if value.empty?

          messages = dns1035_label_messages(value)
          issues << issue(path + [field], :invalid, messages.join(",")) unless messages.empty?
        end
        %w[kind listKind].each do |field|
          value = fetch(names, field).to_s
          next if value.empty?

          messages = dns1035_label_messages(value.downcase)
          unless messages.empty?
            issues << issue(path + [field], :invalid,
                            "may have mixed case, but should otherwise match: #{messages.join(",")}")
          end
        end
        Array(fetch(names, "shortNames")).each_with_index do |short, index|
          messages = dns1035_label_messages(short)
          issues << issue(path + ["shortNames", index.to_s], :invalid, messages.join(",")) unless messages.empty?
        end
        kind = fetch(names, "kind").to_s
        issues << issue(path + ["listKind"], :invalid, "kind and listKind may not be the same") if !kind.empty? && kind == fetch(names,
                                                                                                                                 "listKind").to_s
        Array(fetch(names, "categories")).each_with_index do |category, index|
          messages = dns1035_label_messages(category)
          issues << issue(path + ["categories", index.to_s], :invalid, messages.join(",")) unless messages.empty?
        end
        issues
      end

      def crd_subresources_errors(subresources, path)
        return [] unless subresources.is_a?(Hash)

        scale = fetch(subresources, "scale")
        return [] unless scale.is_a?(Hash)

        issues = []
        {"specReplicasPath" => ".spec", "statusReplicasPath" => ".status"}.each do |field, prefix|
          value = fetch(scale, field).to_s
          if value.empty?
            issues << issue(path + ["scale.#{field}"], :required, "")
          elsif !value.match?(/\A\.[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)*\z/)
            issues << issue(path + ["scale.#{field}"], :invalid, "must be a simple json path starting with .")
          elsif !value.start_with?("#{prefix}.")
            issues << issue(path + ["scale.#{field}"], :invalid, "should be a json path under #{prefix}")
          end
        end
        issues
      end

      def crd_column_errors(column, path)
        issues = []
        issues << issue(path + ["name"], :required, "") if fetch(column, "name").to_s.empty?
        types = %w[boolean date integer number string]
        type = fetch(column, "type").to_s
        if type.empty?
          issues << issue(path + ["type"], :required, "must be one of #{types.join(",")}")
        elsif !types.include?(type)
          issues << issue(path + ["type"], :invalid, "must be one of #{types.join(",")}")
        end
        formats = %w[byte date date-time double float int32 int64 password]
        format = fetch(column, "format").to_s
        issues << issue(path + ["format"], :invalid, "must be one of #{formats.join(",")}") if !format.empty? && !formats.include?(format)
        issues << issue(path + ["JSONPath"], :required, "") if fetch(column, "jsonPath").to_s.empty?
        issues
      end

      def crd_conversion_errors(conversion, path)
        return [] unless conversion.is_a?(Hash)

        issues = []
        strategy = fetch(conversion, "strategy").to_s
        webhook = fetch(conversion, "webhook")
        webhook = {} unless webhook.is_a?(Hash)
        client = fetch(webhook, "clientConfig")
        review_versions = Array(fetch(webhook, "conversionReviewVersions"))
        case strategy
        when "None"
          if client.is_a?(Hash)
            issues << issue(path + ["webhookClientConfig"], :forbidden,
                            "should not be set when strategy is not set to Webhook")
          end
          unless review_versions.empty?
            issues << issue(path + ["conversionReviewVersions"], :forbidden,
                            "should not be set when strategy is not set to Webhook")
          end
        when "Webhook"
          if client.is_a?(Hash)
            url = fetch(client, "url")
            service = fetch(client, "service")
            if blank?(url) == !service.is_a?(Hash) ? false : (blank?(url) && !service.is_a?(Hash)) || (!blank?(url) && service.is_a?(Hash))
              issues << issue(path + ["webhookClientConfig"], :required,
                              "exactly one of url or service is required")
            end
          else
            issues << issue(path + ["webhookClientConfig"], :required, "required when strategy is set to Webhook")
          end
          if review_versions.empty?
            issues << issue(path + ["conversionReviewVersions"], :required, "")
          elsif (review_versions & %w[v1 v1beta1]).empty?
            issues << issue(path + ["conversionReviewVersions"], :invalid, "must include at least one of v1, v1beta1")
          end
        else
          issues << issue(path + ["strategy"], :unsupported, unsupported_detail(%w[None Webhook])) unless strategy.empty?
          issues << issue(path + ["strategy"], :required, "") if strategy.empty?
        end
        issues
      end

      # ---- scheduling.k8s.io v1alpha2 declarative validation ------------------
      # staging/src/k8s.io/api/scheduling/v1alpha2/types.go +k8s: tags.

      def scheduling_policy_errors(policy, path)
        policy = {} unless policy.is_a?(Hash)
        members = %w[basic gang].select { |member| fetch(policy, member).is_a?(Hash) }
        issues = []
        if members.empty?
          issues << issue(path, :invalid, "must specify one of: `basic`, `gang`")
        elsif members.length > 1
          issues << issue(path, :invalid, "must specify exactly one of: `basic`, `gang`")
        end
        gang = fetch(policy, "gang")
        if gang.is_a?(Hash)
          count = fetch(gang, "minCount")
          if count.nil?
            issues << issue(path + %w[gang minCount], :required, "")
          elsif count.is_a?(Integer) && count < 1
            issues << issue(path + %w[gang minCount], :invalid, "must be greater than or equal to 1")
          end
        end
        issues
      end

      def pod_group_resource_claims_errors(claims, path)
        return [] unless claims.is_a?(Array)

        issues = []
        issues << issue(path, :too_many, "must have at most 4 items") if claims.length > 4
        claims.each_with_index do |claim, index|
          next unless claim.is_a?(Hash)

          base = path + [index.to_s]
          name = fetch(claim, "name").to_s
          if name.empty?
            issues << issue(base + ["name"], :required, "")
          else
            issues.concat(invalid_messages(base + ["name"], dns1123_label_messages(name)))
          end
          members = %w[resourceClaimName resourceClaimTemplateName].reject { |member| fetch(claim, member).nil? }
          if members.empty?
            issues << issue(base, :invalid, "must specify one of: `resourceClaimName`, `resourceClaimTemplateName`")
          elsif members.length > 1
            issues << issue(base, :invalid, "must specify exactly one of: `resourceClaimName`, `resourceClaimTemplateName`")
          end
          members.each do |member|
            issues.concat(invalid_messages(base + [member], dns1123_subdomain_messages(fetch(claim, member))))
          end
        end
        issues
      end

      def pod_group_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        ref = fetch(spec, "podGroupTemplateRef")
        if ref.is_a?(Hash)
          workload = fetch(ref, "workload")
          if workload.is_a?(Hash)
            name = fetch(workload, "workloadName").to_s
            if name.empty?
              issues << issue(%w[spec podGroupTemplateRef workload workloadName], :required, "")
            else
              issues.concat(invalid_messages(%w[spec podGroupTemplateRef workload workloadName], dns1123_subdomain_messages(name)))
            end
            template = fetch(workload, "podGroupTemplateName").to_s
            if template.empty?
              issues << issue(%w[spec podGroupTemplateRef workload podGroupTemplateName], :required, "")
            else
              issues.concat(invalid_messages(%w[spec podGroupTemplateRef workload podGroupTemplateName], dns1123_label_messages(template)))
            end
          else
            issues << issue(%w[spec podGroupTemplateRef], :invalid, "must specify one of: `workload`")
          end
        end
        issues.concat(scheduling_policy_errors(fetch(spec, "schedulingPolicy"), %w[spec schedulingPolicy]))
        issues.concat(pod_group_resource_claims_errors(fetch(spec, "resourceClaims"), %w[spec resourceClaims]))
        issues
      end

      def workload_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        controller = fetch(spec, "controllerRef")
        if controller.is_a?(Hash)
          group = fetch(controller, "apiGroup").to_s
          issues.concat(invalid_messages(%w[spec controllerRef apiGroup], dns1123_subdomain_messages(group))) unless group.empty?
          %w[kind name].each do |field|
            value = fetch(controller, field).to_s
            if value.empty?
              issues << issue(["spec", "controllerRef", field], :required, "")
            else
              issues.concat(invalid_messages(["spec", "controllerRef", field], path_segment_name_messages(value)))
            end
          end
        end
        templates = fetch(spec, "podGroupTemplates")
        if !templates.is_a?(Array) || templates.empty?
          issues << issue(%w[spec podGroupTemplates], :required, "")
          return issues
        end
        issues << issue(%w[spec podGroupTemplates], :too_many, "must have at most 8 items") if templates.length > 8
        templates.each_with_index do |template, index|
          next unless template.is_a?(Hash)

          base = ["spec", "podGroupTemplates", index.to_s]
          name = fetch(template, "name").to_s
          if name.empty?
            issues << issue(base + ["name"], :required, "")
          else
            issues.concat(invalid_messages(base + ["name"], dns1123_label_messages(name)))
          end
          issues.concat(scheduling_policy_errors(fetch(template, "schedulingPolicy"), base + ["schedulingPolicy"]))
          issues.concat(pod_group_resource_claims_errors(fetch(template, "resourceClaims"), base + ["resourceClaims"]))
        end
        issues
      end

      # pkg/apis/policy/validation ValidatePodDisruptionBudgetSpec
      def pod_disruption_budget_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        if !fetch(spec, "minAvailable").nil? && !fetch(spec, "maxUnavailable").nil?
          issues << issue(%w[spec], :invalid, "minAvailable and maxUnavailable cannot be both set")
        end
        policy = fetch(spec, "unhealthyPodEvictionPolicy")
        if !policy.nil? && !%w[AlwaysAllow IfHealthyBudget].include?(policy.to_s)
          issues << issue(%w[spec unhealthyPodEvictionPolicy], :unsupported, unsupported_detail(%w[AlwaysAllow IfHealthyBudget]))
        end
        issues
      end

      # staging/src/k8s.io/api/resource/v1alpha3/types.go ResourcePoolStatusRequestSpec (declarative)
      def resource_pool_status_request_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = []
        driver = fetch(spec, "driver").to_s
        if driver.empty?
          issues << issue(%w[spec driver], :required, "")
        else
          issues.concat(invalid_messages(%w[spec driver], dns1123_subdomain_messages(driver)))
        end
        pool = fetch(spec, "poolName")
        issues.concat(pool_name_errors(pool, %w[spec poolName])) unless pool.nil?
        limit = fetch(spec, "limit")
        if limit.is_a?(Integer)
          issues << issue(%w[spec limit], :invalid, "must be greater than or equal to 1") if limit < 1
          issues << issue(%w[spec limit], :invalid, "must be less than or equal to 1000") if limit > 1000
        end
        count = fetch(spec, "poolCount")
        issues << issue(%w[spec poolCount], :invalid, "must be greater than or equal to 0") if count.is_a?(Integer) && count.negative?
        issues
      end

      # pkg/apis/certificates/helpers.go ParseCSR
      def certificate_request_errors(value)
        require "openssl"
        path = %w[spec request]
        bytes = decode_wire_bytes(value)
        bytes = value.to_s if bytes.nil?
        match = bytes.match(/-----BEGIN ([^-]+)-----/)
        return [issue(path, :invalid, "PEM block type must be CERTIFICATE REQUEST")] if match.nil? || match[1] != "CERTIFICATE REQUEST"

        OpenSSL::X509::Request.new(bytes)
        []
      rescue OpenSSL::X509::RequestError, OpenSSL::ASN1::ASN1Error, ArgumentError
        [issue(path, :invalid, "must be a valid PKCS#10 certificate request")]
      end

      # pkg/apis/batch/validation ValidateJob: an Indexed job's highest pod
      # hostname (<name>-<completions-1>) must be a DNS label.
      def indexed_job_hostname_errors(root)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash) && fetch(spec, "completionMode").to_s == "Indexed"

        completions = fetch(spec, "completions")
        return [] unless completions.is_a?(Integer) && completions.positive?

        metadata = fetch(root, "metadata")
        name = metadata.is_a?(Hash) ? fetch(metadata, "name").to_s : ""
        hostname = "#{name}-#{completions - 1}"
        return [] if dns1123_label_messages(hostname).empty?

        [issue(%w[metadata name], :invalid, "will not able to create pod with invalid DNS label: #{hostname}")]
      end

      # pkg/apis/core/validation ValidatePodCreate (ephemeral containers are a
      # subresource) and validateContainers (names are unique across the
      # container lists).
      def pod_container_set_errors(root, _operation)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = []
        # The create-time ephemeralContainers Forbidden is reported by the
        # PodSpec walk in pod_nested_errors.
        seen = {}
        %w[initContainers containers ephemeralContainers].each do |list|
          Array(fetch(spec, list)).each_with_index do |container, index|
            next unless container.is_a?(Hash)

            name = fetch(container, "name").to_s
            next if name.empty?

            issues << issue(["spec", list, index.to_s, "name"], :duplicate, "") if seen[name]
            seen[name] = true
          end
        end
        issues
      end

      # pkg/apis/core/validation validateResourceClaimNames / pod-level resources:
      # container resources.claims must name entries of spec.resourceClaims;
      # pod-level resources may not carry claims.
      def resource_claim_reference_errors(root, claims, path)
        issues = []
        pod_level = path == %w[spec resources claims]
        issues << issue(path, :forbidden, "claims may not be set for Resources at pod-level") if pod_level
        spec = fetch(root, "spec")
        names = if spec.is_a?(Hash)
                  Array(fetch(spec, "resourceClaims")).filter_map do |entry|
                    entry.is_a?(Hash) ? fetch(entry, "name").to_s : nil
                  end
                else
                  []
                end
        claims.each_with_index do |entry, index|
          name = entry.is_a?(Hash) ? fetch(entry, "name").to_s : ""
          next if !pod_level && names.include?(name)

          detail = names.empty? ? "must be one of the names in pod.spec.resourceClaims which is empty" : "must be one of the names in pod.spec.resourceClaims"
          issues << issue(path + [index.to_s], :not_found, detail)
        end
        issues
      end

      # ---- resource.k8s.io ResourceClaim (pkg/apis/resource/validation validateDeviceClaim)

      def resource_claim_errors(root, spec_path)
        spec = spec_path.reduce(root) { |current, segment| current.is_a?(Hash) ? fetch(current, segment) : nil }
        return [] unless spec.is_a?(Hash)

        devices = fetch(spec, "devices")
        return [] unless devices.is_a?(Hash)

        path = spec_path + ["devices"]
        issues = []
        requests = Array(fetch(devices, "requests"))
        request_names = {}
        requests.each do |request|
          next unless request.is_a?(Hash)

          subrequests = Array(fetch(request, "firstAvailable")).grep(Hash)
          request_names[fetch(request, "name").to_s] = subrequests.map { |sub| fetch(sub, "name").to_s }
        end
        issues << issue(path + ["requests"], :too_many, "must have at most 32 items") if requests.length > 32
        seen = {}
        requests.each_with_index do |request, index|
          next unless request.is_a?(Hash)

          base = path + ["requests", index.to_s]
          name = fetch(request, "name").to_s
          issues.concat(dra_request_name_errors(name, base + ["name"]))
          issues << issue(base + ["name"], :duplicate, "") if seen[name]
          seen[name] = true
          first_available = fetch(request, "firstAvailable")
          exactly = fetch(request, "exactly")
          # v1beta1 carries the exact request fields inline on the request;
          # conversion materializes Exactly when any of them is set.
          if exactly.nil?
            inline = request.select do |key, _value|
              %w[deviceClassName selectors allocationMode count adminAccess tolerations capacity].include?(key.to_s)
            end
            exactly = inline unless inline.empty?
          end
          has_first = first_available.is_a?(Array) && !first_available.empty?
          has_exactly = exactly.is_a?(Hash)
          if !has_first && !has_exactly
            issues << issue(base, :required, "exactly one of `exactly` or `firstAvailable` is required")
          elsif has_first && has_exactly
            issues << issue(base, :invalid, "exactly one of `exactly` or `firstAvailable` is required, but multiple fields are set")
          elsif has_first
            issues << issue(base + ["firstAvailable"], :too_many, "must have at most 8 items") if first_available.length > 8
            sub_seen = {}
            first_available.each_with_index do |sub, sub_index|
              next unless sub.is_a?(Hash)

              sub_base = base + ["firstAvailable", sub_index.to_s]
              sub_name = fetch(sub, "name").to_s
              issues.concat(dra_request_name_errors(sub_name, sub_base + ["name"]))
              issues << issue(sub_base + ["name"], :duplicate, "") if sub_seen[sub_name]
              sub_seen[sub_name] = true
              issues.concat(dra_device_request_body_errors(sub, sub_base))
            end
          else
            issues.concat(dra_device_request_body_errors(exactly, base + ["exactly"]))
          end
        end
        constraints = Array(fetch(devices, "constraints"))
        issues << issue(path + ["constraints"], :too_many, "must have at most 32 items") if constraints.length > 32
        constraints.each_with_index do |constraint, index|
          next unless constraint.is_a?(Hash)

          base = path + ["constraints", index.to_s]
          issues.concat(dra_request_reference_errors(fetch(constraint, "requests"), base + ["requests"], request_names))
          match = fetch(constraint, "matchAttribute")
          distinct = fetch(constraint, "distinctAttribute")
          if !match.nil?
            issues.concat(dra_fully_qualified_name_errors(match, base + ["matchAttribute"]))
          elsif !distinct.nil?
            issues.concat(dra_fully_qualified_name_errors(distinct, base + ["distinctAttribute"]))
          else
            issues << issue(base, :required,
                            "exactly one of \"matchAttribute\" or \"distinctAttribute\" is required, but multiple fields are set")
          end
        end
        configs = Array(fetch(devices, "config"))
        issues << issue(path + ["config"], :too_many, "must have at most 32 items") if configs.length > 32
        configs.each_with_index do |config, index|
          next unless config.is_a?(Hash)

          base = path + ["config", index.to_s]
          issues.concat(dra_request_reference_errors(fetch(config, "requests"), base + ["requests"], request_names))
          issues.concat(dra_device_configuration_errors(config, base))
        end
        issues
      end

      def dra_request_name_errors(name, path)
        return [issue(path, :required, "")] if name.empty?

        invalid_messages(path, dns1123_label_messages(name))
      end

      def dra_fully_qualified_name_errors(name, path)
        name = name.to_s
        parts = name.split("/", -1)
        return [issue(path, :invalid, "a fully qualified name must be a domain and a name separated by a slash")] unless parts.length == 2

        issues = invalid_messages(path, dns1123_subdomain_messages(parts[0]))
        issues.concat(invalid_messages(path, dns1123_label_messages(parts[1])))
        issues
      end

      def dra_request_reference_errors(references, path, request_names)
        return [] unless references.is_a?(Array)

        issues = []
        issues << issue(path, :too_many, "must have at most 32 items") if references.length > 32
        seen = {}
        references.each_with_index do |reference, index|
          reference = reference.to_s
          base = path + [index.to_s]
          segments = reference.split("/", -1)
          if segments.length > 2
            issues << issue(base, :invalid,
                            "must be the name of a request in the claim or the name of a request and a subrequest separated by '/'")
            next
          end
          segments.each { |segment| issues.concat(dra_request_name_errors(segment, base)) }
          known = request_names.key?(segments[0]) &&
                  (segments.length == 1 || request_names.fetch(segments[0]).include?(segments[1]))
          unless known
            issues << issue(base, :invalid,
                            "must be the name of a request in the claim or the name of a request and a subrequest separated by '/'")
          end
          issues << issue(base, :duplicate, "") if seen[reference]
          seen[reference] = true
        end
        issues
      end

      def dra_device_request_body_errors(request, path)
        issues = []
        class_name = fetch(request, "deviceClassName").to_s
        if class_name.empty?
          issues << issue(path + ["deviceClassName"], :required, "")
        else
          issues.concat(invalid_messages(path + ["deviceClassName"], dns1123_subdomain_messages(class_name)))
        end
        Array(fetch(request, "selectors")).each_with_index do |selector, index|
          next unless selector.is_a?(Hash)

          base = path + ["selectors", index.to_s]
          cel = fetch(selector, "cel")
          if cel.is_a?(Hash)
            issues << issue(base + %w[cel expression], :required, "") if fetch(cel, "expression").to_s.empty?
          else
            issues << issue(base + ["cel"], :required, "")
          end
        end
        mode = fetch(request, "allocationMode")
        count = fetch(request, "count")
        count = 0 if count.nil?
        case mode.to_s
        when "", "ExactCount"
          # SetDefaults_DeviceRequest defaults allocationMode to ExactCount and count to 1.
          if mode.to_s == "ExactCount" && count.is_a?(Integer) && count <= 0
            issues << issue(path + ["count"], :invalid,
                            "must be greater than zero")
          end
        when "All"
          if count.is_a?(Integer) && count != 0
            issues << issue(path + ["count"], :invalid,
                            "must not be specified when allocationMode is 'All'")
          end
        else
          issues << issue(path + ["allocationMode"], :unsupported, unsupported_detail(%w[All ExactCount]))
        end
        Array(fetch(request, "tolerations")).each_with_index do |toleration, index|
          next unless toleration.is_a?(Hash)

          base = path + ["tolerations", index.to_s]
          key = fetch(toleration, "key").to_s
          issues.concat(invalid_messages(base + ["key"], qualified_name_messages(key))) unless key.empty?
          value = fetch(toleration, "value").to_s
          case fetch(toleration, "operator").to_s
          when "Exists"
            issues << issue(base + ["value"], :invalid, "must be empty for operator `Exists`") unless value.empty?
          when "Equal"
            issues.concat(invalid_messages(base + ["value"], label_value_messages(value)))
          when ""
            issues << issue(base + ["operator"], :required, "")
          else
            issues << issue(base + ["operator"], :unsupported, unsupported_detail(%w[Equal Exists]))
          end
          effect = fetch(toleration, "effect").to_s
          issues << issue(base + ["effect"], :unsupported, unsupported_detail(%w[NoExecute NoSchedule None])) if !effect.empty? && !%w[
            NoExecute NoSchedule None
          ].include?(effect)
        end
        issues
      end

      def dra_device_configuration_errors(config, path)
        opaque = fetch(config, "opaque")
        return [issue(path + ["opaque"], :required, "")] unless opaque.is_a?(Hash)

        issues = []
        driver = fetch(opaque, "driver").to_s
        if driver.empty?
          issues << issue(path + %w[opaque driver], :required, "")
        else
          issues.concat(invalid_messages(path + %w[opaque driver], dns1123_subdomain_messages(driver)))
        end
        issues << issue(path + %w[opaque parameters], :required, "") if fetch(opaque, "parameters").nil?
        issues
      end

      # ---- certificates PodCertificateRequest --------------------------------

      def signer_name_errors(value, path)
        value = value.to_s
        return [issue(path, :required, "")] if value.empty?

        segments = value.split("/", -1)
        unless segments.length == 2
          return [issue(path, :invalid,
                        "must be a fully qualified domain and path of the form 'example.com/signer-name'")]
        end

        issues = []
        domain, signer_path = segments
        issues << issue(path, :too_long, "may not be more than 253 bytes") if domain.length > 253
        domain_labels = domain.split(".", -1)
        domain_labels.each do |label|
          messages = dns1123_label_messages(label)
          next if messages.empty?

          issues.concat(messages.map { |message| issue(path, :invalid, "validating label #{label.inspect}: #{message}") })
          break
        end
        issues << issue(path, :invalid, "should be a domain with at least two segments separated by dots") if domain_labels.length < 2
        signer_path.split(".", -1).each do |label|
          messages = dns1123_subdomain_messages(label)
          next if messages.empty?

          issues.concat(messages.map { |message| issue(path, :invalid, "validating label #{label.inspect}: #{message}") })
          break
        end
        issues << issue(path, :too_long, "may not be more than 571 bytes") if value.length > 571
        issues
      end

      def pod_certificate_request_errors(root)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        issues = signer_name_errors(fetch(spec, "signerName"), %w[spec signerName])
        annotations = fetch(spec, "unverifiedUserAnnotations")
        if annotations.is_a?(Hash)
          annotations.each_key do |key|
            issues.concat(invalid_messages(%w[spec unverifiedUserAnnotations], qualified_name_messages(key.to_s.downcase)))
          end
        end
        {"podName" => "podUID", "serviceAccountName" => "serviceAccountUID", "nodeName" => "nodeUID"}.each do |name_field, uid_field|
          issues.concat(invalid_messages(["spec", name_field], dns1123_subdomain_messages(fetch(spec, name_field).to_s)))
          uid = fetch(spec, uid_field).to_s
          issues << issue(["spec", uid_field], :invalid, "must not be empty") if uid.empty?
          issues << issue(["spec", uid_field], :too_long, "may not be more than 128 bytes") if uid.length > 128
        end
        # pkg/apis/certificates/v1beta1/defaults.go SetDefaults_PodCertificateRequestSpec
        # supplies MaxExpirationSeconds before validation runs.
        max_expiration = fetch(spec, "maxExpirationSeconds")
        max_expiration = POD_CERTIFICATE_REQUEST_DEFAULT_MAX_EXPIRATION if max_expiration.nil?
        signer = fetch(spec, "signerName").to_s
        kubernetes_signer = signer.start_with?("kubernetes.io/")
        upper = kubernetes_signer ? 86_400 : 7_862_400
        unless max_expiration.is_a?(Integer) && max_expiration >= 3600 && max_expiration <= upper
          issues << issue(%w[spec maxExpirationSeconds], :invalid, "must be in the range [3600, #{upper}]")
        end
        stub = fetch(spec, "stubPKCS10Request").to_s
        pkix = fetch(spec, "pkixPublicKey").to_s
        proof = fetch(spec, "proofOfPossession").to_s
        if !stub.empty? && pkix.empty? && proof.empty?
          issues.concat(stub_pkcs10_request_errors(stub))
        elsif stub.empty? && !pkix.empty? && !proof.empty?
          issues.concat(pkix_public_key_errors(pkix, proof, fetch(spec, "podUID").to_s))
        else
          issues << issue(%w[spec], :invalid, "exactly one of (stubPKCS10Request) or (pkixPublicKey, proofOfPossession) must be set")
        end
        issues
      end

      def decode_wire_bytes(value)
        require "base64"
        Base64.strict_decode64(value.to_s)
      rescue ArgumentError
        nil
      end

      def stub_pkcs10_request_errors(encoded)
        require "openssl"
        path = %w[spec stubPKCS10Request]
        der = decode_wire_bytes(encoded)
        return [issue(path, :invalid, "must be a valid PKCS#10 CSR")] if der.nil?
        return [issue(path, :too_long, "may not be more than 10240 bytes")] if der.bytesize > 10_240

        request = begin
          OpenSSL::X509::Request.new(der)
        rescue OpenSSL::X509::RequestError, OpenSSL::ASN1::ASN1Error
          nil
        end
        return [issue(path, :invalid, "must be a valid PKCS#10 CSR")] if request.nil?

        public_key = request.public_key
        case public_key
        when OpenSSL::PKey::EC
          curve = public_key.group.curve_name
          return [issue(path, :invalid, "elliptic public keys must use curve P256, P384, or P521")] unless %w[prime256v1 secp384r1
                                                                                                              secp521r1].include?(curve)
        when OpenSSL::PKey::RSA
          bits = public_key.n.num_bits
          return [issue(path, :invalid, "RSA keys must have modulus size 3072 or 4096")] unless [3072, 4096].include?(bits)
        else
          unless public_key.oid == "ED25519"
            return [issue(path, :invalid,
                          "unknown public key type; supported types are Ed25519, ECDSA, and RSA")]
          end
        end
        request.verify(public_key) ? [] : [issue(path, :invalid, "invalid signature")]
      rescue OpenSSL::PKey::PKeyError
        [issue(path, :invalid, "must be a valid PKCS#10 CSR")]
      end

      def pkix_public_key_errors(pkix, proof, pod_uid)
        require "openssl"
        pkix_path = %w[spec pkixPublicKey]
        proof_path = %w[spec proofOfPossession]
        key_der = decode_wire_bytes(pkix)
        proof_der = decode_wire_bytes(proof)
        return [issue(pkix_path, :invalid, "must be a valid PKIX-serialized public key")] if key_der.nil?
        return [issue(pkix_path, :too_long, "may not be more than 10240 bytes")] if key_der.bytesize > 10_240
        return [issue(proof_path, :too_long, "may not be more than 10240 bytes")] if proof_der && proof_der.bytesize > 10_240

        public_key = begin
          OpenSSL::PKey.read(key_der)
        rescue OpenSSL::PKey::PKeyError
          nil
        end
        return [issue(pkix_path, :invalid, "must be a valid PKIX-serialized public key")] if public_key.nil?

        digest = OpenSSL::Digest::SHA256.digest(pod_uid)
        verified = case public_key
                   when OpenSSL::PKey::EC
                     return [issue(pkix_path, :invalid, "elliptic public keys must use curve P256 or P384")] unless %w[prime256v1 secp384r1
                                                                                                                       secp521r1].include?(public_key.group.curve_name)

                     public_key.dsa_verify_asn1(digest, proof_der.to_s)
                   when OpenSSL::PKey::RSA
                     return [issue(pkix_path, :invalid, "RSA keys must have modulus size 3072 or 4096")] unless [3072,
                                                                                                                 4096].include?(public_key.n.num_bits)

                     public_key.verify_pss("SHA256", proof_der.to_s, digest, salt_length: :auto, mgf1_hash: "SHA256")
                   else
                     unless public_key.oid == "ED25519"
                       return [issue(pkix_path, :invalid,
                                     "unknown public key type; supported types are Ed25519, ECDSA, and RSA")]
                     end

                     public_key.verify(nil, proof_der.to_s, pod_uid)
                   end
        verified ? [] : [issue(proof_path, :invalid, "could not verify proof-of-possession signature")]
      rescue OpenSSL::PKey::PKeyError
        [issue(proof_path, :invalid, "could not verify proof-of-possession signature")]
      end

      # ---- resource.k8s.io DeviceTaintRule -----------------------------------

      def device_taint_rule_errors(root, old = nil)
        spec = fetch(root, "spec")
        spec = {} unless spec.is_a?(Hash)
        old_spec = old.is_a?(Hash) ? fetch(old, "spec") : nil
        old_taint = old_spec.is_a?(Hash) ? fetch(old_spec, "taint") : nil
        issues = []
        selector = fetch(spec, "deviceSelector")
        if selector.is_a?(Hash)
          driver = fetch(selector, "driver")
          issues.concat(invalid_messages(%w[spec deviceSelector driver], dns1123_subdomain_messages(driver))) unless driver.nil?
          pool = fetch(selector, "pool")
          issues.concat(pool_name_errors(pool, %w[spec deviceSelector pool])) unless pool.nil?
          device = fetch(selector, "device")
          issues.concat(invalid_messages(%w[spec deviceSelector device], dns1123_label_messages(device))) unless device.nil?
        end
        taint = fetch(spec, "taint")
        taint = {} unless taint.is_a?(Hash)
        issues.concat(invalid_messages(%w[spec taint key], qualified_name_messages(fetch(taint, "key").to_s)))
        value = fetch(taint, "value").to_s
        issues.concat(invalid_messages(%w[spec taint value], label_value_messages(value))) unless value.empty?
        effect = fetch(taint, "effect").to_s
        if !old_taint.is_a?(Hash) || fetch(old_taint, "effect").to_s != effect
          if effect.empty?
            issues << issue(%w[spec taint effect], :required, "")
          elsif !%w[NoExecute NoSchedule None].include?(effect)
            issues << issue(%w[spec taint effect], :unsupported, unsupported_detail(%w[NoExecute NoSchedule None]))
          end
        end
        issues
      end

      def pool_name_errors(name, path)
        name = name.to_s
        return [issue(path, :required, "")] if name.empty?
        return [issue(path, :too_long, "may not be more than 253 bytes")] if name.length > 253

        name.split("/", -1).flat_map { |part| invalid_messages(path, dns1123_subdomain_messages(part)) }
      end

      # ---- apiserverinternal StorageVersion status ---------------------------

      def api_version_messages(value)
        value = value.to_s
        parts = value.split("/", -1)
        messages = []
        case parts.length
        when 1
          version = parts[0]
        when 2
          group, version = parts
          if group.empty?
            messages << "group part: must be non-empty"
          else
            messages.concat(dns1123_subdomain_messages(group).map { |message| "group part: #{message}" })
          end
        else
          return ["an apiVersion is a DNS-1035 label, which must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?') with an optional DNS subdomain prefix and '/' (e.g. 'example.com/MyVersion')"]
        end
        if version.empty?
          messages << "version part: must be non-empty"
        else
          messages.concat(dns1035_label_messages(version).map { |message| "version part: #{message}" })
        end
        messages
      end

      def storage_version_errors(root)
        status = fetch(root, "status")
        return [] unless status.is_a?(Hash)

        issues = []
        entries = Array(fetch(status, "storageVersions"))
        seen = {}
        entries.each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          base = ["status", "storageVersions", index.to_s]
          server = fetch(entry, "apiServerID").to_s
          if seen[server]
            issues << issue(base + ["apiServerID"], :duplicate, "")
          else
            seen[server] = true
          end
          issues.concat(invalid_messages(base + ["apiServerID"], dns1123_subdomain_messages(server)))
          encoding = fetch(entry, "encodingVersion").to_s
          messages = api_version_messages(encoding)
          issues << issue(base + ["encodingVersion"], :invalid, messages.join(",")) unless messages.empty?
          decodable = Array(fetch(entry, "decodableVersions"))
          decodable.each_with_index do |version, version_index|
            messages = api_version_messages(version)
            issues << issue(base + ["decodableVersions", version_index.to_s], :invalid, messages.join(",")) unless messages.empty?
          end
          unless decodable.include?(encoding)
            issues << issue(base + ["decodableVersions"], :invalid,
                            "decodableVersions must include encodingVersion #{encoding}")
          end
          Array(fetch(entry, "servedVersions")).each_with_index do |version, version_index|
            messages = api_version_messages(version)
            issues << issue(base + ["servedVersions", version_index.to_s], :invalid, messages.join(",")) unless messages.empty?
            unless decodable.include?(version)
              issues << issue(base + ["servedVersions", version_index.to_s], :invalid,
                              "individual served version : #{version} must be included in decodableVersions : #{decodable.inspect.tr(",", "")}")
            end
          end
        end
        encodings = entries.grep(Hash).map { |entry| fetch(entry, "encodingVersion").to_s }
        actual_common = encodings.empty? || encodings.uniq.length != 1 ? nil : encodings.first
        common = fetch(status, "commonEncodingVersion")
        if actual_common.nil? && !common.nil?
          issues << issue(%w[status commonEncodingVersion], :invalid,
                          "should be nil if servers do not agree on the same encoding version, or if there is no server reporting the supported versions yet")
        elsif !actual_common.nil? && common.nil?
          issues << issue(%w[status commonEncodingVersion], :invalid, "the common encoding version is #{actual_common}")
        elsif !actual_common.nil? && !common.nil? && actual_common != common.to_s
          issues << issue(%w[status commonEncodingVersion], :invalid, "the actual common encoding version is #{actual_common}")
        end
        seen_types = {}
        Array(fetch(status, "conditions")).each_with_index do |condition, index|
          next unless condition.is_a?(Hash)

          base = ["status", "conditions", index.to_s]
          type = fetch(condition, "type").to_s
          if seen_types.key?(type)
            issues << issue(base + ["type"], :invalid,
                            "the type of the condition is not unique, it also appears in conditions[#{seen_types[type]}]")
          end
          seen_types[type] = index
          issues.concat(invalid_messages(base + ["type"], qualified_name_messages(type)))
          issues.concat(invalid_messages(base + ["status"], qualified_name_messages(fetch(condition, "status").to_s)))
          issues << issue(base + ["reason"], :required, "") if fetch(condition, "reason").to_s.empty?
          issues << issue(base + ["message"], :required, "") if fetch(condition, "message").to_s.empty?
        end
        issues
      end

      def required(object, name, path, issues, detail = "")
        issues << issue(path + [name], :required, detail) if blank?(fetch(object, name))
      end

      def issue(path, code, message)
        kubernetes_type = case code
                          when :required then "Required value"
                          when :unsupported then "Unsupported value"
                          when :not_found then "Not found"
                          when :forbidden then "Forbidden"
                          when :duplicate then "Duplicate value"
                          when :internal then "Internal error"
                          when :too_long then "Too long"
                          when :too_many then "Too many"
                          else "Invalid value"
                          end
        ValidationIssue.new(path: path, code: code, message: message, kubernetes_type: kubernetes_type)
      end

      def object_like?(value)
        value.is_a?(Hash) || value.is_a?(ValueObject)
      end

      def plain_object(value)
        return value if value.is_a?(Hash)

        value.to_h
      end

      def fetch(object, key)
        return nil unless object.is_a?(Hash)
        return object[key] if object.key?(key)
        return object[key.to_sym] if object.key?(key.to_sym)

        nil
      end

      def value_at_path(object, path)
        path.reduce(object) do |current, segment|
          if current.is_a?(Hash)
            fetch(current, segment)
          elsif current.is_a?(Array) && segment.to_s.match?(/\A\d+\z/)
            current[segment.to_i]
          end
        end
      end

      def blank?(value)
        value.nil? || (value.is_a?(String) && value.empty?)
      end

      def zero_value?(value)
        return true if value.nil? || value == false || value == 0 || value == ""
        return value.all? { |item| zero_value?(item) } if value.is_a?(Array)
        return value.empty? || value.values.all? { |item| zero_value?(item) } if value.is_a?(Hash)

        false
      end

      def provided?(value)
        return false if value.nil?
        return false if value.is_a?(String) && value.empty?
        return false if value.is_a?(Hash) && value.empty?

        true
      end

      def blank_array?(value)
        value.nil? || (value.is_a?(Array) && value.empty?)
      end

      # Static CEL result type ("bool", "int", "dyn", ...) from the project's
      # CEL parser; a syntax error is reported as "error" so the caller
      # rejects the expression the way the apiserver's compile step does.
      def cel_compile_error(expression)
        require "rubernetes/security/cel" unless defined?(Rubernetes::Security::CEL::Types)
        Rubernetes::Security::CEL::Types.result_type(expression)
        "expression does not compile"
      rescue Rubernetes::Security::CEL::Error, NotImplementedError => error
        error.message
      end

      def cel_result_type(expression)
        require "rubernetes/security/cel" unless defined?(Rubernetes::Security::CEL::Types)
        Rubernetes::Security::CEL::Types.result_type(expression).to_s
      rescue Rubernetes::Security::CEL::Error, NotImplementedError
        # An expression CEL itself cannot compile really does have the error
        # type; anything else (a load failure, a bug in the checker) must not
        # masquerade as one, or every expression is rejected.
        "error"
      end

      def kubernetes_type_name(value)
        return "null" if value.nil?
        return "bool" if [true, false].include?(value)
        return "string" if value.is_a?(String)
        return "int" if value.is_a?(Integer)
        return "float" if value.is_a?(Float)
        return "array" if value.is_a?(Array)
        return "object" if value.is_a?(Hash)

        value.class.name.to_s.downcase
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
    end
  end
end

require_relative "kubernetes_validator/pod_resources"
require_relative "kubernetes_validator/pod_resize"
require_relative "kubernetes_validator/pod_update"
require_relative "kubernetes_validator/admission_policy_cel"
require_relative "kubernetes_validator/resource_quota"
require_relative "kubernetes_validator/label_keys"
require_relative "kubernetes_validator/ip_fields"
require_relative "kubernetes_validator/resource_claim_status"
