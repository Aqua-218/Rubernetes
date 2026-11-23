# frozen_string_literal: true

module Rubernetes
  module Schema
    # ObjectMeta validation (apimachinery ValidateObjectMeta and
    # ValidateObjectMetaUpdate) and the per-kind name functions, applied
    # per operation the way each registry strategy applies them.
    module KubernetesValidator
      module_function

      # Handler kinds whose validation function never touches ObjectMeta
      # (ValidateScale does: ValidateObjectMeta with a required namespace).
      METADATA_EXEMPT_KINDS = %w[TokenRequest SubjectAccessReview SelfSubjectAccessReview LocalSubjectAccessReview Binding].freeze

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
        issues.concat(kube_finalizer_errors(definition.group, kind, metadata))
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

      # These registries use core/validation.ValidateObjectMeta, whose legacy
      # finalizer check is stricter than apimachinery's qualified-name check.
      KUBE_FINALIZER_KINDS = %w[
        CertificateSigningRequest ClusterRole ClusterRoleBinding ClusterTrustBundle ConfigMap
        ControllerRevision CronJob CSIDriver CSINode CSIStorageCapacity DaemonSet Deployment DeviceClass
        DeviceTaintRule EndpointSlice Endpoints FlowSchema HorizontalPodAutoscaler Ingress IngressClass
        IPAddress Job LimitRange Namespace NetworkPolicy Node PersistentVolume PersistentVolumeClaim Pod
        PodCertificateRequest PodGroup PodTemplate PriorityClass PriorityLevelConfiguration ReplicaSet
        ReplicationController ResourceClaim ResourceClaimTemplate ResourcePoolStatusRequest ResourceQuota
        ResourceSlice Role RoleBinding Scale Secret Service ServiceAccount ServiceCIDR StatefulSet
        StorageClass StorageVersion StorageVersionMigration VolumeAttachment VolumeAttributesClass Workload
      ].freeze
      STANDARD_FINALIZERS = %w[kubernetes orphan foregroundDeletion].freeze

      def kube_finalizer_errors(group, kind, metadata)
        finalizers = fetch(metadata, "finalizers")
        return [] unless finalizers.is_a?(Array) && !finalizers.empty?
        return [] unless KUBE_FINALIZER_KINDS.include?(kind) || (kind == "Event" && group == "events.k8s.io")

        finalizers.each_with_index.filter_map do |value, index|
          next unless value.is_a?(String) && !value.include?("/") && !STANDARD_FINALIZERS.include?(value)

          issue(["metadata", "finalizers", index.to_s], :invalid, "name is neither a standard finalizer name nor is it fully qualified")
        end
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
    end
  end
end
