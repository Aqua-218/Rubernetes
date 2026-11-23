# frozen_string_literal: true

require "pathname"

module Rubernetes
  module Schema
    # PersistentVolume, PersistentVolumeClaim, VolumeAttachment, StorageClass,
    # CSIStorageCapacity and CSINode.
    module KubernetesValidator
      module_function

      SUPPORTED_ACCESS_MODES = %w[ReadOnlyMany ReadWriteMany ReadWriteOnce ReadWriteOncePod].freeze

      def pvc_errors(root, _operation = :create, old: nil, path: ["spec"])
        spec = fetch(root, "spec") || {}
        return [] unless spec.is_a?(Hash)

        issues = pvc_access_modes(fetch(spec, "accessModes"), path)
        selector = fetch(spec, "selector")
        issues.concat(label_selector_errors(selector, path + ["selector"])) if selector.is_a?(Hash)
        storage_path = path + %w[resources [storage]]
        storage = fetch(fetch(fetch(spec, "resources"), "requests"), "storage")
        if !provided?(storage)
          issues << issue(storage_path, :required, "")
        elsif (quantity = limit_quantity(storage)) && !quantity.positive?
          issues << valued_issue(storage_path, storage, "must be greater than zero")
        end
        %w[storageClassName volumeAttributesClassName].each do |field|
          name = fetch(spec, field)
          issues.concat(invalid_messages(path + [field], dns1123_subdomain_messages(name))) unless blank?(name)
        end
        mode = fetch(spec, "volumeMode")
        issues << issue(path + ["volumeMode"], :unsupported, 'supported values: "Block", "Filesystem"') if mode && !%w[Block Filesystem].include?(mode)
        issues.concat(pvc_data_source_errors(spec, old, path))
      end

      def pvc_access_modes(modes, path)
        field = path + ["accessModes"]
        return [issue(field, :required, "at least 1 access mode is required")] unless modes.is_a?(Array) && !modes.empty?

        issues = modes.reject { |mode| SUPPORTED_ACCESS_MODES.include?(mode) }.map do |mode|
          ValidationIssue.new(path: field, code: :unsupported, kubernetes_type: "Unsupported value", value: mode,
                              message: "supported values: #{SUPPORTED_ACCESS_MODES.map(&:inspect).join(", ")}")
        end
        if modes.include?("ReadWriteOncePod") && !(modes & (SUPPORTED_ACCESS_MODES - ["ReadWriteOncePod"])).empty?
          issues << issue(field, :forbidden, "may not use ReadWriteOncePod with other access modes")
        end
        issues
      end

      def pvc_data_source_errors(spec, old, path)
        issues = []
        data_source = fetch(spec, "dataSource")
        data_source_ref = fetch(spec, "dataSourceRef")
        old_spec = fetch(old, "spec")
        allow_old_group = %w[dataSource dataSourceRef].any? { |field| !fetch(fetch(old_spec, field), "apiGroup").nil? }
        # validateDataSource / validateDataSourceRef: name and kind are
        # required and the core (empty) apiGroup only admits PersistentVolumeClaim.
        {"dataSource" => data_source, "dataSourceRef" => data_source_ref}.each do |name, ref|
          next unless ref.is_a?(Hash)

          required(ref, "name", [*path, name], issues)
          required(ref, "kind", [*path, name], issues)
          api_group = fetch(ref, "apiGroup")
          if blank?(api_group) && !blank?(fetch(ref, "kind")) && fetch(ref, "kind").to_s != "PersistentVolumeClaim"
            issues << issue([*path, name], :invalid, "must be 'PersistentVolumeClaim' when referencing the default apiGroup")
          elsif !blank?(api_group) && !allow_old_group
            issues.concat(invalid_messages([*path, name, "apiGroup"], dns1123_subdomain_messages(api_group)))
          end
        end
        namespace = fetch(data_source_ref, "namespace")
        if !blank?(namespace)
          issues.concat(invalid_messages(path + %w[dataSourceRef namespace], dns1123_label_messages(namespace)))
          issues << issue(path, :invalid, "may not be specified when dataSourceRef.namespace is specified") if data_source.is_a?(Hash)
        elsif data_source.is_a?(Hash) && data_source_ref.is_a?(Hash)
          comparable = ->(ref) { %w[apiGroup kind name].map { |key| fetch(ref, key) } }
          unless comparable.call(data_source) == comparable.call(data_source_ref)
            issues << issue(path, :invalid,
                            "must match dataSourceRef")
          end
        end
        issues
      end

      def claim_template_errors(root)
        Array(fetch(fetch(root, "spec"), "volumeClaimTemplates")).each_with_index.flat_map do |claim, index|
          pvc_errors(claim, path: ["spec", "volumeClaimTemplates", index.to_s, "spec"])
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

      PV_NODE_AFFINITY_GA_LABELS = {
        "failure-domain.beta.kubernetes.io/zone" => "topology.kubernetes.io/zone",
        "failure-domain.beta.kubernetes.io/region" => "topology.kubernetes.io/region",
        "beta.kubernetes.io/os" => "kubernetes.io/os",
        "beta.kubernetes.io/arch" => "kubernetes.io/arch",
        "beta.kubernetes.io/instance-type" => "node.kubernetes.io/instance-type"
      }.freeze

      def persistent_volume_update_errors(root, old, operation, mutable_node_affinity: false)
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
        old_affinity = fetch(old_spec, "nodeAffinity")
        if !mutable_node_affinity && !old_affinity.nil? && !pv_node_affinity_equal?(fetch(new_spec, "nodeAffinity"), old_affinity)
          issues << issue(%w[nodeAffinity], :invalid, "field is immutable, except for updating from beta label to GA")
        end
        issues
      end

      def pv_node_affinity_equal?(current, previous)
        return true if current == previous
        return false unless current.is_a?(Hash) && previous.is_a?(Hash)

        current_selector = fetch(current, "required")
        previous_selector = fetch(previous, "required")
        return false if current_selector.nil? != previous_selector.nil?

        terms = Array(fetch(current_selector, "nodeSelectorTerms"))
        old_terms = Array(fetch(previous_selector, "nodeSelectorTerms"))
        terms.size == old_terms.size && terms.zip(old_terms).all? do |term, old_term|
          %w[matchExpressions matchFields].all? do |field|
            requirements = Array(fetch(term, field))
            old_requirements = Array(fetch(old_term, field))
            requirements.size == old_requirements.size && requirements.zip(old_requirements).all? do |requirement, old_requirement|
              key = fetch(requirement, "key")
              old_key = fetch(old_requirement, "key")
              (key == old_key || key == PV_NODE_AFFINITY_GA_LABELS.fetch(old_key, old_key)) &&
                fetch(requirement, "operator") == fetch(old_requirement, "operator") &&
                Array(fetch(requirement, "values")) == Array(fetch(old_requirement, "values"))
            end
          end
        end
      end

      # Every volume source key a PersistentVolume spec may arrive with.
      PERSISTENT_VOLUME_SPEC_SOURCES = %w[
        awsElasticBlockStore azureDisk azureFile cephfs cinder configMap csi downwardAPI emptyDir ephemeral fc flexVolume
        flocker gcePersistentDisk glusterfs hostPath iscsi local nfs persistentVolumeClaim photonPersistentDisk portworxVolume projected
        quobyte rbd scaleIO storageos vsphereVolume
      ].freeze
      # The sources reported Forbidden when a PersistentVolume names several.
      PERSISTENT_VOLUME_EXCLUSIVE_SOURCES = %w[
        awsElasticBlockStore azureDisk azureFile cephfs cinder csi fc flocker
        gcePersistentDisk glusterfs iscsi local nfs photonPersistentDisk portworxVolume
        quobyte rbd scaleIO storageos vsphereVolume
      ].freeze
      # The members of a Pod volume's (or a volumeSource's) one-of.
      VOLUME_SOURCES = %w[
        awsElasticBlockStore azureDisk azureFile cephfs cinder configMap downwardAPI emptyDir ephemeral fc flexVolume
        flocker gcePersistentDisk gitRepo glusterfs hostPath iscsi nfs persistentVolumeClaim portworxVolume projected quobyte rbd scaleIO
        storageos vsphere
      ].freeze
      INLINE_VOLUME_SPEC_FIELDS = %w[
        accessModes awsElasticBlockStore azureDisk azureFile cephFS cinder claimRef csi fc flocker gcePersistentDisk
        glusterfs iscsi local nfs nodeAffinity photonPersistentDisk portworxVolume quobyte rbd scaleIO storageos vsphereVolume
      ].freeze

      def volume_errors(root, kind, operation = :create, old: nil)
        issues = []
        if kind == "PersistentVolume"
          issues.concat(persistent_volume_spec_errors(fetch(root, "spec"), operation))
          issues.concat(pv_node_selector_errors(root, old) * (operation == :update ? 2 : 1))
        end
        walk(root) do |value, path|
          next unless value.is_a?(Hash)
          next unless path.last == "volumes" || path.last == "volumeSource" || value.key?("persistentVolumeClaim")

          present = VOLUME_SOURCES.select { |name| source_key_present?(value, name) }
          if present.length > 1
            issues << issue(path + [present.last], :invalid, "may not have more than one field specified at a time")
          elsif present.empty? && (path.last == "volumeSource" || value.key?("name"))
            issues << issue(path, :required, "must specify a volume type")
          end
        end
        issues
      end

      # The spec's source one-of and what goes with it.  An update reports
      # each group of issues twice, group by group.
      def persistent_volume_spec_errors(spec, operation)
        return [] unless spec.is_a?(Hash)

        repeat = operation == :update ? 2 : 1
        present_sources = PERSISTENT_VOLUME_SPEC_SOURCES.select { |name| source_key_present?(spec, name) }
        return persistent_volume_source_errors(spec, present_sources) * repeat unless present_sources.empty?

        # Without a source the spec reports what a missing spec does.
        issues = ZERO_VALUE_SPEC_ISSUES.fetch("PersistentVolume").map { |path, code, message| issue(path, code, message) } * repeat
        if node_affinity_without_required?(fetch(spec, "nodeAffinity"))
          issues.concat([issue(%w[spec nodeAffinity required], :required, "must specify required node constraints")] * repeat)
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
          PERSISTENT_VOLUME_EXCLUSIVE_SOURCES.each do |name|
            next unless sources.include?(name)

            issues << issue(["spec", persistent_volume_field_name(name)], :forbidden,
                            "may not specify more than 1 volume type")
          end
        end
        persistent_volume_common_errors(spec, issues)

        # Source-specific validation is meaningful only for a single selected
        # source.  In the multi-source zero graph, the upstream one-of errors
        # short-circuit the source's own required-field checks.
        return issues unless sources.length == 1

        single_volume_source_errors(spec, sources.first, issues)
        host_path = fetch(fetch(spec, "hostPath"), "path")
        if fetch(spec, "persistentVolumeReclaimPolicy") == "Recycle" && host_path.is_a?(String) && !host_path.include?("\0") &&
           Pathname.new(host_path).cleanpath.root?
          issues << issue(%w[spec persistentVolumeReclaimPolicy], :forbidden, "may not be 'recycle' for a hostPath mount of '/'")
        end
        csi = fetch(spec, "csi")
        secret = csi.is_a?(Hash) ? fetch(csi, "controllerExpandSecretRef") : nil
        if secret.is_a?(Hash)
          required(secret, "name", %w[spec csi controllerExpandSecretRef], issues)
          required(secret, "namespace", %w[spec csi controllerExpandSecretRef], issues)
        end
        issues
      end

      # AccessModes and capacity are required for every non-inline PV,
      # independently of which source selected the volume
      # (ValidatePersistentVolumeSpec: the only capacity key is storage).
      def persistent_volume_common_errors(spec, issues)
        access_modes = fetch(spec, "accessModes")
        issues << issue(%w[spec accessModes], :required, "") unless access_modes.is_a?(Array) && !access_modes.empty?
        capacity = fetch(spec, "capacity")
        capacity = {} unless capacity.is_a?(Hash)
        issues << issue(%w[spec capacity], :required, "") if capacity.empty?
        issues << issue(%w[spec capacity], :unsupported, "supported values: \"storage\"") unless capacity.keys.map(&:to_s) == ["storage"]
        return unless node_affinity_without_required?(fetch(spec, "nodeAffinity"))

        issues << issue(%w[spec nodeAffinity required], :required, "must specify required node constraints")
      end

      def node_affinity_without_required?(node_affinity)
        node_affinity.is_a?(Hash) && !fetch(node_affinity, "required").is_a?(Hash)
      end

      def pv_node_selector_errors(root, old)
        selector = value_at_path(root, %w[spec nodeAffinity required])
        return [] unless selector.is_a?(Hash)

        path = %w[spec nodeAffinity required nodeSelectorTerms]
        terms = Array(fetch(selector, "nodeSelectorTerms"))
        return [issue(path, :required, "must have at least one node selector term")] if terms.empty?

        old_terms = Array(value_at_path(old, path))
        allow_invalid_labels = old_terms.any? do |term|
          Array(fetch(term, "matchExpressions")).any? do |requirement|
            Array(fetch(requirement, "values")).any? { |value| !label_value_messages(value).empty? }
          end
        end
        terms.each_with_index.flat_map do |term, index|
          term_path = path + [index.to_s]
          labels = Array(fetch(term, "matchExpressions")).each_with_index.flat_map do |requirement, req_index|
            pv_node_label_errors(requirement, term_path + ["matchExpressions", req_index.to_s], allow_invalid_labels)
          end
          fields = Array(fetch(term, "matchFields")).each_with_index.flat_map do |requirement, req_index|
            pv_node_field_errors(requirement, term_path + ["matchFields", req_index.to_s])
          end
          labels + fields
        end
      end

      def pv_node_label_errors(requirement, path, allow_invalid_labels)
        values = Array(fetch(requirement, "values"))
        issues = case fetch(requirement, "operator")
                 when "In", "NotIn"
                   values.empty? ? [issue(path + ["values"], :required, "must be specified when `operator` is 'In' or 'NotIn'")] : []
                 when "Exists", "DoesNotExist"
                   values.empty? ? [] : [issue(path + ["values"], :forbidden, "may not be specified when `operator` is 'Exists' or 'DoesNotExist'")]
                 when "Lt", "Gt"
                   values.length == 1 ? [] : [issue(path + ["values"], :required, "must be specified single value when `operator` is 'Lt' or 'Gt'")]
                 else
                   [issue(path + ["operator"], :invalid, "not a valid selector operator")]
                 end
        issues.concat(invalid_messages(path + ["key"], qualified_name_messages(fetch(requirement, "key"))))
        unless allow_invalid_labels
          values.each_with_index { |value, index| issues.concat(invalid_messages(path + ["values", index.to_s], label_value_messages(value))) }
        end
        issues
      end

      def pv_node_field_errors(requirement, path)
        values = Array(fetch(requirement, "values"))
        value_message = "must be only one value when `operator` is 'In' or 'NotIn' for node field selector"
        issues = if %w[In NotIn].include?(fetch(requirement, "operator"))
                   values.length == 1 ? [] : [issue(path + ["values"], :required, value_message)]
                 else
                   [issue(path + ["operator"], :invalid, "not a valid selector operator")]
                 end
        if fetch(requirement, "key") == "metadata.name"
          values.each_with_index { |value, index| issues.concat(invalid_messages(path + ["values", index.to_s], dns1123_subdomain_messages(value))) }
        else
          issues << issue(path + ["key"], :invalid, "not a valid field selector key")
        end
        issues
      end

      # The required fields and formats of the one selected volume source.
      def single_volume_source_errors(spec, name, issues)
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
        when "scaleIO", "storageos"
          required(source, "volumeName", path, issues)
        when "csi"
          required(source, "driver", path, issues)
          required(source, "volumeHandle", path, issues)
        end
      end

      def persistent_volume_field_name(name)
        name == "cephfs" ? "cephFS" : name
      end

      def volume_attachment_errors(root, old = nil, operation = :create)
        spec = fetch(root, "spec")
        return [] unless spec.is_a?(Hash)

        issues = volume_attachment_attacher_errors(spec)
        issues << issue(%w[spec], :invalid, "field is immutable") if operation == :update && old && spec != fetch(old, "spec")
        issues << issue(%w[spec nodeName], :invalid, DNS1123_SUBDOMAIN_MSG) if blank?(fetch(spec, "nodeName"))
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
        inline_volume_spec_errors(inline, issues) if inline.is_a?(Hash)
        issues
      end

      def volume_attachment_attacher_errors(spec)
        path = %w[spec attacher]
        attacher = fetch(spec, "attacher").to_s
        return [issue(path, :required, "")] if attacher.empty?

        errors = []
        errors << issue(path, :too_long, "may not be more than 63 bytes") if attacher.bytesize > 63
        errors.concat(invalid_messages(path, dns1123_subdomain_messages(attacher.downcase)))
      end

      # VolumeAttachment validates an inline PersistentVolumeSpec with the
      # same zero-value source union used by PersistentVolume.  The Go
      # strategy reports every absent source member (rather than only the
      # source parent) when the inline object is present.
      def inline_volume_spec_errors(inline, issues)
        base = %w[spec source inlineVolumeSpec]
        if INLINE_VOLUME_SPEC_FIELDS.all? { |field| zero_value?(fetch(inline, field)) }
          INLINE_VOLUME_SPEC_FIELDS.each { |field| issues << issue(base + [field], :required, "") }
          return
        end

        access_modes = fetch(inline, "accessModes")
        issues << issue(base + ["accessModes"], :required, "") unless access_modes.is_a?(Array) && !access_modes.empty?
        present_sources = (INLINE_VOLUME_SPEC_FIELDS - ["accessModes"]).select do |field|
          wire_field = field == "cephFS" ? "cephfs" : field
          inline.key?(field) || inline.key?(field.to_sym) || inline.key?(wire_field) || inline.key?(wire_field.to_sym)
        end
        return unless present_sources.length > 1

        present_sources.each do |field|
          detail = if %w[claimRef nodeAffinity].include?(field)
                     "may not be specified in the context of inline volumes"
                   else
                     "may not specify more than 1 volume type"
                   end
          issues << issue(base + [field], :forbidden, detail)
        end
      end

      STORAGE_CLASS_IMMUTABLE_FIELDS = %w[parameters provisioner reclaimPolicy volumeBindingMode].freeze

      def storage_class_errors(root, operation = :create, old = nil)
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
        if operation == :update && old
          STORAGE_CLASS_IMMUTABLE_FIELDS.each do |field|
            value = fetch(spec, field)
            previous = fetch(old, field)
            next if value == previous || (field == "parameters" && (value || {}) == (previous || {}))

            issues << issue([field], :invalid, "field is immutable")
          end
        end

        issues
      end

      def csi_storage_capacity_errors(root)
        issues = []
        storage_class_name = fetch(root, "storageClassName")
        valid_name = storage_class_name.is_a?(String) &&
                     storage_class_name.match?(/\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/)
        issues << issue(%w[storageClassName], :invalid, DNS1123_SUBDOMAIN_MSG) unless valid_name

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

      private_class_method :persistent_volume_spec_errors, :persistent_volume_common_errors, :node_affinity_without_required?,
                           :single_volume_source_errors, :inline_volume_spec_errors
    end
  end
end
