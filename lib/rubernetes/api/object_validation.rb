# frozen_string_literal: true

module Rubernetes
  module API
    # ObjectMeta and core-kind validation with the field paths, reasons, and
    # messages of k8s.io/apimachinery/pkg/api/validation and
    # k8s.io/kubernetes/pkg/apis/core/validation at v1.36.2, so the Status
    # body matches the kube-apiserver oracle.  Schema-driven type, enum, and
    # required-field checks run separately in the schema validator; this
    # module covers the name/label/annotation rules and the Pod invariants
    # that the OpenAPI schema cannot express.
    module ObjectValidation
      DNS1123_SUBDOMAIN = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\z/
      DNS1123_LABEL = /\A[a-z0-9]([-a-z0-9]*[a-z0-9])?\z/
      DNS1035_LABEL = /\A[a-z]([-a-z0-9]*[a-z0-9])?\z/
      QUALIFIED_NAME = /\A([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]\z/
      LABEL_VALUE = /\A(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?\z/
      DNS1123_SUBDOMAIN_MAX = 253
      DNS1123_LABEL_MAX = 63
      QUALIFIED_NAME_MAX = 63
      LABEL_VALUE_MAX = 63
      TOTAL_ANNOTATION_SIZE_LIMIT = 256 * 1024

      DNS1123_SUBDOMAIN_MESSAGE = "a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end " \
                                  "with an alphanumeric character (e.g. 'example.com', regex used for validation is " \
                                  "'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"
      DNS1123_LABEL_MESSAGE = "a lowercase RFC 1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an " \
                              "alphanumeric character (e.g. 'my-name',  or '123-abc', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?')"
      DNS1035_LABEL_MESSAGE = "a DNS-1035 label must consist of lower case alphanumeric characters or '-', start with an alphabetic character, and end with " \
                              "an alphanumeric character (e.g. 'my-name',  or 'abc-123', regex used for validation is '[a-z]([-a-z0-9]*[a-z0-9])?')"
      QUALIFIED_NAME_MESSAGE = "name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character " \
                               "(e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"
      LABEL_VALUE_MESSAGE = "a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?')"

      # pkg/apis/core/validation ValidateXName choices.  Everything not listed
      # is a DNS-1123 subdomain (apivalidation.NameIsDNSSubdomain).
      #
      # The RBAC kinds are the exception that matters: pkg/apis/rbac/validation
      # ValidateRBACName is content.IsPathSegmentName, which permits ':'.  The
      # bootstrap policy itself depends on it -- "system:node",
      # "system:kube-scheduler" and the rest are not DNS subdomains.
      NAME_RULES = {
        "Namespace" => :dns1123_label,
        # RelaxedServiceNameValidation (Beta, on in v1.36, KEP-5311):
        # ValidateServiceCreate uses NameIsDNSLabel, so a Service name may
        # start with a digit.
        "Service" => :dns1123_label,
        "Node" => :dns1123_subdomain,
        "ServiceAccount" => :dns1123_subdomain,
        "Endpoints" => :dns1123_subdomain,
        "Role" => :path_segment,
        "RoleBinding" => :path_segment,
        "ClusterRole" => :path_segment,
        "ClusterRoleBinding" => :path_segment,
        "IPAddress" => :ip_address
      }.freeze
      PATH_SEGMENT_NAME_MAY_NOT_BE = %w[. ..].freeze
      PATH_SEGMENT_NAME_MAY_NOT_CONTAIN = %w[/ %].freeze
      # Kinds whose objects are also label-selected and therefore carry the
      # 63-character label limit on their name (ValidateReplicaSetName et al.).
      LABEL_LENGTH_NAME_KINDS = %w[ReplicaSet ReplicationController StatefulSet Deployment DaemonSet Job].freeze
      CRONJOB_NAME_MAX = 52

      RESTART_POLICIES = %w[Always OnFailure Never].freeze
      DNS_POLICIES = %w[ClusterFirstWithHostNet ClusterFirst Default None].freeze
      IMAGE_PULL_POLICIES = %w[Always Never IfNotPresent].freeze
      PROTOCOLS = %w[TCP UDP SCTP].freeze

      Cause = Struct.new(:reason, :field, :message, keyword_init: true)

      module_function

      # Returns the list of field.Error causes for +object+; empty when valid.
      def validate(kind, object, old: nil, namespaced: true)
        causes = []
        metadata = object["metadata"].is_a?(Hash) ? object["metadata"] : {}
        validate_object_meta(kind, metadata, causes, namespaced: namespaced, old_metadata: old && old["metadata"])
        case kind
        when "Pod" then validate_pod_spec(object["spec"], "spec", causes)
        when "StatefulSet"
          # apps validation volumesToAddForTemplates: every volumeClaimTemplate is
          # a PVC volume of the same name for the template's mounts.
          claim_names = Array(object.dig("spec", "volumeClaimTemplates")).filter_map do |claim|
            claim.dig("metadata", "name").to_s if claim.is_a?(Hash) && !claim.dig("metadata", "name").to_s.empty?
          end
          validate_pod_template_spec(object.dig("spec", "template"), "spec.template", causes, extra_volume_names: claim_names)
        when "Deployment", "ReplicaSet", "DaemonSet", "Job"
          validate_pod_template_spec(object.dig("spec", "template"), "spec.template", causes)
        when "CronJob"
          validate_pod_template_spec(object.dig("spec", "jobTemplate", "spec", "template"), "spec.jobTemplate.spec.template", causes)
        end
        validate_immutability(kind, object, old, causes)
        causes
      end

      # validation.go ValidateSecretUpdate / ValidateConfigMapUpdate: once
      # `immutable` is true the data and the flag itself are frozen, and the
      # API server is what enforces it.  A Secret that keeps accepting writes
      # is not immutable at all.
      IMMUTABLE_KINDS = {"Secret" => %w[data stringData], "ConfigMap" => %w[data binaryData]}.freeze
      # Fields frozen after creation regardless of any flag
      # (ValidatePriorityClassUpdate: `value` is immutable).
      ALWAYS_IMMUTABLE_FIELDS = {"PriorityClass" => %w[value]}.freeze

      def validate_immutability(kind, object, old, causes)
        if old.is_a?(Hash)
          Array(ALWAYS_IMMUTABLE_FIELDS[kind]).each do |field|
            next if old[field] == object[field]

            causes << invalid(field, object[field], "field is immutable")
          end
        end
        fields = IMMUTABLE_KINDS[kind]
        return if fields.nil? || !old.is_a?(Hash)
        return unless old["immutable"] == true

        causes << invalid("immutable", object["immutable"], "field is immutable") unless object["immutable"] == true
        fields.each do |field|
          next if old[field] == object[field]

          causes << invalid(field, nil, "field is immutable")
        end
      end

      def validate_object_meta(kind, metadata, causes, namespaced:, old_metadata: nil)
        name = metadata["name"]
        generate_name = metadata["generateName"]
        name_errors(kind, name.to_s, prefix: false).each { |message| causes << invalid("metadata.name", name, message) } if !name.nil? && !name.to_s.empty?
        if !generate_name.nil? && !generate_name.to_s.empty?
          name_errors(kind, generate_name.to_s, prefix: true).each do |message|
            causes << invalid("metadata.generateName", generate_name, message)
          end
        end
        namespace = metadata["namespace"]
        if namespaced
          if !namespace.nil? && !namespace.to_s.empty?
            label_errors(namespace.to_s, DNS1123_LABEL, DNS1123_LABEL_MESSAGE, DNS1123_LABEL_MAX).each do |message|
              causes << invalid("metadata.namespace", namespace, message)
            end
          end
        elsif !namespace.nil? && !namespace.to_s.empty?
          causes << Cause.new(reason: "FieldValueForbidden", field: "metadata.namespace", message: "Forbidden: not allowed on this type")
        end
        validate_labels(metadata["labels"], "metadata.labels", causes)
        validate_annotations(metadata["annotations"], "metadata.annotations", causes)
        Array(metadata["finalizers"]).each_with_index do |finalizer, index|
          next if finalizer.is_a?(String) && qualified_name_errors(finalizer).empty?

          causes << invalid("metadata.finalizers[#{index}]", finalizer, "name part must be non-empty") if finalizer.to_s.empty?
          qualified_name_errors(finalizer.to_s).each { |message| causes << invalid("metadata.finalizers[#{index}]", finalizer, message) }
        end
        Array(metadata["ownerReferences"]).each_with_index do |reference, index|
          next unless reference.is_a?(Hash)

          %w[apiVersion kind name uid].each do |key|
            causes << required("metadata.ownerReferences[#{index}].#{key}") if reference[key].to_s.empty?
          end
        end
        return unless old_metadata.is_a?(Hash)

        %w[name namespace uid creationTimestamp].each do |key|
          next if old_metadata[key].nil? || metadata[key].nil? || old_metadata[key].to_s == metadata[key].to_s

          causes << invalid("metadata.#{key}", metadata[key], "field is immutable")
        end
      end

      # networking/validation ValidateIPAddressName: the name is the address
      # itself in canonical form ("fe80::42:1dff:fe84:f9e2", "10.0.0.1").
      def ip_address_name_errors(name)
        require "ipaddr"
        address = IPAddr.new(name)
        address.to_s == name ? [] : ["must be a canonical IP address (#{address})"]
      rescue ArgumentError
        ["must be a valid IP address"]
      end

      def name_errors(kind, name, prefix:)
        rule = NAME_RULES.fetch(kind, :dns1123_subdomain)
        errors = case rule
                 when :dns1123_label then label_errors(name, DNS1123_LABEL, DNS1123_LABEL_MESSAGE, DNS1123_LABEL_MAX, prefix: prefix)
                 when :dns1035_label then label_errors(name, DNS1035_LABEL, DNS1035_LABEL_MESSAGE, DNS1123_LABEL_MAX, prefix: prefix)
                 when :path_segment then path_segment_errors(name, prefix: prefix)
                 when :ip_address then ip_address_name_errors(name)
                 else label_errors(name, DNS1123_SUBDOMAIN, DNS1123_SUBDOMAIN_MESSAGE, DNS1123_SUBDOMAIN_MAX, prefix: prefix)
                 end
        errors << "must be no more than #{DNS1123_LABEL_MAX} characters" if LABEL_LENGTH_NAME_KINDS.include?(kind) && name.length > DNS1123_LABEL_MAX
        errors << "must be no more than #{CRONJOB_NAME_MAX} characters" if kind == "CronJob" && name.length > CRONJOB_NAME_MAX
        errors.uniq
      end

      # validation.IsDNS1123Subdomain and friends: a generateName prefix is
      # checked with a synthetic suffix appended, like ValidateNameFunc(prefix).
      def label_errors(value, pattern, message, max_length, prefix: false)
        candidate = prefix ? "#{value}a" : value
        errors = []
        errors << "must be no more than #{max_length} characters" if candidate.length > max_length
        errors << message unless pattern.match?(candidate)
        errors
      end

      # content.IsPathSegmentName / IsPathSegmentPrefix.  A prefix is only
      # checked for illegal content: an arbitrary suffix can still make "." or
      # ".." into a legal name, so the exact-match rule does not apply to it.
      def path_segment_errors(value, prefix: false)
        unless prefix
          illegal = PATH_SEGMENT_NAME_MAY_NOT_BE.find { |candidate| value == candidate }
          return ["may not be '#{illegal}'"] if illegal
        end

        PATH_SEGMENT_NAME_MAY_NOT_CONTAIN.filter_map do |illegal|
          "may not contain '#{illegal}'" if value.include?(illegal)
        end
      end

      def qualified_name_errors(value)
        errors = []
        parts = value.split("/", -1)
        name = parts.last.to_s
        case parts.length
        when 1
          # name only
        when 2
          prefix = parts.first
          if prefix.empty?
            errors << "prefix part must be non-empty"
          else
            errors.concat(label_errors(prefix, DNS1123_SUBDOMAIN, "prefix part #{DNS1123_SUBDOMAIN_MESSAGE}", DNS1123_SUBDOMAIN_MAX))
          end
        else
          errors << "a qualified name must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]') with an optional DNS subdomain prefix and '/' (e.g. 'example.com/MyName')"
          return errors
        end
        if name.empty?
          errors << "name part must be non-empty"
        else
          errors << "name part must be no more than #{QUALIFIED_NAME_MAX} characters" if name.length > QUALIFIED_NAME_MAX
          errors << QUALIFIED_NAME_MESSAGE unless QUALIFIED_NAME.match?(name)
        end
        errors
      end

      def validate_labels(labels, path, causes)
        return if labels.nil?

        unless labels.is_a?(Hash)
          causes << invalid(path, labels, "must be a map of string to string")
          return
        end

        labels.each do |key, value|
          qualified_name_errors(key.to_s).each { |message| causes << invalid(path, key, message) }
          text = value.to_s
          causes << invalid(path, text, "must be no more than #{LABEL_VALUE_MAX} characters") if text.length > LABEL_VALUE_MAX
          causes << invalid(path, text, LABEL_VALUE_MESSAGE) unless LABEL_VALUE.match?(text)
        end
      end

      def validate_annotations(annotations, path, causes)
        return if annotations.nil?

        unless annotations.is_a?(Hash)
          causes << invalid(path, annotations, "must be a map of string to string")
          return
        end

        total = 0
        annotations.each do |key, value|
          qualified_name_errors(key.to_s).each { |message| causes << invalid(path, key, message) }
          total += key.to_s.bytesize + value.to_s.bytesize
        end
        return unless total > TOTAL_ANNOTATION_SIZE_LIMIT

        causes << Cause.new(reason: "FieldValueTooLong", field: path,
                            message: "Too long: must have at most #{TOTAL_ANNOTATION_SIZE_LIMIT} bytes")
      end

      def validate_pod_template_spec(template, path, causes, extra_volume_names: [])
        return unless template.is_a?(Hash)

        validate_labels(template.dig("metadata", "labels"), "#{path}.metadata.labels", causes)
        validate_annotations(template.dig("metadata", "annotations"), "#{path}.metadata.annotations", causes)
        validate_pod_spec(template["spec"], "#{path}.spec", causes, extra_volume_names: extra_volume_names)
      end

      # ValidatePodSpec subset: containers, init containers, volumes, ports,
      # policies, and the cross-references between them.
      # apivalidation.IsValidSysctlName: a sysctl name is segments separated
      # by "." or "/", each a lowercase alphanumeric run that may contain "-"
      # and "_" inside but not at either end.  Accepting anything let a Pod
      # naming "foo-" or "bar.." through, and the node then failed it much
      # later instead of the API server rejecting it outright.
      SYSCTL_SEGMENT = /\A[a-z0-9]([-_a-z0-9]*[a-z0-9])?\z/
      SYSCTL_MESSAGE = "must have at most 253 characters and match regex " \
                       "[a-z0-9]([-_a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-_a-z0-9]*[a-z0-9])?)*"

      def validate_sysctls(security_context, path, causes)
        return unless security_context.is_a?(Hash)

        Array(security_context["sysctls"]).each_with_index do |entry, index|
          next unless entry.is_a?(Hash)

          name = entry["name"].to_s
          field = "#{path}.sysctls[#{index}].name"
          if name.empty?
            causes << required(field)
            next
          end
          segments = name.split(%r{[./]}, -1)
          next if name.length <= 253 && !segments.empty? && segments.all? { |segment| segment.match?(SYSCTL_SEGMENT) }

          causes << invalid(field, name, SYSCTL_MESSAGE)
        end
      end

      def validate_pod_spec(spec, path, causes, extra_volume_names: [])
        unless spec.is_a?(Hash)
          causes << required(path)
          return
        end

        validate_sysctls(spec["securityContext"], "#{path}.securityContext", causes)
        volumes = Array(spec["volumes"])
        volume_names = extra_volume_names.to_h { |name| [name.to_s, true] }
        volumes.each_with_index do |volume, index|
          next unless volume.is_a?(Hash)

          name = volume["name"].to_s
          if name.empty?
            causes << required("#{path}.volumes[#{index}].name")
          else
            label_errors(name, DNS1123_LABEL, DNS1123_LABEL_MESSAGE, DNS1123_LABEL_MAX).each do |message|
              causes << invalid("#{path}.volumes[#{index}].name", name, message)
            end
            causes << duplicate("#{path}.volumes[#{index}].name", name) if volume_names.key?(name)
            volume_names[name] = true
          end
        end

        containers = spec["containers"]
        causes << required("#{path}.containers") if !containers.is_a?(Array) || containers.empty?
        names = {}
        all_ports = {}
        Array(containers).each_with_index do |container, index|
          validate_container(container, "#{path}.containers[#{index}]", names, all_ports, volume_names, causes)
        end
        Array(spec["initContainers"]).each_with_index do |container, index|
          validate_container(container, "#{path}.initContainers[#{index}]", names, all_ports, volume_names, causes, init: true)
        end
        unless spec["restartPolicy"].nil? || RESTART_POLICIES.include?(spec["restartPolicy"])
          causes << unsupported("#{path}.restartPolicy", spec["restartPolicy"], RESTART_POLICIES)
        end
        causes << unsupported("#{path}.dnsPolicy", spec["dnsPolicy"], DNS_POLICIES) unless spec["dnsPolicy"].nil? || DNS_POLICIES.include?(spec["dnsPolicy"])
        if spec.key?("terminationGracePeriodSeconds") && !spec["terminationGracePeriodSeconds"].nil? &&
           (!spec["terminationGracePeriodSeconds"].is_a?(Integer) || spec["terminationGracePeriodSeconds"].negative?)
          causes << invalid("#{path}.terminationGracePeriodSeconds", spec["terminationGracePeriodSeconds"],
                            "must be greater than or equal to 0")
        end
        if spec.key?("activeDeadlineSeconds") && !spec["activeDeadlineSeconds"].nil? &&
           (!spec["activeDeadlineSeconds"].is_a?(Integer) || spec["activeDeadlineSeconds"] < 1)
          causes << invalid("#{path}.activeDeadlineSeconds", spec["activeDeadlineSeconds"], "must be between 1 and 2147483647, inclusive")
        end
      end

      def validate_container(container, path, names, all_ports, volume_names, causes, init: false)
        unless container.is_a?(Hash)
          causes << required(path)
          return
        end

        name = container["name"].to_s
        if name.empty?
          causes << required("#{path}.name")
        else
          label_errors(name, DNS1123_LABEL, DNS1123_LABEL_MESSAGE, DNS1123_LABEL_MAX).each do |message|
            causes << invalid("#{path}.name", name, message)
          end
          causes << duplicate("#{path}.name", name) if names.key?(name)
          names[name] = true
        end
        causes << required("#{path}.image") if container["image"].to_s.empty?
        unless container["imagePullPolicy"].nil? || IMAGE_PULL_POLICIES.include?(container["imagePullPolicy"])
          causes << unsupported("#{path}.imagePullPolicy", container["imagePullPolicy"], IMAGE_PULL_POLICIES)
        end
        Array(container["ports"]).each_with_index do |port, index|
          next unless port.is_a?(Hash)

          port_path = "#{path}.ports[#{index}]"
          number = port["containerPort"]
          if number.nil?
            causes << required("#{port_path}.containerPort")
          elsif !number.is_a?(Integer) || number < 1 || number > 65_535
            causes << invalid("#{port_path}.containerPort", number, "must be between 1 and 65535, inclusive")
          end
          if port["hostPort"] && (!port["hostPort"].is_a?(Integer) || port["hostPort"] < 1 || port["hostPort"] > 65_535)
            causes << invalid("#{port_path}.hostPort", port["hostPort"], "must be between 1 and 65535, inclusive")
          end
          protocol = port["protocol"] || "TCP"
          causes << unsupported("#{port_path}.protocol", protocol, PROTOCOLS) unless PROTOCOLS.include?(protocol)
          port_name = port["name"].to_s
          unless port_name.empty?
            label_errors(port_name, DNS1123_LABEL, DNS1123_LABEL_MESSAGE, 15).each do |message|
              causes << invalid("#{port_path}.name", port_name, message)
            end
            # A container port NAME is unique across the whole Pod
            # (validation.go:2727): a named targetPort resolves through it, so
            # two ports sharing a name make the Service's target ambiguous.
            if all_ports.key?("name/#{port_name}")
              causes << duplicate("#{port_path}.name", port_name)
            else
              all_ports["name/#{port_name}"] = true
            end
          end
          next unless port["hostPort"].is_a?(Integer)

          key = "#{protocol}/#{port["hostIP"]}/#{port["hostPort"]}"
          causes << duplicate("#{port_path}.hostPort", key) if all_ports.key?(key)
          all_ports[key] = true
        end
        Array(container["volumeMounts"]).each_with_index do |mount, index|
          next unless mount.is_a?(Hash)

          mount_path = "#{path}.volumeMounts[#{index}]"
          mount_name = mount["name"].to_s
          if mount_name.empty?
            causes << required("#{mount_path}.name")
          elsif !volume_names.key?(mount_name)
            causes << Cause.new(reason: "FieldValueNotFound", field: "#{mount_path}.name",
                                message: "Not found: #{mount_name.inspect}")
          end
          causes << required("#{mount_path}.mountPath") if mount["mountPath"].to_s.empty?
        end
        validate_probe(container["livenessProbe"], "#{path}.livenessProbe", causes)
        validate_probe(container["readinessProbe"], "#{path}.readinessProbe", causes)
        validate_probe(container["startupProbe"], "#{path}.startupProbe", causes)
        return unless init && container["lifecycle"].is_a?(Hash) && container["restartPolicy"] != "Always"

        causes << Cause.new(reason: "FieldValueForbidden", field: "#{path}.lifecycle",
                            message: "Forbidden: may not be set for init containers without restartPolicy=Always")
      end

      def validate_probe(probe, path, causes)
        return unless probe.is_a?(Hash)

        handlers = %w[exec httpGet tcpSocket grpc].count { |key| probe[key].is_a?(Hash) }
        causes << required(path, "must specify a handler type") if handlers.zero?
        if handlers > 1
          causes << Cause.new(reason: "FieldValueForbidden", field: path,
                              message: "Forbidden: may not specify more than 1 handler type")
        end
        %w[initialDelaySeconds timeoutSeconds periodSeconds successThreshold failureThreshold].each do |key|
          value = probe[key]
          next if value.nil?

          minimum = %w[successThreshold failureThreshold periodSeconds timeoutSeconds].include?(key) ? 1 : 0
          causes << invalid("#{path}.#{key}", value, "must be greater than or equal to #{minimum}") if !value.is_a?(Integer) || value < minimum
        end
      end

      def invalid(field, value, message)
        Cause.new(reason: "FieldValueInvalid", field: field, message: "Invalid value: #{json_value(value)}: #{message}")
      end

      def required(field, detail = nil)
        message = detail ? "Required value: #{detail}" : "Required value"
        Cause.new(reason: "FieldValueRequired", field: field, message: message)
      end

      def duplicate(field, value)
        Cause.new(reason: "FieldValueDuplicate", field: field, message: "Duplicate value: #{json_value(value)}")
      end

      def unsupported(field, value, supported)
        Cause.new(reason: "FieldValueNotSupported", field: field,
                  message: "Unsupported value: #{json_value(value)}: supported values: #{supported.map(&:inspect).join(", ")}")
      end

      # field.Error renders string values quoted and everything else as JSON.
      def json_value(value)
        value.is_a?(String) ? value.inspect : JSON.generate(value)
      end

      # StatusError message for an invalid object, aggregated the way
      # apierrors.NewInvalid renders field.ErrorList.
      def status_message(kind, name, causes)
        rendered = causes.map { |cause| "#{cause.field}: #{cause.message}" }
        body = rendered.length == 1 ? rendered.first : "[#{rendered.join(", ")}]"
        "#{kind} #{name.to_s.inspect} is invalid: #{body}"
      end
    end
  end
end
