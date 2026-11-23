# frozen_string_literal: true

require_relative "schema"
require_relative "config_references"
require_relative "pod_credentials"
require_relative "empty_dir"
require_relative "pod_placement"
require_relative "container_probes"
require_relative "claim_templates"
require_relative "../resource_helpers"
require_relative "../schema/kubernetes_validator/formats"
require_relative "../schema/kubernetes_validator/pod_spec"

module Rubernetes
  module Manifest
    # The short way to write what every workload repeats: its containers,
    # and the labels that tie the selector to the Pod template.
    #
    #   deployment "web" do
    #     replicas 3
    #     container "nginx", image: "nginx:1.27" do
    #       port 80
    #       cpu request: "100m", limit: "500m"
    #       env from: configmap("app-config")
    #     end
    #   end
    #
    # The methods exist on a resource only when its type has a Pod template,
    # which is read from the schema (Pod, the workloads, Job, CronJob).  What
    # they write is ordinary fields; the generated field methods remain, and
    # both can be used in one block.
    module Workload
      POD_SPEC = "io.k8s.api.core.v1.PodSpec"
      CONTAINER = "io.k8s.api.core.v1.Container"
      VOLUME = "io.k8s.api.core.v1.Volume"

      VOLUME_SOURCES = {
        "ConfigMap" => %w[configMap name],
        "Secret" => %w[secret secretName],
        "PersistentVolumeClaim" => %w[persistentVolumeClaim claimName]
      }.freeze

      def self.running_containers(pod_spec)
        sidecars = Array(pod_spec["initContainers"]).select { |container| container["restartPolicy"] == "Always" }
        Array(pod_spec["containers"]) + sidecars
      end

      def self.bind_volume(entry, reference)
        if reference.is_a?(Array)
          type = "projected"
          field = "sources"
          value = reference.map { |ref| {VOLUME_SOURCES.fetch(ref.kind).first => {"name" => ref.name}} }
        else
          type, field = VOLUME_SOURCES.fetch(reference.kind)
          value = reference.name
        end
        fields = entry.fetch(type, {})
        unless (entry.keys - ["name", type]).empty? && fields.is_a?(Hash) && fields.fetch(field, value) == value
          raise Error, "volume #{entry.fetch("name").inspect} conflicts with its declared source"
        end

        entry[type] = fields.merge(field => value)
      end

      def self.resolve_volume(source, helpers, namespace, block_device: false)
        if source.is_a?(Array)
          raise Error, "a projected volume needs at least one ConfigMap or Secret" if source.empty?
          raise Error, "device needs a Block PersistentVolumeClaim" if block_device

          return source.map { |item| ResourceReferences.resolve(item, helpers, namespace) }
        end

        kinds = block_device ? ["PersistentVolumeClaim"] : VOLUME_SOURCES.keys
        ResourceReferences.resolve(source, helpers, namespace, kinds: kinds)
      end

      def self.volume_claim(source)
        source if source.is_a?(Hash) && source["kind"] == "PersistentVolumeClaim"
      end

      def self.validate_claim_mode(claim, block_device:, backtrace: nil, template: false)
        mode = claim.dig("spec", "volumeMode") || "Filesystem"
        expected = block_device ? "Block" : "Filesystem"
        return if mode == expected

        helper = block_device ? "mount" : "device"
        type = template ? "volumeClaimTemplates" : "PersistentVolumeClaim"
        raise Error, "#{type}/#{claim.dig("metadata", "name")} has volumeMode #{mode}; use #{helper}", backtrace
      end

      def self.install(context, object, schema_name, schema)
        path = pod_spec_path(schema_name, schema)
        return if path.nil?

        spec_field = schema.definition(schema_name).dig("properties", "spec")
        spec = schema.reference(spec_field) if spec_field
        spec_definition = spec ? schema.definition(spec) : {}
        context.extend(PodTemplate)
        context.extend(ClaimTemplates) if object.values_at("apiVersion", "kind") == ["apps/v1", "StatefulSet"]
        context.extend(ConfigRollout) if object["apiVersion"] == "apps/v1" && %w[Deployment StatefulSet DaemonSet].include?(object["kind"])
        # A Job, or the CronJob that makes them.
        job = spec&.end_with?(".JobSpec") || spec_definition.fetch("properties", {}).key?("jobTemplate")
        context.workload(object, path, selector: Array(spec_definition["required"]).include?("selector"), runs_to_completion: job)
      end

      # Where the PodSpec sits in a resource of this type, or nil.
      def self.pod_spec_path(schema_name, schema)
        step = lambda do |type, property|
          field = type && schema.defined?(type) && schema.definition(type).dig("properties", property)
          field && schema.reference(field)
        end
        spec = step.call(schema_name, "spec")
        return %w[spec] if spec == POD_SPEC
        return %w[template spec] if step.call(step.call(schema_name, "template"), "spec") == POD_SPEC
        return %w[spec template spec] if step.call(step.call(spec, "template"), "spec") == POD_SPEC

        job = step.call(step.call(spec, "jobTemplate"), "spec")
        %w[spec jobTemplate spec template spec] if step.call(step.call(job, "template"), "spec") == POD_SPEC
      end

      module PodTemplate
        include EmptyDirDeclarations
        include PodPlacement
        include PodCredentialFields

        def workload(object, path, selector:, runs_to_completion:)
          @workload = object
          @pod_spec_path = path
          @selects = selector
          @runs_to_completion = runs_to_completion
          @pod_credentials = PodCredentials.new(@helpers, object.dig("metadata", "namespace"))
          at_finish { complete_workload }
        end

        def container(name, image:, **fields, &) = add_container("containers", name, image, fields, &)
        def init_container(name, image:, **fields, &) = add_container("initContainers", name, image, fields, &)
        def sidecar(name, image:, **fields, &) = add_container("initContainers", name, image, fields, restartable: true, &)

        # volume "config", from: configmap("app-config")
        # volume "scratch"                      # an emptyDir
        # volume "data", persistent_volume_claim: {claim_name: "data"}
        def volume(name, from: nil, **source)
          entry = @schema.object(VOLUME, source, "volumes.#{name}").merge("name" => String(name))
          if from
            reference = Workload.resolve_volume(from, @helpers, @workload.dig("metadata", "namespace"))
            Workload.bind_volume(entry, reference)
            claim = Workload.volume_claim(from)
            record_volume_claim(entry.fetch("name"), claim) if claim
          end
          entry["emptyDir"] = {} if entry.length == 1
          (pod_spec["volumes"] ||= []) << entry
        end

        # The rest of the Pod's own fields, beside the containers:
        #   pod { service_account_name "builder"; termination_grace_period_seconds 5 }
        def pod(&)
          builder = ObjectBuilder.new(object: pod_spec, schema_name: POD_SPEC, schema: @schema, helpers: @helpers, path: @pod_spec_path.join("."))
          builder.extend(PodCredentialFields)
          builder.pod_credentials = @pod_credentials
          builder.instance_exec(&)
        end

        private

        def pod_spec
          @pod_spec_path.reduce(@workload) { |node, key| node[key] ||= {} }
        end

        def add_container(list, name, image, fields, restartable: false, &block)
          path = "#{list}.#{name}"
          entry = {"name" => String(name), "image" => String(image)}.merge(@schema.object(CONTAINER, fields, path))
          builder = ObjectBuilder.new(object: entry, schema_name: CONTAINER, schema: @schema, helpers: @helpers, path: path)
          builder.extend(ContainerFields)
          builder.workload_owner = @workload
          builder.workload_namespace = @workload.dig("metadata", "namespace")
          builder.volume_reference = method(:record_volume_reference)
          builder.volume_use = method(:record_volume_use)
          builder.env_resource_reference = method(:record_env_resource_reference)
          builder.instance_exec(&block) if block
          builder.finish
          if restartable
            raise Error, "sidecar #{name.inspect} requires restartPolicy Always" unless entry.fetch("restartPolicy", "Always") == "Always"

            entry["restartPolicy"] = "Always"
          end
          (pod_spec[list] ||= []) << entry
        end

        def record_volume_reference(name, reference, claim)
          references = @volume_references ||= {}
          raise Error, "volume #{name.inspect} refers to different volume sources" if references.key?(name) && references[name] != reference

          references[name] = reference
          record_volume_claim(name, claim) if claim
        end

        def record_volume_claim(name, claim)
          (@volume_claims ||= {})[name] = claim
        end

        def record_volume_use(name, block_device, backtrace, claim, template: nil)
          return Workload.validate_claim_mode(claim, block_device: block_device, backtrace: backtrace) if claim && @workload["kind"] != "StatefulSet"

          (@named_volume_uses ||= []) << [name, block_device, backtrace, template]
        end

        def validate_named_volume_modes(templates)
          volumes = Array(pod_spec["volumes"]).compact.group_by { |volume| volume["name"] }
          @named_volume_uses.each do |name, block_device, backtrace, reference|
            validate_template_reference(reference, templates[name], volumes, backtrace) if reference
            if (template = templates[name])
              Workload.validate_claim_mode(template, block_device: block_device, backtrace: backtrace, template: true)
              next
            end

            claim = @volume_claims&.fetch(name, nil)
            entries = volumes.fetch(name, [])
            next unless claim && entries.one? && entries.first.dig("persistentVolumeClaim", "claimName") == claim.dig("metadata", "name")

            Workload.validate_claim_mode(claim, block_device: block_device, backtrace: backtrace)
          end
        end

        def validate_template_reference(reference, template, volumes, backtrace)
          name = reference.name
          raise Error, "StatefulSet claim template #{name.inspect} no longer refers to its declaration", backtrace unless template.equal?(reference.claim)
          return unless volumes.key?(name) || @volume_references&.key?(name)

          raise Error, "StatefulSet claim template #{name.inspect} conflicts with another volume declaration", backtrace
        end

        def complete_referenced_volumes(templates)
          volumes = Array(pod_spec["volumes"])
          declared = volumes.compact.group_by { |volume| volume["name"] }
          @volume_references.each do |name, reference|
            next if templates.key?(name)

            matches = declared.fetch(name, [])
            raise Error, "volume #{name.inspect} was declared more than once" if matches.size > 1

            entry = matches.first || {"name" => name}
            Workload.bind_volume(entry, reference)
            volumes << entry if matches.empty?
          end
          pod_spec["volumes"] = volumes unless volumes.empty?
        end

        def complete_workload
          @pod_credentials.apply(pod_spec) if @pod_credentials.used?
          validate_env_resource_targets if @env_resource_references
          templates = Array(@workload.dig("spec", "volumeClaimTemplates")).compact.to_h { |claim| [claim.dig("metadata", "name"), claim] }
          complete_referenced_volumes(templates) if @volume_references
          validate_named_volume_modes(templates) if @named_volume_uses
          template = @pod_spec_path.length > 1 && @workload.dig(*@pod_spec_path[0..-2])
          select_template(template) if @selects && template
          # A Job's Pods may not restart for ever, and the API has no default
          # that is valid for them.
          pod_spec["restartPolicy"] ||= "Never" if @runs_to_completion && template
          complete_placement(template)
        end

        def record_env_resource_reference(entry, location)
          (@env_resource_references ||= {}.compare_by_identity)[entry] = location
        end

        def validate_env_resource_targets
          containers = Array(pod_spec["containers"]) + Array(pod_spec["initContainers"])
          names = containers.filter_map { |entry| entry["name"] }
          containers.flat_map { |entry| Array(entry["env"]) }.each do |entry|
            location = @env_resource_references[entry]
            next unless location

            target = entry.dig("valueFrom", "resourceFieldRef", "containerName")
            next if target.nil? || names.include?(target)

            raise Error, "env_resource container #{target.inspect} is missing. Available containers: #{names.sort.join(", ")}", location
          end
        end

        # A selector that was not written selects the template's labels, or
        # `app: <name>`; a template always carries what its selector matches.
        def select_template(template)
          metadata = template["metadata"] ||= {}
          selector = @workload["spec"]["selector"] ||= {"matchLabels" => metadata["labels"] || {"app" => @workload.dig("metadata", "name")}}
          metadata["labels"] = selector["matchLabels"].merge(metadata["labels"] || {}) if selector["matchLabels"]
        end
      end

      module ContainerFields
        include ContainerProbes

        attr_writer :workload_owner, :workload_namespace, :volume_reference, :volume_use, :env_resource_reference

        def finish
          super
          @quantity_declarations&.each do |resource, location|
            request = @object.dig("resources", "requests", resource)
            limit = @object.dig("resources", "limits", resource)
            next if request.nil? || limit.nil?
            next unless Rubernetes::Schema::Quantity.from_json(request) > Rubernetes::Schema::Quantity.from_json(limit)

            raise Error, "#{resource} request #{request} exceeds limit #{limit}", location
          rescue Rubernetes::Schema::Quantity::ParseError => error
            raise Error, "invalid #{resource} quantity: #{error.message}", location
          end
        end

        def port(number, name: nil, protocol: nil)
          (@object["ports"] ||= []) << {"containerPort" => Integer(number), "name" => name&.to_s, "protocol" => protocol&.to_s}.compact
        end

        def cpu(request: nil, limit: nil) = quantity("cpu", request, limit)
        def memory(request: nil, limit: nil) = quantity("memory", request, limit)
        def ephemeral_storage(request: nil, limit: nil) = quantity("ephemeral-storage", request, limit)

        # Read a Pod field at container startup using the Kubernetes Downward API.
        def env_field(name, path = nil, label: nil, annotation: nil)
          fields = [path, label, annotation].compact
          unless fields.length == 1 && (fields.first.is_a?(String) || fields.first.is_a?(Symbol))
            raise Error, "env_field expects one Pod field path, label: or annotation:"
          end

          validator = Rubernetes::Schema::KubernetesValidator
          if path
            path = path.to_s
            unless validator::ENV_FIELD_PATHS.include?(path)
              raise Error, "unknown Pod environment field #{path.inspect}. Available: #{validator::ENV_FIELD_PATHS.join(", ")}"
            end
          else
            key = (label || annotation).to_s
            errors = validator.qualified_name_messages(label ? key : key.downcase)
            raise Error, "invalid Pod #{label ? "label" : "annotation"} key #{key.inspect}: #{errors.join(", ")}" unless errors.empty?

            path = "metadata.#{label ? "labels" : "annotations"}['#{key}']"
          end
          (@object["env"] ||= []) << {"name" => String(name), "valueFrom" => {"fieldRef" => {"apiVersion" => "v1", "fieldPath" => path}}}
        end

        def env_resource(name, resource, divisor: nil, container: nil)
          resource = String(resource)
          unless ResourceHelpers.downward_resource_field?(resource)
            resources = ResourceHelpers::DOWNWARD_RESOURCE_FIELDS.join(", ")
            raise Error, "unknown Pod environment resource #{resource.inspect}. Available: #{resources}, requests.hugepages-*, limits.hugepages-*"
          end

          selector = {"resource" => resource, "containerName" => container&.to_s}.compact
          selector["divisor"] = env_resource_divisor(resource, divisor) unless divisor.nil?
          entry = {"name" => String(name), "valueFrom" => {"resourceFieldRef" => selector}}
          @env_resource_reference.call(entry, caller(1, 1)) unless container.nil?
          (@object["env"] ||= []) << entry
        end

        # env "LOG_LEVEL", "debug"
        # env from: configmap("app-config")                     # every key
        # env "PASSWORD", from: secret("db"), key: "password"   # one key
        def env(name = nil, value = nil, from: nil, key: nil)
          return field("env", name) if name.is_a?(Array)

          from = ResourceReferences.resolve(from, @helpers, @workload_namespace, key: key) if from
          source = from && (from.kind == "ConfigMap" ? "configMap" : "secret")
          if name.nil?
            raise Error, "env needs a name, or from: a configmap or secret" unless from

            (@object["envFrom"] ||= []) << {"#{source}Ref" => {"name" => from.name}}
          elsif from
            raise Error, "env #{name.inspect} from a #{from.kind} needs key:" unless key

            (@object["env"] ||= []) << {"name" => String(name), "valueFrom" => {"#{source}KeyRef" => {"name" => from.name, "key" => String(key)}}}
          else
            (@object["env"] ||= []) << {"name" => String(name), "value" => String(value)}
          end
        end

        def mount(volume, at:, read_only: nil, from: nil)
          name, readonly_source = volume_binding(volume, from, block_device: false)
          read_only = true if read_only.nil? && readonly_source
          (@object["volumeMounts"] ||= []) << {"name" => name, "mountPath" => String(at), "readOnly" => read_only}.compact
        end

        def device(volume, at:, from: nil)
          name, = volume_binding(volume, from, block_device: true)
          (@object["volumeDevices"] ||= []) << {"name" => name, "devicePath" => String(at)}
        end

        private

        def env_resource_divisor(resource, divisor)
          quantity = Rubernetes::Schema::Quantity.from_json(divisor)
          raise Error, "env_resource divisor for #{resource} must be positive" unless quantity.sign.positive?

          error = ResourceHelpers.downward_divisor_error(resource, quantity)
          raise Error, "env_resource divisor for #{resource}: #{error}" if error

          quantity.to_s
        rescue Rubernetes::Schema::Quantity::ParseError => error
          raise Error, "invalid env_resource divisor #{divisor.inspect}: #{error.message}"
        end

        def volume_binding(volume, source, block_device:)
          if volume.is_a?(ClaimTemplateReference)
            raise Error, "claim template #{volume.name.inspect} belongs to a different StatefulSet" unless volume.workload.equal?(@workload_owner)
            raise Error, "specify one volume source" if source

            @volume_use.call(volume.name, block_device, caller(2, 1), nil, template: volume)
            return [volume.name, false]
          end
          if volume.is_a?(EmptyDirReference)
            raise Error, "emptyDir #{volume.name.inspect} belongs to a different workload" unless volume.workload.equal?(@workload_owner)
            raise Error, "emptyDir #{volume.name.inspect} is a filesystem volume, use mount" if block_device
            raise Error, "specify one volume source" if source

            return [volume.name, false]
          end
          if volume.is_a?(Array) || (volume.nil? && source.is_a?(Array))
            raise Error, 'supply a name for the projected volume, e.g. mount "settings", from: [defaults, overrides]'
          end

          if volume.is_a?(Hash) || volume.is_a?(Reference)
            raise Error, "specify one volume source" if source

            source = volume
            volume = nil
          end
          reference = Workload.resolve_volume(source, @helpers, @workload_namespace, block_device: block_device) if source
          claim = Workload.volume_claim(source)

          name = volume.nil? && reference ? reference.name : String(volume)
          if reference && !Rubernetes::Schema::KubernetesValidator.dns1123_label_messages(name).empty?
            raise Error, "#{reference.kind}/#{name} needs an explicit volume name using from:" if volume.nil?

            raise Error, "invalid Pod volume name #{name.inspect}"
          end

          @volume_use.call(name, block_device, caller(2, 1), claim)
          @volume_reference.call(name, reference, claim) if reference
          [name, reference && (reference.is_a?(Array) || reference.kind != "PersistentVolumeClaim")]
        end

        def quantity(resource, request, limit)
          resources = @object["resources"] ||= {}
          (@quantity_declarations ||= {})[resource] = caller(2, 1)
          {"request" => request, "limit" => limit}.compact.each do |field, value|
            text = String(value)
            parsed = Rubernetes::Schema::Quantity.parse(text.strip)
            raise Error, "#{resource} #{field} must be non-negative" if parsed.negative?

            (resources["#{field}s"] ||= {})[resource] = text
          rescue Rubernetes::Schema::Quantity::ParseError => error
            raise Error, "invalid #{resource} #{field} quantity #{value.inspect}: #{error.message}"
          end
        end
      end
    end
  end
end
