# frozen_string_literal: true

require_relative "schema"

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

      def self.install(context, object, schema_name, schema)
        path = pod_spec_path(schema_name, schema)
        return if path.nil?

        spec = schema.reference(schema.definition(schema_name).dig("properties", "spec"))
        context.extend(PodTemplate)
        # A Job, or the CronJob that makes them.
        job = spec.end_with?(".JobSpec") || schema.definition(spec).fetch("properties", {}).key?("jobTemplate")
        context.workload(object, path, selector: Array(schema.definition(spec)["required"]).include?("selector"), runs_to_completion: job)
      end

      # Where the PodSpec sits in a resource of this type, or nil.
      def self.pod_spec_path(schema_name, schema)
        step = lambda do |type, property|
          field = type && schema.defined?(type) && schema.definition(type).dig("properties", property)
          field && schema.reference(field)
        end
        spec = step.call(schema_name, "spec")
        return %w[spec] if spec == POD_SPEC
        return %w[spec template spec] if step.call(step.call(spec, "template"), "spec") == POD_SPEC

        job = step.call(step.call(spec, "jobTemplate"), "spec")
        %w[spec jobTemplate spec template spec] if step.call(step.call(job, "template"), "spec") == POD_SPEC
      end

      module PodTemplate
        def workload(object, path, selector:, runs_to_completion:)
          @workload = object
          @pod_spec_path = path
          @selects = selector
          @runs_to_completion = runs_to_completion
          @spread_over = []
          at_finish { complete_workload }
        end

        def container(name, image:, **fields, &) = add_container("containers", name, image, fields, &)
        def init_container(name, image:, **fields, &) = add_container("initContainers", name, image, fields, &)

        # volume "config", from: configmap("app-config")
        # volume "scratch"                      # an emptyDir
        # volume "data", persistent_volume_claim: {claim_name: "data"}
        def volume(name, from: nil, **source)
          entry = {"name" => String(name)}
          entry["configMap"] = {"name" => from.name} if from&.kind == "ConfigMap"
          entry["secret"] = {"secretName" => from.name} if from&.kind == "Secret"
          entry.merge!(@schema.object(VOLUME, source, "volumes.#{name}"))
          entry["emptyDir"] = {} if entry.length == 1
          (pod_spec["volumes"] ||= []) << entry
        end

        # The rest of the Pod's own fields, beside the containers:
        #   pod { service_account_name "builder"; termination_grace_period_seconds 5 }
        def pod(&)
          ObjectBuilder.new(object: pod_spec, schema_name: POD_SPEC, schema: @schema, helpers: @helpers, path: @pod_spec_path.join("."))
            .instance_exec(&)
        end

        # No two Pods of this workload in the same topology domain.
        def anti_affinity(on:)
          @spread_over << String(on)
        end

        private

        def pod_spec
          @pod_spec_path.reduce(@workload) { |node, key| node[key] ||= {} }
        end

        def add_container(list, name, image, fields, &block)
          path = "#{list}.#{name}"
          entry = {"name" => String(name), "image" => String(image)}.merge(@schema.object(CONTAINER, fields, path))
          builder = ObjectBuilder.new(object: entry, schema_name: CONTAINER, schema: @schema, helpers: @helpers, path: path)
          builder.extend(ContainerFields)
          builder.instance_exec(&block) if block
          (pod_spec[list] ||= []) << entry
        end

        def complete_workload
          template = @pod_spec_path.length > 1 && @workload.dig(*@pod_spec_path[0..-2])
          select_template(template) if @selects && template
          # A Job's Pods may not restart for ever, and the API has no default
          # that is valid for them.
          pod_spec["restartPolicy"] ||= "Never" if @runs_to_completion && template
          return if @spread_over.empty?

          labels = workload_labels(template) || raise(Error, "anti_affinity needs labels on the Pods to tell them apart")
          terms = pod_spec["affinity"] ||= {}
          terms = (terms["podAntiAffinity"] ||= {})["requiredDuringSchedulingIgnoredDuringExecution"] ||= []
          @spread_over.each { |key| terms << {"labelSelector" => {"matchLabels" => labels}, "topologyKey" => key} }
        end

        # A selector that was not written selects the template's labels, or
        # `app: <name>`; a template always carries what its selector matches.
        def select_template(template)
          metadata = template["metadata"] ||= {}
          selector = @workload["spec"]["selector"] ||= {"matchLabels" => metadata["labels"] || {"app" => @workload.dig("metadata", "name")}}
          metadata["labels"] = selector["matchLabels"].merge(metadata["labels"] || {}) if selector["matchLabels"]
        end

        def workload_labels(template)
          labels = @selects ? @workload.dig("spec", "selector", "matchLabels") : (template || @workload).dig("metadata", "labels")
          labels unless labels.nil? || labels.empty?
        end
      end

      module ContainerFields
        def port(number, name: nil, protocol: nil)
          (@object["ports"] ||= []) << {"containerPort" => Integer(number), "name" => name, "protocol" => protocol}.compact
        end

        def cpu(request: nil, limit: nil) = quantity("cpu", request, limit)
        def memory(request: nil, limit: nil) = quantity("memory", request, limit)

        # env "LOG_LEVEL", "debug"
        # env from: configmap("app-config")                     # every key
        # env "PASSWORD", from: secret("db"), key: "password"   # one key
        def env(name = nil, value = nil, from: nil, key: nil)
          return field("env", name) if name.is_a?(Array)

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

        def mount(volume, at:, read_only: nil)
          (@object["volumeMounts"] ||= []) << {"name" => String(volume), "mountPath" => String(at), "readOnly" => read_only}.compact
        end

        private

        def quantity(resource, request, limit)
          resources = @object["resources"] ||= {}
          (resources["requests"] ||= {})[resource] = String(request) if request
          (resources["limits"] ||= {})[resource] = String(limit) if limit
        end
      end
    end
  end
end
