# frozen_string_literal: true

module Rubernetes
  module Manifest
    module Autoscale
      # Attach an autoscaling/v2 HPA to the workload returned by a declaration.
      def autoscale(workload, replicas:, cpu: nil, memory: nil, container: nil, name: nil)
        raise Error, "autoscale expects a workload declared in this manifest" unless result.any? { |entry| entry.equal?(workload) }

        api_version, kind = workload.values_at("apiVersion", "kind")
        group, version = split_api_version(api_version)
        target = @registry.fetch("resources").find { |entry| entry.values_at("group", "version", "kind") == [group, version, kind] }
        unless target && Array(target["subresources"]).any? { |entry| entry["resource"] == "scale" && Array(entry["verbs"]).include?("update") }
          raise Error, "#{kind} does not declare a writable scale subresource"
        end

        unless replicas.is_a?(Range) && replicas.begin.is_a?(Integer) && replicas.end.is_a?(Integer)
          raise Error, "autoscale replicas must be a bounded Range of integers, such as 2..8"
        end

        minimum = replicas.begin
        maximum = replicas.exclude_end? ? replicas.end - 1 : replicas.end
        raise Error, "autoscale replicas must be a nonempty range within 1..2147483647" unless minimum.positive? && maximum.between?(minimum, 2_147_483_647)

        targets = {"cpu" => cpu, "memory" => memory}.compact
        raise Error, "autoscale needs a target utilization percentage for cpu: or memory:" if targets.empty?

        container_name = autoscale_container(workload, container) unless container.nil?
        metrics = targets.map do |resource_name, percentage|
          unless percentage.is_a?(Integer) && percentage.between?(1, 2_147_483_647)
            raise Error, "autoscale #{resource_name} utilization must be a positive int32 percentage"
          end

          source = {"name" => resource_name, "target" => {"type" => "Utilization", "averageUtilization" => percentage}}
          if container_name
            {"type" => "ContainerResource", "containerResource" => source.merge("container" => container_name)}
          else
            {"type" => "Resource", "resource" => source}
          end
        end
        target_name, namespace = workload.fetch("metadata").values_at("name", "namespace")
        reference = {"apiVersion" => api_version, "kind" => kind, "name" => target_name}
        resource(api_version: "autoscaling/v2", kind: "HorizontalPodAutoscaler", name: name || target_name, namespace: namespace) do
          spec scale_target_ref: reference, min_replicas: minimum, max_replicas: maximum, metrics: metrics
        end
      end

      private

      def autoscale_container(workload, container)
        pod_spec = workload.dig("spec", "template", "spec") || {}
        names = Workload.running_containers(pod_spec).filter_map { |entry| entry["name"] }
        return container.to_s if (container.is_a?(String) || container.is_a?(Symbol)) && names.include?(container.to_s)

        declared = names.empty? ? "(none)" : names.join(", ")
        target = "#{workload["kind"]}/#{workload.dig("metadata", "name")}"
        raise Error, "autoscale cannot target container #{container.inspect} in #{target}. Running containers: #{declared}"
      end
    end
  end
end
