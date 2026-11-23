# frozen_string_literal: true

require_relative "../schema/definition"
require_relative "../schema/kubernetes_validator/field_access"

module Rubernetes
  module API
    # The typed wire shape of Pods and built-in workload PodSpecs.
    module PodWire
      POD_SPEC_PATHS = {
        "Pod" => %w[spec], "PodTemplate" => %w[template spec], "ReplicationController" => %w[spec template spec],
        "Deployment" => %w[spec template spec], "ReplicaSet" => %w[spec template spec], "DaemonSet" => %w[spec template spec],
        "StatefulSet" => %w[spec template spec], "Job" => %w[spec template spec], "CronJob" => %w[spec jobTemplate spec template spec]
      }.freeze
      CONTAINER_FIELDS = %w[containers initContainers ephemeralContainers].freeze
      Fields = Schema::KubernetesValidator

      module_function

      def resource?(resource)
        resource.kind == "Pod" && resource.group.to_s.empty? && !resource.custom?
      end

      def normalize(object)
        spec = object["spec"] if object.is_a?(Hash)
        return object unless spec.is_a?(Hash)

        grace = spec["terminationGracePeriodSeconds"]
        normalized = spec
        # pkg/apis/core/v1/conversion.go clamps negative grace periods.
        normalized = normalized.merge("terminationGracePeriodSeconds" => 1) if grace.is_a?(Integer) && grace.negative?
        # The typed Pod omits an empty toleration list before managed fields are recorded.
        normalized = normalized.except("tolerations") if normalized["tolerations"] == []

        normalized.equal?(spec) ? object : object.merge("spec" => normalized)
      end

      def resource_selectors?(resource)
        POD_SPEC_PATHS.key?(resource.kind) && !resource.custom?
      end

      # resource.Quantity is a value field in the typed ResourceFieldSelector.
      # Go materializes its zero for null and omission. The value is supplied
      # after apply ownership is calculated, and for older stored objects.
      def normalize_resource_selectors(resource, object)
        return object unless resource_selectors?(resource)

        path = POD_SPEC_PATHS.fetch(resource.kind)
        return object unless resource_selectors(Fields.value_at_path(object, path)).any? { |ref| Fields.fetch(ref, "divisor").nil? }

        copy = Fields.deep_copy_value(object)
        resource_selectors(copy.dig(*path)).each { |ref| ref["divisor"] = "0" if ref["divisor"].nil? }
        object.frozen? ? Schema::DeepFreeze.call(copy) : copy
      end

      def resource_selectors(spec)
        return enum_for(__method__, spec) unless block_given?

        CONTAINER_FIELDS.each do |field|
          Array(Fields.fetch(spec, field)).each do |container|
            Array(Fields.fetch(container, "env")).each do |entry|
              ref = Fields.fetch(Fields.fetch(entry, "valueFrom"), "resourceFieldRef")
              yield ref if ref.is_a?(Hash)
            end
          end
        end
        Array(Fields.fetch(spec, "volumes")).each do |volume|
          sources = Array(Fields.fetch(Fields.fetch(volume, "projected"), "sources"))
          [volume, *sources].each do |source|
            Array(Fields.fetch(Fields.fetch(source, "downwardAPI"), "items")).each do |item|
              ref = Fields.fetch(item, "resourceFieldRef")
              yield ref if ref.is_a?(Hash)
            end
          end
        end
      end
    end
  end
end
