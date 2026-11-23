# frozen_string_literal: true

module Rubernetes
  module Schema
    # batch Job strategy populates missing selector fields after assigning the
    # server UID. Existing controller labels must survive for validation.
    module JobSelector
      CONTROLLER_UID = "batch.kubernetes.io/controller-uid"
      JOB_NAME = "batch.kubernetes.io/job-name"

      module_function

      def resource?(resource)
        resource.kind == "Job" && resource.group == "batch" && !resource.custom?
      end

      def object?(object)
        object.is_a?(Hash) && object["apiVersion"] == "batch/v1" && object["kind"] == "Job"
      end

      def normalize_label_values!(job)
        normalize_string_map!(job["metadata"], "labels")
        spec = job["spec"]
        return unless spec.is_a?(Hash)

        template = spec["template"]
        normalize_string_map!(template["metadata"], "labels") if template.is_a?(Hash)
        selector = spec["selector"]
        normalize_string_map!(selector, "matchLabels")
        expressions = selector["matchExpressions"] if selector.is_a?(Hash)
        return unless expressions.is_a?(Array)

        expressions.each do |expression|
          next unless expression.is_a?(Hash)

          values = expression["values"]
          expression["values"] = values.map { |value| value.nil? ? "" : value } if values.is_a?(Array) && values.include?(nil)
        end
      end

      def normalize_string_map!(owner, field)
        values = owner[field] if owner.is_a?(Hash)
        return unless values.is_a?(Hash) && values.value?(nil)

        # Typed map[string]string decoding retains a null-valued key with the
        # zero value of a string. A present empty label can match a selector.
        owner[field] = values.transform_values { |value| value.nil? ? "" : value }
      end
      private_class_method :normalize_string_map!

      # Typed Job serialization omits the selector's empty maps and slices.
      # SSA computes ownership from the unstructured patch before defaulting.
      def omit_empty_collections(job)
        spec = job["spec"] if job.is_a?(Hash)
        selector = spec["selector"] if spec.is_a?(Hash)
        return job unless selector.is_a?(Hash)

        wire = selector.dup
        wire.delete("matchLabels") if wire["matchLabels"].nil? || wire["matchLabels"] == {}
        expressions = wire["matchExpressions"]
        if expressions.nil? || expressions == []
          wire.delete("matchExpressions")
        elsif expressions.is_a?(Array)
          wire["matchExpressions"] = expressions.map do |expression|
            if expression.is_a?(Hash) && (expression["values"].nil? || expression["values"] == [])
              expression.except("values")
            else
              expression
            end
          end
        end
        return job if wire == selector

        job.merge("spec" => spec.merge("selector" => wire))
      end

      def inherited_labels(job)
        return unless job.is_a?(Hash)

        metadata = job["metadata"]
        root = metadata["labels"] if metadata.is_a?(Hash)
        return unless root.nil? || root == {}

        spec = job["spec"]
        template = spec["template"] if spec.is_a?(Hash)
        metadata = template["metadata"] if template.is_a?(Hash)
        labels = metadata["labels"] if metadata.is_a?(Hash)
        labels if labels.is_a?(Hash)
      end

      # SetDefaults_Job runs when a stored Job is decoded. If generation
      # allocated the template label map during creation, this populates the
      # read view while the original stored object still has no root labels.
      def decode_labels(job)
        labels = inherited_labels(job)
        return job if labels.nil? || labels.empty?

        metadata = job["metadata"].is_a?(Hash) ? job["metadata"] : {}
        metadata = metadata.merge("labels" => labels)
        return job.merge("metadata" => metadata) unless job.frozen?

        job.merge("metadata" => metadata.freeze).freeze
      end

      def expected(name, uid, prefixed: true)
        labels = {"controller-uid" => uid, "job-name" => name}
        if prefixed
          labels[CONTROLLER_UID] = uid
          labels[JOB_NAME] = name
        end
        labels
      end

      def generate!(job, inherited_labels:)
        spec = job["spec"]
        uid = job.dig("metadata", "uid")
        return unless spec.is_a?(Hash) && spec["manualSelector"] != true && uid && !uid.empty?

        selector = spec["selector"] ||= {}
        match = selector["matchLabels"] ||= {}
        match[CONTROLLER_UID] = uid unless match.key?(CONTROLLER_UID)
        template = spec["template"] ||= {}
        metadata = template["metadata"] ||= {}
        labels = metadata["labels"] ||= {}
        expected(job.dig("metadata", "name"), uid).each { |key, value| labels[key] = value unless labels.key?(key) }
        # SetDefaults_Job aliases a supplied template map to empty root labels.
        # A mutating webhook can replace the root map before this strategy runs.
        root = job["metadata"]
        current = root["labels"]
        job["metadata"] = root.merge("labels" => labels.dup) if inherited_labels && current == inherited_labels
      end
    end
  end
end
