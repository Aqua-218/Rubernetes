# frozen_string_literal: true

module Rubernetes
  module Controller
    module Builtins
      class WorkloadController < BaseController
        POD = ResourceDescriptor.parse("Pod")

        protected

        def descriptor_for(value)
          ResourceDescriptor.parse(value)
        end

        def list_children(adapter, descriptor, namespace)
          return [] unless adapter

          adapter.list(descriptor, namespace: namespace || :all)
        end

        def template(resource)
          candidate = Support.value(Support.spec(resource), "template", {})
          candidate.is_a?(Hash) ? Support.deep_copy(candidate) : {}
        end

        def template_hash(resource_or_template)
          candidate = resource_or_template.is_a?(Hash) && Support.kind(resource_or_template).to_s.empty? ? resource_or_template : template(resource_or_template)
          Digest::SHA256.hexdigest(JSON.generate(Support.canonical(candidate)))[0, 10]
        end

        def owner_ref?(owner, dependent)
          Support.owner_reference_matches?(owner, dependent, controller: true)
        end

        def pod_for(owner, name:, template_value: nil, labels: nil, node_name: nil, ordinal: nil)
          source = template_value ? Support.deep_copy(template_value) : template(owner)
          metadata = Support.metadata(source)
          spec = Support.spec(source)
          metadata["name"] = name
          metadata["namespace"] ||= Support.namespace(owner) if Support.namespace(owner)
          merged_labels = Support.value(metadata, "labels", {})
          merged_labels = {} unless merged_labels.is_a?(Hash)
          merged_labels = merged_labels.merge(labels || {})
          metadata["labels"] = merged_labels unless merged_labels.empty?
          spec["nodeName"] = node_name if node_name
          {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => spec}
        end

        def pod_alive?(pod)
          phase = Support.value(Support.status(pod), "phase", "").to_s
          !Support.value(Support.metadata(pod), "deletionTimestamp", nil) && !%w[Succeeded Failed].include?(phase)
        end

        def result(resource, operations, status: nil, events: [], batches: nil, force_status: false, status_first: false)
          status ||= Support.status(resource)
          status_operation = operation_status(resource, status, descriptor: descriptor_for(resource), force: force_status)
          operations = Array(operations).compact
          if status_operation && status_first
            operations.unshift(status_operation)
            batches = [[status_operation], *batches] if batches
          elsif status_operation
            operations << status_operation
          end
          ReconcileResult.new(operations: operations, status: status,
                              batches: batches, events: events, controller: name,
                              key: [Support.namespace(resource), Support.name(resource)].compact.join("/"))
        end

        def replica_count(resource, field = "replicas", default: 1)
          count = Support.integer(Support.value(Support.spec(resource), field, default), default)
          raise ArgumentError, "#{field} must be non-negative" if count.negative?

          count
        end

        def selector_for(resource)
          selector = Support.value(Support.spec(resource), "selector", {})
          selector = Support.value(selector, "matchLabels", selector) if selector.is_a?(Hash) && Support.value(selector, "matchLabels", nil)
          selector || {}
        end

        def revision(object)
          annotations = Support.annotations(object)
          Support.integer(annotations["deployment.kubernetes.io/revision"] || annotations["controller.kubernetes.io/revision"], 0)
        end

        def with_owner_metadata(object, owner)
          candidate = Support.deep_copy(object)
          candidate["metadata"] ||= {}
          candidate["metadata"]["ownerReferences"] = [Support.owner_reference(owner)]
          candidate
        end

        # The same result, asking to be planned again after +requeue_after+
        # seconds (nil leaves it as it is).
        def with_requeue(planned, requeue_after)
          return planned if requeue_after.nil?

          ReconcileResult.new(operations: planned.operations, batches: planned.batches, status: planned.status,
                              events: planned.events, controller: planned.controller, key: planned.key,
                              requeue_after: requeue_after)
        end
      end
    end
  end
end
