# frozen_string_literal: true

require_relative "status"

module Rubernetes
  module API
    module PodLogOptions
      module_function

      # PodLogOptions uses the case-sensitive API enum. The disabled API
      # rejects an explicit stream and omits it from the node request.
      def stream(request, pod_name, enabled:)
        value = request.query_value("stream")
        return enabled ? :all : nil if value.nil?

        reason, field, message = if !enabled
                                   ["FieldValueForbidden", "stream", "Forbidden: may not be specified"]
                                 elsif !%w[All Stdout Stderr].include?(value)
                                   ["FieldValueNotSupported", "stream",
                                    "Unsupported value: #{value.inspect}: supported values: \"All\", \"Stderr\", \"Stdout\""]
                                 elsif value != "All" && !request.query_value("tailLines").nil?
                                   ["FieldValueForbidden", "", "Forbidden: `tailLines` and specific `stream` are mutually exclusive for now"]
                                 end
        if reason
          detail = field.empty? ? message : "#{field}: #{message}"
          raise Status::Invalid.new("PodLogOptions #{pod_name.inspect} is invalid: #{detail}",
                                    details: {"kind" => "PodLogOptions", "name" => pod_name},
                                    causes: [{"reason" => reason, "field" => field, "message" => message}])
        end

        value.downcase.to_sym
      end

      def node_container(containers, pod, name)
        selected = container_name(pod, name)
        return containers.first if selected.empty?

        containers.find { |entry| (entry[:name] || entry["name"]).to_s == selected }
      end

      def remote_endpoint?(node)
        defined?(NodeEndpointResolver::PodScopedEndpoint) && node.is_a?(NodeEndpointResolver::PodScopedEndpoint)
      end

      # These are node lifecycle records. API Pod status can carry a user
      # supplied containerID and must never select a local file or runtime id.
      def previous_target(record, containers, pod, name)
        selected = container_name(pod, name)
        entry = node_container(containers, pod, selected)
        state = entry && (entry[:status] || entry["status"] || {})
        id = state&.dig("lastState", "terminated", "containerID").to_s
        raise Status::BadRequest.new("previous terminated container #{selected.inspect} in pod #{pod.dig("metadata", "name").inspect} not found") if id.empty?

        path = entry[:previous_log_path] || entry["previous_log_path"] if (entry[:previous_id] || entry["previous_id"]) == id
        {id: id, sandbox_id: record[:sandbox_id] || record["sandbox_id"], archived_log_path: path}.compact
      end

      def container_name(pod, name)
        return name.to_s unless name.to_s.empty?

        first = Array(pod.dig("spec", "containers")).first
        first.is_a?(Hash) ? (first["name"] || first[:name]).to_s : ""
      end
    end
  end
end
