# frozen_string_literal: true

module Rubernetes
  module Client
    class KubernetesClient
      # Core v1 pods/log. The HTTP client retains connection credentials and
      # yields raw body chunks, closing the stream when the caller stops.
      def pod_logs(name, namespace: nil, container: nil, follow: false, previous: false,
                   tail_lines: nil, timestamps: false, since_time: nil, since_seconds: nil, &)
        namespace ||= context_namespace || Kubeconfig::DEFAULT_NAMESPACE
        raise UsageError, "Pod logs require a namespace" if namespace == :all || namespace.to_s.empty?

        path = resource_path("pods", name, namespace: namespace, api_version: "v1", subresource: "log", operation: :get)
        query = {"container" => container, "follow" => (true if follow), "previous" => (true if previous),
                 "tailLines" => tail_lines, "timestamps" => (true if timestamps),
                 "sinceTime" => since_time, "sinceSeconds" => since_seconds}.compact
        timeouts = follow ? {read_timeout: 0} : {}
        @rest_client.stream("GET", path, query: query, **timeouts, &)
      end
    end
  end
end
