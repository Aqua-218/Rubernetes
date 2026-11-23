# frozen_string_literal: true

require_relative "../schema/kubernetes_validator/formats"

module Rubernetes
  module Rubectl
    # Reports filesystem measurements as published by the kubelet Summary API.
    class NodeDiskUsage
      MEASUREMENTS = %w[usedBytes availableBytes capacityBytes].freeze
      LABELS = {"fs" => "Node root filesystem", "imageFs" => "Runtime image filesystem", "containerFs" => "Runtime container filesystem"}.freeze

      def self.fetch(client, name)
        unless Schema::KubernetesValidator.dns1123_subdomain_messages(name).empty?
          raise Client::UsageError, "disk node/NAME requires a valid Kubernetes node name"
        end

        summary = client.get("/api/v1/nodes/#{name}/proxy/stats/summary")
        node = summary["node"] if summary.is_a?(Hash)
        raise Client::Error, "kubelet for node #{name} returned an invalid stats summary" unless node.is_a?(Hash)

        runtime = node["runtime"].is_a?(Hash) ? node["runtime"] : {}
        filesystems = {"fs" => node["fs"], "imageFs" => runtime["imageFs"], "containerFs" => runtime["containerFs"]}
        {"nodeName" => name, "filesystems" => filesystems.transform_values { |stats| measurements(stats) }}
      end

      def self.text(report)
        lines = ["Node #{report.fetch("nodeName")}"]
        report.fetch("filesystems").each do |kind, stats|
          used, available, capacity = stats.values_at(*MEASUREMENTS).map { |value| value.nil? ? "unknown" : "#{value} B" }
          lines << "#{LABELS.fetch(kind)}  used: #{used}  available: #{available}  capacity: #{capacity}"
        end
        lines.join("\n")
      end

      def self.measurements(stats)
        MEASUREMENTS.to_h do |field|
          value = stats[field] if stats.is_a?(Hash)
          [field, (value if value.is_a?(Integer) && value >= 0)]
        end
      end
      private_class_method :measurements
    end
  end
end
