# frozen_string_literal: true

require_relative "../schema/kubernetes_validator/formats"
require_relative "../schema/quantity"

module Rubernetes
  module Rubectl
    # Reports disk usage from the kubelet Summary API for selected Pods.
    class PodDiskUsage
      CONTAINER_LISTS = %w[containers initContainers ephemeralContainers].freeze
      NO_SAMPLE_REASONS = {
        "notScheduled" => "Pod is not scheduled",
        "missingUID" => "Pod has no UID",
        "noSample" => "no kubelet sample for this Pod UID"
      }.freeze
      STORAGE_LABELS = {"ram" => "RAM", "pvc" => "PVC", "disk" => "disk", "unknown" => "unknown storage"}.freeze

      def self.fetch(client, name, namespace:)
        pod = client.get("pods", name, namespace: namespace)
        raise Client::Error, "Kubernetes API returned an invalid Pod" unless pod.is_a?(Hash)

        usage = new(pod)
        samples = usage.measurable? ? read_node(client, usage.node_name, [usage.uid]) : {}
        usage.report(samples[usage.uid])
      end

      def self.rank(client, namespace:, node: nil)
        raise Client::UsageError, "--node must be a Kubernetes node name" if node && !valid_node?(node)

        pods = list_pods(client, namespace, node)
        pods.select! { |pod| pod.node_name == node } if node
        totals = pods.group_by(&:node_name).flat_map do |name, group|
          uids = group.select(&:measurable?).map(&:uid)
          samples = uids.empty? ? {} : read_node(client, name, uids)
          group.map { |pod| pod.total(samples[pod.uid]) }
        end
        sorted = totals.sort_by do |entry|
          bytes = entry["ephemeralStorageUsedBytes"]
          [bytes.nil? ? 1 : 0, -bytes.to_i, entry.dig("pod", "namespace").to_s, entry.dig("pod", "name")]
        end
        {"pods" => sorted}
      end

      # Keep just Pod identities and their assigned nodes while paging through
      # the cluster. Container specs are needed only for a single-Pod report.
      def self.list_pods(client, namespace, node)
        query = {"limit" => 500}
        query["fieldSelector"] = "spec.nodeName=#{node}" if node
        pods = []
        loop do
          list = client.get("pods", namespace: namespace, query: query)
          raise Client::Error, "Kubernetes API returned an invalid Pod list" unless list.is_a?(Hash) && list["items"].is_a?(Array)

          list.fetch("items").each { |pod| pods << new(pod, details: false) }
          token = list.dig("metadata", "continue")
          break if token.to_s.empty?
          raise Client::Error, "Kubernetes API repeated a Pod list continuation token" if query["continue"] == token

          query = query.merge("continue" => token)
        end
        pods
      end
      private_class_method :list_pods

      def self.text(report)
        return ranking_text(report.fetch("pods")) if report.key?("pods")

        pod = report.fetch("pod")
        node = report["nodeName"] || "unassigned"
        lines = ["Pod #{pod["namespace"]}/#{pod["name"]} on #{node}", "Ephemeral storage: #{total_label(report)}"]
        containers = report.fetch("containers")
        lines << "Containers" unless containers.empty?
        containers.each do |item|
          lines << "  #{item["name"]}  writable layer: #{bytes_label(item["writableLayerUsedBytes"])}  logs: #{bytes_label(item["logsUsedBytes"])}"
        end
        volumes = report.fetch("volumes")
        lines << "Volumes" unless volumes.empty?
        volumes.each do |item|
          storage = STORAGE_LABELS.fetch(item["storage"])
          detail = item["claimName"] || item["source"]
          limit = "  emptyDir limit: #{bytes_label(item["sizeLimitBytes"])}" if item["sizeLimitBytes"]
          lines << "  #{item["name"]}  #{storage}#{" (#{detail})" if detail}: #{bytes_label(item["usedBytes"])}#{limit}"
        end
        lines.join("\n")
      end

      def self.ranking_text(pods)
        return "No Pods found." if pods.empty?

        rows = pods.map do |entry|
          pod = entry.fetch("pod")
          ["#{pod["namespace"]}/#{pod["name"]}", entry["nodeName"] || "unassigned", total_label(entry)]
        end
        ([%w[POD NODE] + ["EPHEMERAL STORAGE"]] + rows).map { |row| row.join("\t") }.join("\n")
      end

      def self.total_label(report)
        reason = NO_SAMPLE_REASONS[report["status"]]
        "#{bytes_label(report["ephemeralStorageUsedBytes"])}#{" (#{reason})" if reason}"
      end

      def self.read_node(client, node, uids)
        raise Client::Error, "Kubernetes API returned an invalid Pod node name" unless valid_node?(node)

        summary = client.get("/api/v1/nodes/#{node}/proxy/stats/summary")
        raise Client::Error, "kubelet returned an invalid stats summary" unless summary.is_a?(Hash)

        wanted = uids.to_h { |uid| [uid, true] }
        Array(summary["pods"]).each_with_object({}) do |item, samples|
          uid = item.dig("podRef", "uid")
          samples[uid] ||= item if wanted.key?(uid)
        end
      end

      def self.valid_node?(node) = Schema::KubernetesValidator.dns1123_subdomain_messages(node).empty?
      def self.bytes_label(value) = value.nil? ? "unknown" : "#{value} B"
      private_class_method :ranking_text, :total_label, :read_node, :valid_node?, :bytes_label

      attr_reader :node_name, :uid

      def initialize(pod, details: true)
        @metadata = pod.fetch("metadata", {}).slice("name", "namespace", "uid")
        spec = pod.fetch("spec", {})
        @spec = spec if details
        @node_name = spec["nodeName"]
        @node_name = nil if @node_name == ""
        @uid = @metadata["uid"]
      end

      def measurable? = @node_name && !@uid.to_s.empty?

      def report(sample)
        total(sample).merge("containers" => containers(sample&.fetch("containers", nil)), "volumes" => volumes(sample&.fetch("volume", nil)))
      end

      def total(sample)
        {"pod" => @metadata, "nodeName" => @node_name, "status" => sample_status(sample),
         "ephemeralStorageUsedBytes" => used_bytes(sample&.fetch("ephemeral-storage", nil))}
      end

      private

      def sample_status(sample)
        return "notScheduled" unless @node_name
        return "missingUID" if @uid.to_s.empty?

        sample ? "sampled" : "noSample"
      end

      def containers(samples)
        measured = by_name(samples)
        declared = CONTAINER_LISTS.flat_map { |field| Array(@spec[field]) }.map { |item| item.fetch("name") }
        (declared | measured.keys).map do |name|
          item = measured.fetch(name, {})
          {"name" => name, "writableLayerUsedBytes" => used_bytes(item["rootfs"]), "logsUsedBytes" => used_bytes(item["logs"])}
        end
      end

      def volumes(samples)
        measured = by_name(samples)
        declared = by_name(@spec["volumes"])
        (declared.keys | measured.keys).map do |name|
          spec = declared.fetch(name, {})
          source = (spec.keys - ["name"]).first
          metric = measured.fetch(name, {})
          claim = metric.dig("pvcRef", "name") || spec.dig("persistentVolumeClaim", "claimName")
          claim ||= "#{@metadata["name"]}-#{name}" if source == "ephemeral"
          volume = {"name" => name, "storage" => volume_storage(source, spec, claim), "usedBytes" => used_bytes(metric)}
          volume["source"] = source if source
          volume["claimName"] = claim if claim
          if (limit = spec.dig("emptyDir", "sizeLimit"))
            bytes = Schema::Quantity.from_json(limit).value.ceil
            volume["sizeLimitBytes"] = bytes if bytes.positive?
          end
          volume
        end
      end

      def volume_storage(source, spec, claim)
        return "pvc" if claim || %w[persistentVolumeClaim ephemeral].include?(source)

        case source
        when "emptyDir"
          medium = spec.dig("emptyDir", "medium").to_s
          return "disk" if medium.empty?
          return "ram" if medium == "Memory" || medium.start_with?("HugePages")
        when "configMap", "gitRepo"
          return "disk"
        when "secret", "projected", "downwardAPI"
          return "ram"
        end
        "unknown"
      end

      def by_name(items) = Array(items).to_h { |item| [item.fetch("name"), item] }

      def used_bytes(stats)
        value = stats && stats["usedBytes"]
        value if value.is_a?(Integer) && value >= 0
      end
    end
  end
end
