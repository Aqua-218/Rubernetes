# frozen_string_literal: true

require "time"
require_relative "../runtime/cri/client"
require_relative "resource_metrics"

module Rubernetes
  module Node
    # Pod statistics and Prometheus metrics reported by CRI runtimes.
    class CRIStats
      FIELDS = {
        "cpu" => {"usage_core_nano_seconds" => "usageCoreNanoSeconds", "usage_nano_cores" => "usageNanoCores"},
        "memory" => {"working_set_bytes" => "workingSetBytes", "available_bytes" => "availableBytes", "usage_bytes" => "usageBytes",
                     "rss_bytes" => "rssBytes", "page_faults" => "pageFaults", "major_page_faults" => "majorPageFaults"},
        "swap" => {"swap_available_bytes" => "swapAvailableBytes", "swap_usage_bytes" => "swapUsageBytes"},
        "process" => {"process_count" => "process_count"},
        "writable_layer" => {"used_bytes" => "usedBytes", "inodes_used" => "inodesUsed"}
      }.freeze
      INTERFACE_FIELDS = {"rx_bytes" => "rxBytes", "rx_errors" => "rxErrors", "tx_bytes" => "txBytes", "tx_errors" => "txErrors"}.freeze
      METRIC_NAME = /\A[A-Za-z_:][A-Za-z0-9_:]*\z/
      LABEL_NAME = /\A[A-Za-z_][A-Za-z0-9_]*\z/
      METRIC_TYPES = {"COUNTER" => "counter", "GAUGE" => "gauge"}.freeze
      MACHINE_METRIC_NAMES = CadvisorMetrics::MACHINE_FAMILIES.map(&:first).freeze

      def initialize(clients, log_roots: {})
        @clients = clients.dup.freeze
        @log_roots = log_roots.dup.freeze
        @descriptors = {}
        @mutex = Mutex.new
      end

      def pod_samples(stamp = Time.now.utc.iso8601)
        @clients.each_with_object({}) do |client, samples|
          samples.merge!(samples_for(client, stamp))
        end
      end

      def metrics
        families = {}
        @clients.each do |client|
          descriptors = descriptors_for(client)
          next if descriptors.empty?

          response = client.runtime("ListPodSandboxMetrics")
          Array(response["pod_metrics"]).each do |pod|
            batches = [pod, *Array(pod["container_metrics"])]
            batches.each { |batch| Array(batch["metrics"]).each { |metric| add_metric(families, descriptors, metric) } }
          end
        rescue Runtime::CRI::Client::Error
          # Kubernetes continues exposing the other metrics if CRI fails.
          next
        end
        families.sort.map do |name, (type, help, samples)|
          "# HELP #{name} #{help}\n# TYPE #{name} #{type}\n#{samples.join}"
        end.join
      end

      private

      def samples_for(client, stamp)
        stats = client.runtime("ListPodSandboxStats", {"filter" => {}})
        Array(stats["stats"]).each_with_object({}) do |entry, samples|
          id = entry.dig("attributes", "id")
          linux = entry["linux"]
          samples[id] = pod_usage(linux, stamp).merge("logs_root" => @log_roots[client]) if id && linux
        end
      rescue Runtime::CRI::Client::Error => error
        raise unless error.code == Runtime::CRI::Client::UNIMPLEMENTED

        fallback_samples(client, stamp)
      end

      # Older runtimes still supply each container's writable layer through
      # ListContainerStats. Join by CRI ID before adding the local cgroup stats.
      def fallback_samples(client, stamp)
        containers = client.runtime("ListContainers", {"filter" => {}}).fetch("containers", [])
        owners = containers.to_h { |container| container.values_at("id", "pod_sandbox_id") }
        stats = client.runtime("ListContainerStats", {"filter" => {}}).fetch("stats", [])
        grouped = stats.group_by { |container| owners[container.dig("attributes", "id")] }
        grouped.reject { |sandbox, _| sandbox.nil? || sandbox.empty? }.transform_values do |items|
          samples = items.filter_map { |item| container_sample(item, stamp) }
          {"summary" => aggregate_cpu_memory(samples), "containers" => samples, "logs_root" => @log_roots[client], "cgroup_fallback" => true}
        end
      end

      def aggregate_cpu_memory(containers)
        %w[cpu memory].to_h do |field|
          stats = containers.filter_map { |container| container.dig("summary", field) }
          aggregate = FIELDS.fetch(field).values.to_h { |key| [key, stats.sum { |entry| entry[key].to_i }] }
          [field, stats.empty? ? nil : aggregate.merge("time" => stats.last["time"])]
        end.compact
      end

      def pod_usage(linux, stamp)
        pod = usage_fields(linux)
        pod["process_stats"] = usage(linux, "process")&.except("time")
        pod["network"] = network(linux["network"])
        pod["io"] = psi(linux["io"])
        containers = Array(linux["containers"]).filter_map { |container| container_sample(container, stamp) }
        {"summary" => pod.compact, "containers" => containers}
      end

      def container_sample(container, stamp)
        id = container.dig("attributes", "id")
        return if id.nil? || id.empty?

        summary = usage_fields(container)
        summary["cpu"] ||= {"time" => stamp, "usageCoreNanoSeconds" => 0, "usageNanoCores" => 0}
        summary["memory"] ||= {"time" => stamp, "workingSetBytes" => 0, "usageBytes" => 0, "rssBytes" => 0}
        summary["rootfs"] = usage(container, "writable_layer") || {"time" => nil}
        summary["io"] = psi(container["io"])
        {"id" => id, "name" => container.dig("attributes", "metadata", "name"), "summary" => summary.compact,
         "rootfs_mount" => container.dig("writable_layer", "fs_id", "mountpoint")}
      end

      def usage_fields(value)
        %w[cpu memory swap].to_h { |name| [name, usage(value, name)] }.compact
      end

      def usage(value, field)
        stats = value[field]
        return if stats.nil?

        convert_values(stats, FIELDS.fetch(field)).merge("time" => timestamp(stats["timestamp"]), "psi" => pressure(stats["psi"])).compact
      end

      def convert_values(stats, names)
        names.each_with_object({}) do |(wire_name, api_name), result|
          result[api_name] = number(stats.dig(wire_name, "value")) if stats[wire_name]
        end
      end

      def network(stats)
        return if stats.nil?

        primary = network_interface(stats["default_interface"]) if stats["default_interface"]
        interfaces = Array(stats["interfaces"]).map { |entry| network_interface(entry) }
        {"time" => timestamp(stats["timestamp"]), "interfaces" => [primary, *interfaces].compact}.merge(primary || {}).compact
      end

      def network_interface(stats)
        convert_values(stats, INTERFACE_FIELDS).merge("name" => stats["name"]).compact
      end

      def psi(stats)
        return if stats.nil?

        {"time" => timestamp(stats["timestamp"]), "psi" => pressure(stats["psi"])}.compact
      end

      def pressure(stats)
        return unless stats

        %w[full some].to_h do |field|
          entry = stats[field] || stats[field.capitalize]
          [field, entry&.transform_keys(&:downcase)&.transform_values { |value| value.is_a?(String) ? value.to_i : value }]
        end.compact
      end

      def number(value) = value && Integer(value)

      def timestamp(value)
        nanos = value.to_i
        Time.at(Rational(nanos, 1_000_000_000)).utc.iso8601(9) if nanos.positive?
      end

      def descriptors_for(client)
        @mutex.synchronize do
          @descriptors[client] ||= Array(client.runtime("ListMetricDescriptors")["descriptors"]).to_h { |item| [item["name"], item] }
        end
      end

      def add_metric(families, descriptors, metric)
        name = metric["name"].to_s
        descriptor = descriptors[name]
        type = METRIC_TYPES[metric["metric_type"]]
        return unless descriptor && type && METRIC_NAME.match?(name) && !MACHINE_METRIC_NAMES.include?(name)

        keys = Array(descriptor["label_keys"])
        values = Array(metric["label_values"])
        return unless keys.length == values.length && keys.uniq == keys && keys.all? { |key| LABEL_NAME.match?(key) }

        help = ResourceMetrics.escape(descriptor["help"].to_s)
        family = (families[name] ||= [type, help, []])
        return unless family[0] == type && family[1] == help

        milliseconds = metric["timestamp"].to_i / 1_000_000 if metric["timestamp"].to_i.positive?
        family[2] << ResourceMetrics.sample(name, keys.zip(values).sort.to_h, metric.dig("value", "value").to_i, milliseconds)
      end
    end
  end
end
