# frozen_string_literal: true

require "time"
require_relative "../observability/metrics"

module Rubernetes
  module Node
    # pkg/kubelet/metrics/collectors/resource_metrics.go: /metrics/resource,
    # what metrics-server (and so HPA and `kubectl top`) scrapes, rendered
    # from the Summary API with each sample's own timestamp in milliseconds.
    module ResourceMetrics
      DESCRIPTORS = [
        ["node_cpu_usage_seconds_total", "counter", "STABLE", "Cumulative cpu time consumed by the node in core-seconds"],
        ["node_memory_working_set_bytes", "gauge", "STABLE", "Current working set of the node in bytes"],
        ["container_cpu_usage_seconds_total", "counter", "STABLE", "Cumulative cpu time consumed by the container in core-seconds"],
        ["container_memory_working_set_bytes", "gauge", "STABLE", "Current working set of the container in bytes"],
        ["container_start_time_seconds", "gauge", "STABLE", "Start time of the container since unix epoch in seconds"],
        ["pod_cpu_usage_seconds_total", "counter", "STABLE", "Cumulative cpu time consumed by the pod in core-seconds"],
        ["pod_memory_working_set_bytes", "gauge", "STABLE", "Current working set of the pod in bytes"],
        ["resource_scrape_error", "gauge", "STABLE", "1 if there was an error while getting container metrics, 0 otherwise"]
      ].freeze

      module_function

      def render(summary, scrape_error: false)
        samples = Hash.new { |hash, key| hash[key] = [] }
        node = summary.fetch("node", {})
        add_cpu(samples["node_cpu_usage_seconds_total"], node["cpu"], {})
        add_memory(samples["node_memory_working_set_bytes"], node["memory"], {})
        Array(summary["pods"]).each do |pod|
          ref = pod["podRef"] || {}
          labels = {"namespace" => ref["namespace"].to_s, "pod" => ref["name"].to_s}
          add_cpu(samples["pod_cpu_usage_seconds_total"], pod["cpu"], labels)
          add_memory(samples["pod_memory_working_set_bytes"], pod["memory"], labels)
          Array(pod["containers"]).each do |container|
            container_labels = {"container" => container["name"].to_s}.merge(labels)
            add_cpu(samples["container_cpu_usage_seconds_total"], container["cpu"], container_labels)
            add_memory(samples["container_memory_working_set_bytes"], container["memory"], container_labels)
            started = parse_time(container["startTime"])
            samples["container_start_time_seconds"] << [container_labels, started.to_f, (started.to_f * 1000).to_i] if started
          end
        end
        samples["resource_scrape_error"] << [{}, scrape_error ? 1 : 0, nil]
        DESCRIPTORS.filter_map do |name, type, stability, help|
          lines = samples[name]
          next if lines.empty?

          header = "# HELP #{name} [#{stability}] #{help}\n# TYPE #{name} #{type}\n"
          header + lines.map { |labels, value, timestamp| sample(name, labels, value, timestamp) }.join
        end.join
      end

      def add_cpu(list, cpu, labels)
        return unless cpu.is_a?(Hash) && cpu["usageCoreNanoSeconds"]

        list << [labels, cpu["usageCoreNanoSeconds"].to_f / 1e9, millis(cpu["time"])]
      end

      def add_memory(list, memory, labels)
        return unless memory.is_a?(Hash) && memory["workingSetBytes"]

        list << [labels, memory["workingSetBytes"].to_i, millis(memory["time"])]
      end

      def sample(name, labels, value, timestamp)
        label_text = labels.empty? ? "" : "{#{labels.map { |key, item| "#{key}=\"#{escape(item)}\"" }.join(",")}}"
        rendered = format_float(value)
        "#{name}#{label_text} #{rendered}#{timestamp ? " #{timestamp}" : ""}\n"
      end

      # expfmt writeFloat: every sample value is a float64 ("1.3950976e+07").
      def format_float(value) = Observability::Metrics.go_float(value.to_f)

      def millis(time)
        parsed = parse_time(time)
        parsed ? (parsed.to_f * 1000).to_i : nil
      end

      def parse_time(value)
        value.nil? ? nil : Time.parse(value.to_s)
      rescue ArgumentError
        nil
      end

      def escape(value) = value.to_s.gsub("\\", "\\\\\\\\").gsub("\"", "\\\"").gsub("\n", "\\n")
    end
  end
end

module Rubernetes
  module Node
    # /metrics/cadvisor: the container metrics kubelet's embedded cAdvisor
    # collector exports (cadvisor/metrics/prometheus.go), for the containers
    # and Pods of the Summary -- the same measurements /stats/summary gives,
    # under cAdvisor's names and labels (container, id, image, name,
    # namespace, pod; cpu="total" for the CPU counter), plus the machine
    # totals.  The Pod's own cgroup is the entry with an empty container.
    module CadvisorMetrics
      DESCRIPTORS = [
        ["machine_cpu_cores", "gauge", "Number of logical CPU cores."],
        ["machine_memory_bytes", "gauge", "Amount of memory installed on the machine."],
        ["container_cpu_usage_seconds_total", "counter", "Cumulative cpu time consumed in seconds."],
        ["container_memory_usage_bytes", "gauge", "Current memory usage in bytes, including all memory regardless of when it was accessed"],
        ["container_memory_working_set_bytes", "gauge", "Current working set in bytes."],
        ["container_memory_rss", "gauge", "Size of RSS in bytes."],
        ["container_memory_failures_total", "counter", "Cumulative count of memory allocation failures."],
        ["container_fs_usage_bytes", "gauge", "Number of bytes that are consumed by the container on this filesystem."],
        ["container_start_time_seconds", "gauge", "Start time of the container since unix epoch in seconds."],
        ["container_last_seen", "gauge", "Last time a container was seen by the exporter"]
      ].freeze

      module_function

      def render(summary, machine: {}, images: {})
        samples = Hash.new { |hash, key| hash[key] = [] }
        samples["machine_cpu_cores"] << [{}, machine[:cpu_cores]] if machine[:cpu_cores]
        samples["machine_memory_bytes"] << [{}, machine[:memory_bytes]] if machine[:memory_bytes]
        stamp = Time.now.to_f
        Array(summary["pods"]).each do |pod|
          ref = pod["podRef"] || {}
          pod_labels = {"namespace" => ref["namespace"].to_s, "pod" => ref["name"].to_s}
          pod_id = "/kubepods/pod#{ref["uid"]}"
          add_entry(samples, pod, {"container" => "", "id" => pod_id, "image" => "", "name" => ""}.merge(pod_labels), stamp)
          Array(pod["containers"]).each do |container|
            name = container["name"].to_s
            labels = {"container" => name, "id" => "#{pod_id}/#{name}", "image" => images.fetch([ref["uid"].to_s, name], "").to_s,
                      "name" => name}.merge(pod_labels)
            add_entry(samples, container, labels, stamp)
            started = ResourceMetrics.parse_time(container["startTime"])
            samples["container_start_time_seconds"] << [labels, started.to_f] if started
            rootfs = container["rootfs"]
            if rootfs.is_a?(Hash) && rootfs["usedBytes"]
              samples["container_fs_usage_bytes"] << [labels.merge("device" => "rootfs"), rootfs["usedBytes"].to_i]
            end
          end
        end
        DESCRIPTORS.filter_map do |name, type, help|
          lines = samples[name]
          next if lines.empty?

          "# HELP #{name} #{help}\n# TYPE #{name} #{type}\n" +
            lines.map { |labels, value| ResourceMetrics.sample(name, labels.sort.to_h, value, nil) }.join
        end.join
      end

      def add_entry(samples, entry, labels, stamp)
        cpu = entry["cpu"]
        if cpu.is_a?(Hash) && cpu["usageCoreNanoSeconds"]
          samples["container_cpu_usage_seconds_total"] << [labels.merge("cpu" => "total"), cpu["usageCoreNanoSeconds"].to_f / 1e9]
        end
        memory = entry["memory"]
        if memory.is_a?(Hash)
          samples["container_memory_usage_bytes"] << [labels, memory["usageBytes"].to_i] if memory["usageBytes"]
          samples["container_memory_working_set_bytes"] << [labels, memory["workingSetBytes"].to_i] if memory["workingSetBytes"]
          samples["container_memory_rss"] << [labels, memory["rssBytes"].to_i] if memory["rssBytes"]
          if memory["pageFaults"]
            samples["container_memory_failures_total"] << [labels.merge("failure_type" => "pgfault", "scope" => "container"), memory["pageFaults"].to_i]
          end
          if memory["majorPageFaults"]
            samples["container_memory_failures_total"] << [labels.merge("failure_type" => "pgmajfault", "scope" => "container"), memory["majorPageFaults"].to_i]
          end
        end
        samples["container_last_seen"] << [labels, stamp.floor]
      end
    end
  end
end
