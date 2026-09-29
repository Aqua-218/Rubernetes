# frozen_string_literal: true

require_relative "../observability/metrics"

module Rubernetes
  module Scheduler
    # pkg/scheduler/metrics/resources: kube-scheduler's /metrics/resources,
    # the requests and limits of every Pod the scheduler knows that has not
    # finished, one sample per Pod, resource and (for a Pod with a node) the
    # node it runs on.  As upstream's podResourceCollector: init containers
    # count with the maximum of their requests against the sum of the app
    # containers'; Pod-level resources (PodLevelResources) win when set;
    # the unit label is "cores" for cpu, "bytes" for memory, storage and
    # hugepages, "integer" for anything else; a Pod without a node has an
    # empty node label; scheduler and priority come from the Pod spec.
    module ResourceMetrics
      REQUEST = "kube_pod_resource_request"
      LIMIT = "kube_pod_resource_limit"
      HELP = {
        REQUEST => "Resources requested by workloads on the cluster, broken down by pod. This shows the resource usage the scheduler and kubelet expect per pod for resources along with the unit for the resource if any.",
        LIMIT => "Resources limit for workloads on the cluster, broken down by pod. This shows the resource usage the scheduler and kubelet expect per pod for resources along with the unit for the resource if any."
      }.freeze
      TERMINAL_PHASES = %w[Succeeded Failed].freeze

      module_function

      def render(pods)
        requests = []
        limits = []
        Array(pods).each do |pod|
          object = pod.respond_to?(:to_h) ? pod.to_h : pod
          next unless object.is_a?(Hash)

          phase = object.dig("status", "phase").to_s
          next if TERMINAL_PHASES.include?(phase)

          base = pod_labels(object)
          totals(object, "requests").each { |resource, value| requests << [base, resource, value] }
          totals(object, "limits").each { |resource, value| limits << [base, resource, value] }
        end
        family(REQUEST, requests) + family(LIMIT, limits)
      end

      def pod_labels(object)
        metadata = object["metadata"] || {}
        spec = object["spec"] || {}
        {"namespace" => metadata["namespace"].to_s, "pod" => metadata["name"].to_s,
         "node" => spec["nodeName"].to_s, "scheduler" => (spec["schedulerName"] || "default-scheduler").to_s,
         "priority" => spec["priority"].nil? ? "" : spec["priority"].to_s}
      end

      # resourcehelper.PodRequests / PodLimits without the pod-overhead and
      # in-place-resize refinements the scheduler's collector does not use.
      def totals(object, kind)
        spec = object["spec"] || {}
        pod_level = spec.dig("resources", kind)
        sums = Hash.new(0.0)
        Array(spec["containers"]).each do |container|
          (container.dig("resources", kind) || {}).each { |resource, quantity| sums[resource.to_s] += parse_quantity(quantity) }
        end
        Array(spec["initContainers"]).each do |container|
          restart_always = container["restartPolicy"].to_s == "Always"
          (container.dig("resources", kind) || {}).each do |resource, quantity|
            value = parse_quantity(quantity)
            if restart_always
              sums[resource.to_s] += value
            else
              sums[resource.to_s] = value if value > sums[resource.to_s]
            end
          end
        end
        if pod_level.is_a?(Hash)
          pod_level.each { |resource, quantity| sums[resource.to_s] = parse_quantity(quantity) if %w[cpu memory].include?(resource.to_s) }
        end
        sums.sort.to_h
      end

      def unit_for(resource)
        case resource
        when "cpu" then "cores"
        when "memory", "ephemeral-storage", "storage" then "bytes"
        else resource.start_with?("hugepages-") ? "bytes" : "integer"
        end
      end

      SUFFIXES = {"n" => 1e-9, "u" => 1e-6, "m" => 1e-3, "" => 1.0, "k" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12, "P" => 1e15, "E" => 1e18,
                  "Ki" => 1024.0, "Mi" => 1024.0**2, "Gi" => 1024.0**3, "Ti" => 1024.0**4, "Pi" => 1024.0**5, "Ei" => 1024.0**6}.freeze

      def parse_quantity(value)
        return value.to_f if value.is_a?(Numeric)

        text = value.to_s.strip
        match = /\A([+-]?[0-9]*\.?[0-9]+(?:[eE][+-]?[0-9]+)?)(n|u|m|k|M|G|T|P|E|Ki|Mi|Gi|Ti|Pi|Ei)?\z/.match(text)
        return 0.0 unless match

        Float(match[1]) * SUFFIXES.fetch(match[2].to_s)
      end

      def family(name, rows)
        return "" if rows.empty?

        lines = ["# HELP #{name} [STABLE] #{HELP.fetch(name)}", "# TYPE #{name} gauge"]
        rows.each do |base, resource, value|
          labels = base.merge("resource" => resource, "unit" => unit_for(resource))
          rendered = labels.map { |key, item| "#{key}=\"#{escape(item)}\"" }.join(",")
          lines << "#{name}{#{rendered}} #{Observability::Metrics.go_float(value)}"
        end
        lines.join("\n") + "\n"
      end

      def escape(value) = value.to_s.gsub("\\", "\\\\\\\\").gsub("\"", "\\\"").gsub("\n", "\\n")
    end
  end
end
