# frozen_string_literal: true

require "json"
require "time"
require_relative "storage"

module Rubernetes
  module MetricsServer
    # metrics-server pkg/api (v0.8.0): metrics.k8s.io/v1beta1 NodeMetrics and
    # PodMetrics, get and list only, answered from the storage for the Nodes
    # and Pods that exist now (label selectors pass to the list, field
    # selectors match metadata.name/metadata.namespace), sorted by
    # namespace/name.  A Table is served for `kubectl get`.
    class API
      GROUP = "metrics.k8s.io"
      VERSION = "v1beta1"
      GROUP_VERSION = "#{GROUP}/#{VERSION}".freeze
      TABLE = /as=Table/

      RESOURCES = [
        {"name" => "nodes", "singularName" => "", "namespaced" => false, "kind" => "NodeMetrics", "verbs" => %w[get list]},
        {"name" => "pods", "singularName" => "", "namespaced" => true, "kind" => "PodMetrics", "verbs" => %w[get list]}
      ].freeze

      # lister: #nodes(label_selector:) and #pods(namespace:, label_selector:)
      # returning API objects (metadata is what is used), and #node(name) /
      # #pod(namespace, name) returning one or nil.
      def initialize(storage:, lister:, clock: -> { Time.now.utc })
        @storage = storage
        @lister = lister
        @clock = clock
      end

      # [status, headers, body]
      def call(method, path, query, accept: nil)
        return error(405, "MethodNotAllowed", "the server does not allow this method on the requested resource") unless %w[GET HEAD].include?(method)

        case path
        when "/apis" then json(200, group_list)
        when "/apis/#{GROUP}", "/apis/#{GROUP}/" then json(200, group)
        when "/apis/#{GROUP_VERSION}", "/apis/#{GROUP_VERSION}/" then json(200, resource_list)
        when %r{\A/apis/#{Regexp.escape(GROUP_VERSION)}/nodes/?\z}
          respond(node_list(query), accept, :node)
        when %r{\A/apis/#{Regexp.escape(GROUP_VERSION)}/nodes/([^/]+)\z}
          node_get(Regexp.last_match(1), accept)
        when %r{\A/apis/#{Regexp.escape(GROUP_VERSION)}/pods/?\z}
          respond(pod_list(nil, query), accept, :pod)
        when %r{\A/apis/#{Regexp.escape(GROUP_VERSION)}/namespaces/([^/]+)/pods/?\z}
          respond(pod_list(Regexp.last_match(1), query), accept, :pod)
        when %r{\A/apis/#{Regexp.escape(GROUP_VERSION)}/namespaces/([^/]+)/pods/([^/]+)\z}
          pod_get(Regexp.last_match(1), Regexp.last_match(2), accept)
        else
          error(404, "NotFound", "the server could not find the requested resource")
        end
      rescue ArgumentError => failure
        error(400, "BadRequest", failure.message)
      end

      def group_list
        {"kind" => "APIGroupList", "apiVersion" => "v1", "groups" => [group]}
      end

      def group
        version = {"groupVersion" => GROUP_VERSION, "version" => VERSION}
        {"kind" => "APIGroup", "apiVersion" => "v1", "name" => GROUP, "versions" => [version], "preferredVersion" => version}
      end

      def resource_list
        {"kind" => "APIResourceList", "apiVersion" => "v1", "groupVersion" => GROUP_VERSION, "resources" => RESOURCES}
      end

      # --------------------------------------------------------------- nodes

      def node_list(query)
        nodes = @lister.nodes(label_selector: query["labelSelector"])
        nodes = field_filter(nodes, query["fieldSelector"], namespaced: false)
        items = nodes.filter_map { |node| node_metrics(node) }.sort_by { |item| item.dig("metadata", "name") }
        {"kind" => "NodeMetricsList", "apiVersion" => GROUP_VERSION, "metadata" => {}, "items" => items}
      end

      def node_get(name, accept)
        node = @lister.node(name)
        return not_found("nodes", name) if node.nil?

        metrics = node_metrics(node)
        return not_found("nodes", name) if metrics.nil?

        respond(metrics, accept, :node)
      end

      def node_metrics(node)
        name = node.dig("metadata", "name").to_s
        usage = @storage.node_usage(name)
        return nil if usage.nil?

        {"kind" => "NodeMetrics", "apiVersion" => GROUP_VERSION,
         "metadata" => metadata(name, nil, node.dig("metadata", "labels")),
         "timestamp" => rfc3339(usage.timestamp), "window" => API.go_duration(usage.window),
         "usage" => {"cpu" => usage.cpu, "memory" => usage.memory}}
      end

      # ---------------------------------------------------------------- pods

      def pod_list(namespace, query)
        pods = @lister.pods(namespace: namespace, label_selector: query["labelSelector"])
        pods = field_filter(pods, query["fieldSelector"], namespaced: true)
        items = pods.filter_map { |pod| pod_metrics(pod) }
                    .sort_by { |item| [item.dig("metadata", "namespace"), item.dig("metadata", "name")] }
        {"kind" => "PodMetricsList", "apiVersion" => GROUP_VERSION, "metadata" => {}, "items" => items}
      end

      def pod_get(namespace, name, accept)
        pod = @lister.pod(namespace, name)
        return error(404, "NotFound", %(pods "#{namespace}/#{name}" not found), details: {"name" => "#{namespace}/#{name}", "kind" => "pods"}) if pod.nil?

        metrics = pod_metrics(pod)
        return not_found("pods", "#{namespace}/#{name}") if metrics.nil?

        respond(metrics, accept, :pod)
      end

      def pod_metrics(pod)
        namespace = pod.dig("metadata", "namespace").to_s
        name = pod.dig("metadata", "name").to_s
        usage = @storage.pod_usage(namespace, name)
        return nil if usage.nil?

        containers, earliest = usage
        {"kind" => "PodMetrics", "apiVersion" => GROUP_VERSION,
         "metadata" => metadata(name, namespace, pod.dig("metadata", "labels")),
         "timestamp" => earliest ? rfc3339(earliest.timestamp) : nil, "window" => API.go_duration(earliest ? earliest.window : 0),
         "containers" => containers.map { |container, value| {"name" => container, "usage" => {"cpu" => value.cpu, "memory" => value.memory}} }}
      end

      # --------------------------------------------------------------- shape

      def metadata(name, namespace, labels)
        value = {"name" => name}
        value["namespace"] = namespace if namespace
        value["creationTimestamp"] = rfc3339(@clock.call)
        value["labels"] = labels if labels.is_a?(Hash) && !labels.empty?
        value
      end

      # generic.AddObjectMetaFieldsSet: metadata.name (and metadata.namespace),
      # with fields.ParseSelector's =, == and != requirements.
      def field_filter(objects, selector, namespaced:)
        return objects if selector.to_s.strip.empty?

        requirements = selector.to_s.split(",").map(&:strip).reject(&:empty?).map do |part|
          match = /\A([^=!]+?)\s*(==|=|!=)\s*(.*)\z/.match(part)
          raise ArgumentError, %(invalid field selector: #{part.inspect}) unless match

          field = match[1].strip
          allowed = namespaced ? %w[metadata.name metadata.namespace] : %w[metadata.name]
          raise ArgumentError, %(field label not supported: #{field}) unless allowed.include?(field)

          [field, match[2] == "!=", match[3].strip]
        end
        objects.select do |object|
          requirements.all? do |field, negated, value|
            actual = object.dig("metadata", field.delete_prefix("metadata.")).to_s
            negated ? actual != value : actual == value
          end
        end
      end

      def respond(object, accept, kind)
        return json(200, object) unless accept.to_s.match?(TABLE)

        json(200, table(object, kind))
      end

      # addNodeMetricsToTable / addPodMetricsToTable (meta.k8s.io/v1beta1).
      def table(object, kind)
        items = object["items"] || [object]
        rows = items.map do |item|
          usage = kind == :node ? item["usage"] : sum_containers(item["containers"])
          [item, usage]
        end
        names = rows.empty? ? [] : rows.first.last.keys.sort
        columns = [{"name" => "Name", "type" => "string", "format" => "name", "description" => "Name of the resource", "priority" => 0}]
        names.each { |name| columns << {"name" => name, "type" => "string", "format" => "quantity", "description" => "", "priority" => 0} }
        columns << {"name" => "Window", "type" => "string", "format" => "duration", "description" => "", "priority" => 0}
        {"kind" => "Table", "apiVersion" => "meta.k8s.io/v1beta1", "metadata" => {},
         "columnDefinitions" => rows.empty? ? nil : columns,
         "rows" => rows.map do |item, usage|
           {"cells" => [item.dig("metadata", "name")] + names.map { |name| usage[name] } + [item["window"]], "object" => item}
         end}
      end

      def sum_containers(containers)
        totals = Hash.new(0r)
        Array(containers).each do |container|
          container["usage"].each { |name, value| totals[name] += Schema::Quantity.from_json(value).value }
        end
        totals.transform_values do |value|
          Schema::Quantity.new(value).to_s
        end
      end

      def not_found(resource, name)
        error(404, "NotFound", %(#{resource}.#{GROUP} "#{name}" not found), details: {"name" => name, "group" => GROUP, "kind" => resource})
      end

      def error(code, reason, message, details: nil)
        status = {"kind" => "Status", "apiVersion" => "v1", "metadata" => {}, "status" => "Failure", "message" => message,
                  "reason" => reason, "code" => code}
        status["details"] = details if details
        json(code, status)
      end

      def json(code, body) = [code, {"content-type" => "application/json"}, JSON.generate(body)]

      def rfc3339(time) = time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      # time.Duration.String().
      def self.go_duration(seconds)
        nanos = seconds.is_a?(Float) ? (seconds * 1e9).round : (Rational(seconds) * 1_000_000_000).to_i
        return "0s" if nanos.zero?

        sign = nanos.negative? ? "-" : ""
        u = nanos.abs
        if u < 1_000_000_000
          unit, divisor = if u < 1_000 then ["ns", 1]
                          elsif u < 1_000_000 then ["µs", 1_000]
                          else ["ms", 1_000_000]
                          end
          return "#{sign}#{fraction(u, divisor)}#{unit}"
        end
        text = "#{fraction(u % 60_000_000_000, 1_000_000_000)}s"
        minutes = u / 60_000_000_000
        if minutes.positive?
          text = "#{minutes % 60}m#{text}"
          hours = minutes / 60
          text = "#{hours}h#{text}" if hours.positive?
        end
        "#{sign}#{text}"
      end

      def self.fraction(value, divisor)
        whole = value / divisor
        rest = value % divisor
        return whole.to_s if rest.zero?

        digits = divisor.to_s.length - 1
        "#{whole}.#{rest.to_s.rjust(digits, "0").sub(/0+\z/, "")}"
      end
    end
  end
end
