# frozen_string_literal: true

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "../schema"

module Rubernetes
  module Controller
    # Resolves a CrossVersionObjectReference through the same GVK -> GVR
    # boundary used by the API server.  The controller never pluralizes an
    # arbitrary kind itself: unknown kinds must come from discovery (or an
    # explicitly registered mapping) before a scale request is attempted.
    class RESTMapper
      attr_reader :schema_registry

      def initialize(schema_registry: nil, mappings: {})
        @schema_registry = schema_registry
        @mappings = normalize_mappings(mappings)
      end

      def resolve(reference)
        api_version = Support.value(reference, "apiVersion", nil) ||
                      Support.value(reference, "api_version", nil)
        kind = Support.value(reference, "kind", nil).to_s
        raise ArgumentError, "HPA scaleTargetRef.kind is required" if kind.empty?

        group, version = ResourceDescriptor.split_api_version(api_version)
        mapped = @mappings[[group, version, kind]]
        return descriptor_for(mapped, fallback_kind: kind) if mapped

        discovered = discover(group: group, version: version, kind: kind)
        return descriptor_for(discovered, fallback_kind: kind) if discovered

        return ResourceDescriptor.parse(kind) if (api_version.nil? || api_version.to_s.empty?) && ResourceDescriptor::KNOWN.key?(kind)

        # ResourceDescriptor::KNOWN is the production bootstrap's pinned
        # discovery snapshot.  A custom kind is accepted only when a real
        # schema registry supplied it above.
        raise UnknownGVKError, "HPA scale target #{group}/#{version}/#{kind} is not discoverable" unless ResourceDescriptor::KNOWN.key?(kind)

        descriptor = ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => kind})
        raise UnknownGVKError, "HPA scale target #{group}/#{version}/#{kind} is not served" unless descriptor.group == group && descriptor.version == version

        descriptor
      end

      alias resource_for resolve
      alias resolve_target resolve

      private

      def normalize_mappings(mappings)
        Array(mappings).to_h do |key, value|
          parts = if key.is_a?(Array)
                    key
                  else
                    text = key.to_s
                    text.split("/", 3)
                  end
          raise ArgumentError, "RESTMapper mapping key must be group/version/kind" unless parts.length == 3

          [parts.map(&:to_s), value]
        end
      end

      def discover(group:, version:, kind:)
        return nil unless schema_registry

        candidate = if schema_registry.respond_to?(:find_gvk)
                      schema_registry.find_gvk(group: group, version: version, kind: kind)
                    elsif schema_registry.respond_to?(:resource_for_gvk)
                      schema_registry.resource_for_gvk(group: group, version: version, kind: kind)
                    elsif schema_registry.respond_to?(:resolve)
                      schema_registry.resolve(group: group, version: version, kind: kind)
                    end
        return candidate unless candidate && schema_registry.respond_to?(:resources)

        # The generated schema catalog indexes GVK and GVR separately.  Its
        # GVK entry is deliberately protocol-only, so join it to the served
        # resource entry without guessing a plural resource name.
        Array(schema_registry.resources).find do |resource|
          resource.respond_to?(:gvk) && resource.gvk == candidate.gvk
        end || candidate
      end

      def descriptor_for(value, fallback_kind:)
        return value if value.is_a?(ResourceDescriptor)
        return nil if value.nil?

        if value.respond_to?(:gvr) && value.respond_to?(:gvk)
          group, version, kind = gvk_parts(value.gvk)
          resource = value.gvr.respond_to?(:resource) ? value.gvr.resource : value.gvr[2]
          scope = value.respond_to?(:scope) ? value.scope : :namespaced
          return ResourceDescriptor.parse({"apiVersion" => group.empty? ? version : "#{group}/#{version}",
                                           "kind" => kind}, resource: resource, scope: scope)
        end
        if value.respond_to?(:gvk) && value.respond_to?(:resource)
          group, version, kind = gvk_parts(value.gvk)
          scope = value.respond_to?(:scope) ? value.scope : :namespaced
          return ResourceDescriptor.parse({"apiVersion" => group.empty? ? version : "#{group}/#{version}",
                                           "kind" => kind}, resource: value.resource, scope: scope)
        end
        return ResourceDescriptor.parse(value, scope: value[:scope] || value["scope"]) if value.is_a?(Hash) && value.key?("kind")

        if value.is_a?(Hash)
          api_version = Support.value(value, "apiVersion", nil) || Support.value(value, "api_version", nil)
          kind = Support.value(value, "kind", fallback_kind)
          resource = Support.value(value, "resource", nil)
          scope = Support.value(value, "scope", nil)
          return ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => kind}, resource: resource, scope: scope)
        end

        ResourceDescriptor.parse(value)
      end

      def gvk_parts(gvk)
        if gvk.respond_to?(:group) && gvk.respond_to?(:version) && gvk.respond_to?(:kind)
          [gvk.group.to_s, gvk.version.to_s, gvk.kind.to_s]
        else
          Array(gvk).then { |parts| [parts[0].to_s, parts[1].to_s, parts[2].to_s] }
        end
      end
    end

    # Immutable view of the autoscaling/v1 Scale subresource.  The target
    # object is retained so the planner can emit one optimistic update through
    # StoreAdapter; no scale client method mutates the store during planning.
    ScaleSnapshot = Struct.new(:descriptor, :target, :replicas, :resource_version,
                               :status_replicas, keyword_init: true) do
      def initialize(descriptor:, target:, replicas:, resource_version: nil, status_replicas: nil)
        super(descriptor: descriptor, target: Support.immutable_copy(target), replicas: Integer(replicas),
              resource_version: resource_version&.to_s, status_replicas: status_replicas)
        freeze
      end
    end

    # Production scale client backed by the controller's API/store boundary.
    # It intentionally exposes get_scale and build_update rather than a
    # callback so resourceVersion and UID fencing remain in the normal apply
    # path.
    class ScaleClient
      attr_reader :adapter

      def initialize(store: nil, adapter: nil)
        @adapter = adapter || if store.is_a?(StoreAdapter)
                                store
                              elsif store
                                StoreAdapter.new(store)
                              end
      end

      def get_scale(descriptor:, name:, namespace:)
        raise StoreError, "HPA scale client requires an API store" unless adapter

        target = adapter.find(descriptor, name: name, namespace: namespace)
        raise StoreError, "scale target #{descriptor.identifier}/#{name} was not found" unless target

        snapshot_for(target, descriptor: descriptor)
      end

      def snapshot_for(target, descriptor: ResourceDescriptor.parse(target))
        raise ArgumentError, "HPA scale client requires a scale target" unless target

        spec = Support.spec(target)
        status = Support.status(target)
        replicas = Support.value(spec, "replicas", nil)
        replicas = Support.value(Support.value(target, "scale", {}), "spec", {})["replicas"] if replicas.nil?
        raise ArgumentError, "scale target #{descriptor.identifier}/#{Support.name(target)} does not expose spec.replicas" if replicas.nil?

        ScaleSnapshot.new(
          descriptor: descriptor,
          target: target,
          replicas: Support.integer(replicas, 0),
          resource_version: Support.value(Support.metadata(target), "resourceVersion", nil),
          status_replicas: Support.value(status, "replicas", nil)
        )
      end

      def build_update(snapshot, replicas)
        candidate = Support.deep_copy(snapshot.target)
        candidate["spec"] ||= {}
        if Support.value(candidate["spec"], "replicas", nil).nil? && candidate["scale"].is_a?(Hash)
          candidate["scale"]["spec"] ||= {}
          candidate["scale"]["spec"]["replicas"] = Integer(replicas)
        else
          candidate["spec"]["replicas"] = Integer(replicas)
        end
        candidate
      end
    end

    # pkg/controller/podautoscaler/metrics: the resource metrics API
    # (metrics.k8s.io PodMetrics), the custom metrics API
    # (custom.metrics.k8s.io/v1beta2) and the external metrics API
    # (external.metrics.k8s.io/v1beta1), through the API client.  Each
    # method returns [value(s), timestamp] or raises MetricsError.
    class MetricsClient
      class MetricsError < StandardError; end

      PodMetric = Struct.new(:value, :timestamp, :window, keyword_init: true)

      def initialize(client: nil)
        @client = client
      end

      # GetResourceMetric: {pod => PodMetric} in milli-units.
      def resource_metric(resource, namespace, selector, container)
        list = fetch("/apis/metrics.k8s.io/v1beta1/namespaces/#{namespace}/pods", labelSelector: selector)
        items = Array(list && list["items"])
        raise MetricsError, "no metrics returned from resource metrics API" if items.empty?

        metrics = {}
        items.each do |item|
          name = Support.name(item)
          timestamp = Support.parse_time(item["timestamp"])
          window = duration_seconds(item["window"])
          containers = Array(item["containers"])
          if container.to_s.empty?
            next if containers.empty?

            sum = 0
            missing = false
            containers.each do |entry|
              value = (entry["usage"] || {})[resource]
              if value.nil?
                missing = true
                break
              end
              sum += milli(value)
            end
            metrics[name] = PodMetric.new(value: sum, timestamp: timestamp, window: window) unless missing
          else
            entry = containers.find { |candidate| candidate["name"] == container }
            value = entry && (entry["usage"] || {})[resource]
            metrics[name] = PodMetric.new(value: milli(value), timestamp: timestamp, window: window) if value
          end
        end
        [metrics, Support.parse_time(items.first["timestamp"])]
      end

      # GetRawMetric: a pods metric.
      def raw_metric(metric_name, namespace, selector, metric_selector)
        list = fetch("/apis/custom.metrics.k8s.io/v1beta2/namespaces/#{namespace}/pods/*/#{metric_name}",
                     labelSelector: selector, metricLabelSelector: metric_selector)
        items = Array(list && list["items"])
        raise MetricsError, "no metrics returned from custom metrics API" if items.empty?

        metrics = items.to_h do |item|
          [Support.value(item["describedObject"] || {}, "name", ""),
           PodMetric.new(value: milli(item["value"]), timestamp: Support.parse_time(item["timestamp"]),
                         window: Float(item["windowSeconds"] || 60))]
        end
        [metrics, Support.parse_time(items.first["timestamp"])]
      end

      # GetObjectMetric.
      def object_metric(metric_name, namespace, object_reference, metric_selector)
        resource = ResourceDescriptor.parse({"apiVersion" => object_reference["apiVersion"], "kind" => object_reference["kind"]})
        group = resource.group.to_s.empty? ? "" : "#{resource.group}/"
        path = if resource.cluster_scoped?
                 "/apis/custom.metrics.k8s.io/v1beta2/#{resource.resource}.#{group.chomp("/")}/#{object_reference["name"]}/#{metric_name}".sub(
                   ".//", "/"
                 )
               else
                 "/apis/custom.metrics.k8s.io/v1beta2/namespaces/#{namespace}/#{[resource.resource, resource.group].reject do |part|
                   part.to_s.empty?
                 end.join(".")}/#{object_reference["name"]}/#{metric_name}"
               end
        list = fetch(path, metricLabelSelector: metric_selector)
        item = Array(list && list["items"]).first
        raise MetricsError, "no metrics returned from custom metrics API" unless item

        [milli(item["value"]), Support.parse_time(item["timestamp"])]
      end

      # GetExternalMetric: the values in milli-units.
      def external_metric(metric_name, namespace, selector)
        list = fetch("/apis/external.metrics.k8s.io/v1beta1/namespaces/#{namespace}/#{metric_name}", labelSelector: selector)
        items = Array(list && list["items"])
        raise MetricsError, "no metrics returned from external metrics API" if items.empty?

        [items.map { |item| milli(item["value"]) }, Support.parse_time(items.first["timestamp"])]
      end

      private

      def fetch(path, **query)
        raise MetricsError, "unable to fetch metrics from resource metrics API: no API client" if @client.nil?

        query = query.reject { |_, value| value.nil? || value.to_s.empty? }
        @client.get(path, query: query.empty? ? nil : query)
      rescue MetricsError
        raise
      rescue StandardError => error
        raise MetricsError, "unable to fetch metrics from resource metrics API: #{error.message}"
      end

      def milli(value) = (Schema::Quantity.from_json(value).value * 1000).ceil

      def duration_seconds(value)
        text = value.to_s
        return 0.0 if text.empty?

        text.scan(/(\d+(?:\.\d+)?)(h|ms|m|s)/).sum do |amount, unit|
          Float(amount) * {"h" => 3600, "m" => 60, "s" => 1, "ms" => 0.001}.fetch(unit)
        end
      end
    end

    # pkg/controller/podautoscaler/replica_calculator.go.
    class ReplicaCalculator
      Tolerances = Struct.new(:scale_down, :scale_up) do
        def within?(ratio) = ratio.between?(1.0 - scale_down, 1.0 + scale_up)
      end

      def initialize(metrics_client:, pods:, clock:, cpu_initialization_period: 300, delay_of_initial_readiness_status: 30)
        @metrics = metrics_client
        @pods = pods
        @clock = clock
        @cpu_initialization_period = cpu_initialization_period
        @initial_readiness_delay = delay_of_initial_readiness_status
      end

      # GetResourceReplicas: [replicas, utilization, raw average, timestamp].
      def resource_replicas(current, target_utilization, resource, tolerances, namespace, selector, container)
        begin
          metrics, timestamp = @metrics.resource_metric(resource, namespace, selector_string(selector), container)
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError, "unable to get metrics for resource #{resource}: #{error.message}"
        end
        pods = pods_for(namespace, selector)
        raise MetricsClient::MetricsError, "no pods returned by selector while calculating replica count" if pods.empty?

        ready, unready, missing, ignored = group_pods(pods, metrics, resource)
        (ignored + unready).each { |name| metrics.delete(name) }
        raise MetricsClient::MetricsError, "did not receive metrics for targeted pods (pods might be unready)" if metrics.empty?

        requests = calculate_requests(pods, container, resource)
        ratio, utilization, raw = utilization_ratio(metrics, requests, target_utilization)
        scale_up_with_unready = !unready.empty? && ratio > 1.0
        if !scale_up_with_unready && missing.empty?
          return [current, utilization, raw, timestamp] if tolerances.within?(ratio)

          return [(ratio * ready).ceil, utilization, raw, timestamp]
        end

        unless missing.empty?
          if ratio < 1.0
            fallback = [100, target_utilization].max
            missing.each { |name| metrics[name] = MetricsClient::PodMetric.new(value: requests[name].to_i * fallback / 100) }
          elsif ratio > 1.0
            missing.each { |name| metrics[name] = MetricsClient::PodMetric.new(value: 0) }
          end
        end
        unready.each { |name| metrics[name] = MetricsClient::PodMetric.new(value: 0) } if scale_up_with_unready
        new_ratio, = utilization_ratio(metrics, requests, target_utilization)
        return [current, utilization, raw, timestamp] if tolerances.within?(new_ratio) || (ratio < 1.0 && new_ratio > 1.0) || (ratio > 1.0 && new_ratio < 1.0)

        replicas = (new_ratio * metrics.length).ceil
        return [current, utilization, raw, timestamp] if (new_ratio < 1.0 && replicas > current) || (new_ratio > 1.0 && replicas < current)

        [replicas, utilization, raw, timestamp]
      end

      # GetRawResourceReplicas: [replicas, raw usage, timestamp].
      def raw_resource_replicas(current, target_usage, resource, tolerances, namespace, selector, container)
        begin
          metrics, timestamp = @metrics.resource_metric(resource, namespace, selector_string(selector), container)
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError, "unable to get metrics for resource #{resource}: #{error.message}"
        end
        replicas, usage = plain_metric_replicas(metrics, current, target_usage, tolerances, namespace, selector, resource)
        [replicas, usage, timestamp]
      end

      # GetMetricReplicas.
      def metric_replicas(current, target_usage, metric_name, tolerances, namespace, selector, metric_selector)
        begin
          metrics, timestamp = @metrics.raw_metric(metric_name, namespace, selector_string(selector), metric_selector)
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError, "unable to get metric #{metric_name}: #{error.message}"
        end
        replicas, usage = plain_metric_replicas(metrics, current, target_usage, tolerances, namespace, selector, "")
        [replicas, usage, timestamp]
      end

      # GetObjectMetricReplicas.
      def object_metric_replicas(current, target_usage, metric_name, tolerances, namespace, object_reference, selector, metric_selector)
        begin
          usage, timestamp = @metrics.object_metric(metric_name, namespace, object_reference, metric_selector)
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError, "unable to get metric #{metric_name}: #{error.message} on #{object_reference["kind"]} " \
                                             "#{namespace}/#{object_reference["name"]}"
        end
        replicas = usage_ratio_replica_count(current, usage.to_f / target_usage, tolerances, namespace, selector)
        [replicas, usage, timestamp]
      end

      # GetObjectPerPodMetricReplicas.
      def object_per_pod_metric_replicas(status_replicas, target_average, metric_name, tolerances, namespace, object_reference,
                                         metric_selector)
        begin
          usage, timestamp = @metrics.object_metric(metric_name, namespace, object_reference, metric_selector)
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError, "unable to get metric #{metric_name}: #{error.message} on #{object_reference["kind"]} " \
                                             "#{namespace}/#{object_reference["name"]}"
        end
        replicas = status_replicas
        ratio = usage.to_f / (target_average.to_f * replicas)
        replicas = (usage.to_f / target_average).ceil unless tolerances.within?(ratio)
        [replicas, (usage.to_f / status_replicas).ceil, timestamp]
      end

      # GetExternalMetricReplicas.
      def external_metric_replicas(current, target_usage, metric_name, tolerances, namespace, metric_selector, selector)
        begin
          values, timestamp = @metrics.external_metric(metric_name, namespace, Support.selector_string(metric_selector))
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError,
                "unable to get external metric #{namespace}/#{metric_name}/#{metric_selector.inspect}: #{error.message}"
        end
        usage = values.sum
        replicas = usage_ratio_replica_count(current, usage.to_f / target_usage, tolerances, namespace, selector)
        [replicas, usage, timestamp]
      end

      # GetExternalPerPodMetricReplicas.
      def external_per_pod_metric_replicas(status_replicas, target_per_pod, metric_name, tolerances, namespace, metric_selector)
        begin
          values, timestamp = @metrics.external_metric(metric_name, namespace, Support.selector_string(metric_selector))
        rescue MetricsClient::MetricsError => error
          raise MetricsClient::MetricsError,
                "unable to get external metric #{namespace}/#{metric_name}/#{metric_selector.inspect}: #{error.message}"
        end
        usage = values.sum
        replicas = status_replicas
        ratio = usage.to_f / (target_per_pod.to_f * replicas)
        replicas = (usage.to_f / target_per_pod).ceil unless tolerances.within?(ratio)
        [replicas, (usage.to_f / status_replicas).ceil, timestamp]
      end

      private

      def plain_metric_replicas(metrics, current, target_usage, tolerances, namespace, selector, resource)
        pods = pods_for(namespace, selector)
        raise MetricsClient::MetricsError, "no pods returned by selector while calculating replica count" if pods.empty?

        ready, unready, missing, ignored = group_pods(pods, metrics, resource)
        (ignored + unready).each { |name| metrics.delete(name) }
        raise MetricsClient::MetricsError, "did not receive metrics for targeted pods (pods might be unready)" if metrics.empty?

        ratio, usage = usage_ratio(metrics, target_usage)
        scale_up_with_unready = !unready.empty? && ratio > 1.0
        if !scale_up_with_unready && missing.empty?
          return [current, usage] if tolerances.within?(ratio)

          return [(ratio * ready).ceil, usage]
        end

        unless missing.empty?
          if ratio < 1.0
            missing.each { |name| metrics[name] = MetricsClient::PodMetric.new(value: target_usage) }
          elsif ratio > 1.0
            missing.each { |name| metrics[name] = MetricsClient::PodMetric.new(value: 0) }
          end
        end
        unready.each { |name| metrics[name] = MetricsClient::PodMetric.new(value: 0) } if scale_up_with_unready
        new_ratio, = usage_ratio(metrics, target_usage)
        return [current, usage] if tolerances.within?(new_ratio) || (ratio < 1.0 && new_ratio > 1.0) || (ratio > 1.0 && new_ratio < 1.0)

        replicas = (new_ratio * metrics.length).ceil
        return [current, usage] if (new_ratio < 1.0 && replicas > current) || (new_ratio > 1.0 && replicas < current)

        [replicas, usage]
      end

      def usage_ratio_replica_count(current, ratio, tolerances, namespace, selector)
        return ratio.ceil if current.zero?
        return current if tolerances.within?(ratio)

        pods = pods_for(namespace, selector)
        if pods.empty?
          raise MetricsClient::MetricsError,
                "unable to calculate ready pods: no pods returned by selector while calculating replica count"
        end

        ready = pods.count { |pod| Support.value(Support.status(pod), "phase", "") == "Running" && Support.ready?(pod) }
        [(ratio * ready).ceil, (2**31) - 1].min
      end

      # GetResourceUtilizationRatio.
      def utilization_ratio(metrics, requests, target)
        total = 0
        request_total = 0
        entries = 0
        metrics.each do |name, metric|
          next unless requests.key?(name)

          total += metric.value
          request_total += requests[name]
          entries += 1
        end
        raise MetricsClient::MetricsError, "no metrics returned matched known pods" if request_total.zero?

        utilization = (total * 100) / request_total
        [utilization.to_f / target, utilization, total / entries]
      end

      def usage_ratio(metrics, target)
        usage = metrics.values.sum(&:value) / metrics.length
        [usage.to_f / target, usage]
      end

      # groupPods.
      def group_pods(pods, metrics, resource)
        ready = 0
        unready = []
        missing = []
        ignored = []
        now = @clock.call
        pods.each do |pod|
          name = Support.name(pod)
          phase = Support.value(Support.status(pod), "phase", "").to_s
          if !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil? || phase == "Failed"
            ignored << name
            next
          end
          if phase == "Pending"
            unready << name
            next
          end
          metric = metrics[name]
          if metric.nil?
            missing << name
            next
          end
          if resource.to_s == "cpu"
            condition = Array(Support.value(Support.status(pod), "conditions", [])).find { |entry| entry["type"] == "Ready" }
            started = Support.parse_time(Support.value(Support.status(pod), "startTime", nil))
            not_ready = if condition.nil? || started.nil?
                          true
                        else
                          transition = Support.parse_time(condition["lastTransitionTime"]) || started
                          if started + @cpu_initialization_period > now
                            condition["status"] == "False" || (metric.timestamp && metric.timestamp < transition + metric.window.to_f)
                          else
                            condition["status"] == "False" && started + @initial_readiness_delay > transition
                          end
                        end
            if not_ready
              unready << name
              next
            end
          end
          ready += 1
        end
        [ready, unready, missing, ignored]
      end

      # calculateRequests: per Pod, milli-units.
      def calculate_requests(pods, container, resource)
        pods.to_h do |pod|
          spec = Support.spec(pod)
          pod_requests = Support.value(Support.value(spec, "resources", {}) || {}, "requests", {}) || {}
          if container.to_s.empty? && !pod_requests.empty?
            value = pod_requests[resource]
            raise MetricsClient::MetricsError, "missing pod-level request for #{resource} in Pod #{Support.name(pod)}" if value.nil?

            next [Support.name(pod), (Schema::Quantity.from_json(value).value * 1000).ceil]
          end

          containers = Array(spec["containers"]) + Array(spec["initContainers"]).select { |entry| entry["restartPolicy"] == "Always" }
          total = 0
          found = false
          containers.each do |entry|
            if container.to_s.empty? || container == entry["name"]
              value = (Support.value(entry["resources"] || {}, "requests", {}) || {})[resource]
              if value.nil?
                raise MetricsClient::MetricsError,
                      "missing request for #{resource} in container #{entry["name"]} of Pod #{Support.name(pod)}"
              end

              total += (Schema::Quantity.from_json(value).value * 1000).ceil
            end
            if container == entry["name"]
              found = true
              break
            end
          end
          if !container.to_s.empty? && !found
            raise MetricsClient::MetricsError,
                  "container #{container} not found in Pod #{Support.name(pod)}"
          end

          [Support.name(pod), total]
        end
      end

      def pods_for(namespace, selector)
        Array(@pods.call(namespace)).select { |pod| Support.selector_matches?(selector, pod) }
      end

      def selector_string(selector) = Support.selector_string(selector)
    end

    # pkg/controller/podautoscaler/horizontal.go.
    class HorizontalPodAutoscalerController < BaseController
      HPA = ResourceDescriptor.parse("HorizontalPodAutoscaler")
      POD = ResourceDescriptor.parse("Pod")
      SYNC_PERIOD = 15.0
      DOWNSCALE_STABILIZATION_WINDOW = 300
      TOLERANCE = 0.1
      SCALE_UP_LIMIT_FACTOR = 2.0
      SCALE_UP_LIMIT_MINIMUM = 4

      include SecondarySupport

      attr_reader :rest_mapper, :scale_client, :metrics_client

      def initialize(store: nil, rest_mapper: nil, scale_client: nil, metrics_client: nil, schema_registry: nil,
                     clock: -> { Time.now.utc }, **)
        schema_registry ||= if store.respond_to?(:schema_registry)
                              store.schema_registry
                            elsif store.respond_to?(:registry)
                              store.registry
                            end
        @rest_mapper = rest_mapper || RESTMapper.new(schema_registry: schema_registry)
        @scale_client = scale_client
        @metrics_client = metrics_client
        @clock = clock
        @mutex = Mutex.new
        @recommendations = {}
        @scale_up_events = {}
        @scale_down_events = {}
        @selectors = {}
        super(store: store, **)
      end

      def plan(hpa, store: nil, pods: nil, metrics_client: nil, scale_client: nil, **_options)
        adapter = adapter_for(store)
        key = "#{Support.namespace(hpa)}/#{Support.name(hpa)}"
        context = {events: [], operations: [], hpa: Support.deep_copy(hpa)}
        context[:hpa]["status"] ||= {}
        client = scale_client || @scale_client || ScaleClient.new(adapter: adapter)
        metrics = metrics_client || @metrics_client || MetricsClient.new(client: adapter.respond_to?(:client) ? adapter.client : nil)
        pods_source = if pods
                        ->(namespace) { Array(pods).select { |pod| Support.namespace(pod) == namespace } }
                      else
                        lambda { |namespace|
                          list_for(adapter, POD, namespace: namespace)
                        }
                      end
        calculator = ReplicaCalculator.new(metrics_client: metrics, pods: pods_source, clock: @clock)
        observe_hpa(key)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        context[:monitor] = {action: "none", error: "none"}
        reconcile(context, key, client, calculator, pods_source)
        # monitor.ObserveReconciliationResult.
        monitor = context[:monitor]
        labels = {"action" => monitor[:action], "error" => monitor[:error]}
        ControllerMetrics.increment("horizontal_pod_autoscaler_controller_reconciliations_total", labels)
        ControllerMetrics.observe("horizontal_pod_autoscaler_controller_reconciliation_duration_seconds",
                                  Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
        original = Support.status(hpa)
        status = context[:hpa]["status"]
        if status != original
          context[:operations] << operation_status(hpa, status, descriptor: HPA,
                                                                reason: "horizontal pod autoscaler status")
        end
        ReconcileResult.new(operations: context[:operations].compact, status: status, events: once_per_state(key, context[:events]), controller: name,
                            key: key, requeue_after: SYNC_PERIOD)
      end

      # monitor.ObserveHPAAddition / ObserveHPADeletion: the HPAs this
      # controller manager knows of (the process's, across instances).
      HPA_KEYS = Set.new
      HPA_KEYS_MUTEX = Mutex.new

      def observe_hpa(key)
        size = HPA_KEYS_MUTEX.synchronize { HPA_KEYS.add?(key) ? HPA_KEYS.size : nil }
        ControllerMetrics.set("horizontal_pod_autoscaler_controller_num_horizontal_pod_autoscalers", size) if size
      end

      def orphan_cleanup? = true

      def plan_orphans(key, store: nil)
        size = HPA_KEYS_MUTEX.synchronize { HPA_KEYS.delete?(key.to_s) ? HPA_KEYS.size : nil }
        ControllerMetrics.set("horizontal_pod_autoscaler_controller_num_horizontal_pod_autoscalers", size) if size
        nil
      end

      private

      # reconcileAutoscaler.
      def reconcile(context, key, client, calculator, pods_source)
        hpa = context[:hpa]
        spec = Support.spec(hpa)
        reference = Support.value(spec, "scaleTargetRef", {}) || {}
        descriptor = begin
          @rest_mapper.resolve(reference)
        rescue UnknownGVKError, ArgumentError => error
          # An API version that does not parse is the spec's fault (errSpec).
          context[:monitor][:error] = error.is_a?(ArgumentError) ? "spec" : "internal"
          return failed_get_scale(context, error.message)
        end
        snapshot = begin
          client.get_scale(descriptor: descriptor, name: Support.value(reference, "name", "").to_s, namespace: Support.namespace(hpa))
        rescue StoreError, ArgumentError => error
          context[:monitor][:error] = "internal"
          return failed_get_scale(context, error.message)
        end
        set_condition(hpa, "AbleToScale", "True", "SucceededGetScale", "the HPA controller was able to get the target's current scale")
        current = snapshot.replicas
        record_initial_recommendation(current, key)
        min_replicas = Support.integer(Support.value(spec, "minReplicas", 1), 1)
        max_replicas = Support.integer(Support.value(spec, "maxReplicas", min_replicas), min_replicas)
        desired = 0
        rescale_reason = ""
        rescale = true
        statuses = []
        needs_metrics = true
        if current.zero?
          needs_metrics = false
          desired = 0
          rescale = false
          set_condition(hpa, "ScalingActive", "False", "ScalingDisabled",
                        "scaling is disabled since the replica count of the target is zero")
          remove_condition(hpa, "ScaledToZero")
        elsif current > max_replicas
          rescale_reason = "Current number of replicas above Spec.MaxReplicas"
          desired = max_replicas
          needs_metrics = false
        elsif current < min_replicas
          rescale_reason = "Current number of replicas below Spec.MinReplicas"
          desired = min_replicas
          needs_metrics = false
        end

        if needs_metrics
          metric_desired, metric_name, statuses, error = compute_replicas_for_metrics(context, snapshot, calculator, pods_source, key)
          if error && metric_desired == -1
            set_status(hpa, current, Support.integer(Support.value(Support.status(hpa), "desiredReplicas", 0), 0), statuses, false)
            event(context, "Warning", "FailedComputeMetricsReplicas", error)
            context[:monitor][:error] = "internal"
            return
          end

          rescale_metric = ""
          if metric_desired > desired
            desired = metric_desired
            rescale_metric = metric_name
          end
          rescale_reason = "#{rescale_metric} above target" if desired > current
          rescale_reason = "All metrics below target" if desired < current
          desired = if spec["behavior"].nil?
                      normalize_desired_replicas(hpa, key, current, desired, min_replicas, max_replicas)
                    else
                      normalize_with_behaviors(hpa, key, current, desired, min_replicas, max_replicas)
                    end
          rescale = desired != current
        end

        if rescale
          update = operation_update(snapshot.target, client.build_update(snapshot, desired), descriptor: snapshot.descriptor,
                                                                                             reason: "horizontal pod autoscaler rescale")
          context[:operations] << update
          set_condition(hpa, "AbleToScale", "True", "SucceededRescale",
                        "the HPA controller was able to update the target scale to #{desired}")
          event(context, "Normal", "SuccessfulRescale", "New size: #{desired}; reason: #{rescale_reason}")
          store_scale_event(spec["behavior"], key, current, desired)
          remove_condition(hpa, "ScaledToZero")
          context[:monitor][:action] = desired > current ? "scale_up" : "scale_down"
        else
          desired = current
        end
        set_status(hpa, current, desired, statuses, rescale)
        # monitor.ObserveDesiredReplicas.
        ControllerMetrics.set("horizontal_pod_autoscaler_controller_desired_replicas", desired,
                              {"namespace" => Support.namespace(hpa).to_s, "hpa_name" => Support.name(hpa).to_s})
      end

      def failed_get_scale(context, message)
        event(context, "Warning", "FailedGetScale", message)
        set_condition(context[:hpa], "AbleToScale", "False", "FailedGetScale",
                      "the HPA controller was unable to get the target's current scale: #{message}")
      end

      # computeReplicasForMetrics: [replicas | -1, metric name, statuses, error].
      def compute_replicas_for_metrics(context, snapshot, calculator, pods_source, key)
        hpa = context[:hpa]
        selector = scale_selector(snapshot.target)
        if selector.nil?
          event(context, "Warning", "SelectorRequired", "selector is required")
          set_condition(hpa, "ScalingActive", "False", "InvalidSelector", "the HPA target's scale is missing a selector")
          return [-1, "", [], "selector is required"]
        end
        if (ambiguous = ambiguous_selector(hpa, key, selector, pods_source))
          event(context, "Warning", "AmbiguousSelector", ambiguous)
          set_condition(hpa, "ScalingActive", "False", "AmbiguousSelector", ambiguous)
          return [-1, "", [], ambiguous]
        end

        spec_replicas = snapshot.replicas
        status_replicas = Support.integer(snapshot.status_replicas, 0)
        metrics = Array(Support.value(Support.spec(hpa), "metrics", []))
        statuses = Array.new(metrics.length) { {"type" => ""} }
        replicas = 0
        metric = ""
        invalid = 0
        first_error = nil
        first_condition = nil
        metrics.each_with_index do |spec, index|
          proposal, proposal_name, status, condition, error = compute_replicas_for_metric(context, spec, spec_replicas, status_replicas,
                                                                                          selector, calculator)
          if error
            if invalid.zero?
              first_condition = condition
              first_error = error
            end
            invalid += 1
            next
          end
          statuses[index] = status
          if replicas.zero? || proposal > replicas
            replicas = proposal
            metric = proposal_name
          end
        end
        error = first_error && "invalid metrics (#{invalid} invalid out of #{metrics.length}), first error is: #{first_error}"
        if invalid >= metrics.length || (invalid.positive? && replicas < spec_replicas)
          set_condition(hpa, *first_condition) if first_condition
          return [-1, "", statuses, error]
        end

        set_condition(hpa, "ScalingActive", "True", "ValidMetricFound",
                      "the HPA was able to successfully calculate a replica count from #{metric}")
        [replicas, metric, statuses, error]
      end

      # computeReplicasForMetric: [replicas, name, status, condition, error].
      # monitor.ObserveMetricComputationResult around computeReplicasForMetric.
      def compute_replicas_for_metric(context, spec, spec_replicas, status_replicas, selector, calculator)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = compute_one_metric(context, spec, spec_replicas, status_replicas, selector, calculator)
        proposal, _name, _status, _condition, error = result
        current = Support.integer(Support.value(Support.status(context[:hpa]), "currentReplicas", 0), 0)
        action = if error then "none"
                 elsif proposal.to_i > current then "scale_up"
                 elsif proposal.to_i < current then "scale_down"
                 else "none"
                 end
        error_label = if error.nil? then "none"
                      elsif error.to_s.start_with?("unknown metric source type") then "spec"
                      else "internal"
                      end
        labels = {"action" => action, "error" => error_label, "metric_type" => spec["type"].to_s}
        ControllerMetrics.increment("horizontal_pod_autoscaler_controller_metric_computation_total", labels)
        ControllerMetrics.observe("horizontal_pod_autoscaler_controller_metric_computation_duration_seconds",
                                  Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, labels)
        result
      end

      def compute_one_metric(context, spec, spec_replicas, status_replicas, selector, calculator)
        hpa = context[:hpa]
        namespace = Support.namespace(hpa)
        tolerances = tolerances_for(hpa)
        case spec["type"].to_s
        when "Resource", "ContainerResource"
          container_type = spec["type"] == "ContainerResource"
          source = container_type ? spec["containerResource"] : spec["resource"]
          reason = container_type ? "FailedGetContainerResourceMetric" : "FailedGetResourceMetric"
          resource = source["name"].to_s
          container = container_type ? source["container"].to_s : ""
          target = source["target"] || {}
          begin
            if !target["averageValue"].nil?
              replicas, raw, = calculator.raw_resource_replicas(spec_replicas, milli(target["averageValue"]), resource, tolerances, namespace,
                                                                selector, container)
              current = {"averageValue" => quantity(resource, raw)}
              name = "#{resource} resource"
            elsif !target["averageUtilization"].nil?
              replicas, utilization, raw, = calculator.resource_replicas(spec_replicas, Integer(target["averageUtilization"]), resource, tolerances,
                                                                         namespace, selector, container)
              current = {"averageUtilization" => utilization, "averageValue" => quantity(resource, raw)}
              name = if container_type
                       "#{resource} container resource utilization (percentage of request)"
                     else
                       "#{resource} resource utilization (percentage " \
                         "of request)"
                     end
            else
              raise MetricsClient::MetricsError,
                    "invalid resource metric source: neither an average utilization target nor an average value (usage) target was set"
            end
          rescue MetricsClient::MetricsError => error
            detail = if !target["averageValue"].nil? then "failed to get #{resource} usage: #{error.message}"
                     elsif !target["averageUtilization"].nil? then "failed to get #{resource} utilization: #{error.message}"
                     else error.message
                     end
            label = if container_type
                      "failed to get #{source["container"]} container metric value: #{detail}"
                    else
                      "failed to get #{resource} resource metric " \
                        "value: #{detail}"
                    end
            return [0, "", nil, unable_condition(context, reason, detail), label]
          end
          status = if container_type
                     {"type" => "ContainerResource",
                      "containerResource" => {"name" => resource, "container" => container, "current" => current}}
                   else
                     {"type" => "Resource", "resource" => {"name" => resource, "current" => current}}
                   end
          [replicas, name, status, nil, nil]
        when "Pods"
          source = spec["pods"]
          begin
            replicas, usage, = calculator.metric_replicas(spec_replicas, milli(source.dig("target", "averageValue")), source.dig("metric", "name").to_s,
                                                          tolerances, namespace, selector, Support.selector_string(source.dig("metric", "selector")))
          rescue MetricsClient::MetricsError => error
            return [0, "", nil, unable_condition(context, "FailedGetPodsMetric", error.message),
                    "failed to get pods metric value: #{error.message}"]
          end
          [replicas, "pods metric #{source.dig("metric", "name")}",
           {"type" => "Pods", "pods" => {"metric" => source["metric"], "current" => {"averageValue" => decimal_milli(usage)}}}, nil, nil]
        when "Object"
          source = spec["object"]
          target = source["target"] || {}
          metric_selector = Support.selector_string(source.dig("metric", "selector"))
          begin
            if target["type"] == "Value" && !target["value"].nil?
              replicas, usage, = calculator.object_metric_replicas(spec_replicas, milli(target["value"]), source.dig("metric", "name").to_s, tolerances,
                                                                   namespace, source["describedObject"], selector, metric_selector)
              current = {"value" => decimal_milli(usage)}
              name = "#{source.dig("describedObject", "kind")} metric #{source.dig("metric", "name")}"
            elsif target["type"] == "AverageValue" && !target["averageValue"].nil?
              replicas, usage, = calculator.object_per_pod_metric_replicas(status_replicas, milli(target["averageValue"]), source.dig("metric", "name").to_s,
                                                                           tolerances, namespace, source["describedObject"], metric_selector)
              current = {"averageValue" => decimal_milli(usage)}
              name = "external metric #{source.dig("metric", "name")}(#{selector_text(source.dig("metric", "selector"))})"
            else
              raise MetricsClient::MetricsError, "invalid object metric source: neither a value target nor an average value target was set"
            end
          rescue MetricsClient::MetricsError => error
            return [0, "", nil, unable_condition(context, "FailedGetObjectMetric", error.message),
                    "failed to get object metric value: #{error.message}"]
          end
          [replicas, name,
           {"type" => "Object", "object" => {"describedObject" => source["describedObject"], "metric" => source["metric"], "current" => current}},
           nil, nil]
        when "External"
          source = spec["external"]
          target = source["target"] || {}
          metric = source["metric"] || {}
          begin
            if !target["averageValue"].nil?
              replicas, usage, = calculator.external_per_pod_metric_replicas(status_replicas, milli(target["averageValue"]), metric["name"].to_s, tolerances,
                                                                             namespace, metric["selector"])
              current = {"averageValue" => decimal_milli(usage)}
            elsif !target["value"].nil?
              replicas, usage, = calculator.external_metric_replicas(spec_replicas, milli(target["value"]), metric["name"].to_s, tolerances, namespace,
                                                                     metric["selector"], selector)
              current = {"value" => decimal_milli(usage)}
            else
              raise MetricsClient::MetricsError,
                    "invalid external metric source: neither a value target nor an average value target was set"
            end
          rescue MetricsClient::MetricsError => error
            return [0, "", nil, unable_condition(context, "FailedGetExternalMetric", error.message),
                    "failed to get #{metric["name"]} external metric value: #{error.message}"]
          end
          [replicas, "external metric #{metric["name"]}(#{selector_text(metric["selector"])})",
           {"type" => "External", "external" => {"metric" => metric, "current" => current}}, nil, nil]
        else
          message = "unknown metric source type #{spec["type"].to_s.dump}"
          [0, "", nil, unable_condition(context, "InvalidMetricSourceType", message), message]
        end
      end

      def unable_condition(context, reason, message)
        event(context, "Warning", reason, message)
        ["ScalingActive", "False", reason, "the HPA was unable to compute the replica count: #{message}"]
      end

      # The Scale subresource's status.selector.
      def scale_selector(target)
        selector = Support.value(Support.spec(target), "selector", nil)
        selector = Support.value(Support.status(target), "selector", nil) if selector.nil?
        return nil if selector.nil? || selector == {} || selector == ""
        return selector if selector.is_a?(String)
        return {"matchLabels" => selector} if Support.kind(target) == "ReplicationController"

        selector
      end

      # validateAndParseSelector: Pods selected by more than one HPA.
      def ambiguous_selector(hpa, key, selector, pods_source)
        @mutex.synchronize { @selectors[key] = [Support.namespace(hpa), selector] }
        pods = Array(pods_source.call(Support.namespace(hpa))).select { |pod| Support.selector_matches?(selector, pod) }
        others = @mutex.synchronize { @selectors.reject { |other, _| other == key }.to_a }
        controlling = others.select do |_, (namespace, other_selector)|
          namespace == Support.namespace(hpa) && pods.any? { |pod| Support.selector_matches?(other_selector, pod) }
        end
        return nil if controlling.empty?

        names = ([key] + controlling.map(&:first)).sort.map do |entry|
          namespace, hpa_name = entry.split("/", 2)
          "#{namespace}/#{hpa_name}"
        end
        "pods by selector #{Support.selector_string(selector)} are controlled by multiple HPAs: [#{names.join(" ")}]"
      end

      def tolerances_for(hpa)
        up = TOLERANCE
        down = TOLERANCE
        behavior = Support.value(Support.spec(hpa), "behavior", nil)
        if behavior
          down = Schema::Quantity.from_json(behavior.dig("scaleDown", "tolerance")).value.to_f unless behavior.dig("scaleDown",
                                                                                                                   "tolerance").nil?
          up = Schema::Quantity.from_json(behavior.dig("scaleUp", "tolerance")).value.to_f unless behavior.dig("scaleUp", "tolerance").nil?
        end
        ReplicaCalculator::Tolerances.new(down, up)
      end

      def record_initial_recommendation(current, key)
        @mutex.synchronize { @recommendations[key] ||= [[current, @clock.call]] }
      end

      # stabilizeRecommendation (no behavior): the highest recommendation
      # of the downscale window.
      def normalize_desired_replicas(hpa, key, current, desired, min_replicas, max_replicas)
        stabilized = @mutex.synchronize do
          highest = desired
          old_index = nil
          cutoff = @clock.call - DOWNSCALE_STABILIZATION_WINDOW
          @recommendations[key].each_with_index do |(value, time), index|
            if time < cutoff
              old_index = index
            elsif value > highest
              highest = value
            end
          end
          old_index ? @recommendations[key][old_index] = [desired, @clock.call] : @recommendations[key] << [desired, @clock.call]
          highest
        end
        if stabilized == desired
          set_condition(hpa, "AbleToScale", "True", "ReadyForNewScale", "recommended size matches current size")
        else
          set_condition(hpa, "AbleToScale", "True", "ScaleDownStabilized",
                        "recent recommendations were higher than current one, applying the highest recent recommendation")
        end
        result, reason, message = convert_with_rules(current, stabilized, min_replicas, max_replicas)
        set_condition(hpa, "ScalingLimited", result == stabilized ? "False" : "True", reason, message)
        result
      end

      def convert_with_rules(current, desired, min_replicas, max_replicas)
        scale_up_limit = [SCALE_UP_LIMIT_FACTOR * current, SCALE_UP_LIMIT_MINIMUM].max.to_i
        if max_replicas > scale_up_limit
          maximum = scale_up_limit
          reason = "ScaleUpLimit"
          message = "the desired replica count is increasing faster than the maximum scale rate"
        else
          maximum = max_replicas
          reason = "TooManyReplicas"
          message = "the desired replica count is more than the maximum replica count"
        end
        if desired < min_replicas
          return [min_replicas, "TooFewReplicas",
                  "the desired replica count is less than the minimum replica count"]
        end
        return [maximum, reason, message] if desired > maximum

        [desired, "DesiredWithinRange", "the desired count is within the acceptable range"]
      end

      # normalizeDesiredReplicasWithBehaviors.
      def normalize_with_behaviors(hpa, key, current, desired, min_replicas, max_replicas)
        behavior = hpa["spec"]["behavior"]
        scale_up = behavior["scaleUp"] || {}
        scale_down = behavior["scaleDown"] || {}
        down_window = scale_down.fetch("stabilizationWindowSeconds", DOWNSCALE_STABILIZATION_WINDOW) || DOWNSCALE_STABILIZATION_WINDOW
        up_window = scale_up.fetch("stabilizationWindowSeconds", 0) || 0
        stabilized, reason, message = @mutex.synchronize do
          now = @clock.call
          up = desired
          down = desired
          old_index = nil
          @recommendations[key].each_with_index do |(value, time), index|
            up = [value, up].min if time > now - up_window
            down = [value, down].max if time > now - down_window
            old_index = index if time < now - up_window && time < now - down_window
          end
          recommendation = [[current, up].max, down].min
          old_index ? @recommendations[key][old_index] = [desired, now] : @recommendations[key] << [desired, now]
          if desired >= current
            [recommendation, "ScaleUpStabilized",
             "recent recommendations were lower than current one, applying the lowest recent recommendation"]
          else
            [recommendation, "ScaleDownStabilized",
             "recent recommendations were higher than current one, applying the highest recent recommendation"]
          end
        end
        if stabilized == desired
          set_condition(hpa, "AbleToScale", "True", "ReadyForNewScale", "recommended size matches current size")
        else
          set_condition(hpa, "AbleToScale", "True", reason, message)
        end
        result, limit_reason, limit_message = convert_with_behavior_rate(key, current, stabilized, min_replicas, max_replicas, scale_up,
                                                                         scale_down)
        set_condition(hpa, "ScalingLimited", result == stabilized ? "False" : "True", limit_reason, limit_message)
        result
      end

      def convert_with_behavior_rate(key, current, desired, min_replicas, max_replicas, scale_up, scale_down)
        ups, downs = @mutex.synchronize { [Array(@scale_up_events[key]).dup, Array(@scale_down_events[key]).dup] }
        if desired > current
          limit = [scale_limit(:up, current, ups, downs, scale_up), current].max
          if max_replicas > limit
            maximum = limit
            reason = "ScaleUpLimit"
            message = "the desired replica count is increasing faster than the maximum scale rate"
          else
            maximum = max_replicas
            reason = "TooManyReplicas"
            message = "the desired replica count is more than the maximum replica count"
          end
          return [maximum, reason, message] if desired > maximum
        elsif desired < current
          limit = [scale_limit(:down, current, ups, downs, scale_down), current].min
          if min_replicas < limit
            minimum = limit
            reason = "ScaleDownLimit"
            message = "the desired replica count is decreasing faster than the maximum scale rate"
          else
            minimum = min_replicas
            reason = "TooFewReplicas"
            message = "the desired replica count is less than the minimum replica count"
          end
          return [minimum, reason, message] if desired < minimum
        end
        [desired, "DesiredWithinRange", "the desired count is within the acceptable range"]
      end

      # calculateScaleUpLimitWithScalingRules / calculateScaleDownLimitWithBehaviors.
      def scale_limit(direction, current, ups, downs, rules)
        select = rules.fetch("selectPolicy", "Max") || "Max"
        return current if select == "Disabled"

        minimum_change = select == "Min"
        results = Array(rules["policies"]).map do |policy|
          period = Integer(policy["periodSeconds"])
          added = replicas_change(period, ups)
          deleted = replicas_change(period, downs)
          start = current - added + deleted
          value = Integer(policy["value"])
          if direction == :up
            policy["type"] == "Pods" ? start + value : (start * (1 + (value / 100.0))).ceil
          else
            policy["type"] == "Pods" ? start - value : (start * (1 - (value / 100.0))).to_i
          end
        end
        return current if results.empty?

        if direction == :up
          minimum_change ? results.min : results.max
        else
          minimum_change ? results.max : results.min
        end
      end

      def replicas_change(period, events)
        cutoff = @clock.call - period
        events.sum { |change, time, _| time > cutoff ? change : 0 }
      end

      # storeScaleEvent.
      def store_scale_event(behavior, key, previous, replicas)
        return if behavior.nil?

        direction = replicas > previous ? @scale_up_events : @scale_down_events
        rules = replicas > previous ? (behavior["scaleUp"] || {}) : (behavior["scaleDown"] || {})
        longest = Array(rules["policies"]).map { |policy| Integer(policy["periodSeconds"]) }.max || 0
        change = (replicas - previous).abs
        @mutex.synchronize do
          events = (direction[key] ||= [])
          cutoff = @clock.call - longest
          events.each { |event| event[2] = true if event[1] < cutoff }
          old = events.rindex { |event| event[2] }
          entry = [change, @clock.call, false]
          old ? events[old] = entry : events << entry
        end
      end

      # setStatus.
      def set_status(hpa, current, desired, statuses, rescale)
        status = hpa["status"]
        updated = {"currentReplicas" => current, "desiredReplicas" => desired}
        updated["lastScaleTime"] = status["lastScaleTime"] if status["lastScaleTime"]
        updated["lastScaleTime"] = @clock.call.utc.strftime("%Y-%m-%dT%H:%M:%SZ") if rescale
        # CurrentMetrics: one entry per metric spec, empty for a metric that
        # could not be computed.
        updated["currentMetrics"] = statuses unless statuses.nil? || statuses.empty?
        updated["conditions"] = status["conditions"] if status["conditions"]
        observed = Support.value(Support.metadata(hpa), "generation", nil)
        updated["observedGeneration"] = observed unless observed.nil?
        hpa["status"] = updated
      end

      # setConditionInList.
      def set_condition(hpa, type, status, reason, message)
        conditions = (hpa["status"]["conditions"] ||= [])
        existing = conditions.find { |condition| condition["type"] == type }
        unless existing
          existing = {"type" => type}
          conditions << existing
        end
        existing["lastTransitionTime"] = @clock.call.utc.strftime("%Y-%m-%dT%H:%M:%SZ") if existing["status"] != status
        existing["status"] = status
        existing["reason"] = reason
        existing["message"] = message
        existing
      end

      def remove_condition(hpa, type)
        conditions = hpa["status"]["conditions"]
        conditions&.reject! { |condition| condition["type"] == type }
      end

      def event(context, type, reason, message)
        context[:events] << {"type" => type, "reason" => reason, "message" => message}
      end

      def milli(value) = (Schema::Quantity.from_json(value).value * 1000).ceil

      # resource.NewMilliQuantity(raw, DecimalSI|BinarySI).String().
      def quantity(resource, raw)
        Schema::Quantity.new(Rational(raw, 1000), resource == "memory" ? :binary_si : :decimal_si).to_s
      end

      def decimal_milli(raw) = Schema::Quantity.new(Rational(raw, 1000), :decimal_si).to_s

      # %+v of a *metav1.LabelSelector.
      def selector_text(selector)
        return "nil" if selector.nil?

        labels = (selector["matchLabels"] || {}).sort.map { |key, value| "#{key}: #{value}," }.join
        "&LabelSelector{MatchLabels:map[string]string{#{labels}},MatchExpressions:[]LabelSelectorRequirement{},}"
      end
    end
  end
end
