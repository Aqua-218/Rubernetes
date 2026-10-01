# frozen_string_literal: true

require "fileutils"

require "digest"
require "time"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Concrete infrastructure and storage controllers for the Kubernetes
    # v1.36.2 contract. Behavior is anchored to commit
    # 24e2b02af5543d7910c2bb074c7264df5a8f0467 and the upstream control-loop
    # boundaries in pkg/controller/nodelifecycle/taint_manager.go,
    # pkg/controller/volume/{persistentvolume,attachdetach,expand},
    # pkg/controller/clusterroleaggregation, and
    # staging/src/k8s.io/cloud-provider/controllers.
    module InfrastructureStorageSupport
      MANAGED_ROUTE_CONTROLLER = "rubernetes-node-route-controller"

      protected

      def normalize_time(value)
        parsed = Support.parse_time(value)
        raise ArgumentError, "clock must return Time or RFC3339 value" unless parsed

        parsed
      end

      def adapter_for_storage(store)
        candidate = store || self.store
        return nil unless candidate

        candidate.is_a?(StoreAdapter) ? candidate : StoreAdapter.new(candidate)
      end

      def list_storage_objects(adapter, descriptor, namespace: :all)
        return [] unless adapter

        adapter.list(descriptor, namespace: namespace)
      end

      def provider_from(explicit = nil)
        explicit || @cloud_provider
      end

      # Select a provider call form from the method signature so an
      # ArgumentError raised by the provider itself is never swallowed.
      def call_provider(provider, names, positional:, keywords: {})
        if provider.nil?
          raise ProviderUnavailableError,
                "cloud provider is not configured for #{name}; configure an injected provider before reconciliation"
        end

        method_name = Array(names).find { |candidate| provider.respond_to?(candidate) }
        unless method_name
          raise ProviderUnavailableError,
                "cloud provider for #{name} does not implement any of #{Array(names).join(", ")}"
        end

        callable = provider.method(method_name)
        parameters = callable.parameters
        accepts_keywords = parameters.any? { |type, _name| %i[key keyreq keyrest].include?(type) }
        if accepts_keywords
          accepted = if parameters.any? { |type, _name| type == :keyrest }
                       keywords
                     else
                       accepted_names = parameters.filter_map { |type, parameter_name| parameter_name if %i[key keyreq].include?(type) }
                       keywords.select { |key, _value| accepted_names.include?(key.to_sym) }
                     end
          positional_parameters = parameters.select { |type, _name| %i[req opt rest].include?(type) }
          if positional_parameters.empty?
            callable.call(**accepted)
          elsif positional_parameters.any? { |type, _name| type == :rest }
            callable.call(*positional, **accepted)
          else
            callable.call(*positional.first(positional_parameters.length), **accepted)
          end
        else
          positional_parameters = parameters.select { |type, _name| %i[req opt rest].include?(type) }
          if positional_parameters.any? { |type, _name| type == :rest }
            callable.call(*positional)
          else
            callable.call(*positional.first(positional_parameters.length))
          end
        end
      end

      def hash_value(value)
        return value if value.is_a?(Hash)
        return value.to_h if value.respond_to?(:to_h)

        {}
      end

      def provider_ingress(value)
        return value if value.is_a?(Array)
        return [] if value.nil? || value == false

        hash = hash_value(value)
        candidate = Support.value(hash, "ingress", nil) ||
                    Support.value(Support.value(hash, "status", {}), "ingress", nil) ||
                    Support.value(Support.value(hash, "loadBalancer", {}), "ingress", nil) ||
                    Support.value(Support.value(Support.value(hash, "status", {}), "loadBalancer", {}), "ingress", nil)
        return Array(candidate) unless candidate.nil?

        ip = Support.value(hash, "ip", nil)
        hostname = Support.value(hash, "hostname", nil)
        return [{"ip" => ip.to_s}] unless ip.to_s.empty?
        return [{"hostname" => hostname.to_s}] unless hostname.to_s.empty?

        []
      end

      def canonical_rule(rule)
        Support.canonical(rule)
      end

      def quantity_base(value)
        return value.to_f if value.is_a?(Numeric)

        text = value.to_s.strip
        return 0.0 if text.empty?
        return text.to_f if text.match?(/\A-?(?:\d+(?:\.\d+)?|\.\d+)\z/)

        suffixes = {
          "Ki" => 1024.0, "Mi" => 1024.0**2, "Gi" => 1024.0**3,
          "Ti" => 1024.0**4, "Pi" => 1024.0**5, "Ei" => 1024.0**6,
          "n" => 1e-9, "u" => 1e-6, "m" => 1e-3,
          "k" => 1e3, "M" => 1e6, "G" => 1e9, "T" => 1e12,
          "P" => 1e15, "E" => 1e18
        }
        suffix, multiplier = suffixes.find { |candidate, _| text.end_with?(candidate) }
        return text.to_f unless suffix

        text.delete_suffix(suffix).to_f * multiplier
      end

      def descriptor_from(value, api_version:, resource:, scope:)
        ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => value},
                                 resource: resource, scope: scope)
      end

      def upsert_condition(conditions, type, status, reason, message: nil)
        values = Array(conditions).map { |condition| Support.deep_copy(condition) }
        current = values.find { |condition| Support.value(condition, "type", "").to_s == type.to_s }
        if current
          current["status"] = status.to_s
          current["reason"] = reason.to_s
          current["message"] = message.to_s if message
        else
          condition = {"type" => type.to_s, "status" => status.to_s, "reason" => reason.to_s}
          condition["message"] = message.to_s if message
          values << condition
        end
        values
      end

      def remove_conditions(conditions, *types)
        rejected = types.map(&:to_s)
        Array(conditions).filter_map do |condition|
          next if rejected.include?(Support.value(condition, "type", "").to_s)

          Support.deep_copy(condition)
        end
      end

      def workload_pod?(pod)
        return false unless Support.kind(pod) == "Pod"
        return false unless Support.value(Support.spec(pod), "nodeName", nil)
        return false if Support.value(Support.metadata(pod), "deletionTimestamp", nil)

        !%w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
      end

      def volume_attachment_descriptor
        descriptor_from("VolumeAttachment", api_version: "storage.k8s.io/v1",
                                            resource: "volumeattachments", scope: :cluster)
      end

      def name_key(object)
        [Support.namespace(object), Support.name(object)].compact.join("/")
      end
    end

    # Evicts Pods after NoExecute tolerations expire. NodeController publishes
    # Node.spec.taints; this controller owns only the eviction side.
    class TaintEvictionController < BaseController
      include InfrastructureStorageSupport

      # float64(time.Since(fireAt) * time.Second): upstream multiplies the
      # nanosecond Duration by another 1e9 (wrapping as int64), and that is
      # what the histogram holds.
      def self.go_duration_times_second(seconds)
        value = (seconds * 1_000_000_000).to_i * 1_000_000_000
        value = ((value + (2**63)) % (2**64)) - (2**63)
        value.to_f
      end

      NODE = ResourceDescriptor.parse("Node")
      POD = ResourceDescriptor.parse("Pod")

      def initialize(clock: nil, **)
        @clock = clock || -> { Time.now.utc }
        # When a taint carries no timeAdded (kubectl taint sets none), the
        # toleration clock starts when this controller first saw the taint,
        # as upstream's taint manager does.  Falling back to the Node's Ready
        # transition started it long ago, so every tolerationSeconds had
        # already elapsed and each tolerating Pod was evicted at once.
        @taint_first_seen = {}
        @taint_mutex = Mutex.new
        super(**)
      end

      def plan(node, store: nil, pods: nil, now: nil, **_options)
        adapter = adapter_for_storage(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        timestamp = normalize_time(now || @clock.call)
        taints = eviction_taints(node)
        remember_taints(node, taints, timestamp)
        operations = []
        events = []
        next_deadline = nil
        Array(pods).select { |pod| pod_on_node?(pod, node) }.each do |pod|
          due_taint = taints.find { |taint| eviction_due?(pod, taint, timestamp, node) }
          unless due_taint
            deadline = taints.filter_map { |taint| eviction_deadline(pod, taint, node) }.min
            next_deadline = [next_deadline, deadline].compact.min if deadline
            next
          end

          # addConditionAndDeletePod, and emitPodDeletionEvent on the Pod;
          # deletePodHandler counts each delete that went through.
          fired = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          deletions = disruption_and_delete(pod, timestamp, reason: "DeletionByTaintManager",
                                                            message: "Taint manager: deleting due to NoExecute taint")
          observed = deletions.map do |operation|
            next operation unless operation.delete?

            operation.observed do |succeeded, _|
              next unless succeeded

              ControllerMetrics.increment("taint_eviction_controller_pod_deletions_total")
              ControllerMetrics.observe("taint_eviction_controller_pod_deletion_duration_seconds",
                                        self.class.go_duration_times_second(Process.clock_gettime(Process::CLOCK_MONOTONIC) - fired))
            end
          end
          operations.concat(observed)
          events << {"type" => "Normal", "reason" => "TaintManagerEviction",
                     "message" => "Marking for deletion Pod #{name_key(pod)}", "involvedObject" => pod_reference(pod)}
        end
        # Upstream's taint manager fires each eviction from a timer at its
        # deadline.  Returning nothing made the eviction wait for whatever
        # next happened to touch the Node.
        requeue_after = next_deadline && [next_deadline - timestamp, 0.5].max
        ReconcileResult.new(operations: operations, status: Support.status(node), events: events,
                            controller: name, key: Support.name(node), requeue_after: requeue_after)
      end

      private

      # apipod.UpdatePodCondition on a copy of the status (lastTransitionTime
      # kept when the status is unchanged), patched only when it changed.
      def disruption_and_delete(pod, now, reason:, message:, uid_precondition: false)
        operations = []
        status = Support.deep_copy(Support.status(pod))
        conditions = Array(status["conditions"]).map { |entry| Support.deep_copy(entry) }
        wanted = {"type" => "DisruptionTarget", "status" => "True", "reason" => reason, "message" => message}
        generation = Support.value(Support.metadata(pod), "generation", nil)
        wanted["observedGeneration"] = generation unless generation.nil?
        stamp = now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        existing = conditions.find { |entry| entry["type"] == "DisruptionTarget" }
        changed = if existing.nil?
                    conditions << wanted.merge("lastProbeTime" => nil, "lastTransitionTime" => stamp)
                    true
                  elsif wanted.any? { |key, value| existing[key] != value }
                    existing["lastTransitionTime"] = stamp if existing["status"] != "True"
                    existing.merge!(wanted)
                    true
                  else
                    false
                  end
        if changed
          status["conditions"] = conditions
          operations << operation_status(pod, status, descriptor: POD, reason: "taint eviction DisruptionTarget", force: true)
        end
        options = nil
        uid = Support.uid(pod).to_s
        options = {"preconditions" => {"uid" => uid}} if uid_precondition && !uid.empty?
        operations << operation_delete(pod, descriptor: POD, reason: "taint eviction", options: options)
        operations
      end

      def pod_reference(pod)
        {"apiVersion" => "v1", "kind" => "Pod", "namespace" => Support.namespace(pod), "name" => Support.name(pod),
         "uid" => Support.uid(pod)}.compact
      end

      def pod_on_node?(pod, node)
        workload_pod?(pod) && Support.value(Support.spec(pod), "nodeName", "").to_s == Support.name(node)
      end

      def eviction_taints(node)
        Array(Support.value(Support.spec(node), "taints", [])).filter_map do |taint|
          copy = Support.deep_copy(taint)
          copy if Support.value(copy, "effect", "").to_s == "NoExecute"
        end
      end

      def taint_key(taint)
        key = Support.value(taint, "key", "").to_s
        value = Support.value(taint, "value", nil)
        value.to_s.empty? ? key : "#{key}=#{value}"
      end

      def eviction_due?(pod, taint, now, node = nil)
        matching = matching_tolerations(pod, taint)
        return true if matching.empty?
        return false if matching.any? { |toleration| Support.value(toleration, "tolerationSeconds", nil).nil? }

        seconds = matching.filter_map do |toleration|
          parsed = Support.integer(Support.value(toleration, "tolerationSeconds", nil), -1)
          parsed if parsed >= 0
        end.max
        return false unless seconds

        added_at = taint_added_at(taint, node)
        return seconds.zero? unless added_at

        now >= added_at + seconds
      end

      # When a tolerating Pod's eviction falls due, or nil if it never does.
      def eviction_deadline(pod, taint, node)
        matching = matching_tolerations(pod, taint)
        return nil if matching.empty?
        return nil if matching.any? { |toleration| Support.value(toleration, "tolerationSeconds", nil).nil? }

        seconds = matching.filter_map do |toleration|
          parsed = Support.integer(Support.value(toleration, "tolerationSeconds", nil), -1)
          parsed if parsed >= 0
        end.max
        added_at = taint_added_at(taint, node)
        seconds && added_at ? added_at + seconds : nil
      end

      def taint_added_at(taint, node = nil)
        Support.parse_time(Support.value(taint, "timeAdded", nil)) ||
          Support.parse_time(Support.value(taint, "addedAt", nil)) ||
          Support.parse_time(Support.value(taint, "lastTransitionTime", nil)) ||
          first_seen(node, taint)
      end

      def taint_identity(node, taint)
        [Support.name(node || {}).to_s, Support.value(taint, "key", "").to_s,
         Support.value(taint, "value", "").to_s, Support.value(taint, "effect", "").to_s]
      end

      def first_seen(node, taint)
        @taint_mutex.synchronize { @taint_first_seen[taint_identity(node, taint)] }
      end

      # Record when each of this Node's NoExecute taints was first observed,
      # and forget the ones that are gone so a re-added taint starts afresh.
      def remember_taints(node, taints, now)
        name = Support.name(node).to_s
        current = taints.map { |taint| taint_identity(node, taint) }
        @taint_mutex.synchronize do
          @taint_first_seen.delete_if { |identity, _| identity.first == name && !current.include?(identity) }
          current.each { |identity| @taint_first_seen[identity] ||= now }
        end
      end

      def matching_tolerations(pod, taint)
        Array(Support.value(Support.spec(pod), "tolerations", [])).select do |toleration|
          toleration_matches?(toleration, taint)
        end
      end

      def toleration_matches?(toleration, taint)
        effect = Support.value(toleration, "effect", "").to_s
        taint_effect = Support.value(taint, "effect", "").to_s
        return false unless effect.empty? || effect == taint_effect

        key = Support.value(toleration, "key", "").to_s
        taint_key_value = Support.value(taint, "key", "").to_s
        operator = Support.value(toleration, "operator", "Equal").to_s
        return true if operator == "Exists" && (key.empty? || key == taint_key_value)

        return false unless operator == "Equal" && key == taint_key_value

        Support.value(toleration, "value", "").to_s == Support.value(taint, "value", "").to_s
      end
    end

    # DRA device taints are sourced separately from ordinary Node taints while
    # retaining the NoExecute toleration timing contract.
    class DeviceTaintEvictionController < TaintEvictionController
      DEVICE_TAINT_PREFIXES = %w[resource.kubernetes.io/ device.kubernetes.io/ dra.kubernetes.io/].freeze

      def plan(node, store: nil, pods: nil, device_taints: nil, now: nil, **_options)
        adapter = adapter_for_storage(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        timestamp = normalize_time(now || @clock.call)
        taints = Array(device_taints || discovered_device_taints(node)).select do |taint|
          Support.value(taint, "effect", "").to_s == "NoExecute"
        end
        remember_taints(node, taints, timestamp)
        operations = []
        events = []
        Array(pods).select { |pod| pod_on_device_node?(pod, node) }.each do |pod|
          due_taint = taints.find { |taint| device_eviction_due?(pod, taint, timestamp, node) }
          next unless due_taint

          # deletePod: the condition, then a delete with a UID precondition;
          # a delete that went through is counted with the time since the
          # taint's effect became active (a Pod already gone is not).
          effective = device_eviction_time(pod, due_taint, node) || timestamp
          deletions = disruption_and_delete(pod, timestamp, reason: "DeletionByDeviceTaintManager",
                                                            message: "Device Taint manager: deleting due to NoExecute taint", uid_precondition: true)
          observed = deletions.map do |operation|
            next operation unless operation.delete?

            operation.observed do |succeeded, _|
              next unless succeeded

              ControllerMetrics.increment("device_taint_eviction_controller_pod_deletions_total")
              ControllerMetrics.observe("device_taint_eviction_controller_pod_deletion_duration_seconds",
                                        [normalize_time(@clock.call) - effective, 0.0].max)
            end
          end
          operations.concat(observed)
          events << {"type" => "Normal", "reason" => "DeviceTaintManagerEviction", "message" => "Marking for deletion",
                     "involvedObject" => pod_reference(pod)}
        end
        ReconcileResult.new(operations: operations, status: Support.status(node), events: events,
                            controller: name, key: Support.name(node))
      end

      private

      def discovered_device_taints(node)
        status = Support.status(node)
        spec = Support.spec(node)
        candidates = Array(Support.value(status, "deviceTaints", nil))
        candidates += Array(Support.value(spec, "deviceTaints", nil))
        candidates += Array(Support.value(spec, "resourceTaints", nil))
        candidates += Array(Support.value(spec, "taints", [])).select do |taint|
          DEVICE_TAINT_PREFIXES.any? { |prefix| Support.value(taint, "key", "").to_s.start_with?(prefix) }
        end
        candidates.filter_map { |taint| taint.is_a?(Hash) ? Support.deep_copy(taint) : nil }
      end

      def pod_on_device_node?(pod, node)
        workload_pod?(pod) && Support.value(Support.spec(pod), "nodeName", "").to_s == Support.name(node)
      end

      # eviction.when: the taint's timeAdded plus the longest matching
      # tolerationSeconds.
      def device_eviction_time(pod, taint, node)
        added_at = Support.parse_time(Support.value(taint, "timeAdded", nil)) ||
                   Support.parse_time(Support.value(Support.condition(node || {}, "Ready") || {}, "lastTransitionTime", nil))
        return nil unless added_at

        seconds = Array(Support.value(Support.spec(pod), "tolerations", [])).select do |toleration|
          device_toleration_matches?(toleration, taint)
        end
          .filter_map do |toleration|
          Support.integer(
            Support.value(toleration, "tolerationSeconds", nil), -1
          )
        end
          .select(&:positive?).max
        added_at + seconds.to_i
      rescue StandardError
        nil
      end

      def device_eviction_due?(pod, taint, now, node = nil)
        matching = Array(Support.value(Support.spec(pod), "tolerations", [])).select do |toleration|
          device_toleration_matches?(toleration, taint)
        end
        return true if matching.empty?
        return false if matching.any? { |toleration| Support.value(toleration, "tolerationSeconds", nil).nil? }

        seconds = matching.filter_map do |toleration|
          parsed = Support.integer(Support.value(toleration, "tolerationSeconds", nil), -1)
          parsed if parsed >= 0
        end.max
        return false unless seconds

        added_at = Support.parse_time(Support.value(taint, "timeAdded", nil)) ||
                   Support.parse_time(Support.value(Support.condition(node || {}, "Ready") || {}, "lastTransitionTime", nil))
        return seconds.zero? unless added_at

        now >= added_at + seconds
      end

      def device_toleration_matches?(toleration, taint)
        effect = Support.value(toleration, "effect", "").to_s
        return false unless effect.empty? || effect == Support.value(taint, "effect", "").to_s

        key = Support.value(toleration, "key", "").to_s
        taint_key_value = Support.value(taint, "key", "").to_s
        operator = Support.value(toleration, "operator", "Equal").to_s
        return true if operator == "Exists" && (key.empty? || key == taint_key_value)

        operator == "Equal" && key == taint_key_value &&
          Support.value(toleration, "value", "").to_s == Support.value(taint, "value", "").to_s
      end
    end

    # Cloud provider Service controller. A service with loadBalancerClass is
    # owned by the matching external implementation and is ignored here.
    class ServiceLBController < BaseController
      include InfrastructureStorageSupport

      SERVICE = ResourceDescriptor.parse("Service")
      NODE = ResourceDescriptor.parse("Node")

      def initialize(cloud_provider: nil, provider: nil, cloud: nil, **)
        @cloud_provider = cloud_provider || provider || cloud
        super(**)
      end

      def plan(service, store: nil, nodes: nil, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        return empty_result(service) unless cloud_owned?(service)

        adapter = adapter_for_storage(store)
        nodes ||= list_storage_objects(adapter, NODE, namespace: :all)
        result = call_provider(provider_from(provider || cloud_provider || cloud), %i[ensure_load_balancer ensureLoadBalancer create_load_balancer],
                               positional: [service, Array(nodes)],
                               keywords: {service: service, nodes: Array(nodes)})
        candidate_status = Support.deep_copy(Support.status(service))
        ingress = provider_ingress(result)
        load_balancer = Support.deep_copy(Support.value(candidate_status, "loadBalancer", {}))
        load_balancer = {} unless load_balancer.is_a?(Hash)
        load_balancer["ingress"] = Support.deep_copy(ingress) unless ingress.empty?
        candidate_status["loadBalancer"] = load_balancer unless load_balancer.empty?
        update = operation_status(service, candidate_status, descriptor: SERVICE,
                                                             reason: ingress.empty? ? "ensuring load balancer" : "load balancer ensured")
        events = if update.nil?
                   []
                 elsif ingress.empty?
                   [{"type" => "Normal", "reason" => "EnsuringLoadBalancer",
                     "message" => "ensuring load balancer for service #{name_key(service)}"}]
                 else
                   [{"type" => "Normal", "reason" => "EnsuredLoadBalancer",
                     "message" => "load balancer ensured for service #{name_key(service)}"}]
                 end
        ReconcileResult.new(operations: [update].compact, status: candidate_status, events: events,
                            controller: name, key: name_key(service))
      end

      def delete(service, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        call_provider(provider_from(provider || cloud_provider || cloud), %i[delete_load_balancer deleteLoadBalancer], positional: [service],
                                                                                                                       keywords: {service: service})
        ReconcileResult.new(operations: [], status: Support.status(service),
                            events: [{"type" => "Normal", "reason" => "DeletingLoadBalancer",
                                      "message" => "deleting load balancer for service #{name_key(service)}"}],
                            controller: name, key: name_key(service))
      end

      private

      def empty_result(service)
        ReconcileResult.new(operations: [], status: Support.status(service), controller: name,
                            key: name_key(service))
      end

      def cloud_owned?(service)
        Support.kind(service) == "Service" &&
          Support.value(Support.spec(service), "type", "ClusterIP").to_s == "LoadBalancer" &&
          Support.value(Support.spec(service), "loadBalancerClass", nil).to_s.empty?
      end
    end

    ServiceLbController = ServiceLBController
    ServiceLoadBalancerController = ServiceLBController

    # Synchronizes node PodCIDR routes through an injected cloud provider.
    # Route status entries carry a controller marker to fence ownership.
    class NodeRouteController < BaseController
      include InfrastructureStorageSupport

      NODE = ResourceDescriptor.parse("Node")
      MANAGED_BY = InfrastructureStorageSupport::MANAGED_ROUTE_CONTROLLER

      def initialize(cloud_provider: nil, provider: nil, cloud: nil, **)
        @cloud_provider = cloud_provider || provider || cloud
        super(**)
      end

      def plan(node, store: nil, routes: nil, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        cloud = provider_from(provider || cloud_provider || cloud)
        desired = desired_routes(node)
        existing = Array(routes || Support.value(Support.status(node), "routes", []))
        operations = []
        events = []
        desired.each do |route|
          call_provider(cloud, %i[ensure_route create_route], positional: [node, route],
                                                              keywords: {node: node, route: route, destination: route["destination"]})
          unless existing.any? { |candidate| route_identity(candidate) == route_identity(route) }
            events << {"type" => "Normal", "reason" => "RouteCreated",
                       "message" => "route #{route.fetch("destination")} assigned to node #{Support.name(node)}"}
          end
        end
        stale = existing.select do |candidate|
          managed_route?(candidate) &&
            desired.none? { |route| route_identity(route) == route_identity(candidate) }
        end
        stale.each do |route|
          call_provider(cloud, %i[delete_route remove_route], positional: [node, route],
                                                              keywords: {node: node, route: route, destination: Support.value(route, "destination", "")})
          events << {"type" => "Normal", "reason" => "RouteDeleted",
                     "message" => "route #{Support.value(route, "destination", "")} removed from node #{Support.name(node)}"}
        end
        candidate_status = Support.deep_copy(Support.status(node))
        candidate_status["routes"] = (existing.reject { |route| stale.include?(route) } + desired.reject do |route|
          existing.any? { |current| route_identity(current) == route_identity(route) }
        end).sort_by { |route| route_identity(route) }
        update = operation_status(node, candidate_status, descriptor: NODE, reason: "node route reconciliation")
        operations << update if update
        ReconcileResult.new(operations: operations, status: candidate_status, events: events,
                            controller: name, key: Support.name(node))
      end

      def delete(node, routes: nil, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        cloud = provider_from(provider || cloud_provider || cloud)
        Array(routes || Support.value(Support.status(node), "routes", [])).select { |route| managed_route?(route) }.each do |route|
          call_provider(cloud, %i[delete_route remove_route], positional: [node, route],
                                                              keywords: {node: node, route: route, destination: Support.value(route, "destination", "")})
        end
        ReconcileResult.new(operations: [], status: Support.status(node), controller: name,
                            key: Support.name(node))
      end

      private

      def desired_routes(node)
        spec = Support.spec(node)
        cidrs = Array(Support.value(spec, "podCIDRs", nil))
        cidrs = [Support.value(spec, "podCIDR", nil)] if cidrs.empty?
        provider_id = Support.value(spec, "providerID", nil).to_s
        cidrs.filter_map do |cidr|
          next if cidr.to_s.empty?

          {"destination" => cidr.to_s, "node" => Support.name(node),
           "providerID" => provider_id, "managedBy" => MANAGED_BY}
        end.sort_by { |route| route.fetch("destination") }
      end

      def route_identity(route)
        [Support.value(route, "destination", "").to_s, Support.value(route, "node", "").to_s]
      end

      def managed_route?(route)
        Support.value(route, "managedBy", nil).to_s == MANAGED_BY ||
          Support.value(route, "controller", nil).to_s == name.to_s
      end
    end

    # Removes nodes that the configured cloud provider no longer owns and
    # publishes a separate cloud readiness condition while present.
    class CloudNodeLifecycleController < BaseController
      include InfrastructureStorageSupport

      NODE = ResourceDescriptor.parse("Node")

      def initialize(cloud_provider: nil, provider: nil, cloud: nil, **)
        @cloud_provider = cloud_provider || provider || cloud
        super(**)
      end

      def plan(node, provider: nil, cloud_provider: nil, cloud: nil, **_options)
        return empty_result(node) unless cloud_owned?(node)

        cloud = provider_from(provider || cloud_provider || cloud)
        provider_id = Support.value(Support.spec(node), "providerID", "").to_s
        result = if cloud.respond_to?(:instance_exists_by_provider_id)
                   call_provider(cloud, [:instance_exists_by_provider_id], positional: [provider_id],
                                                                           keywords: {node: node, provider_id: provider_id})
                 else
                   call_provider(cloud, %i[instance_exists? instance_exists node_exists? node_exists],
                                 positional: [node], keywords: {node: node, provider_id: provider_id})
                 end
        if result.nil?
          raise ProviderUnavailableError,
                "cloud provider for #{name} returned no instance-existence result"
        end
        return deletion_result(node) if result == false || Support.value(hash_value(result), "exists", true) == false

        candidate_status = Support.deep_copy(Support.status(node))
        candidate_status["conditions"] = upsert_condition(candidate_status["conditions"], "CloudNodeReady", "True", "CloudNodeExists")
        update = operation_status(node, candidate_status, descriptor: NODE, reason: "cloud node lifecycle")
        ReconcileResult.new(operations: [update].compact, status: candidate_status,
                            events: if update
                                      [{"type" => "Normal", "reason" => "CloudNodeReady",
                                        "message" => "cloud instance for node #{Support.name(node)} exists"}]
                                    else
                                      []
                                    end,
                            controller: name, key: Support.name(node))
      end

      private

      def cloud_owned?(node)
        Support.kind(node) == "Node" && !Support.value(Support.spec(node), "providerID", nil).to_s.empty?
      end

      def empty_result(node)
        ReconcileResult.new(operations: [], status: Support.status(node), controller: name,
                            key: Support.name(node))
      end

      def deletion_result(node)
        ReconcileResult.new(operations: [operation_delete(node, descriptor: NODE, reason: "cloud instance no longer exists")],
                            status: Support.status(node),
                            events: [{"type" => "Warning", "reason" => "CloudNodeNotReady",
                                      "message" => "cloud instance for node #{Support.name(node)} no longer exists"}],
                            controller: name, key: Support.name(node))
      end
    end

    # PersistentVolume binder. It applies class, access-mode, selector, volume
    # mode, and capacity matching before writing the PV claimRef and PVC
    # volumeName pair.
    # pkg/controller/volume/persistentvolume (v1.36.2): syncClaim binds a
    # claim to the smallest matching Available volume (or its pre-bound
    # one), leaves WaitForFirstConsumer claims to the scheduler, hands
    # dynamic provisioning to the external provisioner, and marks claims
    # Lost when their volume goes; syncVolume keeps volume phases, unbinds
    # volumes whose claim went elsewhere, and reclaims Released volumes
    # (Retain; Delete -- the in-tree hostPath deleter or the external
    # provisioner; Recycle -- a recycler Pod).
    class PersistentVolumeBinderController < BaseController
      include InfrastructureStorageSupport

      PV = ResourceDescriptor.parse("PersistentVolume")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      POD = ResourceDescriptor.parse("Pod")
      STORAGE_CLASS = ResourceDescriptor.parse("StorageClass")

      ANN_BIND_COMPLETED = "pv.kubernetes.io/bind-completed"
      ANN_BOUND_BY_CONTROLLER = "pv.kubernetes.io/bound-by-controller"
      ANN_SELECTED_NODE = "volume.kubernetes.io/selected-node"
      ANN_DYNAMICALLY_PROVISIONED = "pv.kubernetes.io/provisioned-by"
      ANN_MIGRATED_TO = "pv.kubernetes.io/migrated-to"
      ANN_STORAGE_PROVISIONER = "volume.kubernetes.io/storage-provisioner"
      ANN_BETA_STORAGE_PROVISIONER = "volume.beta.kubernetes.io/storage-provisioner"
      ANN_BETA_STORAGE_CLASS = "volume.beta.kubernetes.io/storage-class"
      ANN_PRE_RESIZE_CAPACITY = "volume.alpha.kubernetes.io/pre-resize-capacity"
      ANN_DEFAULT_CLASS = "storageclass.kubernetes.io/is-default-class"
      ANN_BETA_DEFAULT_CLASS = "storageclass.beta.kubernetes.io/is-default-class"
      IN_TREE_FINALIZER = "kubernetes.io/pv-controller"
      EXTERNAL_FINALIZER = "external-provisioner.volume.kubernetes.io/finalizer"
      # CSI migration (on for every migratable in-tree plugin in v1.36).
      MIGRATED_PLUGINS = {
        "kubernetes.io/aws-ebs" => "ebs.csi.aws.com", "kubernetes.io/gce-pd" => "pd.csi.storage.gke.io",
        "kubernetes.io/azure-disk" => "disk.csi.azure.com", "kubernetes.io/azure-file" => "file.csi.azure.com",
        "kubernetes.io/cinder" => "cinder.csi.openstack.org", "kubernetes.io/vsphere-volume" => "csi.vsphere.vmware.com",
        "kubernetes.io/portworx-volume" => "pxd.portworx.com"
      }.freeze
      ACCESS_MODE_ORDER = %w[ReadWriteOnce ReadOnlyMany ReadWriteMany ReadWriteOncePod].freeze
      RECYCLER_IMAGE = "registry.k8s.io/build-image/debian-base:bookworm-v1.0.6"
      RECYCLER_SCRIPT = "test -e /scrub && find /scrub -mindepth 1 -delete && test -z \"$(ls -A /scrub)\" || exit 1"
      # A pending operation's recheck (the upstream operation executor and
      # 15 s resync).
      RECHECK_SECONDS = 5.0

      def initialize(*, host_path_deleter: nil, **)
        super(*, **)
        # hostPathDeleter.Delete: only under /tmp (anchored here, which the
        # upstream regexp is not: this controller runs as root on the host).
        @host_path_deleter = host_path_deleter || lambda do |path|
          unless path.to_s.match?(%r{\A/tmp/.+})
            raise ArgumentError,
                  "host_path deleter only supports /tmp/.+ but received provided #{path}"
          end

          FileUtils.rm_rf(path)
        end
      end

      def plan(object, store: nil, persistent_volumes: nil, volumes: nil, claims: nil, pods: nil, storage_classes: nil, **_options)
        adapter = adapter_for_storage(store)
        context = {
          adapter: adapter,
          volumes: persistent_volumes || volumes || list_storage_objects(adapter, PV, namespace: :all),
          claims: claims,
          pods: pods,
          classes: storage_classes || list_storage_objects(adapter, STORAGE_CLASS, namespace: :all),
          events: [], operations: [], requeue: nil
        }
        case Support.kind(object)
        when "PersistentVolume" then sync_volume(object, context)
        when "PersistentVolumeClaim" then sync_claim(object, context)
        else return ReconcileResult.new(operations: [], controller: name, key: name_key(object))
        end
        ReconcileResult.new(operations: context[:operations].compact,
                            events: once_per_state("#{Support.kind(object)}/#{name_key(object)}", context[:events]),
                            controller: name, key: name_key(object), requeue_after: context[:requeue])
      end

      private

      # ---------------------------------------------------------- claims

      def sync_claim(claim, context)
        claim = anneal_claim_migration(claim, context)
        return if claim.nil?

        if annotation?(claim, ANN_BIND_COMPLETED)
          sync_bound_claim(claim, context)
        else
          sync_unbound_claim(claim, context)
        end
      end

      def sync_unbound_claim(claim, context)
        volume_name = Support.value(Support.spec(claim), "volumeName", "").to_s
        if volume_name.empty?
          delay = delay_binding?(claim, context)
          if delay.is_a?(String)
            context[:requeue] = RECHECK_SECONDS
            return
          end

          volume = find_best_match(claim, context[:volumes], delay)
          if volume.nil?
            return if assign_default_class(claim, context)

            if delay && !annotation?(claim, ANN_SELECTED_NODE)
              emit_delay_binding_event(claim, context)
            elsif !claim_class(claim).empty?
              provision_claim(claim, context)
              return
            else
              event(context, "Normal", "FailedBinding", "no persistent volumes available for this claim and no storage class is set")
            end
            update_claim_status(claim, "Pending", nil, context)
          else
            bind(volume, claim, context)
          end
          return
        end

        volume = find_volume(context, volume_name)
        if volume.nil?
          update_claim_status(claim, "Pending", nil, context)
        elsif claim_ref(volume).nil?
          if (reason = volume_satisfy_error(volume, claim))
            event(context, "Warning", "VolumeMismatch", "Cannot bind to requested volume #{volume_name.dump}: #{reason}")
            update_claim_status(claim, "Pending", nil, context)
          else
            bind(volume, claim, context)
          end
        elsif bound_to_claim?(volume, claim)
          bind(volume, claim, context)
        else
          event(context, "Warning", "FailedBinding", "volume #{volume_name.dump} already bound to a different claim.")
          # A claim the controller bound itself to a now-foreign volume is
          # an error upstream (retried); a user's pre-binding stays Pending.
          if annotation?(claim, ANN_BOUND_BY_CONTROLLER)
            context[:requeue] = RECHECK_SECONDS
          else
            update_claim_status(claim, "Pending", nil, context)
          end
        end
      end

      def sync_bound_claim(claim, context)
        volume_name = Support.value(Support.spec(claim), "volumeName", "").to_s
        if volume_name.empty?
          return update_claim_status_with_event(claim, "Lost", nil, context, "Warning", "ClaimLost",
                                                "Bound claim has lost reference to PersistentVolume. Data on the volume is lost!")
        end

        volume = find_volume(context, volume_name)
        if volume.nil?
          update_claim_status_with_event(claim, "Lost", nil, context, "Warning", "ClaimLost",
                                         "Bound claim has lost its PersistentVolume. Data on the volume is lost!")
        elsif claim_ref(volume).nil? || Support.value(claim_ref(volume), "uid", "").to_s == Support.uid(claim).to_s
          bind(volume, claim, context)
        else
          update_claim_status_with_event(claim, "Lost", nil, context, "Warning", "ClaimMisbound",
                                         "Two claims are bound to the same volume, this one is bound incorrectly")
        end
      end

      # checkVolumeSatisfyClaim.
      def volume_satisfy_error(volume, claim)
        return "the volume is marked for deletion #{Support.name(volume).dump}" unless Support.value(Support.metadata(volume),
                                                                                                     "deletionTimestamp", nil).nil?
        return "requested PV is too small" if storage(volume_capacity(volume)) < storage(claim_request(claim))
        return "storageClassName does not match" if volume_class(volume) != claim_class(claim)
        return "volumeAttributesClassName does not match" if vac(claim) != vac(volume)
        return "incompatible volumeMode" if volume_mode(claim) != volume_mode(volume)
        return "incompatible accessMode" unless access_modes_contain?(access_modes(volume), access_modes(claim))

        nil
      end

      # IsDelayBindingMode: true/false, or an error message.
      def delay_binding?(claim, context)
        class_name = claim_class(claim)
        return false if class_name.empty?

        storage_class = find_class(context, class_name)
        return false if storage_class.nil?

        mode = Support.value(storage_class, "volumeBindingMode", nil)
        return "VolumeBindingMode not set for StorageClass #{class_name.dump}" if mode.nil?

        mode.to_s == "WaitForFirstConsumer"
      end

      def emit_delay_binding_event(claim, context)
        names = pods_using(claim, context).reject do |pod|
          pod_terminated?(pod)
        end.select { |pod| Support.value(Support.spec(pod), "nodeName", "").to_s.empty? }
          .map { |pod| Support.name(pod) }
        if names.empty?
          event(context, "Normal", "WaitForFirstConsumer", "waiting for first consumer to be created before binding")
        elsif names.length == 1
          event(context, "Normal", "WaitForPodScheduled", "waiting for pod #{names.first} to be scheduled")
        else
          event(context, "Normal", "WaitForPodScheduled", "waiting for pods #{names.join(",")} to be scheduled")
        end
      end

      # assignDefaultStorageClass: a claim with no class at all gets the
      # default one (retroactive default StorageClass assignment).
      def assign_default_class(claim, context)
        return false if claim_has_class?(claim)

        default = default_class(context[:classes])
        return false if default.nil?

        updated = Support.deep_copy(claim)
        (updated["spec"] ||= {})["storageClassName"] = Support.name(default)
        # RecordRetroactiveStorageClassMetric: every assignment, and the ones
        # whose claim update failed.
        assign = operation_update(claim, updated, descriptor: PVC, reason: "assign the default StorageClass")&.observed do |succeeded, _|
          ControllerMetrics.increment("retroactive_storageclass_total")
          ControllerMetrics.increment("retroactive_storageclass_errors_total") unless succeeded
        end
        context[:operations] << assign if assign
        true
      end

      # provisionClaim: the in-tree provisioners are not enabled (no
      # --enable-hostpath-provisioner), so a kubernetes.io/ provisioner that
      # was not migrated to CSI fails, and any other is external.
      def provision_claim(claim, context)
        storage_class = find_class(context, claim_class(claim))
        if storage_class.nil?
          event(context, "Warning", "ProvisioningFailed", "storageclass.storage.k8s.io #{claim_class(claim).dump} not found")
          return
        end

        provisioner = Support.value(storage_class, "provisioner", "").to_s
        provisioner = MIGRATED_PLUGINS.fetch(provisioner, provisioner)
        if provisioner.start_with?("kubernetes.io/")
          event(context, "Warning", "ProvisioningFailed", "no provisionable volume plugin matched")
          return
        end

        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        unless annotations[ANN_STORAGE_PROVISIONER] == provisioner && annotations[ANN_BETA_STORAGE_PROVISIONER] == provisioner
          updated = Support.deep_copy(claim)
          updated["metadata"]["annotations"] =
            annotations.merge(ANN_STORAGE_PROVISIONER => provisioner, ANN_BETA_STORAGE_PROVISIONER => provisioner)
          annotate = operation_update(claim, updated, descriptor: PVC,
                                                      reason: "set the claim's external provisioner")&.observed do |succeeded, _|
            # provisionClaimOperationExternal failed: RecordMetric's error.
            unless succeeded
              ControllerMetrics.increment("volume_operation_errors_total",
                                          {"plugin_name" => provisioner, "operation_name" => "provision"})
            end
          end
          context[:operations] << annotate if annotate
        end
        event(context, "Normal", "ExternalProvisioning",
              "Waiting for a volume to be created either by the external provisioner '#{provisioner}' or manually by the system " \
              "administrator. If volume creation is delayed, please verify that the provisioner is running and correctly registered.")
      end

      # updateClaimMigrationAnnotations (claim side).
      def anneal_claim_migration(claim, context)
        annotations = Support.value(Support.metadata(claim), "annotations", nil)
        return claim unless annotations.is_a?(Hash)

        provisioner = annotations[ANN_STORAGE_PROVISIONER] || annotations[ANN_BETA_STORAGE_PROVISIONER]
        return claim if provisioner.nil?

        updated_annotations = migration_annotations(annotations, provisioner)
        return claim if updated_annotations.nil?

        updated = Support.deep_copy(claim)
        updated["metadata"]["annotations"] = updated_annotations
        context[:operations] << operation_update(claim, updated, descriptor: PVC, reason: "anneal migration annotations")
        nil
      end

      def migration_annotations(annotations, provisioner)
        driver = MIGRATED_PLUGINS[provisioner]
        current = annotations[ANN_MIGRATED_TO]
        if driver
          return nil if current == driver

          annotations.merge(ANN_MIGRATED_TO => driver)
        else
          return nil if current.to_s.empty?

          annotations.reject { |key, _| key == ANN_MIGRATED_TO }
        end
      end

      # ---------------------------------------------------------- binding

      # bind: the volume first (claimRef, bound-by-controller, phase
      # Bound), then the claim (volumeName, bound-by-controller,
      # bind-completed, phase Bound with the volume's modes and capacity).
      def bind(volume, claim, context)
        updated_volume = Support.deep_copy(volume)
        reference = claim_ref(volume)
        unless reference && Support.value(reference, "name", "") == Support.name(claim) &&
               Support.value(reference, "namespace", "") == Support.namespace(claim) &&
               Support.value(reference, "uid", "").to_s == Support.uid(claim).to_s
          (updated_volume["spec"] ||= {})["claimRef"] = {"kind" => "PersistentVolumeClaim", "namespace" => Support.namespace(claim),
                                                         "name" => Support.name(claim), "uid" => Support.uid(claim), "apiVersion" => "v1",
                                                         "resourceVersion" => Support.value(Support.metadata(claim), "resourceVersion", nil)}.compact
        end
        if !bound_to_claim?(volume, claim) && !annotation?(updated_volume, ANN_BOUND_BY_CONTROLLER)
          set_annotation(updated_volume, ANN_BOUND_BY_CONTROLLER, "yes")
        end
        context[:operations] << operation_update(volume, updated_volume, descriptor: PV, reason: "bind PersistentVolume to claim")
        update_volume_phase(updated_volume, "Bound", "", context)

        updated_claim = Support.deep_copy(claim)
        if Support.value(Support.spec(claim), "volumeName", "").to_s != Support.name(volume)
          (updated_claim["spec"] ||= {})["volumeName"] = Support.name(volume)
          set_annotation(updated_claim, ANN_BOUND_BY_CONTROLLER, "yes") unless annotation?(updated_claim, ANN_BOUND_BY_CONTROLLER)
        end
        set_annotation(updated_claim, ANN_BIND_COMPLETED, "yes") unless annotation?(updated_claim, ANN_BIND_COMPLETED)
        context[:operations] << operation_update(claim, updated_claim, descriptor: PVC, reason: "bind claim to PersistentVolume")
        update_claim_status(updated_claim, "Bound", updated_volume, context)
      end

      # updateClaimStatus.
      def update_claim_status(claim, phase, volume, context)
        status = Support.deep_copy(Support.status(claim))
        current_phase = Support.value(status, "phase", "").to_s
        status["phase"] = phase
        if volume.nil?
          status.delete("accessModes")
          status.delete("capacity")
          status.delete("currentVolumeAttributesClassName")
        else
          modes = Support.value(Support.spec(volume), "accessModes", nil)
          modes.nil? ? status.delete("accessModes") : status["accessModes"] = modes
          if current_phase != phase
            capacity = volume_capacity(volume)
            pre_resize = Support.value(Support.value(Support.metadata(volume), "annotations", {}) || {}, ANN_PRE_RESIZE_CAPACITY, nil)
            if pre_resize
              status["capacity"] = Support.deep_copy(Support.value(status, "capacity", {}) || {}).merge("storage" => pre_resize)
            elsif storage(Support.value(Support.value(status, "capacity", {}) || {}, "storage", nil)) != storage(capacity) ||
                  Support.value(Support.value(status, "capacity", {}) || {}, "storage", nil).nil?
              status["capacity"] = Support.deep_copy(Support.value(Support.spec(volume), "capacity", {}))
            end
          end
          if current_phase == "Pending" && phase == "Bound"
            vac_name = Support.value(Support.spec(volume), "volumeAttributesClassName", nil)
            vac_name.nil? ? status.delete("currentVolumeAttributesClassName") : status["currentVolumeAttributesClassName"] = vac_name
          end
        end
        return claim if status == Support.status(claim)

        context[:operations] << operation_status(claim, status, descriptor: PVC, reason: "claim phase #{phase}", force: true)
        claim.merge("status" => status)
      end

      def update_claim_status_with_event(claim, phase, volume, context, type, reason, message)
        return claim if Support.value(Support.status(claim), "phase", "").to_s == phase

        updated = update_claim_status(claim, phase, volume, context)
        event(context, type, reason, message)
        updated
      end

      # ---------------------------------------------------------- volumes

      def sync_volume(volume, context)
        volume = anneal_volume(volume, context)
        return if volume.nil?

        reference = claim_ref(volume)
        if reference.nil? || Support.value(reference, "uid", "").to_s.empty?
          update_volume_phase(volume, "Available", "", context)
          return
        end

        namespace = Support.value(reference, "namespace", "")
        claim_name = Support.value(reference, "name", "")
        claim = find_claim(context, namespace, claim_name)
        phase = Support.value(Support.status(volume), "phase", "").to_s
        # A claim missing from the cache, or with another UID, is read from
        # the API server before the volume is released (cache lag).
        if (claim.nil? && !%w[Released Failed].include?(phase)) ||
           (claim && Support.uid(claim).to_s != Support.value(reference, "uid", "").to_s)
          claim = live_claim(context, namespace, claim_name) || (claim.nil? ? nil : claim)
        end
        claim = nil if claim && Support.uid(claim).to_s != Support.value(reference, "uid", "").to_s
        if claim.nil?
          phase = Support.value(Support.status(volume), "phase", "").to_s
          volume = update_volume_phase(volume, "Released", "", context) unless %w[Released Failed].include?(phase)
          reclaim_volume(volume, context)
        elsif Support.value(Support.spec(claim), "volumeName", "").to_s.empty?
          if volume_mode(claim) != volume_mode(volume)
            event(context, "Warning", "VolumeMismatch",
                  "Cannot bind PersistentVolume to requested PersistentVolumeClaim #{Support.name(claim).dump} due to incompatible volumeMode.")
            event(context, "Warning", "VolumeMismatch",
                  "Cannot bind PersistentVolume #{Support.name(volume).dump} to requested PersistentVolumeClaim due to incompatible volumeMode.",
                  involved: claim)
          end
          # The claim's own sync binds it (claimQueue.Add).
        elsif Support.value(Support.spec(claim), "volumeName", "").to_s == Support.name(volume)
          update_volume_phase(volume, "Bound", "", context)
        elsif annotation?(volume, ANN_DYNAMICALLY_PROVISIONED) && reclaim_policy(volume) == "Delete"
          phase = Support.value(Support.status(volume), "phase", "").to_s
          volume = update_volume_phase(volume, "Released", "", context) unless %w[Released Failed].include?(phase)
          reclaim_volume(volume, context)
        else
          unbind_volume(volume, context)
        end
      end

      # updateVolumeMigrationAnnotationsAndFinalizers.
      def anneal_volume(volume, context)
        annotations = Support.value(Support.metadata(volume), "annotations", nil)
        updated_annotations = nil
        if annotations.is_a?(Hash) && annotations.key?(ANN_DYNAMICALLY_PROVISIONED)
          updated_annotations = migration_annotations(annotations, annotations[ANN_DYNAMICALLY_PROVISIONED])
        end
        finalizers = deletion_finalizers(volume)
        return volume if updated_annotations.nil? && finalizers.nil?

        updated = Support.deep_copy(volume)
        updated["metadata"]["annotations"] = updated_annotations if updated_annotations
        updated["metadata"]["finalizers"] = finalizers if finalizers
        context[:operations] << operation_update(volume, updated, descriptor: PV, reason: "anneal migration annotations or finalizers")
        nil
      end

      # modifyDeletionFinalizers: nil when unchanged.
      def deletion_finalizers(volume)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        return nil unless annotations.key?(ANN_DYNAMICALLY_PROVISIONED)

        current = Array(Support.value(Support.metadata(volume), "finalizers", []))
        provisioner = annotations[ANN_DYNAMICALLY_PROVISIONED].to_s
        if MIGRATED_PLUGINS.key?(provisioner)
          return current.include?(IN_TREE_FINALIZER) ? current - [IN_TREE_FINALIZER] : nil
        end
        return nil unless provisioner.start_with?("kubernetes.io/")

        result = current.dup
        policy = reclaim_policy(volume)
        if policy == "Delete" && !result.include?(IN_TREE_FINALIZER)
          result << IN_TREE_FINALIZER
        elsif %w[Retain Recycle].include?(policy) && result.include?(IN_TREE_FINALIZER)
          result -= [IN_TREE_FINALIZER]
        end
        result -= [EXTERNAL_FINALIZER]
        result == current ? nil : result
      end

      def update_volume_phase(volume, phase, message, context)
        return volume if Support.value(Support.status(volume), "phase", "").to_s == phase

        status = Support.deep_copy(Support.status(volume)).merge("phase" => phase)
        message.to_s.empty? ? status.delete("message") : status["message"] = message
        context[:operations] << operation_status(volume, status, descriptor: PV, reason: "volume phase #{phase}", force: true)
        volume.merge("status" => status)
      end

      def update_volume_phase_with_event(volume, phase, context, type, reason, message)
        return volume if Support.value(Support.status(volume), "phase", "").to_s == phase

        updated = update_volume_phase(volume, phase, message, context)
        event(context, type, reason, message)
        updated
      end

      # unbindVolume: a controller-bound volume forgets its claim, a
      # user-bound one keeps the reference without the UID.
      def unbind_volume(volume, context)
        updated = Support.deep_copy(volume)
        if annotation?(volume, ANN_BOUND_BY_CONTROLLER)
          updated["spec"].delete("claimRef")
          annotations = updated["metadata"]["annotations"].reject { |key, _| key == ANN_BOUND_BY_CONTROLLER }
          annotations.empty? ? updated["metadata"].delete("annotations") : updated["metadata"]["annotations"] = annotations
        else
          updated["spec"]["claimRef"] = updated["spec"]["claimRef"].merge("uid" => "")
        end
        context[:operations] << operation_update(volume, updated, descriptor: PV, reason: "unbind PersistentVolume")
        update_volume_phase(updated, "Available", "", context)
      end

      # reclaimVolume.
      def reclaim_volume(volume, context)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        return unless annotations[ANN_MIGRATED_TO].to_s.empty?

        case reclaim_policy(volume)
        when "Retain" then nil
        when "Recycle" then recycle_volume(volume, context)
        when "Delete" then delete_volume(volume, context)
        else
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeUnknownReclaimPolicy",
                                         "Volume has unrecognized PersistentVolumeReclaimPolicy")
        end
      end

      # deleteVolumeOperation: hostPath is the only in-tree deleter; an
      # externally provisioned (or CSI, or migrated) volume is left to its
      # provisioner.
      #
      # A failed deletion is volume_operation_errors_total{operation_name=
      # "delete"}, by getProvisionerNameFromVolume ("N/A" when no deleter
      # matched).
      def delete_volume(volume, context)
        plugin, error = deletable_plugin(volume)
        if error
          record_volume_operation_error("N/A", "delete")
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedDelete", error)
          return
        end
        return if plugin.nil?
        return unless volume_released?(volume, context)

        begin
          @host_path_deleter.call(Support.value(Support.value(Support.spec(volume), "hostPath", {}), "path", ""))
        rescue StandardError => failure
          record_volume_operation_error("kubernetes.io/host-path", "delete")
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedDelete", failure.message)
          return
        end
        finalizers = Array(Support.value(Support.metadata(volume), "finalizers", []))
        if finalizers.include?(IN_TREE_FINALIZER)
          updated = Support.deep_copy(volume)
          updated["metadata"]["finalizers"] = finalizers - [IN_TREE_FINALIZER]
          context[:operations] << operation_update(volume, updated, descriptor: PV, reason: "remove the in-tree deletion finalizer")
        end
        remove = operation_delete(volume, descriptor: PV, reason: "delete released PersistentVolume")&.observed do |succeeded, error|
          not_found = error.respond_to?(:status) && error.status.to_i == 404
          record_volume_operation_error("kubernetes.io/host-path", "delete") unless succeeded || not_found
        end
        context[:operations] << remove if remove
      end

      def record_volume_operation_error(plugin, operation)
        ControllerMetrics.increment("volume_operation_errors_total",
                                    {"plugin_name" => plugin.to_s.empty? ? "N/A" : plugin, "operation_name" => operation})
      end

      # findDeletablePlugin: [:host_path | nil, error message | nil].
      def deletable_plugin(volume)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        provisioner = annotations[ANN_DYNAMICALLY_PROVISIONED].to_s
        unless provisioner.empty?
          return [:host_path, nil] if provisioner == "kubernetes.io/host-path"
          return [nil, nil] unless provisioner.start_with?("kubernetes.io/")

          return [nil, "no deletable volume plugin matched"]
        end
        return [nil, nil] unless annotations[ANN_MIGRATED_TO].to_s.empty?
        return [nil, nil] unless Support.value(Support.spec(volume), "csi", nil).nil?
        return [:host_path, nil] unless Support.value(Support.spec(volume), "hostPath", nil).nil?

        [nil, "error getting deleter volume plugin for volume #{Support.name(volume).dump}: no deletable volume plugin matched"]
      end

      # isVolumeReleased.
      def volume_released?(volume, context)
        reference = claim_ref(volume)
        return false if reference.nil? || Support.value(reference, "uid", "").to_s.empty?

        claim = find_claim(context, Support.value(reference, "namespace", ""), Support.value(reference, "name", ""))
        return true unless claim && Support.uid(claim).to_s == Support.value(reference, "uid", "").to_s

        volume_name = Support.value(Support.spec(claim), "volumeName", "").to_s
        !volume_name.empty? && volume_name != Support.name(volume)
      end

      # recycleVolumeOperation with the hostPath/NFS recycler Pod
      # (RecycleVolumeByWatchingPodUntilCompletion), one step per sync.
      def recycle_volume(volume, context)
        return unless volume_released?(volume, context)

        reference = claim_ref(volume)
        users = pods_by_claim(context, Support.value(reference, "namespace", ""), Support.value(reference, "name", ""))
          .reject { |pod| pod_terminated?(pod) }.map { |pod| "#{Support.namespace(pod)}/#{Support.name(pod)}" }.sort
        cached = find_claim(context, Support.value(reference, "namespace", ""), Support.value(reference, "name", ""))
        if !users.empty? && cached.nil?
          event(context, "Normal", "VolumeFailedRecycle", "Volume is used by pods: #{users.join(",")}")
          return
        end

        source = recycler_source(volume)
        if source.nil?
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedRecycle",
                                         "No recycler plugin found for the volume!")
          return
        end

        pod_name = "recycler-for-#{Support.name(volume)}"
        pod = context[:adapter] && context[:adapter].find(POD, name: pod_name, namespace: "default")
        if pod.nil?
          context[:operations] << operation_create(recycler_pod(pod_name, volume, source), descriptor: POD,
                                                                                           reason: "start the volume recycler")
          context[:requeue] = RECHECK_SECONDS
          return
        end

        case Support.value(Support.status(pod), "phase", "").to_s
        when "Succeeded"
          context[:operations] << operation_delete(pod, descriptor: POD, reason: "remove the finished recycler")
          event(context, "Normal", "VolumeRecycled", "Volume recycled")
          unbind_volume(volume, context)
        when "Failed"
          context[:operations] << operation_delete(pod, descriptor: POD, reason: "remove the failed recycler")
          message = Support.value(Support.status(pod), "message", "").to_s
          update_volume_phase_with_event(volume, "Failed", context, "Warning", "VolumeFailedRecycle",
                                         "Recycle failed: pod failed, pod.Status.Message #{message}")
        else
          context[:requeue] = RECHECK_SECONDS
        end
      end

      def recycler_source(volume)
        spec = Support.spec(volume)
        return {"hostPath" => Support.deep_copy(spec["hostPath"]), minimum: 60} if spec["hostPath"]
        return {"nfs" => Support.deep_copy(spec["nfs"]), minimum: 300} if spec["nfs"]

        nil
      end

      # NewPersistentVolumeRecyclerPodTemplate with the plugin's timeout:
      # max(minimum, 30 s per GiB).
      def recycler_pod(name, volume, source)
        size_gib = (storage(volume_capacity(volume)) / (1024**3)).ceil
        timeout = [source[:minimum], 30 * size_gib].max
        {"apiVersion" => "v1", "kind" => "Pod",
         "metadata" => {"name" => name, "namespace" => "default"},
         "spec" => {"activeDeadlineSeconds" => timeout, "restartPolicy" => "Never",
                    "volumes" => [{"name" => "vol"}.merge(source.except(:minimum))],
                    "containers" => [{"name" => "pv-recycler", "image" => RECYCLER_IMAGE, "command" => ["/bin/sh"],
                                      "args" => ["-c", RECYCLER_SCRIPT], "volumeMounts" => [{"name" => "vol", "mountPath" => "/scrub"}]}]}}
      end

      # ---------------------------------------------------------- matching

      # findBestMatchForClaim: the access-mode groups that contain the
      # request, smallest group first; in each, FindMatchingVolume.
      def find_best_match(claim, volumes, delay)
        requested = access_modes(claim)
        groups = Array(volumes).group_by { |volume| mode_key(access_modes(volume)) }
        groups.keys.select { |key| access_modes_contain?(key.split(","), requested) }
          .sort_by { |key| [key.split(",").length, key] }.each do |key|
          best = find_matching_volume(claim, groups[key], delay)
          return best if best
        end
        nil
      end

      # FindMatchingVolume (node = nil: the controller binds without topology).
      def find_matching_volume(claim, volumes, delay)
        requested = storage(claim_request(claim))
        selector = Support.value(Support.spec(claim), "selector", nil)
        smallest = nil
        volumes.sort_by { |volume| Support.name(volume) }.each do |volume|
          next if claim_ref(volume) && !bound_to_claim?(volume, claim)

          size = storage(volume_capacity(volume))
          next if size < requested
          next if volume_mode(claim) != volume_mode(volume)
          next if vac(claim) != vac(volume)
          next unless Support.value(Support.metadata(volume), "deletionTimestamp", nil).nil?
          return volume if bound_to_claim?(volume, claim)
          next if delay
          next unless Support.value(Support.status(volume), "phase", "").to_s == "Available"
          next if selector && !Support.selector_matches?(selector, volume)
          next if volume_class(volume) != claim_class(claim)

          smallest = volume if smallest.nil? || storage(volume_capacity(smallest)) > size
        end
        smallest
      end

      # ---------------------------------------------------------- helpers

      def event(context, type, reason, message, involved: nil)
        entry = {"type" => type, "reason" => reason, "message" => message}
        if involved
          entry["involvedObject"] = {"apiVersion" => "v1", "kind" => Support.kind(involved), "namespace" => Support.namespace(involved),
                                     "name" => Support.name(involved), "uid" => Support.uid(involved)}.compact
        end
        context[:events] << entry
      end

      def annotation?(object, key) = (Support.value(Support.metadata(object), "annotations", {}) || {}).key?(key)

      def set_annotation(object, key, value)
        object["metadata"] ||= {}
        object["metadata"]["annotations"] = (object["metadata"]["annotations"] || {}).merge(key => value)
      end

      def claim_ref(volume)
        reference = Support.value(Support.spec(volume), "claimRef", nil)
        reference.is_a?(Hash) ? reference : nil
      end

      # IsVolumeBoundToClaim.
      def bound_to_claim?(volume, claim)
        reference = claim_ref(volume)
        return false unless reference
        return false unless Support.value(reference, "name", "") == Support.name(claim) &&
                            Support.value(reference, "namespace", "") == Support.namespace(claim)

        uid = Support.value(reference, "uid", "").to_s
        uid.empty? || uid == Support.uid(claim).to_s
      end

      def claim_class(claim)
        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        return annotations[ANN_BETA_STORAGE_CLASS].to_s if annotations.key?(ANN_BETA_STORAGE_CLASS)

        Support.value(Support.spec(claim), "storageClassName", "").to_s
      end

      def claim_has_class?(claim)
        annotations = Support.value(Support.metadata(claim), "annotations", {}) || {}
        annotations.key?(ANN_BETA_STORAGE_CLASS) || !Support.spec(claim)["storageClassName"].nil?
      end

      def volume_class(volume)
        annotations = Support.value(Support.metadata(volume), "annotations", {}) || {}
        return annotations[ANN_BETA_STORAGE_CLASS].to_s if annotations.key?(ANN_BETA_STORAGE_CLASS)

        Support.value(Support.spec(volume), "storageClassName", "").to_s
      end

      def vac(object) = Support.value(Support.spec(object), "volumeAttributesClassName", "").to_s
      def volume_mode(object) = (Support.value(Support.spec(object), "volumeMode", nil) || "Filesystem").to_s
      def access_modes(object) = Array(Support.value(Support.spec(object), "accessModes", [])).map(&:to_s)
      def access_modes_contain?(available, requested) = requested.all? { |mode| available.include?(mode) }
      def mode_key(modes) = ACCESS_MODE_ORDER.select { |mode| modes.include?(mode) }.join(",")
      def reclaim_policy(volume) = Support.value(Support.spec(volume), "persistentVolumeReclaimPolicy", "").to_s
      def volume_capacity(volume) = Support.value(Support.value(Support.spec(volume), "capacity", {}) || {}, "storage", nil)

      def claim_request(claim)
        Support.value(Support.value(Support.value(Support.spec(claim), "resources", {}) || {}, "requests", {}) || {}, "storage", nil)
      end

      def storage(quantity) = quantity.nil? ? 0 : quantity_base(quantity)

      def find_volume(context, name) = Array(context[:volumes]).find { |volume| Support.name(volume) == name.to_s }

      def find_claim(context, namespace, claim_name)
        if context[:claims]
          return Array(context[:claims]).find do |claim|
            Support.namespace(claim) == namespace.to_s && Support.name(claim) == claim_name.to_s
          end
        end

        context[:adapter]&.find(PVC, name: claim_name.to_s, namespace: namespace.to_s)
      end

      def live_claim(context, namespace, claim_name)
        adapter = context[:adapter]
        return nil unless adapter.respond_to?(:find_live)

        adapter.find_live(PVC, name: claim_name.to_s, namespace: namespace.to_s)
      rescue StandardError
        nil
      end

      def find_class(context, class_name) = Array(context[:classes]).find { |item| Support.name(item) == class_name.to_s }

      # GetDefaultClass: the newest default class, then by name.
      def default_class(classes)
        defaults = Array(classes).select do |item|
          annotations = Support.value(Support.metadata(item), "annotations", {}) || {}
          annotations[ANN_DEFAULT_CLASS] == "true" || annotations[ANN_BETA_DEFAULT_CLASS] == "true"
        end
        defaults.min_by do |item|
          created = Support.parse_time(Support.value(Support.metadata(item), "creationTimestamp", nil))
          [-(created ? created.to_r : 0), Support.name(item)]
        end
      end

      def pods_using(claim, context) = pods_by_claim(context, Support.namespace(claim), Support.name(claim))

      def pods_by_claim(context, namespace, claim_name)
        pods = context[:pods] || list_storage_objects(context[:adapter], POD, namespace: namespace)
        Array(pods).select do |pod|
          Support.namespace(pod).to_s == namespace.to_s &&
            Array(Support.value(Support.spec(pod), "volumes", [])).any? do |volume|
              Support.value(Support.value(volume, "persistentVolumeClaim", {}) || {}, "claimName", nil).to_s == claim_name.to_s ||
                (volume.is_a?(Hash) && volume["ephemeral"] && "#{Support.name(pod)}-#{volume["name"]}" == claim_name.to_s)
            end
        end
      end

      # util.IsPodTerminated: terminal phase, or deleted with no running container.
      def pod_terminated?(pod)
        phase = Support.value(Support.status(pod), "phase", "").to_s
        return true if %w[Succeeded Failed].include?(phase)
        return false if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

        Array(Support.value(Support.status(pod), "containerStatuses", [])).none? do |status|
          (Support.value(status, "state", {}) || {}).key?("running")
        end
      end
    end

    # pkg/controller/volume/attachdetach (v1.36.2) for CSI volumes: the
    # desired state is every attachable volume of every scheduled,
    # not-terminated Pod on a node whose kubelet leaves attach/detach to the
    # controller (volumes.kubernetes.io/controller-managed-attach-detach);
    # the actual state is the VolumeAttachments.  The reconciler detaches
    # what is no longer desired once the node reports it unmounted (or
    # maxWaitForUnmountDuration has passed), and attaches what is desired
    # through a VolumeAttachment named csi-<sha256(handle+driver+node)> --
    # refusing a second node for a volume that cannot be multi-attached
    # (Multi-Attach error).
    class PersistentVolumeAttachDetachController < BaseController
      include InfrastructureStorageSupport

      PV = ResourceDescriptor.parse("PersistentVolume")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      POD = ResourceDescriptor.parse("Pod")
      NODE = ResourceDescriptor.parse("Node")
      CSI_DRIVER = ResourceDescriptor.parse({"apiVersion" => "storage.k8s.io/v1", "kind" => "CSIDriver"},
                                            resource: "csidrivers", scope: :cluster)
      VOLUME_ATTACHMENT = ResourceDescriptor.parse({"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment"},
                                                   resource: "volumeattachments", scope: :cluster)
      MANAGED_ANNOTATION = "volumes.kubernetes.io/controller-managed-attach-detach"
      CSI_PLUGIN = "kubernetes.io/csi"
      MAX_WAIT_FOR_UNMOUNT = 6 * 60
      RECHECK_SECONDS = 1.0

      def initialize(*, clock: -> { Time.now.utc }, **)
        super(*, **)
        @clock = clock
        @detach_requested = {}
        @reported = {}
        @mutex = Mutex.new
      end

      def plan(volume, store: nil, pods: nil, claims: nil, volume_attachments: nil, attachments: nil, nodes: nil, csi_drivers: nil,
               volumes: nil, **_options)
        adapter = adapter_for_storage(store)
        pods ||= list_storage_objects(adapter, POD, namespace: :all)
        claims ||= list_storage_objects(adapter, PVC, namespace: :all)
        volume_attachments ||= attachments || list_storage_objects(adapter, VOLUME_ATTACHMENT, namespace: :all)
        nodes ||= list_storage_objects(adapter, NODE, namespace: :all)
        csi_drivers ||= list_storage_objects(adapter, CSI_DRIVER, namespace: :all)
        context = {operations: [], events: [], requeue: nil, detaching: []}
        csi = Support.value(Support.spec(volume), "csi", nil)
        unless csi.is_a?(Hash) && attach_required?(csi, csi_drivers)
          report_attached_volumes(volume, adapter, volumes, volume_attachments, nodes, csi_drivers, context)
          return result_for(volume, context)
        end

        driver = csi["driver"].to_s
        handle = csi["volumeHandle"].to_s
        unique_name = "#{CSI_PLUGIN}/#{driver}^#{handle}"
        desired = desired_pods_by_node(volume, pods, claims, nodes)
        existing = Array(volume_attachments).select { |attachment| attachment_for_volume?(attachment, volume) }
        attached_nodes = existing.reject { |attachment| deleting?(attachment) }.map { |attachment| attachment_node(attachment) }

        # Detach: attachments no scheduled Pod needs any more.
        existing.each do |attachment|
          node_name = attachment_node(attachment)
          next if desired.key?(node_name) || deleting?(attachment)

          key = [Support.name(volume), node_name]
          if volume_in_use?(nodes, node_name, unique_name)
            first = @mutex.synchronize { @detach_requested[key] ||= @clock.call }
            if @clock.call - first < MAX_WAIT_FOR_UNMOUNT
              context[:requeue] = RECHECK_SECONDS
              next
            end
          end
          @mutex.synchronize { @detach_requested.delete(key) }
          context[:detaching] << Support.name(attachment)
          detach = operation_delete(attachment, descriptor: VOLUME_ATTACHMENT, reason: "DetachVolume.Detach")
          # Still mounted after maxWaitForUnmountDuration: a forced detach.
          if detach && volume_in_use?(nodes, node_name, unique_name)
            detach = detach.observed do |succeeded, _|
              if succeeded
                ControllerMetrics.increment("attach_detach_controller_attachdetach_controller_forced_detaches",
                                            {"reason" => "timeout"})
              end
            end
          end
          context[:operations] << detach if detach
        end

        # Attach: desired nodes without an attachment.
        desired.sort.each do |node_name, node_pods|
          @mutex.synchronize { @detach_requested.delete([Support.name(volume), node_name]) }
          attachment = existing.find { |candidate| attachment_node(candidate) == node_name && !deleting?(candidate) }
          if attachment
            report_attach_result(volume, attachment, node_pods, context)
            next
          end

          others = attached_nodes - [node_name]
          if !others.empty? && !multi_attach_allowed?(volume)
            report_multi_attach_error(volume, node_pods, desired.slice(*others).values.flatten, context)
            next
          end

          context[:operations] << operation_create(volume_attachment(volume, driver, handle, node_name), descriptor: VOLUME_ATTACHMENT,
                                                                                                         reason: "AttachVolume.Attach")
          attached_nodes << node_name
          context[:requeue] = RECHECK_SECONDS
        end
        report_attached_volumes(volume, adapter, volumes, volume_attachments, nodes, csi_drivers, context)
        result_for(volume, context)
      end

      # The A/D controller's plugins that can serve a volume (fc, iscsi and
      # csi -- ProbeAttachableVolumePlugins), by
      # GetFullQualifiedPluginNameForVolume; nil for any other volume.
      def self.attachable_plugin(source)
        return nil unless source.is_a?(Hash)
        return "kubernetes.io/csi:#{source.dig("csi", "driver")}" if source["csi"].is_a?(Hash)
        return "kubernetes.io/fc" if source["fc"].is_a?(Hash)
        return "kubernetes.io/iscsi" if source["iscsi"].is_a?(Hash)

        nil
      end

      # attachDetachStateCollector: volumes in use by the scheduled Pods of
      # each node, by plugin (storage_count_attachable_volumes_in_use), and
      # the volumes of the desired (every attachable volume a managed node's
      # running Pods need) and actual (attached VolumeAttachments) state of
      # the world by plugin (attachdetach_controller_total_volumes).
      def self.state_counts(pods:, claims:, volumes:, nodes:, attachments:, drivers:)
        pv_by_name = Array(volumes).to_h { |pv| [Support.name(pv), pv] }
        claim_by_key = Array(claims).to_h { |claim| [[Support.namespace(claim).to_s, Support.name(claim).to_s], claim] }
        managed = Array(nodes).select do |node|
          (Support.value(Support.metadata(node), "annotations", {}) || {})[MANAGED_ANNOTATION] == "true"
        end
          .to_h { |node| [Support.name(node), true] }
        planner = allocate
        in_use = Hash.new(0)
        desired = {}
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName", "").to_s
          next if node_name.empty?

          Array(Support.value(Support.spec(pod), "volumes", [])).each do |entry|
            source = volume_source(pod, entry, claim_by_key, pv_by_name)
            plugin = attachable_plugin(source)
            next unless plugin

            in_use[[node_name, plugin]] += 1
            next unless managed[node_name] && !planner.send(:terminated?, pod)
            next if source["csi"].is_a?(Hash) && !planner.send(:attach_required?, source["csi"], drivers)

            desired[[node_name, source]] = plugin
          end
        end
        totals = Hash.new(0)
        desired.each_value { |plugin| totals[[plugin, "desired_state_of_world"]] += 1 }
        Array(attachments).each do |attachment|
          next unless Support.value(Support.status(attachment), "attached", false) == true

          pv = pv_by_name[Support.value(Support.value(Support.spec(attachment), "source", {}) || {}, "persistentVolumeName", nil).to_s]
          plugin = attachable_plugin(pv && Support.spec(pv))
          totals[[plugin, "actual_state_of_world"]] += 1 if plugin
        end
        {in_use: in_use, totals: totals}
      end

      # CreateVolumeSpec: a claim (or a generic ephemeral volume's claim)
      # resolves to its bound PersistentVolume's spec, anything else is the
      # Pod's own volume source.
      def self.volume_source(pod, entry, claim_by_key, pv_by_name)
        claim_name = Support.value(Support.value(entry, "persistentVolumeClaim", {}) || {}, "claimName", nil)
        claim_name ||= "#{Support.name(pod)}-#{Support.value(entry, "name", "")}" if Support.value(entry, "ephemeral", nil).is_a?(Hash)
        return entry unless claim_name

        claim = claim_by_key[[Support.namespace(pod).to_s, claim_name.to_s]]
        pv = claim && pv_by_name[Support.value(Support.spec(claim), "volumeName", "").to_s]
        pv && Support.spec(pv)
      end

      private

      # nodeStatusUpdater: node.status.volumesAttached lists, per managed
      # node, every volume the controller has attached there (a CSI volume's
      # devicePath is empty; attacher.Attach returns none), and a volume
      # stops being reported the moment its detach starts so the kubelet
      # cannot begin a new mount of it.  The list is the whole node's, from
      # every VolumeAttachment, so any volume's sync repairs it; only a node
      # whose list changes is patched.
      def report_attached_volumes(volume, adapter, volumes, attachments, nodes, drivers, context)
        volumes ||= list_storage_objects(adapter, PV, namespace: :all)
        by_name = Array(volumes).to_h { |pv| [Support.name(pv), pv] }
        by_name[Support.name(volume)] = volume
        managed = Array(nodes).select do |node|
          (Support.value(Support.metadata(node), "annotations", {}) || {})[MANAGED_ANNOTATION] == "true"
        end
        desired = Hash.new { |hash, key| hash[key] = [] }
        Array(attachments).each do |attachment|
          next if deleting?(attachment) || context[:detaching].include?(Support.name(attachment))
          next unless Support.value(Support.status(attachment), "attached", false) == true

          pv = by_name[Support.value(Support.value(Support.spec(attachment), "source", {}) || {}, "persistentVolumeName", nil).to_s]
          csi = pv && Support.value(Support.spec(pv), "csi", nil)
          next unless csi.is_a?(Hash) && attach_required?(csi, drivers)

          desired[attachment_node(attachment)] << {"name" => "#{CSI_PLUGIN}/#{csi["driver"]}^#{csi["volumeHandle"]}", "devicePath" => ""}
        end
        managed.each do |node|
          wanted = desired.fetch(Support.name(node), []).uniq { |entry| entry["name"] }.sort_by { |entry| entry["name"] }
          current = Array(Support.value(Support.status(node), "volumesAttached", [])).map do |entry|
            {"name" => Support.value(entry, "name", "").to_s, "devicePath" => Support.value(entry, "devicePath", "").to_s}
          end.sort_by { |entry| entry["name"] }
          next if current == wanted

          context[:operations] << operation_status_merge(node, {"volumesAttached" => wanted.empty? ? nil : wanted}, descriptor: NODE,
                                                                                                                    reason: "node volumesAttached")
        end
      end

      def result_for(volume, context)
        ReconcileResult.new(operations: context[:operations], events: context[:events], controller: name, key: Support.name(volume),
                            requeue_after: context[:requeue])
      end

      # csi plugin CanAttach: attachRequired defaults to true, also when the
      # CSIDriver object does not exist.
      def attach_required?(csi, drivers)
        driver = Array(drivers).find { |item| Support.name(item) == csi["driver"].to_s }
        return true if driver.nil?

        Support.value(Support.spec(driver), "attachRequired", true) != false
      end

      # desiredStateOfWorldPopulator: node => Pods using the volume.
      def desired_pods_by_node(volume, pods, claims, nodes)
        managed = Array(nodes).select do |node|
          (Support.value(Support.metadata(node), "annotations", {}) || {})[MANAGED_ANNOTATION] == "true"
        end.map { |node| Support.name(node) }
        claim_keys = Array(claims).select { |claim| Support.value(Support.spec(claim), "volumeName", "").to_s == Support.name(volume) }
          .map { |claim| [Support.namespace(claim).to_s, Support.name(claim).to_s] }
        result = Hash.new { |hash, key| hash[key] = [] }
        Array(pods).each do |pod|
          node_name = Support.value(Support.spec(pod), "nodeName", "").to_s
          next if node_name.empty? || !managed.include?(node_name) || terminated?(pod)

          uses = Array(Support.value(Support.spec(pod), "volumes", [])).any? do |entry|
            claim_name = Support.value(Support.value(entry, "persistentVolumeClaim", {}) || {}, "claimName", nil)
            claim_name && claim_keys.include?([Support.namespace(pod).to_s, claim_name.to_s])
          end
          result[node_name] << pod if uses
        end
        result.to_h
      end

      # util.IsPodTerminated.
      def terminated?(pod)
        phase = Support.value(Support.status(pod), "phase", "").to_s
        return true if %w[Succeeded Failed].include?(phase)
        return false if Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?

        Array(Support.value(Support.status(pod), "containerStatuses", [])).none? do |status|
          (Support.value(status, "state", {}) || {}).key?("running")
        end
      end

      # util.IsMultiAttachAllowed: an RWX/ROX volume, or one with no modes.
      def multi_attach_allowed?(volume)
        modes = Array(Support.value(Support.spec(volume), "accessModes", [])).map(&:to_s)
        modes.empty? || modes.intersect?(%w[ReadWriteMany ReadOnlyMany])
      end

      def volume_in_use?(nodes, node_name, unique_name)
        node = Array(nodes).find { |item| Support.name(item) == node_name }
        node && Array(Support.value(Support.status(node), "volumesInUse", [])).map(&:to_s).include?(unique_name)
      end

      def attachment_for_volume?(attachment, volume)
        source = Support.value(Support.spec(attachment), "source", {}) || {}
        Support.value(source, "persistentVolumeName", nil).to_s == Support.name(volume)
      end

      def attachment_node(attachment) = Support.value(Support.spec(attachment), "nodeName", "").to_s
      def deleting?(attachment) = !Support.value(Support.metadata(attachment), "deletionTimestamp", nil).nil?

      # getAttachmentName.
      def volume_attachment(volume, driver, handle, node_name)
        {"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment",
         "metadata" => {"name" => "csi-#{Digest::SHA256.hexdigest("#{handle}#{driver}#{node_name}")}"},
         "spec" => {"attacher" => driver, "nodeName" => node_name, "source" => {"persistentVolumeName" => Support.name(volume)}}}
      end

      # operation_generator: SuccessfulAttachVolume / FailedAttachVolume on
      # the Pods, once per attachment outcome.
      def report_attach_result(volume, attachment, pods, context)
        status = Support.status(attachment)
        outcome = if Support.value(status, "attached", false) == true
                    ["Normal", "SuccessfulAttachVolume", "AttachVolume.Attach succeeded for volume #{Support.name(volume).dump} "]
                  elsif (error = Support.value(Support.value(status, "attachError", {}) || {}, "message", nil))
                    ["Warning", "FailedAttachVolume", "AttachVolume.Attach failed for volume #{Support.name(volume).dump} : #{error}"]
                  end
        unless outcome
          context[:requeue] = RECHECK_SECONDS
          return
        end

        # One event per attachment outcome, not one per sync.
        key = Support.name(attachment)
        already = @mutex.synchronize do
          seen = @reported[key] == outcome[1]
          @reported[key] = outcome[1]
          @reported.shift while @reported.length > 4096
          seen
        end
        return if already

        pods.each { |pod| context[:events] << pod_event(pod, *outcome) }
      end

      def report_multi_attach_error(volume, pods, blocking, context)
        prefix = "Multi-Attach error for volume #{Support.name(volume).dump}"
        if blocking.empty?
          pods.each do |pod|
            context[:events] << pod_event(pod, "Warning", "FailedAttachVolume",
                                          "#{prefix} Volume is already exclusively attached to one node and can't be attached to another")
          end
          return
        end

        pods.each do |pod|
          local = blocking.select { |other| Support.namespace(other) == Support.namespace(pod) }.map { |other| Support.name(other) }
          elsewhere = blocking.length - local.length
          message = if local.empty?
                      "Volume is already used by #{elsewhere} pod(s) in different namespaces"
                    else
                      text = "Volume is already used by pod(s) #{local.join(", ")}"
                      elsewhere.positive? ? "#{text} and #{elsewhere} pod(s) in different namespaces" : text
                    end
          context[:events] << pod_event(pod, "Warning", "FailedAttachVolume", "#{prefix} #{message}")
        end
      end

      def pod_event(pod, type, reason, message)
        {"type" => type, "reason" => reason, "message" => message,
         "involvedObject" => {"apiVersion" => "v1", "kind" => "Pod", "namespace" => Support.namespace(pod), "name" => Support.name(pod),
                              "uid" => Support.uid(pod)}.compact}
      end
    end

    # Expands a PVC only after its bound PV reports enough capacity. Filesystem
    # claims retain FileSystemResizePending until node expansion is observed.
    class PersistentVolumeExpanderController < BaseController
      include InfrastructureStorageSupport

      PV = ResourceDescriptor.parse("PersistentVolume")
      PVC = ResourceDescriptor.parse("PersistentVolumeClaim")
      STORAGE_CLASS = ResourceDescriptor.parse("StorageClass")

      def plan(claim, store: nil, persistent_volume: nil, volume: nil, storage_class: nil,
               allow_volume_expansion: nil, node_expanded: false, provider: nil,
               cloud_provider: nil, cloud: nil, **_options)
        adapter = adapter_for_storage(store)
        pv = persistent_volume || volume
        unless pv
          volume_name = Support.value(Support.spec(claim), "volumeName", nil).to_s
          pv = list_storage_objects(adapter, PV, namespace: :all).find { |candidate| Support.name(candidate) == volume_name }
        end
        return no_expansion_result(claim) unless pv

        requested = claim_requested_capacity(claim)
        current = claim_status_capacity(claim)
        return no_expansion_result(claim) unless requested > current

        class_object = storage_class
        if class_object.nil? && adapter
          class_name = Support.value(Support.spec(claim), "storageClassName", nil).to_s
          unless class_name.empty?
            class_object = list_storage_objects(adapter, STORAGE_CLASS, namespace: :all).find do |candidate|
              Support.name(candidate) == class_name
            end
          end
        end
        expansion_allowed = if allow_volume_expansion.nil?
                              class_spec = Support.spec(class_object || {})
                              Support.value(class_spec, "allowVolumeExpansion",
                                            Support.value(class_object || {}, "allowVolumeExpansion", false)) == true
                            else
                              !!allow_volume_expansion
                            end
        return failed_expansion_result(claim, "VolumeExpansionNotAllowed") unless expansion_allowed

        pv_capacity_value = volume_capacity_value(pv)
        pv_capacity = quantity_base(pv_capacity_value)
        if pv_capacity < requested
          expanded = call_provider(provider_from(provider || cloud_provider || cloud), %i[expand_volume expand], positional: [pv, claim],
                                                                                                                 keywords: {volume: pv, claim: claim,
                                                                                                                            requested_capacity: requested})
          pv_capacity_value = provider_capacity(expanded) || pv_capacity_value
          pv_capacity = quantity_base(pv_capacity_value)
        end
        return resizing_result(claim, requested) if pv_capacity < requested

        operations = []
        if provider_capacity_candidate?(pv, pv_capacity_value)
          candidate_pv = Support.deep_copy(pv)
          candidate_pv["spec"] ||= {}
          candidate_pv["spec"]["capacity"] ||= {}
          candidate_pv["spec"]["capacity"]["storage"] = pv_capacity_value
          pv_operation = operation_update(pv, candidate_pv, descriptor: PV, reason: "persistent volume expansion")
          operations << pv_operation if pv_operation
        end
        candidate_status = Support.deep_copy(Support.status(claim))
        candidate_status["capacity"] = Support.deep_copy(Support.value(Support.spec(pv), "capacity", {}))
        candidate_status["capacity"] ||= {}
        candidate_status["capacity"]["storage"] = pv_capacity_value
        conditions = remove_conditions(candidate_status["conditions"], "Resizing", "ResizeStarted", "ResizeFailed")
        filesystem = Support.value(Support.spec(pv), "volumeMode", "Filesystem").to_s != "Block"
        conditions = if filesystem && !node_expanded
                       upsert_condition(conditions, "FileSystemResizePending", "True", "ControllerResizeInProgress")
                     else
                       remove_conditions(conditions, "FileSystemResizePending")
                     end
        candidate_status["conditions"] = conditions
        status_operation = operation_status(claim, candidate_status, descriptor: PVC, reason: "persistent volume expansion")
        operations << status_operation if status_operation
        ReconcileResult.new(operations: operations, status: candidate_status,
                            events: [{"type" => "Normal", "reason" => "VolumeResizeSuccessful",
                                      "message" => "persistent volume claim #{name_key(claim)} expanded"}],
                            controller: name, key: name_key(claim))
      end

      private

      def no_expansion_result(claim)
        ReconcileResult.new(operations: [], status: Support.status(claim), controller: name,
                            key: name_key(claim))
      end

      def failed_expansion_result(claim, reason)
        status = Support.deep_copy(Support.status(claim))
        status["conditions"] = upsert_condition(status["conditions"], "Resizing", "False", reason)
        operation = operation_status(claim, status, descriptor: PVC, reason: "persistent volume expansion failed")
        ReconcileResult.new(operations: [operation].compact, status: status,
                            events: [{"type" => "Warning", "reason" => "VolumeResizeFailed",
                                      "message" => "persistent volume claim #{name_key(claim)} cannot be expanded: #{reason}"}],
                            controller: name, key: name_key(claim))
      end

      def resizing_result(claim, requested)
        status = Support.deep_copy(Support.status(claim))
        status["conditions"] = upsert_condition(status["conditions"], "Resizing", "True", "ExternalExpanding",
                                                message: "waiting for volume capacity #{requested}")
        operation = operation_status(claim, status, descriptor: PVC, reason: "persistent volume expansion pending")
        ReconcileResult.new(operations: [operation].compact, status: status,
                            events: [{"type" => "Normal", "reason" => "VolumeResizeSuccessful",
                                      "message" => "persistent volume claim #{name_key(claim)} expansion is pending"}],
                            controller: name, key: name_key(claim))
      end

      def claim_requested_capacity(claim)
        resources = Support.value(Support.spec(claim), "resources", {})
        quantity_base(Support.value(Support.value(resources, "requests", {}), "storage", 0))
      end

      def claim_status_capacity(claim)
        quantity_base(Support.value(Support.value(Support.status(claim), "capacity", {}), "storage", 0))
      end

      def volume_capacity_value(volume)
        spec_capacity = Support.value(Support.value(Support.spec(volume), "capacity", {}), "storage", nil)
        status_capacity = Support.value(Support.value(Support.status(volume), "capacity", {}), "storage", nil)
        spec_capacity || status_capacity || 0
      end

      def provider_capacity(value)
        return nil if value.nil? || value == false
        return Support.value(value, "capacity", nil) if value.is_a?(Hash)
        return value if value.is_a?(Numeric) || value.is_a?(String)

        nil
      end

      def provider_capacity_candidate?(pv, capacity)
        quantity_base(capacity) > quantity_base(volume_capacity_value(pv))
      end
    end

    # Aggregates rules into ClusterRoles selected by aggregationRule. Only the
    # selected target is updated; canonical rule de-duplication is replay safe.
    class ClusterRoleAggregationController < BaseController
      include InfrastructureStorageSupport

      CLUSTER_ROLE = ResourceDescriptor.parse("ClusterRole")

      def plan(target, store: nil, cluster_roles: nil, roles: nil, **_options)
        return empty_result(target) unless Support.kind(target) == "ClusterRole"

        adapter = adapter_for_storage(store)
        cluster_roles ||= roles || list_storage_objects(adapter, CLUSTER_ROLE, namespace: :all)
        selectors = Array(Support.value(Support.value(target, "aggregationRule", {}), "clusterRoleSelectors", nil))
        return empty_result(target) if selectors.empty?

        selected = Array(cluster_roles).select do |role|
          Support.kind(role) == "ClusterRole" && Support.name(role) != Support.name(target) &&
            selectors.any? { |selector| Support.selector_matches?(selector, role) }
        end.sort_by { |role| Support.name(role) }
        rules = []
        seen = {}
        selected.each do |role|
          Array(Support.value(role, "rules", [])).each do |rule|
            key = canonical_rule(rule)
            next if seen[key]

            seen[key] = true
            rules << Support.deep_copy(rule)
          end
        end
        candidate = Support.deep_copy(target)
        candidate["rules"] = rules
        update = operation_update(target, candidate, descriptor: CLUSTER_ROLE, reason: "cluster role aggregation")
        events = if update
                   [{"type" => "Normal", "reason" => "ClusterRoleAggregated",
                     "message" => "cluster role #{Support.name(target)} aggregated #{rules.length} rule(s)"}]
                 else
                   []
                 end
        ReconcileResult.new(operations: [update].compact, status: Support.status(target), events: events,
                            controller: name, key: Support.name(target))
      end

      private

      def empty_result(target)
        ReconcileResult.new(operations: [], status: Support.status(target), controller: name,
                            key: Support.name(target))
      end
    end

    # Registration metadata stays next to concrete implementations so registry
    # integration can avoid a CorpusController fallback. register! is explicit
    # and never runs while this file is merely required.
    module InfrastructureStorageControllerFactory
      VERSION = "v1.36.2"
      NAMES = %w[
        taint-eviction-controller device-taint-eviction-controller service-lb-controller
        node-route-controller cloud-node-lifecycle-controller persistentvolume-binder-controller
        persistent-volume-attach-detach-controller persistent-volume-expander-controller
        clusterrole-aggregation-controller
      ].freeze
      CONTROLLER_NAMES = NAMES

      IMPLEMENTATIONS = {
        "taint-eviction-controller" => TaintEvictionController,
        "device-taint-eviction-controller" => DeviceTaintEvictionController,
        "service-lb-controller" => ServiceLBController,
        "node-route-controller" => NodeRouteController,
        "cloud-node-lifecycle-controller" => CloudNodeLifecycleController,
        "persistentvolume-binder-controller" => PersistentVolumeBinderController,
        "persistent-volume-attach-detach-controller" => PersistentVolumeAttachDetachController,
        "persistent-volume-expander-controller" => PersistentVolumeExpanderController,
        "clusterrole-aggregation-controller" => ClusterRoleAggregationController
      }.freeze

      METADATA = {
        "taint-eviction-controller" => {
          kind: "Node", feature_gates: ["SeparateTaintEvictionController"],
          startup_conditions: ["API server available"], sync_targets: %w[Node Pod],
          status_fields: ["taints"], events: ["TaintManagerEviction"]
        },
        "device-taint-eviction-controller" => {
          kind: "Node", feature_gates: ["DynamicResourceAllocation"],
          startup_conditions: ["API server available"], sync_targets: %w[Node Pod],
          status_fields: ["taints"], events: ["DeviceTaintEviction"]
        },
        "service-lb-controller" => {
          kind: "Service", feature_gates: [], startup_conditions: ["cloud provider configured"],
          sync_targets: %w[Service Node LoadBalancer], status_fields: ["loadBalancer"],
          events: %w[EnsuringLoadBalancer EnsuredLoadBalancer DeletingLoadBalancer]
        },
        "node-route-controller" => {
          kind: "Node", feature_gates: [], startup_conditions: ["cloud provider configured"],
          sync_targets: %w[Node Route], status_fields: ["routes"],
          events: %w[RouteCreated RouteDeleted]
        },
        "cloud-node-lifecycle-controller" => {
          kind: "Node", feature_gates: [], startup_conditions: ["cloud provider configured"],
          sync_targets: ["Node"], status_fields: ["conditions"], events: ["CloudNodeNotReady"]
        },
        "persistentvolume-binder-controller" => {
          kind: "PersistentVolumeClaim", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: %w[PersistentVolume PersistentVolumeClaim], status_fields: %w[phase capacity],
          events: %w[ProvisioningSucceeded ProvisioningFailed]
        },
        "persistent-volume-attach-detach-controller" => {
          kind: "PersistentVolume", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: %w[PersistentVolume Node VolumeAttachment], status_fields: ["attached"],
          events: %w[SuccessfulAttachVolume FailedAttachVolume]
        },
        "persistent-volume-expander-controller" => {
          kind: "PersistentVolumeClaim", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: %w[PersistentVolumeClaim PersistentVolume], status_fields: %w[capacity conditions],
          events: %w[VolumeResizeSuccessful VolumeResizeFailed]
        },
        "clusterrole-aggregation-controller" => {
          kind: "ClusterRole", feature_gates: [], startup_conditions: ["API server available"],
          sync_targets: ["ClusterRole"], status_fields: ["rules"], events: ["ClusterRoleAggregated"]
        }
      }.freeze
      METADATA.each_value do |entry|
        entry.each_value { |value| value.freeze if value.is_a?(Array) }
        entry.freeze
      end

      module_function

      def implementation(name)
        IMPLEMENTATIONS.fetch(name.to_s)
      end

      def entries
        if defined?(BuiltinControllerCorpus)
          NAMES.map do |name|
            BuiltinControllerCorpus.fetch(name) ||
              raise(ValidationError, "missing pinned corpus entry #{name.inspect}")
          end.freeze
        else
          NAMES.map do |name|
            local = METADATA.fetch(name)
            {"name" => name, "kind" => local.fetch(:kind),
             "startupConditions" => local.fetch(:startup_conditions),
             "featureGates" => local.fetch(:feature_gates), "syncTargets" => local.fetch(:sync_targets),
             "statusFields" => local.fetch(:status_fields), "events" => local.fetch(:events),
             "aliases" => [],
             "cloudProvider" => %w[service-lb-controller node-route-controller cloud-node-lifecycle-controller].include?(name)}.freeze
          end.freeze
        end
      end

      def metadata(name = nil)
        return entries.map { |entry| entry.respond_to?(:to_h) ? entry.to_h : entry }.freeze if name.nil?

        Support.immutable_copy(METADATA.fetch(name.to_s))
      end

      def names
        NAMES
      end

      def definitions(registry: nil)
        NAMES.map { |name| definition(name, registry: registry) }.freeze
      end

      def definition(name, registry: nil)
        name = name.to_s
        metadata = METADATA.fetch(name)
        implementation = IMPLEMENTATIONS.fetch(name)
        kind = usable_descriptor(ResourceDescriptor.parse(metadata.fetch(:kind)), registry)
        definition = nil
        mutex = Mutex.new
        instance = nil
        reconcile = lambda do |resource, context = nil|
          context = {} unless context.is_a?(Hash)
          controller = context[:controller] || context["controller"]
          controller ||= mutex.synchronize do
            instance ||= implementation.new(store: context[:store] || context["store"], definition: definition)
          end
          options = context[:options] || context["options"] || {}
          options = options.dup if options.is_a?(Hash)
          options[:store] = context[:store] || context["store"] if options.is_a?(Hash) && !options.key?(:store) && !options.key?("store")
          controller.plan(resource, **(options.is_a?(Hash) ? options : {}))
        end
        ControllerDefinition.new(
          name: name, kind: kind, owns: [], watches: watch_specs(name, registry: registry),
          reconcile_block: reconcile, feature_gates: metadata.fetch(:feature_gates),
          startup_conditions: metadata.fetch(:startup_conditions), sync_targets: metadata.fetch(:sync_targets),
          status_fields: metadata.fetch(:status_fields), events: metadata.fetch(:events),
          implementation: implementation
        )
      end

      def register!(registry)
        definitions(registry: registry).each { |definition| registry.register(definition) }
        registry
      end
      alias register register!

      def reconcile_block(implementation)
        lambda do |resource, context = nil|
          context = {} unless context.is_a?(Hash)
          controller = context[:controller] || context["controller"]
          options = context[:options] || context["options"] || {}
          options = options.dup if options.is_a?(Hash)
          if controller && controller.respond_to?(:plan)
            controller.plan(resource, **options)
          else
            implementation.new(store: context[:store] || context["store"], definition: nil).plan(resource, **options)
          end
        end
      end

      alias build_definitions definitions

      def usable_descriptor(descriptor, registry)
        return descriptor unless registry

        registry.validate_descriptor!(descriptor)
        descriptor
      rescue UnknownGVKError
        ResourceDescriptor.parse(descriptor.kind)
      end

      NODE_KEYED_POD_WATCHERS = %w[taint-eviction-controller device-taint-eviction-controller].freeze
      # The Node a Pod is bound to, the only node key its events concern.
      POD_NODE_KEY = lambda do |pod|
        node = Support.value(Support.spec(pod), "nodeName", nil).to_s
        node.empty? ? nil : node
      end

      def watch_specs(name, registry: nil)
        descriptors = case name
                      when "taint-eviction-controller", "device-taint-eviction-controller"
                        [ResourceDescriptor.parse("Node"), ResourceDescriptor.parse("Pod")]
                      when "service-lb-controller"
                        [ResourceDescriptor.parse("Service"), ResourceDescriptor.parse("Node")]
                      when "node-route-controller", "cloud-node-lifecycle-controller"
                        [ResourceDescriptor.parse("Node")]
                      when "persistentvolume-binder-controller"
                        [ResourceDescriptor.parse("PersistentVolume"), ResourceDescriptor.parse("PersistentVolumeClaim"),
                         ResourceDescriptor.parse("StorageClass")]
                      when "persistent-volume-attach-detach-controller"
                        [ResourceDescriptor.parse("PersistentVolume"), ResourceDescriptor.parse("PersistentVolumeClaim"),
                         ResourceDescriptor.parse("Pod"), ResourceDescriptor.parse("Node"),
                         ResourceDescriptor.parse({"apiVersion" => "storage.k8s.io/v1", "kind" => "VolumeAttachment"},
                                                  resource: "volumeattachments", scope: :cluster)]
                      when "persistent-volume-expander-controller"
                        [ResourceDescriptor.parse("PersistentVolumeClaim"), ResourceDescriptor.parse("PersistentVolume")]
                      when "clusterrole-aggregation-controller"
                        [ResourceDescriptor.parse("ClusterRole")]
                      else
                        []
                      end
        specs = descriptors.map do |descriptor|
          descriptor = usable_descriptor(descriptor, registry)
          if NODE_KEYED_POD_WATCHERS.include?(name) && descriptor.kind == "Pod"
            # A Pod event concerns the node it is bound to and no other: the
            # fan-out reconciled every node for every Pod event, which is
            # what a mass Pod deletion then queued up behind.
            next WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                               index_name: "infrastructure/#{name}/#{descriptor.identifier}/node",
                               predicate: ->(_object) { true }, route: :self,
                               queue_key: POD_NODE_KEY)
          end
          WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                        index_name: "infrastructure/#{name}/#{descriptor.identifier}",
                        predicate: ->(_object) { true },
                        queue_key: ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") })
        end
        if name == "persistentvolume-binder-controller"
          # The volume queue: a PersistentVolume event also syncs the volume
          # itself (syncVolume), besides re-syncing the claims.
          descriptor = usable_descriptor(ResourceDescriptor.parse("PersistentVolume"), registry)
          specs << WatchSpec.new(resource: descriptor, via: :all, scope: descriptor.scope,
                                 index_name: "infrastructure/#{name}/#{descriptor.identifier}/self",
                                 predicate: ->(_object) { true }, route: :self,
                                 queue_key: ->(object) { Support.name(object).to_s })
        end
        specs
      end
    end

    InfrastructureStorageFactory = InfrastructureStorageControllerFactory
    PinnedInfrastructureControllerFactory = InfrastructureStorageControllerFactory
  end
end
