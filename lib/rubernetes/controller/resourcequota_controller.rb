# frozen_string_literal: true

require_relative "../claim_quota_usage"
require_relative "../pod_quota_usage"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"

module Rubernetes
  module Controller
    # Computes ResourceQuota usage from the namespace snapshot and writes only
    # the quota status subresource.  Quantity units are retained from the
    # configured hard limit, while resource counts remain numeric when the
    # API object supplied a numeric hard value.
    class ResourceQuotaController < BaseController
      RESOURCE_QUOTA = ResourceDescriptor.parse("ResourceQuota")
      POD = ResourceDescriptor.parse("Pod")

      KIND_TO_RESOURCE = {
        "Pod" => "pods", "Service" => "services", "ConfigMap" => "configmaps",
        "Secret" => "secrets", "ReplicationController" => "replicationcontrollers",
        "ResourceQuota" => "resourcequotas", "PersistentVolumeClaim" => "persistentvolumeclaims",
        "LimitRange" => "limitranges", "Endpoints" => "endpoints",
        "EndpointSlice" => "endpointslices", "ServiceAccount" => "serviceaccounts",
        "Event" => "events", "PodDisruptionBudget" => "poddisruptionbudgets",
        "Deployment" => "deployments", "ReplicaSet" => "replicasets",
        "StatefulSet" => "statefulsets", "DaemonSet" => "daemonsets",
        "Job" => "jobs", "CronJob" => "cronjobs", "ResourceClaim" => "resourceclaims"
      }.freeze

      include SecondarySupport

      # resource_quota_controller.go: "We are only interested in observing
      # updates to quota.spec to ensure that quota.status is calculated" -- a
      # ResourceQuota update that changed nothing but status is not a reason
      # to recompute.  Reconciling on those meant the admission plugin's
      # synchronous charge (status.used += the admitted object) woke the
      # controller before its informer held the object it had just admitted,
      # and the recomputed, stale usage overwrote the charge: a LoadBalancer
      # created 170 ms after a NodePort Service sailed past
      # services.nodeports: 1 ("capture the life of a service").  Object
      # events and the periodic resync keep status.used converging.
      #
      # And resource_quota_monitor.go registers only UpdateFunc and DeleteFunc
      # for the counted kinds: an ADD was already charged by admission, and
      # recomputing on it from an informer cache that has not caught up
      # overwrote the charge with the old total -- the same LoadBalancer
      # slipped past services.nodeports: 1 again in round 61.  Adds of the
      # quota itself, updates, deletes and the periodic resync still recompute.
      # Upstream's quota controller replenishes on deletions and on a Pod
      # reaching a terminal phase (replenishment_controller.go); creations
      # are admission's business, and a recompute triggered by a creation
      # can run in the window between admission charging the quota and the
      # object being stored, list one object too few and erase the charge
      # ("ResourceQuota ... capture the life of a service" then admitted a
      # LoadBalancer past the limit).  Quota events count only when the spec
      # changed.
      def skip_event?(object, old_object, type = nil)
        kind = Support.kind(object)
        if kind != "ResourceQuota"
          return false if type == :delete || type == :sync
          return false if kind == "Pod" && became_terminal?(object, old_object)

          return true
        end
        return false if old_object.nil?

        Support.spec(object) == Support.spec(old_object)
      end

      def became_terminal?(object, old_object)
        terminal = ->(pod) { pod && (%w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s) ||
                                     !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?) }
        terminal.call(object) && !terminal.call(old_object)
      end

      def plan(resource_quota, store: nil, objects: nil, **_options)
        adapter = adapter_for(store)
        namespace = Support.namespace(resource_quota)
        hard = Support.value(Support.spec(resource_quota), "hard", {})
        hard = {} unless hard.is_a?(Hash)
        objects ||= counted_objects(adapter, namespace, hard)
        # A quota only counts the objects its scopes select
        # (pkg/quota/v1/evaluator/core/pods.go + scope matching): a quota
        # scoped to Terminating must ignore a Pod with no
        # activeDeadlineSeconds, and so on.  spec.scopes and spec.scopeSelector
        # were accepted by the API server and read by nobody, so every quota
        # counted every Pod.
        objects = objects_in_scope(resource_quota, objects)
        pod_totals = pod_quota_totals(objects)
        used = hard.each_with_object({}) do |(resource_name, limit), result|
          name = resource_name.to_s
          result[name] = if pod_quota_resource?(name)
                           # Quantity.Add over the Pods' PodUsageFunc, canonical.
                           pod_totals.fetch(name) { Rubernetes::Schema::Quantity.parse("0") }.to_s
                         else
                           format_quota_quantity(usage_for(name, objects), limit, name)
                         end
        end
        status = Support.deep_copy(Support.status(resource_quota))
        status["hard"] = Support.deep_copy(hard)
        status["used"] = used
        events = []
        result_for(resource_quota, [], status: status, events: events)
      end

      private

      # The objects a quota counts, read FRESH from the API when the adapter
      # can: status.used is written with the resourceVersion the quota was
      # read at, but that only guards against concurrent writers, not against
      # stale inputs.  A total computed from an informer cache that had not
      # yet delivered an admitted Service overwrote admission's charge and the
      # next Service was admitted past the limit ("capture the life of a
      # service").  Only the kinds the quota's hard limits name are listed;
      # a limit whose kind cannot be resolved falls back to everything in the
      # namespace.
      def counted_objects(adapter, namespace, hard)
        return [] unless adapter
        return namespaced_objects(adapter, namespace) unless adapter.respond_to?(:list) &&
                                                             adapter.method(:list).parameters.any? { |_, name| name == :fresh }

        kinds = hard.keys.map { |name| counted_kind(name.to_s) }
        return namespaced_objects(adapter, namespace) if kinds.any?(&:nil?)

        kinds.uniq.flat_map { |kind| Array(adapter.list(kind, namespace: namespace, fresh: true)) }
      end

      def counted_kind(name)
        case name
        when *POD_COMPUTE_RESOURCES, "pods", /\A(requests|limits)\.(?!storage\z)/ then "Pod"
        when "requests.storage", /#{Regexp.escape(STORAGE_CLASS_SUFFIX)}/ then "PersistentVolumeClaim"
        when /#{Regexp.escape(Rubernetes::ClaimQuotaUsage::PER_CLASS_SUFFIX)}\z/ then "ResourceClaim"
        when /\Aservices/ then "Service"
        when %r{\Acount/} then resource_kind(name.sub(%r{\Acount/}, "").split(".").first)
        else resource_kind(name)
        end
      end

      def resource_kind(resource)
        KIND_TO_RESOURCE.find { |_kind, value| value == resource }&.first
      end

      # Scopes apply to Pods only; other kinds are unaffected by them.
      def objects_in_scope(resource_quota, objects)
        spec = Support.spec(resource_quota)
        scopes = Array(Support.value(spec, "scopes", [])).map(&:to_s)
        selector_terms = Array(Support.value(Support.value(spec, "scopeSelector", {}) || {}, "matchExpressions", []))
        return objects if scopes.empty? && selector_terms.empty?

        Array(objects).select do |object|
          next true unless Support.kind(object) == "Pod"

          scopes.all? { |scope| pod_matches_scope?(object, scope, nil) } &&
            selector_terms.all? { |term| pod_matches_scope_expression?(object, term) }
        end
      end

      def pod_matches_scope?(pod, scope, values)
        spec = Support.spec(pod)
        case scope
        when "Terminating" then !Support.value(spec, "activeDeadlineSeconds", nil).nil?
        when "NotTerminating" then Support.value(spec, "activeDeadlineSeconds", nil).nil?
        when "BestEffort" then best_effort_pod?(pod)
        when "NotBestEffort" then !best_effort_pod?(pod)
        when "PriorityClass" then !Support.value(spec, "priorityClassName", "").to_s.empty?
        when "CrossNamespacePodAffinity" then cross_namespace_affinity?(pod)
        else
          _ = values
          true
        end
      end

      # scopeSelector.matchExpressions: {scopeName, operator, values}.
      def pod_matches_scope_expression?(pod, term)
        scope = Support.value(term, "scopeName", "").to_s
        operator = Support.value(term, "operator", "Exists").to_s
        values = Array(Support.value(term, "values", [])).map(&:to_s)
        if scope == "PriorityClass"
          name = Support.value(Support.spec(pod), "priorityClassName", "").to_s
          return case operator
                 when "In" then values.include?(name)
                 when "NotIn" then !values.include?(name)
                 when "Exists" then !name.empty?
                 when "DoesNotExist" then name.empty?
                 else true
                 end
        end

        matched = pod_matches_scope?(pod, scope, values)
        case operator
        when "DoesNotExist" then !matched
        else matched
        end
      end

      # QoS BestEffort: no container asks for any request or limit.
      def best_effort_pod?(pod)
        spec = Support.spec(pod)
        containers = Array(Support.value(spec, "containers", [])) + Array(Support.value(spec, "initContainers", []))
        containers.all? do |container|
          resources = Support.value(container, "resources", {}) || {}
          %w[requests limits].all? { |section| (Support.value(resources, section, {}) || {}).empty? }
        end
      end

      def cross_namespace_affinity?(pod)
        affinity = Support.value(Support.spec(pod), "affinity", {}) || {}
        %w[podAffinity podAntiAffinity].any? do |kind|
          terms = Support.value(affinity, kind, {}) || {}
          (Array(Support.value(terms, "requiredDuringSchedulingIgnoredDuringExecution", [])) +
           Array(Support.value(terms, "preferredDuringSchedulingIgnoredDuringExecution", []))).any? do |term|
            inner = Support.value(term, "podAffinityTerm", term) || term
            !Array(Support.value(inner, "namespaces", [])).empty? ||
              !(Support.value(inner, "namespaceSelector", nil)).nil?
          end
        end
      end

      # pkg/quota/v1/evaluator/core/pods.go: the bare compute names are the
      # requests ("cpu" is requests.cpu), and every "requests.<name>" /
      # "limits.<name>" -- hugepages and extended resources such as
      # requests.example.com/dongle included -- is summed over the Pods.
      # Only the three built-in names were handled, so a quota on cpu, memory
      # or an extended resource reported 0 for ever and admission, which trusts
      # status.used, let every Pod through.
      POD_COMPUTE_RESOURCES = %w[cpu memory ephemeral-storage].freeze
      STORAGE_CLASS_SUFFIX = ".storageclass.storage.k8s.io/"

      def usage_for(resource_name, objects)
        name = resource_name.to_s
        case name
        when *POD_COMPUTE_RESOURCES
          pod_usage(objects, "requests", name)
        when "requests.storage"
          Array(objects).select { |object| Support.kind(object) == "PersistentVolumeClaim" }
                        .sum { |claim| claim_storage_request(claim) }
        when /\A(requests|limits)\.(.+)\z/
          pod_usage(objects, Regexp.last_match(1), Regexp.last_match(2))
        when /\A(.+)#{Regexp.escape(STORAGE_CLASS_SUFFIX)}(persistentvolumeclaims|requests\.storage)\z/
          # <class>.storageclass.storage.k8s.io/...: the claims of that class.
          storage_class = Regexp.last_match(1)
          claims = Array(objects).select do |object|
            Support.kind(object) == "PersistentVolumeClaim" &&
              Support.value(Support.spec(object), "storageClassName", nil).to_s == storage_class
          end
          Regexp.last_match(2) == "persistentvolumeclaims" ? claims.length : claims.sum { |claim| claim_storage_request(claim) }
        when "services.nodeports"
          # services.go Usage: "node port quota charging is based on service
          # ports" -- every port of a NodePort Service, and of a LoadBalancer
          # that allocates them, whether or not a nodePort has been assigned
          # yet.  Counting assigned ones charged a brand-new Service zero.
          Array(objects).select { |object| Support.kind(object) == "Service" }
                        .sum { |service| service_node_port_usage(Support.spec(service)) }
        when "services.loadbalancers"
          Array(objects).count { |object| Support.kind(object) == "Service" && Support.value(Support.spec(object), "type", "") == "LoadBalancer" }
        when /#{Regexp.escape(Rubernetes::ClaimQuotaUsage::PER_CLASS_SUFFIX)}\z/
          Array(objects).select { |object| Support.kind(object) == "ResourceClaim" }
                        .sum { |claim| Rubernetes::ClaimQuotaUsage.usage(claim)[name] }
        else
          countable_resource(name, objects)
        end
      end

      # The resources pods.go's evaluator charges (MatchingResources).
      def pod_quota_resource?(name)
        return true if POD_COMPUTE_RESOURCES.include?(name) || %w[pods count/pods].include?(name)
        return false if name == "requests.storage"

        name.match?(/\A(requests|limits)\./) || name.start_with?(Rubernetes::ResourceHelpers::HUGE_PAGES_PREFIX)
      end

      def pod_quota_totals(objects)
        now = @clock ? @clock.call : Time.now.utc
        now = Time.at(now) if now.is_a?(Numeric)
        Array(objects).select { |object| Support.kind(object) == "Pod" }.each_with_object({}) do |pod, totals|
          Rubernetes::PodQuotaUsage.quantities(Support.deep_copy(pod), now: now).each do |name, quantity|
            totals[name] = totals.key?(name) ? Rubernetes::Schema::Quantity.new(totals[name].value + quantity.value, totals[name].format) : quantity
          end
        end
      end

      def pod_usage(objects, metric, resource)
        Array(objects).select { |object| Support.kind(object) == "Pod" && !terminal_pod?(object) }
                      .sum { |pod| pod_resource_usage(pod, metric, resource) }
      end

      def claim_storage_request(claim)
        quantity_to_base(Support.value(Support.value(Support.spec(claim), "resources", {}), "requests", {}).fetch("storage", 0))
      end

      def countable_resource(resource_name, objects)
        normalized = resource_name.sub(/\Acount\//, "")
        normalized = normalized.split(".").first
        kind = if normalized.include?("/")
                 normalized.split("/").last
               else
                 KIND_TO_RESOURCE.find { |_candidate, resource| resource == normalized }&.first
               end
        return 0 unless kind

        Array(objects).count { |object| Support.kind(object) == kind }
      end

      def pod_resource_usage(pod, metric, resource)
        containers = Array(Support.value(Support.spec(pod), "containers", []))
        init_containers = Array(Support.value(Support.spec(pod), "initContainers", []))
        container_total = containers.sum { |container| quantity_for_container(container, metric, resource) }
        init_max = init_containers.map { |container| quantity_for_container(container, metric, resource) }.max.to_f
        [container_total, init_max].max
      end

      def quantity_for_container(container, metric, resource)
        resources = Support.value(container, "resources", {})
        quantities = Support.value(resources, metric, {})
        quantity_to_base(Support.value(quantities, resource, 0))
      end

      # services.go Usage: a NodePort Service charges one per service port, and
      # so does a LoadBalancer unless allocateLoadBalancerNodePorts is false.
      def service_node_port_usage(service_spec)
        ports = Array(Support.value(service_spec, "ports", [])).length
        case Support.value(service_spec, "type", "").to_s
        when "NodePort" then ports
        when "LoadBalancer"
          Support.value(service_spec, "allocateLoadBalancerNodePorts", nil) == false ? 0 : ports
        else 0
        end
      end

      def terminal_pod?(pod)
        %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s)
      end

      # Quantity.String(): the canonical form, which is also what the API
      # server stores.  The limit's own suffix ("0Gi" for a 10Gi limit) never
      # compared equal to the stored "0", so every sync rewrote an unchanged
      # status and its watch event queued the next -- a write every ~60 ms per
      # quota, each one a chance to overwrite admission's synchronous charge
      # with an older total ("capture the life of a service" admitted a
      # LoadBalancer past services.nodeports: 1).
      def format_quota_quantity(value, template, resource_name)
        rendered = if resource_name.end_with?(".cpu") && value.to_f.round != value.to_f &&
                      template.to_s.match?(/\A-?\d+(?:\.\d+)?\z/)
                     "#{Integer((value.to_f * 1_000).round)}m"
                   else
                     format_quantity(value, template)
                   end
        Rubernetes::Schema::Quantity.parse(rendered.to_s).to_s
      rescue Rubernetes::Schema::Quantity::ParseError
        rendered
      end
    end
  end
end
