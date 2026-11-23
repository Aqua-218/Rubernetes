# frozen_string_literal: true

require_relative "../claim_quota_usage"
require_relative "../pod_quota_usage"
require_relative "../pvc_quota_usage"
require_relative "../service_quota_usage"

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
      CUSTOM_USAGE_SYNC_SECONDS = 15.0

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

      RESOURCE_TO_KIND = KIND_TO_RESOURCE.invert.freeze

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
      # resource_quota_monitor.go enqueues deletes and updates that may
      # replenish quota. Admission charges adds and increases before the
      # object reaches the store, so those events can skip a recompute.
      def skip_event?(object, old_object, type = nil)
        kind = Support.kind(object)
        if kind != "ResourceQuota"
          return false if %i[delete sync].include?(type)
          return false if kind == "Pod" && became_terminal?(object, old_object)
          return false if kind == "Service" && service_releases_quota?(object, old_object)

          return true
        end
        return false if old_object.nil?

        Support.spec(object) == Support.spec(old_object)
      end

      def became_terminal?(object, old_object)
        terminal = lambda { |pod|
          pod && (%w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s) ||
                          !Support.value(Support.metadata(pod), "deletionTimestamp", nil).nil?)
        }
        terminal.call(object) && !terminal.call(old_object)
      end

      def plan(resource_quota, store: nil, objects: nil, **_options)
        adapter = adapter_for(store)
        namespace = Support.namespace(resource_quota)
        hard = Support.value(Support.spec(resource_quota), "hard", {})
        hard = {} unless hard.is_a?(Hash)
        custom_limits = objects ? [] : custom_count_limits(hard.keys)
        custom = custom_counts(adapter, namespace, custom_limits)
        objects ||= counted_objects(adapter, namespace, hard.except(*custom.keys))
        # A quota only counts the objects its scopes select
        # (pkg/quota/v1/evaluator/core/pods.go + scope matching): a quota
        # scoped to Terminating must ignore a Pod with no
        # activeDeadlineSeconds, and so on.  spec.scopes and spec.scopeSelector
        # were accepted by the API server and read by nobody, so every quota
        # counted every Pod.
        groups = objects_in_scope(resource_quota, objects).group_by { |object| Support.kind(object) }
        pods = groups.fetch("Pod", [])
        pod_totals = nil
        used = hard.to_h do |resource_name, limit|
          name = resource_name.to_s
          amount = if custom.key?(name)
                     custom.fetch(name).to_s
                   elsif name == "count/pods"
                     pods.length.to_s
                   elsif pod_quota_resource?(name)
                     pod_totals ||= pod_quota_totals(pods)
                     pod_totals.fetch(name, 0).to_s
                   else
                     format_quota_quantity(usage_for(name, groups), limit, name)
                   end
          [name, amount]
        end
        status = Support.status(resource_quota).merge("hard" => hard, "used" => used)
        result_for(resource_quota, [], status: status, requeue_after: (CUSTOM_USAGE_SYNC_SECONDS unless custom_limits.empty?))
      end

      private

      def service_releases_quota?(service, old_service)
        return false unless old_service

        current = ServiceQuotaUsage.usage(Support.spec(service))
        ServiceQuotaUsage.usage(Support.spec(old_service)).any? { |name, amount| amount > current.fetch(name) }
      end

      def custom_count_limits(limits)
        limits.map(&:to_s).filter_map do |name|
          next unless name.start_with?("count/")

          resource, group = name.delete_prefix("count/").split(".", 2)
          builtin = resource_kind(resource)
          name if group && (builtin.nil? || ResourceDescriptor.parse(builtin).group != group)
        end
      end

      # The controller's static informers do not watch instance events for
      # each CRD. Refresh just the quotas for custom collections periodically
      # so deletions release their count.
      def custom_counts(adapter, namespace, selected)
        return {} if selected.empty? || !adapter.is_a?(StoreAdapter)

        adapter.custom_resource_descriptors.each_with_object({}) do |descriptor, counts|
          name = "count/#{descriptor.resource}.#{descriptor.group}"
          next unless descriptor.namespaced? && selected.include?(name)

          counts[name] = Array(adapter.custom_resource_items(descriptor, namespace: namespace)).length
        end
      end

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
        when "requests.storage", /#{Regexp.escape(STORAGE_CLASS_SUFFIX)}/o then "PersistentVolumeClaim"
        when /#{Regexp.escape(Rubernetes::ClaimQuotaUsage::PER_CLASS_SUFFIX)}\z/o then "ResourceClaim"
        when /\Aservices/ then "Service"
        when %r{\Acount/} then resource_kind(name.delete_prefix("count/").split(".").first)
        else resource_kind(name)
        end
      end

      def resource_kind(resource)
        RESOURCE_TO_KIND[resource]
      end

      # The VolumeAttributesClass scope matches claims. The remaining scopes
      # here apply to Pods.
      def objects_in_scope(resource_quota, objects)
        spec = Support.spec(resource_quota)
        scopes = Array(Support.value(spec, "scopes", [])).map(&:to_s)
        selector_terms = Array(Support.value(Support.value(spec, "scopeSelector", {}) || {}, "matchExpressions", []))
        return objects if scopes.empty? && selector_terms.empty?

        if PVCQuotaUsage.scopes_include_class?(scopes, selector_terms)
          return Array(objects).select do |object|
            Support.kind(object) == "PersistentVolumeClaim" && PVCQuotaUsage.matches?(object, scopes, selector_terms)
          end
        end

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
              !Support.value(inner, "namespaceSelector", nil).nil?
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

      def usage_for(name, groups)
        case name
        when "requests.storage"
          groups.fetch("PersistentVolumeClaim", []).sum { |claim| PVCQuotaUsage.storage_request(claim) || 0 }
        when /\A(.+)#{Regexp.escape(STORAGE_CLASS_SUFFIX)}(persistentvolumeclaims|requests\.storage)\z/o
          storage_class, metric = Regexp.last_match.captures
          groups.fetch("PersistentVolumeClaim", []).sum do |claim|
            next 0 unless Support.value(Support.spec(claim), "storageClassName").to_s == storage_class

            metric == "persistentvolumeclaims" ? 1 : (PVCQuotaUsage.storage_request(claim) || 0)
          end
        when "services.nodeports", "services.loadbalancers"
          groups.fetch("Service", []).sum { |service| ServiceQuotaUsage.usage(Support.spec(service)).fetch(name) }
        when /#{Regexp.escape(Rubernetes::ClaimQuotaUsage::PER_CLASS_SUFFIX)}\z/o
          groups.fetch("ResourceClaim", []).sum { |claim| Rubernetes::ClaimQuotaUsage.usage(claim)[name] }
        else
          resource = name.delete_prefix("count/").partition(".").first
          kind = resource.include?("/") ? resource.split("/").last : resource_kind(resource)
          groups.fetch(kind, []).length
        end
      end

      # The resources pods.go's evaluator charges (MatchingResources).
      def pod_quota_resource?(name)
        return true if POD_COMPUTE_RESOURCES.include?(name) || %w[pods count/pods].include?(name)
        return false if name == "requests.storage"

        name.match?(/\A(requests|limits)\./) || name.start_with?(Rubernetes::ResourceHelpers::HUGE_PAGES_PREFIX)
      end

      def pod_quota_totals(pods)
        now = @clock ? @clock.call : Time.now.utc
        now = Time.at(now) if now.is_a?(Numeric)
        pods.each_with_object({}) do |pod, totals|
          ResourceHelpers.add!(totals, PodQuotaUsage.quantities(pod, now: now))
        end
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
