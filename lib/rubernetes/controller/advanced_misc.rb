# frozen_string_literal: true

require "ipaddr"
require "time"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "registry"

module Rubernetes
  module Controller
    # Concrete implementations for the less frequently exercised
    # kube-controller-manager controllers in Kubernetes v1.36.2.  The source
    # contract is pinned to commit 24e2b02af5543d7910c2bb074c7264df5a8f0467.
    # Each planner consumes immutable informer-style snapshots and returns
    # only the fields owned by that controller.
    module AdvancedMiscSupport
      RESOURCE_CLAIM = ResourceDescriptor.parse("ResourceClaim")
      RESOURCE_SLICE = ResourceDescriptor.parse("ResourceSlice")
      POD = ResourceDescriptor.parse("Pod")
      SECRET = ResourceDescriptor.parse("Secret")
      SERVICE_ACCOUNT = ResourceDescriptor.parse("ServiceAccount")
      CONFIG_MAP = ResourceDescriptor.parse("ConfigMap")
      VAP = ResourceDescriptor.parse("ValidatingAdmissionPolicy")
      SERVICE_CIDR = ResourceDescriptor.parse("ServiceCIDR")
      NODE = ResourceDescriptor.parse("Node")
      IP_ADDRESS = ResourceDescriptor.parse(
        {"apiVersion" => "networking.k8s.io/v1", "kind" => "IPAddress"},
        resource: "ipaddresses", scope: :cluster
      )
      RESOURCE_POOL_STATUS_REQUEST = ResourceDescriptor.parse(
        {"apiVersion" => "resource.k8s.io/v1alpha3", "kind" => "ResourcePoolStatusRequest"},
        resource: "resourcepoolstatusrequests", scope: :cluster
      )
      VAP_BINDING = ResourceDescriptor.parse(
        {"apiVersion" => "admissionregistration.k8s.io/v1", "kind" => "ValidatingAdmissionPolicyBinding"},
        resource: "validatingadmissionpolicybindings", scope: :cluster
      )
      STORAGE_VERSION_MIGRATION = ResourceDescriptor.parse(
        {"apiVersion" => "storagemigration.k8s.io/v1beta1", "kind" => "StorageVersionMigration"},
        resource: "storageversionmigrations", scope: :cluster
      )

      RESOURCE_CLAIM_FINALIZER = "resource.kubernetes.io/delete-protection".freeze
      SERVICE_ACCOUNT_TOKEN_TYPE = "kubernetes.io/service-account-token".freeze
      TRACKING_CONFIG_MAP = "kube-apiserver-legacy-service-account-token-tracking".freeze
      TRACKING_NAMESPACE = "kube-system".freeze
      LAST_USED_LABEL = "kubernetes.io/legacy-token-last-used".freeze
      INVALID_SINCE_LABEL = "kubernetes.io/legacy-token-invalid-since".freeze
      SERVICE_CIDR_FINALIZER = "networking.k8s.io/service-cidr-finalizer".freeze
      # The reason kube-apiserver stamps on the default ServiceCIDR's Ready
      # condition when it publishes --service-cluster-ip-range (see
      # Api::ServiceAllocator#bootstrap!).  The controller must agree with it:
      # a metav1.Condition requires a reason, and a controller that reconciles
      # towards a different one rewrites the status on every pass forever.
      SERVICE_CIDR_READY_REASON = "KubernetesServiceCIDRIsReady".freeze

      module_function

      def normalize_time(value, fallback = nil)
        parsed = Support.parse_time(value)
        parsed ||= fallback if fallback
        raise ArgumentError, "clock must return Time or RFC3339 value" unless parsed

        parsed.utc
      end

      def result(resource, operations:, events: [], status: nil, controller: nil, descriptor: nil)
        key = if resource
                namespace = descriptor&.cluster_scoped? ? nil : Support.namespace(resource)
                [namespace, Support.name(resource)].compact.join("/")
              end
        ReconcileResult.new(operations: operations.compact, status: status || Support.status(resource),
                            events: events, controller: controller, key: key)
      end

      def condition_list(resource_or_status)
        source = resource_or_status.is_a?(Hash) && Support.value(resource_or_status, "status", nil).is_a?(Hash) ?
                 Support.status(resource_or_status) : resource_or_status
        Array(Support.value(source, "conditions", [])).select { |condition| condition.is_a?(Hash) }
      end

      def condition_for(resource_or_status, type)
        condition_list(resource_or_status).find { |condition| Support.value(condition, "type", "").to_s == type.to_s }
      end

      def upsert_condition(conditions, type, status, reason, message: nil, now: nil)
        values = Array(conditions).map { |condition| Support.deep_copy(condition) }
        current = values.find { |condition| Support.value(condition, "type", "").to_s == type.to_s }
        candidate = current || {"type" => type.to_s}
        candidate["status"] = status.to_s
        candidate["reason"] = reason.to_s unless reason.nil?
        candidate["message"] = message.to_s unless message.nil?
        candidate["lastTransitionTime"] = now.utc.iso8601(9) if now
        values << candidate unless current
        values
      end

      def owner_reference(owner, kind: nil)
        Support.owner_references(owner).find do |reference|
          next false if kind && Support.ref_value(reference, "kind", "").to_s != kind.to_s

          controller = Support.ref_value(reference, "controller", nil)
          controller == true || controller.to_s.casecmp("true").zero?
        end
      end

      def object_name(object)
        [Support.namespace(object), Support.name(object)].compact.join("/")
      end

      def metadata_value(object, key, default = nil)
        Support.value(Support.metadata(object), key, default)
      end

      def api_group(ref)
        Support.value(ref, "apiGroup", nil) || Support.value(ref, "apigroup", nil) || ""
      end

      def value_at(object, *keys)
        keys.each do |key|
          value = Support.value(object, key, nil)
          return value unless value.nil?
        end
        nil
      end

      def explicit_descriptor(api_version, kind, resource, scope)
        ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => kind}, resource: resource, scope: scope)
      end
    end

    # pkg/controller/resourceclaim (v1.36.2).  Keyed by the object an event
    # is about:
    #
    #   Pod (syncPod)             a claim is created from each
    #       ResourceClaimTemplate the Pod needs (named <pod>-<claim>-<5
    #       random>, owned by the Pod, annotated resource.kubernetes.io/
    #       pod-claim-name) and recorded in status.resourceClaimStatuses; a
    #       scheduled Pod is added to reservedFor of an allocated claim that
    #       does not list it yet (Pods bound without the scheduler).
    #   ResourceClaim (syncClaim) reservations of Pods that are gone,
    #       replaced or done are dropped; with none left, a claim carrying
    #       the delete-protection finalizer is deallocated and loses the
    #       finalizer; a generated claim whose Pod was replaced or is done is
    #       deleted.
    #   ResourceClaimTemplate     the Pods of its namespace that use it.
    #
    # Only the claim-side cleanup existed before: no Pod ever got a claim
    # from a template, so every Pod using one stayed unschedulable.
    class ResourceClaimController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      TEMPLATE = ResourceDescriptor.parse("ResourceClaimTemplate")
      POD_CLAIM_ANNOTATION = "resource.kubernetes.io/pod-claim-name"
      # utilrand.String: lower-case consonants and digits without vowels
      # or look-alikes.
      NAME_ALPHABET = "bcdfghjklmnpqrstvwxz2456789"

      def initialize(*arguments, random: Random.new, **options)
        super(*arguments, **options)
        @random = random
      end

      def plan(object, pods: nil, deleted_pod_uids: [], authoritative_pods: nil, now: nil, store: nil, **options)
        return result(object, operations: [], controller: name, descriptor: RESOURCE_CLAIM) unless object.is_a?(Hash)

        case Support.kind(object).to_s
        when "Pod" then plan_pod(object, store: store, **options)
        when "ResourceClaimTemplate" then plan_template(object, store: store, **options)
        else
          claim_result = plan_claim(object, pods: pods, deleted_pod_uids: deleted_pod_uids,
                                            authoritative_pods: authoritative_pods, store: store)
          # A Pod with the same namespace/name reaches this controller under
          # the same key; its work is not lost to the claim.
          pod = (adapter = adapter_for(store)) && find_for(adapter, POD, Support.name(object), namespace: Support.namespace(object))
          return claim_result unless pod

          pod_result = plan_pod(pod, store: store, **options)
          ReconcileResult.new(operations: claim_result.operations + pod_result.operations,
                              events: Array(claim_result.events) + Array(pod_result.events),
                              status: claim_result.status, controller: name, key: claim_result.key)
        end
      end

      # enqueuePod: the Pod itself, and -- because a Pod that is done or
      # gone releases its reservations and a generated claim of a done Pod
      # is deleted -- every claim it names.  A DELETED event carries the last
      # state, which cannot always tell a delete from an update, so the
      # claims of any Pod with claims are queued; syncClaim is a no-op for a
      # claim with nothing to release.
      # getAdminAccessMetricLabel: "true" when an exactly-specified request
      # asks for admin access.
      def self.admin_access_label(claim)
        requests = Array(claim&.dig("spec", "devices", "requests"))
        requests.any? { |request| request.is_a?(Hash) && request.dig("exactly", "adminAccess") == true } ? "true" : "false"
      end

      # The customCollector's labels for one claim: allocated, admin access,
      # and its source (extended resources, a template, or none).
      def self.claim_metric_labels(claim)
        annotations = claim.dig("metadata", "annotations") || {}
        source = if annotations["resource.kubernetes.io/extended-resource-claim"] == "true" then "extended_resource"
                 elsif !annotations["resource.kubernetes.io/pod-claim-name"].to_s.empty? then "resource_claim_template"
                 else ""
                 end
        {"allocated" => claim.dig("status", "allocation").nil? ? "false" : "true", "admin_access" => admin_access_label(claim), "source" => source}
      end

      def self.pod_queue_keys(pod)
        namespace = Support.namespace(pod)
        keys = [[namespace, Support.name(pod)].compact.join("/")]
        claims = Array(Support.value(Support.spec(pod), "resourceClaims", []))
        extended = Support.value(Support.status(pod), "extendedResourceClaimStatus", nil)
        keys << [namespace, extended["resourceClaimName"]].compact.join("/") if extended.is_a?(Hash) && !extended["resourceClaimName"].to_s.empty?
        return keys.uniq if claims.empty?

        statuses = Array(Support.value(Support.status(pod), "resourceClaimStatuses", []))
        claims.each do |pod_claim|
          next unless pod_claim.is_a?(Hash)

          name = pod_claim["resourceClaimName"] ||
                 statuses.find { |entry| entry.is_a?(Hash) && entry["name"] == pod_claim["name"] }&.fetch("resourceClaimName", nil)
          keys << [namespace, name].compact.join("/") unless name.to_s.empty?
        end
        keys.uniq
      end

      # ---------------------------------------------------------- syncPod

      def plan_pod(pod, store: nil, claims: nil, templates: nil, **_options)
        empty = result(pod, operations: [], controller: name, descriptor: POD)
        return empty unless metadata_value(pod, "deletionTimestamp", nil).nil?
        return empty if Array(value_at(Support.spec(pod), "resourceClaims")).empty?

        adapter = adapter_for(store)
        namespace = Support.namespace(pod)
        claims ||= adapter ? list_for(adapter, RESOURCE_CLAIM, namespace: namespace) : []
        templates ||= adapter ? list_for(adapter, TEMPLATE, namespace: namespace) : []
        operations = []
        events = []
        new_statuses = {}
        created = []
        Array(value_at(Support.spec(pod), "resourceClaims")).each do |pod_claim|
          begin
            claim = handle_claim(pod, pod_claim, claims + created, templates)
          rescue ClaimFailure => error
            events << {"type" => "Warning", "reason" => "FailedResourceClaimCreation",
                       "message" => "PodResourceClaim #{pod_claim["name"]}: #{error.message}"}
            return result(pod, operations: operations, events: events, controller: name, descriptor: POD)
          end
          next if claim.nil?

          if claim[:create]
            created << claim[:create]
            admin_access = self.class.admin_access_label(claim[:create])
            create = operation_create(claim[:create], descriptor: RESOURCE_CLAIM, reason: "create ResourceClaim from template")
            create = create&.observed do |succeeded, _|
              ControllerMetrics.increment("resourceclaim_controller_creates_total",
                                          {"status" => succeeded ? "success" : "failure", "admin_access" => admin_access})
            end
            operations << create if create
          end
          new_statuses[pod_claim["name"].to_s] = claim[:name]
        end
        unless new_statuses.empty?
          statuses = new_statuses.map { |pod_claim_name, claim_name| {"name" => pod_claim_name, "resourceClaimName" => claim_name} }
          operations << operation_status(pod, {"resourceClaimStatuses" => statuses}, descriptor: POD,
                                         reason: "record ResourceClaims created for the Pod", force: true)
        end
        return result(pod, operations: operations, events: events, controller: name, descriptor: POD) if value_at(Support.spec(pod), "nodeName").to_s.empty?

        # A scheduled Pod reserves its allocated claims (a Pod bound without
        # the scheduler); a claim created just now is not allocated yet.
        pod_for_names = Support.deep_copy(pod)
        (pod_for_names["status"] ||= {})["resourceClaimStatuses"] =
          Array(Support.status(pod)["resourceClaimStatuses"]).reject { |entry| new_statuses.key?(entry["name"].to_s) } +
          new_statuses.map { |pod_claim_name, claim_name| {"name" => pod_claim_name, "resourceClaimName" => claim_name} }
        Array(value_at(Support.spec(pod), "resourceClaims")).each do |pod_claim|
          claim_name, check_owner = claim_name_for(pod_for_names, pod_claim)
          next if claim_name.nil?

          claim = claims.find { |candidate| Support.name(candidate) == claim_name }
          next if claim.nil?
          next if check_owner && !owned_by_pod?(claim, pod)
          next if value_at(Support.status(claim), "allocation").nil? || reserved_for?(claim, pod)

          status = Support.deep_copy(Support.status(claim))
          status["reservedFor"] = Array(status["reservedFor"]) + [{"resource" => "pods", "name" => Support.name(pod), "uid" => Support.uid(pod)}]
          operations << operation_status(claim, status, descriptor: RESOURCE_CLAIM, reason: "reserve claim for scheduled Pod")
        end
        result(pod, operations: operations, events: events, controller: name, descriptor: POD)
      end

      def plan_template(template, store: nil, **options)
        adapter = adapter_for(store)
        return result(template, operations: [], controller: name, descriptor: TEMPLATE) unless adapter

        pods = list_for(adapter, POD, namespace: Support.namespace(template)).select do |pod|
          Array(value_at(Support.spec(pod), "resourceClaims")).any? { |entry| entry["resourceClaimTemplateName"] == Support.name(template) }
        end
        operations = pods.flat_map { |pod| plan_pod(pod, store: store, **options).operations }
        result(template, operations: operations, controller: name, descriptor: TEMPLATE)
      end

      class ClaimFailure < StandardError; end

      # handleClaim: {name:, create:} for a claim the Pod's status must name,
      # nil when there is nothing to record.
      def handle_claim(pod, pod_claim, claims, templates)
        begin
          claim_name, must_check_owner = claim_name_for(pod, pod_claim)
        rescue ClaimNotCreated
          claim_name = :not_created
        end
        return nil if claim_name.nil?

        unless claim_name == :not_created
          existing = claims.find { |candidate| Support.name(candidate) == claim_name }
          return nil if existing && (!must_check_owner || owned_by_pod?(existing, pod))
        end
        template_name = pod_claim["resourceClaimTemplateName"]
        return nil if template_name.nil?

        found = claims.find do |candidate|
          owned_by_pod?(candidate, pod) && metadata_value(candidate, "annotations", {}).to_h[POD_CLAIM_ANNOTATION] == pod_claim["name"]
        end
        return {name: Support.name(found), create: nil} if found

        template = templates.find { |candidate| Support.name(candidate) == template_name }
        unless template
          raise ClaimFailure, "resource claim template \"#{template_name}\": resourceclaimtemplate.resource.k8s.io \"#{template_name}\" not found"
        end

        spec = Support.spec(template)
        template_metadata = spec["metadata"] || {}
        annotations = (template_metadata["annotations"] || {}).merge(POD_CLAIM_ANNOTATION => pod_claim["name"].to_s)
        claim = {
          "apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
          "metadata" => {
            "name" => generated_name(Support.name(pod), pod_claim["name"].to_s),
            "namespace" => Support.namespace(pod),
            "ownerReferences" => [{"apiVersion" => "v1", "kind" => "Pod", "name" => Support.name(pod), "uid" => Support.uid(pod),
                                   "controller" => true, "blockOwnerDeletion" => true}],
            "annotations" => annotations
          },
          "spec" => Support.deep_copy(spec["spec"] || {})
        }
        claim["metadata"]["labels"] = template_metadata["labels"] if template_metadata["labels"]
        {name: claim["metadata"]["name"], create: claim}
      end

      class ClaimNotCreated < StandardError; end

      # resourceclaim.Name: [name, must check owner]; nil name = not needed.
      def claim_name_for(pod, pod_claim)
        if pod_claim["resourceClaimName"]
          [pod_claim["resourceClaimName"].to_s, false]
        elsif pod_claim["resourceClaimTemplateName"]
          status = Array(Support.status(pod)["resourceClaimStatuses"]).find { |entry| entry["name"] == pod_claim["name"] }
          raise ClaimNotCreated unless status

          [status["resourceClaimName"], true]
        else
          raise ClaimFailure, "checking for claim before creating it: pod \"#{object_name(pod)}\", spec.resourceClaim " \
                              "#{pod_claim["name"].to_s.dump}: none of the supported fields are set"
        end
      end

      # generateName <pod>-<claim>- shortened to 57 characters, plus the five
      # random characters the API server would append.
      def generated_name(pod_name, claim_name)
        base = "#{pod_name}-#{claim_name}-"
        if base.length > 57
          base = "#{pod_name[0, pod_name.length * 57 / base.length]}-#{claim_name[0, claim_name.length * 57 / base.length]}"
        end
        base + Array.new(5) { NAME_ALPHABET[@random.rand(NAME_ALPHABET.length)] }.join
      end

      def owned_by_pod?(claim, pod)
        reference = owner_reference(claim)
        reference && Support.ref_value(reference, "uid", "").to_s == Support.uid(pod).to_s
      end

      def reserved_for?(claim, pod)
        Array(value_at(Support.status(claim), "reservedFor")).any? { |entry| Support.value(entry, "uid", "").to_s == Support.uid(pod).to_s }
      end

      # -------------------------------------------------------- syncClaim

      def plan_claim(claim, pods: nil, deleted_pod_uids: [], authoritative_pods: nil, store: nil)
        adapter = adapter_for(store)
        pod_snapshot = authoritative_pods.nil? ? pods : authoritative_pods
        pod_snapshot = list_for(adapter, POD, namespace: Support.namespace(claim)) if pod_snapshot.nil? && adapter
        deleted_uids = Array(deleted_pod_uids).map(&:to_s)
        status = Support.deep_copy(Support.status(claim))
        reserved = Array(Support.value(status, "reservedFor", [])).select { |entry| entry.is_a?(Hash) }
        remaining = reserved.select { |reference| keep_reserved_reference?(claim, reference, pod_snapshot, deleted_uids) }

        operations = []
        events = []
        has_finalizer = Array(metadata_value(claim, "finalizers", [])).map(&:to_s).include?(RESOURCE_CLAIM_FINALIZER)
        deleting = !metadata_value(claim, "deletionTimestamp", nil).nil?
        next_status = status
        deallocated = false
        if remaining.length < reserved.length
          next_status = Support.deep_copy(status)
          next_status["reservedFor"] = remaining
          if remaining.empty? && has_finalizer && next_status["allocation"]
            next_status.delete("allocation")
            deallocated = true
          end
          operations << operation_status(claim, next_status, descriptor: RESOURCE_CLAIM, reason: "remove stale ResourceClaim reservations")
          if has_finalizer && next_status["allocation"].nil?
            operations << remove_finalizer(claim, next_status)
          end
        elsif has_finalizer && deleting && remaining.empty?
          if next_status["allocation"]
            next_status = Support.deep_copy(status)
            next_status.delete("allocation")
            deallocated = true
            operations << operation_status(claim, next_status, descriptor: RESOURCE_CLAIM, reason: "remove allocation because not needed")
          end
          operations << remove_finalizer(claim, next_status)
        end
        if deallocated
          events << {"type" => "Normal", "reason" => "ResourceClaimAllocated", "message" => "ResourceClaim #{object_name(claim)} allocation released"}
        end

        # Generated claims are deleted once their Pod was replaced or is done.
        if remaining.empty? && pod_snapshot
          owner = owner_reference(claim, kind: "Pod")
          if owner && Support.ref_value(owner, "apiVersion", "v1").to_s == "v1"
            owner_pod = Array(pod_snapshot).find { |pod| Support.name(pod) == Support.ref_value(owner, "name", "").to_s }
            if owner_pod && (Support.uid(owner_pod).to_s != Support.ref_value(owner, "uid", nil).to_s || pod_done?(owner_pod))
              operations << operation_delete(claim, descriptor: RESOURCE_CLAIM, reason: "delete unused generated ResourceClaim")
            end
          end
        end
        result(claim, operations: operations.compact, events: events, status: next_status, controller: name, descriptor: RESOURCE_CLAIM)
      end

      private

      def remove_finalizer(claim, status)
        updated = Support.deep_copy(claim)
        finalizers = Array(Support.value(updated["metadata"], "finalizers", [])).map(&:to_s)
        finalizers.delete_at(finalizers.index(RESOURCE_CLAIM_FINALIZER))
        updated["metadata"]["finalizers"] = finalizers
        updated["status"] = Support.deep_copy(status)
        operation_update(claim, updated, descriptor: RESOURCE_CLAIM, reason: "remove ResourceClaim delete-protection finalizer")
      end

      def pod_reference?(reference)
        api_group(reference).to_s.empty? && Support.value(reference, "resource", "").to_s.downcase == "pods"
      end

      def keep_reserved_reference?(claim, reference, pods, deleted_uids)
        return true unless pod_reference?(reference)

        uid = Support.value(reference, "uid", nil).to_s
        return false if !uid.empty? && deleted_uids.include?(uid)
        return true unless pods

        pod = Array(pods).find do |candidate|
          Support.namespace(candidate) == Support.namespace(claim) && Support.name(candidate) == Support.value(reference, "name", "").to_s
        end
        return false unless pod
        return false unless Support.uid(pod).to_s == uid

        !pod_done?(pod)
      end

      # isPodDone.
      def pod_done?(pod)
        %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s) ||
          (!metadata_value(pod, "deletionTimestamp", nil).nil? && value_at(Support.spec(pod), "nodeName").to_s.empty?)
      end
    end

    # Computes ResourcePoolStatusRequest synchronously from ResourceSlices and
    # current ResourceClaim allocations.  Incomplete pools are retried rather
    # than finalized, matching the v1.36.2 controller's bounded queue policy.
    class ResourcePoolStatusRequestController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      COMPLETED_TTL = 3_600
      PENDING_TTL = 86_400
      MAX_RETRIES = 5
      DEFAULT_LIMIT = 100

      def plan(request, resource_slices: nil, resource_claims: nil, now: nil, limit: nil, store: nil, **_options)
        return result(request, operations: [], controller: name, descriptor: RESOURCE_POOL_STATUS_REQUEST) unless request.is_a?(Hash)
        return result(request, operations: [], controller: name, descriptor: RESOURCE_POOL_STATUS_REQUEST) unless Support.value(request, "status", nil).nil?

        adapter = adapter_for(store)
        resource_slices = list_for(adapter, RESOURCE_SLICE, namespace: :all) if resource_slices.nil? && adapter
        resource_claims = list_for(adapter, RESOURCE_CLAIM, namespace: :all) if resource_claims.nil? && adapter
        resource_slices ||= []
        resource_claims ||= []
        timestamp = normalize_time(now || Time.now.utc)
        desired_status = calculate_status(request, resource_slices: resource_slices, resource_claims: resource_claims,
                                          now: timestamp, limit: limit)
        incomplete = Array(Support.value(desired_status, "pools", [])).any? do |pool|
          !Support.value(pool, "validationError", nil).to_s.empty?
        end
        if incomplete
          events = [{"type" => "Warning", "reason" => "ResourcePoolStatusIncomplete",
                     "message" => "one or more resource pools are incomplete; retrying",
                     "retryable" => true, "maxRetries" => MAX_RETRIES}]
          return result(request, operations: [], events: events, status: desired_status,
                        controller: name, descriptor: RESOURCE_POOL_STATUS_REQUEST)
        end

        operation = operation_status(request, desired_status, descriptor: RESOURCE_POOL_STATUS_REQUEST,
                                     reason: "calculate ResourcePoolStatusRequest status")
        events = [{"type" => "Normal", "reason" => "ResourcePoolStatusUpdated",
                   "message" => "calculated ResourcePoolStatusRequest status"}]
        result(request, operations: [operation].compact, events: events, status: desired_status,
               controller: name, descriptor: RESOURCE_POOL_STATUS_REQUEST)
      end

      # The upstream controller's periodic cleanup is exposed as a pure
      # planner for callers that own the request list.  Every delete carries
      # the original UID in the immutable object for StoreAdapter fencing.
      def cleanup_expired(requests, now:, completed_ttl: COMPLETED_TTL, pending_ttl: PENDING_TTL)
        timestamp = normalize_time(now)
        Array(requests).filter_map do |request|
          status = Support.value(request, "status", nil)
          reference_time = if status
                             completed_condition = Array(Support.value(status, "conditions", [])).find do |condition|
                               %w[Complete Failed MigrationSucceeded MigrationFailed].include?(Support.value(condition, "type", "").to_s)
                             end
                             Support.parse_time(Support.value(completed_condition || {}, "lastTransitionTime", nil)) || Support.creation_time(request)
                           else
                             Support.creation_time(request)
                           end
          age = timestamp.to_f - reference_time.to_f
          next if age <= 0
          ttl = status.nil? ? pending_ttl.to_f : completed_ttl.to_f
          next unless age > ttl

          operation_delete(request, descriptor: RESOURCE_POOL_STATUS_REQUEST,
                           reason: "delete expired ResourcePoolStatusRequest")
        end
      end

      private

      def calculate_status(request, resource_slices:, resource_claims:, now:, limit: nil)
        driver = value_at(Support.spec(request), "driver").to_s
        pool_filter = value_at(Support.spec(request), "poolName", "pool_name").to_s
        slices = Array(resource_slices).select do |slice|
          spec = Support.spec(slice)
          next false unless value_at(spec, "driver").to_s == driver

          pool_name = pool_name_for(slice)
          pool_filter.empty? || pool_name == pool_filter
        end
        max_generations = slices.each_with_object({}) do |slice, result_hash|
          key = [value_at(Support.spec(slice), "driver").to_s, pool_name_for(slice)]
          generation = generation_for(slice)
          result_hash[key] = [result_hash[key] || generation, generation].max
        end
        pools = {}
        slices.each do |slice|
          key = [value_at(Support.spec(slice), "driver").to_s, pool_name_for(slice)]
          next unless generation_for(slice) == max_generations[key]

          spec = Support.spec(slice)
          pool = (pools[key] ||= {
            "driver" => key[0], "poolName" => key[1], "generation" => max_generations[key],
            "nodeName" => nil, "_nodes" => [], "totalDevices" => 0, "resourceSliceCount" => 0,
            "expectedSliceCount" => expected_slice_count(slice)
          })
          pool["totalDevices"] += Array(value_at(spec, "devices")).length
          pool["resourceSliceCount"] += 1
          pool["_nodes"] << value_at(spec, "nodeName").to_s
        end

        allocations = allocation_counts(resource_claims)
        statuses = pools.values.map do |pool|
          nodes = pool.delete("_nodes").uniq
          pool["nodeName"] = nodes.first if nodes.length == 1 && !nodes.first.to_s.empty?
          pool.delete("nodeName") if pool["nodeName"].nil?
          expected = pool.delete("expectedSliceCount")
          if expected > pool["resourceSliceCount"]
            message = "pool #{pool["driver"]}/#{pool["poolName"]} is incomplete: observed #{pool["resourceSliceCount"]}/#{expected} slices at generation #{pool["generation"]}"
            pool.delete("resourceSliceCount")
            pool.delete("totalDevices")
            pool["validationError"] = message.byteslice(0, 256)
          else
            allocated = allocations[[pool["driver"], pool["poolName"]]] || 0
            pool["allocatedDevices"] = allocated
            pool["unavailableDevices"] = 0
            pool["availableDevices"] = [pool["totalDevices"] - allocated, 0].max
          end
          pool
        end.sort_by { |pool| [pool["driver"].to_s, pool["poolName"].to_s] }

        effective_limit = limit.nil? ? value_at(Support.spec(request), "limit") : limit
        effective_limit = Support.integer(effective_limit, DEFAULT_LIMIT)
        effective_limit = DEFAULT_LIMIT if effective_limit.negative?
        returned = statuses.first(effective_limit)
        incomplete_count = returned.count { |pool| Support.value(pool, "validationError", nil) }
        message = "Calculated status for #{returned.length} pools"
        message = "#{message} (#{incomplete_count} incomplete)" if incomplete_count.positive?
        {
          "poolCount" => statuses.length,
          "pools" => returned,
          "conditions" => [{"type" => "Complete", "status" => "True", "lastTransitionTime" => now.utc.iso8601(9),
                            "reason" => "CalculationComplete", "message" => message}]
        }
      end

      def pool_name_for(slice)
        spec = Support.spec(slice)
        pool = value_at(spec, "pool")
        return value_at(pool, "name", "poolName").to_s if pool.is_a?(Hash)

        value_at(spec, "poolName", "pool_name").to_s
      end

      def generation_for(slice)
        pool = value_at(Support.spec(slice), "pool")
        value = pool.is_a?(Hash) ? value_at(pool, "generation") : nil
        Support.integer(value, Support.integer(value_at(Support.spec(slice), "generation"), 0))
      end

      def expected_slice_count(slice)
        pool = value_at(Support.spec(slice), "pool")
        value = pool.is_a?(Hash) ? value_at(pool, "resourceSliceCount", "resource_slice_count") : nil
        Support.integer(value, Support.integer(value_at(Support.spec(slice), "resourceSliceCount"), 1))
      end

      def allocation_counts(claims)
        Array(claims).each_with_object(Hash.new(0)) do |claim, counts|
          allocation = value_at(Support.status(claim), "allocation")
          results = allocation.is_a?(Hash) ? value_at(value_at(allocation, "devices") || {}, "results") : nil
          Array(results).each do |entry|
            driver = value_at(entry, "driver").to_s
            pool = value_at(entry, "pool").to_s
            counts[[driver, pool]] += 1 unless driver.empty? || pool.empty?
          end
        end
      end
    end

    # Deletes only auto-generated, demonstrably unused legacy service-account
    # token Secrets.  The first pass marks a token invalid; a later pass may
    # delete it after the configured grace period, matching Kubernetes' safety
    # behavior for malformed or newly observed tokens.
    class LegacyServiceAccountTokenCleanerController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      DATE_FORMAT = "%Y-%m-%d".freeze
      DEFAULT_CLEANUP_PERIOD = 30 * 24 * 60 * 60

      def plan(secret, service_accounts: nil, pods: nil, tracking_config_map: nil, tracked_since: nil,
               now: nil, cleanup_period: DEFAULT_CLEANUP_PERIOD, store: nil, **_options)
        raise ArgumentError, "cleanup_period must be positive" unless cleanup_period.to_f.positive?

        adapter = adapter_for(store)
        if adapter
          service_accounts ||= list_for(adapter, SERVICE_ACCOUNT, namespace: Support.namespace(secret))
          pods ||= list_for(adapter, POD, namespace: Support.namespace(secret))
          tracking_config_map ||= find_for(adapter, CONFIG_MAP, TRACKING_CONFIG_MAP, namespace: TRACKING_NAMESPACE)
        end
        service_accounts ||= []
        pods ||= []
        timestamp = normalize_time(now || Time.now.utc)
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless candidate_secret?(secret)

        since = tracked_since || tracking_since_from(tracking_config_map)
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless since
        since_time = parse_date(since)
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless since_time
        return result(secret, operations: [], controller: name, descriptor: SECRET) if timestamp < since_time + 86_400 + cleanup_period.to_f

        cutoff = timestamp - cleanup_period.to_f
        creation_time = Support.creation_time(secret)
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless creation_time && creation_time < cutoff
        labels = Support.deep_copy(Support.labels(secret))
        last_used = labels[LAST_USED_LABEL] || labels[LAST_USED_LABEL.to_sym]
        if last_used
          parsed_last_used = parse_date(last_used)
          return result(secret, operations: [], controller: name, descriptor: SECRET) unless parsed_last_used
          return result(secret, operations: [], controller: name, descriptor: SECRET) if parsed_last_used >= date_floor(cutoff)
        end

        service_account = linked_service_account(secret, service_accounts)
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless service_account
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless service_account_references_secret?(service_account, secret)
        return result(secret, operations: [], controller: name, descriptor: SECRET) if mounted_by_pod?(secret, pods)

        invalid_since = labels[INVALID_SINCE_LABEL] || labels[INVALID_SINCE_LABEL.to_sym]
        parsed_invalid_since = parse_date(invalid_since)
        if parsed_invalid_since.nil?
          labels[INVALID_SINCE_LABEL] = timestamp.strftime(DATE_FORMAT)
          candidate = Support.deep_copy(secret)
          candidate["metadata"] = Support.deep_copy(Support.metadata(secret))
          candidate["metadata"]["labels"] = labels
          operation = operation_update(secret, candidate, descriptor: SECRET,
                                       reason: "mark legacy service-account token invalid")
          return result(secret, operations: [operation].compact,
                        events: [{"type" => "Normal", "reason" => "LegacyTokenCleaned",
                                  "message" => "marked unused legacy service-account token #{object_name(secret)} invalid"}],
                        controller: name, descriptor: SECRET)
        end

        return result(secret, operations: [], controller: name, descriptor: SECRET) if parsed_invalid_since >= date_floor(cutoff)

        operation = operation_delete(secret, descriptor: SECRET,
                                     reason: "delete unused legacy service-account token")
        result(secret, operations: [operation],
               events: [{"type" => "Normal", "reason" => "LegacyTokenCleaned",
                         "message" => "deleted unused legacy service-account token #{object_name(secret)}"}],
               controller: name, descriptor: SECRET)
      end

      private

      def candidate_secret?(secret)
        Support.kind(secret) == "Secret" &&
          value_at(secret, "type").to_s == SERVICE_ACCOUNT_TOKEN_TYPE &&
          metadata_value(secret, "deletionTimestamp", nil).nil?
      end

      def tracking_since_from(config_map)
        return nil unless config_map.is_a?(Hash)
        data = Support.value(config_map, "data", {})
        value_at(data, "since", "trackedSince", "tracked_since")
      end

      def parse_date(value)
        text = value.to_s
        return nil unless text.match?(/\A\d{4}-\d{2}-\d{2}\z/)

        year, month, day = text.split("-").map(&:to_i)
        Time.utc(year, month, day)
      rescue ArgumentError, TypeError
        nil
      end

      def date_floor(time)
        Time.utc(time.utc.year, time.utc.month, time.utc.day)
      end

      def linked_service_account(secret, service_accounts)
        annotations = Support.annotations(secret)
        name = value_at(annotations, "kubernetes.io/service-account.name", "serviceAccountName").to_s
        return nil if name.empty?

        candidate = Array(service_accounts).find do |service_account|
          Support.namespace(service_account) == Support.namespace(secret) &&
            Support.name(service_account) == name
        end
        return nil unless candidate

        expected_uid = value_at(annotations, "kubernetes.io/service-account.uid", "serviceAccountUID")
        return nil if expected_uid && !expected_uid.to_s.empty? && Support.uid(candidate).to_s != expected_uid.to_s

        candidate
      end

      def service_account_references_secret?(service_account, secret)
        Array(value_at(Support.spec(service_account), "secrets") || Support.value(service_account, "secrets", [])).any? do |reference|
          value_at(reference, "name").to_s == Support.name(secret)
        end
      end

      def mounted_by_pod?(secret, pods)
        Array(pods).any? do |pod|
          next false unless Support.namespace(pod) == Support.namespace(secret)

          pod_references_secret?(pod, Support.name(secret))
        end
      end

      def pod_references_secret?(pod, secret_name)
        spec = Support.spec(pod)
        image_pull = Array(value_at(spec, "imagePullSecrets")).any? do |reference|
          value_at(reference, "name").to_s == secret_name
        end
        volume_reference = Array(value_at(spec, "volumes")).any? do |volume|
          secret_ref = value_at(volume, "secret")
          projected = value_at(volume, "projected")
          direct = secret_ref.is_a?(Hash) && value_at(secret_ref, "secretName", "name").to_s == secret_name
          projected_ref = projected.is_a?(Hash) && Array(value_at(projected, "sources")).any? do |source|
            source_secret = value_at(source, "secret")
            source_secret.is_a?(Hash) && value_at(source_secret, "name", "secretName").to_s == secret_name
          end
          provider_refs = %w[azureFile cephfs cinder flexVolume rbd scaleIO iscsi storageos].any? do |provider|
            provider_value = value_at(volume, provider)
            next false unless provider_value.is_a?(Hash)
            value = value_at(provider_value, "secretName") || value_at(value_at(provider_value, "secretRef") || {}, "name")
            value.to_s == secret_name
          end
          csi = value_at(volume, "csi")
          csi_ref = csi.is_a?(Hash) && value_at(value_at(csi, "nodePublishSecretRef") || {}, "name").to_s == secret_name
          direct || projected_ref || provider_refs || csi_ref
        end
        image_pull || volume_reference || Array(value_at(spec, "containers")) .concat(Array(value_at(spec, "initContainers")))
          .concat(Array(value_at(spec, "ephemeralContainers"))).any? do |container|
            env_ref = Array(value_at(container, "env")).any? do |env|
              ref = value_at(env, "valueFrom")
              secret_ref = ref.is_a?(Hash) ? value_at(ref, "secretKeyRef") : nil
              secret_ref.is_a?(Hash) && value_at(secret_ref, "name").to_s == secret_name
            end
            env_from_ref = Array(value_at(container, "envFrom")).any? do |env_from|
              secret_ref = value_at(env_from, "secretRef")
              secret_ref.is_a?(Hash) && value_at(secret_ref, "name").to_s == secret_name
            end
            env_ref || env_from_ref
          end
      end
    end

    # pkg/controller/validatingadmissionpolicystatus (v1.36.2): for a policy
    # whose generation is newer than status.observedGeneration, runs the
    # TypeChecker and applies observedGeneration and
    # typeChecking.expressionWarnings (field manager
    # validatingadmissionpolicy-status, forced) -- nothing else: no
    # condition, no event.  Bindings are watched but never written.
    class ValidatingAdmissionPolicyStatusController < BaseController
      include AdvancedMiscSupport

      def plan(policy, bindings: [], type_checker: nil, warnings: nil, now: nil, **_options)
        return result(policy, operations: [], controller: name, descriptor: VAP) unless policy.is_a?(Hash)

        generation = Support.integer(metadata_value(policy, "generation", 0), 0)
        observed = Support.integer(Support.value(Support.status(policy), "observedGeneration", 0), 0)
        return result(policy, operations: [], controller: name, descriptor: VAP) if generation <= observed

        raw_warnings = warnings.nil? ? run_type_checker(type_checker, policy) : warnings
        normalized_warnings = Array(raw_warnings).map { |warning| normalize_warning(warning) }
        desired_status = Support.deep_copy(Support.status(policy))
        desired_status["observedGeneration"] = generation
        # TypeChecking().WithExpressionWarnings(): an empty list is omitted.
        desired_status["typeChecking"] = normalized_warnings.empty? ? {} : {"expressionWarnings" => normalized_warnings}
        operation = operation_status(policy, desired_status, descriptor: VAP,
                                     reason: "update ValidatingAdmissionPolicy type-check status")
        result(policy, operations: [operation].compact, status: desired_status, controller: name, descriptor: VAP)
      end

      private

      def run_type_checker(checker, policy)
        return [] unless checker
        return checker.call(policy) if checker.respond_to?(:call)
        return checker.check(policy) if checker.respond_to?(:check)
        return checker.Check(policy) if checker.respond_to?(:Check)

        raise ArgumentError, "type_checker must respond to call, check, or Check"
      end

      def normalize_warning(warning)
        if warning.is_a?(Hash)
          field_ref = value_at(warning, "fieldRef", "field_ref")
          message = value_at(warning, "warning", "message")
          return {"fieldRef" => field_ref.to_s, "warning" => message.to_s}
        end

        field_ref = warning.respond_to?(:field_ref) ? warning.field_ref : warning.respond_to?(:FieldRef) ? warning.FieldRef : nil
        message = warning.respond_to?(:warning) ? warning.warning : warning.respond_to?(:Warning) ? warning.Warning : warning.to_s
        {"fieldRef" => field_ref.to_s, "warning" => message.to_s}
      end
    end

    # Protects ServiceCIDR finalizers and status while respecting IPAddress
    # ownership and overlapping (parent) ServiceCIDRs.
    class ServiceCIDRController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      DELETION_GRACE_PERIOD = 10

      def plan(service_cidr, service_cidrs: nil, ip_addresses: nil, now: nil,
               deletion_grace_period: DELETION_GRACE_PERIOD, store: nil, **_options)
        return result(service_cidr, operations: [], controller: name, descriptor: SERVICE_CIDR) unless service_cidr.is_a?(Hash)

        adapter = adapter_for(store)
        service_cidrs = list_for(adapter, SERVICE_CIDR, namespace: :all) if service_cidrs.nil? && adapter
        ip_addresses = list_for(adapter, IP_ADDRESS, namespace: :all) if ip_addresses.nil? && adapter
        service_cidrs ||= []
        ip_addresses ||= []
        timestamp = normalize_time(now || Time.now.utc)
        finalizers = Array(metadata_value(service_cidr, "finalizers", [])).map(&:to_s)
        deleting = !metadata_value(service_cidr, "deletionTimestamp", nil).nil?
        operations = []
        events = []

        if deleting
          can_delete = can_delete?(service_cidr, service_cidrs, ip_addresses)
          unless can_delete
            desired_status = status_with_condition(service_cidr, "False", "Terminating",
                                                   "There are still IPAddresses referencing the ServiceCIDR, please remove them or create a new ServiceCIDR",
                                                   timestamp)
            operation = operation_status(service_cidr, desired_status, descriptor: SERVICE_CIDR,
                                         reason: "report ServiceCIDR deletion blocked")
            events << {"type" => "Warning", "reason" => "ServiceCIDRUpdated",
                       "message" => "ServiceCIDR deletion is blocked by an owned IPAddress"}
            return result(service_cidr, operations: [operation].compact, events: events, status: desired_status,
                          controller: name, descriptor: SERVICE_CIDR)
          end

          deletion_time = Support.parse_time(metadata_value(service_cidr, "deletionTimestamp", nil))
          if deletion_time && timestamp < deletion_time + deletion_grace_period.to_f
            events << {"type" => "Normal", "reason" => "ServiceCIDRUpdated",
                       "message" => "waiting for ServiceCIDR deletion grace period", "retryable" => true}
            return result(service_cidr, operations: [], events: events, controller: name, descriptor: SERVICE_CIDR)
          end

          if finalizers.include?(SERVICE_CIDR_FINALIZER)
            candidate = Support.deep_copy(service_cidr)
            candidate["metadata"] = Support.deep_copy(Support.metadata(service_cidr))
            candidate["metadata"]["finalizers"] = finalizers.reject { |value| value == SERVICE_CIDR_FINALIZER }
            operations << operation_update(service_cidr, candidate, descriptor: SERVICE_CIDR,
                                           reason: "remove ServiceCIDR protection finalizer")
            events << {"type" => "Normal", "reason" => "ServiceCIDRUpdated",
                       "message" => "removed ServiceCIDR protection finalizer"}
          end
          return result(service_cidr, operations: operations, events: events,
                        controller: name, descriptor: SERVICE_CIDR)
        end

        unless finalizers.include?(SERVICE_CIDR_FINALIZER)
          candidate = Support.deep_copy(service_cidr)
          candidate["metadata"] = Support.deep_copy(Support.metadata(service_cidr))
          candidate["metadata"]["finalizers"] = finalizers + [SERVICE_CIDR_FINALIZER]
          operations << operation_update(service_cidr, candidate, descriptor: SERVICE_CIDR,
                                         reason: "add ServiceCIDR protection finalizer")
        end

        desired_status = status_with_condition(service_cidr, "True", SERVICE_CIDR_READY_REASON,
                                               "Kubernetes Service CIDR is ready", timestamp)
        operation = operation_status(service_cidr, desired_status, descriptor: SERVICE_CIDR,
                                     reason: "update ServiceCIDR ready status")
        operations << operation if operation
        events << {"type" => "Normal", "reason" => "ServiceCIDRUpdated",
                   "message" => "ServiceCIDR is ready"} if operations.any?
        result(service_cidr, operations: operations, events: events, status: desired_status,
               controller: name, descriptor: SERVICE_CIDR)
      end

      private

      def status_with_condition(service_cidr, condition_status, reason, message, now)
        status = Support.deep_copy(Support.status(service_cidr))
        current = condition_for(status, "Ready")
        if current && Support.value(current, "status", "").to_s == condition_status.to_s &&
           Support.value(current, "reason", nil).to_s == reason.to_s &&
           Support.value(current, "message", nil).to_s == message.to_s
          return status
        end
        status["conditions"] = upsert_condition(Support.value(status, "conditions", []), "Ready", condition_status,
                                                 reason, message: message, now: now)
        status
      end

      def cidr_strings(service_cidr)
        Array(value_at(Support.spec(service_cidr), "cidrs", "CIDRs")).map(&:to_s).reject(&:empty?)
      end

      def parse_prefix(value)
        text = value.to_s
        address, prefix = text.split("/", 2)
        return nil if prefix.nil?
        parsed_address = IPAddr.new(address)
        prefix_i = Integer(prefix)
        bits = parsed_address.ipv4? ? 32 : 128
        return nil unless prefix_i.between?(0, bits)

        [parsed_address.mask(prefix_i), prefix_i, bits]
      rescue IPAddr::InvalidAddressError, ArgumentError, TypeError
        nil
      end

      def contains_prefix?(parent, child)
        parent_parsed = parse_prefix(parent)
        child_parsed = parse_prefix(child)
        return false unless parent_parsed && child_parsed
        parent_network, parent_length, parent_bits = parent_parsed
        child_network, child_length, child_bits = child_parsed
        return false unless parent_bits == child_bits && parent_length <= child_length

        parent_network.to_i == child_network.mask(parent_length).to_i
      end

      def containing_cidrs(address, service_cidrs)
        Array(service_cidrs).select do |candidate|
          cidr_strings(candidate).any? { |cidr| IPAddr.new(cidr).include?(address) }
        rescue IPAddr::InvalidAddressError, ArgumentError
          false
        end
      end

      def can_delete?(service_cidr, service_cidrs, ip_addresses)
        candidates = Array(service_cidrs)
        candidates = candidates + [service_cidr] unless candidates.any? { |candidate| Support.uid(candidate) == Support.uid(service_cidr) || Support.name(candidate) == Support.name(service_cidr) }
        own_cidrs = cidr_strings(service_cidr)
        has_parent = own_cidrs.all? do |own_cidr|
          candidates.any? do |candidate|
            next false if Support.name(candidate) == Support.name(service_cidr)
            cidr_strings(candidate).any? { |other| contains_prefix?(other, own_cidr) }
          end
        end
        return true if has_parent

        own_cidrs.none? do |own_cidr|
          begin
            network = IPAddr.new(own_cidr)
          rescue IPAddr::InvalidAddressError, ArgumentError
            next false
          end
          Array(ip_addresses).any? do |ip_address|
            managed_by = value_at(Support.metadata(ip_address), "labels")
            managed_by = value_at(managed_by, "ipaddress.kubernetes.io/managed-by") if managed_by.is_a?(Hash)
            next false if managed_by && !managed_by.to_s.empty? && managed_by.to_s != "ipallocator.k8s.io"
            begin
              parent_ref = value_at(Support.spec(ip_address), "parentRef", "parent_ref")
              if parent_ref.is_a?(Hash)
                parent_resource = value_at(parent_ref, "resource").to_s
                parent_name = value_at(parent_ref, "name").to_s
                next false unless parent_resource.empty? || parent_resource == "servicecidrs"
                next false unless parent_name.empty? || parent_name == Support.name(service_cidr)
              end
              address = IPAddr.new(Support.name(ip_address))
              next false unless network.include?(address)

              containing = containing_cidrs(address, candidates)
              containing.length == 1 && Support.name(containing.first) == Support.name(service_cidr)
            rescue IPAddr::InvalidAddressError, ArgumentError
              false
            end
          end
        end
      end
    end

    # Migrates stored resources by applying only TypeMeta + UID/RV fences.
    # Conflicts are deliberately ignored; transient failures remain pending;
    # malformed or permanent failures produce a terminal Failed condition.
    class StorageVersionMigratorController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      SUCCESS_REASON = "StorageVersionMigrationSucceeded".freeze
      RUNNING_REASON = "StorageVersionMigrationInProgress".freeze
      FAILED_REASON = "StorageVersionMigrationFailed".freeze

      def plan(migration, resources: nil, patch_results: {}, now: nil, gc_resource_version: nil,
               resource_descriptor: nil, target_api_version: nil, target_kind: nil, store: nil, **_options)
        return result(migration, operations: [], controller: name, descriptor: STORAGE_VERSION_MIGRATION) unless migration.is_a?(Hash)
        return result(migration, operations: [], controller: name, descriptor: STORAGE_VERSION_MIGRATION) if terminal?(migration)

        status = Support.deep_copy(Support.status(migration))
        checkpoint = Support.value(status, "resourceVersion", nil).to_s
        if checkpoint.empty?
          return result(migration, operations: [], events: [{"type" => "Normal", "reason" => "MigrationRunning",
                                                            "message" => "waiting for the storage version checkpoint"}],
                        controller: name, descriptor: STORAGE_VERSION_MIGRATION)
        end

        unless valid_resource_version?(checkpoint)
          return failed_result(migration, "invalid migration checkpoint resourceVersion #{checkpoint.inspect}", now)
        end
        if gc_resource_version && valid_resource_version?(gc_resource_version.to_s) && compare_resource_version(gc_resource_version.to_s, checkpoint) == -1
          return result(migration, operations: [], events: [{"type" => "Normal", "reason" => "MigrationRunning",
                                                             "message" => "garbage-collector cache is behind the migration checkpoint",
                                                             "retryable" => true}],
                        controller: name, descriptor: STORAGE_VERSION_MIGRATION)
        end
        if gc_resource_version && !valid_resource_version?(gc_resource_version.to_s)
          return failed_result(migration, "invalid garbage-collector resourceVersion #{gc_resource_version.inspect}", now)
        end

        target_spec = Support.value(Support.spec(migration), "resource", {})
        target_resource = if target_spec.is_a?(Hash)
                           value_at(target_spec, "resource", "name")
                         else
                           target_spec
                         end
        target_resource = target_resource.to_s
        if resources.nil? && (adapter = adapter_for(store))
          target_group = value_at(target_spec, "group", "apiGroup").to_s if target_spec.is_a?(Hash)
          target_group ||= ""
          resources = adapter.all.select do |candidate|
            api_group, = ResourceDescriptor.split_api_version(Support.api_version(candidate))
            kind_resource = ResourceDescriptor.pluralize(Support.kind(candidate))
            (target_group.empty? || api_group == target_group) &&
              (target_resource.empty? || kind_resource == target_resource)
          end
        end
        resources ||= []
        operations = []
        retry_event = nil
        permanent_error = nil

        Array(resources).each do |resource|
          rv = metadata_value(resource, "resourceVersion", nil).to_s
          unless valid_resource_version?(rv)
            permanent_error = "resource #{object_name(resource)} has invalid resourceVersion #{rv.inspect}"
            break
          end
          next if compare_resource_version(rv, checkpoint) == 1

          key = [Support.namespace(resource), Support.name(resource)].compact.join("/")
          outcome = patch_outcome(patch_results, resource, key)
          case outcome
          when :conflict, "conflict"
            next
          when :retry, "retry"
            retry_event = {"type" => "Warning", "reason" => "MigrationRetry",
                           "message" => "resource #{object_name(resource)} could not be migrated yet", "retryable" => true}
            break
          when nil, :success, "success"
            descriptor = target_descriptor(resource, resource_descriptor, target_resource)
            operations << Operation.new(
              action: :patch, resource: descriptor,
              key: object_key(descriptor, resource), object: resource,
              patch: {"apiVersion" => (target_api_version || descriptor.api_version).to_s,
                      "kind" => (target_kind || descriptor.kind).to_s,
                      "metadata" => {"uid" => Support.uid(resource),
                                     "resourceVersion" => rv}},
              reason: "migrate stored resource version"
            )
          else
            if retriable_outcome?(outcome)
              retry_event = {"type" => "Warning", "reason" => "MigrationRetry",
                             "message" => "resource #{object_name(resource)} migration failed transiently", "retryable" => true}
              break
            end
            permanent_error = "migration encountered unhandled error for #{object_name(resource)}: #{outcome}"
            break
          end
        end

        return result(migration, operations: operations, events: [retry_event].compact,
                      controller: name, descriptor: STORAGE_VERSION_MIGRATION) if retry_event
        return failed_result(migration, permanent_error, now, operations: operations) if permanent_error

        desired_status = with_migration_condition(status, "MigrationSucceeded", "True", SUCCESS_REASON, "", now)
        status_operation = operation_status(migration, desired_status, descriptor: STORAGE_VERSION_MIGRATION,
                                            reason: "mark storage version migration succeeded")
        operations << status_operation if status_operation
        result(migration, operations: operations,
               events: [{"type" => "Normal", "reason" => "MigrationSucceeded",
                         "message" => "storage version migration completed"}],
               status: desired_status, controller: name, descriptor: STORAGE_VERSION_MIGRATION)
      end

      private

      def terminal?(migration)
        condition_list(migration).any? do |condition|
          %w[MigrationSucceeded MigrationFailed].include?(Support.value(condition, "type", "").to_s) &&
            Support.value(condition, "status", "").to_s == "True"
        end
      end

      def valid_resource_version?(value)
        value.to_s.match?(/\A[1-9]\d*\z/)
      end

      def compare_resource_version(left, right)
        left_text = left.to_s
        right_text = right.to_s
        return -1 if left_text.length < right_text.length
        return 1 if left_text.length > right_text.length

        left_text <=> right_text
      end

      def patch_outcome(results, resource, key)
        return nil unless results.is_a?(Hash)
        results[key] || results[[Support.namespace(resource), Support.name(resource)]] || results[Support.name(resource)]
      end

      def retriable_outcome?(outcome)
        return true if outcome.is_a?(Hash) && (value_at(outcome, "retryable", "retriable") == true)
        return true if outcome.respond_to?(:status) && [408, 429, 500, 502, 503, 504].include?(outcome.status.to_i)
        outcome.to_s.match?(/timeout|too many requests|unavailable|internal|connection|temporary|retry/i)
      end

      def target_descriptor(resource, explicit, target_resource)
        return ResourceDescriptor.parse(explicit) if explicit

        api_version = Support.api_version(resource) || "v1"
        kind = Support.kind(resource)
        scope = Support.namespace(resource).nil? ? :cluster : :namespaced
        ResourceDescriptor.parse({"apiVersion" => api_version, "kind" => kind},
                                 resource: (target_resource.empty? ? nil : target_resource), scope: scope)
      end

      def with_migration_condition(status, type, state, reason, message, now)
        next_status = Support.deep_copy(status)
        conditions = Array(Support.value(next_status, "conditions", [])).map { |condition| Support.deep_copy(condition) }
        current = conditions.find { |condition| Support.value(condition, "type", "").to_s == type.to_s }
        return next_status if current && Support.value(current, "status", "").to_s == state.to_s &&
                              Support.value(current, "reason", "").to_s == reason.to_s &&
                              Support.value(current, "message", "").to_s == message.to_s
        desired = current || {"type" => type}
        desired["status"] = state
        desired["reason"] = reason
        desired["message"] = message
        desired["lastTransitionTime"] = normalize_time(now).utc.iso8601(9) if now
        conditions << desired unless current
        next_status["conditions"] = conditions
        next_status
      end

      def failed_result(migration, message, now, operations: [])
        desired_status = with_migration_condition(Support.status(migration), "MigrationFailed", "True", FAILED_REASON,
                                                  message.to_s, now)
        operation = operation_status(migration, desired_status, descriptor: STORAGE_VERSION_MIGRATION,
                                     reason: "mark storage version migration failed")
        result(migration, operations: operations + [operation].compact,
               events: [{"type" => "Warning", "reason" => "MigrationFailed", "message" => message.to_s}],
               status: desired_status, controller: name, descriptor: STORAGE_VERSION_MIGRATION)
      end
    end

    # Emits warning events for Pod pairs that share a volume with incompatible
    # SELinux policies or labels.  Kubernetes intentionally performs no API
    # mutation here (warning Events are the sole side effect).
    class SELinuxWarningController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      def plan(pod, pods: nil, nodes: [], volumes: nil, store: nil, **_options)
        return result(pod, operations: [], controller: name, descriptor: POD) unless pod.is_a?(Hash)

        if pods.nil? && (adapter = adapter_for(store))
          pods = list_for(adapter, POD, namespace: :all)
        end
        snapshot = Array(pods)
        snapshot = snapshot + [pod] unless snapshot.any? { |candidate| pod_key(candidate) == pod_key(pod) }
        snapshot = snapshot.select do |candidate|
          (Support.kind(candidate).empty? || Support.kind(candidate) == "Pod") &&
            !%w[Succeeded Failed].include?(Support.value(Support.status(candidate), "phase", "").to_s)
        end
        descriptors = snapshot.sort_by { |candidate| pod_key(candidate) }
        by_volume = Hash.new { |hash, key| hash[key] = [] }
        descriptors.each do |candidate|
          volume_records(candidate, volumes).each do |record|
            by_volume[record[:identity]] << record.merge(pod: candidate)
          end
        end

        events = []
        by_volume.keys.sort.each do |identity|
          records = by_volume[identity].sort_by { |record| pod_key(record[:pod]) }
          records.combination(2).each do |left, right|
            if left[:policy] != right[:policy]
              events.concat(conflict_events(left, right, "SELinuxChangePolicy", "SELinuxChangePolicyConflict"))
            end
            if selinux_labels_conflict?(left[:label], right[:label])
              events.concat(conflict_events(left, right, "SELinuxLabel", "SELinuxLabelConflict"))
            end
          end
        end
        # Avoid duplicate reports where a Pod has two equivalent volume
        # entries; preserve deterministic first-seen ordering.
        events = events.each_with_object([]) do |event, unique|
          key = [event["pod"], event["otherPod"], event["reason"], event["message"]]
          unique << event unless unique.any? { |existing| [existing["pod"], existing["otherPod"], existing["reason"], existing["message"]] == key }
        end
        result(pod, operations: [], events: events, status: Support.status(pod),
               controller: name, descriptor: POD)
      end

      private

      def pod_key(pod)
        [Support.namespace(pod), Support.name(pod)].compact.join("/")
      end

      def volume_records(pod, supplied_volumes)
        source = Array(value_at(Support.spec(pod), "volumes"))
        source = Array(supplied_volumes[pod_key(pod)]) if supplied_volumes.is_a?(Hash) && supplied_volumes.key?(pod_key(pod))
        source.filter_map do |volume|
          identity = unique_volume_identity(pod, volume)
          next if identity.nil? || identity.empty?

          policy = effective_policy(pod, volume)
          label = effective_label(pod, volume)
          policy = "Recursive" if label.to_s.empty? && policy != "Recursive"
          label = "" if policy == "Recursive"
          {identity: identity, policy: policy, label: label}
        end
      end

      def unique_volume_identity(pod, volume)
        return volume.to_s unless volume.is_a?(Hash)
        direct = value_at(volume, "uniqueVolumeName", "unique_volume_name", "volumeName", "volume_name")
        return direct.to_s unless direct.to_s.empty?
        pvc = value_at(volume, "persistentVolumeClaim")
        if pvc.is_a?(Hash)
          claim = value_at(pvc, "claimName", "name").to_s
          return "pvc:#{Support.namespace(pod)}/#{claim}" unless claim.empty?
        end
        csi = value_at(volume, "csi")
        if csi.is_a?(Hash)
          driver = value_at(csi, "driver").to_s
          handle = value_at(csi, "volumeHandle", "volume_handle").to_s
          return "csi:#{driver}:#{handle}" unless driver.empty? || handle.empty?
        end
        host = value_at(volume, "hostPath")
        return "hostPath:#{value_at(host, "path")}" if host.is_a?(Hash) && !value_at(host, "path").to_s.empty?

        # EmptyDir and projected ephemeral volumes are Pod-local and cannot
        # represent a shared volume between Pods.
        nil
      end

      def effective_policy(pod, volume)
        security_context = Support.value(Support.spec(pod), "securityContext", {})
        policy = value_at(security_context, "seLinuxChangePolicy", "selinuxChangePolicy") ||
                 value_at(pod, "seLinuxChangePolicy", "selinux_change_policy") || "MountOption"
        unsupported = value_at(volume, "supportsSELinuxContextMount", "supports_selinux_context_mount")
        policy = "Recursive" if unsupported == false
        policy.to_s == "Recursive" ? "Recursive" : "MountOption"
      end

      def effective_label(pod, volume)
        direct = value_at(volume, "seLinuxLabel", "selinuxLabel")
        return direct.to_s unless direct.nil?
        security_context = Support.value(Support.spec(pod), "securityContext", {})
        options = value_at(volume, "seLinuxOptions") || value_at(security_context, "seLinuxOptions", "selinuxOptions")
        if options.is_a?(Hash)
          [value_at(options, "user"), value_at(options, "role"), value_at(options, "type"), value_at(options, "level")].map { |part| part.to_s }.join(":").then { |label| label == ":::" ? "" : label }
        else
          value_at(pod, "seLinuxLabel", "selinuxLabel").to_s
        end
      end

      def selinux_labels_conflict?(left, right)
        left_parts = left.to_s.split(":", 4)
        right_parts = right.to_s.split(":", 4)
        left_parts.fill(nil, left_parts.length...4)
        right_parts.fill(nil, right_parts.length...4)
        4.times do |index|
          a = left_parts[index].to_s
          b = right_parts[index].to_s
          next if a == b
          return true if index == 3
          next if a.empty? || b.empty?

          return true
        end
        false
      end

      def conflict_events(left, right, property, reason)
        first = event_for_conflict(left, right, property, reason)
        second = event_for_conflict(right, left, property, reason)
        [first, second]
      end

      def event_for_conflict(current, other, property, reason)
        current_key = pod_key(current[:pod])
        other_key = pod_key(other[:pod])
        if Support.namespace(current[:pod]) == Support.namespace(other[:pod])
          message = "#{property} \"#{current[property_key(property)]}\" conflicts with pod #{Support.name(other[:pod])} that uses the same volume as this pod with #{property} \"#{other[property_key(property)]}\". If both pods land on the same node, only one of them may access the volume."
        else
          message = "#{property} \"#{current[property_key(property)]}\" conflicts with another pod that uses the same volume as this pod with a different #{property}. If both pods land on the same node, only one of them may access the volume."
        end
        {"type" => "Warning", "reason" => reason, "message" => message,
         "pod" => current_key, "otherPod" => other_key, "property" => property,
         "propertyValue" => current[property_key(property)], "otherPropertyValue" => other[property_key(property)]}
      end

      def property_key(property)
        property == "SELinuxLabel" ? :label : :policy
      end
    end

    # Opt-in registration metadata for the seven controllers in this batch.
    # The parent controller entrypoint can register these definitions in one
    # atomic operation once all parallel implementation batches are loaded.
    module AdvancedMiscControllerFactory
      VERSION = "v1.36.2".freeze
      NAMES = %w[
        resourceclaim-controller
        resourcepoolstatusrequest-controller
        legacy-serviceaccount-token-cleaner-controller
        validatingadmissionpolicy-status-controller
        service-cidr-controller
        storage-version-migrator-controller
        selinux-warning-controller
      ].freeze
      CONTROLLER_NAMES = NAMES

      IMPLEMENTATIONS = {
        "resourceclaim-controller" => ResourceClaimController,
        "resourcepoolstatusrequest-controller" => ResourcePoolStatusRequestController,
        "legacy-serviceaccount-token-cleaner-controller" => LegacyServiceAccountTokenCleanerController,
        "validatingadmissionpolicy-status-controller" => ValidatingAdmissionPolicyStatusController,
        "service-cidr-controller" => ServiceCIDRController,
        "storage-version-migrator-controller" => StorageVersionMigratorController,
        "selinux-warning-controller" => SELinuxWarningController
      }.freeze

      WATCHES = {
        "resourceclaim-controller" => [
          ["ResourceClaim", :all], ["Pod", :all], ["ResourceClaimTemplate", :all]
        ],
        "resourcepoolstatusrequest-controller" => [
          ["ResourcePoolStatusRequest", :all], ["ResourceSlice", :all], ["ResourceClaim", :all]
        ],
        "legacy-serviceaccount-token-cleaner-controller" => [
          ["Secret", :all], ["ServiceAccount", :all], ["Pod", :all]
        ],
        "validatingadmissionpolicy-status-controller" => [
          ["ValidatingAdmissionPolicy", :all], ["ValidatingAdmissionPolicyBinding", :all]
        ],
        "service-cidr-controller" => [
          ["ServiceCIDR", :all], ["IPAddress", :all], ["Node", :all]
        ],
        "storage-version-migrator-controller" => [["StorageVersionMigration", :all]],
        "selinux-warning-controller" => [["Pod", :all], ["Node", :all]]
      }.freeze

      METADATA = NAMES.each_with_object({}) do |controller_name, metadata|
        entry = BuiltinControllerCorpus.fetch(controller_name)
        metadata[controller_name] = {
          kind: entry.kind, feature_gates: entry.feature_gates,
          startup_conditions: entry.startup_conditions, sync_targets: entry.sync_targets,
          status_fields: entry.status_fields, events: entry.events
        }.freeze
      end.freeze

      module_function

      def names
        NAMES
      end

      def metadata(name = nil)
        return entries.map(&:to_h).freeze if name.nil?

        Support.immutable_copy(METADATA.fetch(name.to_s))
      end

      def implementation(name)
        IMPLEMENTATIONS.fetch(name.to_s)
      end

      def entries
        NAMES.map { |controller_name| BuiltinControllerCorpus.fetch(controller_name) || raise(ValidationError, "missing pinned corpus entry #{controller_name.inspect}") }
      end

      def definitions(registry: nil)
        NAMES.map { |controller_name| definition(controller_name, registry: registry) }.freeze
      end

      alias build_definitions definitions

      def definition(controller_name, registry: nil)
        controller_name = controller_name.to_s
        metadata = METADATA.fetch(controller_name)
        implementation = IMPLEMENTATIONS.fetch(controller_name)
        kind_descriptor = usable_descriptor(descriptor_for(metadata.fetch(:kind)), registry)
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
        definition = ControllerDefinition.new(
          name: controller_name, kind: kind_descriptor, owns: [],
          watches: watch_specs(controller_name, registry: registry), reconcile_block: reconcile,
          feature_gates: metadata.fetch(:feature_gates), startup_conditions: metadata.fetch(:startup_conditions),
          sync_targets: metadata.fetch(:sync_targets), status_fields: metadata.fetch(:status_fields),
          events: metadata.fetch(:events), implementation: implementation
        )
        definition
      end

      def register!(registry)
        definitions(registry: registry).each { |definition| registry.register(definition) }
        registry
      end

      alias register register!

      def descriptor_for(kind)
        case kind.to_s
        when "ResourcePoolStatusRequest"
          AdvancedMiscSupport::RESOURCE_POOL_STATUS_REQUEST
        when "ValidatingAdmissionPolicyBinding"
          AdvancedMiscSupport::VAP_BINDING
        when "IPAddress"
          AdvancedMiscSupport::IP_ADDRESS
        when "StorageVersionMigration"
          AdvancedMiscSupport::STORAGE_VERSION_MIGRATION
        else
          ResourceDescriptor.parse(kind)
        end
      end

      # Watches whose event is reconciled as the observed object itself
      # (WatchSpec route: :self): a Pod needs claims created for it, a
      # ResourceClaimTemplate names the Pods waiting for it.
      SELF_ROUTED_WATCHES = {"resourceclaim-controller" => %w[Pod ResourceClaimTemplate]}.freeze

      def watch_specs(controller_name, registry: nil)
        WATCHES.fetch(controller_name).each_with_index.map do |(kind, relationship), index|
          descriptor = usable_descriptor(descriptor_for(kind), registry)
          route = SELF_ROUTED_WATCHES.fetch(controller_name, []).include?(kind) ? :self : :fan_out
          queue_key = if controller_name == "resourceclaim-controller" && kind == "Pod"
                        ->(object) { ResourceClaimController.pod_queue_keys(object) }
                      else
                        ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") }
                      end
          WatchSpec.new(resource: descriptor, via: relationship,
                        index_name: "advanced/#{controller_name}/#{index}",
                        predicate: ->(_object) { true },
                        queue_key: queue_key, scope: descriptor.scope, route: route)
        end.freeze
      end

      def usable_descriptor(descriptor, registry)
        return descriptor unless registry

        registry.validate_descriptor!(descriptor)
        descriptor
      rescue UnknownGVKError
        ResourceDescriptor.parse(descriptor.kind)
      end
    end

    AdvancedMiscRegistration = AdvancedMiscControllerFactory
  end
end
