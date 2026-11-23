# frozen_string_literal: true

require_relative "resource_claim_workloads"

require "ipaddr"
require "time"

require_relative "runtime"
require_relative "support"
require_relative "types"
require_relative "secondary_support"
require_relative "registry"
require_relative "builtin_factory"
require_relative "../support/service_cidr"

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
      IP_ADDRESS = ResourceDescriptor.parse("IPAddress")
      RESOURCE_POOL_STATUS_REQUEST = ResourceDescriptor.parse("ResourcePoolStatusRequest")
      VAP_BINDING = ResourceDescriptor.parse("ValidatingAdmissionPolicyBinding")
      STORAGE_VERSION_MIGRATION = ResourceDescriptor.parse("StorageVersionMigration")

      RESOURCE_CLAIM_FINALIZER = "resource.kubernetes.io/delete-protection"
      SERVICE_ACCOUNT_TOKEN_TYPE = "kubernetes.io/service-account-token"
      TRACKING_CONFIG_MAP = "kube-apiserver-legacy-service-account-token-tracking"
      TRACKING_NAMESPACE = "kube-system"
      LAST_USED_LABEL = "kubernetes.io/legacy-token-last-used"
      INVALID_SINCE_LABEL = "kubernetes.io/legacy-token-invalid-since"
      SERVICE_CIDR_FINALIZER = "networking.k8s.io/service-cidr-finalizer"
      # The reason kube-apiserver stamps on the default ServiceCIDR's Ready
      # condition when it publishes --service-cluster-ip-range (see
      # Api::ServiceAllocator#bootstrap!).  The controller must agree with it:
      # a metav1.Condition requires a reason, and a controller that reconciles
      # towards a different one rewrites the status on every pass forever.
      SERVICE_CIDR_READY_REASON = "KubernetesServiceCIDRIsReady"

      module_function

      def normalize_time(value, fallback = nil)
        parsed = Support.parse_time(value)
        parsed ||= fallback if fallback
        raise ArgumentError, "clock must return Time or RFC3339 value" unless parsed

        parsed.utc
      end

      def result(resource, operations:, events: [], status: nil, controller: nil, descriptor: nil, requeue_after: nil)
        key = if resource
                namespace = descriptor&.cluster_scoped? ? nil : Support.namespace(resource)
                [namespace, Support.name(resource)].compact.join("/")
              end
        ReconcileResult.new(operations: operations.compact, status: status || Support.status(resource),
                            events: events, controller: controller, key: key, requeue_after: requeue_after)
      end

      def condition_list(resource_or_status)
        source = if resource_or_status.is_a?(Hash) && Support.value(resource_or_status, "status", nil).is_a?(Hash)
                   Support.status(resource_or_status)
                 else
                   resource_or_status
                 end
        Array(Support.value(source, "conditions", [])).grep(Hash)
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
      include ResourceClaimWorkloads

      TEMPLATE = ResourceDescriptor.parse("ResourceClaimTemplate")
      POD_CLAIM_ANNOTATION = "resource.kubernetes.io/pod-claim-name"
      # utilrand.String: lower-case consonants and digits without vowels
      # or look-alikes.
      NAME_ALPHABET = "bcdfghjklmnpqrstvwxz2456789"

      def initialize(*, random: Random.new, **)
        super(*, **)
        @random = random
      end

      def plan(object, pods: nil, deleted_pod_uids: [], authoritative_pods: nil, now: nil, store: nil, feature_gates: {}, **)
        return result(object, operations: [], controller: name, descriptor: RESOURCE_CLAIM) unless object.is_a?(Hash)

        workload_claims = feature_gates[WORKLOAD_CLAIMS::GATE] == true
        adapter = adapter_for(store)
        kind = Support.kind(object)
        primary = case kind
                  when "Pod" then plan_pod(object, store: store, workload_claims: workload_claims, **)
                  when "PodGroup"
                    return plan_pod_group(object, store: store, **) if workload_claims

                    return result(object, operations: [], controller: name, descriptor: CLAIM_POD_GROUP)
                  when "ResourceClaimTemplate" then plan_template(object, store: store, workload_claims: workload_claims, **)
                  else plan_claim(object, pods: pods, deleted_pod_uids: deleted_pod_uids, workload_claims: workload_claims,
                                          authoritative_pods: authoritative_pods, store: store, **)
                  end
        secondary = []
        # The queue uses namespace/name for all three kinds. Preserve the
        # related Pod and PodGroup work even if a ResourceClaim owns that key.
        if kind == "ResourceClaim" && (pod = find_for(adapter, POD, Support.name(object), namespace: Support.namespace(object)))
          secondary << plan_pod(pod, store: store, workload_claims: workload_claims, **)
        end
        if workload_claims && (group = related_pod_group(object, adapter))
          secondary << plan_pod_group(group, store: store)
        end
        return primary if secondary.empty?

        ReconcileResult.new(operations: primary.operations + secondary.flat_map(&:operations),
                            events: Array(primary.events) + secondary.flat_map(&:events), status: primary.status, controller: name, key: primary.key)
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
        {"allocated" => claim.dig("status", "allocation").nil? ? "false" : "true", "admin_access" => admin_access_label(claim),
         "source" => source}
      end

      def self.pod_queue_keys(pod)
        namespace = Support.namespace(pod)
        keys = [[namespace, Support.name(pod)].compact.join("/")]
        claims = Array(Support.value(Support.spec(pod), "resourceClaims", []))
        extended = Support.value(Support.status(pod), "extendedResourceClaimStatus", nil)
        if extended.is_a?(Hash) && !extended["resourceClaimName"].to_s.empty?
          keys << [namespace,
                   extended["resourceClaimName"]].compact.join("/")
        end
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

      def self.claim_queue_keys(claim)
        namespace = Support.namespace(claim)
        reference = AdvancedMiscSupport.owner_reference(claim, kind: "PodGroup")
        owner = Support.ref_value(reference, "name", nil) if reference
        [Support.name(claim), owner].compact.map { |name| "#{namespace}/#{name}" }
      end

      def self.group_queue_keys(group, adapter)
        namespace = Support.namespace(group)
        keys = pod_queue_keys(group)
        members = adapter.list(POD, namespace: namespace).select do |pod|
          WORKLOAD_CLAIMS.member?(pod, group) && !Array(Support.spec(pod)["resourceClaims"]).empty?
        end
        keys + members.map { |pod| "#{namespace}/#{Support.name(pod)}" }
      end

      def self.template_queue_keys(template, adapter)
        namespace = Support.namespace(template)
        template_name = Support.name(template)
        [POD, CLAIM_POD_GROUP].flat_map do |kind|
          adapter.list(kind, namespace: namespace).filter_map do |object|
            if Array(Support.spec(object)["resourceClaims"]).any? { |entry| entry["resourceClaimTemplateName"] == template_name }
              "#{namespace}/#{Support.name(object)}"
            end
          end
        end
      end

      # ---------------------------------------------------------- syncPod

      def plan_pod(pod, store: nil, claims: nil, templates: nil, workload_claims: false, pod_group: nil, **_options)
        empty = result(pod, operations: [], controller: name, descriptor: POD)
        return empty unless metadata_value(pod, "deletionTimestamp", nil).nil?
        return empty if Array(value_at(Support.spec(pod), "resourceClaims")).empty?

        adapter = adapter_for(store)
        namespace = Support.namespace(pod)
        pod_group ||= pod_group_for(pod, adapter) if workload_claims
        claims ||= adapter ? list_for(adapter, RESOURCE_CLAIM, namespace: namespace) : []
        templates ||= adapter ? list_for(adapter, TEMPLATE, namespace: namespace) : []
        operations = []
        events = []
        new_statuses = {}
        created = []
        Array(value_at(Support.spec(pod), "resourceClaims")).each do |pod_claim|
          begin
            claim = handle_claim(pod, pod_claim, claims + created, templates, pod_group: pod_group)
          rescue ClaimFailure => error
            events << {"type" => "Warning", "reason" => "FailedResourceClaimCreation",
                       "message" => "PodResourceClaim #{pod_claim["name"]}: #{error.message}"}
            return result(pod, operations: operations, events: events, controller: name, descriptor: POD)
          end
          next if claim.nil?

          if claim[:create]
            created << claim[:create]
            operations << template_claim_creation(claim[:create])
          end
          new_statuses[pod_claim["name"].to_s] = claim[:name]
        end
        unless new_statuses.empty?
          statuses = new_statuses.map { |pod_claim_name, claim_name| {"name" => pod_claim_name, "resourceClaimName" => claim_name} }
          status = {"resourceClaimStatuses" => merge_claim_statuses(pod, statuses)}
          operations << operation_status(pod, status, descriptor: POD, reason: "record ResourceClaims created for the Pod", force: true)
        end
        return result(pod, operations: operations, events: events, controller: name, descriptor: POD) if value_at(Support.spec(pod),
                                                                                                                  "nodeName").to_s.empty?

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
          next if check_owner && !owned_by_workload?(claim, pod, pod_group)
          next if value_at(Support.status(claim), "allocation").nil? || WORKLOAD_CLAIMS.reserved_for_pod?(pod, claim, workload_claims: workload_claims)

          status = Support.deep_copy(Support.status(claim))
          status["reservedFor"] = Array(status["reservedFor"]) + [WORKLOAD_CLAIMS.reference_for(pod, pod_claim, pod_group, workload_claims: workload_claims)]
          operations << operation_status(claim, status, descriptor: RESOURCE_CLAIM, reason: "reserve claim for scheduled Pod")
        end
        result(pod, operations: operations, events: events, controller: name, descriptor: POD)
      end

      def plan_template(template, store: nil, workload_claims: false, **)
        adapter = adapter_for(store)
        return result(template, operations: [], controller: name, descriptor: TEMPLATE) unless adapter

        pods = list_for(adapter, POD, namespace: Support.namespace(template)).select do |pod|
          Array(value_at(Support.spec(pod), "resourceClaims")).any? { |entry| entry["resourceClaimTemplateName"] == Support.name(template) }
        end
        operations = pods.flat_map { |pod| plan_pod(pod, store: store, workload_claims: workload_claims, **).operations }
        result(template, operations: operations, controller: name, descriptor: TEMPLATE)
      end

      class ClaimFailure < StandardError; end

      # handleClaim: {name:, create:} for a claim the Pod's status must name,
      # nil when there is nothing to record.
      def handle_claim(pod, pod_claim, claims, templates, pod_group: nil)
        begin
          claim_name, must_check_owner = claim_name_for(pod, pod_claim)
        rescue ClaimNotCreated
          claim_name = :not_created
        end
        return nil if claim_name.nil?

        unless claim_name == :not_created
          existing = claims.find { |candidate| Support.name(candidate) == claim_name }
          return nil if existing && (!must_check_owner || owned_by_workload?(existing, pod, pod_group))
        end
        template_name = pod_claim["resourceClaimTemplateName"]
        return nil if template_name.nil?

        owner = WORKLOAD_CLAIMS.matching_group_claim(pod_group, pod_claim) ? pod_group : pod
        found = claims.find do |candidate|
          owned_by_consumer?(candidate, owner) && metadata_value(candidate, "annotations", {}).to_h[POD_CLAIM_ANNOTATION] == pod_claim["name"]
        end
        return {name: Support.name(found), create: nil} if found
        return nil unless owner.equal?(pod)

        template = templates.find { |candidate| Support.name(candidate) == template_name }
        unless template
          raise ClaimFailure,
                "resource claim template \"#{template_name}\": resourceclaimtemplate.resource.k8s.io \"#{template_name}\" not found"
        end

        spec = Support.spec(template)
        template_metadata = spec["metadata"] || {}
        annotations = (template_metadata["annotations"] || {}).merge(POD_CLAIM_ANNOTATION => pod_claim["name"].to_s)
        claim = {
          "apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
          "metadata" => {
            "name" => generated_name(Support.name(pod), pod_claim["name"].to_s),
            "namespace" => Support.namespace(pod),
            "ownerReferences" => [claim_owner_reference(pod)],
            "annotations" => annotations
          },
          "spec" => Support.deep_copy(spec["spec"] || {})
        }
        claim["metadata"]["labels"] = template_metadata["labels"] if template_metadata["labels"]
        {name: claim["metadata"]["name"], create: claim}
      end

      class ClaimNotCreated < StandardError; end

      def claim_owner_reference(consumer)
        reference = Support.owner_reference(consumer)
        reference.delete("blockOwnerDeletion") if Support.kind(consumer) == "PodGroup"
        reference
      end

      def template_claim_creation(claim)
        admin_access = self.class.admin_access_label(claim)
        operation_create(claim, descriptor: RESOURCE_CLAIM, reason: "create ResourceClaim from template").observed do |succeeded, _|
          ControllerMetrics.increment("resourceclaim_controller_creates_total",
                                      {"status" => succeeded ? "success" : "failure", "admin_access" => admin_access})
        end
      end

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
        base = "#{pod_name[0, pod_name.length * 57 / base.length]}-#{claim_name[0, claim_name.length * 57 / base.length]}" if base.length > 57
        base + Array.new(5) { NAME_ALPHABET[@random.rand(NAME_ALPHABET.length)] }.join
      end

      def owned_by_consumer?(claim, consumer)
        reference = owner_reference(claim)
        reference && Support.ref_value(reference, "uid", "").to_s == Support.uid(consumer).to_s
      end

      def owned_by_workload?(claim, pod, pod_group)
        owned_by_consumer?(claim, pod) || (pod_group && owned_by_consumer?(claim, pod_group))
      end

      # -------------------------------------------------------- syncClaim

      def plan_claim(claim, pods: nil, deleted_pod_uids: [], authoritative_pods: nil, store: nil,
                     workload_claims: false, pod_groups: nil, deleted_pod_group_uids: [], **_options)
        adapter = adapter_for(store)
        snapshot = authoritative_pods.nil? ? pods : authoritative_pods
        lookup_pod = reservation_pod_lookup(Support.namespace(claim), snapshot, adapter)
        deleted_uids = Array(deleted_pod_uids).to_set(&:to_s)
        status = Support.status(claim)
        reserved = Array(Support.value(status, "reservedFor")).grep(Hash)
        deleted_group_uids = Array(deleted_pod_group_uids).to_set(&:to_s)
        remaining = reserved.select do |reference|
          if workload_claims && WORKLOAD_CLAIMS.group_reference?(reference)
            keep_group_reservation?(claim, reference, pod_groups, deleted_group_uids, adapter)
          else
            keep_reserved_reference?(reference, lookup_pod, deleted_uids)
          end
        end

        operations = []
        events = []
        has_finalizer = Array(metadata_value(claim, "finalizers", [])).map(&:to_s).include?(RESOURCE_CLAIM_FINALIZER)
        deleting = !metadata_value(claim, "deletionTimestamp", nil).nil?
        pruned = remaining.length < reserved.length
        status = status.merge("reservedFor" => remaining) if pruned
        releasing = has_finalizer && remaining.empty? && (deleting || pruned)
        deallocated = releasing && status["allocation"]
        if deallocated
          status = status.except("allocation")
          events << {"type" => "Normal", "reason" => "ResourceClaimAllocated",
                     "message" => "ResourceClaim #{object_name(claim)} allocation released"}
        end
        if pruned || deallocated
          reason = pruned ? "remove stale ResourceClaim reservations" : "remove allocation because not needed"
          operations << operation_status(claim, status, descriptor: RESOURCE_CLAIM, reason: reason)
        end
        drop_finalizer = pruned ? status["allocation"].nil? : deleting && remaining.empty?
        operations << remove_finalizer(claim, status) if has_finalizer && drop_finalizer

        # Generated claims are deleted once their Pod was replaced or is done.
        if remaining.empty? && lookup_pod
          owner = owner_reference(claim, kind: "Pod")
          if owner && Support.ref_value(owner, "apiVersion", "v1").to_s == "v1"
            owner_pod = lookup_pod.call(Support.ref_value(owner, "name", "").to_s)
            if owner_pod && (Support.uid(owner_pod).to_s != Support.ref_value(owner, "uid", nil).to_s || pod_done?(owner_pod))
              operations << operation_delete(claim, descriptor: RESOURCE_CLAIM, reason: "delete unused generated ResourceClaim")
            end
          end
        end
        result(claim, operations: operations.compact, events: events, status: status, controller: name, descriptor: RESOURCE_CLAIM)
      end

      private

      # Store-backed reconciles look up only named consumers. An explicitly
      # supplied snapshot is authoritative, including an empty one.
      def reservation_pod_lookup(namespace, pods, adapter)
        if pods
          by_name = {}
          Array(pods).each { |pod| by_name[Support.name(pod)] ||= pod if Support.namespace(pod) == namespace }
          by_name.method(:[])
        elsif adapter
          ->(name) { find_for(adapter, POD, name, namespace: namespace) }
        end
      end

      def remove_finalizer(claim, status)
        metadata = Support.metadata(claim)
        finalizers = Array(Support.value(metadata, "finalizers")).map(&:to_s)
        finalizers.delete_at(finalizers.index(RESOURCE_CLAIM_FINALIZER))
        updated = claim.merge("metadata" => metadata.merge("finalizers" => finalizers), "status" => status)
        operation_update(claim, updated, descriptor: RESOURCE_CLAIM, reason: "remove ResourceClaim delete-protection finalizer")
      end

      def pod_reference?(reference)
        api_group(reference).to_s.empty? && Support.value(reference, "resource", "").to_s.downcase == "pods"
      end

      def keep_reserved_reference?(reference, lookup_pod, deleted_uids)
        return true unless pod_reference?(reference)

        uid = Support.value(reference, "uid", nil).to_s
        return false if !uid.empty? && deleted_uids.include?(uid)
        return true unless lookup_pod

        pod = lookup_pod.call(Support.value(reference, "name", "").to_s)
        pod && Support.uid(pod).to_s == uid && !pod_done?(pod)
      end

      # isPodDone.
      def pod_done?(pod)
        %w[Succeeded Failed].include?(Support.value(Support.status(pod), "phase", "").to_s) ||
          (!metadata_value(pod, "deletionTimestamp", nil).nil? && value_at(Support.spec(pod), "nodeName").to_s.empty?)
      end
    end

    require_relative "resource_pool_status_request_controller"

    # Deletes only auto-generated, demonstrably unused legacy service-account
    # token Secrets.  The first pass marks a token invalid; a later pass may
    # delete it after the configured grace period, matching Kubernetes' safety
    # behavior for malformed or newly observed tokens.
    class LegacyServiceAccountTokenCleanerController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      DATE_FORMAT = "%Y-%m-%d"
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
        return result(secret, operations: [], controller: name, descriptor: SECRET) unless service_account_references_secret?(
          service_account, secret
        )
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
        image_pull || volume_reference || Array(value_at(spec, "containers")).concat(Array(value_at(spec, "initContainers")))
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

        field_ref = if warning.respond_to?(:field_ref)
                      warning.field_ref
                    else
                      warning.respond_to?(:FieldRef) ? warning.FieldRef : nil
                    end
        message = if warning.respond_to?(:warning)
                    warning.warning
                  else
                    warning.respond_to?(:Warning) ? warning.Warning : warning.to_s
                  end
        {"fieldRef" => field_ref.to_s, "warning" => message.to_s}
      end
    end

    # Protects ServiceCIDR finalizers and status while respecting IPAddress
    # ownership and overlapping (parent) ServiceCIDRs.
    class ServiceCIDRController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      DELETION_GRACE_PERIOD = 10

      def self.queue_keys(object, adapter)
        # A new covering range can unblock a different range's deletion
        # without changing any IPAddress or the deleting ServiceCIDR itself.
        if object["kind"] == "IPAddress"
          keys = []
          address = IPAddr.new(Support.name(object))
          matches = ->(cidr) { Rubernetes::Support::ServiceCIDR.usable_address?(cidr, address) }
        else
          keys = [Support.name(object)]
          changed = Array(Support.spec(object)["cidrs"]).map { |prefix| IPAddr.new(prefix) }
          matches = ->(cidr) { changed.any? { |prefix| prefix.include?(cidr) || cidr.include?(prefix) } }
        end
        adapter.list(SERVICE_CIDR, namespace: :all).each do |pool|
          next unless Support.metadata(pool)["deletionTimestamp"]
          next unless Array(Support.spec(pool)["cidrs"]).any? { |prefix| matches.call(IPAddr.new(prefix)) }

          keys << Support.name(pool)
        end
        keys.uniq
      end

      def plan(service_cidr, service_cidrs: nil, ip_addresses: nil, now: nil,
               deletion_grace_period: DELETION_GRACE_PERIOD, store: nil, **_options)
        return result(service_cidr, operations: [], controller: name, descriptor: SERVICE_CIDR) unless service_cidr.is_a?(Hash)

        timestamp = normalize_time(now || Time.now.utc)
        finalizers = Array(metadata_value(service_cidr, "finalizers", [])).map(&:to_s)
        deleting = !metadata_value(service_cidr, "deletionTimestamp", nil).nil?
        operations = []
        events = []

        if deleting
          adapter = adapter_for(store)
          service_cidrs ||= list_for(adapter, SERVICE_CIDR)
          ip_addresses ||= list_for(adapter, IP_ADDRESS)
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
            return result(service_cidr, operations: [], events: events, controller: name, descriptor: SERVICE_CIDR,
                                        requeue_after: deletion_time + deletion_grace_period.to_f - timestamp)
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
        if operations.any?
          events << {"type" => "Normal", "reason" => "ServiceCIDRUpdated",
                     "message" => "ServiceCIDR is ready"}
        end
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
      rescue ArgumentError, TypeError
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
          cidr_strings(candidate).any? { |cidr| Rubernetes::Support::ServiceCIDR.usable_address?(IPAddr.new(cidr), address) }
        rescue ArgumentError
          false
        end
      end

      def can_delete?(service_cidr, service_cidrs, ip_addresses)
        candidates = Array(service_cidrs)
        candidates += [service_cidr] if candidates.none? { |candidate| Support.name(candidate) == Support.name(service_cidr) }
        own_cidrs = cidr_strings(service_cidr)
        has_parent = own_cidrs.all? do |own_cidr|
          candidates.any? do |candidate|
            next false if Support.name(candidate) == Support.name(service_cidr)

            cidr_strings(candidate).any? { |other| contains_prefix?(other, own_cidr) }
          end
        end
        return true if has_parent

        Array(ip_addresses).none? do |ip_address|
          address = IPAddr.new(Support.name(ip_address))
          next false unless allocated_address?(ip_address, address)

          containing = containing_cidrs(address, candidates)
          containing.one? && Support.name(containing.first) == Support.name(service_cidr)
        rescue IPAddr::Error
          false
        end
      end

      def allocated_address?(object, address)
        labels = Support.labels(object)
        manager = labels[Rubernetes::Support::ServiceCIDR::MANAGED_BY_LABEL]
        family = labels[Rubernetes::Support::ServiceCIDR::FAMILY_LABEL]
        # Older Rubernetes allocations carried only the old manager label.
        # Protect their owning Service until allocator repair updates the labels.
        return object.dig("spec", "parentRef", "resource") == "services" && family.nil? if manager == Rubernetes::Support::ServiceCIDR::LEGACY_MANAGER

        manager == Rubernetes::Support::ServiceCIDR::MANAGER && family == (address.ipv4? ? "IPv4" : "IPv6")
      end
    end

    # Migrates stored resources by applying only TypeMeta + UID/RV fences.
    # Conflicts are deliberately ignored; transient failures remain pending;
    # malformed or permanent failures produce a terminal Failed condition.
    class StorageVersionMigratorController < BaseController
      include AdvancedMiscSupport
      include SecondarySupport

      SUCCESS_REASON = "StorageVersionMigrationSucceeded"
      RUNNING_REASON = "StorageVersionMigrationInProgress"
      FAILED_REASON = "StorageVersionMigrationFailed"

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

        return failed_result(migration, "invalid migration checkpoint resourceVersion #{checkpoint.inspect}", now) unless valid_resource_version?(checkpoint)
        if gc_resource_version && valid_resource_version?(gc_resource_version.to_s) && compare_resource_version(gc_resource_version.to_s,
                                                                                                                checkpoint) == -1
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

        if retry_event
          return result(migration, operations: operations, events: [retry_event].compact,
                                   controller: name, descriptor: STORAGE_VERSION_MIGRATION)
        end
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
        snapshot += [pod] unless snapshot.any? { |candidate| pod_key(candidate) == pod_key(pod) }
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
            events.concat(conflict_events(left, right, "SELinuxChangePolicy", "SELinuxChangePolicyConflict")) if left[:policy] != right[:policy]
            events.concat(conflict_events(left, right, "SELinuxLabel", "SELinuxLabelConflict")) if selinux_labels_conflict?(left[:label], right[:label])
          end
        end
        # Avoid duplicate reports where a Pod has two equivalent volume
        # entries; preserve deterministic first-seen ordering.
        events = events.each_with_object([]) do |event, unique|
          key = [event["pod"], event["otherPod"], event["reason"], event["message"]]
          unique << event unless unique.any? do |existing|
            [existing["pod"], existing["otherPod"], existing["reason"], existing["message"]] == key
          end
        end
        record_conflict_metrics(pod, events)
        result(pod, operations: [], events: events, status: Support.status(pod),
                    controller: name, descriptor: POD)
      end

      CONFLICT_METRIC = "selinux_warning_controller_selinux_volume_conflict"
      CONFLICT_SERIES = {} # rubocop:disable Style/MutableConstant -- mutated at runtime (registry/cache)
      CONFLICT_SERIES_LOCK = Mutex.new

      private

      # selinux_warning_controller_selinux_volume_conflict: one series (value
      # 1) per conflicting Pod pair and property, as upstream's volume cache
      # collector emits them; this Pod's series are replaced on every sync so
      # a resolved conflict disappears.
      def record_conflict_metrics(pod, events)
        registry = Controller.metrics
        return unless registry

        key = pod_key(pod)
        series = events.select { |event| event["pod"] == key }.map do |event|
          namespace, name = event["pod"].to_s.split("/", 2)
          other_namespace, other_name = event["otherPod"].to_s.split("/", 2)
          {"property" => event["property"].to_s,
           "pod1_namespace" => namespace.to_s, "pod1_name" => name.to_s, "pod1_value" => event["propertyValue"].to_s,
           "pod2_namespace" => other_namespace.to_s, "pod2_name" => other_name.to_s, "pod2_value" => event["otherPropertyValue"].to_s}
        end.uniq
        registry.register(CONFLICT_METRIC, type: :gauge) unless registry.registered?(CONFLICT_METRIC)
        CONFLICT_SERIES_LOCK.synchronize do
          Array(CONFLICT_SERIES[key]).each { |labels| registry.delete(CONFLICT_METRIC, labels) unless series.include?(labels) }
          series.each { |labels| registry.set(CONFLICT_METRIC, 1, labels) }
          series.empty? ? CONFLICT_SERIES.delete(key) : CONFLICT_SERIES[key] = series
        end
      rescue StandardError
        nil
      end

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
          [value_at(options, "user"), value_at(options, "role"), value_at(options, "type"),
           value_at(options, "level")].join(":").then { |label| label == ":::" ? "" : label }
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
          message = "#{property} \"#{current[property_key(property)]}\" conflicts with pod #{Support.name(other[:pod])} that uses the same volume as this " \
                    "pod with #{property} \"#{other[property_key(property)]}\". If both pods land on the same node, only one of them may access the volume."
        else
          message = "#{property} \"#{current[property_key(property)]}\" conflicts with another pod that uses the same volume as this pod with a different " \
                    "#{property}. If both pods land on the same node, only one of them may access the volume."
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
      include BuiltinFactory

      VERSION = "v1.36.2"
      IMPLEMENTATIONS = {
        "resourceclaim-controller" => ResourceClaimController,
        "resourcepoolstatusrequest-controller" => ResourcePoolStatusRequestController,
        "legacy-serviceaccount-token-cleaner-controller" => LegacyServiceAccountTokenCleanerController,
        "validatingadmissionpolicy-status-controller" => ValidatingAdmissionPolicyStatusController,
        "service-cidr-controller" => ServiceCIDRController,
        "storage-version-migrator-controller" => StorageVersionMigratorController,
        "selinux-warning-controller" => SELinuxWarningController
      }.freeze
      NAMES = IMPLEMENTATIONS.keys.freeze
      CONTROLLER_NAMES = NAMES

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
          ["ServiceCIDR", :all], ["IPAddress", :all]
        ],
        "storage-version-migrator-controller" => [["StorageVersionMigration", :all]],
        "selinux-warning-controller" => [["Pod", :all], ["Node", :all]]
      }.freeze

      METADATA = NAMES.to_h { |name| [name, BuiltinControllerCorpus.fetch(name).metadata] }.freeze

      module_function :entries, :register!, :usable_descriptor
      alias register register!

      module_function

      def names = CONTROLLER_NAMES

      def metadata(name = nil)
        return entries.map(&:to_h).freeze if name.nil?

        Support.immutable_copy(METADATA.fetch(name.to_s))
      end

      def implementation(name)
        IMPLEMENTATIONS.fetch(name.to_s)
      end

      def definitions(registry: nil, feature_gates: {})
        NAMES.map { |controller_name| definition(controller_name, registry: registry, feature_gates: feature_gates) }.freeze
      end

      alias build_definitions definitions

      def definition(controller_name, registry: nil, feature_gates: {})
        controller_name = controller_name.to_s
        implementation = IMPLEMENTATIONS.fetch(controller_name)
        entry = BuiltinControllerCorpus.fetch(controller_name)
        kind = usable_descriptor(descriptor_for(entry.kind), registry)
        watches = watch_specs(controller_name, registry: registry, feature_gates: feature_gates)
        entry.build_controller(implementation, kind: kind, watches: watches) do |definition, store|
          implementation.new(store: store, definition: definition)
        end
      end

      def descriptor_for(kind) = ResourceDescriptor.parse(kind)

      # Watches whose event is reconciled as the observed object itself
      # (WatchSpec route: :self): a Pod needs claims created for it, a
      # ResourceClaimTemplate names the Pods waiting for it.
      SELF_ROUTED_WATCHES = {"resourceclaim-controller" => %w[Pod ResourceClaimTemplate]}.freeze

      def watch_specs(controller_name, registry: nil, feature_gates: {})
        watches = WATCHES.fetch(controller_name)
        use_workload_claims = controller_name == "resourceclaim-controller" && feature_gates[DRA::WorkloadClaims::GATE] == true
        watches += [["PodGroup", :all]] if use_workload_claims
        watches.each_with_index.map do |(kind, relationship), index|
          descriptor = usable_descriptor(descriptor_for(kind), registry)
          route = SELF_ROUTED_WATCHES.fetch(controller_name, []).include?(kind) ? :self : :fan_out
          route = :self if use_workload_claims && kind == "PodGroup"
          queue_key = if controller_name == "service-cidr-controller"
                        route = :mapped
                        ServiceCIDRController.method(:queue_keys)
                      elsif use_workload_claims && kind == "PodGroup"
                        ResourceClaimController.method(:group_queue_keys)
                      elsif use_workload_claims && kind == "ResourceClaim"
                        ResourceClaimController.method(:claim_queue_keys)
                      elsif use_workload_claims && kind == "ResourceClaimTemplate"
                        ResourceClaimController.method(:template_queue_keys)
                      elsif controller_name == "resourceclaim-controller" && kind == "Pod"
                        ResourceClaimController.method(:pod_queue_keys)
                      else
                        ->(object) { [Support.namespace(object), Support.name(object)].compact.join("/") }
                      end
          cache_only = controller_name == "resourcepoolstatusrequest-controller" && kind != "ResourcePoolStatusRequest"
          WatchSpec.new(resource: descriptor, via: relationship,
                        index_name: "advanced/#{controller_name}/#{index}",
                        predicate: ->(_object) { !cache_only },
                        queue_key: queue_key, scope: descriptor.scope, route: route)
        end.freeze
      end
    end

    AdvancedMiscRegistration = AdvancedMiscControllerFactory
  end
end
