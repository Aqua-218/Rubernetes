# frozen_string_literal: true

require "securerandom"
require "time"

require_relative "../dra"
require_relative "../dra/workload_claims"
require_relative "dynamic_resources/node_allocatable"
require_relative "dynamic_resources/filter"
require_relative "dynamic_resources/workload_claims"

module Rubernetes
  module Scheduler
    # pkg/scheduler/framework/plugins/dynamicresources (v1.36.2): scheduling
    # Pods that reference ResourceClaims.
    #
    #   PreEnqueue  every claim exists (a template's claim is named in
    #               status.resourceClaimStatuses), is not being deleted and,
    #               when generated, is owned by the Pod
    #   PreFilter   (run on the cycle's first Filter call) claims already in
    #               use elsewhere, allocated claims' node selectors, device
    #               classes, and the allocator for the rest
    #   Filter      allocated claims must be usable on the node; the others
    #               are allocated for it by the structured allocator
    #   Score       prioritized-list (firstAvailable) choices, normalized
    #   Reserve     the node's allocations become in-flight, so no other Pod
    #               can take the same devices before the API has them
    #   Unreserve   in-flight allocations dropped, the Pod's reservation
    #               removed from claims it was added to
    #   PreBind     each claim gets the delete-protection finalizer, its
    #               allocation and the Pod in status.reservedFor
    #   PostFilter  an allocated claim that no other Pod uses is deallocated
    #               when it blocked the Pod everywhere
    #
    # Claims, slices and classes come from the scheduler's informers
    # (context.volume_data "resourceClaims" / "resourceSlices" /
    # "deviceClasses"), with the claims this plugin wrote overlaid until the
    # informer has caught up (the assume cache).
    class DynamicResources
      NAME = "DynamicResources"
      FINALIZER = "resource.kubernetes.io/delete-protection"
      # resourceapi.FirstAvailableDeviceRequestMaxSize.
      FIRST_AVAILABLE_MAX = 8
      # DynamicResourcesBindingTimeoutDefault.
      BINDING_TIMEOUT = 600.0
      STATE_KEY = :dynamic_resources
      RESOURCE = "resourceclaims"

      class ClaimError < StandardError; end
      class APIError < StandardError; end

      # The claim reads and writes, over a Client::KubernetesClient
      # (resource.k8s.io/v1).  Conflicts surface as the client's APIError
      # with status 409.
      class ClientAPI
        API_VERSION = "resource.k8s.io/v1"

        def initialize(client) = @client = client

        def get_claim(namespace, name)
          @client.get(RESOURCE, name, namespace: namespace, api_version: API_VERSION)
        end

        def update_claim(claim) = @client.update(typed(claim))
        def update_claim_status(claim) = @client.update(typed(claim), subresource: "status")

        def patch_claim_status(namespace, name, patch)
          @client.patch(RESOURCE, patch, type: :strategic, namespace: namespace, api_version: API_VERSION, name: name,
                                         subresource: "status")
        end

        def create_claim(claim) = @client.create(typed(claim), namespace: claim.dig("metadata", "namespace"), api_version: API_VERSION)

        def delete_claim(namespace, name)
          @client.delete(RESOURCE, name, namespace: namespace, api_version: API_VERSION)
        end

        def patch_pod_status(namespace, name, status)
          @client.patch("pods", {"status" => status}, type: :strategic, namespace: namespace, api_version: "v1", name: name,
                                                      subresource: "status")
        end

        private

        def typed(claim) = claim.merge("apiVersion" => API_VERSION, "kind" => "ResourceClaim")
      end

      # +num_user+: claims[0...num_user] are the Pod's own; a claim after them
      # is its extended-resource claim (in memory until PreBind creates it).
      State = Struct.new(:skip, :rejection, :claims, :informations, :allocator, :node_allocations, :unavailable, :mutex,
                         :num_user, :extended_scalars, :extended_resolver, :bindings, :shared_pending, keyword_init: true)
      # The node's allocations for the claims to allocate, and the node's
      # version of the extended-resource claim (its requests) with the
      # container request mappings.
      NodeAllocation = Struct.new(:results, :extended_claim, :mappings, :node_allocatable_status, :status_written, keyword_init: true)
      SPECIAL_CLAIM_NAME = "<extended-resources>"
      ExtendedResources = Rubernetes::DRA::ExtendedResources
      WorkloadClaims = Rubernetes::DRA::WorkloadClaims
      Information = Struct.new(:available_on_nodes, :allocation)
      Allocator = Rubernetes::DRA::Allocator

      # +api+: #get_claim(namespace, name), #update_claim(claim),
      # #update_claim_status(claim) -> the stored claim (raises on conflict
      # with #conflict? true), #patch_claim_status(namespace, name, patch).
      def initialize(api: nil, features: Allocator::Features.defaults, cel: nil, clock: -> { Time.now.utc },
                     binding_timeout: BINDING_TIMEOUT, enabled: true, extended_resources: true, node_allocatable: false,
                     workload_claims: false)
        @api = api
        @features = features
        @cel = cel || Rubernetes::DRA::CEL.new(consumable_capacity: features.consumable_capacity,
                                               list_type_attributes: features.list_type_attributes)
        @clock = clock
        @binding_timeout = Float(binding_timeout)
        @enabled = enabled
        # DRAExtendedResource (beta, on).
        @features_extended = extended_resources
        @node_allocatable = node_allocatable
        @workload_claims = workload_claims
        @pending = {}
        @assumed = {}
        @mutex = Mutex.new
      end

      attr_accessor :api
      # Scheduler::Metrics: scheduler_resourceclaim_creates_total.
      attr_accessor :metrics

      # ---------------------------------------------------------- phases

      def pre_enqueue(pod, _node = nil, context = nil)
        return true unless @enabled

        pod_claims(pod, context)
        true
      rescue ClaimError => error
        Filters::Helpers.reject(error.message, code: "UnschedulableAndUnresolvable")
      end

      def call(pod, node, context = nil)
        return true unless @enabled

        state = cycle_state(pod, context)
        return true if state.skip
        return state.rejection if state.rejection

        filter(pod, node, state, context)
      end

      def pod_with_node_allocatable_status(pod, node, context)
        return pod unless @enabled && @node_allocatable

        statuses = cycle_state(pod, context).node_allocations&.dig(node.name)&.node_allocatable_status
        statuses && !statuses.empty? ? NodeAllocatable.with_status(pod, statuses) : pod
      end

      def discard_assumption(pod, node, context)
        state = cycle_state(pod, context)
        return if state.informations.nil?

        @mutex.synchronize do
          state.informations.each_with_index do |info, index|
            next if info.allocation.nil?

            claim = extended_index?(state, index) ? state.node_allocations[node.name]&.extended_claim : state.claims[index]
            @pending.delete(claim_uid(claim)) if claim
          end
        end
      end

      # Score + NormalizeScore (DefaultNormalizeScore) over the feasible
      # nodes; nodes without an allocation score 0.
      def score_nodes(pod, nodes, context)
        return Scores::SKIP unless @enabled && @features.prioritized_list

        state = cycle_state(pod, context)
        raw = nodes.to_h do |node|
          allocation = !state.skip && state.claims && state.node_allocations&.[](node.name)
          [node.name, allocation ? compute_score(state, allocation.results) : 0]
        end
        Scores::Normalize.default(raw)
      end

      def reserve(pod, node, context = nil)
        return true unless @enabled

        state = cycle_state(pod, context)
        return true if state.skip || state.claims.nil? || state.claims.empty?

        to_allocate = state.claims.each_index.reject { |index| allocated?(state.claims[index]) }
        return true if to_allocate.empty?
        return true if state.allocator.nil?

        node_allocation = state.node_allocations[node.name]
        allocations = node_allocation&.results
        if allocations.nil? || allocations.empty?
          return true if to_allocate.all? { |index| extended_index?(state, index) }

          raise PluginError.new("claim allocation not found for node", plugin: NAME, phase: :reserve)
        end
        # An extended-resource claim this node does not need (it advertises
        # the resource itself) was left out of the allocation.
        to_allocate = to_allocate.reject { |index| extended_index?(state, index) } if node_allocation.extended_claim.nil?
        if allocations.length != to_allocate.length
          raise PluginError.new("internal error, have #{allocations.length} allocations, #{to_allocate.length} claims to allocate",
                                plugin: NAME, phase: :reserve)
        end

        to_allocate.each_with_index do |index, allocation_index|
          allocation = allocations[allocation_index]
          state.informations[index].allocation = allocation
          source = extended_index?(state, index) ? node_allocation.extended_claim : state.claims[index]
          claim = Support.deep_copy(source)
          finalizers = Array(claim.dig("metadata", "finalizers"))
          (claim["metadata"] ||= {})["finalizers"] = finalizers + [FINALIZER] unless finalizers.include?(FINALIZER)
          (claim["status"] ||= {})["allocation"] = allocation
          binding = state.bindings&.[](ref(claim))
          claim["status"]["reservedFor"] = Array(claim["status"]["reservedFor"]) + [binding] if binding && WorkloadClaims.group_reference?(binding)
          @mutex.synchronize { @pending[claim_uid(claim)] = claim }
        end
        true
      end

      def unreserve(pod, node, context = nil)
        return true unless @enabled

        state = cycle_state(pod, context)
        return true if state.skip || state.claims.nil?

        state.claims.each do |claim|
          uid = claim_uid(claim)
          next if state.shared_pending&.include?(uid)

          @mutex.synchronize do
            @pending.delete(uid)
            @assumed.delete(uid)
          end
          next unless allocated?(claim) && WorkloadClaims.reserved_for_pod?(pod.to_h, claim)

          patch = {"metadata" => {"uid" => uid}, "status" => {"reservedFor" => [{"$patch" => "delete", "uid" => pod.uid}]}}
          begin
            @api&.patch_claim_status(claim.dig("metadata", "namespace"), claim.dig("metadata", "name"), patch)
          rescue StandardError
            nil
          end
        end
        # unreserveExtendedResourceClaim: a claim PreBind already created for
        # the extended resources goes again.
        extended = extended_claim(state)
        if extended && !special?(extended)
          begin
            @api&.delete_claim(extended.dig("metadata", "namespace"), extended.dig("metadata", "name"))
          rescue StandardError
            nil
          end
        end
        @api&.patch_pod_status(pod.namespace, pod.name, {NodeAllocatable::STATUS_FIELD => nil}) if state.node_allocations&.dig(node.name)&.status_written
        true
      end

      # PreBindPreFlight: the Pod has claims for PreBind to bind.
      def pre_bind_preflight?(pod, _node = nil, context = nil)
        return false unless @enabled

        state = cycle_state(pod, context)
        !(state.skip || state.claims.nil? || state.claims.empty?)
      end

      def pre_bind(pod, node, context = nil)
        return true unless @enabled

        state = cycle_state(pod, context)
        return true if state.skip || state.claims.nil? || state.claims.empty?

        state.claims.each_index do |index|
          claim = state.claims[index]
          verify_shared_claim!(pod, claim) if state.shared_pending&.include?(claim_uid(claim))
          next if reserved_for_pod?(pod, state.claims[index])

          state.claims[index] = bind_claim(state, index, pod, node.name)
        end
        node_allocation = state.node_allocations[node.name]
        if node_allocation&.node_allocatable_status && !node_allocation.node_allocatable_status.empty?
          @api&.patch_pod_status(pod.namespace, pod.name, {NodeAllocatable::STATUS_FIELD => node_allocation.node_allocatable_status})
          node_allocation.status_written = true
        end
        return true unless @features.device_binding_and_status && binding_conditions?(state)

        # Upstream waits here (polling every 5 s up to bindingTimeout) in the
        # binding goroutine.  This pipeline binds from the scheduling loop, so
        # the wait is the scheduler's retry: the Pod goes back through backoff
        # and PreBind looks again; a claim whose conditions time out is
        # unavailable in Filter and PostFilter deallocates it.
        ready = pod_ready_for_binding?(state, context)
        return true if ready

        raise PluginError.new("waiting for binding conditions for device on node #{node.name}", plugin: NAME, phase: :pre_bind)
      end

      # PostFilter: deallocate one claim that blocked the Pod and that no
      # other Pod uses.  Never a preemption result.
      def post_filter(pod, context)
        return nil unless @enabled

        state = cycle_state(pod, context)
        return nil if state.skip || state.claims.nil? || state.claims.empty?

        extended = extended_claim(state)
        Array(state.unavailable).sort.each do |index|
          claim = state.claims[index]
          if extended_index?(state, index)
            next if special?(claim)

            break
          end
          reserved = Array(claim.dig("status", "reservedFor"))
          next unless reserved.empty? || (reserved.length == 1 && reserved.first["uid"].to_s == pod.uid)

          updated = Support.deep_copy(claim)
          status = (updated["status"] ||= {})
          status.delete("reservedFor")
          status.delete("allocation")
          status.delete("devices")
          @api&.update_claim_status(updated)
          return nil
        end
        @api&.delete_claim(extended.dig("metadata", "namespace"), extended.dig("metadata", "name")) if extended && !special?(extended)
        unreserve_idle_group_claim(pod, context)
        nil
      end

      # ---------------------------------------------- extended resources

      def extended_index?(state, index) = !state.num_user.nil? && index >= state.num_user

      def extended_claim(state)
        state.num_user && state.claims && state.claims.length > state.num_user ? state.claims[state.num_user] : nil
      end

      def special?(claim) = claim.dig("metadata", "name") == SPECIAL_CLAIM_NAME

      def resolver(context)
        store = context.respond_to?(:cycle_state) ? context.cycle_state : {}
        store[:dra_extended_resolver] ||= ExtendedResources::Resolver.new(data(context, "deviceClasses"))
      end

      # preFilterExtendedResources: [claim, the Pod's scalar requests] when
      # the Pod asks for an extended resource a DeviceClass provides -- the
      # claim a previous cycle created, else an in-memory one.
      def prefilter_extended(pod, context)
        return [nil, nil] unless @features_extended

        classes = resolver(context)
        return [nil, nil] if classes.empty?

        requests = Rubernetes::ResourceHelpers.pod_requests(pod.to_h)
        scalars = requests.each_with_object({}) do |(name, quantity), result|
          next if quantity.zero? || !ExtendedResources.extended_resource_name?(name)

          result[name] = quantity.value.ceil
        end
        return [nil, nil] unless scalars.keys.any? { |name| classes.device_class(name) }

        existing = data(context, "resourceClaims").find do |claim|
          claim.dig("metadata", "annotations", ExtendedResources::ANNOTATION) == "true" &&
            Array(claim.dig("metadata", "ownerReferences")).any? do |owner|
              owner["name"] == pod.name && owner["controller"] == true && owner["uid"].to_s == pod.uid
            end
        end
        return [existing, scalars] if existing

        claim = {"metadata" => {"namespace" => pod.namespace, "name" => SPECIAL_CLAIM_NAME, "uid" => SecureRandom.uuid,
                                "generateName" => "#{pod.name}-extended-resources-",
                                "ownerReferences" => [{"apiVersion" => "v1", "kind" => "Pod", "name" => pod.name, "uid" => pod.uid,
                                                       "controller" => true}],
                                "annotations" => {ExtendedResources::ANNOTATION => "true"}},
                 "spec" => {}, "status" => {}}
        [claim, scalars]
      end

      # filterExtendedResources: [the node's claim, request mappings,
      # rejection].  A resource the node advertises is NodeResourcesFit's;
      # one it does not have and no DeviceClass provides cannot fit.
      def filter_extended(state, pod, node)
        claim = extended_claim(state)
        return [nil, [], nil] if claim.nil?
        unless Array(claim.dig("spec", "devices", "requests")).empty?
          return [nil, [], Filters::Helpers.reject("cannot schedule extended resource claim", code: "UnschedulableAndUnresolvable")]
        end

        classes = state.extended_resolver
        wanted = {}
        state.extended_scalars.each do |name, quantity|
          next if quantity.zero?

          allocatable = node.allocatable.fetch(name, Rational(0))
          if classes&.device_class(name) && allocatable.zero?
            wanted[name] = quantity
          elsif !node.allocatable.key?(name)
            return [nil, [], Filters::Helpers.reject("cannot fit resource", code: "UnschedulableAndUnresolvable")]
          end
        end
        return [nil, [], nil] if state.num_user.zero? && wanted.empty?
        return [nil, [], nil] if allocated?(claim)
        return [nil, [], nil] if wanted.empty?

        requests, mappings = ExtendedResources.requests_and_mappings(pod.to_h, wanted, classes)
        node_claim = Support.deep_copy(claim)
        (node_claim["spec"] ||= {})["devices"] = {"requests" => requests}
        [node_claim, mappings, nil]
      end

      # ------------------------------------------------------- PreFilter

      def cycle_state(pod, context)
        store = context.respond_to?(:cycle_state) ? context.cycle_state : nil
        return prefilter(pod, context) if store.nil?

        store[STATE_KEY] ||= prefilter(pod, context)
      end

      def prefilter(pod, context)
        claims = pod_claims(pod, context)
        num_user = claims.length
        extended, scalars = prefilter_extended(pod, context)
        claims += [extended] if extended
        return State.new(skip: true) if claims.empty?

        bindings = claim_bindings(pod, context)
        shared_pending = Set.new
        informations = Array.new(claims.length) { Information.new(nil, nil) }
        to_allocate = 0
        classes = data(context, "deviceClasses").to_h { |klass| [klass.dig("metadata", "name").to_s, klass] }
        claims.each_with_index do |claim, index|
          pending = pending_allocation(claim_uid(claim))
          binding = bindings[ref(claim)]
          if !allocated?(claim) && pending && share_pending_claim?(binding, pending)
            shared_pending << claim_uid(claim)
            claim = claims[index] = pending
          end
          if allocated?(claim)
            # CanBeReserved is always true (no limit on consumers).
            informations[index].available_on_nodes = claim.dig("status", "allocation", "nodeSelector")
            next
          end

          to_allocate += 1
          return unschedulable(state_claims: claims, message: "resource claim #{ref(claim)} is in the process of being allocated") if pending
          next if index >= num_user

          Array(claim.dig("spec", "devices", "requests")).each do |request|
            if request["exactly"]
              rejection = validate_class(classes, request.dig("exactly", "deviceClassName"), request["name"])
              return State.new(rejection: rejection, claims: claims) if rejection
            elsif !Array(request["firstAvailable"]).empty?
              unless @features.prioritized_list
                return unschedulable(state_claims: claims, message: "resource claim #{ref(claim)}, request #{request["name"]}: has subrequests, " \
                                                                    "but the DRAPrioritizedList feature is disabled")
              end

              request["firstAvailable"].each do |sub|
                rejection = validate_class(classes, sub["deviceClassName"], "#{request["name"]}/#{sub["name"]}")
                return State.new(rejection: rejection, claims: claims) if rejection
              end
            else
              return unschedulable(state_claims: claims,
                                   message: "resource claim #{ref(claim)}, request #{request["name"]}: unknown request type")
            end
          end
        end

        state = State.new(claims: claims, informations: informations, node_allocations: {}, unavailable: Set.new, mutex: Mutex.new,
                          num_user: num_user, extended_scalars: scalars || {}, extended_resolver: extended ? resolver(context) : nil,
                          bindings: bindings, shared_pending: shared_pending)
        if to_allocate.positive?
          state.allocator = {
            slices: data(context, "resourceSlices"), classes: classes.values,
            allocated_state: gather_allocated_state(context)
          }
        end
        state
      rescue ClaimError => error
        unschedulable(state_claims: claims, message: error.message)
      end

      def unschedulable(state_claims:, message:)
        State.new(claims: state_claims, rejection: Filters::Helpers.reject(message, code: "UnschedulableAndUnresolvable"))
      end

      # validateDeviceClass.
      def validate_class(classes, name, request_name)
        raise PluginError.new("request #{request_name}: unsupported request type", plugin: NAME, phase: :filter) if name.to_s.empty?
        return nil if classes.key?(name.to_s)

        Filters::Helpers.reject("request #{request_name}: device class #{name} does not exist", code: "UnschedulableAndUnresolvable")
      end

      # computeScore.
      def compute_score(state, allocations)
        allocations ||= []
        score = 0
        unallocated = 0
        state.claims.each do |claim|
          allocation = if allocated?(claim)
                         claim.dig("status", "allocation")
                       else
                         allocations[unallocated].tap { unallocated += 1 }
                       end
          allocated = Array(allocation&.dig("devices", "results")).map do |result|
            result["request"].to_s
          end.select { |name| name.include?("/") }.to_set
          Array(claim.dig("spec", "devices", "requests")).each do |request|
            next if request["exactly"]

            Array(request["firstAvailable"]).each_with_index do |sub, index|
              score += FIRST_AVAILABLE_MAX - index if allocated.include?("#{request["name"]}/#{sub["name"]}")
            end
          end
        end
        score
      end

      # --------------------------------------------------------- PreBind

      # bindClaim: finalizer, allocation and reservation, retried on conflict
      # with a fresh copy of the claim.
      def bind_claim(state, index, pod, node_name)
        claim = state.claims[index]
        allocation = state.informations[index].allocation
        raise PluginError.new("no ResourceClaim API is configured", plugin: NAME, phase: :pre_bind) unless @api

        extended = extended_index?(state, index)
        if extended
          node_allocation = state.node_allocations[node_name]
          # Nothing to create: this node advertises the resource itself.
          return claim if allocation.nil? || node_allocation&.extended_claim.nil?

          if special?(claim)
            special_uid = claim_uid(claim)
            begin
              claim = create_extended_claim(pod, node_allocation.extended_claim)
            ensure
              @mutex.synchronize { @pending.delete(special_uid) }
            end
            state.claims[index] = claim
          end
        end
        binding = state.bindings&.[](ref(claim)) || {"resource" => "pods", "name" => pod.name, "uid" => pod.uid}
        stored = bind_claim_status(claim, allocation, binding)
        patch_pod_extended_status(pod, stored, state.node_allocations[node_name]&.mappings || []) if extended
        stored
      end

      # createExtendedResourceClaimInAPI.
      def create_extended_claim(pod, node_claim)
        claim = {
          "apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
          "metadata" => {"generateName" => "#{pod.name}-extended-resources-", "namespace" => pod.namespace,
                         "ownerReferences" => [{"apiVersion" => "v1", "kind" => "Pod", "name" => pod.name, "uid" => pod.uid, "controller" => true}],
                         "annotations" => {ExtendedResources::ANNOTATION => "true"}},
          "spec" => Support.deep_copy(node_claim["spec"] || {})
        }
        created = @api.create_claim(claim)
        @metrics&.resourceclaim_create("success")
        created
      rescue StandardError => error
        @metrics&.resourceclaim_create("failure")
        raise PluginError.new("create ResourceClaim for extended resources #{pod.namespace}/#{pod.name}: #{error.message}",
                              plugin: NAME, phase: :pre_bind)
      end

      # patchPodExtendedResourceClaimStatus.
      def patch_pod_extended_status(pod, claim, mappings)
        status = {"extendedResourceClaimStatus" => {"resourceClaimName" => claim.dig("metadata", "name"), "requestMappings" => mappings}}
        @api.patch_pod_status(pod.namespace, pod.name, status)
      rescue StandardError => error
        raise PluginError.new("patch pod status for extended resource claim #{pod.namespace}/#{pod.name}: #{error.message}",
                              plugin: NAME, phase: :pre_bind)
      end

      def bind_claim_status(claim, allocation, binding)
        current = Support.deep_copy(claim)
        stored = nil
        5.times do |attempt|
          current = @api.get_claim(current.dig("metadata", "namespace"), current.dig("metadata", "name")) if attempt.positive?
          if current.dig("metadata", "deletionTimestamp")
            raise PluginError.new("claim #{ref(current)} got deleted in the meantime", plugin: NAME, phase: :pre_bind)
          end

          if allocation
            if current.dig("status", "allocation")
              raise PluginError.new("claim #{ref(current)} got allocated elsewhere in the meantime", plugin: NAME, phase: :pre_bind)
            end

            finalizers = Array(current.dig("metadata", "finalizers"))
            unless finalizers.include?(FINALIZER)
              current = Support.deep_copy(current)
              current["metadata"]["finalizers"] = finalizers + [FINALIZER]
              begin
                current = @api.update_claim(current)
              rescue StandardError => error
                next if conflict?(error)

                raise PluginError.new("add finalizer to claim #{ref(current)}: #{error.message}", plugin: NAME, phase: :pre_bind)
              end
            end
            current = Support.deep_copy(current)
            (current["status"] ||= {})["allocation"] = Support.deep_copy(allocation)
          else
            current = Support.deep_copy(current)
          end
          status = (current["status"] ||= {})
          reserved = Array(status["reservedFor"])
          status["reservedFor"] = reserved + [binding] unless reserved.include?(binding)
          if @features.device_binding_and_status
            if status["allocation"].nil?
              raise PluginError.new("claim #{ref(current)} got deallocated elsewhere in the meantime", plugin: NAME, phase: :pre_bind)
            end

            status["allocation"]["allocationTimestamp"] ||= @clock.call.utc.iso8601
          end
          begin
            stored = @api.update_claim_status(current)
            break
          rescue StandardError => error
            next if conflict?(error)

            what = allocation ? "add allocation and reservation to" : "add reservation to"
            raise PluginError.new("#{what} claim #{ref(current)}: #{error.message}", plugin: NAME, phase: :pre_bind)
          end
        end
        raise PluginError.new("update of claim #{ref(claim)} kept conflicting", plugin: NAME, phase: :pre_bind) if stored.nil?

        uid = claim_uid(stored)
        @mutex.synchronize do
          @assumed[uid] = stored
          @pending.delete(uid)
        end
        stored
      ensure
        @mutex.synchronize { @pending.delete(claim_uid(claim)) } if allocation && stored.nil?
      end

      # isClaimReadyForBinding.
      def claim_ready_for_binding?(claim)
        allocation = claim.dig("status", "allocation")
        return false if allocation.nil?

        Array(allocation.dig("devices", "results")).each do |result|
          next if Array(result["bindingConditions"]).empty?

          status = Array(claim.dig("status", "devices")).find do |device|
            device["driver"] == result["driver"] && device["pool"] == result["pool"] && device["device"] == result["device"]
          end
          return false if status.nil?

          conditions = Array(status["conditions"])
          Array(result["bindingFailureConditions"]).each do |type|
            failed = conditions.find { |condition| condition["type"] == type }
            next unless failed && failed["status"] == "True"

            raise ClaimError, "device binding failed: claim=#{claim.dig("metadata", "name")}, reason=#{failed["reason"]}, " \
                              "message=#{failed["message"].to_s.dump}"
          end
          Array(result["bindingConditions"]).each do |type|
            return false unless conditions.any? { |condition| condition["type"] == type && condition["status"] == "True" }
          end
        end
        true
      end

      # isClaimTimeout.
      def claim_timeout?(claim)
        allocation = claim.dig("status", "allocation")
        stamp = allocation && allocation["allocationTimestamp"]
        return false if stamp.nil?
        return false if Array(allocation.dig("devices", "results")).none? { |result| result["bindingConditions"] }

        Time.parse(stamp.to_s) + @binding_timeout < @clock.call
      rescue ArgumentError
        false
      end

      def binding_conditions?(state)
        state.claims.any? do |claim|
          Array(claim.dig("status", "allocation", "devices", "results")).any? { |result| !Array(result["bindingConditions"]).empty? }
        end
      end

      def pod_ready_for_binding?(state, _context)
        state.claims.each_with_index do |claim, index|
          current = @api ? @api.get_claim(claim.dig("metadata", "namespace"), claim.dig("metadata", "name")) : claim
          state.claims[index] = current
          ready = claim_ready_for_binding?(current)
          next if ready
          if claim_timeout?(current)
            raise PluginError.new("device binding timeout: claim=#{current.dig("metadata", "name")}", plugin: NAME,
                                                                                                      phase: :pre_bind)
          end

          return false
        end
        true
      rescue ClaimError => error
        raise PluginError.new(error.message, plugin: NAME, phase: :pre_bind)
      end

      # ---------------------------------------------------- claim tracker

      def pending_allocation(uid)
        @mutex.synchronize { @pending[uid] }
      end

      # The claims the informer holds, with this plugin's own writes
      # overlaid until the informer has a newer copy.
      def claims_by_key(context)
        informer = data(context, "resourceClaims")
        by_key = informer.to_h { |claim| ["#{claim.dig("metadata", "namespace")}/#{claim.dig("metadata", "name")}", claim] }
        @mutex.synchronize do
          @assumed.delete_if do |uid, assumed|
            key = "#{assumed.dig("metadata", "namespace")}/#{assumed.dig("metadata", "name")}"
            current = by_key[key]
            if current && claim_uid(current) == uid && !newer?(assumed, current)
              true
            elsif current.nil? || claim_uid(current) != uid
              # Deleted or replaced: nothing to overlay.
              current.nil? ? false : true
            else
              by_key[key] = assumed
              false
            end
          end
        end
        by_key
      end

      # GatherAllocatedState: informer claims plus in-flight allocations.
      def gather_allocated_state(context)
        claims = claims_by_key(context).values
        pending = @mutex.synchronize { @pending.values }
        Allocator::AllocatedState.from_claims(claims + pending, consumable_capacity: @features.consumable_capacity)
      end

      def newer?(left, right)
        left_rv = left.dig("metadata", "resourceVersion").to_s
        right_rv = right.dig("metadata", "resourceVersion").to_s
        return false if left_rv == right_rv
        return Integer(left_rv) > Integer(right_rv) if left_rv.match?(/\A\d+\z/) && right_rv.match?(/\A\d+\z/)

        true
      end

      # ---------------------------------------------------------- helpers

      def data(context, key)
        volume_data = context.respond_to?(:volume_data) ? context.volume_data : {}
        Array(volume_data.is_a?(Hash) ? volume_data[key] : nil).map { |item| Support.object_hash(item) }
      end

      def allocated?(claim) = !claim.dig("status", "allocation").nil?

      def reserved_for_pod?(pod, claim)
        WorkloadClaims.reserved_for_pod?(pod.to_h, claim, workload_claims: @workload_claims)
      end

      def claim_uid(claim) = claim.dig("metadata", "uid").to_s
      def ref(claim) = "#{claim.dig("metadata", "namespace")}/#{claim.dig("metadata", "name")}"

      def conflict?(error)
        (error.respond_to?(:conflict?) && error.conflict?) || (error.respond_to?(:status) && error.status.to_i == 409)
      end
    end
  end
end
