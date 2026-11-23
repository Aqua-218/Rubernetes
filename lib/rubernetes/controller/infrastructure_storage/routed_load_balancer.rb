# frozen_string_literal: true

require_relative "../../network/load_balancer_pool"

module Rubernetes
  module Controller
    module RoutedLoadBalancer
      FINALIZER = "rubernetes.io/routed-load-balancer"
      CLOUD_FINALIZER = "service.kubernetes.io/load-balancer-cleanup"
      ALLOCATION_ID = "rubernetes.io/routed-load-balancer-allocation"
      CLAIMS = ResourceDescriptor.parse("ConfigMap")
      CLAIMS_NAMESPACE = "kube-system"
      CLAIMS_NAME = "rubernetes-load-balancer-allocations"
      MAX_ALLOCATIONS = 4096 # keep the allocation object below the ConfigMap size limit
      STEP_DELAY = 0.1
      PENDING_DELAY = 10

      private

      def plan_routed_load_balancer(service, adapter, pool, default_routed)
        raise ProviderUnavailableError, "the routed load balancer needs an API store" unless adapter

        live = routed_live(adapter, self.class::SERVICE, service)
        return empty_result(service) unless live && Support.uid(live) == Support.uid(service)

        routed = routed_service?(live, default_routed)
        return empty_result(live) unless routed || routed_finalizer?(live)

        token = live.dig("metadata", "annotations", ALLOCATION_ID)
        active = routed && !live.dig("metadata", "deletionTimestamp")
        if routed_finalizer?(live)
          return retire_routed_allocation(live, adapter, token) unless active && token
        else
          return empty_result(live) unless active

          return change_routed_metadata(live, token: SecureRandom.uuid, protect: true, reason: "protect routed allocation")
        end

        record, claims = routed_claims(adapter)
        uid = Support.uid(live)
        claim = claims[uid]
        return write_routed_claims(live, record, claims.reject { |key, _| key == uid }) if claim && claim.fetch("token") != token

        addresses = claim ? claim.fetch("addresses").map { |ip| IPAddr.new(ip) } : []
        requested = routed_request(live, pool)
        families = routed_families(live, pool)
        if addresses.any? { |ip| !families.include?(Network::LoadBalancerPool::ADDRESS_FAMILIES.fetch(ip.family)) } ||
           (requested && !addresses.empty? && addresses.any? { |ip| ip.family == requested.family } && !addresses.include?(requested))
          return retire_routed_allocation(live, adapter, token)
        end

        free_claims = claims.reject { |key, _| key == uid }
        used = free_claims.values.flat_map { |other| other.fetch("addresses").map { |ip| IPAddr.new(ip) } }
        selected = select_routed_addresses(live, pool, families, addresses, requested, used)
        if !selected || (!claim && claims.size >= MAX_ALLOCATIONS)
          # A stale planner or forced deletion can leave a claim whose Service
          # no longer recognizes its token. Check the live API before reusing it.
          services = adapter.list(self.class::SERVICE, namespace: :all, fresh: true).to_h { |candidate| [Support.uid(candidate), candidate] }
          retained = claims.select { |key, allocation| routed_claim_alive?(services[key], allocation) }
          return write_routed_claims(live, record, retained) if retained != claims

          return pending_routed(live, "no routed VIP is available for the requested address families")
        end

        desired = {"token" => token, "addresses" => selected.map(&:to_s)}
        return write_routed_claims(live, record, claims.merge(uid => desired)) unless claim == desired

        ingress = desired.fetch("addresses").map { |ip| {"ip" => ip, "ipMode" => "VIP"} }
        missing_families = (families & pool.families).size > selected.size
        write_routed_status(live, ingress, "EnsuredLoadBalancer", "routed VIPs assigned") ||
          routed_result(live, delay: missing_families ? PENDING_DELAY : nil)
      rescue InvalidRoutedAddress => error
        pending_routed(live, error.message)
      end

      class InvalidRoutedAddress < StandardError
      end

      def routed_service?(service, default_routed)
        return false unless Support.kind(service) == "Service" && service.dig("spec", "type") == "LoadBalancer"

        klass = service.dig("spec", "loadBalancerClass")
        klass == Network::LoadBalancerPool::CLASS_NAME || (klass.nil? && default_routed && available_classless_service?(service))
      end

      def available_classless_service?(service)
        return true if routed_finalizer?(service)

        !Array(service.dig("metadata", "finalizers")).include?(CLOUD_FINALIZER) && Array(service.dig("status", "loadBalancer", "ingress")).empty?
      end

      def routed_finalizer?(service) = Array(service.dig("metadata", "finalizers")).include?(FINALIZER)

      def routed_live(adapter, descriptor, object)
        method = InfrastructureCapability.live_reads?(adapter) ? :find_live : :find
        adapter.public_send(method, descriptor, name: Support.name(object), namespace: Support.namespace(object))
      end

      def routed_claims(adapter)
        reference = {"metadata" => {"name" => CLAIMS_NAME, "namespace" => CLAIMS_NAMESPACE}}
        record = routed_live(adapter, CLAIMS, reference)
        return [nil, {}] unless record

        claims = record.fetch("data", {}).transform_values { |value| JSON.parse(value) }
        [record, claims]
      end

      def routed_claim_alive?(current, claim)
        return false unless current

        ingress = Array(current.dig("status", "loadBalancer", "ingress")).filter_map { |entry| entry["ip"] }
        return true if (ingress & claim.fetch("addresses")).any?

        routed_finalizer?(current) && current.dig("metadata", "annotations", ALLOCATION_ID) == claim.fetch("token")
      end

      def routed_families(service, pool)
        families = Array(service.dig("spec", "ipFamilies"))
        families.empty? ? pool.families.take(1) : families
      end

      def routed_request(service, pool)
        desired = service.dig("spec", "loadBalancerIP")
        return if desired.to_s.empty?

        raise InvalidRoutedAddress, "requested VIP #{desired} must be an IP address" if desired.include?("/")

        ip = IPAddr.new(desired)
        family = Network::LoadBalancerPool::ADDRESS_FAMILIES.fetch(ip.family)
        if !pool.usable?(ip) || !routed_families(service, pool).include?(family)
          raise InvalidRoutedAddress, "requested VIP #{desired} is outside the eligible routed pools"
        end

        ip
      rescue IPAddr::Error
        raise InvalidRoutedAddress, "requested VIP #{desired} must be an IP address"
      end

      def select_routed_addresses(service, pool, families, current, requested, used)
        selected = families.map do |family|
          existing = current.find { |ip| Network::LoadBalancerPool::ADDRESS_FAMILIES.fetch(ip.family) == family }
          next existing if existing

          if requested && Network::LoadBalancerPool::ADDRESS_FAMILIES.fetch(requested.family) == family
            return nil if used.include?(requested)

            next requested
          end
          pool.next_address(family, used)
        end
        required = service.dig("spec", "ipFamilyPolicy") == "RequireDualStack" ? families.size : 1
        return if selected.first.nil? || selected.compact.size < required

        selected.compact
      end

      # Drop the token first. This fences any in-flight status publication and
      # keeps a type change back to LoadBalancer from adopting a retiring VIP.
      def retire_routed_allocation(service, adapter, token)
        return change_routed_metadata(service, token: nil, protect: true, reason: "retire routed allocation") if token

        status_update = write_routed_status(service, [], "DeletingLoadBalancer", "routed VIPs withdrawn")
        return status_update if status_update

        record, claims = routed_claims(adapter)
        uid = Support.uid(service)
        return write_routed_claims(service, record, claims.reject { |key, _| key == uid }) if claims.key?(uid)

        change_routed_metadata(service, token: nil, protect: false, reason: "finalize routed allocation")
      end

      def change_routed_metadata(service, token:, protect:, reason:)
        candidate = Support.deep_copy(service)
        metadata = candidate.fetch("metadata")
        finalizers = Array(metadata["finalizers"]) - [FINALIZER]
        metadata["finalizers"] = protect ? finalizers + [FINALIZER] : finalizers
        annotations = metadata["annotations"] ||= {}
        token ? annotations[ALLOCATION_ID] = token : annotations.delete(ALLOCATION_ID)
        routed_result(service, operation: operation_update(service, candidate, descriptor: self.class::SERVICE, reason: reason),
                               delay: STEP_DELAY)
      end

      def write_routed_claims(service, record, claims)
        candidate = Support.deep_copy(record || {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {
                                        "name" => CLAIMS_NAME, "namespace" => CLAIMS_NAMESPACE
                                      }})
        candidate["data"] = claims.transform_values { |claim| JSON.generate(claim) }
        reason = "record routed VIP reservations"
        operation = if record
                      operation_update(record, candidate, descriptor: CLAIMS, reason: reason)
                    else
                      operation_create(candidate, descriptor: CLAIMS, reason: reason)
                    end
        routed_result(service, operation: operation, delay: STEP_DELAY)
      end

      def write_routed_status(service, ingress, reason, message)
        status = Support.deep_copy(Support.status(service))
        return if Array(status.dig("loadBalancer", "ingress")) == ingress

        status["loadBalancer"] = ingress.empty? ? {} : {"ingress" => ingress}
        operation = operation_status(service, status, descriptor: self.class::SERVICE, reason: message)
        event = {"type" => "Normal", "reason" => reason, "message" => message}
        routed_result(service, operation: operation, status: status, events: [event], delay: STEP_DELAY)
      end

      def pending_routed(service, message)
        event = {"type" => "Warning", "reason" => "SyncLoadBalancerFailed", "message" => message}
        key = "#{name_key(service)}/#{Support.uid(service)}"
        routed_result(service, events: once_per_state(key, [event]), delay: PENDING_DELAY)
      end

      def routed_result(service, operation: nil, status: Support.status(service), events: [], delay: nil)
        ReconcileResult.new(operations: [operation].compact, status: status, events: events,
                            controller: name, key: name_key(service), requeue_after: delay)
      end
    end
  end
end
