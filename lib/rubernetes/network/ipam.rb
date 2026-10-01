# frozen_string_literal: true

require "ipaddr"

require_relative "durable_state"
require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    # Transactional IPv4/IPv6 address allocator.  A lease is first durable in
    # Reserved state, then becomes Committed only after the network effect has
    # succeeded.  Releasing requires an explicit process-stop confirmation so
    # a stale sandbox can never race a new owner for the same address.
    class IPAM
      Lease = Struct.new(:family, :ip, :pod_uid, :sandbox_id, :operation_id,
                         :state, :node, :subnet, :generation, :metadata,
                         keyword_init: true) do
        def [](key)
          to_h.fetch(key.to_s) { to_h.fetch(key.to_sym) }
        end

        def to_h
          {
            "family" => family,
            "ip" => ip,
            "pod_uid" => pod_uid,
            "sandbox_id" => sandbox_id,
            "operation_id" => operation_id,
            "state" => state,
            "node" => node,
            "subnet" => subnet,
            "generation" => generation,
            "metadata" => metadata || {}
          }
        end

        alias_method :address, :ip

        def committed?
          state == "committed"
        end

        def released?
          state == "released"
        end

        def reserved?
          state == "reserved"
        end
      end

      # Array-compatible return value for dual-stack reservations.  Delegating
      # the single-family fields keeps the common `lease.ip` call ergonomic
      # while retaining an explicit collection for atomic dual-stack work.
      class LeaseSet < Array
        attr_reader :operation_id, :sandbox_id, :pod_uid

        def initialize(leases, operation_id:, sandbox_id:, pod_uid:)
          super(leases)
          @operation_id = operation_id
          @sandbox_id = sandbox_id
          @pod_uid = pod_uid
          freeze
        end

        def lease
          first if length == 1
        end

        def ip
          return lease.ip if lease

          map(&:ip)
        end

        def family
          return lease.family if lease

          map(&:family)
        end

        def state
          return lease.state if lease

          map(&:state).uniq
        end

        def [](key, *rest)
          return super unless key.is_a?(String) || key.is_a?(Symbol)

          to_h.fetch(key.to_s) { to_h.fetch(key.to_sym) }
        end

        def to_h
          {
            "leases" => map(&:to_h),
            "ips" => map(&:ip),
            "families" => map(&:family),
            "operation_id" => operation_id,
            "sandbox_id" => sandbox_id,
            "pod_uid" => pod_uid,
            "state" => state
          }
        end

        def to_a
          map(&:to_h)
        end
      end

      RecoveryReport = Struct.new(:reclaimed, :unknown, :identity_mismatch,
                                  :orphans, :errors, :audit, keyword_init: true) do
        def to_h
          {
            "reclaimed" => reclaimed,
            "unknown" => unknown,
            "identity_mismatch" => identity_mismatch,
            "orphans" => orphans,
            "errors" => errors,
            "audit" => audit
          }
        end

        alias_method :released, :reclaimed
      end

      DEFAULT_NODE_PREFIX = {"ipv4" => 24, "ipv6" => 64}.freeze
      ACTIVE_STATES = %w[reserved committed unknown].freeze
      MAX_NODE_SUBNET_SCAN = 1_000_000

      def initialize(cluster_cidr: nil, ipv4_cidr: nil, ipv6_cidr: nil,
                     node_subnet_prefix: nil, ipv4_node_prefix: nil,
                     ipv6_node_prefix: nil, state_path: nil, path: nil,
                     state_store: nil, store: nil, journal: nil,
                     kernel_observer: nil, observer: nil, clock: -> { Time.now.utc },
                     fsync: true, **_options)
        @clock = clock
        @mutex = Mutex.new
        @observer = kernel_observer || observer
        @journal = journal
        @store = state_store || store || (if state_path || path
                                            DurableState.new(state_path || path, default: default_state,
                                                                                 fsync: fsync)
                                          end)
        @state = @store ? normalize_state(@store.read) : default_state
        @durable_state = Support.copy(@state)
        @node_cidrs = parse_cluster_cidrs(cluster_cidr: cluster_cidr, ipv4_cidr: ipv4_cidr, ipv6_cidr: ipv6_cidr)
        raise ValidationError, "at least one cluster CIDR is required" if @node_cidrs.empty?

        @node_prefixes = {
          "ipv4" => Support.integer(ipv4_node_prefix || prefix_for(node_subnet_prefix, "ipv4"), "ipv4 node prefix", min: 0, max: 32),
          "ipv6" => Support.integer(ipv6_node_prefix || prefix_for(node_subnet_prefix, "ipv6"), "ipv6 node prefix", min: 0, max: 128)
        }
        validate_prefixes!
      end

      attr_reader :node_cidrs, :node_prefixes

      def allocate_node(node:, families: nil, **)
        allocate_node_subnet(node: node, families: families, **)
      end

      def allocate_node_subnet(node:, families: nil, **_options)
        node_id = Support.identifier(node, "node")
        requested = normalize_families(families || @node_cidrs.keys)
        @mutex.synchronize do
          current = @state.fetch("nodes", {})[node_id] || {}
          requested.each do |family|
            next if current.key?(family)

            current[family] = next_node_subnet(family)
          end
          @state["nodes"][node_id] = current
          persist!("node_subnet_allocated", "node" => node_id, "subnets" => current)
          Support.copy(current)
        end
      end

      alias subnet_for_node allocate_node_subnet

      def release_node_subnet(node:, families: nil, force: false)
        node_id = Support.identifier(node, "node")
        requested = families && normalize_families(families)
        @mutex.synchronize do
          current = @state.fetch("nodes", {})[node_id]
          return {} unless current

          active = @state.fetch("leases", {}).values.select do |lease|
            lease["node"] == node_id && ACTIVE_STATES.include?(lease["state"])
          end
          # A force flag cannot prove that an old sandbox stopped. Releasing a
          # subnet while any lease is active would make its addresses
          # immediately eligible for a new owner.
          if active.any? { |lease| requested.nil? || requested.include?(lease["family"]) }
            raise LeaseStateError, "cannot release node subnet #{node_id.inspect} while leases are active"
          end

          released = requested ? current.slice(*requested) : current.dup
          released_families = released.keys.freeze
          released_families.each { |family| current.delete(family) }
          @state["nodes"].delete(node_id) if current.empty?
          persist!("node_subnet_released", "node" => node_id, "families" => released_families)
          Support.copy(released)
        end
      end

      def reserve(node:, pod_uid:, sandbox_id:, operation_id: nil, families: nil,
                  dual_stack: nil, config_digest: nil, metadata: {}, **options)
        node_id = Support.identifier(node, "node")
        pod = Support.identifier(pod_uid, "pod_uid")
        sandbox = Support.identifier(sandbox_id, "sandbox_id")
        operation = Support.identifier(operation_id || "network-#{sandbox}", "operation_id")
        requested = normalize_families(families || (dual_stack == false ? ["ipv4"] : @node_cidrs.keys))
        requested = %w[ipv4 ipv6] if dual_stack == true && families.nil?
        requested.each { |family| raise ValidationError, "#{family} CIDR is not configured" unless @node_cidrs.key?(family) }
        digest = config_digest || Support.digest({"node" => node_id, "pod_uid" => pod, "sandbox_id" => sandbox,
                                                  "families" => requested, "metadata" => metadata})

        @mutex.synchronize do
          existing = find_operation(operation_id: operation, sandbox_id: sandbox)
          if existing
            ensure_intent!(existing, node_id: node_id, pod_uid: pod, sandbox_id: sandbox, families: requested, config_digest: digest)
            return lease_set_for(existing.fetch("lease_keys"), operation_id: operation, sandbox_id: sandbox, pod_uid: pod)
          end
          sandbox_operation = find_operation(operation_id: nil, sandbox_id: sandbox)
          if sandbox_operation && ACTIVE_STATES.include?(sandbox_operation.fetch("state")) && sandbox_operation.fetch("operation_id") != operation
            raise OperationConflict,
                  "sandbox #{sandbox.inspect} already owns IPAM operation #{sandbox_operation.fetch("operation_id")}"
          end

          # Every change is persisted, so the state before this transaction
          # is the last one written; rolling back rebuilds from it instead of
          # copying the whole node's IPAM state up front on every call.
          state_before = @durable_state
          subnets = allocate_node_locked(node_id, requested)
          begin
            leases = requested.map do |family|
              ip = next_pod_ip(family, subnets.fetch(family), node_id)
              key = lease_key(family, ip)
              {
                "family" => family,
                "ip" => ip,
                "pod_uid" => pod,
                "sandbox_id" => sandbox,
                "operation_id" => operation,
                "state" => "reserved",
                "node" => node_id,
                "subnet" => subnets.fetch(family),
                "generation" => next_generation,
                "metadata" => Support.copy(metadata)
              }.tap { |lease| @state["leases"][key] = lease }
            end
          rescue StandardError
            # Restore the complete pre-transaction state. This also removes a
            # node subnet allocated for a dual-stack request whose second
            # family had no address available.
            @state = Support.working_copy(state_before)
            raise
          end
          operation_record = {
            "operation_id" => operation,
            "sandbox_id" => sandbox,
            "pod_uid" => pod,
            "node" => node_id,
            "families" => requested,
            "config_digest" => Support.string(digest, "config_digest"),
            "state" => "reserved",
            "lease_keys" => leases.map { |lease| lease_key(lease.fetch("family"), lease.fetch("ip")) },
            "metadata" => Support.copy(options.merge(metadata: metadata))
          }
          @state["operations"][operation] = operation_record
          persist!("lease_reserved", "operation" => operation_record, "leases" => leases)
          lease_set_for(operation_record.fetch("lease_keys"), operation_id: operation, sandbox_id: sandbox, pod_uid: pod)
        end
      rescue LeaseUnavailable
        raise
      rescue StandardError => error
        raise error if error.is_a?(Error)

        raise LeaseError, "IP reservation failed for sandbox #{sandbox_id.inspect}: #{error.message}"
      end

      alias reserve_ips reserve

      def commit(lease_or_set = nil, operation_id: nil, sandbox_id: nil, network_ready: true,
                 ready: nil, **_options)
        operation = operation_id || operation_from_argument(lease_or_set)&.fetch("operation_id", nil)
        operation ||= lease_or_set.respond_to?(:operation_id) && lease_or_set.operation_id
        operation = Support.identifier(operation, "operation_id")
        raise LeaseStateError, "network effect must be ready before IP commit" if ready == false || network_ready == false

        @mutex.synchronize do
          # Every change is persisted, so the state before this transaction
          # is the last one written; rolling back rebuilds from it instead of
          # copying the whole node's IPAM state up front on every call.
          state_before = @durable_state
          begin
            record = @state.fetch("operations", {})[operation]
            raise LeaseStateError, "unknown IPAM operation #{operation.inspect}" unless record
            if record["state"] == "committed"
              return lease_set_for(record.fetch("lease_keys"), operation_id: operation,
                                                               sandbox_id: record.fetch("sandbox_id"), pod_uid: record.fetch("pod_uid"))
            end
            unless record["state"] == "reserved"
              raise LeaseStateError,
                    "cannot commit IPAM operation #{operation.inspect} in #{record.fetch("state")}"
            end

            record.fetch("lease_keys").each do |key|
              lease = @state.fetch("leases").fetch(key)
              raise LeaseStateError, "lease #{key} is no longer reserved" unless lease["state"] == "reserved"

              @state["leases"][key] = lease.merge("state" => "committed", "committed_at" => Support.now(@clock).iso8601(6))
            end
            record = @state["operations"][operation] = record.merge("state" => "committed")
            persist!("lease_committed", "operation_id" => operation, "lease_keys" => record.fetch("lease_keys"))
            lease_set_for(record.fetch("lease_keys"), operation_id: operation,
                                                      sandbox_id: record.fetch("sandbox_id"), pod_uid: record.fetch("pod_uid"))
          rescue StandardError
            @state = Support.working_copy(state_before) if @durable_state.equal?(state_before)
            raise
          end
        end
      end

      alias commit_ips commit

      def release(lease_or_set = nil, operation_id: nil, sandbox_id: nil,
                  stopped: nil, process_stopped: nil, confirm_stopped: nil,
                  stop_confirmed: nil, force: false, **_options)
        operation = operation_id || operation_from_argument(lease_or_set)&.fetch("operation_id", nil)
        operation ||= lease_or_set.respond_to?(:operation_id) && lease_or_set.operation_id
        operation ||= find_operation(operation_id: nil, sandbox_id: sandbox_id)&.fetch("operation_id", nil)
        operation = Support.identifier(operation, "operation_id")
        confirmed = [stopped, process_stopped, confirm_stopped, stop_confirmed].compact.any?(true)
        # `force` is retained for API compatibility, but cannot establish that
        # the old sandbox process has stopped. Reuse must remain fail-closed.
        raise LeaseStateError, "IP release requires explicit process-stop confirmation" unless confirmed

        @mutex.synchronize do
          # Every change is persisted, so the state before this transaction
          # is the last one written; rolling back rebuilds from it instead of
          # copying the whole node's IPAM state up front on every call.
          state_before = @durable_state
          begin
            record = @state.fetch("operations", {})[operation]
            # Releasing what was never reserved is a completed release, not a
            # failure.  A hostNetwork Pod takes no address at all -- the add
            # path already skips the reservation for one -- so its teardown
            # arrives here with an operation IPAM has never heard of, and
            # refusing it left the Pod in CleanupPending: the node never issued
            # its final delete and the Pod stayed Terminating in the API.
            return LeaseSet.new([], operation_id: operation, sandbox_id: sandbox_id, pod_uid: nil) unless record
            if record["state"] == "released"
              return lease_set_for(record.fetch("lease_keys"), operation_id: operation,
                                                               sandbox_id: record.fetch("sandbox_id"), pod_uid: record.fetch("pod_uid"))
            end

            record.fetch("lease_keys").each do |key|
              lease = @state.fetch("leases").fetch(key)
              @state["leases"][key] = lease.merge("state" => "released", "released_at" => Support.now(@clock).iso8601(6))
            end
            record = @state["operations"][operation] = record.merge("state" => "released")
            prune_released_operations_locked!
            persist!("lease_released", "operation_id" => operation, "lease_keys" => record.fetch("lease_keys"),
                                       "stop_confirmed" => true)
            lease_set_for(record.fetch("lease_keys"), operation_id: operation,
                                                      sandbox_id: record.fetch("sandbox_id"), pod_uid: record.fetch("pod_uid"))
          rescue StandardError
            @state = Support.working_copy(state_before) if @durable_state.equal?(state_before)
            raise
          end
        end
      end

      alias release_ips release

      def lease(value = nil, family: nil, ip: nil, sandbox_id: nil, operation_id: nil, include_released: true)
        @mutex.synchronize do
          candidate = if value
                        normalize_lease_argument(value).first
                      elsif ip
                        @state.fetch("leases", {}).values.find { |entry| entry["ip"] == String(ip) }
                      elsif operation_id
                        operation = @state.fetch("operations", {})[String(operation_id)]
                        operation && @state.fetch("leases", {})[operation.fetch("lease_keys").first]
                      elsif sandbox_id
                        operation = find_operation(operation_id: nil, sandbox_id: String(sandbox_id))
                        operation && @state.fetch("leases", {})[operation.fetch("lease_keys").first]
                      end
          return nil unless candidate
          return nil if !include_released && candidate["state"] == "released"

          lease_from(candidate)
        end
      end

      def leases(operation_id: nil, sandbox_id: nil, node: nil, state: nil, include_released: false)
        @mutex.synchronize do
          values = @state.fetch("leases", {}).values
          values = values.select { |lease| lease["operation_id"] == String(operation_id) } if operation_id
          values = values.select { |lease| lease["sandbox_id"] == String(sandbox_id) } if sandbox_id
          values = values.select { |lease| lease["node"] == String(node) } if node
          values = values.select { |lease| lease["state"] == String(state) } if state
          values = values.reject { |lease| lease["state"] == "released" } unless include_released
          values.sort_by { |lease| [lease.fetch("sandbox_id"), lease.fetch("family")] }.map { |entry| lease_from(entry) }.freeze
        end
      end

      def operations(state: nil)
        @mutex.synchronize do
          values = @state.fetch("operations").values
          values = values.select { |entry| entry["state"] == String(state) } if state
          Support.copy(values).freeze
        end
      end

      def used?(ip, include_released: false)
        value = String(ip)
        @mutex.synchronize do
          entry = @state.fetch("leases", {}).values.find { |lease| lease["ip"] == value }
          entry && (include_released || entry["state"] != "released")
        end
      end

      # Bind a reserved lease to the exact kernel address and route objects
      # observed after topology application. Recovery subsequently compares
      # namespace inode, link identity, prefix, and the complete route tuple;
      # an IP string alone is never sufficient ownership proof.
      def bind_kernel_identity(operation_id:, resources:, require_complete: false)
        operation = Support.identifier(operation_id, "operation_id")
        observed = Array(resources).map do |resource|
          value = resource.respond_to?(:to_h) ? resource.to_h : resource
          Support.copy(value)
        end
        @mutex.synchronize do
          record = @state.fetch("operations", {})[operation]
          raise LeaseStateError, "unknown IPAM operation #{operation.inspect}" unless record
          raise LeaseStateError, "cannot bind released IPAM operation #{operation.inspect}" if record["state"] == "released"

          record.fetch("lease_keys").each do |key|
            lease = @state.fetch("leases").fetch(key)
            address = observed.find do |entry|
              entry.fetch("kind", nil).to_s == "address" &&
                Support.fetch(entry.fetch("metadata", {}), "address", "ip", default: nil).to_s == lease.fetch("ip")
            end
            if address.nil?
              raise LeaseStateError, "kernel address identity is missing for #{key}" if require_complete

              next
            end

            metadata = Support.canonical(address.fetch("metadata", {}))
            required = %w[netns_inode ifindex ifname prefix]
            missing = required.select { |field| Support.fetch(metadata, field, default: nil).nil? }
            unless missing.empty?
              raise LeaseStateError, "kernel address identity for #{key} is missing #{missing.join(", ")}" if require_complete

              next
            end
            routes = observed.filter_map do |entry|
              next unless entry.fetch("kind", nil).to_s == "route"

              route = Support.canonical(entry.fetch("metadata", {}))
              next unless route["netns_inode"].to_i == metadata.fetch("netns_inode").to_i
              next unless route["ifindex"].to_i == metadata.fetch("ifindex").to_i
              next unless route["ifname"].to_s == metadata.fetch("ifname").to_s
              next unless route["family"].nil? || Support.family(route["family"]) == lease.fetch("family")

              {
                "identity" => entry.fetch("identity"),
                "destination" => route.fetch("destination"),
                "gateway" => route["gateway"],
                "table" => route.fetch("table"),
                "metric" => route["metric"],
                "protocol" => route.fetch("protocol"),
                "scope" => route.fetch("scope"),
                "route_type" => route.fetch("route_type")
              }
            end.sort_by { |route| route.fetch("identity") }
            identity = {
              "address_identity" => address.fetch("identity"),
              "netns_inode" => Integer(metadata.fetch("netns_inode")),
              "ifindex" => Integer(metadata.fetch("ifindex")),
              "ifname" => metadata.fetch("ifname").to_s,
              "prefix" => Integer(metadata.fetch("prefix")),
              "routes" => routes
            }
            @state["leases"][key] =
              lease.merge("metadata" => Support.copy(lease.fetch("metadata", {})).merge("kernel_identity" => identity))
          end
          persist!("lease_kernel_identity_bound", "operation_id" => operation,
                                                  "lease_keys" => record.fetch("lease_keys"))
          lease_set_for(record.fetch("lease_keys"), operation_id: operation,
                                                    sandbox_id: record.fetch("sandbox_id"), pod_uid: record.fetch("pod_uid"))
        end
      rescue KeyError, ArgumentError, TypeError => error
        raise LeaseStateError, "kernel IPAM identity is incomplete: #{error.message}"
      end

      def recover(observer: nil, kernel_observer: nil, **_options)
        source = observer || kernel_observer || @observer
        observed = normalize_observed(source)
        @mutex.synchronize do
          reclaimed = []
          unknown = []
          identity_mismatch = []
          audit = []
          errors = []
          expected = @state.fetch("leases", {}).values.reject { |lease| lease["state"] == "released" }
          expected.each do |lease|
            key = lease_key(lease.fetch("family"), lease.fetch("ip"))
            actual = observed[key]
            if actual.nil?
              if lease["state"] == "reserved"
                @state["leases"][key] = lease.merge("state" => "released", "recovered_at" => Support.now(@clock).iso8601(6))
                reclaimed << key
                audit << {"kind" => "reclaimed_reservation", "resource" => key}
              else
                @state["leases"][key] = lease.merge("state" => "unknown")
                unknown << key
                audit << {"kind" => "unknown_committed_lease", "resource" => key}
              end
            elsif !identity_matches?(lease, actual)
              identity_mismatch << {"resource" => key, "lease" => Support.copy(lease), "observed" => Support.copy(actual)}
              audit << {"kind" => "identity_mismatch", "resource" => key}
            else
              audit << {"kind" => "matched", "resource" => key}
            end
          end
          expected_keys = expected.map { |lease| lease_key(lease.fetch("family"), lease.fetch("ip")) }
          orphans = observed.reject { |key, _value| expected_keys.include?(key) }.keys.sort
          persist!("ipam_recovered", "reclaimed" => reclaimed, "unknown" => unknown,
                                     "identity_mismatch" => identity_mismatch, "orphans" => orphans)
          RecoveryReport.new(reclaimed: reclaimed.freeze, unknown: unknown.freeze,
                             identity_mismatch: Support.immutable(identity_mismatch), orphans: orphans.freeze,
                             errors: errors.freeze, audit: Support.immutable(audit)).freeze
        rescue StandardError => error
          raise error if error.is_a?(Error)

          errors << {"error" => "#{error.class}: #{error.message}"}
          RecoveryReport.new(reclaimed: reclaimed.freeze, unknown: unknown.freeze,
                             identity_mismatch: Support.immutable(identity_mismatch), orphans: orphans.freeze,
                             errors: Support.immutable(errors), audit: Support.immutable(audit)).freeze
        end
      end

      alias reconcile recover

      def state
        @mutex.synchronize { Support.copy(@state) }
      end

      private

      def default_state
        {"version" => 1, "nodes" => {}, "leases" => {}, "operations" => {}, "generation" => 0}
      end

      def parse_cluster_cidrs(cluster_cidr:, ipv4_cidr:, ipv6_cidr:)
        values = {}
        if cluster_cidr.is_a?(Hash)
          ipv4_cidr ||= Support.fetch(cluster_cidr, "ipv4", "v4", default: nil)
          ipv6_cidr ||= Support.fetch(cluster_cidr, "ipv6", "v6", default: nil)
        elsif cluster_cidr
          address = Support.ip(cluster_cidr.to_s.split("/", 2).first, name: "cluster_cidr")
          if address.ipv4?
            ipv4_cidr ||= cluster_cidr
          else
            ipv6_cidr ||= cluster_cidr
          end
        end
        if ipv4_cidr
          values["ipv4"] = Support.cidr(ipv4_cidr, name: "ipv4_cidr").then do |network, prefix|
            {"network" => network.to_s, "prefix" => prefix}
          end
        end
        if ipv6_cidr
          values["ipv6"] = Support.cidr(ipv6_cidr, name: "ipv6_cidr").then do |network, prefix|
            {"network" => network.to_s, "prefix" => prefix}
          end
        end
        values
      end

      def prefix_for(value, family)
        return DEFAULT_NODE_PREFIX.fetch(family) if value.nil?
        return value.fetch(family) { value.fetch(family.to_sym) } if value.is_a?(Hash)

        value
      end

      def validate_prefixes!
        @node_cidrs.each do |family, config|
          raise ValidationError, "#{family} node prefix must not be broader than cluster CIDR" unless @node_prefixes.fetch(family) >= config.fetch("prefix")
        end
      end

      def normalize_families(values)
        list = Array(values).map { |value| Support.family(value) }.uniq
        raise ValidationError, "at least one address family is required" if list.empty?

        list.sort_by { |family| family == "ipv4" ? 0 : 1 }
      end

      def normalize_state(value)
        state = Support.copy(value || default_state)
        state["version"] ||= 1
        state["nodes"] ||= {}
        state["leases"] ||= {}
        state["operations"] ||= {}
        state["generation"] = Integer(state["generation"] || 0)
        state
      rescue ArgumentError, TypeError => error
        raise DurabilityError, "invalid IPAM state: #{error.message}"
      end

      def next_node_subnet(family)
        config = @node_cidrs.fetch(family)
        network = IPAddr.new(config.fetch("network"))
        cluster_prefix = config.fetch("prefix")
        node_prefix = @node_prefixes.fetch(family)
        count = 1 << (node_prefix - cluster_prefix)
        raise LeaseUnavailable, "#{family} cluster CIDR has too many node subnets to scan safely" if count > MAX_NODE_SUBNET_SCAN

        used = @state.fetch("nodes", {}).values.filter_map { |entry| entry[family] }.to_set
        count.times do |index|
          candidate = subnet_at(network, node_prefix, index)
          return candidate unless used.include?(candidate)
        end
        raise LeaseUnavailable, "no #{family} node subnet remains in #{network}/#{cluster_prefix}"
      end

      def subnet_at(network, prefix, index)
        bits = network.ipv4? ? 32 : 128
        increment = 1 << (bits - prefix)
        "#{IPAddr.new(network.to_i + (index * increment), network.family)}/#{prefix}"
      end

      def allocate_node_locked(node_id, families)
        current = @state.fetch("nodes")[node_id] ||= {}
        families.each { |family| current[family] ||= next_node_subnet(family) }
        current
      end

      def next_pod_ip(family, subnet, node_id)
        network, prefix = Support.cidr(subnet, name: "node subnet")
        bits = network.ipv4? ? 32 : 128
        total = 1 << [bits - prefix, 20].min
        # The first host address is the node's own address on the bridge (the
        # Pods' default gateway and DNS server), as host-local IPAM reserves
        # the gateway; Pods start at the second.
        start = 2
        last = network.ipv4? ? total - 2 : total - 1
        used = @state.fetch("leases", {}).values.select do |lease|
          lease["node"] == node_id && lease["family"] == family && ACTIVE_STATES.include?(lease["state"])
        end.to_set { |lease| lease["ip"] }
        (start..last).each do |offset|
          candidate = IPAddr.new(network.to_i + offset, network.family).to_s
          return candidate unless used.include?(candidate)
        end
        raise LeaseUnavailable, "no #{family} pod IP remains in #{subnet}"
      end

      def next_generation
        @state["generation"] = Integer(@state["generation"] || 0) + 1
      end

      def lease_key(family, ip)
        "#{family}:#{ip}"
      end

      def lease_from(value)
        Lease.new(family: value.fetch("family"), ip: value.fetch("ip"), pod_uid: value.fetch("pod_uid"),
                  sandbox_id: value.fetch("sandbox_id"), operation_id: value.fetch("operation_id"),
                  state: value.fetch("state"), node: value.fetch("node"), subnet: value.fetch("subnet"),
                  generation: value.fetch("generation"), metadata: Support.immutable(value.fetch("metadata", {}))).freeze
      end

      def lease_set_for(keys, operation_id:, sandbox_id:, pod_uid:)
        values = Array(keys).map { |key| @state.fetch("leases").fetch(key) }
        LeaseSet.new(values.map { |entry| lease_from(entry) }, operation_id: operation_id,
                                                               sandbox_id: sandbox_id, pod_uid: pod_uid)
      end

      # Released operations were kept for ever: one per Pod ever started on
      # the node, and every IPAM write re-encodes the whole state, so each Pod
      # made the next one's address reservation slower (a conformance round
      # starts ~2,000 Pods).  A window of recent releases stays so a retried
      # release or reservation still replays; an older one is treated like
      # any operation IPAM never saw (release of it is already complete).
      RETAINED_RELEASED_OPERATIONS = 64

      def prune_released_operations_locked!
        operations = @state["operations"]
        released = operations.select { |_id, record| record.is_a?(Hash) && record["state"] == "released" }.keys
        excess = released.length - RETAINED_RELEASED_OPERATIONS
        return unless excess.positive?

        released.first(excess).each { |id| operations.delete(id) }
      end

      def find_operation(operation_id:, sandbox_id:)
        if operation_id
          @state.fetch("operations", {})[String(operation_id)]
        elsif sandbox_id
          @state.fetch("operations", {}).values.reverse.find { |entry| entry["sandbox_id"] == String(sandbox_id) }
        end
      end

      def operation_from_argument(value)
        return nil unless value
        return @state.fetch("operations", {})[value.operation_id] if value.respond_to?(:operation_id) && value.operation_id

        if value.is_a?(Hash)
          operation = Support.fetch(value, "operation_id", default: nil)
          return @state.fetch("operations", {})[String(operation)] if operation
        end
        nil
      end

      def normalize_lease_argument(value)
        return value.to_a.flat_map { |entry| normalize_lease_argument(entry) } if value.is_a?(LeaseSet) || value.is_a?(Array)
        return [value.to_h] if value.is_a?(Lease)
        return [Support.copy(value)] if value.is_a?(Hash)

        []
      end

      def ensure_intent!(existing, node_id:, pod_uid:, sandbox_id:, families:, config_digest:)
        expected = existing["node"] == node_id && existing["pod_uid"] == pod_uid && existing["sandbox_id"] == sandbox_id &&
                   Array(existing["families"]).sort == families.sort && existing["config_digest"] == config_digest
        raise OperationConflict, "IPAM operation was replayed with different intent" unless expected
      end

      def identity_matches?(lease, observed)
        owner = Support.fetch(observed, "pod_uid", "sandbox_id", "owner", default: nil)
        # NativeObserver labels kernel-owned records with a transport owner;
        # that label is not a pod identity and must not turn every successful
        # kernel readback into an identity mismatch.
        owner_matches = owner.nil? || %w[kernel-observer network-observer observer].include?(owner.to_s) ||
                        [lease["pod_uid"], lease["sandbox_id"], lease["operation_id"]].include?(owner.to_s)
        return false unless owner_matches

        expected = Support.fetch(lease.fetch("metadata", {}), "kernel_identity", default: nil)
        return true unless expected

        expected = Support.canonical(expected)
        actual = Support.canonical(Support.fetch(observed, "metadata", default: {}))
        return false unless observed["identity"].to_s == expected.fetch("address_identity").to_s

        %w[netns_inode ifindex ifname prefix].each do |field|
          return false unless actual[field].to_s == expected.fetch(field).to_s
        end
        actual_routes = Array(Support.fetch(observed, "network_routes", default: [])).map do |route|
          value = route.respond_to?(:to_h) ? route.to_h : route
          Support.fetch(value, "identity", default: nil).to_s
        end
        Array(expected["routes"]).all? do |route|
          actual_routes.include?(Support.fetch(route, "identity").to_s)
        end
      end

      def normalize_observed(source)
        values = if source.nil?
                   []
                 elsif source.respond_to?(:call)
                   source.call
                 elsif source.respond_to?(:resources)
                   source.resources
                 elsif source.respond_to?(:list_resources)
                   source.list_resources
                 elsif source.respond_to?(:observe)
                   source.observe
                 else
                   raise ValidationError, "kernel observer must respond to call, resources, list_resources, or observe"
                 end
        normalized = Array(values).map do |resource|
          hash = resource.respond_to?(:to_h) ? resource.to_h : resource
          Support.copy(hash)
        end
        routes = normalized.select { |resource| Support.fetch(resource, "kind", default: nil).to_s == "route" }
        normalized.each_with_object({}) do |hash, result|
          metadata = Support.fetch(hash, "metadata", default: {})
          metadata = metadata.respond_to?(:to_h) ? metadata.to_h : {}
          ip = Support.fetch(hash, "ip", "address", default: nil) ||
               Support.fetch(metadata, "ip", "address", default: nil)
          next if ip.nil?

          normalized_ip = String(ip).split("/", 2).first
          family = Support.fetch(hash, "family", default: nil) ||
                   Support.fetch(metadata, "family", default: nil) ||
                   Support.address_family(normalized_ip)
          key = lease_key(Support.family(family), normalized_ip)
          value = Support.copy(hash)
          value["network_routes"] = routes.select do |route|
            route_metadata = Support.fetch(route, "metadata", default: {})
            Support.fetch(route_metadata, "netns_inode", default: nil).to_s == Support.fetch(metadata, "netns_inode", default: nil).to_s &&
              Support.fetch(route_metadata, "ifindex", default: nil).to_s == Support.fetch(metadata, "ifindex", default: nil).to_s &&
              Support.fetch(route_metadata, "ifname", default: nil).to_s == Support.fetch(metadata, "ifname", default: nil).to_s
          end
          result[key] = value
        end
      end

      def persist!(event, payload)
        previous = @durable_state
        durable = false
        begin
          written = @store&.replace(@state)
          durable = !@store.nil?
          @durable_state = written.is_a?(Hash) ? written : Support.copy(@state)
          # Keep working on the sealed records (replaced, never edited), so
          # the next write re-encodes only what changes.
          @state = Support.working_copy(written) if written.is_a?(Hash)
          append_journal(event, payload)
        rescue StandardError
          # Do not make an already-replaced state file disagree with the
          # in-memory state when only the optional journal append failed.
          @state = Support.copy(previous) unless durable
          raise
        end
      end

      def append_journal(event, payload)
        return unless @journal

        parameters = @journal.method(:append).parameters
        requires_operation = parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :operation_id }
        if requires_operation
          @journal.append(operation_id: "network:ipam", event: event, payload: payload)
        else
          @journal.append(event: event, payload: payload)
        end
      end
    end

    Ipam = IPAM
    IPAddressManager = IPAM
  end
end
