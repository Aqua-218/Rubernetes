# frozen_string_literal: true

require_relative "durable_state"
require_relative "errors"
require_relative "ipam"
require_relative "support"
require_relative "topology"

module Rubernetes
  module Network
    # Network interface transaction coordinator.  All kernel effects are
    # adapter-injected, while operation intent/results and ownership are made
    # durable before an external caller observes success.
    # One sandbox transaction at a time, as before, but a waiting attach goes
    # ahead of waiting detaches.  A Pod start queued behind the teardown of
    # the previous spec's Pods -- thirty-four detaches on one node -- waited
    # 5-6 s for its network ("[sig-apps] Daemon set should list and delete a
    # collection of DaemonSets": 10.6 s, upstream 1.3).  Detaches only finish
    # later; nothing waits on them but the Pod's own cleanup.
    class TransactionLock
      def initialize
        @mutex = Mutex.new
        @condition = ConditionVariable.new
        @held_by = nil
        @waiting_adds = 0
      end

      def synchronize(kind = :add)
        acquire(kind)
        begin
          yield
        ensure
          release
        end
      end

      def owned?
        @mutex.synchronize { @held_by.equal?(Thread.current) }
      end

      private

      def acquire(kind)
        @mutex.synchronize do
          raise ThreadError, "deadlock; recursive network transaction" if @held_by.equal?(Thread.current)

          @waiting_adds += 1 if kind == :add
          begin
            @condition.wait(@mutex) while @held_by || (kind != :add && @waiting_adds.positive?)
          ensure
            @waiting_adds -= 1 if kind == :add
          end
          @held_by = Thread.current
        end
      end

      def release
        @mutex.synchronize do
          @held_by = nil
          @condition.broadcast
        end
      end
    end

    class Interface
      Operation = Struct.new(:id, :request_id, :sandbox_id, :owner, :config_digest,
                             :state, :result, :error, :resources, :plan, :created_at,
                             keyword_init: true) do
        def to_h
          {"id" => id, "request_id" => request_id, "sandbox_id" => sandbox_id,
           "owner" => owner, "config_digest" => config_digest, "state" => state,
           "result" => result, "error" => error, "resources" => resources,
           "plan" => plan, "created_at" => created_at}
        end
      end

      RecoveryReport = Struct.new(:operations, :ipam, :kernel_only, :ledger_only,
                                  :identity_mismatch, :errors, :audit, keyword_init: true) do
        def to_h
          {"operations" => operations, "ipam" => ipam.respond_to?(:to_h) ? ipam.to_h : ipam,
           "kernel_only" => kernel_only, "ledger_only" => ledger_only,
           "identity_mismatch" => identity_mismatch, "errors" => errors, "audit" => audit}
        end
      end

      ACTIVE_STATES = %w[preparing applying committed deleting unknown].freeze

      def initialize(ipam: nil, topology: nil, netlink: nil, adapter: nil, ledger: nil,
                     state_path: nil, path: nil, state_store: nil, store: nil,
                     journal: nil, observer: nil, kernel_observer: nil,
                     policy_engine: nil,
                     bridge_manager: nil,
                     sysctl_manager: nil,
                     bridge_name: Topology::DEFAULT_BRIDGE, mtu: 1500,
                     clock: -> { Time.now.utc }, fsync: true, require_observer: false,
                     readback_timeout: 3.0, readback_interval: 0.02,
                     cluster_cidrs: nil, host_forward: nil, logger: nil, **options)
        @clock = clock
        @mutex = Mutex.new
        # A single sandbox transaction must not overlap another add/delete.
        # The state mutex protects snapshots; this lock protects the external
        # topology effect sequence around those snapshots.
        @transaction_mutex = TransactionLock.new
        @adapter = adapter
        @observer = kernel_observer || observer
        @require_observer = require_observer == true
        @readback_timeout = Float(readback_timeout)
        @readback_interval = Float(readback_interval)
        raise ValidationError, "network readback timeout must be positive" unless @readback_timeout.positive?
        raise ValidationError, "network readback interval must be positive" unless @readback_interval.positive?
        if @require_observer && (@observer.nil? || !@observer.respond_to?(:external_observer?) || !@observer.external_observer?)
          raise OwnershipError, "native network interface requires an external kernel observer"
        end

        @ledger = ledger
        @policy_engine = policy_engine
        @sysctl_manager = sysctl_manager
        @journal = journal
        @store = state_store || store || (if state_path || path
                                            DurableState.new(state_path || path, default: default_state,
                                                                                 fsync: fsync)
                                          end)
        @state = @store ? normalize_state(@store.read) : default_state
        @durable_state = Support.copy(@state)
        @ipam = ipam
        @topology = topology || Topology.new(netlink: netlink, adapter: adapter, bridge_name: bridge_name, mtu: mtu,
                                             bridge_manager: bridge_manager, clock: clock)
        @cluster_cidrs = Array(cluster_cidrs).map(&:to_s).reject(&:empty?).uniq.freeze
        @host_forward = host_forward
        @logger = logger
        @host_forward = HostForward.new(logger: logger) if @host_forward.nil? && !@cluster_cidrs.empty?
        @host_forward_applied = false
        @options = options
      end

      attr_reader :ipam, :topology, :ledger, :policy_engine, :sysctl_manager

      # The node's own address on the Pod bridge for each family: the first
      # host of the node subnet, the way the bridge CNI plugin assigns the
      # gateway.  Pods route through it and the node DNS server binds to it.
      def node_gateways(node: "local", families: nil)
        return {} unless @ipam

        subnets = @ipam.allocate_node_subnet(node: node, families: families)
        subnets.each_with_object({}) do |(family, cidr), result|
          network, prefix = Support.cidr(cidr, name: "node subnet")
          result[family.to_s] = {"address" => IPAddr.new(network.to_i + 1, network.family).to_s, "prefix" => prefix}
        end
      end

      # Create the node bridge (if absent) and give it the gateway addresses
      # before any Pod exists.  Idempotent: an address that is already there
      # is accepted.
      def ensure_node_bridge(owner: "node", node: "local", families: nil)
        gateways = node_gateways(node: node, families: families)
        return gateways if gateways.empty?

        bridge = @topology.bridge_name
        @topology.bridge_manager.acquire(name: bridge, mtu: @topology.mtu, owner: owner)
        assign_bridge_addresses(bridge, gateways)
        ensure_host_forwarding!
        gateways
      end

      # The bridge and the routes are not enough on a host whose forward path
      # drops by default; see Network::HostForward.  Applied once per process,
      # after the bridge exists.
      def ensure_host_forwarding!
        return if @host_forward.nil? || @host_forward_applied || @cluster_cidrs.empty?

        @host_forward.ensure!(@cluster_cidrs)
        @host_forward_applied = true
      rescue StandardError
        # A host that refuses the rule is reported by HostForward itself; a
        # failure here must not stop the node from serving Pods that do not
        # need to cross a node boundary.
        @host_forward_applied = true
      end

      # Interface contract: add(sandbox, config) -> IP/route result.
      def add(sandbox, config = nil, **)
        @transaction_mutex.synchronize(:add) { add_transaction(sandbox, config, **) }
      end

      def add_transaction(sandbox, config = nil, **options)
        sandbox_hash, config_hash = normalize_request(sandbox, config, options)
        sandbox_id = sandbox_hash.fetch("sandbox_id")
        request_id = Support.identifier(
          Support.fetch(config_hash, "network_operation_id", "operation_id", "request_id", default: "add:#{sandbox_id}"), "request_id"
        )
        operation_id = Support.identifier(Support.fetch(config_hash, "operation_id", default: request_id), "operation_id")
        digest = Support.digest(config_hash)
        owner = "network:#{sandbox_id}"
        @mutex.synchronize do
          existing = find_operation(request_id: request_id, sandbox_id: sandbox_id)
          if existing
            ensure_intent!(existing, digest: digest, sandbox_id: sandbox_id)
            return operation_result(existing)
          end
          record = operation_record(operation_id: operation_id, request_id: request_id, sandbox_id: sandbox_id,
                                    owner: owner, config_digest: digest, state: "preparing")
          @state["operations"][operation_id] = record
          @state["requests"][request_id] = operation_id
          persist!("network_operation_started", "operation" => record)
        end

        leases = nil
        plan = nil
        resources = []
        apply_started = false
        bridge_acquired = false
        sysctl_acquired = false
        namespace_lease = nil
        begin
          namespace_lease, config_hash = bind_namespace_request(sandbox_hash, config_hash)
          if @ipam && !Support.host_network?(config_hash)
            families = Support.fetch(config_hash, "families", default: nil)
            leases = @ipam.reserve(node: Support.fetch(config_hash, "node", "node_name", default: "local"),
                                   pod_uid: Support.fetch(sandbox_hash, "pod_uid", "uid", default: sandbox_id),
                                   sandbox_id: sandbox_id, operation_id: operation_id,
                                   families: families, dual_stack: Support.fetch(config_hash, "dual_stack", default: nil),
                                   config_digest: digest, metadata: Support.fetch(config_hash, "metadata", default: {}))
          end
          gateways = {}
          if leases && Support.fetch(config_hash, "gateway", default: nil).nil?
            # The default route points at the bridge's node address so the
            # Pod reaches the node (DNS, host services) and, through the
            # node, other subnets.
            gateways = node_gateways(node: Support.fetch(config_hash, "node", "node_name", default: "local"),
                                     families: leases.map { |lease| lease.to_h.fetch("family") })
            unless gateways.empty?
              config_hash = config_hash.merge("gateway" => gateways.transform_values do |entry|
                entry.fetch("address")
              end)
            end
          end
          desired_plan = @topology.desired(sandbox_hash, config_hash, leases: leases,
                                                                      revision: Support.fetch(config_hash, "revision", default: nil))
          # Keep plan nil until preparation succeeds; if state capture fails
          # before any effect, rescue must not attempt to roll back an
          # unapplied desired plan.
          plan = nil
          # Capture non-owned link state before the first effect and persist
          # that prepared plan. A crash during apply can then roll back from
          # durable evidence instead of guessing the old MTU/master/up state.
          plan = @topology.respond_to?(:prepare) ? @topology.prepare(desired_plan) : desired_plan
          update_operation(operation_id, "state" => "applying", "plan" => plan.to_h,
                                         "effect_cursor" => nil, "applied_count" => 0)
          ledger_operation_id = begin_resource_operation(operation_id, digest: digest, owner: owner,
                                                                       request_id: request_id, sandbox_id: sandbox_id)
          apply_started = true
          if @topology.respond_to?(:acquire_bridge)
            @topology.acquire_bridge(plan, owner: sandbox_id)
            bridge_acquired = true unless Support.fetch(plan.metadata, "host_network", default: false)
            assign_bridge_addresses(Support.fetch(plan.metadata, "bridge"), gateways) if bridge_acquired && !gateways.empty?
          end
          if bridge_acquired && @sysctl_manager
            @sysctl_manager.acquire(owner: sandbox_id, bridge: Support.fetch(plan.metadata, "bridge"), operation_id: operation_id)
            sysctl_acquired = true
          end
          flush_pod_neighbours(Support.fetch(plan.metadata, "bridge"), plan_addresses(plan)) if bridge_acquired
          plan = @topology.apply(
            plan,
            operation_id: operation_id,
            before_operation: lambda do |operation, index|
              # Persist the exact effect intent before entering the kernel.
              # Recovery can therefore compensate a crash after the effect
              # but before its readback/claim callback.
              update_operation(operation_id, "effect_cursor" => index, "effect_intent" => operation.to_h)
            end,
            after_operation: lambda do |operation, index|
              observed_resources = resources_from_operation(operation, owner: owner, sandbox_id: sandbox_id)
              claimed = []
              begin
                observed_resources.each do |resource|
                  claim_resource(ledger_operation_id, resource)
                  claimed << resource
                end
              ensure
                # A veth effect produces two proofs (host and peer) and each
                # used to be persisted on its own -- a full rewrite of the
                # node's network state per claim, which is what concurrent Pod
                # starts queued behind.  One write covers the effect, and a
                # claim that succeeded before a later one failed is still
                # recorded, because this runs on the way out either way.
                # Recovery reconciles ledger against state regardless (a
                # ledger-only resource is reported and released).
                unless claimed.empty?
                  resources = merge_resources(resources, claimed)
                  update_operation(operation_id, "resources" => resources)
                end
              end
              update_operation(operation_id, "resources" => resources, "applied_count" => index + 1)
            end
          )
          # A host-network Pod reserved no addresses, so there is no IPAM
          # operation to bind or commit: asking for one failed the Pod with
          # "unknown IPAM operation".
          unless Support.host_network?(config_hash)
            if @ipam.respond_to?(:bind_kernel_identity)
              @ipam.bind_kernel_identity(operation_id: operation_id, resources: resources,
                                         require_complete: @require_observer)
            end
            leases = @ipam&.commit(leases, operation_id: operation_id, network_ready: true) || leases
          end
          result = build_result(operation_id, sandbox_id, leases, plan)
          update_operation(operation_id, "state" => "committed", "resources" => resources,
                                         "effect_intent" => nil, "result" => result)
          result
        rescue StandardError => error
          rollback_errors = []
          begin
            rollback_plan = if apply_started && plan && error.respond_to?(:applied) && error.applied
                              plan_with_operations(plan, error.applied)
                            elsif apply_started
                              plan
                            end
            @topology.rollback(rollback_plan, operation_id: operation_id) if rollback_plan
          rescue StandardError => rollback_error
            rollback_errors << "#{rollback_error.class}: #{rollback_error.message}"
          end
          begin
            @ipam&.release(leases, operation_id: operation_id, stopped: true)
          rescue StandardError => release_error
            rollback_errors << "#{release_error.class}: #{release_error.message}"
          end
          begin
            @topology.release_bridge(plan, owner: sandbox_id) if bridge_acquired && @topology.respond_to?(:release_bridge)
          rescue StandardError => bridge_error
            rollback_errors << "#{bridge_error.class}: #{bridge_error.message}"
          end
          begin
            @sysctl_manager&.release(owner: sandbox_id) if sysctl_acquired
          rescue StandardError => sysctl_error
            rollback_errors << "#{sysctl_error.class}: #{sysctl_error.message}"
          end
          release_resources({"id" => operation_id, "resources" => resources}, force: true, errors: rollback_errors)
          failure = {"class" => error.class.name, "message" => error.message, "rollback_errors" => rollback_errors}
          update_operation(operation_id, "state" => "unknown", "resources" => resources, "error" => failure)
          # A rollback that itself failed is why the *next* attempt collides with
          # a resource this one left claimed, so it has to travel with the
          # error rather than only into the operation record.
          detail = rollback_errors.empty? ? "" : " (rollback: #{rollback_errors.join("; ")})"
          raise EffectError.new("network add failed for sandbox #{sandbox_id}: #{error.message}#{detail}",
                                operation: operation_id, cause_error: error)
        ensure
          namespace_lease&.close
        end
      end

      # Deletion is intentionally fail-closed: the caller must prove the
      # process/VM stopped before an IP or interface identity can be released.
      def delete(sandbox, config = nil, stopped: nil, process_stopped: nil,
                 confirm_stopped: nil, force: false, **)
        @transaction_mutex.synchronize(:delete) do
          delete_transaction(sandbox, config, stopped: stopped, process_stopped: process_stopped,
                                              confirm_stopped: confirm_stopped, force: force, **)
        end
      end

      def delete_transaction(sandbox, config = nil, stopped: nil, process_stopped: nil,
                             confirm_stopped: nil, force: false, **options)
        sandbox_hash, config_hash = normalize_request(sandbox, config, options)
        sandbox_id = sandbox_hash.fetch("sandbox_id")
        confirmed = [stopped, process_stopped, confirm_stopped].compact.any?(true)
        raise OwnershipError, "network delete requires explicit process-stop confirmation" unless confirmed

        operation_id = @mutex.synchronize do
          operation = find_operation(request_id: nil, sandbox_id: sandbox_id)
          return {"sandbox_id" => sandbox_id, "state" => "removed", "idempotent" => true}.freeze unless operation
          return operation_result(operation) if operation.fetch("state") == "removed"

          operation.fetch("id")
        end
        namespace_lease, = bind_namespace_request(sandbox_hash, config_hash)
        update_operation(operation_id, state: "deleting")
        operation = operation_for_id(operation_id)
        errors = []
        topology_released = false
        begin
          plan = plan_from_record(operation.fetch("plan"))
          plan = @topology.bind_namespace(plan, namespace_lease) if namespace_lease
          @topology.rollback(plan, operation_id: operation.fetch("id")) unless plan.empty?
          flush_pod_neighbours(Support.fetch(plan.metadata, "bridge"), plan_addresses(plan)) unless plan.empty?
          @topology.release_bridge(plan, owner: sandbox_id) if @topology.respond_to?(:release_bridge)
          topology_released = true
        rescue StandardError => error
          errors << {"component" => "topology", "error" => "#{error.class}: #{error.message}"}
        end
        if topology_released && @sysctl_manager
          begin
            @sysctl_manager.release(owner: sandbox_id, operation_id: operation.fetch("id"))
          rescue StandardError => error
            errors << {"component" => "sysctl", "error" => "#{error.class}: #{error.message}"}
          end
        end
        begin
          @ipam&.release(operation_id: operation.fetch("id"), stopped: true, force: force)
        rescue StandardError => error
          errors << {"component" => "ipam", "error" => "#{error.class}: #{error.message}"}
        end
        release_resources(operation, force: true, errors: errors)
        if errors.empty?
          finish_resource_operation(operation.fetch("id"))
          result = {"sandbox_id" => sandbox_id, "operation_id" => operation.fetch("id"), "state" => "removed"}.freeze
          update_operation(operation.fetch("id"), "state" => "removed", "result" => result)
          prune_removed_operations!
          result
        else
          update_operation(operation.fetch("id"), "state" => "unknown", "error" => {"cleanup_errors" => errors})
          raise EffectError, "network delete could not release all resources: #{errors.inspect}"
        end
      ensure
        namespace_lease&.close
      end

      private :add_transaction, :delete_transaction

      def check(sandbox, config = nil, **options)
        sandbox_hash, config_hash = normalize_request(sandbox, config, options)
        sandbox_id = sandbox_hash.fetch("sandbox_id")
        operation = @mutex.synchronize { find_operation(request_id: nil, sandbox_id: sandbox_id) }
        return false unless operation && operation.fetch("state") == "committed"

        namespace_lease, = bind_namespace_request(sandbox_hash, config_hash)
        if @adapter.respond_to?(:check)
          !!@adapter.check(sandbox_hash)
        elsif @observer
          plan = plan_from_record(operation.fetch("plan"))
          plan = @topology.bind_namespace(plan, namespace_lease) if namespace_lease
          resources = normalize_observed(@observer, operations: plan.operations)
          operation.fetch("resources", []).all? { |resource| resources.key?(resource.fetch("identity")) }
        else
          true
        end
      ensure
        namespace_lease&.close
      end

      alias exists? check

      def recover(observer: nil, kernel_observer: nil, **options)
        @sysctl_manager&.recover
        source = observer || kernel_observer || @observer
        records = @mutex.synchronize { Support.copy(@state.fetch("operations").values) }
        plan_operations = records.select { |operation| ACTIVE_STATES.include?(operation.fetch("state")) }
          .flat_map { |operation| plan_from_record(operation.fetch("plan")).operations }
        observed = normalize_observed(source, operations: plan_operations)
        expected_before_recovery = records.select { |operation| ACTIVE_STATES.include?(operation.fetch("state")) }
          .flat_map do |operation|
          Array(operation.fetch("resources", [])).map do |resource|
            resource.fetch("identity")
          end
        end
        kernel_only_before_recovery = (observed.keys - expected_before_recovery).sort
        compensated, compensation_audit, compensation_errors = compensate_effect_orphans(
          records, observed, source, candidates: kernel_only_before_recovery
        )
        reconciled_observed = observed.reject { |identity, _resource| compensated.include?(identity) }
        ipam_report = @ipam ? @ipam.recover(observer: -> { reconciled_observed.values }) : nil
        @mutex.synchronize do
          expected_identities = @state.fetch("operations").values.select do |operation|
            ACTIVE_STATES.include?(operation.fetch("state"))
          end.flat_map do |operation|
            Array(operation.fetch("resources", [])).map { |resource| resource.fetch("identity") }
          end.uniq
          kernel_only = (reconciled_observed.keys - expected_identities).sort
          ledger_only = []
          identity_mismatch = []
          errors = compensation_errors
          audit = compensation_audit
          @state.fetch("operations").each_value do |operation|
            next unless ACTIVE_STATES.include?(operation.fetch("state"))

            expected = operation.fetch("resources", []).map { |resource| resource.fetch("identity") }
            missing = expected - reconciled_observed.keys
            next if missing.empty?

            @state.fetch("operations")[operation.fetch("id")] = operation.merge("state" => "unknown")
            ledger_only.concat(missing)
            audit << {"kind" => "ledger_only", "operation_id" => operation.fetch("id"), "resources" => missing}
          end
          if @adapter.respond_to?(:recover)
            begin
              @adapter.recover(options)
            rescue StandardError => error
              errors << {"component" => "adapter", "error" => "#{error.class}: #{error.message}"}
            end
          end
          persist!("network_recovered", "ledger_only" => ledger_only, "kernel_only" => kernel_only,
                                        "identity_mismatch" => identity_mismatch)
          RecoveryReport.new(operations: Support.copy(@state.fetch("operations").values), ipam: ipam_report,
                             kernel_only: kernel_only.freeze, ledger_only: ledger_only.freeze,
                             identity_mismatch: Support.immutable(identity_mismatch), errors: Support.immutable(errors),
                             audit: Support.immutable(audit)).freeze
        end
      end

      alias reconcile recover

      def shutdown
        @sysctl_manager&.shutdown
        @topology.bridge_manager.shutdown if @topology.respond_to?(:bridge_manager)
        true
      end

      def operation(operation_id)
        @mutex.synchronize { operation_for_id(operation_id) }
      end

      def operations(state: nil)
        @mutex.synchronize do
          values = @state.fetch("operations").values
          values = values.select { |entry| entry.fetch("state") == String(state) } if state
          Support.copy(values).freeze
        end
      end

      def state
        @mutex.synchronize { Support.copy(@state) }
      end

      private

      def default_state
        {"version" => 1, "operations" => {}, "requests" => {}}
      end

      def normalize_state(value)
        state = Support.copy(value || default_state)
        state["version"] ||= 1
        state["operations"] ||= {}
        state["requests"] ||= {}
        state
      rescue StandardError => error
        raise DurabilityError, "invalid network operation state: #{error.message}"
      end

      # The host's neighbour cache remembers a Pod IP's MAC after the Pod is
      # gone; the next Pod to receive that IP sits behind a different veth,
      # and until the stale entry expires frames for it go to a MAC nobody
      # answers on.  The CNI bridge plugin sends a gratuitous ARP for the
      # same reason (plugins/main/bridge: arping).  A webhook the API server
      # dialled at a reused IP got no SYN-ACK for the whole 30 s webhook
      # timeout ("CustomResourceConversionWebhook ... convert from CR v1 to
      # CR v2").  The entry is dropped when a Pod takes an address and when
      # it gives one up; an address without an entry is not an error.
      def flush_pod_neighbours(bridge, addresses)
        return if bridge.to_s.empty? || addresses.empty?

        netlink = @topology.respond_to?(:netlink) ? @topology.netlink : nil
        netlink ||= @topology.instance_variable_get(:@netlink)
        return unless netlink.respond_to?(:neighbor_delete)

        addresses.each do |address|
          netlink.neighbor_delete(destination: address, dev: bridge, operation: "neighbour-flush:#{bridge}:#{address}")
        rescue StandardError
          nil
        end
      end

      def plan_addresses(plan)
        Array(plan.operations).select { |operation| operation.action == "address_add" }
          .filter_map { |operation| Support.fetch(operation.parameters, "address", default: nil) }
          .uniq
      end

      # Node-owned bridge addresses are not sandbox resources: they live as
      # long as the bridge and are never rolled back with a Pod.
      def assign_bridge_addresses(bridge, gateways)
        netlink = @topology.respond_to?(:netlink) ? @topology.netlink : nil
        netlink ||= @topology.instance_variable_get(:@netlink)
        return false unless netlink.respond_to?(:address_add)

        gateways.each do |family, entry|
          netlink.address_add(address: entry.fetch("address"), prefix: entry.fetch("prefix"), name: bridge,
                              family: family, operation: "node-bridge-address:#{bridge}:#{family}")
        rescue NetlinkError => error
          raise unless error.errno == Errno::EEXIST::Errno
        end
        true
      end

      def normalize_request(sandbox, config, options)
        sandbox_hash = if sandbox.respond_to?(:to_h)
                         sandbox.to_h
                       else
                         (sandbox.is_a?(Hash) ? sandbox : {"sandbox_id" => sandbox})
                       end
        sandbox_hash = Support.canonical(sandbox_hash)
        sandbox_id = Support.fetch(sandbox_hash, "sandbox_id", "id", "uid", default: nil)
        raise ValidationError, "sandbox ID is required" if sandbox_id.nil?

        sandbox_hash["sandbox_id"] = Support.identifier(sandbox_id, "sandbox_id")
        config_hash = Support.canonical((config.respond_to?(:to_h) ? config.to_h : (config || {})).merge(options))
        netns = Support.fetch(sandbox_hash, "netns", "network_namespace", default: nil)
        if netns && netns.respond_to?(:to_h)
          netns = Support.canonical(netns.to_h)
          sandbox_hash["netns"] = netns
          config_hash.delete("netns")
          config_hash.delete("network_namespace")
          config_hash.delete("namespace_fd")
          config_hash.delete("netns_fd")
          config_hash.delete("network_namespace_fd")
          config_hash["netns_inode"] ||= Support.fetch(netns, "inode", default: nil)
          config_hash["netns_handle"] ||= Support.fetch(netns, "handle", default: nil)
        elsif netns
          raise OwnershipError, "sandbox network namespace requires a complete holder identity"
        elsif Support.fetch(config_hash, "netns", "network_namespace", "namespace_fd", "netns_fd",
                            "network_namespace_fd", default: nil)
          raise OwnershipError, "network namespace configuration requires a runtime holder identity"
        end
        [sandbox_hash, config_hash]
      rescue ArgumentError, TypeError, SystemCallError => error
        raise OwnershipError, "sandbox network namespace descriptor is invalid: #{error.message}"
      end

      def operation_record(operation_id:, request_id:, sandbox_id:, owner:, config_digest:, state:)
        {"id" => operation_id, "request_id" => request_id, "sandbox_id" => sandbox_id,
         "owner" => owner, "config_digest" => config_digest, "state" => state,
         "result" => nil, "error" => nil, "resources" => [], "plan" => {"operations" => [], "mtu" => nil,
                                                                        "backend" => nil, "revision" => nil, "metadata" => {}}, "created_at" => Support.now(@clock).iso8601(6)}
      end

      def bind_namespace_request(sandbox_hash, config_hash)
        return [nil, config_hash] if Support.host_network?(config_hash)

        context = Support.fetch(sandbox_hash, "netns", "network_namespace", default: nil)
        return [nil, config_hash] unless context

        lease = Netlink::NamespaceLease.open(context)
        bound = config_hash.merge("namespace_fd" => lease.fileno,
                                  "netns_inode" => lease.inode,
                                  "netns_handle" => lease.handle)
        [lease, bound]
      rescue StandardError
        lease&.close
        raise
      end

      # A torn-down Pod's operation record is dead weight: the durable journal
      # keeps the audit trail, while @state is rewritten AND deep-copied in
      # full on every persist!.  Left unpruned it reached 245 operations /
      # 1.2 MB on a conformance node, and since a Pod's network setup persists
      # once per operation and per claimed resource, that turned every Pod
      # start into ~11 s of JSON churn (measured: network.connect 11-12 s of a
      # 17 s Pod start).  A small window of recent removals is retained so a
      # retried delete still replays idempotently.
      RETAINED_REMOVED_OPERATIONS = 32

      def prune_removed_operations!
        operations = @state["operations"]
        return unless operations.is_a?(Hash)

        removed = operations.select { |_id, operation| operation.is_a?(Hash) && operation["state"] == "removed" }
        excess = removed.keys[0, [removed.length - RETAINED_REMOVED_OPERATIONS, 0].max]
        return if excess.nil? || excess.empty?

        requests = @state["requests"]
        excess.each do |operation_id|
          operation = operations.delete(operation_id)
          next unless requests.is_a?(Hash) && operation.is_a?(Hash)

          request_id = operation["request_id"]
          requests.delete(String(request_id)) if request_id && requests[String(request_id)] == operation_id
        end
        persist!("network_operations_pruned", "pruned" => excess.length)
      end

      def find_operation(request_id:, sandbox_id:)
        if request_id
          operation_id = @state.fetch("requests", {})[String(request_id)]
          return @state.fetch("operations")[operation_id] if operation_id
        end
        @state.fetch("operations").values.reverse.find { |operation| operation.fetch("sandbox_id") == String(sandbox_id) }
      end

      def operation_for_id(id)
        operation = @state.fetch("operations")[String(id)]
        operation && Support.copy(operation)
      end

      def ensure_intent!(operation, digest:, sandbox_id:)
        same = operation.fetch("sandbox_id") == sandbox_id && operation.fetch("config_digest") == digest
        raise OperationConflict, "network request was replayed with different intent" unless same
      end

      def update_operation(operation_id, **changes)
        @mutex.synchronize do
          operation = @state.fetch("operations").fetch(String(operation_id))
          updated = operation.merge(changes.transform_keys(&:to_s))
          @state["operations"][String(operation_id)] = updated
          persist!("network_operation_updated", "operation" => updated)
          Support.copy(updated)
        end
      end

      def begin_resource_operation(operation_id, digest:, owner:, request_id:, sandbox_id:)
        return operation_id unless @ledger

        begin
          ledger_operation = @ledger.begin_operation(operation_id: operation_id, request_id: request_id,
                                                     action: "network_add", owner: owner,
                                                     config_digest: digest, target_id: sandbox_id)
        rescue ArgumentError
          # Native::OwnershipLedger predates the common ledger's action and
          # target fields; retain the same durable ownership semantics across
          # both implementations instead of silently dropping the ledger.
          ledger_operation = @ledger.begin_operation(operation_id: operation_id, request_id: request_id,
                                                     owner: owner, config_digest: digest)
        end
        ledger_operation.id
      rescue StandardError => error
        raise OwnershipError, "network ownership intent failed: #{error.message}"
      end

      def claim_resource(operation_id, resource)
        return resource unless @ledger

        begin
          result = @ledger.claim(operation_id: operation_id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                                 identity: resource.fetch("identity"), metadata: resource.fetch("metadata", {}))
        rescue StandardError => conflict
          raise conflict unless conflict.message.include?("already owned or identity changed")

          # A retried sandbox rebuilds the same deterministic interface name, so
          # a claim left by an earlier attempt of *this same owner* still names
          # the resource.  Superseding it is only safe once the kernel object it
          # described is proven gone: a live one is genuine reuse and must stay
          # fatal.
          decision = supersede_decision(operation_id, resource)
          raise Runtime::OwnershipConflict, "#{conflict.message} [supersede declined: #{decision}]" unless decision == :superseded

          result = @ledger.claim(operation_id: operation_id, kind: resource.fetch("kind"), id: resource.fetch("id"),
                                 identity: resource.fetch("identity"), metadata: resource.fetch("metadata", {}))
        end
        raise OwnershipError, "network ownership claim was rejected" if result == false

        resource
      rescue StandardError => error
        raise OwnershipError, "network ownership claim failed for #{resource.fetch("id")}: #{error.message}"
      end

      # :superseded when a stale same-owner claim was released and the caller may
      # retry; otherwise a symbol naming why it was refused.
      def supersede_decision(operation_id, resource)
        # The ledger's Resource is a Data object, so to_h yields *symbol* keys;
        # reading it with string keys silently finds nothing.
        held = Array(@ledger.resources(include_released: false)).map { |candidate| ledger_entry(candidate) }
          .find do |entry|
          entry["kind"].to_s == resource.fetch("kind").to_s && entry["id"].to_s == resource.fetch("id").to_s
        end
        return :no_held_claim unless held

        owner = resource["owner"]
        return :owner_differs unless owner && held["owner"].to_s == owner.to_s
        return :identity_matches if held["identity"].to_s == resource.fetch("identity").to_s

        held_name = (held["metadata"] || {})["name"] if held["kind"].to_s == "link"
        return :held_object_still_present if observed_identity?(held["identity"], kind: held["kind"], link_name: held_name)

        @ledger.release(operation_id: operation_id, kind: held["kind"], id: held["id"],
                        identity: held["identity"], force: true)
        :superseded
      rescue StandardError => error
        :"error_#{error.class.name.split("::").last}"
      end

      def ledger_entry(candidate)
        hash = candidate.respond_to?(:to_h) ? candidate.to_h : candidate
        hash.each_with_object({}) { |(key, value), result| result[key.to_s] = value }
      end

      # Only the table the held resource lives in is read: dumping links,
      # addresses, routes and neighbours to look for one veth made this
      # check a tenth of a busy node agent's CPU.
      def observed_identity?(identity, kind: nil, link_name: nil)
        return true if identity.to_s.empty?
        return true unless @observer.respond_to?(:resources)

        kinds = kind && NativeObserver::ACTION_KINDS.values.flatten.include?(kind.to_s) ? [kind.to_s] : nil
        accepted = @observer.method(:resources).parameters.map(&:last)
        options = {}
        options[:kinds] = kinds if kinds && accepted.include?(:kinds)
        options[:link_name] = link_name.to_s if link_name && kinds == ["link"] && accepted.include?(:link_name)
        observed = options.empty? ? @observer.resources : @observer.resources(**options)
        Array(observed).any? do |entry|
          value = entry.respond_to?(:to_h) ? entry.to_h : entry
          (value["identity"] || value["stable_identity"]).to_s == identity.to_s
        end
      rescue StandardError
        true
      end

      # The ledger operation of a deleted sandbox is finished (Removed) once
      # every resource it held is released.  An operation left in its initial
      # state is never forgettable, so the ledger's journal only ever grew:
      # 0.33 MB per 90 Pods, never compacted (OwnershipLedger forgets finished
      # operations beyond the last RETAINED_FINISHED_OPERATIONS and rewrites
      # the journal).  Network operations never walk the container states, so
      # the delete is recorded as the rollback of the attach: RollingBack,
      # Stopped, Removed -- the transitions the ledger allows from New.  A
      # ledger that refuses (an operation it does not know, or one already
      # finished by an earlier attempt) costs nothing but the compaction.
      def finish_resource_operation(operation_id)
        return unless @ledger && @ledger.respond_to?(:finish)

        current = @ledger.respond_to?(:operation) ? @ledger.operation(operation_id) : nil
        state = if current.respond_to?(:state)
                  current.state.to_s
                else
                  (current.is_a?(Hash) ? (current["state"] || current[:state]).to_s : "")
                end
        return if state == "Removed"

        path = case state
               when "New", "Validated", "ImagePinned", "WorkspaceAllocated", "IsolationCreated", "ResourcesAttached", "WorkloadStopped", "StateUnknown"
                 %w[RollingBack Stopped]
               when "Running" then %w[Stopping Stopped]
               when "Stopping", "RollingBack" then %w[Stopped]
               when "CleanupPending" then %w[RollingBack Stopped]
               else []
               end
        path.each { |to| @ledger.transition(operation_id: operation_id, to: to) }
        @ledger.finish(operation_id: operation_id)
      rescue StandardError => error
        if @logger.respond_to?(:warn)
          @logger&.warn("network.ledger_finish_skipped", operation_id: operation_id,
                                                         error: "#{error.class}: #{error.message}")
        end
        nil
      end

      def release_resources(operation, force:, errors:)
        return unless @ledger

        resources = Array(operation.fetch("resources", []))
        resources.each do |resource|
          @ledger.release(operation_id: operation.fetch("id"), kind: resource.fetch("kind"), id: resource.fetch("id"),
                          identity: resource.fetch("identity"), force: force)
        rescue StandardError => error
          entry = {"component" => "ledger", "resource" => resource.fetch("id"), "error" => "#{error.class}: #{error.message}"}
          errors << (errors.first.is_a?(String) ? "#{entry.fetch("component")}: #{entry.fetch("resource")}: #{entry.fetch("error")}" : entry)
        end
      end

      def resources_from_operation(operation, owner:, sandbox_id: nil)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        deadline = started + @readback_timeout
        attempts = 0
        proofs = []
        loop do
          attempts += 1
          proofs = if @observer.respond_to?(:resources_for)
                     Array(@observer.resources_for(operation))
                   else
                     []
                   end
          # resources_for carries the complete kernel tuple used by IPAM and
          # recovery. Never downgrade to identity_for merely because a
          # resources_for read raced DAD/rtnetlink propagation.
          if proofs.empty? && !@observer.respond_to?(:resources_for) && @observer.respond_to?(:identity_for)
            identity = @observer.identity_for(operation)
            proofs = [{"identity" => identity}] if identity
          end
          break unless @require_observer && proofs.empty?
          break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

          sleep(@readback_interval)
        end
        raise OwnershipError, "kernel observer did not read back #{operation.resource}" if @require_observer && proofs.empty?

        # A readback that needed more than one look is the node waiting on the
        # kernel, and it is the most expensive part of attaching a Pod.  Only
        # the waits are recorded: a first-look hit is the normal case and
        # writing it out would cost more than it measures.
        if attempts > 1
          persist!("network_readback_waited", "action" => operation.action.to_s,
                                              "attempts" => attempts,
                                              "seconds" => (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).round(3))
        end
        proofs = [{"identity" => operation.identity}] if proofs.empty?
        proofs.each_with_index.map do |proof, index|
          hash = proof.respond_to?(:to_h) ? proof.to_h : proof
          identity = Support.fetch(hash, "identity", "stable_identity", default: nil)
          if @require_observer && identity.to_s.empty?
            raise OwnershipError, "kernel observer returned an empty identity for #{operation.resource}"
          end

          proof_id = Support.fetch(hash, "id", default: nil)
          resource_id = index.zero? ? operation.resource : proof_id
          resource_id ||= "#{operation.resource}:#{index}"
          metadata = Support.fetch(hash, "metadata", default: operation.parameters)
          {"kind" => Support.fetch(hash, "kind", default: resource_id.split(":", 2).first),
           "id" => resource_id, "identity" => identity || operation.identity, "owner" => owner,
           "state" => "owned", "sandbox_id" => sandbox_id || operation.parameters["sandbox_id"],
           "metadata" => Support.copy(metadata)}
        end
      end

      # A crash may occur after a kernel effect and before its durable claim.
      # Recovery uses the persisted effect_intent plus fresh readback to claim
      # that exact identity, compensates only after the claim succeeds, then
      # releases the same identity. Unrelated host objects are never inferred
      # to be ours from their name alone.
      def compensate_effect_orphans(records, observed, source, candidates:)
        return [[], [], []] unless @ledger && source.respond_to?(:resources_for)

        compensated = []
        audit = []
        errors = []
        Array(records).each do |record|
          next unless %w[applying unknown].include?(record.fetch("state"))

          intent = record["effect_intent"]
          next unless intent

          operation = operation_from_value(intent)
          orphan_resources = Array(source.resources_for(operation)).each_with_index.filter_map do |proof, index|
            resource = resource_from_proof(operation, proof, owner: record.fetch("owner"),
                                                             sandbox_id: record.fetch("sandbox_id"), index: index)
            identity = resource.fetch("identity")
            resource if candidates.include?(identity) && observed.key?(identity)
          end
          next if orphan_resources.empty?

          claimed = []
          resources = Array(record.fetch("resources", []))
          begin
            # One kernel effect (notably a veth pair) can yield multiple
            # stable identities. Claim every proof before compensating, then
            # execute the inverse operation exactly once.
            orphan_resources.each do |resource|
              claim_resource(record.fetch("id"), resource)
              claimed << resource
              resources = merge_resources(resources, [resource])
              update_operation(record.fetch("id"), "resources" => resources)
            end
            plan = plan_from_record(record.fetch("plan"))
            @topology.rollback(plan_with_operations(plan, [operation]), operation_id: record.fetch("id"))
            claimed.each do |resource|
              identity = resource.fetch("identity")
              @ledger.release(operation_id: record.fetch("id"), kind: resource.fetch("kind"),
                              id: resource.fetch("id"), identity: identity, force: true)
              remaining = resources.reject { |entry| entry.fetch("identity") == identity }
              resources = remaining
              update_operation(record.fetch("id"), "resources" => resources)
              compensated << identity
              audit << {"kind" => "kernel_only_compensated", "operation_id" => record.fetch("id"),
                        "resource" => identity}
            end
            update_operation(record.fetch("id"), "resources" => resources, "state" => "unknown",
                                                 "effect_intent" => nil)
          rescue StandardError => error
            orphan_resources.each do |resource|
              identity = resource.fetch("identity")
              errors << {"component" => "orphan_compensation", "operation_id" => record.fetch("id"),
                         "resource" => identity,
                         "claimed" => claimed.any? { |entry| entry.fetch("identity") == identity },
                         "error" => "#{error.class}: #{error.message}"}
              audit << {"kind" => "kernel_only_compensation_failed", "operation_id" => record.fetch("id"),
                        "resource" => identity,
                        "claimed" => claimed.any? { |entry| entry.fetch("identity") == identity }}
            end
          end
        rescue StandardError => error
          errors << {"component" => "orphan_observation", "operation_id" => record.fetch("id"),
                     "error" => "#{error.class}: #{error.message}"}
        end
        [compensated.uniq.freeze, audit, errors]
      end

      def operation_from_value(value)
        operation = value.respond_to?(:to_h) ? value.to_h : value
        Rubernetes::Network::Operation.new(
          action: Support.fetch(operation, "action"), resource: Support.fetch(operation, "resource"),
          identity: Support.fetch(operation, "identity"),
          parameters: Support.immutable(Support.fetch(operation, "parameters", default: {}))
        ).freeze
      end

      def resource_from_proof(operation, proof, owner:, sandbox_id:, index:)
        hash = proof.respond_to?(:to_h) ? proof.to_h : proof
        identity = Support.fetch(hash, "identity", "stable_identity", default: nil)
        raise OwnershipError, "kernel observer returned an empty identity for #{operation.resource}" if identity.to_s.empty?

        proof_id = Support.fetch(hash, "id", default: nil)
        resource_id = index.zero? ? operation.resource : proof_id
        resource_id ||= "#{operation.resource}:#{index}"
        metadata = Support.fetch(hash, "metadata", default: operation.parameters)
        {"kind" => Support.fetch(hash, "kind", default: resource_id.split(":", 2).first),
         "id" => resource_id, "identity" => identity, "owner" => owner,
         "state" => "owned", "sandbox_id" => sandbox_id, "metadata" => Support.copy(metadata)}
      end

      def merge_resources(current, additions)
        (Array(current) + Array(additions)).to_h do |resource|
          [[resource.fetch("kind"), resource.fetch("id"), resource.fetch("identity")], resource]
        end.values.freeze
      end

      def build_result(operation_id, sandbox_id, leases, plan)
        lease_values = leases ? leases.map(&:to_h) : []
        ips = lease_values.map { |entry| entry.fetch("ip") }
        routes = plan.operations.select { |operation| operation.action == "route_add" }.map(&:parameters)
        {"sandbox_id" => sandbox_id, "operation_id" => operation_id, "ip" => (ips.length == 1 ? ips.first : ips),
         "ips" => ips, "leases" => lease_values, "routes" => routes, "mtu" => plan.mtu,
         "backend" => plan.backend, "interface" => Support.fetch(plan.metadata, "host_ifname", default: nil),
         "pod_interface" => Support.fetch(plan.metadata, "pod_ifname", default: nil), "state" => "committed"}.compact.freeze
      end

      def operation_result(operation)
        return Support.immutable(operation.fetch("result")) if operation.fetch("result")

        raise RecoveryRequired, "network operation #{operation.fetch("id")} has no durable result"
      end

      def plan_from_record(value)
        hash = value.respond_to?(:to_h) ? value.to_h : value
        operations = Array(Support.fetch(hash, "operations", default: [])).map do |entry|
          operation = entry.respond_to?(:to_h) ? entry.to_h : entry
          Rubernetes::Network::Operation.new(action: Support.fetch(operation, "action"), resource: Support.fetch(operation, "resource"),
                                             identity: Support.fetch(operation, "identity"), parameters: Support.immutable(Support.fetch(operation, "parameters", default: {})))
        end
        Plan.new(operations: operations.freeze, mtu: Support.fetch(hash, "mtu", default: nil),
                 backend: Support.fetch(hash, "backend", default: nil), revision: Support.fetch(hash, "revision", default: nil),
                 metadata: Support.immutable(Support.fetch(hash, "metadata", default: {}))).freeze
      end

      def plan_with_operations(plan, operations)
        Plan.new(operations: Array(operations).freeze, mtu: plan.mtu, backend: plan.backend,
                 revision: plan.revision, metadata: plan.metadata).freeze
      end

      def normalize_observed(source, operations: [])
        operation_values = Array(operations)
        values = if source.nil?
                   []
                 elsif source.respond_to?(:resources_for)
                   # Native host inventory contains bridges, routes and
                   # addresses owned by other agents and the node itself.
                   # Recovery may inspect only objects provably matching an
                   # active durable plan/effect intent. With no active plan,
                   # there is no ownership scope and therefore no kernel-only
                   # candidate to infer from the host dump.
                   operation_values.flat_map { |operation| Array(source.resources_for(operation)) }
                 elsif source.respond_to?(:call)
                   source.call
                 elsif source.respond_to?(:resources)
                   source.resources
                 elsif source.respond_to?(:list_resources)
                   source.list_resources
                 elsif source.respond_to?(:observe)
                   source.observe
                 else
                   raise ValidationError, "network observer must respond to call, resources, list_resources, or observe"
                 end
        if source.respond_to?(:resources) && !source.respond_to?(:resources_for)
          targets = operation_values.filter_map do |operation|
            parameters = operation.respond_to?(:parameters) ? operation.parameters : Support.fetch(operation, "parameters", default: {})
            Support.fetch(parameters, "namespace_fd", "namespace", default: nil)
          end.uniq
          targets.each do |target|
            values = Array(values) + Array(source.resources(namespace_fd: target))
          rescue ArgumentError
            # Observers without a scoped signature have already supplied
            # their complete inventory in the unscoped call above.
            next
          end
        end
        Array(values).each_with_object({}) do |value, result|
          hash = value.respond_to?(:to_h) ? value.to_h : value
          identity = Support.fetch(hash, "identity", "stable_identity", "id", default: nil)
          result[String(identity)] = Support.copy(hash) if identity
        end
      end

      def persist!(event, payload)
        previous = @durable_state
        durable = false
        begin
          # #replace already hands back a canonical copy of what it wrote;
          # copying the state again here was a second JSON round trip of the
          # whole node's network state, on every one of the ~20 persists a
          # Pod attach performs.
          written = @store&.replace(@state)
          durable = !@store.nil?
          @durable_state = written.is_a?(Hash) ? written : Support.copy(@state)
          # Keep working on the sealed records themselves (they are replaced,
          # never edited), so the next write re-encodes only what changes.
          @state = Support.working_copy(written) if written.is_a?(Hash)
          append_journal(event, payload)
        rescue StandardError
          @state = Support.copy(previous) unless durable
          raise
        end
      end

      def append_journal(event, payload)
        return unless @journal

        parameters = @journal.method(:append).parameters
        requires_operation = parameters.any? { |kind, name| %i[key keyreq].include?(kind) && name == :operation_id }
        if requires_operation
          @journal.append(operation_id: "network:interface", event: event, payload: payload)
        else
          @journal.append(event: event, payload: payload)
        end
      end
    end

    NetworkInterface = Interface
    Backend = Interface
    Manager = Interface
    DataPlane = Interface
  end
end
