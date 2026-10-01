# frozen_string_literal: true

require "digest"
require "ipaddr"

require_relative "errors"
require_relative "netlink"
require_relative "support"

module Rubernetes
  module Network
    # Immutable desired operation used by all link/route/FDB planners.
    Operation = Struct.new(:action, :resource, :identity, :parameters, keyword_init: true) do
      def to_h
        {"action" => action, "resource" => resource, "identity" => identity, "parameters" => parameters}
      end
    end

    DiffPlan = Struct.new(:additions, :removals, :revision, :metadata, keyword_init: true) do
      def empty?
        additions.empty? && removals.empty?
      end

      def to_h
        {"additions" => additions.map { |entry| entry.respond_to?(:to_h) ? entry.to_h : entry },
         "removals" => removals.map { |entry| entry.respond_to?(:to_h) ? entry.to_h : entry },
         "revision" => revision, "metadata" => metadata}
      end
    end

    Plan = Struct.new(:operations, :mtu, :backend, :revision, :metadata, keyword_init: true) do
      def to_h
        {"operations" => operations.map { |entry| entry.respond_to?(:to_h) ? entry.to_h : entry },
         "mtu" => mtu, "backend" => backend, "revision" => revision, "metadata" => metadata}
      end

      def empty?
        operations.empty?
      end
    end

    # The node bridge is shared infrastructure. Pods hold references to it,
    # but never receive a link ownership claim and therefore can never delete
    # it during per-Pod rollback. Explicit node shutdown is the only deletion
    # boundary for a bridge created by this manager.
    class BridgeManager
      def initialize(netlink: nil, adapter: nil)
        @netlink = netlink
        @adapter = adapter
        @mutex = Mutex.new
        @bridges = {}
      end

      def acquire(name:, mtu:, owner:)
        bridge = Support.string(name, "bridge name")
        owner_id = Support.identifier(owner, "bridge reference owner")
        effective_mtu = Support.integer(mtu, "bridge MTU", min: 576, max: 65_535)
        @mutex.synchronize do
          state = @bridges[bridge]
          if state
            raise OwnershipError, "bridge #{bridge} MTU changed while referenced" unless state.fetch("mtu") == effective_mtu

            state.fetch("owners") << owner_id
            return snapshot(state)
          end

          operation = Operation.new(
            action: "link_add", resource: "node-link:#{bridge}", identity: "node-bridge:#{bridge}",
            parameters: Support.immutable("name" => bridge, "kind" => "bridge", "mtu" => effective_mtu,
                                          "up" => true, "stp" => false, "node_owned" => true)
          ).freeze
          created = ensure_bridge(operation)
          state = {"name" => bridge, "mtu" => effective_mtu, "owners" => Set.new([owner_id]),
                   "created" => created, "operation" => operation}
          @bridges[bridge] = state
          snapshot(state)
        end
      end

      def release(name:, owner:)
        bridge = Support.string(name, "bridge name")
        owner_id = Support.identifier(owner, "bridge reference owner")
        @mutex.synchronize do
          state = @bridges[bridge]
          return false unless state

          state.fetch("owners").delete(owner_id)
          true
        end
      end

      def refcount(name)
        @mutex.synchronize { @bridges[String(name)]&.fetch("owners", Set.new)&.length || 0 }
      end

      def shutdown(name: nil)
        @mutex.synchronize do
          selected = name ? [String(name)] : @bridges.keys
          selected.each do |bridge|
            state = @bridges[bridge]
            next unless state
            raise OwnershipError, "bridge #{bridge} is still referenced" unless state.fetch("owners").empty?

            delete_bridge(state) if state.fetch("created")
            @bridges.delete(bridge)
          end
        end
        true
      end

      private

      def ensure_bridge(operation)
        if @adapter.respond_to?(:apply)
          result = @adapter.apply(operation, operation_id: "node-bridge:#{operation.parameters.fetch("name")}")
          raise EffectError, "node bridge adapter rejected link_add" if result == false

          return true
        end
        raise EffectError, "node bridge manager requires a netlink or adapter implementation" unless @netlink

        begin
          current = @netlink.link_state(name: operation.parameters.fetch("name"), index: nil,
                                        namespace: nil, namespace_fd: nil)
          unless current.fetch("kind", nil) == "bridge" &&
                 Integer(current.fetch("mtu")) == operation.parameters.fetch("mtu") && current.fetch("up") == true
            raise OwnershipError, "pre-existing bridge does not match the node bridge contract"
          end

          false
        rescue NetlinkError => error
          raise unless [Errno::ENOENT::Errno, Errno::ENODEV::Errno].include?(error.errno)

          @netlink.link_add(name: operation.parameters.fetch("name"), kind: "bridge",
                            mtu: operation.parameters.fetch("mtu"), up: true, stp: false,
                            operation: "node-bridge:#{operation.parameters.fetch("name")}")
          true
        end
      end

      def delete_bridge(state)
        operation = state.fetch("operation")
        if @adapter.respond_to?(:apply)
          inverse = Operation.new(action: "link_delete", resource: operation.resource, identity: operation.identity,
                                  parameters: Support.immutable("name" => state.fetch("name"))).freeze
          @adapter.apply(inverse, operation_id: "node-bridge:shutdown")
        else
          @netlink.link_delete(name: state.fetch("name"), operation: "node-bridge:shutdown")
        end
      end

      def snapshot(state)
        {"name" => state.fetch("name"), "mtu" => state.fetch("mtu"),
         "refcount" => state.fetch("owners").length, "created" => state.fetch("created")}.freeze
      end
    end

    # Pod link planner.  It only describes effects; Network::Interface owns
    # the transaction and decides when those effects may be applied.
    class Topology
      DEFAULT_BRIDGE = "rbr0"

      def initialize(netlink: nil, adapter: nil, bridge_name: DEFAULT_BRIDGE, mtu: 1500,
                     bridge_manager: nil, clock: -> { Time.now.utc }, **_options)
        @netlink = netlink || (adapter && Netlink.new(adapter: adapter))
        @adapter = adapter
        @bridge_name = Support.string(bridge_name, "bridge name")
        @mtu = Support.integer(mtu, "underlay MTU", min: 576, max: 65_535)
        @clock = clock
        @bridge_manager = bridge_manager || BridgeManager.new(netlink: @netlink, adapter: @adapter)
      end

      attr_reader :bridge_name, :mtu, :bridge_manager, :netlink

      def desired(sandbox, config = {}, leases: nil, overlay: nil, revision: nil, **options)
        sandbox_hash = sandbox.respond_to?(:to_h) ? sandbox.to_h : sandbox
        config_hash = config.respond_to?(:to_h) ? config.to_h : config
        id = Support.string(Support.fetch(sandbox_hash, "sandbox_id", "id", default: sandbox_hash.to_s), "sandbox_id")
        host_network = Support.host_network?(config_hash)
        if host_network
          return Plan.new(operations: [], mtu: @mtu, backend: "host", revision: revision,
                          metadata: {"sandbox_id" => id, "host_network" => true}).freeze
        end

        pod_ifname = valid_ifname(Support.fetch(config_hash, "pod_ifname", "container_ifname", default: "eth0"))
        host_ifname = valid_ifname(Support.fetch(config_hash, "host_ifname", default: default_host_ifname(id)))
        bridge = valid_ifname(Support.fetch(config_hash, "bridge", "bridge_name", default: @bridge_name))
        sandbox_netns = Support.fetch(sandbox_hash, "netns", "network_namespace", default: nil)
        sandbox_netns = sandbox_netns.to_h if sandbox_netns && sandbox_netns.respond_to?(:to_h)
        if sandbox_netns.is_a?(Hash)
          missing = Netlink::NamespaceLease::REQUIRED_FIELDS.select do |field|
            Support.fetch(sandbox_netns, field, default: nil).nil?
          end
          raise OwnershipError, "sandbox network namespace holder is missing #{missing.join(", ")}" unless missing.empty?
        elsif sandbox_netns
          raise OwnershipError, "sandbox network namespace requires a complete holder identity"
        end
        namespace_value = Support.fetch(config_hash, "netns", "network_namespace", default: nil)
        namespace_fd_value = Support.fetch(config_hash, "namespace_fd", "netns_fd", "network_namespace_fd", default: nil)
        raise OwnershipError, "sandbox network namespace requires a verified open FD lease" if sandbox_netns && namespace_fd_value.nil?

        namespace, namespace_target = normalize_namespace(namespace_value, namespace_fd_value)
        namespace_options = {"namespace" => namespace, "namespace_fd" => namespace_target}.compact
        ips = normalize_ips(leases || Support.fetch(config_hash, "ips", "ip", default: []))
        routes = Array(Support.fetch(config_hash, "routes", default: [])).map { |route| normalize_route(route) }
        effective_mtu = Support.integer(Support.fetch(config_hash, "mtu", default: @mtu), "MTU", min: 576, max: 65_535)
        operations = []
        pod_link_resource = "link:#{id}:#{pod_ifname}"
        # The peer's own resource id travels with the add so the plan can tell
        # "a link this plan creates" from "a pre-existing link to restore":
        # deriving it from the bare peer name breaks the moment the id is
        # scoped, and the plan then tries to read the state of an interface it
        # has not created yet.
        operations << op("link_add", "link:#{host_ifname}", "#{host_ifname}:#{id}", "name" => host_ifname, "kind" => "veth",
                                                                                    "peer" => pod_ifname, "peer_resource" => pod_link_resource,
                                                                                    "mtu" => effective_mtu, **namespace_options)
        operations << op("link_set", "link:#{host_ifname}", "#{host_ifname}:#{id}", "name" => host_ifname,
                                                                                    "master" => bridge, "up" => true)
        # The pod-side interface is "eth0" in every sandbox, so its ownership id
        # must carry the sandbox the way addresses and routes already do --
        # otherwise the second pod on the node claims a resource the first one
        # owns and its start fails.
        operations << op("link_set", pod_link_resource, "#{pod_ifname}:#{id}", "name" => pod_ifname,
                                                                               "up" => true, **namespace_options)
        ips.each_with_index do |entry, index|
          ip = entry.fetch("address")
          prefix = entry.fetch("prefix")
          operations << op("address_add", "address:#{id}:#{ip}/#{prefix}", "#{id}:#{ip}/#{prefix}", "address" => ip,
                                                                                                    "prefix" => prefix, "interface" => pod_ifname, "family" => entry.fetch("family"), **namespace_options,
                                                                                                    "index" => index)
        end
        if Support.bool(Support.fetch(config_hash, "default_route", default: true))
          ips.group_by { |entry| entry.fetch("family") }.each_key do |family|
            gateway = Support.fetch(config_hash, "gateway", default: nil)
            gateway = Support.fetch(gateway, family, family.to_sym, default: nil) if gateway.is_a?(Hash)
            gateway = Support.ip(gateway, name: "default route gateway").to_s if gateway
            metric = Support.integer(Support.fetch(config_hash, "route_metric", "default_route_metric", default: 100),
                                     "default route metric", min: 0, max: 0xffff_ffff)
            suffix = family == "ipv4" ? "" : ":#{family}"
            operations << op("route_add", "route:#{id}:default#{suffix}", "#{id}:default:#{family}",
                             "destination" => default_destination(family), "via" => gateway,
                             "interface" => pod_ifname, "family" => family, "table" => 254,
                             "metric" => metric,
                             "protocol" => Netlink::RTPROT_STATIC,
                             "scope" => gateway ? Netlink::RT_SCOPE_UNIVERSE : Netlink::RT_SCOPE_LINK,
                             "route_type" => Netlink::RTN_UNICAST, **namespace_options)
          end
        end
        routes.each do |route|
          operations << op("route_add", "route:#{id}:#{route.fetch("destination")}", "#{id}:#{route.fetch("destination")}",
                           route.merge("interface" => pod_ifname, **namespace_options))
        end
        overlay_plan = build_overlay_plan(overlay || Support.fetch(config_hash, "overlay", default: nil), config_hash, revision)
        selected_backend = overlay_backend(overlay)
        if overlay_plan
          overlay_plan = overlay_plan.to_h if overlay_plan.respond_to?(:to_h)
          selected_backend ||= Support.fetch(overlay_plan, "backend", default: nil)
          Overlay.validate_plan!(overlay_plan)
          operations.concat(Array(Support.fetch(overlay_plan, "operations", default: [])).map do |entry|
            next entry if entry.is_a?(Operation)

            value = entry.respond_to?(:to_h) ? entry.to_h : entry
            Operation.new(action: Support.fetch(value, "action"), resource: Support.fetch(value, "resource"),
                          identity: Support.fetch(value, "identity"),
                          parameters: Support.immutable(Support.fetch(value, "parameters", default: {}))).freeze
          end)
        end
        Plan.new(operations: operations.freeze, mtu: effective_mtu, backend: selected_backend, revision: revision,
                 metadata: {"sandbox_id" => id, "bridge" => bridge, "host_ifname" => host_ifname,
                            "pod_ifname" => pod_ifname, "namespace" => namespace,
                            "namespace_fd" => namespace_target,
                            "netns_handle" => sandbox_netns.is_a?(Hash) && Support.fetch(sandbox_netns, "handle", default: nil),
                            "netns_pid" => sandbox_netns.is_a?(Hash) && Support.fetch(sandbox_netns, "pid", default: nil),
                            "netns_pidfd" => sandbox_netns.is_a?(Hash) && Support.fetch(sandbox_netns, "pidfd", default: nil),
                            "netns_start_time" => sandbox_netns.is_a?(Hash) && Support.fetch(sandbox_netns, "start_time", default: nil),
                            "netns_inode" => sandbox_netns.is_a?(Hash) && Support.fetch(sandbox_netns, "inode", default: nil),
                            "options" => options}.compact).freeze
      end

      alias plan desired

      # Rebind a durable plan to a freshly validated namespace lease.  The
      # persisted descriptor number is only an audit marker; it must never be
      # reused after the batch that owned it closed.
      def bind_namespace(plan, lease)
        descriptor = lease.respond_to?(:fileno) ? lease.fileno : Support.integer(lease, "network namespace FD", min: 0)
        operations = Array(plan.operations).map do |operation|
          next operation unless operation.parameters.key?("namespace_fd") || operation.parameters.key?("namespace")

          params = operation.parameters.merge("namespace" => "fd:#{descriptor}", "namespace_fd" => descriptor)
          Operation.new(action: operation.action, resource: operation.resource, identity: operation.identity,
                        parameters: Support.immutable(params)).freeze
        end
        metadata = plan.metadata.merge("namespace" => "fd:#{descriptor}", "namespace_fd" => descriptor)
        Plan.new(operations: operations.freeze, mtu: plan.mtu, backend: plan.backend,
                 revision: plan.revision, metadata: Support.immutable(metadata)).freeze
      rescue IOError, SystemCallError => error
        raise OwnershipError, "network namespace lease is unavailable: #{error.message}"
      end

      def acquire_bridge(plan, owner:)
        return nil if Support.fetch(plan.metadata, "host_network", default: false)

        @bridge_manager.acquire(name: Support.fetch(plan.metadata, "bridge"), mtu: plan.mtu, owner: owner)
      end

      def release_bridge(plan, owner:)
        return false if Support.fetch(plan.metadata, "host_network", default: false)

        @bridge_manager.release(name: Support.fetch(plan.metadata, "bridge"), owner: owner)
      end

      # Capture rollback state before the first kernel effect.  Interface
      # persists this prepared plan while the operation is still applying, so
      # a crash between two link mutations does not lose the state required
      # to restore a pre-existing link.
      def prepare(plan)
        owned_links = owned_links_for(plan)
        operations = Array(plan.operations).map { |operation| prepare_operation(operation, owned_links: owned_links) }
        Plan.new(operations: operations.freeze, mtu: plan.mtu, backend: plan.backend,
                 revision: plan.revision, metadata: plan.metadata).freeze
      end

      def apply(plan, operation_id: nil, before_operation: nil, after_operation: nil)
        Overlay.validate_plan!(plan)
        plan = prepare(plan)
        applied = []
        effective_operations = []
        Array(plan.operations).each_with_index do |operation, index|
          before_operation&.call(operation, index)
          execute(operation, operation_id: operation_id)
          # Record the effect before invoking the durable ownership callback.
          # A claim failure must roll back the kernel mutation that produced
          # the identity, not only the operations preceding it.
          applied << operation
          effective_operations << operation
          after_operation&.call(operation, index)
        rescue StandardError => error
          raise EffectError.new("network topology operation #{operation.action} failed: #{error.message}",
                                operation: operation.to_h, cause_error: error, applied: applied.freeze)
        end
        Plan.new(operations: effective_operations.freeze, mtu: plan.mtu, backend: plan.backend,
                 revision: plan.revision, metadata: plan.metadata).freeze
      end

      def rollback(plan, operation_id: nil)
        errors = []
        owned_links = owned_links_for(plan)
        Array(plan.operations).reverse_each do |operation|
          inverse = inverse_operation(operation, owned_links: owned_links)
          next unless inverse

          begin
            execute(inverse, operation_id: operation_id)
          rescue StandardError => error
            next if already_absent?(error)

            errors << {"operation" => operation.to_h, "error" => "#{error.class}: #{error.message}"}
          end
        end
        raise EffectError, "network topology rollback failed: #{errors.inspect}" unless errors.empty?

        true
      end

      # Undoing something that is already undone is a completed rollback, not a
      # failure.  The CNI spec says as much of DEL -- "plugins should generally
      # complete a DEL action without error even if some resources are missing"
      # -- and the kernel has every reason to have removed these already: tearing
      # down a network namespace takes its veth, addresses and routes with it, so
      # the inverse operations arrive at a namespace where eth0 no longer exists.
      # Reporting that as a cleanup failure left the Pod in CleanupPending, the
      # node never issued the final delete, and the Pod stayed Terminating in the
      # API until the spec waiting for it to disappear timed out.
      ABSENT_ERRNOS = [Errno::ENODEV::Errno, Errno::ENOENT::Errno, Errno::ESRCH::Errno,
                       Errno::ENXIO::Errno, Errno::EADDRNOTAVAIL::Errno].freeze

      ABSENT_MESSAGES = /was not found|no such (?:device|file|process)|cannot assign requested address|does not exist/i

      def already_absent?(error)
        errno = error.respond_to?(:errno) ? error.errno : nil
        return true if errno && ABSENT_ERRNOS.include?(errno)

        ABSENT_MESSAGES.match?(error.message.to_s)
      end

      private

      def owned_links_for(plan)
        Array(plan.operations).filter_map do |operation|
          next unless operation.action == "link_add"

          peer_resource = operation.parameters["peer_resource"]
          peer_resource ||= "link:#{operation.parameters["peer"]}" if operation.parameters["peer"]
          [operation.resource, peer_resource]
        end.flatten.compact.to_set
      end

      def prepare_operation(operation, owned_links: Set.new)
        return operation unless operation.action == "link_set"
        return operation if operation.parameters.key?("previous_state")
        return operation if owned_links.include?(operation.resource)
        return operation if @adapter.respond_to?(:apply)
        return operation unless operation.parameters["name"] || operation.parameters["index"]
        return operation unless @netlink.respond_to?(:link_state)

        params = operation.parameters
        previous = @netlink.link_state(name: params["name"], index: params["index"],
                                       namespace: params["namespace"], namespace_fd: params["namespace_fd"])
        Operation.new(action: operation.action, resource: operation.resource, identity: operation.identity,
                      parameters: Support.immutable(params.merge("previous_state" => previous))).freeze
      rescue StandardError => error
        raise EffectError.new("cannot capture link rollback state: #{error.message}", operation: operation.to_h, cause_error: error)
      end

      def op(action, resource, identity, parameters)
        Operation.new(action: action, resource: resource, identity: identity,
                      parameters: Support.immutable(parameters)).freeze
      end

      def execute(operation, operation_id: nil)
        if @adapter.respond_to?(:apply)
          result = @adapter.apply(operation, operation_id: operation_id)
          raise EffectError, "network adapter rejected #{operation.action}" if result == false

          return result
        end
        if @adapter.respond_to?(:call) && !@netlink
          result = @adapter.call(operation, operation_id: operation_id)
          raise EffectError, "network adapter rejected #{operation.action}" if result == false

          return result
        end
        raise EffectError, "network topology requires a netlink or adapter implementation" unless @netlink

        params = operation.parameters
        case operation.action
        when "link_add"
          @netlink.link_add(name: params.fetch("name"), kind: params.fetch("kind"), mtu: params["mtu"],
                            master: params["master"], up: params.fetch("up", true), peer: params["peer"],
                            namespace: params["namespace"], namespace_fd: params["namespace_fd"], operation: operation_id,
                            **link_extra_parameters(params))
        when "link_delete"
          @netlink.link_delete(name: params["name"], index: params["index"], namespace: params["namespace"],
                               namespace_fd: params["namespace_fd"], operation: operation_id)
        when "link_set"
          @netlink.link_set(name: params["name"], index: params["index"], mtu: params["mtu"], up: params["up"],
                            master: params["master"], namespace: params["namespace"], namespace_fd: params["namespace_fd"],
                            operation: operation_id, clear_master: params["clear_master"])
        when "address_add"
          @netlink.address_add(address: params.fetch("address"), prefix: params["prefix"], name: params["interface"],
                               index: params["link_index"], operation: operation_id, namespace: params["namespace"],
                               namespace_fd: params["namespace_fd"])
        when "address_delete"
          @netlink.address_delete(address: params.fetch("address"), prefix: params["prefix"], name: params["interface"],
                                  index: params["link_index"], operation: operation_id, namespace: params["namespace"],
                                  namespace_fd: params["namespace_fd"])
        when "route_add"
          @netlink.route_add(destination: params.fetch("destination"), via: params["via"], dev: params["interface"] || params["dev"],
                             table: params.fetch("table", 254), metric: params["metric"], family: params["family"],
                             protocol: params["protocol"], scope: params["scope"], route_type: params["route_type"],
                             operation: operation_id, namespace: params["namespace"], namespace_fd: params["namespace_fd"])
        when "route_delete"
          @netlink.route_delete(destination: params.fetch("destination"), via: params["via"], dev: params["interface"] || params["dev"],
                                table: params.fetch("table", 254), metric: params["metric"], family: params["family"],
                                protocol: params["protocol"], scope: params["scope"], route_type: params["route_type"],
                                operation: operation_id, namespace: params["namespace"], namespace_fd: params["namespace_fd"])
        when "fdb_add"
          @netlink.fdb_add(mac: params.fetch("mac"), destination: params.fetch("destination"), dev: params.fetch("dev"),
                           namespace: params["namespace"], namespace_fd: params["namespace_fd"], operation: operation_id)
        when "fdb_delete"
          @netlink.fdb_delete(mac: params.fetch("mac"), destination: params.fetch("destination"), dev: params.fetch("dev"),
                              namespace: params["namespace"], namespace_fd: params["namespace_fd"], operation: operation_id)
        else
          raise ValidationError, "unsupported topology operation #{operation.action.inspect}"
        end
      end

      def inverse_operation(operation, owned_links: Set.new)
        inverse_action = {
          "link_add" => "link_delete", "link_delete" => "link_add",
          "address_add" => "address_delete", "address_delete" => "address_add",
          "route_add" => "route_delete", "route_delete" => "route_add",
          "fdb_add" => "fdb_delete", "fdb_delete" => "fdb_add"
        }.fetch(operation.action, "link_set")
        if operation.action == "link_set"
          return nil if owned_links.include?(operation.resource)

          previous = Support.fetch(operation.parameters, "previous_state", default: nil)
          raise EffectError, "link_set rollback requires a durable previous state for #{operation.resource}" unless previous

          return Operation.new(action: "link_set", resource: operation.resource, identity: operation.identity,
                               parameters: Support.immutable(
                                 "name" => Support.fetch(previous, "name", default: operation.parameters["name"]),
                                 "index" => Support.fetch(previous, "index", default: operation.parameters["index"]),
                                 "mtu" => Support.fetch(previous, "mtu", default: operation.parameters["mtu"]),
                                 "up" => Support.fetch(previous, "up", default: operation.parameters["up"]),
                                 "master" => Support.fetch(previous, "master", default: operation.parameters["master"]),
                                 "clear_master" => previous["master"].nil? && !operation.parameters["master"].nil?,
                                 "namespace" => operation.parameters["namespace"],
                                 "namespace_fd" => operation.parameters["namespace_fd"]
                               )).freeze
        end

        inverse_parameters = operation.parameters
        if operation.action == "link_add" && operation.parameters["kind"] == "veth" && operation.parameters["peer"]
          # The veth operation's namespace FD belongs to the nested peer. The
          # host-side link itself remains in the caller namespace, so deleting
          # the owned pair must not enter the peer namespace to resolve the
          # host ifindex.
          inverse_parameters = operation.parameters.reject { |key, _value| %w[namespace namespace_fd].include?(key) }
        end
        Operation.new(action: inverse_action, resource: operation.resource, identity: operation.identity,
                      parameters: Support.immutable(inverse_parameters))
      end

      def normalize_ips(values)
        if values.is_a?(Hash)
          lease_values = Support.fetch(values, "leases", default: nil)
          return normalize_ips(lease_values) if lease_values

          value = Support.fetch(values, "ip", "address", default: nil)
          return normalize_ips([value]) if value
        end
        Array(values).flat_map do |entry|
          if entry.respond_to?(:ip) && entry.respond_to?(:family)
            subnet = entry.respond_to?(:subnet) ? entry.subnet : nil
            prefix = subnet && String(subnet).split("/", 2).fetch(1, nil)
            [{"address" => entry.ip, "prefix" => prefix, "family" => entry.family}]
          elsif entry.is_a?(Hash)
            address = Support.fetch(entry, "ip", "address")
            prefix = Support.fetch(entry, "prefix", default: nil)
            subnet = Support.fetch(entry, "subnet", default: nil)
            prefix ||= String(subnet).split("/", 2).fetch(1, nil) if subnet
            [{"address" => address, "prefix" => prefix,
              "family" => Support.fetch(entry, "family", default: nil)}]
          elsif entry.is_a?(Array)
            normalize_ips(entry)
          else
            address, prefix = String(entry).split("/", 2)
            [{"address" => address, "prefix" => prefix, "family" => nil}]
          end
        end.map do |entry|
          ip = Support.ip(entry.fetch("address"), name: "pod IP")
          prefix = entry["prefix"]
          raise ValidationError, "pod IP prefix is required" if prefix.nil?

          max = ip.ipv4? ? 32 : 128
          prefix = Support.integer(prefix, "pod IP prefix", min: 0, max: max)
          family = entry["family"] ? Support.family(entry["family"]) : Support.address_family(ip.to_s)
          raise ValidationError, "pod IP family does not match address" if family != Support.address_family(ip.to_s)

          {"address" => ip.to_s, "prefix" => prefix, "family" => family}.freeze
        end.uniq.freeze
      end

      def normalize_route(route)
        hash = route.respond_to?(:to_h) ? route.to_h : route
        destination = Support.fetch(hash, "destination", "cidr")
        network, prefix = Support.cidr(destination, name: "route destination")
        via = Support.fetch(hash, "via", "gateway", default: nil)
        via = Support.ip(via, name: "route gateway").to_s if via
        {"destination" => "#{network}/#{prefix}", "via" => via,
         "metric" => Support.integer(Support.fetch(hash, "metric", default: 100), "route metric", min: 0, max: 0xffff_ffff),
         "table" => Support.integer(Support.fetch(hash, "table", default: 254), "route table", min: 0, max: 0xffff_ffff),
         "protocol" => Support.integer(Support.fetch(hash, "protocol", default: Netlink::RTPROT_STATIC), "route protocol", min: 0, max: 255),
         "scope" => Support.integer(Support.fetch(hash, "scope", default: via ? Netlink::RT_SCOPE_UNIVERSE : Netlink::RT_SCOPE_LINK), "route scope", min: 0, max: 255),
         "route_type" => Support.integer(Support.fetch(hash, "route_type", "type", default: Netlink::RTN_UNICAST), "route type", min: 0, max: 255)}.compact
      end

      def default_destination(family)
        Support.family(family) == "ipv6" ? "::/0" : "0.0.0.0/0"
      end

      # IFNAMSIZ leaves 14 usable characters, and sandbox ids share a long
      # constant prefix -- truncating the id to its first characters yields
      # almost no entropy and collides between pods, which the ownership ledger
      # then reports as someone else already owning the link.  A digest of the
      # whole id keeps the name short, stable for a given sandbox, and distinct.
      def default_host_ifname(id)
        "veth#{Digest::SHA256.hexdigest(String(id))[0, 10]}"
      end

      def valid_ifname(value)
        name = Support.string(value, "interface name")
        raise ValidationError, "interface name exceeds IFNAMSIZ-1" if name.bytesize >= Netlink::IFNAMSIZ

        name
      end

      def overlay_backend(overlay)
        return nil unless overlay
        return Support.fetch(overlay, "backend", default: nil) if overlay.is_a?(Hash)
        return overlay.backend if overlay.respond_to?(:backend)

        nil
      end

      def normalize_namespace(value, explicit_fd)
        target = explicit_fd || value
        return [nil, nil] if target.nil?
        raise ValidationError, "network namespace paths cannot be reopened; pass a verified open FD lease" if target.is_a?(String) || value.is_a?(String)

        target = target.fileno if target.respond_to?(:fileno)
        descriptor = Support.integer(target, "network namespace FD", min: 0)
        ["fd:#{descriptor}", descriptor]
      rescue IOError, SystemCallError => error
        raise ValidationError, "network namespace descriptor is unavailable: #{error.message}"
      end

      def build_overlay_plan(source, config_hash, revision)
        return nil if source.nil?

        value = source.respond_to?(:to_h) ? source.to_h : source
        return value if value.is_a?(Plan) || (value.is_a?(Hash) && Support.fetch(value, "operations", default: nil))
        raise ValidationError, "overlay configuration must be an object or Overlay plan" unless value.is_a?(Hash)

        options = value.dup
        nodes = Support.fetch(options, "nodes", default: Support.fetch(config_hash, "overlay_nodes", "nodes", default: []))
        local_node = Support.fetch(options, "local_node", default: Support.fetch(config_hash, "node", "node_name", default: nil))
        device = Support.fetch(options, "device", "dev", default: "vxlan0")
        overlay = Overlay.new(
          backend: Support.fetch(options, "backend", default: :auto),
          vni: Support.fetch(options, "vni", default: Overlay::DEFAULT_VNI),
          dstport: Support.fetch(options, "dstport", "destination_port", "port", default: Overlay::DEFAULT_DSTPORT),
          underlay_mtu: Support.fetch(options, "underlay_mtu", default: @mtu),
          family: Support.fetch(options, "family", default: nil),
          netlink: @netlink,
          adapter: @adapter
        )
        options.delete("backend")
        options.delete("vni")
        options.delete("dstport")
        options.delete("destination_port")
        options.delete("port")
        options.delete("underlay_mtu")
        options.delete("family")
        options.delete("nodes")
        options.delete("local_node")
        overlay.desired(nodes: nodes, local_node: local_node, revision: revision, device: device, **options)
      end

      def link_extra_parameters(params)
        params.each_with_object({}) do |(key, value), result|
          next if %w[name kind mtu master up peer namespace namespace_fd index].include?(key)

          result[key.to_sym] = value
        end
      end
    end

    # Overlay planner with deterministic host-gw/VXLAN selection and route/FDB
    # set diffs.  Removing a node is intentionally a separate phase so the
    # caller can first evict its endpoints and conntrack entries.
    class Overlay
      DEFAULT_VNI = 4096
      DEFAULT_DSTPORT = 4789
      IPV4_OVERHEAD = 50
      IPV6_OVERHEAD = 70

      Node = Struct.new(:name, :pod_cidr, :vtep, :mac, :l2_reachable, :next_hop_reachable, :revision, keyword_init: true) do
        def to_h
          {"name" => name, "pod_cidr" => pod_cidr, "vtep" => vtep, "mac" => mac,
           "l2_reachable" => l2_reachable, "next_hop_reachable" => next_hop_reachable, "revision" => revision}
        end
      end

      def initialize(backend: :auto, vni: DEFAULT_VNI, dstport: DEFAULT_DSTPORT, port: nil,
                     underlay_mtu: 1500, family: nil, netlink: nil, adapter: nil, **_options)
        @configured_backend = backend.to_s.downcase
        raise ValidationError, "overlay backend must be auto, host-gw, or vxlan" unless %w[auto host-gw vxlan].include?(@configured_backend)

        @vni = Support.integer(vni, "VXLAN VNI", min: 1, max: 16_777_215)
        @dstport = Support.integer(port || dstport, "VXLAN UDP port", min: 1, max: 65_535)
        @underlay_mtu = Support.integer(underlay_mtu, "underlay MTU", min: 576, max: 65_535)
        @family = family && Support.family(family)
        @netlink = netlink
        @adapter = adapter
      end

      attr_reader :vni, :dstport, :underlay_mtu

      # A completed overlay plan may arrive from durable state or an injected
      # adapter instead of this planner. Validate those plans at every effect
      # boundary so a hand-built operation cannot omit the underlay or remote
      # gateway fields enforced by #desired.
      def self.validate_plan!(plan)
        value = plan.respond_to?(:to_h) ? plan.to_h : plan
        return true unless value.is_a?(Hash)

        # A host-network Pod has no overlay at all: its plan carries no
        # operations and the backend names the host's own stack.  Validating
        # it as an overlay rejected every hostNetwork Pod outright.
        return true if Support.fetch(Support.fetch(value, "metadata", default: {}) || {},
                                     "host_network", default: false) == true

        backend = Support.fetch(value, "backend", default: nil)&.to_s&.downcase
        raise ValidationError, "unsupported overlay backend #{backend.inspect}" if backend && !%w[host-gw vxlan host].include?(backend)

        operations = Array(Support.fetch(value, "operations", default: []))
        overlay_operations = operations.filter_map do |entry|
          operation = entry.respond_to?(:to_h) ? entry.to_h : entry
          next unless operation.is_a?(Hash)

          action = Support.fetch(operation, "action", default: nil).to_s
          parameters = Support.fetch(operation, "parameters", default: {})
          parameters = parameters.to_h if parameters.respond_to?(:to_h)
          next unless parameters.is_a?(Hash)

          kind = Support.fetch(parameters, "kind", default: nil).to_s
          route = %w[route_add route_delete].include?(action) &&
                  !parameters.key?("interface") && !parameters.key?(:interface)
          next unless %w[fdb_add fdb_delete].include?(action) ||
                      (%w[link_add link_delete].include?(action) && kind == "vxlan") || route

          [action, parameters]
        end
        return true if overlay_operations.empty?

        inferred_backend = backend || if overlay_operations.any? do |action, parameters|
          action.start_with?("fdb_") || Support.fetch(parameters, "kind", default: nil).to_s == "vxlan"
        end
                                        "vxlan"
                                      elsif overlay_operations.any? do |_action, parameters|
                                        Support.fetch(parameters, "via", "gateway", default: nil)
                                      end
                                        "host-gw"
                                      else
                                        "vxlan"
                                      end

        case inferred_backend
        when "vxlan"
          overlay_operations.each do |action, parameters|
            case action
            when "link_add"
              underlay = Support.fetch(parameters, "dev", "underlay", "underlay_dev", default: nil)
              raise ValidationError, "VXLAN overlay requires an underlay device" if underlay.to_s.empty?
            when "route_add", "route_delete"
              dev = Support.fetch(parameters, "dev", default: nil)
              raise ValidationError, "VXLAN overlay routes require a device" if dev.to_s.empty?
            when "fdb_add", "fdb_delete"
              %w[mac destination dev].each do |field|
                raise ValidationError, "VXLAN FDB requires #{field}" if Support.fetch(parameters, field, default: nil).to_s.empty?
              end
              mac = Support.fetch(parameters, "mac", default: nil).to_s
              raise ValidationError, "VXLAN FDB MAC is invalid" unless mac.match?(/\A[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\z/)

              Support.ip(Support.fetch(parameters, "destination"), name: "VXLAN FDB destination")
            end
          end
        when "host-gw"
          overlay_operations.each do |action, parameters|
            if action.start_with?("fdb_") || Support.fetch(parameters, "kind", default: nil).to_s == "vxlan"
              raise ValidationError, "host-gw overlay does not support VXLAN link or FDB operations"
            end
            next unless %w[route_add route_delete].include?(action)

            %w[via dev].each do |field|
              raise ValidationError, "host-gw routes require #{field}" if Support.fetch(parameters, field, default: nil).to_s.empty?
            end
            Support.ip(Support.fetch(parameters, "via"), name: "host-gw gateway")
          end
        else
          raise ValidationError, "unsupported overlay backend #{inferred_backend.inspect}"
        end
        true
      end

      def backend(nodes: [], local_node: nil, **_options)
        return @configured_backend unless @configured_backend == "auto"

        entries = Array(nodes).map { |node| normalize_node(node) }
          .reject { |node| local_node && node.name.to_s == local_node.to_s }
        reachable = entries.all? do |node|
          node.l2_reachable && node.next_hop_reachable
        end
        reachable && !entries.empty? ? "host-gw" : "vxlan"
      end

      def mtu(family: @family, **_options)
        if family
          @underlay_mtu - (Support.family(family) == "ipv4" ? IPV4_OVERHEAD : IPV6_OVERHEAD)
        else
          {"ipv4" => @underlay_mtu - IPV4_OVERHEAD, "ipv6" => @underlay_mtu - IPV6_OVERHEAD}
        end
      end

      alias effective_mtu mtu

      def desired(nodes:, local_node: nil, revision: nil, backend: nil, underlay_mtu: @underlay_mtu, **options)
        entries = Array(nodes).map { |node| normalize_node(node) }
        selected = backend&.to_s&.downcase || self.backend(nodes: entries, local_node: local_node)
        raise ValidationError, "unsupported overlay backend #{selected.inspect}" unless %w[host-gw vxlan].include?(selected)

        underlay_mtu = Support.integer(underlay_mtu, "underlay MTU", min: 576, max: 65_535)
        raise ValidationError, "underlay MTU is too small for VXLAN IPv6 overhead" if selected == "vxlan" && underlay_mtu <= IPV6_OVERHEAD

        effective_mtu = if selected == "vxlan"
                          {"ipv4" => underlay_mtu - IPV4_OVERHEAD,
                           "ipv6" => underlay_mtu - IPV6_OVERHEAD}
                        else
                          {"ipv4" => underlay_mtu, "ipv6" => underlay_mtu}
                        end
        operations = []
        device = valid_ifname(Support.fetch(options, "device", "dev", default: "vxlan0"))
        namespace = Support.fetch(options, "namespace", "netns", "network_namespace", default: nil)
        namespace_fd = Support.fetch(options, "namespace_fd", "netns_fd", "network_namespace_fd", default: nil)
        namespace_options = {"namespace" => namespace, "namespace_fd" => namespace_fd}.compact
        remote_entries = entries.reject { |node| local_node && node.name.to_s == local_node.to_s }
        underlay_dev = Support.fetch(options, "dev", "underlay", "underlay_dev", default: nil)
        validate_remote_nodes!(selected, remote_entries, underlay_dev: underlay_dev)
        # A node with no remote peers does not need a VXLAN device. Creating a
        # link without an underlay in that case would leave an inert but
        # kernel-visible overlay object that cannot be owned or routed safely.
        if selected == "vxlan" && !remote_entries.empty?
          vxlan_parameters = {
            "name" => device,
            "kind" => "vxlan",
            "vni" => @vni,
            "dstport" => @dstport,
            "learning" => Support.fetch(options, "learning", default: false),
            "mtu" => effective_mtu.values.min,
            "mtu_by_family" => effective_mtu
          }.merge(namespace_options)
          %w[dev underlay underlay_dev local local_vtep vtep vtep_ip group multicast_group ttl tos proxy
             udp_csum udp_zero_csum6_tx udp_zero_csum6_rx collect_metadata].each do |key|
            value = Support.fetch(options, key, default: nil)
            vxlan_parameters[key] = value unless value.nil?
          end
          operations << Operation.new(action: "link_add", resource: "link:#{device}", identity: "vxlan:#{@vni}:#{device}",
                                      parameters: Support.immutable(vxlan_parameters)).freeze
        end
        remote_entries.each do |node|
          route_parameters = {"destination" => node.pod_cidr,
                              "via" => selected == "host-gw" ? node.vtep : nil,
                              "dev" => selected == "vxlan" ? device : nil,
                              "family" => Support.address_family(node.pod_cidr), "table" => 254,
                              "metric" => 100,
                              "protocol" => Netlink::RTPROT_STATIC,
                              "scope" => selected == "host-gw" ? Netlink::RT_SCOPE_UNIVERSE : Netlink::RT_SCOPE_LINK,
                              "route_type" => Netlink::RTN_UNICAST}.merge(namespace_options).compact
          route_parameters["dev"] = underlay_dev if selected == "host-gw"
          operations << Operation.new(action: "route_add", resource: "route:#{node.name}:#{node.pod_cidr}",
                                      identity: "#{selected}:#{node.name}:#{node.revision || revision}",
                                      parameters: Support.immutable(route_parameters)).freeze
          next unless selected == "vxlan"

          operations << Operation.new(action: "fdb_add", resource: "fdb:#{node.name}:#{node.mac}",
                                      identity: "#{node.mac}:#{node.vtep}:#{node.revision || revision}",
                                      parameters: Support.immutable({"mac" => node.mac, "destination" => node.vtep,
                                                                     "dev" => device}.merge(namespace_options))).freeze
        end
        Plan.new(operations: operations.freeze, mtu: effective_mtu, backend: selected, revision: revision,
                 metadata: {"vni" => @vni, "dstport" => @dstport, "device" => device,
                            "node_revisions" => entries.to_h { |entry| [entry.name, entry.revision] }}).freeze
      end

      alias plan desired

      def route_diff(current:, desired:, revision: nil)
        diff_set(current, desired, revision: revision, metadata: {"kind" => "route"})
      end

      def fdb_diff(current:, desired:, revision: nil)
        diff_set(current, desired, revision: revision, metadata: {"kind" => "fdb"})
      end

      def diff(current:, desired:, revision: nil)
        {
          "routes" => route_diff(current: Support.fetch(current, "routes", default: []),
                                 desired: Support.fetch(desired, "routes", default: []), revision: revision),
          "fdb" => fdb_diff(current: Support.fetch(current, "fdb", default: []), desired: Support.fetch(desired, "fdb", default: []),
                            revision: revision)
        }
      end

      def apply(plan, operation_id: nil, endpoint_remover: nil, conntrack_remover: nil, removing_nodes: [])
        self.class.validate_plan!(plan)
        removed_nodes = Array(removing_nodes).map(&:to_s)
        unless removed_nodes.empty?
          endpoint_remover&.call(removed_nodes)
          conntrack_remover&.call(removed_nodes)
        end
        executor = @adapter || @netlink
        return plan if executor.nil?

        Array(plan.operations).each do |operation|
          if executor.respond_to?(:apply)
            result = executor.apply(operation, operation_id: operation_id)
          elsif executor.respond_to?(:call)
            result = executor.call(operation, operation_id: operation_id)
          elsif executor.respond_to?(:link_add)
            result = execute_netlink(operation, operation_id: operation_id)
          else
            raise EffectError, "overlay adapter must respond to apply or call"
          end
          raise EffectError, "overlay adapter rejected #{operation.action}" if result == false
        end
        plan
      end

      private

      def valid_ifname(value)
        name = Support.string(value, "interface name")
        raise ValidationError, "interface name exceeds Netlink::IFNAMSIZ-1" if name.bytesize >= Netlink::IFNAMSIZ

        name
      end

      def normalize_node(node)
        hash = node.respond_to?(:to_h) ? node.to_h : node
        vtep = Support.fetch(hash, "vtep", "vtep_ip", "next_hop", default: nil)
        vtep = Support.ip(vtep, name: "VTEP IP").to_s if vtep
        mac = Support.fetch(hash, "mac", "vtep_mac", default: nil)
        raise ValidationError, "VTEP MAC is invalid" if mac && !Support.string(mac, "VTEP MAC").match?(/\A[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\z/)

        Node.new(name: Support.string(Support.fetch(hash, "name", "node"), "node name"),
                 pod_cidr: normalize_cidr(Support.fetch(hash, "pod_cidr", "podCIDR", "cidr")),
                 vtep: vtep,
                 mac: mac&.downcase,
                 l2_reachable: Support.bool(Support.fetch(hash, "l2_reachable", default: false)),
                 next_hop_reachable: Support.bool(Support.fetch(hash, "next_hop_reachable", default: false)),
                 revision: Support.fetch(hash, "revision", default: nil)).freeze
      end

      def validate_remote_nodes!(backend, entries, underlay_dev:)
        return if entries.empty?

        if backend == "host-gw"
          raise ValidationError, "host-gw overlay requires an underlay device" if underlay_dev.to_s.empty?

          missing = entries.select { |node| node.vtep.to_s.empty? }.map(&:name)
          raise ValidationError, "host-gw overlay requires a gateway for remote nodes: #{missing.join(", ")}" unless missing.empty?

          return
        end

        raise ValidationError, "VXLAN overlay requires an underlay device" if underlay_dev.to_s.empty?

        missing_vtep = entries.select { |node| node.vtep.to_s.empty? }.map(&:name)
        missing_mac = entries.select { |node| node.mac.to_s.empty? }.map(&:name)
        raise ValidationError, "VXLAN overlay requires a VTEP for remote nodes: #{missing_vtep.join(", ")}" unless missing_vtep.empty?
        return if missing_mac.empty?

        raise ValidationError, "VXLAN overlay requires a MAC for remote nodes: #{missing_mac.join(", ")}"
      end

      def normalize_cidr(value)
        network, prefix = Support.cidr(value, name: "pod CIDR")
        "#{network}/#{prefix}"
      end

      def diff_set(current, desired, revision:, metadata:)
        current_values = Array(current).map { |entry| canonical_entry(entry) }
        desired_values = Array(desired).map { |entry| canonical_entry(entry) }
        DiffPlan.new(additions: (desired_values - current_values).sort_by(&:to_s).freeze,
                     removals: (current_values - desired_values).sort_by(&:to_s).freeze,
                     revision: revision, metadata: Support.immutable(metadata)).freeze
      end

      def canonical_entry(value)
        Support.canonical(value.respond_to?(:to_h) ? value.to_h : value)
      end

      def execute_netlink(operation, operation_id: nil)
        params = operation.parameters
        namespace = params["namespace"]
        namespace_fd = params["namespace_fd"]
        case operation.action
        when "link_add"
          @netlink.link_add(name: params.fetch("name"), kind: params.fetch("kind"), mtu: params["mtu"],
                            up: params.fetch("up", true), peer: params["peer"], master: params["master"],
                            namespace: namespace, namespace_fd: namespace_fd, operation: operation_id,
                            **params.reject { |key, _| %w[name kind mtu up peer master namespace namespace_fd].include?(key) }
                              .transform_keys(&:to_sym))
        when "link_delete"
          @netlink.link_delete(name: params["name"], index: params["index"], namespace: namespace,
                               namespace_fd: namespace_fd, operation: operation_id)
        when "link_set"
          @netlink.link_set(name: params["name"], index: params["index"], mtu: params["mtu"], up: params["up"],
                            master: params["master"], namespace: namespace, namespace_fd: namespace_fd,
                            operation: operation_id, clear_master: params["clear_master"])
        when "route_add"
          @netlink.route_add(destination: params.fetch("destination"), via: params["via"], dev: params["dev"],
                             table: params.fetch("table", 254), metric: params["metric"], family: params["family"],
                             protocol: params["protocol"], scope: params["scope"], route_type: params["route_type"],
                             namespace: namespace, namespace_fd: namespace_fd, operation: operation_id)
        when "route_delete"
          @netlink.route_delete(destination: params.fetch("destination"), via: params["via"], dev: params["dev"],
                                table: params.fetch("table", 254), metric: params["metric"], family: params["family"],
                                protocol: params["protocol"], scope: params["scope"], route_type: params["route_type"],
                                namespace: namespace, namespace_fd: namespace_fd, operation: operation_id)
        when "fdb_add"
          @netlink.fdb_add(mac: params.fetch("mac"), destination: params.fetch("destination"),
                           dev: params.fetch("dev"), namespace: namespace, namespace_fd: namespace_fd,
                           operation: operation_id)
        when "fdb_delete"
          @netlink.fdb_delete(mac: params.fetch("mac"), destination: params.fetch("destination"),
                              dev: params.fetch("dev"), namespace: namespace, namespace_fd: namespace_fd,
                              operation: operation_id)
        else
          raise ValidationError, "unsupported overlay operation #{operation.action.inspect}"
        end
      end
    end

    OverlayNetwork = Overlay
    NetworkTopology = Topology
    BridgePlan = Topology
    VethPlan = Topology
    RoutePlanner = Overlay
    FDBPlanner = Overlay
  end
end
