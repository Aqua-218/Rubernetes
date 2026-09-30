# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/network_test_fakes"
require "fileutils"
require "tmpdir"
require "rubernetes/network"

class M4NetworkTest < Minitest::Test
  include NetworkTestFakes

  def test_dual_stack_reservation_commit_release_is_durable_and_idempotent
    Dir.mktmpdir do |directory|
      path = File.join(directory, "ipam.json")
      ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv6_cidr: "fd00::/48",
                                           ipv4_node_prefix: 24, ipv6_node_prefix: 64, state_path: path)
      leases = ipam.reserve(node: "node-a", pod_uid: "pod-a", sandbox_id: "sandbox-a", dual_stack: true)

      assert_equal %w[ipv4 ipv6], leases.map(&:family)
      committed = ipam.commit(leases)

      assert committed.all?(&:committed?)
      assert_equal committed.to_h, ipam.reserve(node: "node-a", pod_uid: "pod-a", sandbox_id: "sandbox-a", dual_stack: true).to_h
      assert_raises(Rubernetes::Network::LeaseStateError) { ipam.release(committed) }
      ipam.release(committed, stopped: true)

      reopened = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv6_cidr: "fd00::/48",
                                               ipv4_node_prefix: 24, ipv6_node_prefix: 64, state_path: path)

      assert_equal "released", reopened.lease(operation_id: "network-sandbox-a").state
    end
  end

  def test_ipam_recovery_binds_namespace_link_prefix_and_complete_route_identity
    ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv4_node_prefix: 24)
    leases = ipam.reserve(node: "node-a", pod_uid: "pod-a", sandbox_id: "sandbox-a",
                          operation_id: "add:sandbox-a", families: ["ipv4"])
    ip = leases.first.ip
    address = {
      "kind" => "address", "id" => "address:eth0:#{ip}/24",
      "identity" => "address:netns=1234:ifindex=7:address=#{ip}/24", "owner" => "kernel-observer",
      "metadata" => {"address" => ip, "family" => "ipv4", "prefix" => 24,
                     "netns_inode" => 1234, "ifindex" => 7, "ifname" => "eth0"}
    }
    route = {
      "kind" => "route", "id" => "route:eth0:0.0.0.0/0",
      "identity" => "route:netns=1234:ifindex=7:ifname=eth0:destination=0.0.0.0/0:" \
                    "gateway=-:table=254:metric=-:protocol=4:scope=253:type=1",
      "owner" => "kernel-observer",
      "metadata" => {"destination" => "0.0.0.0/0", "gateway" => nil, "table" => 254,
                     "metric" => nil, "protocol" => 4, "scope" => 253, "route_type" => 1,
                     "family" => "ipv4", "netns_inode" => 1234, "ifindex" => 7, "ifname" => "eth0"}
    }

    ipam.bind_kernel_identity(operation_id: "add:sandbox-a", resources: [address, route], require_complete: true)
    ipam.commit(leases, operation_id: "add:sandbox-a")

    assert_empty ipam.recover(observer: -> { [address, route] }).identity_mismatch
    mismatch = ipam.recover(observer: -> { [address] }).identity_mismatch

    assert_equal 1, mismatch.length
    assert_equal "ipv4:#{ip}", mismatch.first.fetch("resource")
  end

  def test_network_add_delete_is_transactional_and_owned
    adapter = RecordingAdapter.new
    ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv4_node_prefix: 24)
    network = Rubernetes::Network::Interface.new(ipam: ipam, adapter: adapter)
    result = network.add({"sandbox_id" => "sandbox-a", "pod_uid" => "pod-a"}, "node" => "node-a", "families" => ["ipv4"])
    # .1 is the node bridge gateway every Pod routes through; Pod addresses
    # start at .2.
    assert_equal "10.244.0.2", result.fetch("ip")
    assert network.check("sandbox-a")
    assert_raises(Rubernetes::Network::OwnershipError) { network.delete("sandbox-a") }
    assert_equal "removed", network.delete("sandbox-a", stopped: true).fetch("state")
    assert_equal "released", ipam.lease(operation_id: "add:sandbox-a").state
  end

  def test_topology_requires_an_explicit_address_prefix
    topology = Rubernetes::Network::Topology.new(adapter: RecordingAdapter.new)

    error = assert_raises(Rubernetes::Network::ValidationError) do
      topology.desired({"sandbox_id" => "sandbox-prefix"}, {"ips" => ["10.244.0.9"]})
    end

    assert_match(/prefix/, error.message)
    plan = topology.desired({"sandbox_id" => "sandbox-prefix"}, {"ips" => ["10.244.0.9/24"]})
    address = plan.operations.find { |operation| operation.action == "address_add" }

    assert_equal "10.244.0.9", address.parameters.fetch("address")
    assert_equal 24, address.parameters.fetch("prefix")
  end

  def test_runtime_netns_context_is_inherited_by_every_pod_namespace_operation
    topology = Rubernetes::Network::Topology.new(adapter: RecordingAdapter.new)
    pidfd = Rubernetes::Platform::Linux::Pidfd.new.open(pid: Process.pid)
    start_time = File.binread("/proc/#{Process.pid}/stat").rpartition(") ").last.split.fetch(19).to_i
    inode = File.stat("/proc/self/ns/net").ino
    sandbox = {"sandbox_id" => "sandbox-netns",
               "netns" => {"handle" => "namespace:sandbox-netns", "path" => "/proc/#{Process.pid}/ns/net",
                           "inode" => inode, "pid" => Process.pid, "pidfd" => pidfd, "start_time" => start_time}}
    lease = Rubernetes::Network::Netlink::NamespaceLease.open(sandbox.fetch("netns"))

    plan = topology.desired(sandbox, {"ips" => ["10.244.0.9/24"], "namespace_fd" => lease.fileno})
    namespaced = plan.operations.select do |operation|
      operation.parameters["name"] == "eth0" || operation.parameters["peer"] == "eth0" ||
        operation.parameters["interface"] == "eth0"
    end

    refute_empty namespaced
    assert(namespaced.all? { |operation| operation.parameters["namespace_fd"] == lease.fileno })
    assert_equal inode, plan.metadata.fetch("netns_inode")
  ensure
    lease&.close
    IO.for_fd(pidfd).close if pidfd
  end

  def test_node_sysctls_are_exactly_owned_reference_counted_and_rolled_back
    Dir.mktmpdir("network-sysctl-") do |directory|
      values = Rubernetes::Network::SysctlManager::STATIC_TARGETS.merge(
        "net/ipv4/conf/rbr0/rp_filter" => "0", "net/ipv6/conf/rbr0/forwarding" => "1"
      )
      values.each_key do |relative|
        path = File.join(directory, relative)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, "9\n")
      end
      manager = Rubernetes::Network::SysctlManager.new(
        state_path: File.join(directory, "state.json"), root: directory, fsync: false
      )

      manager.acquire(owner: "pod-a", bridge: "rbr0")
      manager.acquire(owner: "pod-b", bridge: "rbr0")

      assert(values.all? { |relative, target| File.binread(File.join(directory, relative)).strip == target })
      assert_equal 2, manager.snapshot.fetch("refcount")
      manager.release(owner: "pod-a")

      assert_equal 1, manager.snapshot.fetch("refcount")
      manager.release(owner: "pod-b")

      assert(values.all? { |relative, _target| File.binread(File.join(directory, relative)).strip == "9" })
      assert_equal "inactive", manager.snapshot.fetch("state")
    end
  end

  def test_bridge_is_node_owned_and_never_part_of_a_pod_rollback_plan
    adapter = RecordingAdapter.new
    manager = Rubernetes::Network::BridgeManager.new(adapter: adapter)
    topology = Rubernetes::Network::Topology.new(adapter: adapter, bridge_manager: manager)
    first = topology.desired({"sandbox_id" => "sandbox-a"}, {"ips" => ["10.244.0.9/24"]})
    second = topology.desired({"sandbox_id" => "sandbox-b"}, {"ips" => ["10.244.0.10/24"]})

    refute(first.operations.any? { |operation| operation.parameters["kind"] == "bridge" })
    refute(second.operations.any? { |operation| operation.parameters["kind"] == "bridge" })
    manager.acquire(name: "rbr0", mtu: 1500, owner: "sandbox-a")
    manager.acquire(name: "rbr0", mtu: 1500, owner: "sandbox-b")
    manager.release(name: "rbr0", owner: "sandbox-a")
    manager.release(name: "rbr0", owner: "sandbox-b")

    bridge_adds = adapter.operations.map(&:first).select { |operation| operation.parameters["kind"] == "bridge" }

    assert_equal 1, bridge_adds.length
    refute(adapter.operations.map(&:first).any? { |operation| operation.action == "link_delete" && operation.parameters["name"] == "rbr0" })
    assert_equal 0, manager.refcount("rbr0")
  end

  def test_recovery_claims_compensates_and_releases_effect_before_claim_orphan
    effect = Rubernetes::Network::Operation.new(
      action: "address_add", resource: "address:sandbox-a:10.244.0.9/24", identity: "planned-address",
      parameters: {"address" => "10.244.0.9", "prefix" => 24, "interface" => "eth0",
                   "namespace_fd" => "/proc/42/ns/net"}
    ).freeze
    proof = {
      "kind" => "address", "id" => effect.resource,
      "identity" => "address:netns=1234:ifindex=7:address=10.244.0.9/24",
      "metadata" => {"address" => "10.244.0.9", "prefix" => 24, "netns_inode" => 1234,
                     "ifindex" => 7, "ifname" => "eth0"}
    }
    operation = {
      "id" => "add:sandbox-a", "request_id" => "add:sandbox-a", "sandbox_id" => "sandbox-a",
      "owner" => "network:sandbox-a", "config_digest" => "digest", "state" => "applying",
      "result" => nil, "error" => nil, "resources" => [],
      "plan" => Rubernetes::Network::Plan.new(operations: [effect], mtu: 1500, backend: nil,
                                              revision: nil, metadata: {}).to_h,
      "effect_intent" => effect.to_h, "created_at" => Time.now.utc.iso8601
    }
    store = MemoryStateStore.new("version" => 1, "operations" => {operation.fetch("id") => operation},
                                 "requests" => {operation.fetch("request_id") => operation.fetch("id")})
    ledger = RecoveryLedger.new
    adapter = RecordingAdapter.new
    observer = RecoveryObserver.new(proof)
    network = Rubernetes::Network::Interface.new(adapter: adapter, ledger: ledger, observer: observer,
                                                 state_store: store)

    report = network.recover

    assert_empty report.kernel_only
    assert_equal proof.fetch("identity"), ledger.claims.fetch(0).fetch(:identity)
    assert_equal proof.fetch("identity"), ledger.releases.fetch(0).fetch(:identity)
    rollback = adapter.operations.map(&:first).find { |entry| entry.action == "address_delete" }

    refute_nil rollback
    assert(report.audit.any? { |entry| entry["kind"] == "kernel_only_compensated" })
    refute_includes report.kernel_only, "unrelated-host-link"
  end

  def test_recovery_compensates_one_veth_effect_once_after_claiming_both_identities
    effect = Rubernetes::Network::Operation.new(
      action: "link_add", resource: "link:veth-a", identity: "planned-veth",
      parameters: {"name" => "veth-a", "kind" => "veth", "peer" => "eth0",
                   "namespace_fd" => "/proc/42/ns/net"}
    ).freeze
    host = {"kind" => "link", "id" => "link:veth-a", "identity" => "host-veth-identity",
            "metadata" => {"ifname" => "veth-a", "ifindex" => 7, "netns_inode" => 100}}
    peer = {"kind" => "link", "id" => "link:eth0", "identity" => "peer-veth-identity",
            "metadata" => {"ifname" => "eth0", "ifindex" => 2, "netns_inode" => 200}}
    operation = {
      "id" => "add:sandbox-veth", "request_id" => "add:sandbox-veth", "sandbox_id" => "sandbox-veth",
      "owner" => "network:sandbox-veth", "config_digest" => "digest", "state" => "applying",
      "result" => nil, "error" => nil, "resources" => [],
      "plan" => Rubernetes::Network::Plan.new(operations: [effect], mtu: 1500, backend: nil,
                                              revision: nil, metadata: {}).to_h,
      "effect_intent" => effect.to_h, "created_at" => Time.now.utc.iso8601
    }
    store = MemoryStateStore.new("version" => 1, "operations" => {operation.fetch("id") => operation},
                                 "requests" => {operation.fetch("request_id") => operation.fetch("id")})
    ledger = RecoveryLedger.new
    adapter = RecordingAdapter.new
    network = Rubernetes::Network::Interface.new(
      adapter: adapter, ledger: ledger, observer: RecoveryObserver.new(host, peer), state_store: store
    )

    report = network.recover

    assert_empty report.kernel_only
    assert_equal(%w[host-veth-identity peer-veth-identity], ledger.claims.map { |entry| entry.fetch(:identity) })
    assert_equal(%w[host-veth-identity peer-veth-identity], ledger.releases.map { |entry| entry.fetch(:identity) })
    deletes = adapter.operations.map(&:first).select { |entry| entry.action == "link_delete" }

    assert_equal 1, deletes.length
    assert_equal "veth-a", deletes.first.parameters.fetch("name")
  end

  def test_overlay_auto_selection_mtu_and_diffs_are_deterministic
    overlay = Rubernetes::Network::Overlay.new(backend: :auto, underlay_mtu: 1500)
    nodes = [{name: "node-a", pod_cidr: "10.1.0.0/24", vtep: "192.0.2.1", mac: "aa:bb:cc:dd:ee:01",
              l2_reachable: false, next_hop_reachable: false, revision: 4}]

    assert_equal "vxlan", overlay.backend(nodes: nodes)
    plan = overlay.plan(nodes: nodes, local_node: "node-z", dev: "lo")

    assert_equal 1450, plan.mtu.fetch("ipv4")
    assert_equal 1430, plan.mtu.fetch("ipv6")
    refute_empty overlay.route_diff(current: [], desired: [{"destination" => "10.1.0.0/24"}], revision: 4)
  end

  def test_link_set_failure_rollback_restores_observed_state_and_clears_master
    netlink = RollbackNetlink.new
    topology = Rubernetes::Network::Topology.new(netlink: netlink)
    operation = Rubernetes::Network::Operation.new(
      action: "link_set", resource: "link:existing", identity: "existing",
      parameters: {"name" => "existing", "index" => 7, "up" => false, "mtu" => 1400, "master" => "rbr0"}
    ).freeze
    plan = Rubernetes::Network::Plan.new(operations: [operation, operation], mtu: 1500, backend: nil,
                                         revision: 1, metadata: {}).freeze

    error = assert_raises(Rubernetes::Network::EffectError) { topology.apply(plan) }
    assert_equal 1, error.applied.length
    topology.rollback(Rubernetes::Network::Plan.new(operations: error.applied, mtu: 1500,
                                                    backend: nil, revision: 1, metadata: {}).freeze)
    restore = netlink.calls.last

    assert_equal true, restore.fetch(:up)
    assert_equal 1500, restore.fetch(:mtu)
    assert_equal true, restore.fetch(:clear_master)
  end

  def test_topology_carries_overlay_config_into_interface_lifecycle_plan
    adapter = RecordingAdapter.new
    topology = Rubernetes::Network::Topology.new(adapter: adapter)
    plan = topology.desired(
      {"sandbox_id" => "sandbox-overlay"},
      {"ips" => [], "overlay" => {
        "backend" => "vxlan", "device" => "vxlan-test", "vni" => 4242,
        "dstport" => 4790, "learning" => false, "dev" => "lo", "nodes" => [
          {"name" => "node-b", "pod_cidr" => "10.2.0.0/24", "vtep" => "192.0.2.2",
           "mac" => "aa:bb:cc:dd:ee:ff"}
        ]
      }}
    )
    vxlan = plan.operations.find { |operation| operation.action == "link_add" && operation.parameters["kind"] == "vxlan" }

    refute_nil vxlan
    assert_equal "vxlan", plan.backend
    assert_equal 4242, vxlan.parameters.fetch("vni")
    assert_equal 4790, vxlan.parameters.fetch("dstport")
    assert_equal false, vxlan.parameters.fetch("learning")
    assert_equal "vxlan-test", plan.operations.find { |operation| operation.action == "route_add" }.parameters.fetch("dev")
  end

  def test_veth_pair_rollback_deletes_host_link_in_host_namespace
    topology = Rubernetes::Network::Topology.new(adapter: RecordingAdapter.new)
    operation = Rubernetes::Network::Operation.new(
      action: "link_add", resource: "link:rkh", identity: "veth", parameters: {
        "name" => "rkh", "kind" => "veth", "peer" => "rkp", "namespace_fd" => "/proc/1/ns/net"
      }
    ).freeze
    inverse = topology.send(:inverse_operation, operation, owned_links: Set.new)

    assert_equal "link_delete", inverse.action
    refute inverse.parameters.key?("namespace_fd"), "host-side veth delete must not enter peer namespace"
    refute inverse.parameters.key?("namespace")
  end

  def test_native_observer_decodes_vxlan_fdb_vtep_destination
    netlink = Rubernetes::Network::Netlink.new(adapter: RecordingAdapter.new)
    observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
    payload = [Rubernetes::Network::Netlink::AF_BRIDGE, 0, 0, 5,
               Rubernetes::Network::Netlink::NUD_PERMANENT, 0, 0].pack("CCS<l<S<CC") +
              Rubernetes::Network::Netlink::TLV.encode_many([
                                                              {"type" => Rubernetes::Network::Netlink::NDA_DST,
                                                               "value" => IPAddr.new("192.0.2.1").hton},
                                                              {"type" => Rubernetes::Network::Netlink::NDA_LLADDR,
                                                               "value" => ["02aabbccddee"].pack("H12")}
                                                            ])
    message = Rubernetes::Network::Netlink::Message.new(type: Rubernetes::Network::Netlink::RTM_NEWNEIGH,
                                                        flags: 0, sequence: 1, payload: payload)
    entries = observer.send(:parse_neighbours, [message],
                            {5 => {"index" => 5, "name" => "vxlan0"}}, 4_026_531_840)

    assert_equal 1, entries.length
    entry = entries.first

    assert_equal "192.0.2.1", entry.dig("metadata", "destination")
    assert_includes entry.fetch("identity"), "ifindex=5"
    assert_includes entry.fetch("identity"), "destination=192.0.2.1"
  end

  def test_native_observer_reads_back_vxlan_kind_vni_port_learning_and_underlay
    netlink = Rubernetes::Network::Netlink.new(adapter: RecordingAdapter.new)
    observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
    vxlan_data = Rubernetes::Network::Netlink::TLV.encode_many([
                                                                 {"type" => Rubernetes::Network::Netlink::IFLA_VXLAN_ID,
                                                                  "value" => [4242].pack("L<")},
                                                                 {"type" => Rubernetes::Network::Netlink::IFLA_VXLAN_LINK,
                                                                  "value" => [2].pack("L<")},
                                                                 {"type" => Rubernetes::Network::Netlink::IFLA_VXLAN_PORT,
                                                                  "value" => [4790].pack("S>")},
                                                                 {"type" => Rubernetes::Network::Netlink::IFLA_VXLAN_LEARNING, "value" => [0].pack("C")}
                                                               ])
    link_info = Rubernetes::Network::Netlink::TLV.encode_many([
                                                                {"type" => Rubernetes::Network::Netlink::IFLA_INFO_KIND,
                                                                 "value" => "vxlan\0"},
                                                                {"type" => Rubernetes::Network::Netlink::IFLA_INFO_DATA, "value" => vxlan_data, "nested" => true}
                                                              ])
    payload = [0, 0, 0, 7, 1, 0].pack("CCS<l<L<L<") + Rubernetes::Network::Netlink::TLV.encode_many([
                                                                                                      {
                                                                                                        "type" => Rubernetes::Network::Netlink::IFLA_IFNAME, "value" => "vxlan-test\0"
                                                                                                      },
                                                                                                      {
                                                                                                        "type" => Rubernetes::Network::Netlink::IFLA_MTU, "value" => [1430].pack("L<")
                                                                                                      },
                                                                                                      {
                                                                                                        "type" => Rubernetes::Network::Netlink::IFLA_ADDRESS, "value" => ["02aabbccddee"].pack("H12")
                                                                                                      },
                                                                                                      {"type" => Rubernetes::Network::Netlink::IFLA_LINKINFO, "value" => link_info, "nested" => true}
                                                                                                    ])
    message = Rubernetes::Network::Netlink::Message.new(type: Rubernetes::Network::Netlink::RTM_NEWLINK,
                                                        flags: 0, sequence: 1, payload: payload)
    entry = observer.send(:parse_links, [message]).first

    assert_equal "vxlan", entry.fetch("kind")
    assert_equal 4242, entry.fetch("vni")
    assert_equal 4790, entry.fetch("dstport")
    assert_equal false, entry.fetch("learning")
    assert_equal 2, entry.fetch("underlay_ifindex")
  end

  def test_native_observer_uses_extended_route_table_and_excludes_ip_neighbours_from_fdb
    netlink = Rubernetes::Network::Netlink.new(adapter: RecordingAdapter.new)
    observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
    route_payload = [Rubernetes::Network::Netlink::AF_INET, 24, 0, 0, 44, 4, 0, 1, 0].pack("CCCCCCCCL<") +
                    Rubernetes::Network::Netlink::TLV.encode_many([
                                                                    {"type" => Rubernetes::Network::Netlink::RTA_DST,
                                                                     "value" => IPAddr.new("198.18.0.0").hton},
                                                                    {"type" => Rubernetes::Network::Netlink::RTA_OIF,
                                                                     "value" => [5].pack("L<")},
                                                                    {"type" => Rubernetes::Network::Netlink::RTA_TABLE, "value" => [1000].pack("L<")}
                                                                  ])
    route_message = Rubernetes::Network::Netlink::Message.new(type: Rubernetes::Network::Netlink::RTM_NEWROUTE,
                                                              flags: 0, sequence: 1, payload: route_payload)
    route = observer.send(:parse_routes, [route_message],
                          {5 => {"index" => 5, "name" => "eth0"}}, 4_026_531_840).first

    assert_equal 1000, route.dig("metadata", "table")
    assert_equal "eth0", route.dig("metadata", "ifname")
    assert_equal 4, route.dig("metadata", "protocol")
    assert_equal 0, route.dig("metadata", "scope")
    assert_equal 1, route.dig("metadata", "route_type")
    assert_includes route.fetch("identity"), "table=1000"
    assert_includes route.fetch("identity"), "ifname=eth0"
    assert_includes route.fetch("identity"), "protocol=4"
    assert_includes route.fetch("identity"), "scope=0"
    assert_includes route.fetch("identity"), "type=1"

    neighbour_payload = [Rubernetes::Network::Netlink::AF_INET, 0, 0, 5,
                         Rubernetes::Network::Netlink::NUD_PERMANENT, 0, 0].pack("CCS<l<S<CC") +
                        Rubernetes::Network::Netlink::TLV.encode_many([
                                                                        {"type" => Rubernetes::Network::Netlink::NDA_DST,
                                                                         "value" => IPAddr.new("198.18.0.1").hton},
                                                                        {"type" => Rubernetes::Network::Netlink::NDA_LLADDR, "value" => ["02aabbccddee"].pack("H12")}
                                                                      ])
    neighbour_message = Rubernetes::Network::Netlink::Message.new(type: Rubernetes::Network::Netlink::RTM_NEWNEIGH,
                                                                  flags: 0, sequence: 1, payload: neighbour_payload)

    assert_empty observer.send(:parse_neighbours, [neighbour_message],
                               {5 => {"index" => 5, "name" => "eth0"}}, 4_026_531_840)
  end

  def test_native_observer_rejects_tentative_or_dad_failed_address_as_apply_proof
    netlink = Rubernetes::Network::Netlink.new(adapter: RecordingAdapter.new)
    observer = Rubernetes::Network::NativeObserver.new(netlink: netlink)
    flags = Rubernetes::Network::Netlink::IFA_F_TENTATIVE | Rubernetes::Network::Netlink::IFA_F_DADFAILED
    payload = [Rubernetes::Network::Netlink::AF_INET6, 64, 0, 0, 5].pack("CCCCL<") +
              Rubernetes::Network::Netlink::TLV.encode_many([
                                                              {"type" => Rubernetes::Network::Netlink::IFA_ADDRESS,
                                                               "value" => IPAddr.new("2001:db8::9").hton},
                                                              {"type" => Rubernetes::Network::Netlink::IFA_FLAGS, "value" => [flags].pack("L<")}
                                                            ])
    message = Rubernetes::Network::Netlink::Message.new(type: Rubernetes::Network::Netlink::RTM_NEWADDR,
                                                        flags: 0, sequence: 1, payload: payload)
    entry = observer.send(:parse_addresses, [message], {5 => {"index" => 5, "name" => "eth0"}}, 1234).first

    assert_equal flags, entry.dig("metadata", "flags")
    assert_equal true, entry.dig("metadata", "tentative")
    assert_equal true, entry.dig("metadata", "dad_failed")

    observer.stub(:resources, [entry]) do
      operation = Rubernetes::Network::Operation.new(
        action: "address_add", resource: "address:pod:2001:db8::9/64", identity: "planned",
        parameters: {"address" => "2001:db8::9", "prefix" => 64, "interface" => "eth0"}
      )

      assert_empty observer.resources_for(operation)
    end
  end

  def test_policy_selector_named_port_sctp_and_atomic_snapshot
    adapter = RecordingAdapter.new
    policy = {
      "metadata" => {"name" => "web-policy", "namespace" => "apps"},
      "spec" => {
        "podSelector" => {"matchLabels" => {"app" => "web"}},
        "policyTypes" => ["Ingress"],
        "ingress" => [{"from" => [{"podSelector" => {"matchLabels" => {"app" => "client"}}}],
                       "ports" => [{"protocol" => "SCTP", "port" => "metrics"}]}]
      }
    }
    engine = Rubernetes::Network::PolicyEngine.new(adapter: adapter)
    engine.apply(policy)
    source = {namespace: "apps", labels: {app: "client"}}
    destination = {namespace: "apps", labels: {app: "web"}, ports: [{name: "metrics", port: 9899}]}

    assert engine.allowed?(source: source, destination: destination, direction: "ingress", protocol: "SCTP", port: 9899)
    refute engine.allowed?(source: {namespace: "apps", labels: {app: "other"}}, destination: destination,
                           direction: "ingress", protocol: "SCTP", port: 9899)
    assert_equal 1, adapter.swaps.length
  end

  def test_dns_service_headless_srv_ptr_cname_and_atomic_resolv_projection
    resolver = Rubernetes::Network::DNS::Resolver.new
    resolver.add_service("metadata" => {"name" => "db", "namespace" => "apps"},
                         "spec" => {"clusterIP" => "None", "ports" => [{"name" => "sql", "port" => 5432}]})
    resolver.add_endpoint_slice("metadata" => {"name" => "db-1", "namespace" => "apps",
                                               "labels" => {"kubernetes.io/service-name" => "db"}},
                                "ports" => [{"name" => "sql", "port" => 5432}],
                                "endpoints" => [{"addresses" => ["192.0.2.10"], "conditions" => {"ready" => true},
                                                 "hostname" => "db-1"}])

    assert_equal ["192.0.2.10"], resolver.resolve("db.apps.svc.cluster.local", type: "A").map(&:data)
    assert_equal [5432], resolver.resolve("_sql._tcp.db.apps.svc.cluster.local", type: "SRV").map(&:port)
    # Kubernetes DNS spec 2.4.1: a headless endpoint with a hostname is
    # `<hostname>.<service>.<ns>.svc.<zone>`, and PTR returns that name.
    assert_equal ["db-1.db.apps.svc.cluster.local"], resolver.resolve("10.2.0.192.in-addr.arpa", type: "PTR").map(&:data)
    assert_equal ["db-1.db.apps.svc.cluster.local"], resolver.resolve("_sql._tcp.db.apps.svc.cluster.local", type: "SRV").map(&:data)
    assert_equal ["192.0.2.10"], resolver.resolve("db-1.db.apps.svc.cluster.local", type: "A").map(&:data)
    assert_equal "NOERROR", resolver.resolve("db.apps.svc.cluster.local", type: "AAAA").rcode
    assert_equal "NXDOMAIN", resolver.resolve("missing.apps.svc.cluster.local", type: "A").rcode

    resolver.add_service("metadata" => {"name" => "external", "namespace" => "apps"},
                         "spec" => {"type" => "ExternalName", "externalName" => "outside.example"})

    assert_equal "outside.example", resolver.resolve("external.apps.svc.cluster.local", type: "CNAME").first.data

    Dir.mktmpdir do |directory|
      path = File.join(directory, "resolv.conf")
      content = resolver.project_resolv_conf(path: path, namespace: "apps")

      assert_includes content, "nameserver 10.96.0.10"
      assert_equal content, File.read(path)
    end
  end
end
