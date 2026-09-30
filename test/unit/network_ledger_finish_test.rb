# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes"
require "rubernetes/network"

# Network::Interface began a ledger operation per attach and never finished
# it: the operation stayed in its initial state, was never forgettable, and
# the ownership journal grew 0.33 MB per 90 Pods without ever compacting
# (OwnershipLedger forgets finished operations beyond the last sixteen and
# rewrites the journal).  A delete that released everything now finishes
# the operation as the rollback of the attach: RollingBack, Stopped,
# Removed.
class NetworkLedgerFinishTest < Minitest::Test
  Network = Rubernetes::Network
  Native = Rubernetes::Runtime::Native

  class MemoryStore
    def initialize = @state = {}
    def read = Network::Support.copy(@state)

    def replace(value)
      @state = Network::Support.copy(value)
      Network::Support.freeze_deeply(Network::Support.copy(@state))
    end
  end

  def setup
    @directory = Dir.mktmpdir("network-ledger-finish-")
    @journal_path = File.join(@directory, "ledger.wal")
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def open_ledger
    Native::OwnershipLedger.new(journal: Native::RollbackJournal.new(@journal_path, fsync: false))
  end

  def topology
    build = lambda do |sandbox|
      id = sandbox.respond_to?(:fetch) ? sandbox.fetch("sandbox_id") : "sb"
      operations = [Network::Operation.new(action: "link_add", resource: "link:veth-#{id}", identity: "veth-#{id}:1",
                                           parameters: {"name" => "veth-#{id}", "kind" => "veth", "peer" => "eth0", "peer_resource" => "link:eth0-#{id}"})]
      Network::Plan.new(operations: operations, mtu: 1500, backend: "bridge", revision: 1, metadata: {"bridge" => "cni0"})
    end
    fake = Object.new
    fake.define_singleton_method(:desired) { |sandbox, *, **| build.call(sandbox) }
    fake.define_singleton_method(:apply) do |plan_value, operation_id: nil, before_operation: nil, after_operation: nil|
      Array(plan_value.operations).each_with_index do |op, index|
        before_operation&.call(op, index)
        after_operation&.call(op, index)
      end
      plan_value
    end
    fake.define_singleton_method(:rollback) { |*, **| nil }
    fake.define_singleton_method(:acquire_bridge) { |*, **| nil }
    fake.define_singleton_method(:release_bridge) { |*, **| nil }
    fake
  end

  # A /proc/sys of our own with every sysctl the manager owns for bridge cni0.
  def sysctl_manager(journal)
    root = File.join(@directory, "sys")
    Network::SysctlManager::STATIC_TARGETS.merge("net/ipv4/conf/cni0/rp_filter" => "0",
                                                 "net/ipv6/conf/cni0/forwarding" => "1").each_key do |relative|
      path = File.join(root, relative)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "9\n") unless File.exist?(path)
    end
    Network::SysctlManager.new(state_path: File.join(@directory, "sysctl.json"), root: root, journal: journal, fsync: false)
  end

  def observer
    fake = Object.new
    fake.define_singleton_method(:resources_for) do |operation|
      value = operation.respond_to?(:to_h) ? operation.to_h : operation
      peer = value.dig("parameters", "peer_resource") || "link:eth0"
      [{"kind" => "link", "id" => value["resource"], "identity" => "host-#{value["resource"]}"},
       {"kind" => "link", "id" => peer, "identity" => "peer-#{peer}"}]
    end
    fake.define_singleton_method(:resources) { |*, **| [] }
    fake
  end

  def interface(ledger, sysctl: nil)
    Network::Interface.new(ipam: nil, topology: topology, state_store: MemoryStore.new, ledger: ledger,
                           sysctl_manager: sysctl, require_observer: false, observer: observer)
  end

  def attach_and_detach(interface, id)
    result = interface.add({"sandbox_id" => id, "netns" => nil}, {"node" => "worker-0", "ips" => [], "default_route" => false})
    operation_id = result.respond_to?(:fetch) ? result.fetch("operation_id") : result["operation_id"]
    interface.delete({"sandbox_id" => id, "netns" => nil}, stopped: true)
    operation_id
  end

  def test_a_deleted_sandbox_finishes_its_ledger_operation
    ledger = open_ledger
    operation_id = attach_and_detach(interface(ledger), "sb-1")

    operation = ledger.operation(operation_id)

    assert_equal "Removed", operation.state
    assert(ledger.resources(owner: operation.owner, include_released: true).all? { |resource| resource[:state] == "Released" })
  end

  def test_churn_keeps_the_ledger_bounded_and_compacts_the_journal
    ledger = open_ledger
    network = interface(ledger)
    sizes = []
    120.times do |index|
      attach_and_detach(network, "sb-#{index}")
      sizes << File.size(@journal_path)
    end

    live = ledger.operations.length

    assert_operator live, :<=, Native::OwnershipLedger::RETAINED_FINISHED_OPERATIONS + 1,
                    "finished operations beyond the retained window must be forgotten (#{live} live)"
    assert_includes File.read(@journal_path), Native::OwnershipLedger::COMPACTION_EVENT, "the journal must have been rewritten"
    assert_operator sizes.last, :<, sizes.max, "the journal must shrink after compaction, not only grow"
  end

  # The manager's per-Pod reference records are journaled under the
  # sandbox's operation, so the ledger retires them with it; ~1300 of a
  # worker's 1642 post-round records were these pairs under the manager's
  # own id, which no compaction could drop.
  def test_sysctl_reference_records_are_retired_with_their_operation
    ledger = open_ledger
    manager = sysctl_manager(ledger.journal)
    network = interface(ledger, sysctl: manager)
    network.add({"sandbox_id" => "sb-live", "netns" => nil}, {"node" => "worker-0", "ips" => [], "default_route" => false})
    120.times { |index| attach_and_detach(network, "sb-#{index}") }

    records = File.readlines(@journal_path).map { |line| JSON.parse(line) }
    references = records.select { |record| record["event"].to_s.start_with?("network_sysctl_reference_") }
    live = ledger.operations.map { |operation| operation[:id] }
    orphaned = references.reject { |record| live.include?(record["operation_id"]) }
    # Forgotten records leave the file at the next rewrite (every
    # COMPACTION_MIN_DROPPED_RECORDS dropped), so a bounded tail of them may
    # still be on disk; without the operation id every one of the 240 stayed.
    assert_operator orphaned.length, :<, Native::OwnershipLedger::COMPACTION_MIN_DROPPED_RECORDS,
                    "reference records of forgotten operations must be compacted away"
    assert_operator references.length, :<, 120, "the journal must not keep one pair per churned Pod (#{references.length})"
    assert_includes File.read(@journal_path), Native::OwnershipLedger::COMPACTION_EVENT
    refute_empty references, "the live Pod's neighbours were reference-counted"
    assert references.none? { |record| record["operation_id"] == Network::SysctlManager::JOURNAL_OPERATION_ID },
           "per-Pod records are filed under the Pod's operation, not the manager's own id"
    assert_operator File.size(@journal_path), :<, 400_000
    assert_equal 1, manager.snapshot.fetch("refcount")

    recovered = Network::SysctlManager.new(state_path: File.join(@directory, "sysctl.json"), root: File.join(@directory, "sys"),
                                           journal: ledger.journal, fsync: false)

    assert_equal ["sb-live"], recovered.recover.fetch("owners"), "recovery reads the state file, not the journal"
    assert_equal "1", File.read(File.join(@directory, "sys/net/ipv4/ip_forward")).strip
  end
end
