# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "json"
require "digest"
require "rubernetes"

# OwnershipLedger forgets finished operations and compacts its journal
# (perf work 2026-09-27): a worker's journal reached 34 MB after one
# conformance round with 323 of 324 operations Removed.
class RuntimeLedgerCompactionTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def setup
    @directory = Dir.mktmpdir("ledger-compaction-")
    @path = File.join(@directory, "ledger.jsonl")
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def open_ledger
    Native::OwnershipLedger.new(journal: Native::RollbackJournal.new(@path, fsync: false))
  end

  # One sandbox lifecycle: claim three resources, a container request pair,
  # run to Removed with everything released.
  def run_sandbox(ledger, id, release: true, finish: true)
    owner = "sandbox:#{id}:0123456789abcdef"
    ledger.begin_operation(operation_id: id, owner: owner, config_digest: "cfg-#{id}", request_id: "req-#{id}")
    %w[Validated ImagePinned WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped Running Stopping Stopped].each do |state|
      ledger.transition(operation_id: id, to: state)
    end
    ledger.claim(operation_id: id, kind: "workspace", id: id, identity: "workspace:#{id}",
                 metadata: {"root" => "/x/#{id}", "big" => "z" * 200})
    ledger.claim(operation_id: id, kind: "namespace", id: id, identity: "namespace:#{id}", metadata: {})
    ledger.claim(operation_id: id, kind: "cgroup", id: "#{id}:c1", identity: "cgroup:#{id}:c1", metadata: {"spec" => {"image" => "pause"}})
    ledger.begin_request(request_id: "start:#{id}:c1", operation: "container.start", config_digest: "d", owner: id)
    ledger.complete_request(request_id: "start:#{id}:c1", state: "Completed", result: {"pid" => 1})
    if release
      ledger.release(operation_id: id, kind: "cgroup", id: "#{id}:c1", identity: "cgroup:#{id}:c1")
      ledger.release(operation_id: id, kind: "namespace", id: id, identity: "namespace:#{id}")
      ledger.release(operation_id: id, kind: "workspace", id: id, identity: "workspace:#{id}")
    end
    ledger.finish(operation_id: id) if finish
  end

  def test_released_tombstone_carries_no_metadata
    ledger = open_ledger
    run_sandbox(ledger, "s1", finish: false)
    released = ledger.resources(owner: "sandbox:s1:0123456789abcdef", include_released: true)

    assert_equal 3, released.length
    assert(released.all? { |resource| resource[:state] == "Released" && resource[:metadata] == {} })
    line = File.readlines(@path).find { |entry| entry.include?('"resource_released"') && entry.include?('"kind":"workspace"') }

    refute_includes line, "zzzz", "the release record must not repeat the claim metadata"
  end

  def test_recent_finished_operations_are_retained_and_older_ones_forgotten
    ledger = open_ledger
    total = Native::OwnershipLedger::RETAINED_FINISHED_OPERATIONS + 5
    total.times { |index| run_sandbox(ledger, "s#{index}") }
    ids = ledger.operations.map { |operation| operation[:id] }

    assert_equal Native::OwnershipLedger::RETAINED_FINISHED_OPERATIONS, ids.length
    assert_equal (5...total).map { |index| "s#{index}" }, ids
    assert_nil ledger.request("start:s0:c1"), "requests of a forgotten operation go with it"
    refute_nil ledger.request("start:s#{total - 1}:c1")
    assert_empty ledger.resources(owner: "sandbox:s0:0123456789abcdef", include_released: true)
    assert_equal 3, ledger.resources(owner: "sandbox:s#{total - 1}:0123456789abcdef", include_released: true).length
    # The journal itself is untouched until enough records are dead.
    refute_includes File.read(@path), "journal_compacted"
  end

  def test_unreleased_or_pending_operations_are_never_forgotten
    ledger = open_ledger
    run_sandbox(ledger, "held", release: false)
    ledger.begin_request(request_id: "stop:pending:c1", operation: "container.stop", config_digest: "d", owner: "pending")
    run_sandbox(ledger, "pending")
    (Native::OwnershipLedger::RETAINED_FINISHED_OPERATIONS + 3).times { |index| run_sandbox(ledger, "s#{index}") }
    ids = ledger.operations.map { |operation| operation[:id] }

    assert_includes ids, "held", "an operation still holding a resource keeps its records"
    assert_includes ids, "pending", "an operation with a pending request keeps its records"
    refute_includes ids, "s0"
  end

  def test_journal_is_compacted_with_a_fresh_valid_chain_and_replays_identically
    ledger = open_ledger
    count = 0
    compacted_after = lambda do |index|
      run_sandbox(ledger, "s#{index}")
      File.read(@path).include?("journal_compacted")
    end
    count += 1 until compacted_after.call(count)
    live_before = {operations: ledger.operations, resources: ledger.resources(include_released: true), requests: ledger.requests}
    lines = File.readlines(@path)
    marker = JSON.parse(lines.first)

    assert_equal "journal_compacted", marker["event"]
    assert_equal 1, marker["sequence"]
    assert_equal 1, marker["payload"]["generation"]
    assert_operator marker["payload"]["dropped_records"], :>=, Native::OwnershipLedger::COMPACTION_MIN_DROPPED_RECORDS
    assert_equal lines.length - 1, marker["payload"]["retained_records"]
    assert_equal(lines.each_index.map { |index| index + 1 }, lines.map { |line| JSON.parse(line)["sequence"] })
    refute lines.any? { |line| line.include?('"operation_id":"s0"') }, "forgotten records are gone from disk"

    reopened = open_ledger

    assert_equal live_before[:operations], reopened.operations
    assert_equal live_before[:resources], reopened.resources(include_released: true)
    assert_equal live_before[:requests], reopened.requests
    # Still usable: the retained operations answer replays, new work appends.
    assert_equal "Removed", reopened.operation("s#{count}").state
    run_sandbox(reopened, "after")

    assert_equal "Removed", reopened.operation("after").state
  end

  def test_second_compaction_folds_the_marker
    ledger = open_ledger
    generations = []
    120.times do |index|
      run_sandbox(ledger, "s#{index}")
      first = JSON.parse(File.readlines(@path).first)
      generations << first["payload"]["generation"] if first["event"] == "journal_compacted"
    end

    assert_operator generations.uniq.max, :>=, 2
    assert_equal(1, File.readlines(@path).count { |line| line.include?("journal_compacted") })
  end

  def test_tampering_is_still_detected_after_compaction
    ledger = open_ledger
    count = 0
    compacted_after = lambda do |index|
      run_sandbox(ledger, "s#{index}")
      File.read(@path).include?("journal_compacted")
    end
    count += 1 until compacted_after.call(count)
    lines = File.readlines(@path)
    record = JSON.parse(lines[3])
    record["payload"]["state"] = "Running" if record["payload"].is_a?(Hash)
    record["payload"]["x"] = 1
    lines[3] = JSON.generate(record) << "\n"
    File.write(@path, lines.join)
    assert_raises(Native::JournalCorruption) { open_ledger }
  end

  def test_foreign_journal_events_survive_compaction
    journal = Native::RollbackJournal.new(@path, fsync: false)
    ledger = Native::OwnershipLedger.new(journal: journal)
    journal.append(operation_id: "network:sysctl", event: "network_sysctl_apply_committed", payload: {"state" => "active"})
    count = 0
    compacted_after = lambda do |index|
      run_sandbox(ledger, "s#{index}")
      File.read(@path).include?("journal_compacted")
    end
    count += 1 until compacted_after.call(count)

    assert_includes File.read(@path), "network_sysctl_apply_committed"
  end

  def test_legacy_requests_without_owner_are_forgotten_by_id
    journal = Native::RollbackJournal.new(@path, fsync: false)
    ledger = Native::OwnershipLedger.new(journal: journal)
    ledger.begin_request(request_id: "create:s0:c1", operation: "container.create", config_digest: "d")
    ledger.complete_request(request_id: "create:s0:c1", state: "Completed")

    assert_nil ledger.request("create:s0:c1").owner
    (Native::OwnershipLedger::RETAINED_FINISHED_OPERATIONS + 1).times { |index| run_sandbox(ledger, "s#{index}") }

    assert_nil ledger.request("create:s0:c1")
  end

  def test_owner_index_follows_reuse_of_a_key_by_another_owner
    ledger = open_ledger
    ledger.begin_operation(operation_id: "a", owner: "sandbox:a:0000000000000000", config_digest: "c")
    ledger.transition(operation_id: "a", to: "Validated")
    ledger.claim(operation_id: "a", kind: "veth", id: "veth1", identity: "veth:1", metadata: {})
    ledger.transition(operation_id: "a", to: "RollingBack")
    ledger.release(operation_id: "a", kind: "veth", id: "veth1", identity: "veth:1")
    ledger.begin_operation(operation_id: "b", owner: "sandbox:b:0000000000000000", config_digest: "c")
    ledger.claim(operation_id: "b", kind: "veth", id: "veth1", identity: "veth:2", metadata: {})

    assert_empty ledger.resources(owner: "sandbox:a:0000000000000000", include_released: true)
    assert_equal(["veth:2"], ledger.resources(owner: "sandbox:b:0000000000000000").map { |resource| resource[:identity] })
    reopened = open_ledger

    assert_empty reopened.resources(owner: "sandbox:a:0000000000000000", include_released: true)
    assert_equal(["veth:2"], reopened.resources(owner: "sandbox:b:0000000000000000").map { |resource| resource[:identity] })
  end
end

class RuntimeLedgerInertOperationsTest < Minitest::Test
  Native = Rubernetes::Runtime::Native

  def setup
    @directory = Dir.mktmpdir("ledger-inert-")
    @path = File.join(@directory, "ledger.jsonl")
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  # Operations that never transition (the network ledger before Interface
  # finished them): claim, release, nothing else.
  def write_legacy_journal(released:, live:)
    ledger = Native::OwnershipLedger.new(journal: Native::RollbackJournal.new(@path, fsync: false))
    released.times do |index|
      id = "net-#{index}"
      ledger.begin_operation(operation_id: id, owner: "sandbox:#{id}:0000000000000000", config_digest: "c")
      ledger.claim(operation_id: id, kind: "veth", id: "veth-#{index}", identity: "veth:#{index}", metadata: {})
      ledger.release(operation_id: id, kind: "veth", id: "veth-#{index}", identity: "veth:#{index}", force: true)
    end
    live.times do |index|
      id = "live-#{index}"
      ledger.begin_operation(operation_id: id, owner: "sandbox:#{id}:0000000000000000", config_digest: "c")
      ledger.claim(operation_id: id, kind: "veth", id: "live-veth-#{index}", identity: "veth:live-#{index}", metadata: {})
    end
    ledger.begin_operation(operation_id: "empty", owner: "sandbox:empty:0000000000000000", config_digest: "c")
    ledger
  end

  def test_released_new_operations_are_closed_and_compacted_away_at_load
    before = write_legacy_journal(released: 500, live: 10)
    live_resources = before.resources(include_released: false)

    assert_equal 511, before.operations.length

    reopened = Native::OwnershipLedger.new(journal: Native::RollbackJournal.new(@path, fsync: false))
    ids = reopened.operations.map { |operation| operation[:id] }

    assert_equal Array.new(10) { |index| "live-#{index}" } + ["empty"], ids
    assert_equal live_resources, reopened.resources(include_released: false)
    assert reopened.operations.all? { |operation| operation[:state] == "New" }, "live operations keep their state"
    lines = File.readlines(@path)

    assert_equal "journal_compacted", JSON.parse(lines.first)["event"]
    refute(lines.any? { |line| line.include?("net-7") })
    assert_operator lines.length, :<, 60

    again = Native::OwnershipLedger.new(journal: Native::RollbackJournal.new(@path, fsync: false))

    assert_equal(ids, again.operations.map { |operation| operation[:id] })
  end
end
