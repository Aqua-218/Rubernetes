# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/consensus"

class ConsensusLogSnapshotTest < Minitest::Test
  C = Rubernetes::Consensus

  def entry(index, term, value = index)
    C::Log::Entry.new(index: index, term: term, command: {"v" => value})
  end

  def test_log_persists_hard_state_entries_truncation_and_compaction
    Dir.mktmpdir do |dir|
      storage = C::Storage.new(dir)
      log = storage.log
      log.save_hard_state(term: 2, voted_for: "n1")
      log.append([entry(1, 1), entry(2, 1), entry(3, 2)])

      assert_equal 3, log.last_index
      assert_equal 2, log.last_term
      assert log.matches?(2, 1)
      refute log.matches?(2, 2)
      assert log.up_to_date?(3, 2)
      refute log.up_to_date?(2, 2)
      assert log.up_to_date?(1, 3)
      log.truncate_from(3)

      assert_equal 2, log.last_index
      log.append([entry(3, 3)])
      log.compact_to(index: 1, term: 1)

      assert_equal 2, log.first_index
      assert_equal 1, log.snapshot_index
      assert_equal [2, 3], log.entries.map(&:index)
      storage.close

      reopened = C::Storage.new(dir)

      assert_equal 2, reopened.log.current_term
      assert_equal "n1", reopened.log.voted_for
      assert_equal [2, 3], reopened.log.entries.map(&:index)
      assert_equal 1, reopened.log.snapshot_index
      assert_equal 3, reopened.log.term_at(3)
      reopened.close
    end
  end

  def test_wal_rotation_keeps_only_the_new_generation
    Dir.mktmpdir do |dir|
      storage = C::Storage.new(dir)
      storage.log.append([entry(1, 1), entry(2, 1)])
      storage.log.compact_to(index: 1, term: 1)
      first = storage.wal_path
      storage.rotate!

      refute_equal first, storage.wal_path
      assert_equal 1, storage.wal_files.length
      storage.close
      reopened = C::Storage.new(dir)

      assert_equal [2], reopened.log.entries.map(&:index)
      assert_equal 1, reopened.log.snapshot_index
      reopened.close
    end
  end

  def test_non_contiguous_entry_in_wal_is_corruption
    Dir.mktmpdir do |dir|
      storage = C::Storage.new(dir)
      storage.wal.append([C::WAL::TYPE_ENTRY, {"index" => 5, "term" => 1, "command" => {}}])
      storage.close
      assert_raises(C::WALCorruption) { C::Storage.new(dir) }
    end
  end

  def test_snapshot_header_with_non_ascii_membership_round_trips
    Dir.mktmpdir do |dir|
      store = C::SnapshotStore.new(dir)
      state = "\xff\xfe state bytes — 日本語".b
      membership = {"voters" => %w[a b c], "learners" => [], "note" => "quorum — 過半数"}
      store.write(state: state, index: 7, term: 2, membership: membership)
      snapshot, rejected = store.latest

      assert_empty rejected
      assert_equal state, snapshot.state
      assert_equal "quorum — 過半数", snapshot.membership["note"]
    end
  end

  def test_snapshot_round_trip_and_corruption_detection
    Dir.mktmpdir do |dir|
      store = C::SnapshotStore.new(dir)
      state = "state-bytes-#{"x" * 1000}".b
      metadata = store.write(state: state, index: 42, term: 3, membership: {"voters" => %w[a b c], "learners" => []})
      snapshot, rejected = store.latest

      assert_empty rejected
      assert_equal 42, snapshot.index
      assert_equal 3, snapshot.term
      assert_equal state, snapshot.state
      assert_equal %w[a b c], snapshot.membership["voters"]

      bytes = File.binread(metadata.path)
      cases = {
        "truncated" => bytes.byteslice(0, bytes.bytesize - 10),
        "bit_flip_state" => bytes.dup.tap { |b| b.setbyte(bytes.bytesize - 100, b.getbyte(bytes.bytesize - 100) ^ 1) },
        "bit_flip_header" => bytes.dup.tap { |b| b.setbyte(20, b.getbyte(20) ^ 1) },
        "magic" => "X" + bytes.byteslice(1..),
        "zeroed" => "\0" * bytes.bytesize,
        "empty" => ""
      }
      cases.each do |name, corrupted|
        error = assert_raises(C::SnapshotCorruption, name) { C::SnapshotStore.decode(corrupted) }
        refute_nil error.message
      end
      File.binwrite(metadata.path, cases["bit_flip_state"])
      assert_raises(C::SnapshotCorruption) { store.latest(strict: true) }
      latest, rejected = store.latest(strict: false)

      assert_nil latest
      assert_equal 1, rejected.length
    end
  end

  def test_membership_joint_quorum_and_commit_index
    simple = C::Membership.simple(%w[a b c])

    assert simple.quorum?(%w[a b])
    refute simple.quorum?(%w[a])
    joint = simple.enter_joint(%w[c d e])

    assert_predicate joint, :joint?
    refute joint.quorum?(%w[a b]), "majority of old only is not a joint quorum"
    refute joint.quorum?(%w[d e]), "majority of new only is not a joint quorum"
    assert joint.quorum?(%w[b c d])
    assert_equal 2, joint.committed_index("a" => 5, "b" => 4, "c" => 2, "d" => 3, "e" => 1)
    assert_equal 4, simple.committed_index("a" => 5, "b" => 4, "c" => 2)
    final = joint.leave_joint

    assert_equal %w[c d e], final.voters.to_a.sort
    assert_raises(C::MembershipError) { joint.enter_joint(%w[a]) }
    assert_raises(C::MembershipError) { C::Membership.simple([]) }
    assert_equal joint, C::Membership.from_h(joint.to_h)
  end

  def test_messages_round_trip_and_reject_unknown_or_missing_fields
    message = C::Messages::AppendEntries.new(cluster_id: "c", from: "a", to: "b", term: 2, request_id: "r",
                                             prev_log_index: 1, prev_log_term: 1, leader_commit: 1,
                                             entries: [{"index" => 2, "term" => 2, "command" => {"type" => "noop"}}])
    decoded = C::Messages.decode(message.encode)

    assert_equal message, decoded
    assert_equal 3, decoded.type_code
    assert_raises(C::ProtocolError) { C::Messages.decode('{"type":"append_entries","cluster_id":"c","from":"a","to":"b","term":1,"request_id":"r"}') }
    assert_raises(C::ProtocolError) { C::Messages.decode(message.encode.sub('"to":"b"', '"to":"b","extra":1')) }
    assert_raises(C::ProtocolError) do
      C::Messages.decode('{"type":"request_vote","cluster_id":"c","from":"a","to":"b","term":1,"request_id":"r",' \
                         '"last_log_index":-1,"last_log_term":0}')
    end
    assert_raises(C::ProtocolError) { C::Messages.decode('{"type":"nope"}') }
    assert_raises(C::ProtocolError) { C::Messages.decode('{"type":"timeout_now","type":"timeout_now","cluster_id":"c","from":"a","to":"b","term":1,"request_id":"r"}') }
  end
end
