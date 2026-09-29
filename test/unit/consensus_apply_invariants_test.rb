# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/consensus"

# The apply-side invariants that make an acknowledged-but-missing object
# (conformance round 79: 100 Pod creates answered 201, 98 Pods) attributable
# next time: effect counters against live objects, a running digest equal
# on every replica at the same index, and the acknowledgement check in
# RaftStore#submit.
class ConsensusApplyInvariantsTest < Minitest::Test
  C = Rubernetes::Consensus

  class CapturingLogger
    attr_reader :events

    def initialize
      @events = []
    end

    %w[debug info warn error].each do |level|
      define_method(level) { |event, **fields| @events << [level, event, fields] }
    end

    def named(event)
      @events.select { |(_level, name, _fields)| name == event }
    end
  end

  def create(key, index, machine, uid: nil)
    machine.apply(index, {"type" => "create", "key" => key, "object" => {"metadata" => {"name" => key.split("/").last}},
                          "request_uid" => uid, "leader_time" => index.to_f})
  end

  def delete(key, index, machine)
    machine.apply(index, {"type" => "delete", "key" => key, "expected_resource_version" => nil, "request_uid" => nil,
                          "leader_time" => index.to_f})
  end

  def update(key, index, machine, expected:)
    machine.apply(index, {"type" => "update", "key" => key, "object" => {"metadata" => {"name" => key.split("/").last}, "spec" => {"i" => index}},
                          "expected_resource_version" => expected, "client_precondition" => expected, "request_uid" => nil,
                          "leader_time" => index.to_f})
  end

  def test_effect_counters_match_live_objects_and_a_checkpoint_is_logged
    logger = CapturingLogger.new
    machine = C::KVStateMachine.new(logger: logger, checkpoint_interval: nil)
    create("k/a", 1, machine)
    create("k/b", 2, machine)
    update("k/a", 3, machine, expected: "1")
    assert_equal false, create("k/a", 4, machine)["ok"], "a second create is rejected"
    assert_equal true, delete("k/b", 5, machine)["ok"]
    assert_equal false, delete("k/b", 6, machine)["ok"], "deleting a deleted key is rejected"
    assert_equal({"create" => 2, "update" => 1, "delete" => 1, "rejected" => 2}, machine.effects)
    fields = machine.checkpoint!
    assert_equal 1, fields[:objects]
    assert_equal 1, fields[:expected_objects]
    assert_equal 6, fields[:index]
    assert_equal 0, machine.violations
    assert_equal 1, logger.named("consensus.apply_checkpoint").length
    assert_empty logger.named("consensus.apply_invariant_violation")
  end

  def test_a_request_uid_replay_is_not_counted_as_a_second_create
    machine = C::KVStateMachine.new(checkpoint_interval: nil)
    first = create("k/a", 1, machine, uid: "u1")
    replay = create("k/a", 2, machine, uid: "u1")
    assert_equal first["object"], replay["object"]
    assert_equal 1, machine.effects["create"]
    assert_equal 1, machine.checkpoint![:objects]
    assert_equal 0, machine.violations
  end

  def test_an_object_lost_behind_the_state_machine_is_reported_as_a_violation
    logger = CapturingLogger.new
    machine = C::KVStateMachine.new(logger: logger, checkpoint_interval: nil)
    create("k/a", 1, machine)
    create("k/b", 2, machine)
    # Something other than the log removes an object.
    machine.store.delete("k/b")
    fields = machine.checkpoint!
    assert_equal 1, fields[:objects]
    assert_equal 2, fields[:expected_objects]
    assert_equal 1, machine.violations
    violation = logger.named("consensus.apply_invariant_violation").first
    refute_nil violation
    assert_equal 2, violation[2][:index]
  end

  def test_checkpoints_fire_every_interval_and_the_digest_agrees_between_replicas
    loggers = [CapturingLogger.new, CapturingLogger.new]
    replicas = loggers.map { |logger| C::KVStateMachine.new(logger: logger, checkpoint_interval: 4) }
    10.times do |i|
      replicas.each do |machine|
        if i == 6
          delete("k/1", i + 1, machine)
        else
          create("k/#{i}", i + 1, machine)
        end
      end
    end
    assert_equal replicas[0].digest, replicas[1].digest
    assert_equal 2, loggers[0].named("consensus.apply_checkpoint").length
    assert_equal [4, 8], loggers[0].named("consensus.apply_checkpoint").map { |(_l, _e, fields)| fields[:index] }
    # A replica whose apply went differently has a different digest.
    diverged = C::KVStateMachine.new(checkpoint_interval: nil)
    10.times { |i| create("k/#{i}", i + 1, diverged) }
    refute_equal replicas[0].digest, diverged.digest
  end

  def test_a_snapshot_carries_the_counters_and_an_old_snapshot_derives_them
    machine = C::KVStateMachine.new(checkpoint_interval: nil)
    3.times { |i| create("k/#{i}", i + 1, machine) }
    delete("k/0", 4, machine)
    restored = C::KVStateMachine.new(checkpoint_interval: nil)
    restored.restore(machine.snapshot)
    assert_equal machine.effects, restored.effects
    assert_equal machine.digest, restored.digest
    assert_equal 0, restored.tap(&:checkpoint!).violations
    create("k/9", 5, restored)
    assert_equal 4, restored.effects["create"]

    legacy_document = machine.snapshot_document
    legacy_document.delete("effects")
    legacy_document.delete("digest")
    legacy = C::KVStateMachine.new(checkpoint_interval: nil)
    legacy.restore(C::KVStateMachine.encode_snapshot(legacy_document))
    assert_equal({"create" => 2, "update" => 0, "delete" => 0, "rejected" => 0}, legacy.effects)
    assert_equal 0, legacy.tap(&:checkpoint!).violations
  end

  def test_tracing_logs_every_apply
    logger = CapturingLogger.new
    machine = C::KVStateMachine.new(logger: logger, checkpoint_interval: nil, trace: true)
    create("k/a", 1, machine)
    create("k/a", 2, machine)
    traces = logger.named("consensus.trace.apply")
    assert_equal 2, traces.length
    assert_equal [true, false], traces.map { |(_l, _e, fields)| fields[:ok] }
    assert_equal "Rubernetes::Storage::AlreadyExists", traces.last[2][:error]
    assert_equal "1", traces.first[2][:revision]
  end

  # RaftStore#submit re-reads what it is about to acknowledge.
  class FakeServer
    attr_reader :logger, :store, :node

    FakeNode = Struct.new(:last_applied)

    def initialize(logger, forge: false)
      @logger = logger
      @machine = C::KVStateMachine.new(checkpoint_interval: nil)
      @store = @machine.store
      @node = FakeNode.new(0)
      @index = 0
      @forge = forge
    end

    def propose(command, request_id:, timeout:)
      @index += 1
      @node.last_applied = @index
      position = Thread.current[C::Server::POSITION_KEY]
      position&.merge!(index: @index, term: 1, via: :local, node: "fake")
      # A forged acknowledgement: ok with an object, nothing applied.
      return {"ok" => true, "object" => command["object"].merge("metadata" => command["object"]["metadata"].merge("resourceVersion" => "1"))} if @forge

      @machine.apply(@index, command)
    end

    def read_index(timeout:) = @index
  end

  def test_an_acknowledged_create_that_reads_back_logs_nothing
    logger = CapturingLogger.new
    store = C::RaftStore.new(FakeServer.new(logger))
    store.create("k/a", {"metadata" => {"name" => "a"}})
    store.update("k/a", {"metadata" => {"name" => "a"}, "spec" => {"x" => 1}})
    assert_empty logger.named("consensus.ack_without_object")
  end

  def test_an_acknowledgement_without_the_object_is_logged_with_its_position
    logger = CapturingLogger.new
    # The state machine answers ok with an object the store does not hold.
    store = C::RaftStore.new(FakeServer.new(logger, forge: true))
    store.create("k/a", {"metadata" => {"name" => "a"}})
    violation = logger.named("consensus.ack_without_object").first
    refute_nil violation
    assert_equal "k/a", violation[2][:key]
    assert_equal "1", violation[2][:revision]
    assert_equal 1, violation[2][:index]
    assert_equal "local", violation[2][:via]
  end
end
