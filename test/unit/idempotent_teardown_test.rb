# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "tmpdir"
require "rubernetes"

# Tearing down something that is already gone is a completed teardown, not a
# failure.  Every layer says so upstream -- CRI RemoveContainer "is idempotent,
# and must not return an error if the container has already been removed", the
# CNI spec tells plugins to "complete a DEL action without error even if some
# resources are missing", and every CSI teardown call is required to be
# idempotent -- and the reason is the same in all three: the node cannot
# release a Pod it cannot finish cleaning up.  Ours treated each of these as a
# cleanup failure, which left the Pod in CleanupPending, stopped the node from
# issuing the final delete, and left the Pod Terminating in the API until every
# spec waiting for it to disappear timed out after five minutes.
class IdempotentTeardownTest < Minitest::Test
  Network = Rubernetes::Network
  Runtime = Rubernetes::Runtime
  Volume = Rubernetes::Volume

  def teardown
    FileUtils.remove_entry(@directory) if @directory && File.directory?(@directory)
  end

  # --- network topology ----------------------------------------------------

  class Topology < Network::Topology
    def initialize(failure)
      @failure = failure
      super(netlink: nil, adapter: nil)
    end

    def execute(_operation, operation_id: nil)
      raise @failure
    end
  end

  def plan_with_one_link
    operation = Network::Operation.new(
      action: "link_add", resource: "link:veth0", identity: "veth0:sandbox-1",
      parameters: {"kind" => "veth", "name" => "veth0", "peer" => "eth0"}
    )
    Network::Plan.new(operations: [operation])
  end

  def test_an_interface_that_is_already_gone_does_not_fail_the_rollback
    missing = Network::NetlinkError.new('interface "eth0" was not found while resolving link index',
                                        errno: Errno::ENODEV::Errno, operation: "resolve_interface")

    assert(Topology.new(missing).rollback(plan_with_one_link))
  end

  def test_an_errno_that_means_absent_is_tolerated
    %w[ENODEV ENOENT ESRCH ENXIO EADDRNOTAVAIL].each do |name|
      errno = Errno.const_get(name)::Errno
      error = Network::NetlinkError.new("kernel rejected link_del with errno #{errno}", errno: errno)

      assert(Topology.new(error).rollback(plan_with_one_link), "#{name} should be tolerated")
    end
  end

  # A real failure is still a failure: the node must not report a Pod cleaned
  # up when the kernel refused the request.
  def test_a_genuine_failure_still_fails_the_rollback
    denied = Network::NetlinkError.new("kernel rejected link_del with errno 1", errno: Errno::EPERM::Errno)

    assert_raises(Network::EffectError) { Topology.new(denied).rollback(plan_with_one_link) }
  end

  # --- ownership ledger ----------------------------------------------------

  def ledger_with_resource
    @directory ||= Dir.mktmpdir("teardown-ledger")
    wal = Runtime::DurableWAL.new(File.join(@directory, "ledger-#{@ledgers = (@ledgers || 0) + 1}.wal"), fsync: false)
    ledger = Runtime::ResourceLedger.new(wal: wal)
    operation = ledger.begin_operation(operation_id: "sandbox-1", owner: "sandbox-1",
                                       config_digest: Runtime::Canonical.digest(id: "sandbox-1"))
    ledger.claim(operation_id: operation.id, kind: "link", id: "link:veth0", identity: "veth0:sandbox-1")
    # force is what the teardown path passes, and it is what skips the
    # operation-state check; the identity check is the one under test here.
    [ledger, operation]
  end

  def test_a_forced_release_of_a_reclaimed_resource_is_not_a_conflict
    ledger, operation = ledger_with_resource

    # A veth name is derived from a hash and names get reused: the entry now
    # describes a different sandbox's interface.
    assert_nil(ledger.release(operation_id: operation.id, kind: "link", id: "link:veth0",
                              identity: "veth0:sandbox-2", force: true))
  end

  def test_a_forced_release_of_something_not_held_is_not_a_conflict
    ledger, operation = ledger_with_resource

    assert_nil(ledger.release(operation_id: operation.id, kind: "link", id: "link:veth9",
                              identity: "veth9:sandbox-1", force: true))
  end

  # Outside teardown a mismatch really is a bug and stays loud.
  def test_an_unforced_release_still_refuses_a_mismatch
    ledger, operation = ledger_with_resource

    assert_raises(Runtime::OwnershipConflict) do
      ledger.release(operation_id: operation.id, kind: "link", id: "link:veth0",
                     identity: "veth0:sandbox-2", force: false)
    end
  end

  def test_a_forced_release_of_an_owned_resource_still_releases_it
    ledger, operation = ledger_with_resource

    released = ledger.release(operation_id: operation.id, kind: "link", id: "link:veth0",
                              identity: "veth0:sandbox-1", force: true)

    assert_equal("Released", released.state)
  end

  # --- volume operations ---------------------------------------------------

  def test_teardown_operations_are_recognised_as_cleanup
    support = Volume::OperationSupport
    %w[delete unstage:/a unpublish:pod:/t controller-unpublish:node:1 delete-snapshot:snap].each do |operation|
      assert(support::CLEANUP_OPERATIONS.match?(operation), "#{operation} should be a cleanup operation")
    end
    %w[create stage:/a publish:pod:/t expand snapshot].each do |operation|
      refute(support::CLEANUP_OPERATIONS.match?(operation), "#{operation} must stay fenced")
    end
  end

  # The state machine already names Cleanup as permitted on an Unknown volume;
  # the teardown calls simply were not asking for it.
  def test_cleanup_is_permitted_on_an_unknown_volume
    machine = Volume::StateMachine

    assert(machine.action_allowed?("Unknown", "Cleanup"))
    refute(machine.action_allowed?("Unknown", "Mutate"))
  end
end
