# frozen_string_literal: true

module Rubernetes
  # Raft-based durable store: WAL, snapshot, replication, membership and the
  # Store contract implementation.  Every failure that can compromise safety
  # is a distinct error class so callers cannot mistake a durability failure
  # for a transient condition.
  module Consensus
    class Error < StandardError; end

    # Durable storage errors.  A node that observes one of these must stop
    # acknowledging writes: the WAL or snapshot can no longer be trusted.
    class DurabilityError < Error; end
    class DiskFull < DurabilityError; end
    class ShortWrite < DurabilityError; end
    class FsyncFailed < DurabilityError; end
    class StorageFailed < DurabilityError; end

    # Content that fails a checksum, a bound, or a structural check.  The
    # affected bytes are never partially applied.
    class CorruptionError < Error
      attr_reader :path, :offset

      def initialize(message, path: nil, offset: nil)
        @path = path
        @offset = offset
        super(message)
      end
    end
    class WALCorruption < CorruptionError; end
    class TornWAL < WALCorruption; end
    class SnapshotCorruption < CorruptionError; end

    # Transport and protocol errors.
    class TransportError < Error; end
    class FrameTooLarge < TransportError; end
    class PeerIdentityMismatch < TransportError; end
    class ProtocolError < TransportError; end

    # Client-facing consensus outcomes.
    class NotLeader < Error
      attr_reader :leader_id

      def initialize(message = "this node is not the leader", leader_id: nil)
        @leader_id = leader_id
        super(message)
      end
    end
    class ProposalDropped < Error; end
    # The entry was committed and applied on this node through a snapshot
    # install, so no apply result exists here: the outcome is unknown to
    # this node and the caller must not wait for one.
    class AppliedThroughSnapshot < ProposalDropped; end
    class Timeout < Error; end
    class NotReady < Error; end
    class MembershipError < Error; end
    class InvalidCommand < Error; end
    class RecoveryRequired < Error; end
  end
end
