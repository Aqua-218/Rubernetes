# frozen_string_literal: true

require_relative "support/autoload"

module Rubernetes
  module Consensus
    files = {
      "backup" => %i[Backup],
      "canonical" => %i[Canonical],
      "crc32c" => %i[CRC32C],
      "errors" => %i[AppliedThroughSnapshot CorruptionError DiskFull DurabilityError Error FrameTooLarge FsyncFailed InvalidCommand
                     MembershipError NotLeader NotReady PeerIdentityMismatch ProposalDropped ProtocolError RecoveryRequired ShortWrite SnapshotCorruption
                     StorageFailed Timeout TornWAL TransportError WALCorruption],
      "identity" => %i[Identity],
      "log" => %i[Log],
      "membership" => %i[Membership],
      "messages" => %i[Messages],
      "node" => %i[Node],
      "operation_journal" => %i[OperationJournal],
      "raft_store" => %i[RaftStore],
      "seed" => %i[Seed],
      "server" => %i[Server],
      "snapshot" => %i[SnapshotStore],
      "state_machine" => %i[KVStateMachine],
      "storage" => %i[Storage],
      "transport" => %i[Transport],
      "wal" => %i[WAL]
    }
    Autoload.register(self, File.join(__dir__, "consensus"), files)
  end
end
