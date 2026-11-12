# frozen_string_literal: true

require_relative "membership"
require_relative "snapshot"
require_relative "state_machine"

module Rubernetes
  module Consensus
    # Starts a raft datastore from the contents of a memory store: the way a
    # cluster that ran on the in-memory datastore moves to the replicated one
    # without losing an object, a resourceVersion or a UID.
    #
    # A raft replica's state is a memory store plus the log position it was
    # at.  The exported state therefore only needs a position: it is written
    # as the snapshot at index 1 of an otherwise empty data directory, and a
    # node started on that directory recovers it as it recovers any
    # snapshot.  Further voters are added to the running node afterwards.
    module Seed
      module_function

      # state: Storage::MemoryStore#export_state.  Returns the snapshot's
      # metadata.
      def write(data_directory:, state:, voters:)
        if Dir.exist?(data_directory) && !Dir.empty?(data_directory)
          raise ArgumentError, "#{data_directory} is not empty: a datastore is seeded once, before its first start"
        end

        # Without "effects" the replica starts its apply invariant from what
        # the snapshot holds.
        document = state.merge("applied_index" => 1, "clock_value" => 0.0)
        SnapshotStore.new(File.join(data_directory, "snapshots"))
          .write(state: KVStateMachine.encode_snapshot(document), index: 1, term: 1, membership: Membership.simple(voters).to_h)
      end
    end
  end
end
