# frozen_string_literal: true

require_relative "errors"
require_relative "canonical"
require_relative "wal"

module Rubernetes
  module Consensus
    # 1-indexed replicated log.  Entries are {term, index, command}; committed
    # entries are never modified; entries below the snapshot index are
    # discarded after compaction.  Every mutation is persisted to the WAL
    # before it becomes visible to the caller.
    class Log
      Entry = Data.define(:index, :term, :command) do
        def to_h
          {"index" => index, "term" => term, "command" => command}
        end

        def self.from_h(value)
          raise WALCorruption, "log entry must be an object" unless value.is_a?(Hash)

          index = value["index"]
          term = value["term"]
          unless index.is_a?(Integer) && index.positive? && term.is_a?(Integer) && term >= 0
            raise WALCorruption,
                  "log entry index/term must be positive integers"
          end

          new(index: index, term: term, command: value["command"])
        end

        def bytesize
          Canonical.encode(command).bytesize
        end
      end

      attr_reader :snapshot_index, :snapshot_term, :current_term, :voted_for

      def initialize(wal)
        @wal = wal
        @entries = []
        @snapshot_index = 0
        @snapshot_term = 0
        @current_term = 0
        @voted_for = nil
        @mutex = Monitor.new
        # Held for the duration of a sync and while the WAL is swapped by a
        # rotation, never by #append: a sync runs beside appends.
        @sync_lock = Mutex.new
        replay(@wal.records)
      end

      def first_index
        @snapshot_index + 1
      end

      def last_index
        @mutex.synchronize { @entries.empty? ? @snapshot_index : @entries.last.index }
      end

      def last_term
        @mutex.synchronize { @entries.empty? ? @snapshot_term : @entries.last.term }
      end

      def length
        @mutex.synchronize { @entries.length }
      end

      def term_at(index)
        @mutex.synchronize do
          return 0 if index.zero?
          return @snapshot_term if index == @snapshot_index
          return nil if index < @snapshot_index

          entry = entry_at(index)
          entry&.term
        end
      end

      def entry_at(index)
        @mutex.synchronize do
          position = index - @snapshot_index - 1
          return nil if position.negative? || position >= @entries.length

          @entries[position]
        end
      end

      def entries_from(index, max_count: nil, max_bytes: nil)
        @mutex.synchronize do
          position = index - @snapshot_index - 1
          return [] if position >= @entries.length
          raise ArgumentError, "index #{index} is compacted" if position.negative?

          selected = []
          bytes = 0
          @entries[position..].each do |entry|
            break if max_count && selected.length >= max_count

            size = entry.bytesize
            break if max_bytes && !selected.empty? && bytes + size > max_bytes

            selected << entry
            bytes += size
          end
          selected
        end
      end

      def entries
        @mutex.synchronize { @entries.dup }
      end

      # Persist currentTerm/votedFor.  Must complete before any vote or log
      # response is sent (spec 5.3.2).
      def save_hard_state(term:, voted_for:)
        @mutex.synchronize do
          return if term == @current_term && voted_for == @voted_for

          @wal.append([WAL::TYPE_HARD_STATE, {"term" => term, "voted_for" => voted_for}])
          @current_term = term
          @voted_for = voted_for
        end
      end

      # Append entries at the tail.  Each entry index must be contiguous.
      def append(new_entries, sync: true)
        new_entries = Array(new_entries)
        return true if new_entries.empty?

        @mutex.synchronize do
          expected = last_index + 1
          new_entries.each do |entry|
            raise ArgumentError, "entry index #{entry.index} is not contiguous (expected #{expected})" unless entry.index == expected

            expected += 1
          end
          @wal.append(new_entries.map { |entry| [WAL::TYPE_ENTRY, entry.to_h] }, sync: sync)
          @entries.concat(new_entries)
        end
        true
      end

      # Makes entries appended with +sync: false+ durable.  Not under the
      # log's monitor: the WAL orders its own writes and fsyncs, so entries
      # keep being appended while this waits on the disk.
      def sync
        @sync_lock.synchronize { @wal.sync }
      end

      # Storage#rotate! installs the rewritten WAL; a sync in flight on the
      # old file completes first.
      def replace_wal(wal)
        @sync_lock.synchronize { @mutex.synchronize { @wal = wal } }
      end

      # Delete every entry from `index` onwards (a follower conflict).
      def truncate_from(index)
        @mutex.synchronize do
          raise ArgumentError, "cannot truncate compacted index #{index}" if index <= @snapshot_index
          return true if index > last_index

          @wal.append([WAL::TYPE_TRUNCATE, {"from_index" => index}])
          @entries.slice!((index - @snapshot_index - 1)..)
        end
        true
      end

      # Discard entries covered by a snapshot.  The snapshot itself must be
      # durable before this is called.
      def compact_to(index:, term:)
        @mutex.synchronize do
          return true if index <= @snapshot_index

          @wal.append([WAL::TYPE_COMPACT, {"index" => index, "term" => term}])
          apply_compaction(index, term)
        end
        true
      end

      # Whether the follower log matches the leader at prev_index/prev_term.
      def matches?(prev_index, prev_term)
        return true if prev_index.zero?

        term = term_at(prev_index)
        !term.nil? && term == prev_term
      end

      # Election restriction (spec 5.4.1): candidate log is at least as
      # up to date as ours.
      def up_to_date?(candidate_last_index, candidate_last_term)
        return candidate_last_index >= last_index if candidate_last_term == last_term

        candidate_last_term > last_term
      end

      private

      def replay(records)
        records.each do |record|
          case record.type
          when WAL::TYPE_HARD_STATE
            @current_term = Integer(record.payload.fetch("term"))
            voted = record.payload["voted_for"]
            @voted_for = voted.nil? ? nil : String(voted)
          when WAL::TYPE_ENTRY
            entry = Entry.from_h(record.payload)
            if entry.index <= @snapshot_index
              next
            elsif entry.index == last_index + 1
              @entries << entry
            else
              raise WALCorruption.new("WAL entry #{entry.index} is not contiguous with #{last_index}", path: @wal.path,
                                                                                                       offset: record.offset)
            end
          when WAL::TYPE_TRUNCATE
            from = Integer(record.payload.fetch("from_index"))
            raise WALCorruption.new("WAL truncation below snapshot", path: @wal.path, offset: record.offset) if from <= @snapshot_index

            position = from - @snapshot_index - 1
            @entries.slice!(position..) if position < @entries.length
          when WAL::TYPE_COMPACT
            apply_compaction(Integer(record.payload.fetch("index")), Integer(record.payload.fetch("term")))
          end
        end
      rescue KeyError, TypeError, ArgumentError => error
        raise WALCorruption.new("WAL replay failed: #{error.message}", path: @wal.path)
      end

      def apply_compaction(index, term)
        return if index <= @snapshot_index

        if index <= last_index
          existing = term_at(index)
          @entries.slice!(0, index - @snapshot_index)
          @snapshot_term = existing.nil? ? term : existing
        else
          @entries.clear
          @snapshot_term = term
        end
        @snapshot_index = index
      end
    end
  end
end
