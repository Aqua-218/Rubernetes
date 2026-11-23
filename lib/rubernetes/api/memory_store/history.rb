# frozen_string_literal: true

module Rubernetes
  module API
    class MemoryStore
      def storage_layout_revision(_group) = @mutex.synchronize { [@revision, @compacted_revision] }

      def prefix_has_records?(prefix)
        @mutex.synchronize do
          @objects.any? { |key, object| object && key.start_with?(prefix) } || @history.any? { |event| event.key.start_with?(prefix) }
        end
      end

      private

      # Advance the compaction floor once per interval to the revision that
      # was current at the previous tick, so a revision stays addressable for
      # between one and two intervals, as etcd's periodic compaction does.
      # Called with the store mutex held.
      def compact_if_due!
        return unless @compaction_interval

        now = monotonic_now
        return if now - @last_compaction_at < @compaction_interval

        @last_compaction_at = now
        @compacted_revision = [@compacted_revision, @compaction_floor_candidate].max
        @compaction_floor_candidate = @revision
        @history.shift while @history.first && event_revision(@history.first) <= @compacted_revision
      end

      def append_event(event)
        @history << event
        while @history.length > @history_limit
          dropped = @history.shift
          @compacted_revision = [@compacted_revision, event_revision(dropped)].max
        end
      end
    end
  end
end
