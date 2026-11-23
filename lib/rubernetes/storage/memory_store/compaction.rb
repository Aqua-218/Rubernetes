# frozen_string_literal: true

module Rubernetes
  module Storage
    # History retention: what may be dropped, and dropping it.
    class MemoryStore
      def compact!(revision: nil, to_revision: nil, before_revision: nil, before: nil, through: nil, at_time: nil, now: nil)
        requested_revision = revision || to_revision || before_revision || before || through
        @monitor.synchronize do
          ensure_writes_enabled!

          target = requested_revision.nil? ? compaction_target_locked(now: at_time || now) : parse_revision(requested_revision)
          raise InvalidResourceVersion, "cannot compact beyond current revision #{@revision}" if target > @revision

          compact_locked!(target, prune_all_versions: true)
          @compacted_revision
        end
      end

      alias compact compact!

      private

      def clock_value
        @clock.call.to_f
      end

      def compaction_target_locked(now: nil)
        revision_target = @revision - @history_revisions if @history_revisions
        return [revision_target || 0, @compacted_revision].max unless @history_seconds

        if @retain_longer_window
          # A mutation must also fall outside the revision window. Stop before
          # scanning versions that the count window would keep on every write.
          target = @compacted_revision
          limit = revision_target || @revision
        else
          # The cap already drops this prefix. After a rollback, more
          # mutations older than the age window may be exposed behind it.
          target = [revision_target || 0, @compacted_revision].max
          limit = @revision
        end
        return target if target >= limit

        cutoff = (now.nil? ? clock_value : now.to_f) - @history_seconds
        # Inspect only the contiguous expired prefix. A later mutation can
        # have an earlier wall-clock timestamp after a rollback or election.
        index = history_offset_after(target)
        while (mutation = @history[index]) && mutation.revision <= limit
          break if mutation.timestamp.nil? || mutation.timestamp >= cutoff

          target = mutation.revision
          index += 1
        end
        target
      end

      def history_offset_after(revision)
        return 0 if revision <= @compacted_revision

        # Every successful write adds one mutation at the next revision.
        offset = revision - @compacted_revision
        return offset if offset <= @history.length && @history[offset - 1].revision == revision

        @history.bsearch_index { |mutation| mutation.revision > revision } || @history.length
      end

      def compact_locked!(target, prune_all_versions: false)
        target = [target, @revision].min
        return @compacted_revision if target <= @compacted_revision

        expired = @history.shift(history_offset_after(target))
        if prune_all_versions
          @live_versions.each_key { |key| prune_version_history_locked(key, target) }
          @deleted_versions.keys.each { |key| prune_version_history_locked(key, target) }
        else
          # The revision cap may expire keys that will never be written again.
          expired.map(&:key).uniq.each { |key| prune_version_history_locked(key, target) }
        end
        if @retain_longer_window
          # Requests are inserted in revision order. Discard just the expired
          # entries, even when a write advances the boundary by one revision.
          while (first = @requests.first) && first.last.revision.to_i <= target
            @requests.shift
          end
        elsif prune_all_versions
          # Compatibility mode prunes request replay at each full compaction.
          @requests.delete_if { |_uid, stored| stored.revision <= target }
        end
        @compacted_revision = target
      end

      def prune_version_history_locked(key, target)
        entries = versions_for(key)
        return if entries.nil? || entries.empty?

        first_newer_index = entries.bsearch_index { |entry| entry[0] > target }
        if first_newer_index.nil?
          # Everything is older than the window: a deleted key needs no
          # history at all, a live one only its current version.
          if entries.last[1].nil?
            @deleted_versions.delete(key)
            @sorted_keys = nil
          elsif entries.length > 1
            @live_versions[key] = [entries.last]
          end
          return
        end
        # Keep the baseline at the retention boundary and every later write.
        entries.shift(first_newer_index - 1) if first_newer_index > 1
      end
    end
  end
end
