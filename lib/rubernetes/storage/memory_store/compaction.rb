# frozen_string_literal: true

module Rubernetes
  module Storage
    # History retention: what may be dropped, and dropping it.
    class MemoryStore
      def compact!(revision: nil, to_revision: nil, before_revision: nil, before: nil, through: nil, at_time: nil, now: nil)
        requested_revision = revision || to_revision || before_revision || before || through
        @monitor.synchronize do
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
        return 0 if @revision.zero?

        timestamp = now.nil? ? clock_value : now.to_f
        revision_target = @history_revisions.nil? ? nil : @revision - @history_revisions
        time_target = if @history_seconds.nil?
                        nil
                      else
                        cutoff = timestamp - @history_seconds
                        first_newer_index = @history.bsearch_index { |mutation| mutation.timestamp >= cutoff }
                        if first_newer_index.nil?
                          @history.last&.revision
                        elsif first_newer_index.zero?
                          nil
                        else
                          @history[first_newer_index - 1].revision
                        end
                      end
        # Either rule on its own makes history droppable: the time window is
        # the retention promise (etcd's compaction interval) and the revision
        # count is a memory cap.  Taking the minimum let the cap veto the
        # window -- with a 100k revision cap on a young store the revision
        # target is negative, so nothing was ever compacted and no continue
        # token or watch resourceVersion ever expired.
        [[revision_target, time_target].compact.max || 0, 0].max
      end

      def compact_locked!(target, key_to_prune: nil, prune_all_versions: false)
        target = [target, @revision].min
        return @compacted_revision if target <= @compacted_revision

        @history = @history.drop_while { |mutation| mutation.revision <= target }
        if prune_all_versions
          @versions.keys.each { |key| prune_version_history_locked(key, target) }
          # Request replay memory (S6) follows the same retention as history:
          # a retry arrives within seconds, and remembering every write's
          # result for ever kept a whole run's objects resident -- the heap
          # behind the multi-second GC pauses that timed out read barriers.
          @requests.delete_if { |_uid, stored| stored.revision <= target }
        elsif key_to_prune
          prune_version_history_locked(key_to_prune, target)
        end
        @compacted_revision = target
      end

      def prune_version_history_locked(key, target)
        entries = @versions[key]
        return if entries.nil? || entries.empty?

        first_newer_index = entries.index { |entry| entry[0] > target }
        if first_newer_index.nil?
          # Everything is older than the window: a deleted key needs no
          # history at all, a live one only its current version.
          if entries.last[1].nil?
            @versions.delete(key)
          elsif entries.length > 1
            @versions[key] = [entries.last]
          end
          return
        end
        return if first_newer_index.zero? || entries.length < 2

        baseline = entries[first_newer_index - 1]
        @versions[key] = [baseline, *entries[first_newer_index..]]
      end
    end
  end
end
