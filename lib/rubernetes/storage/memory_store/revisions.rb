# frozen_string_literal: true

module Rubernetes
  module Storage
    # The revision counters, snapshot lookups and the sorted key index behind reads.
    class MemoryStore
      def revision
        @monitor.synchronize { @revision }
      end
      alias resource_version revision
      alias current_revision revision

      def compacted_revision
        @monitor.synchronize { @compacted_revision }
      end

      # The revision of the last write under a key space -- the first two
      # path components of the prefix ("registry/clusterroles" for
      # "registry/clusterroles/_cluster/", whatever the namespace or name that
      # follow).  A reader caching a resource's objects compares this instead
      # of the global revision, which every write to any resource advances:
      # the RBAC authorizer re-listed every ClusterRole on every request
      # because something, somewhere, had always just changed.  A prefix
      # shorter than a key space answers with the global revision.
      def revision_under(prefix)
        @monitor.synchronize do
          bucket = resource_bucket(prefix)
          bucket ? @resource_revisions.fetch(bucket, 0) : @revision
        end
      end

      def resource_version_string
        revision.to_s
      end

      def resourceVersion
        resource_version_string
      end

      def compacted?
        @monitor.synchronize { @compacted_revision.positive? }
      end

      private

      def object_revision(object)
        parse_revision(object.dig("metadata", "resourceVersion"))
      end

      def parse_revision(value)
        revision = Integer(value)
        raise InvalidResourceVersion, "resourceVersion must be non-negative" if revision.negative?

        revision
      rescue TypeError, ArgumentError
        raise InvalidResourceVersion, "resourceVersion must be a non-negative integer"
      end

      def resolve_read_revision(value)
        return @revision if value.nil? || value == "" || value == 0 || value == "0"

        revision = parse_revision(value)
        raise InvalidResourceVersion, "resourceVersion #{revision} is ahead of current revision #{@revision}" if revision > @revision

        ensure_snapshot_available!(revision)
        revision
      end

      def ensure_snapshot_available!(revision)
        return if revision >= @compacted_revision

        raise Gone.new(revision, @compacted_revision)
      end

      def object_at_revision(key, revision)
        entries = @versions[key]
        return nil if entries.nil? || entries.empty?

        entry = entries.reverse_each.find { |candidate| candidate[0] <= revision }
        entry && entry[1]
      end

      # Every key the store has ever held, sorted, memoised until a key is
      # added.  A list used to sort the whole key set and scan it for the
      # prefix on every call -- O(N log N) per list over every key ever
      # written, which put a ResourceQuota admission check at 20 ms once a
      # conformance run had created a few thousand objects.  Updates and
      # deletes leave the key set alone, so the sorted array survives them,
      # and a prefix is then a binary search plus a scan of its own keys.
      def sorted_keys_locked
        @sorted_keys ||= @known_keys.keys.sort!.freeze
      end

      # Keys starting with prefix, in order, all greater than `after` when given.
      def keys_with_prefix_locked(prefix, after: nil)
        sorted = sorted_keys_locked
        start = after && after >= prefix ? after : prefix
        index = sorted.bsearch_index { |key| key >= start } || sorted.length
        index += 1 if after && index < sorted.length && sorted[index] == after
        result = []
        while index < sorted.length && sorted[index].start_with?(prefix)
          result << sorted[index]
          index += 1
        end
        result
      end

      # "registry/<resource>" for a key or prefix; nil when it is shorter.
      def resource_bucket(key)
        parts = key.to_s.delete_prefix("/").split("/", 3)
        return nil if parts.length < 2 || parts[1].empty?

        "#{parts[0]}/#{parts[1]}"
      end
    end
  end
end
