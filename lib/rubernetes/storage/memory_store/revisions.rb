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

      def storage_layout_revision(group)
        @monitor.synchronize do
          return [@revision, @compacted_revision] if group.empty?

          changed = @resource_revisions.fetch("registry/#{group}", 0)
          markers = @resource_revisions.fetch("rubernetes-internal/storage-keys", 0)
          [[changed, markers].max, @compacted_revision]
        end
      end

      # A deleted object can still appear in an exact LIST or a resumed WATCH.
      def prefix_has_records?(prefix)
        @monitor.synchronize do
          each_key_with_prefix_locked(prefix) do |key|
            return true if @live_versions.key?(key) || @deleted_versions.fetch(key).last.first > @compacted_revision
          end
          false
        end
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

      def current_object(key)
        @live_versions[key]&.last&.last
      end

      def versions_for(key)
        @live_versions[key] || @deleted_versions[key]
      end

      def object_at_revision(key, revision)
        return current_object(key) if revision == @revision

        entries = versions_for(key)
        return unless entries
        return entries.last[1] if entries.last[0] <= revision

        following = entries.bsearch_index { |entry| entry[0] > revision }
        entries[following - 1][1] if following.positive?
      end

      def sorted_keys_locked
        @sorted_keys ||= @live_versions.keys.concat(@deleted_versions.keys).sort!.freeze
      end

      def each_key_with_prefix_locked(prefix, after: nil)
        keys = sorted_keys_locked
        prefix_range(keys, prefix, after).each { |index| yield keys[index] }
      end

      def prefix_range(keys, prefix, after)
        start = after && after >= prefix ? after : prefix
        first = keys.bsearch_index { |key| key >= start } || keys.size
        first += 1 if after && keys[first] == after
        last = keys.bsearch_index { |key| key > prefix && !key.start_with?(prefix) } || keys.size
        first...last
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
