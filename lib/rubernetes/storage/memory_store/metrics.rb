# frozen_string_literal: true

module Rubernetes
  module Storage
    # What the store reports as kube-apiserver's storage and watch cache.
    class MemoryStore
      # The API server's registry (Observability::Metrics): this replica plays
      # kube-apiserver's watch cache -- LISTs and watches are served from it,
      # and it receives every committed event -- so it records the cacher's
      # series (apiserver_watch_cache_*, apiserver_init_events_total,
      # apiserver_terminated_watchers_total).  nil records nothing.
      attr_accessor :metrics

      # [group, resource] of a storage key or prefix.
      def self.group_resource(key)
        parts = key.to_s.delete_prefix("/").split("/", 5)
        return ["", parts[2].to_s].freeze if parts[1].to_s.match?(/\Av\d/)

        [parts[1].to_s, parts[3].to_s].freeze
      end

      def live_object_count
        @monitor.synchronize { @live_versions.size }
      end

      # Stored objects per resource key space ("registry/<group/version>/<resource>"),
      # for apiserver_storage_objects.  Only the key list is taken under the
      # lock; it is counted outside, and only when /metrics asks.
      def object_counts
        keys = @monitor.synchronize { @live_versions.keys }
        keys.each_with_object(Hash.new(0)) do |key, counts|
          parts = key.split("/", 5)
          width = parts[1].to_s.match?(/\Av\d/) ? 3 : 4
          next if parts.length < width

          counts[parts.first(width).join("/")] += 1
        end
      end

      # apiserver_resource_size_estimate_bytes: the stored objects' encoded
      # size per resource prefix (what etcd would hold for them).
      def object_sizes
        entries = @monitor.synchronize { @live_versions.transform_values { |entries| entries.last.last } }
        entries.each_with_object(Hash.new(0)) do |(key, object), sizes|
          parts = key.split("/", 5)
          width = parts[1].to_s.match?(/\Av\d/) ? 3 : 4
          next if parts.length < width

          sizes[parts.first(width).join("/")] += JSON.generate(object).bytesize
        rescue JSON::JSONError
          next
        end
      end

      private

      # The group and resource of a storage key, "registry/<group>/<version>/
      # <resource>/..." or "registry/<version>/<resource>/..." for the core
      # group (the version segment is "__stored__" for custom resources).
      def group_resource_labels(key)
        pair = self.class.group_resource(key)
        @group_resources ||= {}
        @group_resources[pair] ||= {"group" => pair.first, "resource" => pair.last}.freeze
      end

      # cacher.dispatchEvents / watchCache.processEvent: every committed event
      # is received and dispatched once (whatever the number of watchers),
      # and the resource's cache is now at this revision.
      def record_commit(key, terminated)
        labels = group_resource_labels(key)
        # A committed entry is what the replica receives from its storage
        # (the raft log): apiserver_storage_events_received_total, then the
        # watch cache's own receipt/dispatch.
        @metrics.increment("apiserver_storage_events_received_total", labels)
        @metrics.increment("apiserver_watch_cache_events_received_total", labels)
        @metrics.increment("apiserver_watch_cache_events_dispatched_total", labels)
        @metrics.set("apiserver_watch_cache_resource_version", @revision % 1_000_000_000_000_000, labels)
        @metrics.increment("apiserver_terminated_watchers_total", labels, by: terminated) if terminated.positive?
      end

      # cacheWatcher.processInterval: the events a new watcher is sent
      # before it goes live (the current state, or the history after its
      # resourceVersion).
      def record_init_events(prefix, count)
        @metrics.increment("apiserver_init_events_total", group_resource_labels(prefix), by: count)
      end

      def record_sharded_watch(watcher, change)
        return unless @metrics && watcher.selector.shard

        @metrics.increment("apiserver_watch_shards_total", group_resource_labels(watcher.prefix), by: change)
      end

      def shard_mismatch_metric(prefix, selector)
        return unless @metrics && selector.shard

        labels = group_resource_labels(prefix)
        -> { @metrics.increment("apiserver_watch_filtered_events_total", labels) }
      end
    end
  end
end
