# frozen_string_literal: true

module Rubernetes
  module API
    # Encoding can change while the identity of a stored object stays fixed.
    # Adopt a single legacy key prefix in place before writing to it. Multiple
    # populated prefixes require operator reconciliation before access.
    class StorageKeyLayout
      Selection = Data.define(:revision, :gvr, :persist_on_write)

      def initialize(store)
        @store = store
        @layouts = {}
        @mutex = Mutex.new
        @revision = store.method(:storage_layout_revision)
        @prefix_has_records = store.method(:prefix_has_records?)
      rescue NameError
        @prefix_has_records = ->(prefix) { store.list(prefix, limit: 1).items.any? }
      end

      def resolve(preferred, versions, write: false)
        return preferred if versions.empty?

        revision = @revision&.call(preferred.group)
        cache_key = [preferred, versions]
        selected = @mutex.synchronize { @layouts[cache_key] }
        unless revision && selected&.revision == revision
          selected = discover(preferred, versions, revision)
          @mutex.synchronize { @layouts[cache_key] = selected } if revision
        end
        record(preferred, selected.gvr) if write && selected.persist_on_write
        selected.gvr
      end

      # A legacy server may create this name after discovery but before the
      # newer server's transaction commits. Compare every other physical key
      # inside the same commit as creation and its admission preconditions.
      def guard_create(selected, versions, preconditions)
        guards = (preconditions || {}).dup
        versions.each do |version|
          next if version == selected.version

          candidate = GVR.new(group: selected.group, version: version, resource: selected.resource)
          guards[yield(candidate)] = nil
        end
        guards
      end

      private

      def discover(preferred, versions, revision)
        candidates = (versions + [preferred.version]).uniq.to_h do |version|
          [version, GVR.new(group: preferred.group, version: version, resource: preferred.resource)]
        end
        occupied = candidates.values.select { |candidate| @prefix_has_records.call(prefix(candidate)) }
        marker = recorded_version(preferred)
        chosen = candidates[marker] if marker
        if (marker && !chosen) || occupied.length > 1 || (chosen && occupied.any? { |candidate| candidate != chosen })
          conflict!(preferred, occupied.map { |candidate| prefix(candidate) }, marker)
        end

        selected = chosen || occupied.first || preferred
        Selection.new(revision: revision, gvr: selected, persist_on_write: marker.nil? && selected != preferred)
      end

      def record(preferred, selected)
        @store.create(marker_key(preferred), {"metadata" => {"name" => preferred.resource}, "version" => selected.version})
      rescue MemoryStore::AlreadyExists, Storage::AlreadyExists
        marker = recorded_version(preferred)
        return if marker == selected.version

        conflict!(preferred, [prefix(selected)], marker)
      end

      def recorded_version(preferred)
        record = @store.get(marker_key(preferred))
        record.fetch("version", "").to_s
      rescue MemoryStore::NotFound, Storage::NotFound
        nil
      end

      def marker_key(gvr)
        group = gvr.group.empty? ? "core" : gvr.group
        "rubernetes-internal/storage-keys/#{group}/#{gvr.resource}"
      end

      def prefix(gvr) = "registry/#{gvr}/"

      def conflict!(preferred, occupied, marker)
        suffix = marker ? ", pinned version #{marker}" : ""
        raise Status::Conflict.new("storage keys for #{preferred.resource}.#{preferred.group} require reconciliation " \
                                   "(populated prefixes #{occupied.join(", ")}#{suffix}); preserve the records and " \
                                   "resolve the layout before serving this resource")
      end
    end
  end
end
