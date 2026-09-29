# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "monitor"
require "securerandom"

module Rubernetes
  module Volume
    # A small append-by-replace snapshot catalog.  Snapshot metadata is part
    # of the volume lifecycle and must survive an agent restart; keeping the
    # default catalog in a plain Hash made an acknowledged snapshot disappear
    # before CSI reconciliation could classify it as Unknown.
    class DurableSnapshotStore
      def initialize(path:, fsync: true)
        @path = File.expand_path(String(path))
        @fsync = fsync == true
        @mutex = Monitor.new
        @values = load!
      end

      attr_reader :path

      def [](id)
        @mutex.synchronize { @values[id.to_s] }
      end

      def []=(id, value)
        @mutex.synchronize do
          key = id.to_s
          existed = @values.key?(key)
          previous = @values[key]
          @values[key] = value
          begin
            persist!
          rescue StandardError
            existed ? @values[key] = previous : @values.delete(key)
            raise
          end
        end
      end

      def delete(id)
        @mutex.synchronize do
          key = id.to_s
          existed = @values.key?(key)
          value = @values.delete(key)
          begin
            persist!
          rescue StandardError
            @values[key] = value if existed
            raise
          end
          value
        end
      end

      def fetch(id, &fallback)
        @mutex.synchronize { @values.fetch(id.to_s, &fallback) }
      end

      def values
        @mutex.synchronize { @values.values.dup.freeze }
      end

      private

      def load!
        return {} unless File.file?(@path)

        raw = JSON.parse(File.binread(@path))
        raise JournalError, "snapshot store must contain a map" unless raw.is_a?(Hash)

        raw.each_with_object({}) do |(id, value), result|
          hash = value.transform_keys(&:to_s)
          result[id.to_s] = SnapshotRecord.new(
            id: hash.fetch("id", id), source_id: hash.fetch("sourceId"), name: hash["name"],
            size_bytes: hash.fetch("sizeBytes", 0), ready_to_use: hash.fetch("readyToUse", false),
            content: hash["content"], identity: hash["identity"], created_at: hash.fetch("createdAt"),
            metadata: hash.fetch("metadata", {})
          )
        end
      rescue JSON::ParserError, KeyError, TypeError, ArgumentError => error
        raise JournalError, "snapshot store is corrupt: #{error.message}"
      end

      def persist!
        FileUtils.mkdir_p(File.dirname(@path))
        temporary = "#{@path}.tmp-#{Process.pid}-#{SecureRandom.hex(6)}"
        payload = @values.transform_values { |value| value.respond_to?(:to_h) ? value.to_h : value }
        File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
          file.write(JSON.generate(payload))
          file.flush
          file.fsync if @fsync
        end
        File.rename(temporary, @path)
        if @fsync
          directory = File.open(File.dirname(@path), File::RDONLY)
          begin
            directory.fsync
          ensure
            directory.close
          end
        end
        true
      rescue SystemCallError, IOError => error
        File.delete(temporary) if temporary && File.exist?(temporary)
        raise JournalError, "snapshot store persist failed: #{error.message}"
      end
    end

    class SnapshotManager
      def initialize(backend_lookup:, record_lookup: nil, create_volume: nil, restore_volume: nil, clone_volume: nil,
                     store: nil, csi: nil, clock: -> { Time.now.utc }, error_sanitizer: nil)
        @backend_lookup = backend_lookup
        @record_lookup = record_lookup
        @create_volume = create_volume
        @restore_volume = restore_volume
        @clone_volume = clone_volume
        @store = store || {}
        @csi = csi
        @clock = clock
        @error_sanitizer = error_sanitizer
        @mutex = Monitor.new
      end

      attr_reader :store

      def create(volume_id, token:, name: nil, allow_published: false, effect_boundary: nil)
        volume = @backend_lookup.call(volume_id)
        raise NotFoundError, "volume #{volume_id} does not exist" unless volume
        if volume.respond_to?(:secret?) && volume.secret?
          raise UnsupportedError, "Secret-backed volumes cannot be snapshotted"
        end
        record = @record_lookup&.call(volume_id)
        if !allow_published && record && !record.publishes.empty?
          raise ConflictError, "volume #{volume_id} is published; stop consumers before snapshot"
        end
        remote = volume.respond_to?(:remote?) && volume.remote?
        source = if remote
                   volume.snapshot(token: token, name: name, effect_boundary: effect_boundary)
                 elsif volume.respond_to?(:snapshot)
                   volume.snapshot
                 else
                   {}
                 end
        source = AdapterSupport.result_hash(source)
        id = source["snapshotId"] || "snap-#{Digest::SHA256.hexdigest("#{volume_id}\0#{token}")[0, 24]}"
        content = sanitize_content(source["content"], secret: volume.respond_to?(:secret?) && volume.secret?)
        metadata = {"backend" => volume.type.to_s, "remote" => remote}
        # Digests are computed over the catalogued bytes so a restore can
        # prove the catalog was not altered at rest (SnapshotIntegrityError).
        unless content.nil?
          metadata["contentSha256"] = source["contentSha256"] || Backend.content_digests(content)
          metadata["contentDigest"] = source["contentDigest"] || Backend.content_digest(content)
        end
        record = SnapshotRecord.new(id: id, source_id: volume_id, name: name,
                                    size_bytes: source["sizeBytes"] || source["size_bytes"] || 0,
                                    ready_to_use: source.key?("readyToUse") ? source["readyToUse"] == true : true,
                                    content: content,
                                    identity: {"source" => volume_id, "nonce" => SecureRandom.hex(16)},
                                    metadata: metadata)
        @mutex.synchronize { @store[record.id] = record }
        record
      rescue StandardError => error
        if remote && id && volume
          begin
            volume.delete_snapshot(id, token: "snapshot-compensate-#{token}")
            effect_boundary&.call(:compensated)
          rescue StandardError => cleanup_error
            raise OperationUnknown.new(
              "snapshot catalog persistence failed and CSI cleanup is ambiguous for #{id}: #{safe_error_message(cleanup_error)}"
            ), cause: safe_error(error)
          end
        end
        sanitized = safe_error(error)
        raise sanitized, cause: nil
      end

      def delete(snapshot_id, token:, effect_boundary: nil)
        snapshot = fetch(snapshot_id)
        volume = @backend_lookup.call(snapshot.source_id)
        remote = remote_snapshot?(snapshot)
        volume.delete_snapshot(snapshot.id, token: token, effect_boundary: effect_boundary) if remote
        @mutex.synchronize { @store.delete(snapshot.id) }
        true
      rescue StandardError => error
        mark_unknown(snapshot_id, reason: safe_error_message(error)) if snapshot && remote
        sanitized = safe_error(error)
        raise sanitized, cause: nil
      end

      def restore(snapshot_id, spec: {}, token:)
        snapshot = fetch(snapshot_id)
        raise StateUnknownError, "snapshot #{snapshot_id} is Unknown; reconcile before restore" if unknown?(snapshot)
        raise ConflictError, "snapshot #{snapshot_id} is not ready" unless snapshot.ready_to_use
        spec = Types.deep_copy(spec).merge("snapshot" => snapshot.to_h, "sourceSnapshotId" => snapshot.id)
        if @restore_volume
          @restore_volume.call(spec, snapshot: snapshot, token: token)
        elsif @create_volume
          @create_volume.call(spec, token: token)
        else
          raise UnsupportedError, "snapshot restore requires a volume creation callback"
        end
      end

      def clone(volume_id, spec: {}, token:)
        source = @backend_lookup.call(volume_id)
        raise NotFoundError, "volume #{volume_id} does not exist" unless source
        if source.respond_to?(:secret?) && source.secret?
          raise UnsupportedError, "Secret-backed volumes cannot be cloned"
        end
        record = @record_lookup&.call(volume_id)
        raise ConflictError, "volume #{volume_id} is published; stop consumers before clone" if record && !record.publishes.empty?
        spec = Types.deep_copy(spec).merge("cloneSourceId" => volume_id)
        if @clone_volume
          @clone_volume.call(source_id: volume_id, spec: spec, token: token)
        elsif @create_volume
          @create_volume.call(spec, token: token)
        else
          raise UnsupportedError, "volume clone requires a volume creation callback"
        end
      end

      # Reconcile the durable catalog against the CSI ListSnapshots result.
      # A missing remote object is not treated as deletion: the local record
      # is fenced as Unknown until an operator/recovery path resolves it.
      def reconcile(entries: nil, error: nil)
        return reconcile_unknown(error) if error
        return {"unknown" => [], "observed" => []} if entries.nil?

        remote_entries = Array(AdapterSupport.result_hash(entries)["entries"] || entries).each_with_object({}) do |entry, result|
          hash = AdapterSupport.result_hash(entry)
          id = hash["snapshotId"] || hash["snapshot_id"] || hash["id"]
          result[id.to_s] = hash if id
        end
        remote = remote_entries.keys
        unknown = []
        resolved = []
        @mutex.synchronize do
          @store.values.each do |record|
            next unless remote_snapshot?(record)

            if remote_entries.key?(record.id)
              if unknown?(record)
                observed = remote_entries.fetch(record.id)
                replacement = SnapshotRecord.new(
                  id: record.id, source_id: record.source_id, name: record.name,
                  size_bytes: observed["sizeBytes"] || record.size_bytes,
                  ready_to_use: observed.key?("readyToUse") ? observed["readyToUse"] == true : true,
                  content: record.content, identity: record.identity, created_at: record.created_at,
                  metadata: record.metadata.reject { |key, _| %w[state reason].include?(key.to_s) }
                )
                @store[record.id] = replacement
                resolved << record.id
              end
              next
            end
            next if unknown?(record)

            replacement = SnapshotRecord.new(
              id: record.id, source_id: record.source_id, name: record.name,
              size_bytes: record.size_bytes, ready_to_use: false, content: record.content,
              identity: record.identity, created_at: record.created_at,
              metadata: record.metadata.merge("state" => "Unknown", "reason" => "missing from CSI ListSnapshots")
            )
            @store[record.id] = replacement
            unknown << record.id
          end
        end
        # Durable stores persist through []=; plain injected stores remain
        # useful for narrow tests without widening the lifecycle contract.
        {"unknown" => unknown.freeze, "observed" => remote.freeze, "resolved" => resolved.freeze}
      end

      def fetch(snapshot_id)
        @mutex.synchronize { @store.fetch(snapshot_id.to_s) { raise NotFoundError, "snapshot #{snapshot_id} does not exist" } }
      end

      def list
        @mutex.synchronize { @store.values.dup.freeze }
      end

      def mark_unknown(snapshot_id, reason:)
        @mutex.synchronize do
          record = @store[snapshot_id.to_s]
          return nil unless record

          replacement = SnapshotRecord.new(
            id: record.id, source_id: record.source_id, name: record.name,
            size_bytes: record.size_bytes, ready_to_use: false, content: record.content,
            identity: record.identity, created_at: record.created_at,
            metadata: record.metadata.merge("state" => "Unknown", "reason" => safe_error_message(reason))
          )
          @store[record.id] = replacement
          replacement
        end
      end

      private

      def unknown?(snapshot)
        Types.key(snapshot.metadata, "state", "Ready") == "Unknown"
      end

      def remote_snapshot?(snapshot)
        metadata = snapshot.metadata
        return Types.key(metadata, "remote") == true if metadata.key?("remote") || metadata.key?(:remote)
        return Types.key(metadata, "backend").to_s.casecmp?("csi") if Types.present?(Types.key(metadata, "backend"))

        source_record = @record_lookup&.call(snapshot.source_id)
        source_record && source_record.backend.to_s.casecmp?("csi")
      rescue NotFoundError, StateUnknownError
        false
      end

      def reconcile_unknown(error)
        safe_message = safe_error_message(error)
        unknown = []
        @mutex.synchronize do
          @store.values.each do |record|
            next unless remote_snapshot?(record)
            next if unknown?(record)
            replacement = SnapshotRecord.new(
              id: record.id, source_id: record.source_id, name: record.name,
              size_bytes: record.size_bytes, ready_to_use: false, content: record.content,
              identity: record.identity, created_at: record.created_at,
              metadata: record.metadata.merge("state" => "Unknown", "reason" => safe_message)
            )
            @store[record.id] = replacement
            unknown << record.id
          end
        end
        {"unknown" => unknown.freeze, "observed" => [], "error" => safe_message}
      end

      def safe_error_message(value)
        sanitized = safe_error(value)
        sanitized.respond_to?(:message) ? sanitized.message.to_s : sanitized.to_s
      end

      def safe_error(value)
        return value unless @error_sanitizer

        candidate = value.respond_to?(:message) ? value : Error.new(value.to_s)
        sanitized = @error_sanitizer.call(candidate)
        return sanitized if sanitized.is_a?(Exception)

        Error.new(sanitized.to_s)
      rescue StandardError
        # Sanitization itself must fail closed: do not persist the original
        # potentially secret-bearing message.
        Error.new("snapshot recovery error [REDACTED]")
      end

      def sanitize_content(content, secret:)
        return nil if secret
        Types.deep_copy(content)
      end
    end

    SnapshotController = SnapshotManager unless const_defined?(:SnapshotController, false)
    Snapshot = SnapshotRecord unless const_defined?(:Snapshot, false)
    SnapshotStore = DurableSnapshotStore unless const_defined?(:SnapshotStore, false)
  end
end
