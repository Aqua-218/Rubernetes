# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "monitor"
require "securerandom"

require_relative "deferred_fsync"
require_relative "record_files"

module Rubernetes
  module Volume
    # Durable operation tokens and mount identities share one small ledger
    # abstraction.  It is intentionally adapter-free: storage can be an
    # in-memory hash for tests or an fsync'd JSON file for a node agent.
    class OperationLedger
      Entry = Struct.new(:key, :operation, :token, :fingerprint, :payload, :status, :result, :error, :timestamp, keyword_init: true) do
        def to_h
          {"key" => key, "operation" => operation, "token" => token, "fingerprint" => fingerprint,
           "payload" => payload, "status" => status, "result" => result, "error" => error, "timestamp" => timestamp}
        end
      end

      def initialize(path: nil, fsync: true, clock: -> { Time.now.utc })
        @path = path && File.expand_path(path.to_s)
        @fsync = fsync
        @clock = clock
        @files = @path && RecordFiles.new(path: @path, fsync: fsync)
        @mutex = Monitor.new
        @entries = {}
        @tokens = {}
        load!
      end

      attr_reader :path

      def begin!(key:, operation:, token:, fingerprint:, payload: nil)
        key = identifier(key, "operation key")
        operation = operation_identifier(operation)
        token = identifier(token, "operation token")
        fingerprint = identifier(fingerprint, "request fingerprint")
        @mutex.synchronize do
          existing = @entries[[key, operation]]
          if existing && existing.status == "failed" && existing.token != token
            @entries.delete([key, operation])
            existing = nil
          end
          token_use = @tokens[[key, token]]
          if token_use && (token_use["operation"] != operation || token_use["fingerprint"] != fingerprint)
            raise OperationTokenConflict, "operation token #{token.inspect} was already used for a different volume request"
          end

          if existing
            return immutable(existing) if existing.token != token && existing.status == "succeeded" && existing.fingerprint == fingerprint
            unless existing.token == token && existing.fingerprint == fingerprint
              raise OperationTokenConflict, "operation #{operation} for #{key} was replayed with a different token or payload"
            end

            return immutable(existing)
          end

          entry = Entry.new(key: key, operation: operation, token: token, fingerprint: fingerprint,
                            payload: Types.deep_copy(payload),
                            status: "pending", result: nil, error: nil, timestamp: now)
          @entries[[key, operation]] = entry
          @tokens[[key, token]] = {"operation" => operation, "fingerprint" => fingerprint}
          persist!(entry)
          # The caller must distinguish a freshly reserved operation from a
          # recovered pending operation. Keep the durable status as pending,
          # but expose the one-shot reservation as "new".
          copy = Entry.new(**entry.to_h.transform_keys(&:to_sym))
          copy.status = "new"
          copy.payload = Types.deep_copy(copy.payload)
          copy.result = Types.deep_copy(copy.result)
          copy.error = Types.deep_copy(copy.error)
          copy.freeze
          copy
        end
      end

      def finish!(key:, operation:, token:, result: nil)
        update!(key: key, operation: operation, token: token, status: "succeeded", result: result, error: nil)
      end

      # Persist the exact point after local validation and immediately before
      # an external effect is sent.  A restart or any error after this marker
      # cannot safely classify the operation as an ordinary failure.
      def effecting!(key:, operation:, token:)
        update!(key: key, operation: operation, token: token, status: "effecting", result: nil, error: nil)
      end

      def fail!(key:, operation:, token:, error:)
        update!(key: key, operation: operation, token: token, status: "failed", result: nil,
                error: error_payload(error))
      end

      def unknown!(key:, operation:, token:, error: nil)
        update!(key: key, operation: operation, token: token, status: "unknown", result: nil,
                error: error && error_payload(error))
      end

      def fetch(key:, operation:)
        @mutex.synchronize { @entries[[String(key), String(operation)]].then { |entry| entry && immutable(entry) } }
      end

      # Recovery retracts a succeeded operation whose kernel effect is proven
      # gone (the mount namespace that held it no longer exists), so the same
      # request can be driven again instead of replaying the stale result.
      def retract!(key:, operation:)
        @mutex.synchronize do
          entry = @entries.delete([String(key), String(operation)])
          return nil unless entry

          @tokens.delete([String(key), entry.token])
          persist!(nil, removed: [[entry.key, entry.operation]])
          immutable(entry)
        end
      end

      def entries
        @mutex.synchronize { @entries.values.map { |entry| immutable(entry) }.freeze }
      end

      def unknown_entries
        entries.select { |entry| entry.status == "unknown" }
      end

      def pending_entries
        entries.select { |entry| %w[pending effecting].include?(entry.status) }
      end

      private

      def update!(key:, operation:, token:, status:, result:, error:)
        @mutex.synchronize do
          entry = @entries.fetch([String(key), String(operation)]) do
            raise OperationUnknown, "operation #{operation} for #{key} is not recorded"
          end
          raise OperationTokenConflict, "operation token does not match the durable operation entry" unless entry.token == String(token)

          entry.status = status
          entry.result = Types.deep_copy(result)
          entry.error = Types.deep_copy(error)
          entry.timestamp = now
          pruned = prune_finished_locked!
          persist!(entry, removed: pruned, durable: DURABLE_STATUSES.include?(status.to_s))
          immutable(entry)
        end
      end

      # Finished entries are kept for idempotent retries (a repeated token
      # returns the recorded result), which only matters for a short while.
      # Kept for ever, the ledger grew to 6,000 entries -- 6 MB of JSON
      # rewritten and fsynced on EVERY volume operation, under the volume
      # manager's lock -- and a Pod with 50 ConfigMap volumes spent 19 minutes
      # in MountVolume.SetUp while the whole node's volume work queued behind
      # it.  Pending, effecting and unknown entries are never pruned: they are
      # what recovery reads.
      FINISHED_TTL_SECONDS = 600
      MAX_FINISHED_ENTRIES = 500
      FINISHED_STATUSES = %w[succeeded failed].freeze

      def prune_finished_locked!
        finished = @entries.select { |_key, entry| FINISHED_STATUSES.include?(entry.status) }
        return [] if finished.length <= MAX_FINISHED_ENTRIES && finished.all? { |_key, entry| fresh?(entry) }

        pruned = []
        finished.sort_by { |_key, entry| entry.timestamp.to_s }.each do |key, entry|
          break if finished.length <= MAX_FINISHED_ENTRIES && fresh?(entry)

          @entries.delete(key)
          @tokens.delete([entry.key, entry.token])
          finished.delete(key)
          pruned << key
        end
        pruned
      end

      def fresh?(entry)
        stamp = Time.iso8601(entry.timestamp.to_s)
        (now_time - stamp) < FINISHED_TTL_SECONDS
      rescue ArgumentError, TypeError
        false
      end

      def now_time
        value = @clock.call
        value.respond_to?(:utc) ? value.utc : Time.now.utc
      end

      def identifier(value, field)
        Types.identifier(value, field)
      end

      def error_payload(error)
        payload = {"class" => error.class.name, "message" => error.message.to_s}
        payload["details"] = Types.deep_copy(error.details) if error.respond_to?(:details) && error.details
        payload
      end

      def operation_identifier(value)
        text = String(value)
        raise ValidationError, "operation must not be empty" if text.empty?
        raise ValidationError, "operation contains an unsafe NUL" if text.include?("\0")
        raise ValidationError, "operation contains a control character" if text.match?(/[[:cntrl:]]/)

        text.freeze
      rescue TypeError
        raise ValidationError, "operation must be a string"
      end

      def now
        value = @clock.call
        value.is_a?(Time) ? value.utc.iso8601(6) : Time.parse(value.to_s).utc.iso8601(6)
      end

      def immutable(entry)
        Entry.new(**entry.to_h.transform_keys(&:to_sym)).tap do |copy|
          copy.payload = Types.deep_copy(copy.payload)
          copy.result = Types.deep_copy(copy.result)
          copy.error = Types.deep_copy(copy.error)
          copy.freeze
        end
      end

      def load!
        return unless @files

        legacy = @files.legacy?
        data = @files.load
        data.each do |raw|
          hash = raw.transform_keys(&:to_s)
          entry = Entry.new(key: hash.fetch("key"), operation: hash.fetch("operation"), token: hash.fetch("token"),
                            fingerprint: hash.fetch("fingerprint"), payload: hash["payload"],
                            status: hash.fetch("status"), result: hash["result"],
                            error: hash["error"], timestamp: hash.fetch("timestamp"))
          @entries[[entry.key, entry.operation]] = entry
          @tokens[[entry.key, entry.token]] = {"operation" => entry.operation, "fingerprint" => entry.fingerprint}
        end
        @files.migrate!(@entries.to_h { |pair, entry| [record_key(pair), entry.to_h] }) if legacy
      rescue JSON::ParserError, KeyError, TypeError => error
        raise JournalError, "volume operation ledger is corrupt: #{error.message}"
      end

      # Statuses whose record must be on disk before the caller proceeds: an
      # effect that may be in flight, and an effect whose outcome is unknown.
      # Recovery reads exactly these; losing a "pending" or "succeeded" record
      # to a crash costs at most a retried idempotent operation.
      DURABLE_STATUSES = %w[effecting unknown].freeze

      # Only the changed entry is written, and pruned or retracted ones
      # removed (RecordFiles); a durable status fsyncs its own record.
      def persist!(entry, removed: [], durable: false)
        return true unless @files

        @files.write(record_key([entry.key, entry.operation]), entry.to_h, durable: durable) if entry
        removed.each { |pair| @files.delete(record_key(pair)) }
        true
      rescue SystemCallError, IOError => error
        raise JournalError, "volume operation ledger persist failed: #{error.message}"
      end

      def record_key(pair)
        pair.join("\0")
      end
    end

    class MountIdentityLedger
      LEGACY_IDENTITY_VERSION = 1
      IDENTITY_VERSION = 2
      UNSET = Object.new.freeze

      Mount = Struct.new(:volume_id, :source, :target, :mount_id, :filesystem_uuid, :device_id,
                         :owner, :stage_path, :generation, :secret, :root, :source_identity,
                         :filesystem_uuid_available, :filesystem, :identity_version, :legacy, :bind,
                         keyword_init: true) do
        def identity_fields
          {"mountId" => mount_id, "filesystemUuid" => filesystem_uuid, "deviceId" => device_id,
           "target" => target, "root" => root, "sourceIdentity" => source_identity,
           "filesystemUuidAvailable" => filesystem_uuid_available}
        end

        # The digest is recomputed only when an identity field changed: the
        # ledger compares every record's identity on each registration, and
        # re-deriving a canonical-JSON SHA-256 per record per call made
        # registering the n-th mount O(n) digests -- a quarter of a node
        # agent's CPU while a few hundred volumes were mounted.
        def fingerprint
          fields = identity_fields
          return @fingerprint if @fingerprint && @fingerprint_fields == fields

          @fingerprint_fields = fields
          @fingerprint = MountIdentityLedger.identity_fingerprint(fields)
        end

        def legacy_identity
          [mount_id, filesystem_uuid, device_id, target].join("/")
        end

        def identity
          legacy? ? legacy_identity : fingerprint
        end

        def legacy?
          legacy == true || identity_version.to_i < MountIdentityLedger::IDENTITY_VERSION
        end

        def bind?
          bind == true
        end

        def to_h
          {"volumeId" => volume_id, "source" => source, "target" => target, "mountId" => mount_id,
           "filesystemUuid" => filesystem_uuid, "filesystemUuidAvailable" => filesystem_uuid_available,
           "deviceId" => device_id, "root" => root, "sourceIdentity" => source_identity,
           "filesystem" => filesystem, "owner" => owner, "stagePath" => stage_path,
           "generation" => generation, "secret" => secret == true, "identityVersion" => identity_version,
           "bind" => bind == true}
        end
      end

      def self.identity_fingerprint(fields)
        Types.digest(fields)
      end

      def initialize(path: nil, fsync: true, live_check: nil)
        @path = path && File.expand_path(path.to_s)
        @fsync = fsync
        @live_check = live_check
        @files = @path && RecordFiles.new(path: @path, fsync: fsync)
        @mutex = Monitor.new
        @mounts = {}
        @stale_dropped = 0
        load!
      end

      attr_reader :path, :stale_dropped

      # A callable answering whether a recorded mount still exists in the
      # kernel (its id still covers its target).  Kernel mount ids are reused
      # as soon as they are freed, so an entry whose cleanup never completed
      # -- the Pod sat in CleanupPending -- shares its id with whatever was
      # mounted next, and matching ids alone refused every later mount that
      # drew the same number.  With a live check the stale entry is dropped
      # instead; without one the ledger keeps its strict behaviour.
      attr_accessor :live_check

      def register(volume_id:, source:, target:, mount_id:, filesystem_uuid:, device_id:, owner:, stage_path: nil,
                   generation: nil, secret: false, root: nil, source_identity: nil,
                   filesystem_uuid_available: UNSET, filesystem: nil, bind: false)
        mount = build_mount(volume_id: volume_id, source: source, target: target, mount_id: mount_id,
                            filesystem_uuid: filesystem_uuid, device_id: device_id, owner: owner,
                            stage_path: stage_path, generation: generation, secret: secret,
                            root: root, source_identity: source_identity,
                            filesystem_uuid_available: filesystem_uuid_available, filesystem: filesystem,
                            bind: bind)
        @mutex.synchronize do
          existing = @mounts[mount.identity]
          if existing
            raise MountIdentityError, "mount identity #{mount.identity} is already owned by a different volume" if existing.to_h != mount.to_h
          elsif (conflict = conflicting_mount(mount))
            drop_stale_conflicts_locked!(mount)
            conflict = conflicting_mount(mount)
            raise MountIdentityError, "mount identity conflicts with an existing attachment for #{conflict.volume_id}" if conflict
          end
          @mounts[mount.identity] = mount
          persist!(written: [mount])
          mount.to_h.freeze
        end
      end

      def remove(identity:, expected: nil)
        @mutex.synchronize do
          mount = mount_for_identity(identity)
          return false unless mount
          if expected && !identity_matches?(mount, expected)
            raise MountIdentityError, "refusing to remove mount #{identity}: stable identity changed"
          end

          @mounts.delete(mount.identity)
          persist!(removed: [mount.identity])
          true
        end
      end

      def find(identity)
        @mutex.synchronize { mount_for_identity(identity)&.to_h&.then { |value| Types.deep_freeze(value) } }
      end

      def entries
        @mutex.synchronize { Types.deep_freeze(@mounts.values.map(&:to_h)) }
      end

      # Drops every record whose target is `path`.  Used when an abandoned
      # mount at a fixed Pod path has been cleared from the kernel: the record
      # then names nothing, and leaving it makes the next mount at that path
      # fail as a conflicting attachment.
      def remove_target(path)
        target = File.expand_path(path.to_s)
        @mutex.synchronize do
          removed = @mounts.select { |_identity, mount| File.expand_path(mount.target.to_s) == target }.keys
          removed.each { |identity| @mounts.delete(identity) }
          persist!(removed: removed)
          removed.length
        end
      end

      def remove_volume(volume_id)
        @mutex.synchronize do
          removed = @mounts.select { |_identity, mount| mount.volume_id.to_s == volume_id.to_s }.keys
          removed.each { |identity| @mounts.delete(identity) }
          persist!(removed: removed)
          removed.length
        end
      end

      # Compare every durable identity against the observed kernel mount table.
      # Unknown observations are deliberately left untouched; recovery may only
      # clean an object whose stable identity is in this ledger.
      def reconcile(observed)
        observed = Array(observed).map do |value|
          hash = value.respond_to?(:to_h) ? value.to_h : value
          hash.respond_to?(:transform_keys) ? hash.transform_keys(&:to_s) : hash
        end
        observed_by_identity = observed.each_with_object({}) do |entry, result|
          identity = identity_for(with_bind_hint(entry))
          result[identity] = entry if identity
        end
        observed_by_legacy_identity = observed.each_with_object({}) do |entry, result|
          identity = legacy_identity_for(entry)
          result[identity] = entry if identity
        end
        @mutex.synchronize do
          owned = []
          missing = []
          identity_mismatches = []
          @mounts.each do |identity, mount|
            observed_entry = observed_by_identity[identity]
            observed_entry ||= observed_by_legacy_identity[mount.legacy_identity] if mount.legacy?
            if observed_entry
              owned << mount.to_h
            elsif observed.any? { |entry| entry["target"].to_s == mount.target.to_s }
              identity_mismatches << {"expected" => mount.to_h,
                                      "observed" => observed.find { |entry| entry["target"].to_s == mount.target.to_s }}
            else
              missing << mount.to_h
            end
          end
          known = @mounts.values.each_with_object({}) do |mount, identities|
            identities[mount.identity] = true
            identities[mount.legacy_identity] = true if mount.legacy?
          end
          orphans = observed.reject do |entry|
            known.key?(identity_for(with_bind_hint(entry))) || known.key?(legacy_identity_for(entry))
          end.freeze
          {"owned" => owned.freeze, "missing" => missing.freeze, "identityMismatches" => identity_mismatches.freeze,
           "orphans" => orphans, "unknown" => orphans}
        end
      end

      def identity_for(entry)
        hash = entry.respond_to?(:to_h) ? entry.to_h : entry
        return nil unless hash.respond_to?(:key?)

        mount_id = value_for(hash, "mountId", :mount_id)
        filesystem_uuid = value_for(hash, "filesystemUuid", :filesystem_uuid)
        device_id = value_for(hash, "deviceId", :device_id)
        target = value_for(hash, "target", :target)
        return nil if [mount_id, device_id, target].any?(&:nil?)

        source_identity = if hash.key?("sourceIdentity") || hash.key?(:source_identity)
                            value_for(hash, "sourceIdentity", :source_identity)
                          else
                            value_for(hash, "source", :source)
                          end
        source = value_for(hash, "source", :source)
        filesystem = value_for(hash, "filesystem", :filesystem) || value_for(hash, "fsType", :fs_type)
        root = value_for(hash, "root", :root)
        availability_present = hash.key?("filesystemUuidAvailable") || hash.key?(:filesystem_uuid_available)
        availability = availability_present ? boolean_value(value_for(hash, "filesystemUuidAvailable", :filesystem_uuid_available)) : nil
        version = value_for(hash, "identityVersion", :identity_version)
        bind = boolean_value(value_for(hash, "bind", :bind)) if hash.key?("bind") || hash.key?(:bind)
        strict = version.to_i >= IDENTITY_VERSION || !filesystem_uuid.nil? ||
                 (availability_present && availability == false && !root.nil?)

        if strict
          return nil if source_identity.nil?

          source_identity = canonical_source_identity(source_identity)
          root = canonical_root(root) unless root.nil?
          availability = true if availability.nil?
          return nil if !filesystem_uuid.nil? && filesystem_uuid.to_s.empty?
          return nil if !filesystem_uuid.nil? && availability == false

          if filesystem_uuid.nil?
            return nil unless availability_present && availability == false && !root.nil?
            return nil unless kernel_mount_id?(mount_id) && kernel_device_id?(device_id)
            return nil if persistent_block_mount?(source: source, source_identity: source_identity, filesystem: filesystem,
                                                  root: root, bind: bind)
          end
          return MountIdentityLedger.identity_fingerprint(
            "mountId" => mount_id.to_s,
            "filesystemUuid" => filesystem_uuid&.to_s,
            "deviceId" => device_id.to_s,
            "target" => target.to_s,
            "root" => root,
            "sourceIdentity" => source_identity,
            "filesystemUuidAvailable" => availability
          )
        end

        legacy_identity_for(hash)
      rescue MountIdentityError, ValidationError, TypeError
        nil
      end

      alias fingerprint_for identity_for

      private

      # A raw mountinfo observation cannot say whether it is a bind mount.  The
      # ledger already knows: an entry with the same kernel mount ID, device,
      # root and target that was registered as a bind lends that fact to the
      # observation so its fingerprint can be computed the same way.
      def with_bind_hint(entry)
        return entry unless entry.respond_to?(:key?)
        return entry if entry.key?("bind") || entry.key?(:bind)

        mount_id = value_for(entry, "mountId", :mount_id).to_s
        target = value_for(entry, "target", :target).to_s
        device_id = value_for(entry, "deviceId", :device_id).to_s
        hint = @mounts.values.find do |mount|
          mount.bind? && mount.mount_id.to_s == mount_id && mount.target.to_s == target &&
            mount.device_id.to_s == device_id
        end
        return entry unless hint

        # The registered bind carries the identity fields the raw observation
        # cannot see (bind flag, and the filesystem UUID it was registered
        # with); lending them keeps the fingerprint computed the same way.
        entry.merge("bind" => true, "filesystemUuid" => hint.filesystem_uuid,
                    "filesystemUuidAvailable" => hint.filesystem_uuid_available)
      end

      def build_mount(volume_id:, source:, target:, mount_id:, filesystem_uuid:, device_id:, owner:, stage_path:,
                      generation:, secret:, root:, source_identity:, filesystem_uuid_available:, filesystem:,
                      bind: false)
        volume_id = Types.identifier(volume_id, "volume id")
        bind = bind == true
        source = text_value(source, "mount source")
        target = text_value(target, "mount target")
        mount_id = Types.identifier(mount_id, "mount id")
        device_id = Types.identifier(device_id, "device id")
        filesystem_uuid = optional_identifier(filesystem_uuid, "filesystem uuid")

        identity_fields_supplied = !root.nil? || !source_identity.nil? || !filesystem.nil? ||
                                   (!filesystem_uuid_available.equal?(UNSET) && !filesystem_uuid_available.nil?)
        new_identity = identity_fields_supplied || filesystem_uuid.nil?
        if new_identity
          source_identity_supplied = !source_identity.nil?
          source_identity = canonical_source_identity(source_identity.nil? ? source : source_identity)
          root = canonical_root(root) unless root.nil?
          availability_supplied = !filesystem_uuid_available.equal?(UNSET) && !filesystem_uuid_available.nil?
          availability = availability_supplied ? boolean_value(filesystem_uuid_available) : nil
          availability = true if availability.nil? && !filesystem_uuid.nil?
          if filesystem_uuid.nil?
            unless availability_supplied && availability == false
              raise_mount_error("filesystem UUID availability must be false when UUID is absent")
            end
            raise_mount_error("mount root is required when filesystem UUID is absent") if root.nil?
            raise_mount_error("mount source identity is required when filesystem UUID is absent") unless source_identity_supplied
            raise_mount_error("mount source identity is required when filesystem UUID is absent") if source_identity.empty?
            unless kernel_mount_id?(mount_id) && kernel_device_id?(device_id)
              raise_mount_error("mount ID and device ID must be kernel identities when filesystem UUID is absent")
            end
            if persistent_block_mount?(source: source, source_identity: source_identity, filesystem: filesystem,
                                       root: root, bind: bind)
              raise_mount_error("persistent block mount requires a real filesystem UUID")
            end
          elsif availability == false
            raise_mount_error("filesystem UUID availability cannot be false when UUID is present")
          end
          return Mount.new(volume_id: volume_id, source: source, target: target, mount_id: mount_id,
                           filesystem_uuid: filesystem_uuid, device_id: device_id, owner: owner.to_s,
                           stage_path: stage_path&.to_s, generation: generation, secret: secret == true,
                           root: root, source_identity: source_identity, filesystem_uuid_available: availability,
                           filesystem: filesystem&.to_s, identity_version: IDENTITY_VERSION, legacy: false,
                           bind: bind)
        end

        raise_mount_error("filesystem UUID is required for legacy mount identities") if filesystem_uuid.nil?

        Mount.new(volume_id: volume_id, source: source, target: target, mount_id: mount_id,
                  filesystem_uuid: filesystem_uuid, device_id: device_id, owner: owner.to_s,
                  stage_path: stage_path&.to_s, generation: generation, secret: secret == true,
                  root: nil, source_identity: canonical_source_identity(source),
                  filesystem_uuid_available: true, filesystem: filesystem&.to_s,
                  identity_version: LEGACY_IDENTITY_VERSION, legacy: true, bind: false)
      end

      # Remove every entry that conflicts with `mount` only because the kernel
      # has since reused its mount id or target: its own mount is gone.
      def drop_stale_conflicts_locked!(mount)
        return unless @live_check

        stale = @mounts.values.select do |existing|
          next false if existing.identity == mount.identity
          next false unless existing.mount_id.to_s == mount.mount_id.to_s || existing.target.to_s == mount.target.to_s

          live = begin
            @live_check.call(existing)
          rescue StandardError
            true
          end
          live == false
        end
        return if stale.empty?

        stale.each { |entry| @mounts.delete(entry.identity) }
        @stale_dropped += stale.length
        persist!(removed: stale.map(&:identity))
      end

      def conflicting_mount(mount)
        @mounts.values.find do |existing|
          # The cheap field comparisons decide almost every record; the
          # identity (a digest) is looked at only for a candidate conflict.
          overlap = existing.mount_id.to_s == mount.mount_id.to_s || existing.target.to_s == mount.target.to_s ||
                    block_identity_conflict?(existing, mount)
          next false unless overlap

          !(existing.identity == mount.identity && existing.to_h == mount.to_h)
        end
      end

      def block_identity_conflict?(left, right)
        return false unless persistent_block_mount?(source: left.source, source_identity: left.source_identity,
                                                    filesystem: left.filesystem, root: left.root, bind: left.bind?) &&
                            persistent_block_mount?(source: right.source, source_identity: right.source_identity,
                                                    filesystem: right.filesystem, root: right.root, bind: right.bind?)

        left.device_id.to_s == right.device_id.to_s ||
          (!left.filesystem_uuid.nil? && left.filesystem_uuid.to_s == right.filesystem_uuid.to_s)
      end

      # A persistent block mount is a block-device superblock mounted at its
      # root: its device number can be renumbered across boots, so only the
      # filesystem UUID identifies it durably.  A bind mount (explicit flag or
      # mountinfo root below "/") rides on someone else's superblock; its
      # (mount ID, device, root, target) tuple is the identity, and sharing a
      # device with another bind is normal rather than a double attachment.
      def persistent_block_mount?(source:, source_identity:, filesystem:, root: nil, bind: false)
        return false if bind == true
        return false if !root.nil? && root.to_s != "/"

        block_source = [source, source_identity].compact.any? { |value| value.to_s.start_with?("/dev/") }
        return false unless block_source

        filesystem.nil? || %w[ext4 xfs].include?(filesystem.to_s.downcase)
      end

      def identity_matches?(mount, expected)
        hash = expected.respond_to?(:to_h) ? expected.to_h : expected
        return false unless hash.respond_to?(:key?)

        fields = {"mountId" => :mount_id, "filesystemUuid" => :filesystem_uuid,
                  "deviceId" => :device_id, "target" => :target, "root" => :root,
                  "sourceIdentity" => :source_identity,
                  "filesystemUuidAvailable" => :filesystem_uuid_available}
        actual = mount.to_h
        fields.all? do |field, snake_key|
          present = hash.key?(field) || hash.key?(snake_key)
          present = hash.key?("source") || hash.key?(:source) if field == "sourceIdentity" && !present
          next true unless present

          expected_value = if hash.key?(field)
                             hash[field]
                           elsif hash.key?(snake_key)
                             hash[snake_key]
                           else
                             hash.key?("source") ? hash["source"] : hash[:source]
                           end
          actual_value = actual[field]
          expected_value == actual_value || expected_value.to_s == actual_value.to_s
        end
      end

      def load!
        return unless @files

        legacy = @files.legacy?
        data = @files.load
        data.each do |raw|
          hash = raw.transform_keys(&:to_s)
          legacy = hash.fetch("identityVersion", LEGACY_IDENTITY_VERSION).to_i < IDENTITY_VERSION
          mount = build_mount(volume_id: hash.fetch("volumeId"), source: hash.fetch("source"),
                              target: hash.fetch("target"), mount_id: hash.fetch("mountId"),
                              filesystem_uuid: hash["filesystemUuid"], device_id: hash.fetch("deviceId"),
                              owner: hash.fetch("owner"), stage_path: hash["stagePath"], generation: hash["generation"],
                              secret: hash["secret"] == true, root: hash["root"],
                              source_identity: hash.key?("sourceIdentity") ? hash["sourceIdentity"] : nil,
                              filesystem_uuid_available: hash.key?("filesystemUuidAvailable") ? hash["filesystemUuidAvailable"] : UNSET,
                              filesystem: hash["filesystem"], bind: hash["bind"] == true)
          mount.legacy = true if legacy
          mount.identity_version = LEGACY_IDENTITY_VERSION if legacy
          if (existing = @mounts[mount.identity]) && existing.to_h != mount.to_h
            raise JournalError, "mount identity ledger contains conflicting records for #{mount.identity}"
          end
          if (conflict = conflicting_mount(mount)) && conflict.identity != mount.identity
            raise JournalError, "mount identity ledger contains a double attachment for #{mount.volume_id}"
          end

          @mounts[mount.identity] = mount
        end
        @files.migrate!(@mounts.transform_values(&:to_h)) if legacy
      rescue JSON::ParserError, KeyError, TypeError, ValidationError, MountIdentityError => error
        raise JournalError, "mount identity ledger is corrupt: #{error.message}"
      end

      def mount_for_identity(identity)
        if identity.respond_to?(:to_h)
          hash = identity.to_h
          strict_identity = identity_for(hash)
          return @mounts[strict_identity] if strict_identity

          legacy_identity = legacy_identity_for(hash)
          return @mounts[legacy_identity] if legacy_identity

          return nil
        end

        @mounts[identity.to_s]
      end

      def legacy_identity_for(entry)
        hash = entry.respond_to?(:to_h) ? entry.to_h : entry
        return nil unless hash.respond_to?(:key?)

        values = [value_for(hash, "mountId", :mount_id), value_for(hash, "filesystemUuid", :filesystem_uuid),
                  value_for(hash, "deviceId", :device_id), value_for(hash, "target", :target)]
        return nil if values.any?(&:nil?)

        values.join("/")
      end

      def value_for(hash, string_key, symbol_key)
        return hash[string_key] if hash.key?(string_key)
        return hash[symbol_key] if hash.key?(symbol_key)

        nil
      end

      def text_value(value, field)
        text = String(value)
        raise_mount_error("#{field} must not be empty") if text.empty?
        raise_mount_error("#{field} contains an unsafe NUL") if text.include?("\0")
        raise_mount_error("#{field} contains a control character") if text.match?(/[[:cntrl:]]/)

        text.freeze
      rescue TypeError => error
        raise_mount_error("#{field} must be a string", cause: error)
      end

      def optional_identifier(value, field)
        return nil if value.nil?

        Types.identifier(value, field)
      rescue ValidationError, TypeError => error
        raise_mount_error("#{field} must be a non-empty identifier", cause: error)
      end

      def canonical_root(value)
        text = text_value(value, "mount root")
        raise_mount_error("mount root must be an absolute canonical path") unless text.start_with?("/")

        File.expand_path(text).freeze
      end

      def canonical_source_identity(value)
        text = text_value(value, "mount source identity")
        return File.expand_path(text).freeze if text.start_with?("/")
        return text.freeze if text.match?(%r{\Acsi://[A-Za-z0-9][A-Za-z0-9._:-]*\z})

        components = text.split("/")
        raise_mount_error("mount source identity must be canonical") if components.any? do |component|
          component.empty? || component == "." || component == ".."
        end

        text
      end

      def boolean_value(value)
        return value if [true, false].include?(value)

        raise_mount_error("filesystem UUID availability must be boolean")
      end

      def kernel_mount_id?(value)
        value.to_s.match?(/\A\d+\z/)
      end

      def kernel_device_id?(value)
        value.to_s.match?(/\A\d+:\d+\z/)
      end

      def raise_mount_error(message, cause: nil)
        error = MountIdentityError.new(message)
        error.set_backtrace(cause.backtrace) if cause
        raise error
      end

      # Only the changed records are written or removed (RecordFiles).
      def persist!(written: [], removed: [])
        return true unless @files

        written.each { |mount| @files.write(mount.identity, mount.to_h) }
        removed.each { |identity| @files.delete(identity) }
        true
      rescue SystemCallError, IOError => error
        raise JournalError, "mount identity ledger persist failed: #{error.message}"
      end
    end

    OwnershipLedger = MountIdentityLedger unless const_defined?(:OwnershipLedger, false)
  end
end
