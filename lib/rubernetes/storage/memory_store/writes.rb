# frozen_string_literal: true

module Rubernetes
  module Storage
    # create, update and delete: preconditions, the optimistic retry loop and the commit.
    class MemoryStore
      def create(key, object, request_uid: nil, request_id: nil, related_versions: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || resource_keyword
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown create options: #{options.keys.join(", ")}" unless options.empty?

        normalized_key = normalize_key(key)
        candidate = normalize_object(object)
        fingerprint = request_fingerprint(:create, normalized_key, candidate, nil, related_versions)

        @monitor.synchronize do
          commit_request(request_uid, fingerprint, :create, normalized_key) do
            raise AlreadyExists, normalized_key if @live_versions.key?(normalized_key)

            check_related_versions!(normalized_key, related_versions)
            commit_locked(:added, normalized_key, candidate)
          end
        end
      end

      def guaranteed_update(
        key,
        prec: nil,
        precondition: nil,
        resource_version: nil,
        request_uid: nil,
        request_id: nil,
        related_versions: nil,
        max_retries: @max_update_retries,
        **options,
        &block
      )
        request_uid ||= request_id || options.delete(:uid)
        allow_nil_result = options.delete(:allow_nil_result) { false }
        # The replay fingerprint must identify the *client's* request. A caller
        # that recomputes the optimistic-concurrency version on every attempt
        # (RaftStore#guaranteed_update does) would otherwise produce a different
        # fingerprint for the same UID once the first attempt applied, and the
        # idempotent replay would be reported as a UID conflict instead.
        replay_precondition = options.key?(:replay_precondition) ? options.delete(:replay_precondition) : :same
        raise ArgumentError, "unknown guaranteed_update options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "guaranteed_update requires a block" unless block

        expected = write_precondition(prec, precondition, resource_version)
        normalized_key = normalize_key(key)
        retries = validate_positive_limit(max_retries, "max_retries", allow_zero: true)
        request_uid = -normalize_request_uid(request_uid) unless request_uid.nil?
        replay_expected = replay_precondition == :same ? expected : normalize_precondition(replay_precondition)
        with_request_lock(request_uid) do
          guaranteed_update_with_retry(
            normalized_key,
            expected,
            request_uid,
            retries,
            allow_nil_result,
            replay_expected,
            related_versions: related_versions,
            &block
          )
        end
      end

      # Replace the complete object while preserving the same optimistic CAS
      # semantics as guaranteed_update. API::StoreAdapter uses this shape for
      # PUT/PATCH paths and supplies transport-only resource metadata in
      # keywords; those keywords are intentionally ignored here.
      def update(
        key,
        object = nil,
        prec: nil,
        precondition: nil,
        resource_version: nil,
        request_uid: nil,
        request_id: nil,
        related_versions: nil,
        **options
      )
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || resource_keyword
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown update options: #{options.keys.join(", ")}" unless options.empty?
        raise ArgumentError, "update requires an API object Hash" unless object.is_a?(Hash)

        expected = write_precondition(prec, precondition, resource_version)
        candidate = normalize_object(object)
        commit_replacement(key, expected, expected, request_uid, related_versions) { candidate }
      end

      alias replace update

      # A replicated command already contains the final object. Compare the
      # observed version for this attempt, but deduplicate by the original
      # client precondition. A replay never needs to decode its payload.
      def apply_update(key, prec:, replay_precondition:, request_uid:, related_versions:)
        commit_replacement(key, normalize_precondition(prec), normalize_precondition(replay_precondition),
                           request_uid, related_versions) { normalize_object(yield) }
      end

      def delete(key, prec: nil, precondition: nil, resource_version: nil, request_uid: nil, request_id: nil, delete_corrupt: false,
                 related_versions: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown delete options: #{options.keys.join(", ")}" unless options.empty?

        expected = write_precondition(prec, precondition, resource_version)
        normalized_key = normalize_key(key)

        @monitor.synchronize do
          fingerprint = request_fingerprint(:delete, normalized_key, nil, expected, related_versions) unless request_uid.nil?
          commit_request(request_uid, fingerprint, :delete, normalized_key) do
            current = current_object(normalized_key)
            raise NotFound, normalized_key if current.nil?

            check_precondition!(normalized_key, current, expected)
            check_related_versions!(normalized_key, related_versions)
            unreadable = current.is_a?(CBORRecord::Unreadable)
            if unreadable && !delete_corrupt
              raise CorruptObject.new(normalized_key, resource_version: object_revision(current))
            elsif delete_corrupt && !unreadable
              raise Conflict.new(normalized_key, "record is readable")
            end

            commit_locked(:deleted, normalized_key, current)
          end
        end
      end

      private

      def commit_replacement(key, expected, replay_expected, request_uid, related_versions)
        key = normalize_key(key)
        uid = -normalize_request_uid(request_uid) unless request_uid.nil?
        fingerprint = request_fingerprint(:guaranteed_update, key, nil, replay_expected, related_versions) if uid
        with_request_lock(uid) do
          @monitor.synchronize do
            commit_request(uid, fingerprint, :guaranteed_update, key) do
              current = current_object(key)
              raise NotFound, key unless current

              check_precondition!(key, current, expected)
              candidate = yield
              check_related_versions!(key, related_versions)
              commit_locked(:modified, key, candidate)
            end
          end
        end
      end

      def normalize_key(key)
        normalized = String(key)
        raise ArgumentError, "key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "key must be coercible to String"
      end

      def normalize_object(object)
        raise ArgumentError, "API object must be a Hash" unless object.is_a?(Hash)

        copy = MemoryStoreSupport.deep_dup(object, check_keys: true)
        metadata = copy["metadata"]
        if metadata.nil?
          copy["metadata"] = {}
        elsif !metadata.is_a?(Hash)
          raise ArgumentError, "API object metadata must be a Hash"
        end
        copy
      end

      # The object committed is normalize_object's private copy in the create
      # and update paths, so it is stamped in place; only a frozen object (the
      # stored one, on delete) is copied first.  Copying again here doubled
      # the deep copies on every write.
      def stamp_object(object, revision)
        copy = object.frozen? ? MemoryStoreSupport.deep_dup(object) : object
        metadata = copy.fetch("metadata")
        metadata["resourceVersion"] = revision.to_s
        MemoryStoreSupport.deep_freeze(copy)
      end

      def write_precondition(prec, precondition, resource_version)
        prec = precondition if prec.nil?
        normalize_precondition(prec.nil? ? resource_version : prec)
      end

      def normalize_precondition(value)
        return nil if value.nil?
        return {resource_version: value} if value.is_a?(String) || value.is_a?(Numeric)

        if value.is_a?(Hash) && value["metadata"].is_a?(Hash)
          metadata = value.fetch("metadata")
          return {
            resource_version: metadata["resourceVersion"],
            uid: metadata["uid"]
          }.compact
        end
        return value if value.is_a?(Hash)

        raise ArgumentError, "precondition must be a resourceVersion or Hash"
      end

      def check_precondition!(key, object, precondition)
        return if precondition.nil?

        expected_resource_version = precondition[:resource_version] || precondition[:resourceVersion] ||
                                    precondition["resourceVersion"] || precondition["resource_version"]
        expected_uid = precondition[:uid] || precondition["uid"]
        raise ArgumentError, "precondition must include resourceVersion or uid" if expected_resource_version.nil? && expected_uid.nil?

        current_resource_version = object_revision(object)
        if !expected_resource_version.nil? && precondition_revision(expected_resource_version, current_resource_version,
                                                                    key) != current_resource_version
          raise Conflict.new(key, "expected resourceVersion #{expected_resource_version}, current is #{current_resource_version}",
                             resource_version: current_resource_version)
        end

        current_uid = object.dig("metadata", "uid")
        return unless !expected_uid.nil? && String(expected_uid) != current_uid.to_s

        raise Conflict.new(key, "expected uid #{expected_uid.inspect}, current is #{current_uid.inspect}",
                           resource_version: current_resource_version)
      end

      def precondition_revision(value, current_resource_version, key)
        parse_revision(value)
      rescue InvalidResourceVersion
        raise Conflict.new(
          key,
          "expected resourceVersion #{value.inspect}, current is #{current_resource_version}",
          resource_version: current_resource_version
        )
      end

      # Invoked under the commit lock. A nil version checks that the related
      # key is absent, so another writer can't insert it before this commit.
      def check_related_versions!(key, versions)
        versions&.each do |related, expected|
          current = current_object(related)&.dig("metadata", "resourceVersion")
          next if current == expected

          raise Conflict.new(key, "related key #{related} changed")
        end
      end

      def guaranteed_update_with_retry(key, expected, request_uid, retries, allow_nil_result,
                                       replay_expected, related_versions:, &)
        if request_uid
          fingerprint = request_fingerprint(:guaranteed_update, key, nil, replay_expected, related_versions)
          replay = @monitor.synchronize { replay_request(request_uid, fingerprint, :guaranteed_update, key) }
          return replay unless replay.equal?(NO_REPLAY)
        end

        attempt = 0
        loop do
          current, observed_revision = @monitor.synchronize do
            observed = current_object(key)
            raise NotFound, key unless observed

            check_precondition!(key, observed, expected)
            [MemoryStoreSupport.deep_dup(observed), object_revision(observed)]
          end

          candidate = yield(current)
          candidate = current if candidate.nil? && allow_nil_result
          raise ArgumentError, "guaranteed_update block must return an API object Hash" unless candidate.is_a?(Hash)

          candidate = normalize_object(candidate)

          @monitor.synchronize do
            # A create or delete can claim this UID while the update block runs.
            replay = replay_request(request_uid, fingerprint, :guaranteed_update, key)
            return replay unless replay.equal?(NO_REPLAY)

            latest = current_object(key)
            latest_revision = latest && object_revision(latest)
            if latest && latest_revision == observed_revision
              check_precondition!(key, latest, expected)
              check_related_versions!(key, related_versions)

              committed = commit_locked(:modified, key, candidate)
              remember_request(request_uid, fingerprint, :guaranteed_update, key, committed)
              return committed
            end
          end

          raise Conflict.new(key, "guaranteed update conflicted after #{attempt + 1} attempts") if attempt >= retries

          sleep_for_retry(attempt)
          attempt += 1
        end
      end

      def sleep_for_retry(attempt)
        ceiling = [MIN_BACKOFF_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS].min
        @sleeper.call(@random.rand * ceiling)
      end

      def commit_locked(type, key, object)
        ensure_writes_enabled!

        @revision += 1
        timestamp = clock_value
        old_object = current_object(key)
        committed_object = stamp_object(object, @revision)
        bucket = resource_bucket(key)
        @resource_revisions[bucket] = @revision if bucket
        if type == :deleted
          entries = @deleted_versions[key] = @live_versions.delete(key)
          entries << [@revision, nil]
        else
          entries = @live_versions[key] ||= @deleted_versions.delete(key) || []
          @sorted_keys = nil if entries.empty?
          entries << [@revision, committed_object]
        end
        mutation = Mutation.new(
          type: type,
          key: key,
          revision: @revision,
          # A deletion is a committed mutation too. Expose its global
          # revision on the returned/event object while retaining the prior
          # object separately for selector transition checks.
          object: committed_object,
          old_object: old_object,
          timestamp: timestamp
        )
        @history << mutation
        # One size estimate for every watcher rather than a JSON encoding each.
        bytesize = nil
        terminated = 0
        @watchers.delete_if do |watcher, _|
          next false unless watcher.closed? || key.start_with?(watcher.prefix)

          bytesize ||= JSON.generate(committed_object).bytesize + 64
          delivered = watcher.enqueue(mutation, bytesize: bytesize)
          # A watcher whose buffer is full is closed rather than waited for
          # (cacheWatcher.add's closeFunc).
          terminated += 1 if !delivered && watcher.overflowed?
          record_sharded_watch(watcher, -1) if watcher.closed?
          watcher.closed?
        end
        record_commit(key, terminated) if @metrics
        # The compatibility policy periodically prunes all key histories and
        # request results. The longer-window policy prunes expired keys and
        # requests incrementally as the compaction boundary advances.
        target = compaction_target_locked(now: timestamp)
        if !@retain_longer_window && @history_seconds &&
           (@last_full_compaction_at.nil? || timestamp - @last_full_compaction_at >= @history_seconds)
          @last_full_compaction_at = timestamp
          compact_locked!(target, prune_all_versions: true)
        else
          compact_locked!(target)
        end
        mutation.object
      end

      def ensure_writes_enabled!
        raise Unavailable, "datastore writes are paused for migration" if @write_pause
      end
    end
  end
end
