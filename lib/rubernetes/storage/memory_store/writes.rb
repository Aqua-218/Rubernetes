# frozen_string_literal: true

module Rubernetes
  module Storage
    # create, update and delete: preconditions, the optimistic retry loop and the commit.
    class MemoryStore
      def create(key, object, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        body = options.delete(:body)
        object_keyword = options.delete(:object)
        resource_keyword = options.delete(:resource)
        object ||= body || object_keyword || resource_keyword
        discard_options(options, :gvr, :namespace, :name)
        raise ArgumentError, "unknown create options: #{options.keys.join(", ")}" unless options.empty?

        normalized_key = normalize_key(key)
        candidate = normalize_object(object)

        @monitor.synchronize do
          fingerprint = request_fingerprint(:create, normalized_key, candidate, nil)
          replay = replay_request(request_uid, fingerprint, :create, normalized_key)
          return replay unless replay.equal?(NO_REPLAY)
          raise AlreadyExists, normalized_key if @objects.key?(normalized_key) && !@objects[normalized_key].nil?

          committed = commit_locked(:added, normalized_key, candidate)
          remember_request(request_uid, fingerprint, :create, normalized_key, committed)
          immutable_response(committed)
        end
      end

      def guaranteed_update(
        key,
        prec: nil,
        precondition: nil,
        resource_version: nil,
        request_uid: nil,
        request_id: nil,
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

        expected = normalize_precondition(
          if prec.nil?
            precondition.nil? ? resource_version : precondition
          else
            prec
          end
        )
        normalized_key = normalize_key(key)
        retries = validate_positive_limit(max_retries, "max_retries", allow_zero: true)
        request_uid = normalize_request_uid(request_uid) unless request_uid.nil?
        replay_expected = replay_precondition == :same ? expected : normalize_precondition(replay_precondition)
        with_request_lock(request_uid) do
          guaranteed_update_with_retry(
            normalized_key,
            expected,
            request_uid,
            retries,
            allow_nil_result,
            replay_expected,
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

        expected = normalize_precondition(
          if prec.nil?
            precondition.nil? ? resource_version : precondition
          else
            prec
          end
        )
        candidate = normalize_object(object)
        guaranteed_update(key, prec: expected, request_uid: request_uid) { |_current| candidate }
      end

      alias replace update

      def delete(key, prec: nil, precondition: nil, resource_version: nil, request_uid: nil, request_id: nil, **options)
        request_uid ||= request_id || options.delete(:uid)
        discard_options(options, :gvr, :resource, :namespace, :name)
        raise ArgumentError, "unknown delete options: #{options.keys.join(", ")}" unless options.empty?

        expected = normalize_precondition(
          if prec.nil?
            precondition.nil? ? resource_version : precondition
          else
            prec
          end
        )
        normalized_key = normalize_key(key)

        @monitor.synchronize do
          fingerprint = request_fingerprint(:delete, normalized_key, nil, expected)
          replay = replay_request(request_uid, fingerprint, :delete, normalized_key)
          return replay unless replay.equal?(NO_REPLAY)

          current = @objects[normalized_key]
          raise NotFound, normalized_key if current.nil?

          check_precondition!(normalized_key, current, expected)

          committed = commit_locked(:deleted, normalized_key, current)
          remember_request(request_uid, fingerprint, :delete, normalized_key, committed)
          immutable_response(committed)
        end
      end

      private

      def normalize_key(key)
        normalized = String(key)
        raise ArgumentError, "key must not be empty" if normalized.empty?

        normalized.freeze
      rescue TypeError
        raise ArgumentError, "key must be coercible to String"
      end

      def normalize_object(object)
        raise ArgumentError, "API object must be a Hash" unless object.is_a?(Hash)

        copy = MemoryStoreSupport.deep_dup(object)
        validate_string_keys!(copy)
        metadata = copy["metadata"]
        if metadata.nil?
          copy["metadata"] = {}
        elsif !metadata.is_a?(Hash)
          raise ArgumentError, "API object metadata must be a Hash"
        end
        copy
      end

      def validate_string_keys!(value, seen = nil)
        return unless value.is_a?(Hash) || value.is_a?(Array)

        seen ||= {}.compare_by_identity
        raise ArgumentError, "API object must not contain cycles" if seen.key?(value)

        seen[value] = true
        begin
          if value.is_a?(Hash)
            value.each do |key, child|
              raise ArgumentError, "API object Hash keys must be Strings" unless key.is_a?(String)

              validate_string_keys!(child, seen)
            end
          else
            value.each { |child| validate_string_keys!(child, seen) }
          end
        ensure
          seen.delete(value)
        end
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

      def immutable_response(object)
        MemoryStoreSupport.immutable_copy(object)
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

      def guaranteed_update_with_retry(key, expected, request_uid, retries, allow_nil_result,
                                       replay_expected = expected, &)
        fingerprint = request_fingerprint(:guaranteed_update, key, nil, replay_expected)
        @monitor.synchronize do
          replay = replay_request(request_uid, fingerprint, :guaranteed_update, key)
          return replay unless replay.equal?(NO_REPLAY)
        end

        attempt = 0
        loop do
          current, observed_revision = @monitor.synchronize do
            current_object = @objects[key]
            raise NotFound, key if current_object.nil?

            check_precondition!(key, current_object, expected)
            [MemoryStoreSupport.deep_dup(current_object), object_revision(current_object)]
          end

          candidate = yield(current)
          candidate = current if candidate.nil? && allow_nil_result
          raise ArgumentError, "guaranteed_update block must return an API object Hash" unless candidate.is_a?(Hash)

          candidate = normalize_object(candidate)

          committed = @monitor.synchronize do
            latest = @objects[key]
            latest_revision = latest && object_revision(latest)
            if latest.nil? || latest_revision != observed_revision
              nil
            else
              check_precondition!(key, latest, expected)
              commit_locked(:modified, key, candidate)
            end
          end

          unless committed.nil?
            @monitor.synchronize do
              remember_request(request_uid, fingerprint, :guaranteed_update, key, committed)
              return immutable_response(committed)
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
        @revision += 1
        timestamp = clock_value
        old_object = @objects[key]
        committed_object = stamp_object(object, @revision)
        @sorted_keys = nil unless @known_keys.key?(key)
        @known_keys[key] = true
        @resource_revisions[resource_bucket(key)] = @revision
        @objects[key] = type == :deleted ? nil : committed_object
        @versions[key] << [@revision, type == :deleted ? nil : committed_object]
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
        bytesize = @watchers.empty? ? nil : JSON.generate(committed_object || {}).bytesize + 64
        terminated = 0
        @watchers.delete_if do |_watcher_id, watcher|
          delivered = watcher.enqueue(mutation, bytesize: bytesize)
          # A watcher whose buffer is full is closed rather than waited for
          # (cacheWatcher.add's closeFunc).
          terminated += 1 if !delivered && watcher.overflowed?
          watcher.closed?
        end
        record_commit(key, terminated) if @metrics
        # etcd auto-compaction: once per retention window every key's old
        # versions go, not only the key just written.  Pruning only the
        # written key left every version of every object that stopped
        # changing -- deleted Pods above all -- resident for ever, and a
        # conformance run grew each replica past 2 GB.
        target = compaction_target_locked(now: timestamp)
        if @history_seconds && (@last_full_compaction_at.nil? || timestamp - @last_full_compaction_at >= @history_seconds)
          @last_full_compaction_at = timestamp
          compact_locked!(target, prune_all_versions: true)
        else
          compact_locked!(target, key_to_prune: key)
        end
        mutation.object
      end
    end
  end
end
