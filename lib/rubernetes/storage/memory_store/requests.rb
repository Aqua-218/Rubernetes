# frozen_string_literal: true

module Rubernetes
  module Storage
    # Request UID memory: a retried write is answered with its first result.
    class MemoryStore
      NO_REPLAY = Object.new.freeze

      private

      def request_fingerprint(operation, key, object, precondition, related_versions = nil)
        payload = {operation: operation.to_s, key: key, object: object, precondition: precondition}
        payload[:related_versions] = related_versions if related_versions && !related_versions.empty?
        MemoryStoreSupport.digest(payload)
      end

      RequestLock = Struct.new(:monitor, :users)
      private_constant :RequestLock

      def with_request_lock(request_uid, &)
        return yield if request_uid.nil?

        # Count queued callers as well as the owner so a third caller never
        # gets a different monitor while the first two are handing it over.
        entry = @monitor.synchronize do
          lock = @request_locks[request_uid] ||= RequestLock.new(Monitor.new, 0)
          lock.users += 1
          lock
        end
        entry.monitor.synchronize(&)
      ensure
        if entry
          @monitor.synchronize do
            entry.users -= 1
            @request_locks.delete(request_uid) if entry.users.zero?
          end
        end
      end

      # Called under the store monitor. commit_locked returns the frozen
      # revision shared by the MVCC history, so replay can return it directly.
      def commit_request(uid, fingerprint, operation, key)
        return yield if uid.nil?

        replay = replay_request(uid, fingerprint, operation, key)
        return replay unless replay.equal?(NO_REPLAY)

        result = yield
        remember_request(uid, fingerprint, operation, key, result)
        result
      end

      def replay_request(request_uid, fingerprint, operation, key)
        return NO_REPLAY if request_uid.nil?

        uid = normalize_request_uid(request_uid)
        stored = @requests[uid]
        return NO_REPLAY if stored.nil?
        unless stored.fingerprint == fingerprint && stored.operation == operation.to_sym && stored.key == key
          raise RequestUIDConflict.new(uid,
                                       key)
        end

        stored.result
      end

      def remember_request(request_uid, fingerprint, operation, key, result)
        return if request_uid.nil?

        uid = normalize_request_uid(request_uid)
        @requests[uid] = RequestResult.new(
          fingerprint: fingerprint.freeze,
          operation: operation.to_sym,
          key: key.freeze,
          revision: object_revision(result),
          result: MemoryStoreSupport.immutable_copy(result)
        )
      end

      def normalize_request_uid(request_uid)
        uid = String(request_uid)
        raise ArgumentError, "request UID must not be empty" if uid.empty?

        uid
      rescue TypeError
        raise ArgumentError, "request UID must be coercible to String"
      end
    end
  end
end
