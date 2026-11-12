# frozen_string_literal: true

module Rubernetes
  module Storage
    # Request UID memory: a retried write is answered with its first result.
    class MemoryStore
      NO_REPLAY = Object.new.freeze

      private

      def request_fingerprint(operation, key, object, precondition)
        MemoryStoreSupport.digest(operation: operation.to_s, key: key, object: object, precondition: precondition)
      end

      def with_request_lock(request_uid, &)
        return yield if request_uid.nil?

        lock = @monitor.synchronize { @request_locks[request_uid] ||= Monitor.new }
        lock.synchronize(&)
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

        immutable_response(stored.result)
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
