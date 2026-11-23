# frozen_string_literal: true

module Rubernetes
  module Storage
    # Errors raised by the in-memory Store implementation.
    class Error < StandardError
      attr_reader :status, :reason, :key, :resource_version, :details, :causes

      def initialize(message = nil, status: nil, reason: nil, key: nil, resource_version: nil, details: nil, causes: nil)
        super(message)
        @status = status
        @reason = reason
        @key = key
        @resource_version = resource_version
        @details = details
        @causes = causes
      end

      alias code status
      alias http_status status
      alias http_code status
    end

    # The datastore cannot serve the request right now but nothing about it
    # is wrong: consensus is between leaders, or the quorum has not answered
    # in time.  kube-apiserver reports the same condition as a 503 with a
    # Retry-After, and every Kubernetes client retries it.
    class Unavailable < Error
      def initialize(message = "the datastore is currently unavailable", retry_after_seconds: 1)
        @retry_after_seconds = retry_after_seconds
        super(message, status: 503, reason: "ServiceUnavailable")
      end

      attr_reader :retry_after_seconds
    end

    # A particular stored object cannot be decoded. Availability failures
    # are reported separately and never qualify for administrative deletion.
    class CorruptObject < Error
      def initialize(key, resource_version: nil, decode_error: true, message: nil)
        @decode_error = decode_error
        description = message || "Internal error occurred: StorageError: corrupt object #{key.inspect} at revision #{resource_version}"
        super(description, status: 500, reason: "InternalError", key: key, resource_version: resource_version)
      end

      def decode_error? = @decode_error

      def watch_event(revision, unreadable_delete: false)
        details = if unreadable_delete
                    {"reason" => "StoreReadError", "message" => "saw a DELETED event, but object data is corrupt - #{message}"}
                  else
                    {"reason" => reason, "message" => message}
                  end
        object = {"kind" => "Status", "apiVersion" => "v1", "status" => "Failure", "code" => status}.merge(details)
        Event.new(type: "ERROR", object: object, revision: revision, key: key)
      end
    end

    class ObjectNotCorrupt < Error; end

    class ReadErrors < Error
      attr_reader :failures

      def initialize(resource, failures)
        @failures = failures.freeze
        causes = failures.map do |failure|
          {"reason" => "UnexpectedServerResponse", "field" => failure.key, "message" => failure.message}
        end
        super("failed to read one or more #{resource} from the storage", status: 500, reason: "StoreReadError",
                                                                         details: {"causes" => causes}, causes: causes)
      end
    end

    class NotFound < Error
      def initialize(key, message = nil)
        super(message || "resource not found: #{key}", status: 404, reason: "NotFound", key: key)
      end
    end

    class AlreadyExists < Error
      def initialize(key, message = nil)
        super(message || "resource already exists: #{key}", status: 409, reason: "AlreadyExists", key: key)
      end
    end

    class Conflict < Error
      def initialize(key, message = nil, resource_version: nil)
        super(
          message || "resource version precondition failed for #{key}",
          status: 409,
          reason: "Conflict",
          key: key,
          resource_version: resource_version
        )
      end
    end

    # A request cannot be replayed with a different operation or payload.
    class RequestUIDConflict < Conflict
      attr_reader :request_uid

      def initialize(request_uid, key, message = nil)
        @request_uid = request_uid
        super(key, message || "request UID #{request_uid.inspect} was already used for a different request")
      end
    end

    class InvalidSelector < Error
      def initialize(message, field: nil)
        cause = ([{"reason" => "FieldValueInvalid", "message" => message.to_s, "field" => field.to_s}] if field)
        super(message, status: 400, reason: "BadRequest", details: cause && {"causes" => cause}, causes: cause)
      end
    end

    class InvalidContinueToken < Error
      def initialize(message = "invalid continue token")
        super(message, status: 400, reason: "BadRequest",
                       details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                               "field" => "continue"}]})
      end
    end

    class InvalidResourceVersion < Error
      def initialize(message)
        super(message, status: 400, reason: "BadRequest",
                       details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                               "field" => "resourceVersion"}]})
      end
    end

    class InvalidLimit < Error
      def initialize(message = "limit must be a positive integer")
        super(message, status: 400, reason: "BadRequest",
                       details: {"causes" => [{"reason" => "FieldValueInvalid", "message" => message.to_s,
                                               "field" => "limit"}]})
      end
    end

    # Returned when a snapshot, watch starting revision or continue token expires.
    class Gone < Error
      def initialize(resource_version, compacted_revision, continue_token: nil)
        details = {"resourceVersion" => resource_version.to_s}
        details["compactedRevision"] = compacted_revision.to_s if compacted_revision
        details["continue"] = continue_token if continue_token
        message = if compacted_revision
                    "resource version #{resource_version} is no longer available; compacted through #{compacted_revision}"
                  else
                    "the continue token has expired; restart the list for a consistent snapshot or use the replacement continue token"
                  end
        super(
          message,
          status: 410,
          reason: "Expired",
          resource_version: resource_version,
          details: details
        )
        @compacted_revision = compacted_revision
      end

      attr_reader :compacted_revision
    end

    Compacted = Gone
    CompactedError = Gone
    ResourceVersionTooOld = Gone
    ResourceVersionExpired = Gone
    Expired = Gone
    ConflictError = Conflict
    NotFoundError = NotFound
    AlreadyExistsError = AlreadyExists

    class WatchOverflow < Error
      def initialize
        super(
          "watch buffer exceeded its configured bound; relist before reconnecting",
          status: 410,
          reason: "Expired",
          details: {
            "causes" => [{"reason" => "WatchOverflow",
                          "message" => "watch buffer exceeded its configured bound; relist before reconnecting",
                          "field" => "resourceVersion"}]
          }
        )
      end
    end

    WatcherOverflow = WatchOverflow
  end
end
