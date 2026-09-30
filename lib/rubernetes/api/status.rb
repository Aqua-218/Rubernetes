# frozen_string_literal: true

module Rubernetes
  module API
    # Kubernetes-compatible Status payloads and request failures.
    #
    # API code raises Error instances at the boundary and converts them to a
    # stable JSON Status object. Internal exception classes are never exposed.
    class Status
      REASONS = {
        bad_request: "BadRequest",
        already_exists: "AlreadyExists",
        conflict: "Conflict",
        expired: "Expired",
        forbidden: "Forbidden",
        gone: "Gone",
        invalid: "Invalid",
        method_not_allowed: "MethodNotAllowed",
        not_acceptable: "NotAcceptable",
        not_found: "NotFound",
        not_implemented: "NotImplemented",
        service_unavailable: "ServiceUnavailable",
        too_many_requests: "TooManyRequests",
        unauthorized: "Unauthorized",
        unsupported_media_type: "UnsupportedMediaType"
      }.freeze

      # A typed API failure which can be rendered without leaking internals.
      class Error < StandardError
        attr_reader :code, :reason, :details, :causes, :retry_after_seconds

        def initialize(message:, code:, reason:, details: nil, causes: nil, retry_after_seconds: nil)
          @code = Integer(code)
          @reason = reason.to_s
          @details = details
          @causes = causes
          @retry_after_seconds = retry_after_seconds
          super(message.to_s)
        end

        # Convert the failure into the wire-level Status representation.
        def to_status
          Status.failure(
            message: message,
            code: code,
            reason: reason,
            details: details,
            causes: causes,
            retry_after_seconds: retry_after_seconds
          )
        end
      end

      class BadRequest < Error
        def initialize(message, **)
          super(message: message, code: 400, reason: REASONS.fetch(:bad_request), **)
        end
      end

      class AlreadyExists < Error
        def initialize(message, **)
          super(message: message, code: 409, reason: REASONS.fetch(:already_exists), **)
        end
      end

      class Conflict < Error
        def initialize(message, **)
          super(message: message, code: 409, reason: REASONS.fetch(:conflict), **)
        end
      end

      class Forbidden < Error
        def initialize(message, **)
          super(message: message, code: 403, reason: REASONS.fetch(:forbidden), **)
        end
      end

      class Unauthorized < Error
        def initialize(message, **)
          super(message: message, code: 401, reason: REASONS.fetch(:unauthorized), **)
        end
      end

      # API Priority and Fairness rejection: 429 with Retry-After.
      class TooManyRequests < Error
        # apimachinery NewTooManyRequests: the hint (and so the Retry-After
        # header) is only set when positive; clients retry on their own when
        # it is present.
        def initialize(message, retry_after_seconds: 1, **options)
          details = options.delete(:details) || {}
          seconds = Integer(retry_after_seconds)
          details = details.merge("retryAfterSeconds" => seconds) if seconds.positive?
          super(message: message, code: 429, reason: REASONS.fetch(:too_many_requests), details: details, **options)
        end
      end

      class Gone < Error
        def initialize(message, **)
          super(message: message, code: 410, reason: REASONS.fetch(:gone), **)
        end
      end

      # Resource content that can no longer be served from the retained
      # watch/list history. Kubernetes uses the Expired reason for this
      # condition so clients know that a fresh list is required.
      class Expired < Error
        def initialize(message, **)
          super(message: message, code: 410, reason: REASONS.fetch(:expired), **)
        end
      end

      class Invalid < Error
        def initialize(message, **)
          super(message: message, code: 422, reason: REASONS.fetch(:invalid), **)
        end
      end

      class MethodNotAllowed < Error
        def initialize(message, **)
          super(message: message, code: 405, reason: REASONS.fetch(:method_not_allowed), **)
        end
      end

      class NotFound < Error
        def initialize(message, **)
          super(message: message, code: 404, reason: REASONS.fetch(:not_found), **)
        end
      end

      # No representation acceptable to the client can be produced (Accept
      # negotiation failed or the object cannot be converted as requested).
      class NotAcceptable < Error
        def initialize(message, **)
          super(message: message, code: 406, reason: REASONS.fetch(:not_acceptable), **)
        end
      end

      class NotImplemented < Error
        def initialize(message, **)
          super(message: message, code: 501, reason: REASONS.fetch(:not_implemented), **)
        end
      end

      class ServiceUnavailable < Error
        def initialize(message, **)
          super(message: message, code: 503, reason: REASONS.fetch(:service_unavailable), **)
        end
      end

      class UnsupportedMediaType < Error
        def initialize(message, **)
          super(message: message, code: 415, reason: REASONS.fetch(:unsupported_media_type), **)
        end
      end

      # errors.NewInternalError: "Internal error occurred: <err>", the error
      # repeated as the only cause.
      class InternalError < Error
        def initialize(message, **)
          super(message: "Internal error occurred: #{message}", code: 500, reason: "InternalError",
                details: {"causes" => [{"message" => message.to_s}]}, **)
        end
      end

      class << self
        # Build a successful Status object. Kubernetes generally uses this for
        # collection deletion and explicit status subresource responses.
        def success(message: "", details: nil)
          payload = {
            "apiVersion" => "v1",
            "kind" => "Status",
            "metadata" => {},
            "status" => "Success"
          }
          payload["message"] = message.to_s unless message.to_s.empty?
          payload["details"] = deep_copy(details) unless details.nil?
          payload
        end

        # Build a failed Status object with optional structured causes.
        def failure(message:, code:, reason:, details: nil, causes: nil, retry_after_seconds: nil)
          build(
            status: "Failure",
            message: message,
            code: code,
            reason: reason,
            details: details,
            causes: causes,
            retry_after_seconds: retry_after_seconds
          )
        end

        private

        def build(status:, message:, code:, reason:, details:, causes: nil, retry_after_seconds: nil)
          payload = {
            "apiVersion" => "v1",
            "kind" => "Status",
            "metadata" => {},
            "status" => status,
            "message" => message.to_s,
            "code" => Integer(code)
          }
          payload["reason"] = reason.to_s unless reason.nil? || reason.to_s.empty?
          # A Status carries ListMeta, and an expired continue token is
          # returned there: client-go reads `Status.ListMeta.Continue` to
          # resume an inconsistent listing.  Reporting it only under details
          # leaves the client with an empty token and it restarts the list
          # from the beginning.
          if details.is_a?(Hash) && details["continue"]
            payload["metadata"]["continue"] = details["continue"].to_s
            payload["metadata"]["resourceVersion"] = details["resourceVersion"].to_s if details["resourceVersion"]
          end
          payload["details"] = deep_copy(details) unless details.nil?
          if causes && !causes.empty?
            payload["details"] ||= {}
            payload["details"]["causes"] = deep_copy(causes)
          end
          if retry_after_seconds
            payload["details"] ||= {}
            payload["details"]["retryAfterSeconds"] = Integer(retry_after_seconds)
          end
          payload
        end

        def deep_copy(value)
          case value
          when Hash
            value.each_with_object({}) { |(key, item), copy| copy[key.to_s] = deep_copy(item) }
          when Array
            value.map { |item| deep_copy(item) }
          else
            value
          end
        end
      end
    end

    # Short alias retained for callers that model Kubernetes' Status as a
    # response error rather than a value object.
    StatusError = Status::Error
  end
end
