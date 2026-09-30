# frozen_string_literal: true

require "securerandom"
require "time"

module Rubernetes
  module Security
    module Audit
      # Builds audit.k8s.io/v1 Event documents.  Secrets, tokens and
      # credential headers never enter an event: request/response bodies are
      # only recorded at the Request / RequestResponse levels and Secret
      # payloads are replaced by their metadata.
      module Event
        REDACTED_RESOURCES = %w[secrets serviceaccounts/token tokenreviews tokenrequests].freeze
        REDACTED_HEADERS = %w[authorization cookie x-remote-user x-remote-group proxy-authorization].freeze

        module_function

        def build(stage:, level:, audit_id:, attributes:, request:, response: nil, request_object: nil, response_object: nil,
                  omit_managed_fields: false, now: Time.now.utc, annotations: {}, impersonated: nil, impersonation_constraint: nil)
          event = {
            "kind" => "Event",
            "apiVersion" => "audit.k8s.io/v1",
            "level" => level,
            "auditID" => audit_id,
            "stage" => stage,
            "requestURI" => request.respond_to?(:path) ? request_uri(request) : nil,
            "verb" => attributes.verb,
            "user" => attributes.user.to_h,
            "sourceIPs" => [request.respond_to?(:remote_address) ? request.remote_address&.sub(/:\d+\z/, "") : nil].compact,
            "userAgent" => (request.respond_to?(:header) ? request.header("user-agent") : nil),
            "requestReceivedTimestamp" => now.iso8601(6),
            "stageTimestamp" => now.iso8601(6),
            "annotations" => annotations
          }
          event["impersonatedUser"] = impersonated.to_h if impersonated
          unless impersonation_constraint.to_s.empty?
            event["authenticationMetadata"] =
              {"impersonationConstraint" => impersonation_constraint}
          end
          if attributes.resource_request?
            event["objectRef"] = {"resource" => attributes.resource, "namespace" => attributes.namespace, "name" => attributes.name,
                                  "apiGroup" => attributes.api_group, "apiVersion" => attributes.api_version,
                                  "subresource" => attributes.subresource}.reject { |_key, value| value.to_s.empty? }
          end
          event["responseStatus"] = response_status(response) if response
          if %w[Request RequestResponse].include?(level) && request_object
            event["requestObject"] = sanitize(attributes, request_object, omit_managed_fields)
          end
          if level == "RequestResponse" && response_object
            event["responseObject"] = sanitize(attributes, response_object, omit_managed_fields)
          end
          event.reject { |_key, value| value.nil? }
        end

        def request_uri(request)
          query = if request.query.is_a?(Hash) && !request.query.empty?
                    "?" + request.query.map { |key, value|
                      "#{key}=#{Array(value).join(",")}"
                    }.join("&")
                  else
                    ""
                  end
          "#{request.path}#{query}"
        end

        def response_status(response)
          status = response.respond_to?(:status) ? response.status : 200
          body = response.respond_to?(:body) ? response.body : nil
          if body.is_a?(Hash) && body["kind"] == "Status"
            {"metadata" => {}, "code" => status, "status" => body["status"], "reason" => body["reason"],
             "message" => body["message"]}.reject do |_key, value|
              value.nil?
            end
          else
            {"metadata" => {}, "code" => status}
          end
        end

        # Secret-bearing objects are reduced to metadata (kube-apiserver's
        # policy for Secret data at Request/RequestResponse levels is the
        # cluster operator's; the specification forbids recording them).
        def sanitize(attributes, object, omit_managed_fields)
          return object unless object.is_a?(Hash)

          copy = deep_copy(object)
          if REDACTED_RESOURCES.include?(attributes.resource) || REDACTED_RESOURCES.include?(attributes.resource_with_subresource)
            copy = {"apiVersion" => copy["apiVersion"], "kind" => copy["kind"], "metadata" => copy["metadata"]}.compact
          end
          if omit_managed_fields && copy["metadata"].is_a?(Hash)
            copy["metadata"] = copy["metadata"].reject { |key, _| key == "managedFields" }
          end
          copy
        end

        def deep_copy(value)
          case value
          when Hash then value.each_with_object({}) { |(key, child), hash| hash[key] = deep_copy(child) }
          when Array then value.map { |child| deep_copy(child) }
          else value
          end
        end
      end
    end
  end
end
