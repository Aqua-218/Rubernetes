# frozen_string_literal: true

module Rubernetes
  module API
    class Server
      # Hands requests to the admission chain (mutating, validating, and the CONNECT
      # of a streaming subresource) and carries what admission produced back out:
      # Status rejections, audit annotations and Warning headers.
      module AdmissionGlue
        # Admission runs between decode and strategy validation (mutating) and
        # after validation (validating).  Rejections become 4xx Status objects.
        def admit_mutating(request, route, operation, object, old_object, namespace, name: nil)
          chain = admission_chain
          return object unless chain

          # Mutating plugins edit the object in place.  Schema application and the
          # store both hand back structures with frozen members, so the chain must
          # be given a mutable copy -- otherwise the first plugin that touches a
          # defaulted sub-object raises FrozenError and the request 500s.
          attributes = admission_attributes(request, route, operation, deep_copy(object), old_object, namespace, name: name)
          begin
            phase("admit") { chain.admit(attributes) }
          ensure
            record_admission_annotations(attributes)
          end
          attributes.warnings.each { |warning| request_warnings(request) << warning }
          attributes.object
        rescue Security::Admission::Rejected => rejected
          raise admission_status(rejected, route)
        end

        def admit_validating(request, route, operation, object, old_object, namespace, name: nil)
          chain = admission_chain
          return true unless chain

          attributes = admission_attributes(request, route, operation, object, old_object, namespace, name: name)
          begin
            phase("validate_admission") { chain.validate(attributes) }
          ensure
            record_admission_annotations(attributes)
          end
          attributes.warnings.each { |warning| request_warnings(request) << warning }
          true
        rescue Security::Admission::Rejected => rejected
          raise admission_status(rejected, route)
        end

        # pods/exec, pods/attach and pods/portforward are CREATE requests that go
        # through admission upstream: a webhook registered for the subresource is
        # handed the options object built from the query string and can deny the
        # connection.  Skipping admission let a denied attach open the stream and
        # hang until the client gave up -- "[sig-api-machinery] AdmissionWebhook
        # should be able to deny attaching pod" reported a kubectl timeout rather
        # than the webhook's message.
        STREAMING_ADMISSION_KINDS = {
          "exec" => "PodExecOptions", "attach" => "PodAttachOptions",
          "portforward" => "PodPortForwardOptions"
        }.freeze

        # Upstream hands these to admission as CONNECT (admission.Connect), not
        # CREATE: the e2e webhook for attach is registered for
        # Operations: [CONNECT], so a CREATE matched no rule and the attach went
        # ahead.  And kubectl 1.36 opens exec/attach over a WebSocket, which is a
        # GET, so admitting POST alone skipped every modern client.
        STREAMING_ADMISSION_METHODS = %w[GET POST].freeze

        def admit_streaming_subresource(request, route)
          kind = STREAMING_ADMISSION_KINDS[route.subresource.to_s]
          return if kind.nil? || !STREAMING_ADMISSION_METHODS.include?(request.method.to_s.upcase)

          options = streaming_options(request, kind)
          admit_mutating(request, route, :connect, options, nil, route.namespace, name: route.name)
          admit_validating(request, route, :connect, options, nil, route.namespace, name: route.name)
        end

        # The options a streaming request carries as query parameters are the
        # object admission sees (pkg/registry/core/pod/rest/subresources.go).
        def streaming_options(request, kind)
          options = {"kind" => kind, "apiVersion" => "v1"}
          if kind == "PodPortForwardOptions"
            ports = Array(request.query_values("ports")).flat_map { |value| value.to_s.split(",") }
            options["ports"] = ports.filter_map do |port|
              Integer(port, 10)
            rescue ArgumentError
              nil
            end
            return options
          end

          %w[stdin stdout stderr tty].each do |field|
            value = query(request, field)
            options[field] = truthy?(value) unless value.nil? || value.to_s.empty?
          end
          container = query(request, "container").to_s
          options["container"] = container unless container.empty?
          options["command"] = Array(request.query_values("command")).map(&:to_s) if kind == "PodExecOptions"
          options
        end

        def admission_chain
          @security&.admission
        end

        def admission_attributes(request, route, operation, object, old_object, namespace, name: nil)
          user = request.identity ? Security::UserInfo.from_h(request.identity) : Security::UserInfo.anonymous
          dry_run = query(request, "dryRun").to_s == "All"
          Security::Admission::Attributes.new(operation: operation, user: user, group: route.resource.group, version: route.resource.version,
                                              resource: route.resource.resource, kind: route.resource.kind, subresource: route.subresource,
                                              namespace: namespace, name: name || route.name || metadata_value(object || old_object || {}, "name"),
                                              object: object, old_object: old_object, dry_run: dry_run)
        end

        def admission_status(rejected, route)
          details = (rejected.details || {}).merge(resource_details(route)) { |_key, left, _right| left }
          case rejected.code
          when 400 then Status::BadRequest.new(rejected.message, details: details)
          when 409 then Status::Conflict.new(rejected.message, details: details)
          when 422 then Status::Invalid.new(rejected.message, details: details)
          when 500 then Status::Error.new(message: rejected.message, code: 500, reason: "InternalError", details: details)
          when 503 then Status::ServiceUnavailable.new(rejected.message, details: details)
          else Status::Forbidden.new(rejected.message, details: details)
          end
        end

        # Annotations an admission plugin added (PodSecurity's enforce-policy
        # and audit-violations, a webhook's) go onto the request's audit
        # event, rejected requests included.
        def record_admission_annotations(attributes)
          audit = Thread.current[AUDIT_KEY]
          return unless audit

          attributes.annotations.each { |key, value| audit.annotate(key, value) }
        end

        def request_warnings(request)
          @request_warnings ||= Hash.new { |hash, key| hash[key] = [] }.compare_by_identity
          @request_warnings[request]
        end

        # Admission warnings reach the client as RFC 7234 Warning headers with
        # kube-apiserver's `299 - "text"` rendering.
        def with_warning_headers(request, response)
          warnings = @request_warnings&.delete(request)
          return response if warnings.nil? || warnings.empty?

          rendered = warnings.map { |warning| "299 - #{warning.to_s.gsub(/[\r\n]+/, " ").inspect}" }
          existing = response.header("warning")
          response.with_header("warning", [existing, *rendered].compact.join(", "))
        end
      end
    end
  end
end
