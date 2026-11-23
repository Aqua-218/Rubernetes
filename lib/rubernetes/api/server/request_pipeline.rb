# frozen_string_literal: true

require_relative "../../schema/go_duration"

module Rubernetes
  module API
    class Server
      # One request from transport input to response: tracing, the request deadline,
      # the security pipeline around dispatch, and the translation of every error
      # into a Status response.
      module RequestPipeline
        # WithTimeoutForNonLongRunningRequests (--request-timeout, 60s; a
        # shorter ?timeout= is honoured): a request that is neither a watch nor
        # a streaming subresource runs on its own thread; past the deadline the
        # client gets 504 Timeout and apiserver_request_aborts_total counts it,
        # while the abandoned handler's later fate is
        # apiserver_request_post_timeout_total{source, status}.
        REQUEST_TIMEOUT_SECONDS = Float(ENV.fetch("RUBERNETES_REQUEST_TIMEOUT", "60"))

        def with_request_execution(request, route, &)
          return prepare_long_running_request(&) if long_running_request?(request, route) && feature_gate_enabled?("APIServingWithRoutine")

          with_request_timeout(request, route, &)
        end

        # Like kube-apiserver's WithRoutine, the worker's preparation stack can
        # terminate before the connection starts serving the long-lived body.
        def prepare_long_running_request
          parent = Thread.current
          locals = parent.keys.to_h { |key| [key, parent[key]] }
          response, error, returned = Thread.new do
            Thread.current.name = "apiserver-stream-prepare"
            locals.each { |key, value| Thread.current[key] = value }
            begin
              [yield, nil, REQUEST_THREAD_LOCALS.to_h { |key| [key, Thread.current[key]] }]
            rescue Exception => failure # rubocop:disable Lint/RescueException -- re-raise on the connection thread
              [nil, failure, REQUEST_THREAD_LOCALS.to_h { |key| [key, Thread.current[key]] }]
            end
          end.value
          returned.each { |key, value| parent[key] = value }
          raise error if error

          response
        end

        def with_request_timeout(request, route)
          deadline = request_timeout_seconds(request, route)
          return yield if deadline.nil?

          parent = Thread.current
          locals = REQUEST_THREAD_LOCALS.to_h { |key| [key, parent[key]] }
          extra_keys = parent.keys - REQUEST_THREAD_LOCALS
          extra_keys.each { |key| locals[key] = parent[key] }
          outcome = Queue.new
          timed_out = false
          worker = Thread.new do
            Thread.current.name = "apiserver-request"
            locals.each { |key, value| Thread.current[key] = value }
            begin
              value = yield
              outcome << [:ok, value, REQUEST_THREAD_LOCALS.to_h { |key| [key, Thread.current[key]] }]
              @metrics&.increment("apiserver_request_post_timeout_total", {"source" => "rest-handler", "status" => "ok"}) if timed_out
            rescue Exception => error # rubocop:disable Lint/RescueException -- re-raised on the request thread
              outcome << [:error, error, REQUEST_THREAD_LOCALS.to_h { |key| [key, Thread.current[key]] }]
              @metrics&.increment("apiserver_request_post_timeout_total", {"source" => "rest-handler", "status" => "panic"}) if timed_out
            end
          end
          result = outcome.pop(timeout: deadline)
          if result.nil?
            timed_out = true
            labels = Observability::Metrics.request_labels(**request_metric_labels(request, route))
              .slice("group", "resource", "scope", "subresource", "verb", "version")
            @metrics&.increment("apiserver_request_aborts_total", labels)
            @metrics&.increment("apiserver_request_post_timeout_total", {"source" => "timeout-handler", "status" => "pending"})
            raise Status::Error.new(message: "request did not complete within the allotted timeout", code: 504, reason: "Timeout")
          end
          kind, value, returned = result
          returned.each { |key, item| parent[key] = item }
          raise value if kind == :error

          value
        ensure
          worker&.join(0) unless timed_out
        end

        # nil for a long-running request (watch, exec, attach, log, proxy,
        # portforward), else the effective deadline.
        def request_timeout_seconds(request, route)
          return nil if long_running_request?(request, route)

          requested = request.query_value("timeout").to_s
          seconds = parse_go_duration_seconds(requested)
          return nil unless REQUEST_TIMEOUT_SECONDS.positive?

          seconds && seconds.positive? ? [seconds, REQUEST_TIMEOUT_SECONDS].min : REQUEST_TIMEOUT_SECONDS
        rescue Schema::GoDuration::ParseError => error
          raise Status::BadRequest.new("invalid timeout specified in the request URL - #{error.message}")
        end

        def long_running_request?(request, route)
          route && (route.watch_request?(request) || LONG_RUNNING_SUBRESOURCES.include?(route.subresource.to_s))
        end

        def parse_go_duration_seconds(text)
          return nil if text.empty?

          Schema::GoDuration.parse(text).fdiv(Schema::GoDuration::SECOND)
        end

        # The transport hands in a Request or a Rack-like environment; anything
        # else is refused by normalize_request and counted as a read.
        def mutating_input?(input)
          return false unless input.is_a?(Request) || input.is_a?(Hash)

          method = input.is_a?(Request) ? input.method : (input["REQUEST_METHOD"] || input[:method])
          !%w[GET HEAD OPTIONS].include?(method.to_s.upcase)
        end

        def call_unmetered(input, metric)
          request = nil
          route = nil
          request = normalize_request(input)
          metric[:request] = request
          route = @router.route(request)
          metric[:route] = route
          pattern = @trace_requests.nil? ? TRACE_REQUESTS : @trace_requests
          Thread.current[REQUEST_PHASES_KEY] = {} if pattern && pattern.match?(request.path.to_s)
          response = with_request_read_barrier do
            route = catch_up_dynamic_route(request, route)
            with_request_execution(request, route) do
              if @security
                secured_call(request, route)
              else
                note_deprecated_api(request, route, nil)
                finalize_response(request, dispatch(request, route), route: route)
              end
            end
          end
          metric[:route] = route
          response
        rescue Status::Error => error
          finalize_response(request, error_response(error))
        rescue MemoryStore::NotFound => error
          finalize_response(request, error_response(Status::NotFound.new(error.message)))
        rescue MemoryStore::AlreadyExists => error
          finalize_response(request, error_response(Status::AlreadyExists.new(error.message)))
        rescue MemoryStore::Conflict => error
          finalize_response(request, error_response(Status::Conflict.new(error.message)))
        rescue MemoryStore::Gone => error
          finalize_response(request, error_response(Status::Expired.new(error.message, details: error.details)))
        rescue MemoryStore::InvalidSelector, MemoryStore::InvalidContinueToken,
               MemoryStore::InvalidResourceVersion, MemoryStore::InvalidLimit => error
          details = error.details
          details ||= {"causes" => [{"reason" => "FieldValueInvalid",
                                     "message" => error.message,
                                     "field" => error.class.name.split("::").last}]}
          finalize_response(request, error_response(Status::BadRequest.new(error.message, details: details)))
        rescue MemoryStore::Error => error
          finalize_response(request, error_response(Status::Error.new(message: error.message, code: error.code,
                                                                      reason: error.reason, details: error.details)))
        rescue JSON::ParserError => error
          finalize_response(request, error_response(Status::BadRequest.new("request body is not valid JSON: #{error.message}")))
        rescue Psych::Exception => error
          finalize_response(request, error_response(Status::BadRequest.new("request body is not valid YAML: #{error.message}")))
        rescue JSON::GeneratorError, EncodingError, ArgumentError => error
          finalize_response(request, error_response(Status::BadRequest.new("request could not be processed: #{safe_error_message(error)}")))
        ensure
          # The request trace is logged with the metric, after this returns.
          metric[:phases] = Thread.current[REQUEST_PHASES_KEY]
          Thread.current[REQUEST_PHASES_KEY] = nil
        end

        def phase(name)
          phases = Thread.current[REQUEST_PHASES_KEY]
          return yield unless phases

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            yield
          ensure
            phases[name] = phases.fetch(name, 0.0) + (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          end
        end

        # Error text shown to clients never carries Ruby class names, paths or
        # object dumps.
        def safe_error_message(error)
          error.message.to_s.gsub(/#<[^>]*>/, "").gsub(%r{/[^\s]+\.rb:\d+}, "").strip[0, 200]
        end

        # Pipeline order per spec 5.1.1: request ID, authentication,
        # authorization, flow control, then routing/decode/admission/store, and
        # audit at the end.  Security failures are rendered as Status objects
        # without leaking internals; the audit ResponseComplete stage always
        # runs, including on 401/403/429.
        def secured_call(request, route)
          entry, refusal = enter_security_pipeline(request, route)
          return refusal if refusal

          secured = entry.request
          note_deprecated_api(secured, route, entry)
          response = nil
          error = nil
          previous_audit = Thread.current[AUDIT_KEY]
          Thread.current[AUDIT_KEY] = entry.audit
          begin
            response = dispatch_secured(secured, route)
            response = response.with_header("audit-id", entry.request.request_id) if response && entry.request.request_id
            response = attach_flow_control_headers(response, entry.ticket&.response_headers)
            response
          rescue StandardError => unexpected
            error = unexpected
            raise
          ensure
            Thread.current[AUDIT_KEY] = previous_audit
            phase("security.exit") { exit_security_pipeline(entry, request, response, error) }
          end
        end

        def attach_flow_control_headers(response, headers)
          return response unless response && headers

          headers.each { |name, value| response = response.with_header(name, value) }
          response
        end

        # endpoints/deprecation + installer: a request to a deprecated built-in
        # kind carries the Warning, sets apiserver_requested_deprecated_apis and
        # the k8s.io/deprecated audit annotations; a deprecated CRD version
        # carries its deprecationWarning.
        def note_deprecated_api(request, route, entry)
          return unless route.resource_route? && route.resource

          resource = route.resource
          group = resource.group.to_s
          version = resource.version.to_s
          if resource.custom?
            warning = @crd_manager&.deprecation_warning(group, version, resource.resource)
            request_warnings(request) << warning if warning && !warning.empty?
            return
          end

          deprecation = Lifecycle.deprecation(group, version, resource.kind)
          return unless deprecation

          request_warnings(request) << deprecation.message
          unless @deprecated_metric_registered
            @metrics&.register("apiserver_requested_deprecated_apis", type: :gauge,
                                                                      help: "Gauge of deprecated APIs that have been requested, broken out by API group, " \
                                                                            "version, resource, subresource, and removed_release.")
            @deprecated_metric_registered = true
          end
          @metrics&.set("apiserver_requested_deprecated_apis", 1,
                        {"group" => group, "version" => version, "resource" => resource.resource.to_s,
                         "subresource" => route.subresource.to_s, "removed_release" => deprecation.removed_release})
          audit = entry&.audit
          audit&.annotate("k8s.io/deprecated", "true")
          audit&.annotate("k8s.io/removed-release", deprecation.removed_release) unless deprecation.removed_release.empty?
        end

        def translate_store_error(error)
          case error
          when MemoryStore::NotFound then error_response(Status::NotFound.new(error.message))
          when MemoryStore::AlreadyExists then error_response(Status::AlreadyExists.new(error.message))
          when MemoryStore::Conflict then error_response(Status::Conflict.new(error.message))
          when MemoryStore::Gone then error_response(Status::Expired.new(error.message))
          when JSON::ParserError then error_response(Status::BadRequest.new("request body is not valid JSON: #{error.message}"))
          when Psych::Exception then error_response(Status::BadRequest.new("request body is not valid YAML: #{error.message}"))
          else error_response(Status::Error.new(message: error.message, code: error.code, reason: error.reason))
          end
        end

        def safe_json(body)
          JSON.parse(body)
        rescue JSON::ParserError, EncodingError, ArgumentError
          nil
        end

        # kube-apiserver forbidden message shape:
        #   pods is forbidden: User "alice" cannot list resource "pods" in API group "" in the namespace "ns"
        def forbidden_message(forbidden, request, route)
          identity = forbidden.user&.name
          identity ||= request.identity.is_a?(Hash) ? request.identity["username"] : nil
          identity ||= Security::UserInfo::ANONYMOUS_NAME
          if route.resource_route? && route.resource
            resource = route.resource
            target = route.subresource.to_s.empty? ? resource.resource : "#{resource.resource}/#{route.subresource}"
            verb = forbidden.attributes&.verb || Security::Authorization::Attributes.verb_for(
              method: request.method, collection: route.collection, watch: route.watch_request?(request), name_present: !route.name.to_s.empty?
            )
            scope = route.namespace.to_s.empty? ? " at the cluster scope" : " in the namespace \"#{route.namespace}\""
            "#{target} is forbidden: User \"#{identity}\" cannot #{verb} resource \"#{target}\" in API group \"#{resource.group}\"#{scope}"
          else
            "forbidden: User \"#{identity}\" cannot #{request.method.downcase} path \"#{request.path}\""
          end
        end

        def forbidden_details(route)
          return nil unless route.resource_route? && route.resource

          {"name" => route.name.to_s, "group" => route.resource.group, "kind" => route.resource.resource}.reject do |_key, value|
            value.to_s.empty?
          end
        end

        private

        def normalize_request(input)
          return input if input.is_a?(Request)
          return Request.from_env(input) if input.is_a?(Hash) && input.keys.any? { |key| key.to_s == "REQUEST_METHOD" }
          return Request.new(**symbolize_keys(input)) if input.is_a?(Hash)

          raise ArgumentError, "server input must be Request or request attributes"
        end

        # [entry, nil] once the pipeline let the request in, else [nil, the
        # response that refuses it].
        def enter_security_pipeline(request, route)
          [phase("security") { @security.enter(request, route) }, nil]
        rescue Security::Pipeline::Unauthorized
          [nil, finalize_response(request, error_response(Status::Unauthorized.new("Unauthorized")))]
        rescue Security::Pipeline::BadRequest => bad_request
          [nil, finalize_response(request, error_response(Status::BadRequest.new(bad_request.message)))]
        rescue Security::Pipeline::AuditRejected => audit_rejected
          # A blocking-strict audit webhook refused the RequestReceived event.
          [nil, finalize_response(request, error_response(Status::Error.new(message: "audit logging failed: #{audit_rejected.message}",
                                                                            code: 500, reason: "InternalError")))]
        rescue Security::Pipeline::Forbidden => forbidden
          [nil, finalize_response(request, error_response(forbidden_status(forbidden, request, route)))]
        rescue Security::FlowControl::RejectedError => rejected
          record_request_termination(request, route, 429)
          response = error_response(Status::TooManyRequests.new("too many requests, please try again later",
                                                                retry_after_seconds: rejected.retry_after))
          [nil, finalize_response(request, attach_flow_control_headers(response, rejected.response_headers))]
        end

        def forbidden_status(forbidden, request, route)
          if (status_error = forbidden.status_error)
            return Status::Forbidden.new(status_error.message, details: status_error.details)
          end

          Status::Forbidden.new(forbidden_message(forbidden, request, route), details: forbidden_details(route))
        end

        # Routing, decode, admission and the store, for a request the pipeline
        # let in; whatever is raised becomes the Status response it describes.
        def dispatch_secured(secured, route)
          peer_response = peer_proxy_response(secured, route)
          return peer_response if peer_response

          dispatched = dispatch(secured, route)
          phase("finalize") { finalize_response(secured, dispatched, route: route) }
        rescue Status::Error => status_error
          finalize_response(secured, error_response(status_error))
        rescue MemoryStore::Error, JSON::ParserError, Psych::Exception => store_error
          finalize_response(secured, translate_store_error(store_error))
        rescue JSON::GeneratorError, EncodingError, ArgumentError => encoding_error
          finalize_response(secured,
                            error_response(Status::BadRequest.new("request could not be processed: #{safe_error_message(encoding_error)}")))
        end

        def peer_proxy_response(request, route)
          return unless @peer_proxy

          attributes = request.attributes
          return unless attributes&.resource_request?
          return if route.resource && resource_enabled?(route.resource)

          group = attributes.api_group
          version = attributes.api_version
          return if @aggregator&.claims?(group, version)

          resource = @registry.find_gvr(group: group, version: version, resource: attributes.resource)
          return if resource && resource_enabled?(resource)

          @peer_proxy.forward(request)
        end

        # The audit ResponseComplete stage, with the request object as the
        # client sent it when the request was for a resource.
        def exit_security_pipeline(entry, request, response, error)
          if entry.attributes.resource_request? && request.body.is_a?(String) && !request.body.empty?
            media_type = request.content_type.to_s.split(";", 2).first.to_s.strip.downcase
            request_object = if cbor_request_media_type?(media_type) && feature_gate_enabled?("CBORServingAndStorage")
                               best_effort do
                                 decoded = decode_cbor_body(request.body)
                                 decoded if decoded.is_a?(Hash)
                               end
                             else
                               safe_json(request.body)
                             end
          end
          @security.exit(entry, response, error: error, response_object: response&.body.is_a?(Hash) ? response.body : nil,
                                          request_object: request_object)
        end
      end
    end
  end
end
