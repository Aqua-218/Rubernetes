# frozen_string_literal: true

require "securerandom"

require_relative "identity"
require_relative "authentication"
require_relative "authorization"
require_relative "audit"
require_relative "flowcontrol"
require_relative "review_adapter"
require_relative "impersonation"

module Rubernetes
  module Security
    # The request security pipeline (spec/api/api-server.md 5.1.1):
    #   request ID -> authentication -> audit -> impersonation -> authorization -> flow control ->
    #   (routing, decode, admission, strategy, store, encode by API::Server) -> audit.
    # API::Server calls #enter before dispatch and #exit after the response is
    # built; admission is exposed separately because it runs inside the
    # handlers between decode and validation.
    class Pipeline
      AUDIT_ID_HEADER = "audit-id"
      ALWAYS_ALLOWED_PATHS = %w[/healthz /livez /readyz /version].freeze

      Entry = Struct.new(:request, :attributes, :audit, :ticket, :started_at, keyword_init: true)

      attr_reader :authenticator, :authorizer, :flow_control, :audit_policy, :audit_backend, :admission, :impersonation, :metrics

      # endpoints/filters/metrics.go: authentication_* / authorization_*.
      AUTH_BUCKETS = Array.new(15) { |index| 0.001 * (2**index) }.freeze
      KNOWN_USERNAMES = %w[admin client kube_proxy kubelet system:serviceaccount:kube-system:default].freeze

      def metrics=(registry)
        @metrics = registry
        return unless registry

        registry.register("authenticated_user_requests", type: :counter, help: "Counter of authenticated requests broken out by username.")
        registry.register("authentication_attempts", type: :counter, help: "Counter of authenticated attempts.")
        registry.register("authentication_duration_seconds", type: :histogram, buckets: AUTH_BUCKETS,
                                                             help: "Authentication duration in seconds broken out by result.")
        registry.register("authorization_attempts_total", type: :counter,
                                                          help: "Counter of authorization attempts broken down by result. It can be either 'allowed', 'denied', 'no-opinion' or 'error'.")
        registry.register("authorization_duration_seconds", type: :histogram, buckets: AUTH_BUCKETS,
                                                            help: "Authorization duration in seconds broken out by result.")
        @admission.metrics = registry if @admission.respond_to?(:metrics=)
        @audit_backend.metrics = registry if @audit_backend.respond_to?(:metrics=)
        @flow_control.metrics = registry if @flow_control.respond_to?(:metrics=)
        members = @authenticator.respond_to?(:authenticators) ? Array(@authenticator.authenticators) : [@authenticator]
        # A cached token authenticator (Authentication::TokenCache) is judged by the one it wraps.
        members = members.map { |member| member.is_a?(Authentication::TokenCache) ? member.inner : member }
        members.each { |member| member.metrics = registry if member.respond_to?(:metrics=) && !member.class.name.to_s.end_with?("JWTAuthenticator") }
      end

      # Review contract for SubjectAccessReview / SelfSubjectRulesReview and
      # the Pod streaming subresource bridge.
      def review_adapter
        return nil unless @authorizer

        @review_adapter ||= ReviewAdapter.new(@authorizer)
      end

      def initialize(authenticator: nil, authorizer: nil, flow_control: nil, audit_policy: nil, audit_backend: nil, admission: nil,
                     clock: -> { Time.now.utc }, anonymous_paths: ALWAYS_ALLOWED_PATHS, constrained_impersonation: true)
        @authenticator = authenticator
        @authorizer = authorizer
        @flow_control = flow_control
        @audit_policy = audit_policy
        @audit_backend = audit_backend || Audit::MemoryBackend.new
        @admission = admission
        @clock = clock
        @anonymous_paths = anonymous_paths
        # ConstrainedImpersonation (Beta, on in v1.36) picks the filter.
        @impersonation = Impersonation::Filter.new(authorizer, constrained: constrained_impersonation != false)
        @impersonation_filter = constrained_impersonation == false ? "impersonation" : "constrainedimpersonation"
      end

      # Returns an Entry whose request carries identity, request_id and attributes.
      # Raises API::Status errors mapped by the caller (401/403/429).
      FailedResponse = Struct.new(:status, :body)

      def enter(request, route)
        audit_id = request.header(AUDIT_ID_HEADER).to_s
        audit_id = SecureRandom.uuid if audit_id.empty? || audit_id.length > 128
        authentication_started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        user = begin
          traced("security.authenticate") { authenticate(request) }
        rescue Unauthorized => error
          # The failed-authentication handler completes the filter too.
          record_filter("authentication", authentication_started)
          # kube-apiserver's WithFailedAuthenticationAudit: a rejected
          # credential is still audited, with no user information.
          attributes = build_attributes(UserInfo.new(name: ""), request, route)
          failed = @audit_policy ? Audit::Context.new(policy: @audit_policy, backend: @audit_backend, attributes: attributes,
                                                      request: request.with(request_id: audit_id, attributes: attributes), audit_id: audit_id, clock: @clock) : nil
          failed&.annotate("authentication.k8s.io/failed", "true")
          failed&.request_received
          failed&.response_complete(FailedResponse.new(401, {"kind" => "Status", "status" => "Failure", "reason" => "Unauthorized", "message" => "Unauthorized"}))
          raise error
        end
        record_filter("authentication", authentication_started)
        attributes = traced("security.attributes") { build_attributes(user, request, route) }
        authorized = request.with(identity: user.to_h, request_id: audit_id, attributes: attributes)
        audit = filtered("audit") do
          traced("security.audit") do
            context = @audit_policy ? Audit::Context.new(policy: @audit_policy, backend: @audit_backend, attributes: attributes, request: authorized,
                                                         audit_id: audit_id, clock: @clock) : nil
            begin
              context&.request_received
            rescue Audit::RejectedError => error
              # A blocking-strict audit webhook that could not take the
              # RequestReceived event fails the request.
              @metrics&.increment("apiserver_audit_requests_rejected_total")
              raise AuditRejected, error.message
            end
            context
          end
        end
        attributes, authorized = filtered(@impersonation_filter) do
          Impersonation.requested?(request) ? impersonate(attributes, authorized, audit) : [attributes, authorized]
        end
        begin
          filtered("authorization") { traced("security.authorize") { authorize!(attributes) } }
          audit&.annotate("authorization.k8s.io/decision", "allow")
          ticket = @flow_control ? filtered("priorityandfairness") { traced("security.flow_control") { flow_control_enter(attributes, request) } } : nil
        rescue Forbidden => error
          audit&.annotate("authorization.k8s.io/decision", "forbid")
          audit&.annotate("authorization.k8s.io/reason", error.message)
          audit&.response_complete(FailedResponse.new(403, {"kind" => "Status", "status" => "Failure", "reason" => "Forbidden", "message" => error.message}))
          raise
        rescue FlowControl::RejectedError => error
          audit&.annotate("apf.kubernetes.io/rejected", "true")
          audit&.response_complete(FailedResponse.new(429, {"kind" => "Status", "status" => "Failure", "reason" => "TooManyRequests", "message" => error.message}))
          raise
        end
        Entry.new(request: authorized, attributes: attributes, audit: audit, ticket: ticket, started_at: @clock.call)
      end

      def exit(entry, response, response_object: nil, request_object: nil, error: nil)
        return if entry.nil?

        @flow_control&.release(entry.ticket)
        audit = entry.audit
        return unless audit

        audit.request_object = request_object if request_object
        if error
          audit.panic(error)
        else
          audit.response_complete(response, response_object: response_object)
        end
      end

      # filterlatency.TrackStarted/TrackCompleted: the time a filter of the
      # handler chain spends before handing the request on
      # (apiserver_request_filter_duration_seconds); a filter that rejects
      # the request never completes and is not observed.
      def filtered(name)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = yield
        record_filter(name, started)
        result
      end

      def record_filter(name, started)
        @metrics&.observe("apiserver_request_filter_duration_seconds", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started,
                          {"filter" => name})
      rescue StandardError
        nil
      end

      # Per-request phase accounting (API::Server request tracing): a no-op
      # unless the request is traced.
      def traced(name)
        phases = Thread.current[:rubernetes_request_phases]
        return yield unless phases

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        begin
          yield
        ensure
          phases[name] = phases.fetch(name, 0.0) + Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        end
      end

      class Unauthorized < Security::Error; end
      class BadRequest < Security::Error; end
      class AuditRejected < Security::Error; end
      class Forbidden < Security::Error
        attr_reader :decision, :user, :attributes, :status_error

        # +status_error+ carries a message and details of its own (a refused
        # impersonation names the identity, not the request).
        def initialize(message, decision: nil, user: nil, attributes: nil, status_error: nil)
          @decision = decision
          @user = user
          @attributes = attributes
          @status_error = status_error
          super(message)
        end
      end

      private

      # WithConstrainedImpersonation / WithImpersonation, after the audit
      # filter: the event keeps the requester as `user` and gains
      # `impersonatedUser`; authorization, flow control and admission all see
      # the impersonated identity.  A refused impersonation is a 403 naming
      # the identity check, a malformed one a 400.
      def impersonate(attributes, request, audit)
        wanted = @impersonation.wanted_user(request)
        return [attributes, request] unless wanted

        result = @impersonation.impersonate(wanted, attributes)
        audit&.impersonated(result.user, result.constraint)
        impersonated = attributes.with(user: result.user)
        [impersonated, Impersonation.strip_headers(request).with(identity: result.user.to_h, attributes: impersonated)]
      rescue Impersonation::BadRequest => error
        audit&.response_complete(FailedResponse.new(400, {"kind" => "Status", "status" => "Failure", "reason" => "BadRequest", "message" => error.message}))
        raise BadRequest, error.message
      rescue Impersonation::Forbidden => error
        audit&.response_complete(FailedResponse.new(403, {"kind" => "Status", "status" => "Failure", "reason" => "Forbidden", "message" => error.message}))
        raise Forbidden.new(error.message, user: attributes.user, attributes: error.attributes, status_error: error)
      end

      def authenticate(request)
        return UserInfo.from_h(request.identity) if request.identity
        return UserInfo.anonymous unless @authenticator

        context = Authentication::RequestContext.new(headers: request.headers, client_certificate: request.client_certificate,
                                                     client_chain: request.client_chain, remote_address: request.remote_address, path: request.path)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        result = "error"
        begin
          user = @authenticator.authenticate(context).user
          result = "success"
          record_authenticated_user(user)
          user
        rescue AuthenticationError => error
          result = "failure"
          raise Unauthorized, error.message
        ensure
          record_auth("authentication", result, started)
        end
      end

      def record_auth(kind, result, started)
        return unless @metrics

        seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
        counter = kind == "authentication" ? "authentication_attempts" : "authorization_attempts_total"
        @metrics.increment(counter, {"result" => result})
        @metrics.observe("#{kind}_duration_seconds", seconds, {"result" => result})
      rescue StandardError
        nil
      end

      # InstrumentedAuthorizer: each configured authorizer's allow or deny, by
      # type and name (the mode in lower case; "default" for the webhook
      # --authorization-webhook-config-file configures).  The privileged
      # group check ahead of the chain is not instrumented upstream.
      INSTRUMENTED_AUTHORIZERS = %w[Node RBAC ABAC Webhook AlwaysAllow AlwaysDeny].freeze

      def record_authorization_decision(decision)
        return unless @metrics && decision
        return if decision.no_opinion?

        type = decision.authorizer.to_s
        return unless INSTRUMENTED_AUTHORIZERS.include?(type)

        name = type == "Webhook" ? "default" : type.downcase
        @metrics.increment("apiserver_authorization_decisions_total",
                           {"type" => type, "name" => name, "decision" => decision.allowed? ? "allowed" : "denied"})
      rescue StandardError
        nil
      end

      # compressUsername.
      def record_authenticated_user(user)
        return unless @metrics

        name = user.respond_to?(:name) ? user.name.to_s : ""
        label = if KNOWN_USERNAMES.include?(name) then name
                elsif name.include?("@") then "email_id"
                else "other"
                end
        @metrics.increment("authenticated_user_requests", {"username" => label})
      rescue StandardError
        nil
      end

      # The streaming subresources a WebSocket GET reaches.
      CREATE_UPGRADE_SUBRESOURCES = %w[exec attach portforward].freeze

      def authorize!(attributes)
        return if @authorizer.nil?

        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        decision = nil
        begin
          decision = @authorizer.authorize(attributes)
        ensure
          result = if decision.nil? then "error"
                   elsif decision.allowed? then "allowed"
                   elsif decision.respond_to?(:denied?) && decision.denied? then "denied"
                   else "no-opinion"
                   end
          record_auth("authorization", result, started)
          record_authorization_decision(decision)
        end
        raise Forbidden.new(decision.reason || "forbidden", decision: decision, user: attributes.user, attributes: attributes) unless decision.allowed?

        # AuthorizePodWebsocketUpgradeCreatePermission (Beta, on): exec,
        # attach and port-forward over a WebSocket arrive as GET, and still
        # need "create" (ensureAuthorizedForVerb in the pod REST handlers).
        return unless attributes.resource_request? && attributes.api_group.empty? && attributes.resource == "pods" &&
                      CREATE_UPGRADE_SUBRESOURCES.include?(attributes.subresource) && attributes.verb != "create"

        create = attributes.with_verb("create")
        decision = @authorizer.authorize(create)
        return if decision.allowed?

        raise Forbidden.new(decision.reason || "forbidden", decision: decision, user: create.user, attributes: create)
      end

      # RequestInfo (k8s.io/apiserver/pkg/endpoints/request): resource
      # requests get verb/group/version/resource/subresource/namespace/name,
      # everything else is a non-resource path.
      def build_attributes(user, request, route)
        if route.respond_to?(:resource_route?) && route.resource_route? && route.resource
          resource = route.resource
          watch = %w[true 1].include?(request.query_value("watch").to_s) if request.respond_to?(:query_value)
          verb = Authorization::Attributes.verb_for(method: request.method, collection: route.collection, watch: watch == true, name_present: !route.name.to_s.empty?)
          Authorization::Attributes.new(user: user, verb: verb, path: request.path,
                                        namespace: route.namespace, api_group: resource.respond_to?(:group) ? resource.group : route.group,
                                        api_version: resource.respond_to?(:version) ? resource.version : route.version,
                                        resource: resource.respond_to?(:resource) ? resource.resource : route.resource.to_s,
                                        subresource: route.subresource, name: selector_name(verb, route.name, request),
                                        resource_request: true,
                                        field_selector: request.query_value("fieldSelector"), label_selector: request.query_value("labelSelector"))
        elsif (info = api_path_request_info(request))
          # RequestInfoFactory classifies ANY path under /api or /apis as a
          # resource request from its shape alone, whether or not this server
          # serves the resource itself: an aggregated API's flunders are
          # authorized as "create flunders in wardle.example.com", not as a
          # non-resource path (which a resource-only ClusterRole never grants
          # and the Aggregator conformance spec then reads as forbidden).
          Authorization::Attributes.new(user: user, verb: info[:verb], path: request.path,
                                        namespace: info[:namespace], api_group: info[:group], api_version: info[:version],
                                        resource: info[:resource], subresource: info[:subresource],
                                        name: selector_name(info[:verb], info[:name], request),
                                        resource_request: true,
                                        field_selector: request.respond_to?(:query_value) ? request.query_value("fieldSelector") : nil,
                                        label_selector: request.respond_to?(:query_value) ? request.query_value("labelSelector") : nil)
        else
          Authorization::Attributes.new(user: user, verb: Authorization::Attributes.non_resource_verb(request.method), path: request.path, resource_request: false)
        end
      end

      # RequestInfoFactory: a list, watch or deletecollection whose field
      # selector requires metadata.name=<name> is about that one object, so
      # RBAC resourceNames can allow it (an extension API server lists
      # kube-system/extension-apiserver-authentication exactly this way).
      SELECTOR_VERBS = %w[list watch deletecollection].freeze

      def selector_name(verb, name, request)
        return name unless name.to_s.empty? && SELECTOR_VERBS.include?(verb.to_s) && request.respond_to?(:query_value)

        selector = request.query_value("fieldSelector")
        return name if selector.nil? || selector.to_s.empty?

        required = self.class.exact_field_match(selector.to_s, "metadata.name")
        return name if required.nil? || required.empty? || %w[. ..].include?(required) || required.match?(%r{[/%]})

        required
      end

      # fields.Selector.RequiresExactMatch: the value of a "field=value" or
      # "field==value" requirement (backslash escapes allowed).
      def self.exact_field_match(selector, field)
        terms = []
        current = +""
        escaped = false
        selector.each_char do |char|
          if escaped
            current << char
            escaped = false
          elsif char == "\\"
            current << char
            escaped = true
          elsif char == ","
            terms << current
            current = +""
          else
            current << char
          end
        end
        terms << current
        terms.each do |term|
          match = term.strip.match(/\A(.+?)(==|=|!=)(.*)\z/)
          next unless match && match[1].strip == field && match[2] != "!="

          return match[3].gsub(/\\(.)/, "\\1")
        end
        nil
      end

      # k8s.io/apiserver/pkg/endpoints/request RequestInfoFactory.NewRequestInfo
      # for /api/<version>/... and /apis/<group>/<version>/... paths.
      def api_path_request_info(request)
        path = request.path.to_s.split("?", 2).first.to_s
        segments = path.split("/").reject(&:empty?)
        if segments.first == "api"
          return nil if segments.length < 3
          group = ""
          version = segments[1]
          rest = segments[2..]
        elsif segments.first == "apis"
          return nil if segments.length < 4
          group = segments[1]
          version = segments[2]
          rest = segments[3..]
        else
          return nil
        end
        namespace = nil
        if rest.first == "namespaces"
          return nil if rest.length < 3
          namespace = rest[1]
          rest = rest[2..]
        end
        resource, name, subresource = rest[0], rest[1], rest[2]
        return nil if resource.nil?

        watch = request.respond_to?(:query_value) && %w[true 1].include?(request.query_value("watch").to_s)
        verb = Authorization::Attributes.verb_for(method: request.method, collection: name.nil?, watch: watch, name_present: !name.nil?)
        {group: group, version: version, namespace: namespace, resource: resource, name: name, subresource: subresource, verb: verb}
      end
    end
  end
end
