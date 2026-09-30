# frozen_string_literal: true

require "json"
require_relative "../../egress"
require "net/http"
require "openssl"
require "securerandom"
require "uri"

require_relative "core"
require_relative "../../../api/managed_fields"

module Rubernetes
  module Security
    module Admission
      module Plugins
        # Shared matching for webhook configurations and admission policies
        # (k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions, rules,
        # namespace / object selectors, matchPolicy Exact / Equivalent).
        module Matching
          def rule_matches?(rule, attributes, match_policy: "Equivalent")
            operations = Array(rule["operations"])
            return false unless operations.include?("*") || operations.include?(attributes.operation)

            groups = Array(rule["apiGroups"])
            versions = Array(rule["apiVersions"])
            resources = Array(rule["resources"])
            scope = rule["scope"] || "*"
            unless scope == "*" || (scope == "Namespaced" && !attributes.namespace.empty?) || (scope == "Cluster" && attributes.namespace.empty?)
              return false
            end
            return false unless groups.include?("*") || groups.include?(attributes.group)
            return false unless versions.include?("*") || versions.include?(attributes.version)

            resources.any? do |candidate|
              candidate == "*" || candidate == "*/*" ||
                (candidate == attributes.resource && attributes.subresource.empty?) ||
                candidate == "#{attributes.resource}/#{attributes.subresource}" ||
                (candidate == "#{attributes.resource}/*") ||
                (candidate == "*/#{attributes.subresource}" && !attributes.subresource.empty?)
            end
          end

          def label_selector_matches?(selector, labels)
            return true if selector.nil? || selector.empty?

            labels ||= {}
            (selector["matchLabels"] || {}).all? { |key, value| labels[key] == value } &&
              Array(selector["matchExpressions"]).all? do |expression|
                values = Array(expression["values"])
                value = labels[expression["key"]]
                case expression["operator"]
                when "In" then values.include?(value)
                when "NotIn" then !values.include?(value)
                when "Exists" then labels.key?(expression["key"])
                when "DoesNotExist" then !labels.key?(expression["key"])
                else false
                end
              end
          end

          def namespace_selector_matches?(selector, attributes)
            return true if selector.nil? || selector.empty?

            labels = if attributes.namespace.empty?
                       nil
                     elsif attributes.resource == "namespaces" && attributes.group.empty?
                       (attributes.object || attributes.old_object)&.dig("metadata", "labels") || {}
                     else
                       namespace = @context.namespace(attributes.namespace)
                       (namespace&.dig("metadata", "labels") || {}).merge("kubernetes.io/metadata.name" => attributes.namespace)
                     end
            return true if labels.nil? && attributes.namespace.empty? && attributes.resource != "namespaces"

            label_selector_matches?(selector, labels)
          end

          def object_selector_matches?(selector, attributes)
            return true if selector.nil? || selector.empty?

            [attributes.object, attributes.old_object].compact.any? do |object|
              label_selector_matches?(selector, object.dig("metadata", "labels"))
            end
          end

          # matchConditions: every expression must be true; an evaluation error
          # follows failurePolicy (Fail -> reject, Ignore -> skip).
          def match_conditions_pass?(conditions, attributes, failure_policy:, name:)
            return true if Array(conditions).empty?

            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            Array(conditions).each do |condition|
              result = cel.evaluate(condition.fetch("expression"), cel_variables(attributes))
              unless result == true
                record_match_condition(name, attributes, "apiserver_admission_match_condition_exclusions_total")
                return false
              end
            rescue CEL::Error => error
              record_match_condition(name, attributes, "apiserver_admission_match_condition_evaluation_errors_total")
              if failure_policy == "Fail"
                raise Rejected.new("failed matchConditions: #{name}: #{condition["name"]}: #{error.message}",
                                   plugin: self.name)
              end

              return false
            end
            true
          ensure
            if started
              record_match_condition(name, attributes, "apiserver_admission_match_condition_evaluation_seconds",
                                     Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
            end
          end

          # webhook/matchconditions/metrics: kind "webhook", type admit or
          # validating, the hook's name and the admission operation.
          def record_match_condition(name, attributes, metric, seconds = nil)
            registry = metrics
            return unless registry

            labels = {"kind" => "webhook", "name" => name.to_s, "operation" => attributes.operation.to_s, "type" => webhook_type}
            seconds ? registry.observe(metric, seconds, labels) : registry.increment(metric, labels)
          rescue StandardError
            nil
          end

          def cel
            @cel ||= if @context.respond_to?(:cel) && @context.cel
                       @context.cel
                     else
                       CEL::Evaluator.new(library: CEL::Library.new(authorizer: (@context.respond_to?(:authorizer) ? @context.authorizer : nil)))
                     end
          end

          def cel_variables(attributes, params: nil, namespace_object: nil)
            {
              "object" => attributes.object,
              "oldObject" => attributes.old_object,
              "request" => admission_request_document(attributes),
              "params" => params,
              "namespaceObject" => namespace_object || (attributes.namespace.empty? ? nil : @context.namespace(attributes.namespace)),
              "authorizer" => CEL::Library::Authorizer.new(@context.respond_to?(:authorizer) ? @context.authorizer : nil, attributes.user,
                                                           nil),
              "variables" => {}
            }
          end

          def admission_request_document(attributes)
            {
              "uid" => attributes.uid,
              "kind" => {"group" => attributes.group, "version" => attributes.version, "kind" => attributes.kind},
              "resource" => {"group" => attributes.group, "version" => attributes.version, "resource" => attributes.resource},
              "subResource" => attributes.subresource.empty? ? nil : attributes.subresource,
              "requestKind" => {"group" => attributes.group, "version" => attributes.version, "kind" => attributes.kind},
              "requestResource" => {"group" => attributes.group, "version" => attributes.version, "resource" => attributes.resource},
              "name" => attributes.name,
              "namespace" => attributes.namespace.empty? ? nil : attributes.namespace,
              "operation" => attributes.operation,
              "userInfo" => attributes.user.to_h,
              "object" => attributes.object,
              "oldObject" => attributes.old_object,
              "dryRun" => attributes.dry_run,
              "options" => attributes.options
            }.compact
          end
        end

        # HTTP client for admission webhooks: URL or service reference, CA
        # bundle, mTLS via the API server's front-proxy client credentials,
        # timeout, 3 MiB body limits.
        class WebhookClient
          WEBHOOK_SECONDS_KEY = :rubernetes_webhook_seconds
          DEFAULT_TIMEOUT = 10
          CONNECT_TIMEOUT = 5
          CONNECT_RETRY_DELAY = 0.5
          MAX_CONNECT_ATTEMPTS = 6
          MAX_TIMEOUT = 30
          MAX_BODY_BYTES = 3 * 1024 * 1024

          # +metrics+: the apiserver registry, or a callable returning it (the
          # plugin receives its registry after construction).
          def initialize(client_certificate: nil, client_key: nil, service_resolver: nil, metrics: nil)
            @client_certificate = client_certificate
            @client_key = client_key
            @service_resolver = service_resolver
            @metrics = metrics
          end

          # x509 metrics (k8s.io/apiserver/pkg/util/x509metrics): a webhook
          # serving certificate without Subject Alternative Names, or signed
          # with SHA-1, counted per call made over it.  Lives on the client,
          # which is the object that made the call: defined on the plugin it
          # was a NoMethodError on every webhook call (2026-09-30, conformance
          # webhook specs all failed "the server could not complete the request").
          def record_x509(http)
            registry = @metrics.respond_to?(:call) ? @metrics.call : @metrics
            certificate = http.respond_to?(:peer_cert) ? http.peer_cert : nil
            return unless registry && certificate

            unless ::Rubernetes::Observability::Metrics.certificate_has_san?(certificate)
              registry.increment("apiserver_webhooks_x509_missing_san_total")
            end
            if ::Rubernetes::Observability::Metrics.certificate_sha1?(certificate)
              registry.increment("apiserver_webhooks_x509_insecure_sha1_total")
            end
          rescue StandardError
            nil
          end

          # Returns [status_code, parsed_body_or_nil].
          def call(client_config, body, timeout_seconds:)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            url = resolve_url(client_config)
            uri = URI.parse(url)
            payload = JSON.generate(body)
            raise Error, "admission review body exceeds #{MAX_BODY_BYTES} bytes" if payload.bytesize > MAX_BODY_BYTES

            timeout = [[timeout_seconds || DEFAULT_TIMEOUT, 1].max, MAX_TIMEOUT].min
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            attempt = 0
            begin
              attempt += 1
              address, address_port = resolve_address(client_config)
              if address.nil? && client_config["service"] && @service_resolver
                # No cluster DNS on this host: falling through to the .svc name
                # produced "getaddrinfo: Name or service not known", which hid
                # the real condition (webhook/aggregator ServiceResolver wording).
                service = client_config.fetch("service")
                raise Error, "no endpoints available for service #{service["namespace"]}/#{service["name"]}"
              end
              http = Security::Egress.http(uri, "cluster", ipaddr: address, port: address_port || uri.port)
              http.use_ssl = uri.scheme == "https"
              remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
              # The connect is bounded separately from the whole call: a
              # single unanswered SYN to an endpoint that had just changed
              # consumed the full 30 s webhook timeout, so the caller's own
              # 30 s readiness poll saw exactly one attempt.  The endpoint is
              # resolved again on retry.
              http.open_timeout = [[CONNECT_TIMEOUT, remaining].min, 0.1].max
              http.read_timeout = [remaining, 0.1].max
              if http.use_ssl?
                http.verify_mode = OpenSSL::SSL::VERIFY_PEER
                bundle = client_config["caBundle"]
                if bundle
                  store = OpenSSL::X509::Store.new
                  OpenSSL::X509::Certificate.load(bundle.unpack1("m0")).each { |certificate| store.add_cert(certificate) }
                  http.cert_store = store
                end
                http.cert = @client_certificate if @client_certificate
                http.key = @client_key if @client_key
              end
              # client-go appends the per-request timeout to the webhook URL.
              target = "#{uri.request_uri}#{uri.query ? "&" : "?"}timeout=#{timeout}s"
              # Inside #start: the peer certificate is only readable while the
              # connection is open (a one-shot #post has closed it already).
              response = http.start do |session|
                session.post(target, payload, {"content-type" => "application/json", "accept" => "application/json"}).tap do
                  record_x509(session)
                end
              end
            rescue Net::OpenTimeout, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH
              raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) + CONNECT_TIMEOUT >= deadline || attempt >= MAX_CONNECT_ATTEMPTS

              sleep(CONNECT_RETRY_DELAY)
              retry
            end
            raise Error, "webhook response exceeds #{MAX_BODY_BYTES} bytes" if response.body.to_s.bytesize > MAX_BODY_BYTES

            [response.code.to_i, response.body.to_s.empty? ? nil : JSON.parse(response.body)]
          rescue JSON::ParserError => error
            raise Error, "webhook returned invalid JSON: #{error.message}"
          rescue Net::OpenTimeout, Net::ReadTimeout
            raise WebhookTimeout,
                  "failed to call webhook: Post #{"#{url}#{uri.query ? "&" : "?"}timeout=#{timeout}s".inspect}: context deadline exceeded"
          rescue OpenSSL::SSL::SSLError, SystemCallError, SocketError, IOError, Net::ProtocolError, Net::HTTPFatalError => error
            raise Error, "failed to call webhook: Post #{"#{url}#{uri.query ? "&" : "?"}timeout=#{timeout}s".inspect}: #{error.message}"
          ensure
            # The request's webhook time, which its SLI latency leaves out
            # (API::Server#call starts the tally).
            spent = Thread.current[WEBHOOK_SECONDS_KEY]
            Thread.current[WEBHOOK_SECONDS_KEY] = spent + (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) if spent
          end

          def resolve_url(client_config)
            return client_config["url"] if client_config["url"]

            service = client_config.fetch("service")
            "https://#{service["name"]}.#{service["namespace"]}.svc:#{service["port"] || 443}#{service["path"] || "/"}"
          end

          # Upstream dials one of the Service's endpoints (there is no cluster
          # DNS on the API server host) while TLS still verifies the
          # `name.namespace.svc` name.  The resolver answers [address, port].
          def resolve_address(client_config)
            return nil if client_config["url"] || @service_resolver.nil?

            service = client_config.fetch("service")
            resolved = @service_resolver.call(service["namespace"], service["name"], service["port"] || 443)
            return nil if resolved.nil?

            resolved.is_a?(Array) ? [resolved[0].to_s, resolved[1] && Integer(resolved[1])] : [resolved.to_s, nil]
          rescue StandardError
            nil
          end
        end

        class WebhookTimeout < Error; end

        # policyReinvokeContext / webhookReinvokeContext (mutating
        # reinvocationcontext.go of both dispatchers): the object as the
        # plugin last left it, the IfNeeded invocations run since the last
        # mutation, and those owed a run on the reinvocation pass.
        class ReinvokeState
          def initialize
            @last_output = nil
            @previously_invoked = Set.new
            @reinvoke = Set.new
          end

          def should_reinvoke?(key) = @reinvoke.include?(key)

          def output_changed?(object) = !Admission.semantically_equal?(@last_output, object)

          def last_output=(object)
            @last_output = object.nil? ? nil : Marshal.load(Marshal.dump(object))
          end

          def add_previously_invoked(key)
            @previously_invoked << key
          end

          def require_reinvoking_previously_invoked
            @reinvoke.merge(@previously_invoked)
            @previously_invoked = Set.new
          end
        end

        # Base for MutatingAdmissionWebhook / ValidatingAdmissionWebhook.
        class AdmissionWebhook < Plugin
          include Helpers
          include Matching

          CONFIGURATION_GROUP = "admissionregistration.k8s.io"
          ADMISSION_REVIEW_VERSIONS = %w[v1 v1beta1].freeze

          def initialize(name, context:, config:)
            super
            @client = config["client"] || WebhookClient.new(client_certificate: config["client_certificate"], client_key: config["client_key"],
                                                            service_resolver: config["service_resolver"], metrics: -> { metrics })
          end

          def handles?(attributes)
            !(attributes.group == CONFIGURATION_GROUP && %w[mutatingwebhookconfigurations
                                                            validatingwebhookconfigurations].include?(attributes.resource))
          end

          def reinvokable?
            true
          end

          private

          def configurations(resource)
            @context.list(resource, nil, group: CONFIGURATION_GROUP)
          end

          def applicable_hooks(configuration, attributes)
            Array(configuration["webhooks"]).select do |hook|
              match_policy = hook["matchPolicy"] || "Equivalent"
              next false unless Array(hook["rules"]).any? { |rule| rule_matches?(rule, attributes, match_policy: match_policy) }
              next false unless namespace_selector_matches?(hook["namespaceSelector"], attributes)
              next false unless object_selector_matches?(hook["objectSelector"], attributes)
              next false if attributes.dry_run && !%w[None NoneOnDryRun].include?(hook["sideEffects"])

              match_conditions_pass?(hook["matchConditions"], attributes, failure_policy: hook["failurePolicy"] || "Fail",
                                                                          name: hook["name"])
            end
          end

          def review_version(hook)
            versions = Array(hook["admissionReviewVersions"])
            version = versions.find { |candidate| ADMISSION_REVIEW_VERSIONS.include?(candidate) }
            raise Rejected.new("webhook #{hook["name"]} does not support any known AdmissionReview version", plugin: name) if version.nil?

            version
          end

          # The webhook admission type label: "admit" for mutating hooks,
          # "validating" for validating ones (webhook dispatchers).
          def webhook_type = is_a?(MutatingAdmissionWebhook) ? "admit" : "validating"

          # ObserveWebhook / ObserveWebhookRejection / ObserveWebhookFailOpen.
          def record_webhook(hook, attributes, started, code:, rejected:, error_type: nil, rejection_code: nil, fail_open: false)
            registry = metrics
            return unless registry

            base = {"name" => hook["name"].to_s, "type" => webhook_type, "operation" => attributes.operation.to_s}
            capped = [code.to_i, 600].min
            registry.observe("apiserver_admission_webhook_admission_duration_seconds",
                             Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, base.merge("rejected" => rejected.to_s))
            registry.increment("apiserver_admission_webhook_request_total", base.merge("code" => capped.to_s, "rejected" => rejected.to_s))
            if error_type
              registry.increment("apiserver_admission_webhook_rejection_count",
                                 base.merge("error_type" => error_type, "rejection_code" => [rejection_code.to_i, 600].min.to_s))
            end
            if fail_open
              registry.increment("apiserver_admission_webhook_fail_open_count",
                                 {"name" => hook["name"].to_s, "type" => webhook_type})
            end
          rescue StandardError
            nil
          end

          def call_hook(hook, attributes, _configuration_name)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            code = 0
            version = review_version(hook)
            request = admission_request_document(attributes)
            review = {"apiVersion" => "admission.k8s.io/#{version}", "kind" => "AdmissionReview", "request" => request}
            code, body = @client.call(hook["clientConfig"], review, timeout_seconds: hook["timeoutSeconds"])
            raise Error, "webhook #{hook["name"]} returned HTTP #{code}" unless code.between?(200, 299)
            raise Error, "webhook #{hook["name"]} returned no response" unless body.is_a?(Hash) && body["response"].is_a?(Hash)

            response = body["response"]
            unless response["uid"] == request["uid"]
              raise Error,
                    "webhook #{hook["name"]} response UID #{response["uid"].inspect} does not match request UID"
            end

            Array(response["warnings"]).each { |warning| attributes.warn(warning.to_s) }
            (response["auditAnnotations"] || {}).each { |key, value| attributes.annotate("#{hook["name"]}/#{key}", value) }
            allowed = response["allowed"] == true
            status = if response["result"].is_a?(Hash)
                       response["result"]
                     else
                       (response["status"].is_a?(Hash) ? response["status"] : {})
                     end
            record_webhook(hook, attributes, started, code: code, rejected: !allowed,
                                                      error_type: allowed ? nil : "no_error",
                                                      rejection_code: if allowed
                                                                        nil
                                                                      else
                                                                        (status["code"].is_a?(Integer) && status["code"] >= 400 ? status["code"] : 0)
                                                                      end)
            response
          rescue Error => error
            failure_policy = hook["failurePolicy"] || "Fail"
            record_webhook(hook, attributes, started, code: code.is_a?(Integer) ? code : 0, rejected: failure_policy != "Ignore",
                                                      error_type: "calling_webhook_error", rejection_code: 0,
                                                      fail_open: failure_policy == "Ignore")
            if failure_policy == "Ignore"
              attributes.annotate("failed-open.#{name.downcase}.admission.k8s.io/#{hook["name"]}", "true")
              return nil
            end
            raise Rejected.new("Internal error occurred: failed calling webhook \"#{hook["name"]}\": #{error.message}", code: 500,
                                                                                                                        reason: "InternalError", plugin: name)
          end

          def reject_from_response!(hook, response)
            # AdmissionResponse.Result is a *metav1.Status carried as "result";
            # reading "status" always found nil -> "denied ... without explanation".
            status = if response["result"].is_a?(Hash)
                       response["result"]
                     else
                       (response["status"].is_a?(Hash) ? response["status"] : {})
                     end
            # k8s.io/apiserver/pkg/admission/plugin/webhook/errors ToStatusErr:
            # the Status' reason stands in for an absent message, and the
            # "without explanation" wording replaces the whole explanation
            # rather than being appended after a second copy of the prefix.
            denied_by = "admission webhook \"#{hook["name"]}\" denied the request"
            explanation = status["message"].to_s.empty? ? status["reason"].to_s : status["message"].to_s
            message = explanation.empty? ? "#{denied_by} without explanation" : "#{denied_by}: #{explanation}"
            code = status["code"].is_a?(Integer) && status["code"] >= 400 ? status["code"] : 400
            raise Rejected.new(message, code: code, reason: status["reason"] || "Forbidden", plugin: name)
          end
        end

        class MutatingAdmissionWebhook < AdmissionWebhook
          # webhookReinvokeContext (webhook/mutating/reinvocationcontext.go),
          # keyed by the webhook accessor UID.
          def admit(attributes)
            state = attributes.reinvocation_value(name) || attributes.set_reinvocation_value(name, ReinvokeState.new)
            state.require_reinvoking_previously_invoked if attributes.reinvocation? && state.output_changed?(attributes.object)
            configurations("mutatingwebhookconfigurations").sort_by do |configuration|
              configuration.dig("metadata", "name").to_s
            end.each do |configuration|
              configuration_name = configuration.dig("metadata", "name").to_s
              seen = Hash.new(0)
              uids = Array(configuration["webhooks"]).to_h do |hook|
                hook_name = hook["name"].to_s
                uid = "#{configuration_name}/#{hook_name}/#{seen[hook_name]}"
                seen[hook_name] += 1
                [hook.object_id, uid]
              end
              applicable_hooks(configuration, attributes).each do |hook|
                uid = uids.fetch(hook.object_id)
                # A hook is never called for the first time on the
                # reinvocation pass, and only IfNeeded hooks run on it.
                next if attributes.reinvocation? && !state.should_reinvoke?(uid)

                response = call_hook(hook, attributes, configuration_name)
                changed = false
                unless response.nil?
                  reject_from_response!(hook, response) unless response["allowed"] == true
                  before = Marshal.load(Marshal.dump(attributes.object))
                  apply_patch(hook, attributes, response)
                  changed = !Admission.semantically_equal?(before, attributes.object)
                end
                if changed
                  state.require_reinvoking_previously_invoked
                  attributes.request_reinvocation!
                end
                state.add_previously_invoked(uid) if hook["reinvocationPolicy"] == "IfNeeded"
              end
            end
          ensure
            state&.last_output = attributes.object
          end

          private

          def apply_patch(hook, attributes, response)
            patch = response["patch"]
            return if patch.nil?
            unless response["patchType"] == "JSONPatch"
              raise Rejected.new("admission webhook \"#{hook["name"]}\" returned an unsupported patch type", code: 500,
                                                                                                             reason: "InternalError", plugin: name)
            end

            operations = JSON.parse(patch.unpack1("m0"))
            attributes.object = API::Patch.apply(attributes.object, operations, type: :json, resource: nil)
          rescue JSON::ParserError, ArgumentError => error
            raise Rejected.new("admission webhook \"#{hook["name"]}\" returned an invalid patch: #{error.message}", code: 500,
                                                                                                                    reason: "InternalError", plugin: name)
          end
        end
        Registry.register("MutatingAdmissionWebhook") do |context, config|
          MutatingAdmissionWebhook.new("MutatingAdmissionWebhook", context: context, config: config)
        end

        class ValidatingAdmissionWebhook < AdmissionWebhook
          def validate(attributes)
            configurations("validatingwebhookconfigurations").sort_by do |configuration|
              configuration.dig("metadata", "name").to_s
            end.each do |configuration|
              applicable_hooks(configuration, attributes).each do |hook|
                response = call_hook(hook, attributes, configuration.dig("metadata", "name"))
                next if response.nil?

                reject_from_response!(hook, response) unless response["allowed"] == true
              end
            end
          end
        end
        Registry.register("ValidatingAdmissionWebhook") do |context, config|
          ValidatingAdmissionWebhook.new("ValidatingAdmissionWebhook", context: context, config: config)
        end

        # ValidatingAdmissionPolicy / MutatingAdmissionPolicy with bindings,
        # paramRef resolution, matchResources, variables, validations with
        # messageExpression, auditAnnotations and validationActions.
        module PolicyCommon
          include Matching

          def bindings_for(policy_name, binding_resource)
            @context.list(binding_resource, nil, group: AdmissionWebhook::CONFIGURATION_GROUP).select { |binding| binding.dig("spec", "policyName") == policy_name }
          end

          def match_resources?(match, attributes)
            return true if match.nil?

            match_policy = match["matchPolicy"] || "Equivalent"
            resource_rules = Array(match["resourceRules"])
            return false if !resource_rules.empty? && resource_rules.none? do |rule|
              rule_matches?(rule, attributes, match_policy: match_policy)
            end
            return false if Array(match["excludeResourceRules"]).any? { |rule| rule_matches?(rule, attributes, match_policy: match_policy) }
            return false unless namespace_selector_matches?(match["namespaceSelector"], attributes)

            object_selector_matches?(match["objectSelector"], attributes)
          end

          def resolve_params(policy, binding, attributes)
            param_kind = policy.dig("spec", "paramKind")
            param_ref = binding.dig("spec", "paramRef")
            return [nil] if param_kind.nil? || param_ref.nil?

            api_version = param_kind["apiVersion"].to_s
            group = api_version.include?("/") ? api_version.split("/").first : ""
            version = api_version.split("/").last
            resource = if @context.respond_to?(:resource_for_kind)
                         @context.resource_for_kind(group,
                                                    param_kind["kind"])
                       else
                         "#{param_kind["kind"].to_s.downcase}s"
                       end
            namespace = param_ref["namespace"] || attributes.namespace
            params = if param_ref["name"]
                       [@context.get(resource, namespace, param_ref["name"], group: group, version: version)].compact
                     else
                       @context.list(resource, namespace, group: group, version: version).select do |object|
                         label_selector_matches?(param_ref["selector"], object.dig("metadata", "labels"))
                       end
                     end
            if params.empty?
              if (param_ref["parameterNotFoundAction"] || "Deny") == "Deny"
                raise Rejected.new("failed to configure binding: no params found for policy binding with `Deny` parameterNotFoundAction",
                                   plugin: name)
              end

              return []
            end
            params
          end

          def evaluate_variables(policy, variables)
            Array(policy.dig("spec", "variables")).each do |variable|
              variables["variables"][variable["name"]] = cel.evaluate(variable["expression"], variables)
            end
            variables
          end
        end

        # ValidatingAdmissionPolicy (admission/plugin/policy/validating
        # dispatcher.go and validator.go, v1.36.2): every matching policy and
        # binding is evaluated -- warnings, audit annotations and metrics for
        # all of them -- and the request is refused with the first denial.
        class ValidatingAdmissionPolicy < Plugin
          include Helpers
          include PolicyCommon

          # A policy decision (policy_decision.go): action admit or deny,
          # evaluation admit / deny / error, the message and reason.
          Decision = Struct.new(:action, :evaluation, :message, :reason, :elapsed, :index)
          Denial = Struct.new(:policy, :binding, :decision)
          MAX_MESSAGE_BYTES = 5 * 1024
          MAX_AUDIT_ANNOTATION_BYTES = 10 * 1024
          FAILURE_ANNOTATION = "validation.policy.admission.k8s.io/validation_failure"

          def validate(attributes)
            denials = []
            @context.list("validatingadmissionpolicies", nil, group: AdmissionWebhook::CONFIGURATION_GROUP).each do |policy|
              policy_name = policy.dig("metadata", "name").to_s
              next unless match_resources?(policy.dig("spec", "matchConstraints"), attributes)

              collector = {}
              bindings_for(policy_name, "validatingadmissionpolicybindings").each do |binding|
                next unless match_resources?(binding.dig("spec", "matchResources"), attributes)

                params = begin
                  collect_params(policy, binding, attributes)
                rescue ConfigurationError => error
                  config_error(denials, policy, binding, error.message)
                  next
                end
                params.each do |param|
                  decisions, annotations = evaluate(policy, attributes, param)
                  dispatch_decisions(denials, policy, binding, attributes, decisions)
                  dispatch_annotations(denials, collector, policy, binding, annotations)
                end
              end
              collector.each do |key, values|
                attributes.annotate("#{policy_name}/#{key}", values.length == 1 ? values.first : values.join(", "))
              end
            end
            raise denial_error(attributes, denials.first) unless denials.empty?
          end

          private

          class ConfigurationError < StandardError; end

          def failure_policy(policy) = policy.dig("spec", "failurePolicy") || "Fail"

          # policyDecisionActionForError.
          def error_action(policy) = failure_policy(policy) == "Ignore" ? :admit : :deny

          # addConfigError.
          def config_error(denials, policy, binding, message)
            case failure_policy(policy)
            when "Ignore" then nil
            when "Fail"
              text = binding ? "failed to configure binding: #{message}" : "failed to configure policy: #{message}"
              denials << Denial.new(policy, binding, Decision.new(:deny, nil, text, nil, 0.0, nil))
            else
              denials << Denial.new(policy, binding,
                                    Decision.new(:deny, nil, "unrecognized failure policy: '#{failure_policy(policy)}'", nil, 0.0, nil))
            end
          end

          # generic.CollectParams.
          def collect_params(policy, binding, attributes)
            param_kind = policy.dig("spec", "paramKind")
            param_ref = binding.dig("spec", "paramRef")
            return [nil] if param_kind.nil? || param_ref.nil?

            api_version = param_kind["apiVersion"].to_s
            group = api_version.include?("/") ? api_version.split("/").first : ""
            version = api_version.split("/").last
            resource = if @context.respond_to?(:resource_for_kind)
                         @context.resource_for_kind(group,
                                                    param_kind["kind"])
                       else
                         "#{param_kind["kind"].to_s.downcase}s"
                       end
            cluster_scoped = @context.respond_to?(:cluster_scoped?) && @context.cluster_scoped?(group, resource)
            namespace = nil
            unless cluster_scoped
              namespace = param_ref["namespace"].to_s.empty? ? attributes.namespace : param_ref["namespace"]
              if namespace.to_s.empty?
                raise ConfigurationError, "cannot use namespaced paramRef in policy binding that matches cluster-scoped resources"
              end
            end
            if !param_ref["namespace"].to_s.empty? && cluster_scoped
              raise ConfigurationError, "paramRef.namespace must not be provided for a cluster-scoped `paramKind`"
            end

            params = if !param_ref["name"].to_s.empty?
                       raise ConfigurationError, "paramRef.name and paramRef.selector are mutually exclusive" if param_ref["selector"]

                       [@context.get(resource, namespace, param_ref["name"], group: group, version: version)].compact
                     elsif param_ref["selector"]
                       @context.list(resource, namespace, group: group, version: version)
                         .select { |object| label_selector_matches?(param_ref["selector"], object.dig("metadata", "labels")) }
                     else
                       raise ConfigurationError, "one of name or selector must be provided"
                     end
            if params.empty? && param_ref["parameterNotFoundAction"] == "Deny"
              raise ConfigurationError, "no params found for policy binding with `Deny` parameterNotFoundAction"
            end

            params
          end

          # validator.Validate: the match conditions, then every validation's
          # decision, then the audit annotations.
          def evaluate(policy, attributes, param)
            namespace_object = attributes.namespace.empty? || attributes.kind == "Namespace" ? nil : @context.namespace(attributes.namespace)
            variables = cel_variables(attributes, params: param, namespace_object: namespace_object)
            begin
              Array(policy.dig("spec", "matchConditions")).each do |condition|
                return [[], []] unless cel.evaluate(condition.fetch("expression"), variables) == true
              end
            rescue CEL::Error => error
              return [[Decision.new(error_action(policy), :error, match_error(policy, error), nil, 0.0, 0)], []]
            end
            begin
              evaluate_variables(policy, variables)
            rescue CEL::Error => error
              return [[Decision.new(error_action(policy), :error, cel_message(error), nil, 0.0, 0)], []]
            end
            decisions = Array(policy.dig("spec", "validations")).each_with_index.map do |validation, index|
              validation_decision(policy, validation, variables, index)
            end
            annotations = Array(policy.dig("spec", "auditAnnotations")).map { |annotation| audit_annotation(policy, annotation, variables) }
            [decisions, annotations]
          end

          def match_error(policy, error)
            "failed to evaluate matchConditions for policy #{policy.dig("metadata", "name")}: #{cel_message(error)}"
          end

          # cel/activation.go ForInput: a compile error or an evaluation error.
          def cel_message(error, expression = nil)
            return "compilation error: #{error.message}" if error.is_a?(CEL::SyntaxError)

            expression ? "expression '#{expression}' resulted in error: #{error.message}" : error.message
          end

          def validation_decision(policy, validation, variables, index)
            expression = validation.fetch("expression").to_s
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            result = begin
              cel.evaluate(expression, variables)
            rescue CEL::Error => error
              return Decision.new(error_action(policy), :error, cel_message(error, expression), nil,
                                  Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, index)
            end
            elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
            return Decision.new(:admit, :admit, nil, nil, elapsed, index) if result == true

            message = nil
            if validation["messageExpression"]
              evaluated = begin
                cel.evaluate(validation["messageExpression"], variables)
              rescue CEL::Error
                nil
              end
              if evaluated.is_a?(String)
                message = evaluated.strip
                message = "" if message.bytesize > MAX_MESSAGE_BYTES || message.include?("\n")
              end
            end
            message = validation["message"].to_s.strip if message.to_s.empty? && !validation["message"].to_s.empty?
            message = "failed expression: #{expression.strip}" if message.to_s.empty?
            Decision.new(:deny, :deny, message, validation["reason"] || "Invalid", elapsed, index)
          end

          AuditAnnotation = Struct.new(:action, :key, :value, :error, :elapsed)

          def audit_annotation(policy, annotation, variables)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            value = cel.evaluate(annotation["valueExpression"].to_s, variables)
            elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
            case value
            when String
              text = value.strip
              if text.empty?
                AuditAnnotation.new(:exclude, annotation["key"], nil, nil,
                                    elapsed)
              else
                AuditAnnotation.new(:publish, annotation["key"], text, nil, elapsed)
              end
            when nil then AuditAnnotation.new(:exclude, annotation["key"], nil, nil, elapsed)
            else
              AuditAnnotation.new(:error, annotation["key"], nil,
                                  "valueExpression '#{annotation["valueExpression"]}' resulted in unsupported return type: #{cel_type(value)}. " \
                                  "Return type must be either string or null.", elapsed)
            end
          rescue CEL::Error => error
            action = failure_policy(policy) == "Fail" ? :error : :exclude
            AuditAnnotation.new(action, annotation["key"], nil, cel_message(error, annotation["valueExpression"]), 0.0)
          end

          def cel_type(value)
            case value
            when Integer then "int"
            when Float then "double"
            when true, false then "bool"
            when Array then "list"
            when Hash then "map"
            else value.class.name.downcase
            end
          end

          def dispatch_decisions(denials, policy, binding, attributes, decisions)
            actions = Array(binding.dig("spec", "validationActions"))
            decisions.each do |decision|
              case decision.action
              when :admit
                observe_policy_check(policy, binding, error_type(decision), "allow", decision.elapsed) if decision.evaluation == :error
              when :deny
                actions.each do |action|
                  case action
                  when "Deny"
                    denials << Denial.new(policy, binding, decision)
                    observe_policy_check(policy, binding, error_type(decision), "deny", decision.elapsed)
                  when "Audit"
                    publish_failure(attributes, binding, decision)
                    observe_policy_check(policy, binding, error_type(decision), "audit", decision.elapsed)
                  when "Warn"
                    attributes.warn("Validation failed for ValidatingAdmissionPolicy '#{policy.dig("metadata", "name")}' with binding " \
                                    "'#{binding.dig("metadata", "name")}': #{decision.message}")
                    observe_policy_check(policy, binding, error_type(decision), "warn", decision.elapsed)
                  end
                end
              end
            end
          end

          def dispatch_annotations(denials, collector, policy, binding, annotations)
            annotations.each do |annotation|
              case annotation.action
              when :publish
                value = annotation.value.byteslice(0, MAX_AUDIT_ANNOTATION_BYTES).to_s
                values = (collector[annotation.key] ||= [])
                values << value unless values.include?(value)
              when :error
                decision = Decision.new(:deny, :error, annotation.error, nil, annotation.elapsed, nil)
                denials << Denial.new(policy, binding, decision)
                observe_policy_check(policy, binding, error_type(decision), "deny", annotation.elapsed)
              end
            end
          end

          # publishValidationFailureAnnotation: admission annotations are
          # never overwritten, so the first failure is the one recorded.
          def publish_failure(attributes, binding, decision)
            return if attributes.annotations.key?(FAILURE_ANNOTATION)

            value = [{"message" => decision.message, "policy" => binding.dig("spec", "policyName"), "binding" => binding.dig("metadata", "name"),
                      "expressionIndex" => decision.index, "validationActions" => Array(binding.dig("spec", "validationActions"))}]
            attributes.annotate(FAILURE_ANNOTATION, JSON.generate(value))
          end

          # errors.go ErrorType.
          def error_type(decision)
            return "no_error" if decision.evaluation == :admit
            return "compile_error" if decision.message.to_s.start_with?("compilation")
            return "out_of_budget" if decision.message.to_s.start_with?("validation failed due to running out of cost budget")

            "invalid_error"
          end

          # apiserver_validating_admission_policy_check_total / _duration_seconds.
          def observe_policy_check(policy, binding, error_type, action, seconds)
            return unless @metrics

            labels = {"policy" => policy.dig("metadata", "name").to_s, "policy_binding" => binding.dig("metadata", "name").to_s,
                      "error_type" => error_type, "enforcement_action" => action}
            @metrics.increment("apiserver_validating_admission_policy_check_total", labels)
            @metrics.observe("apiserver_validating_admission_policy_check_duration_seconds", seconds.to_f, labels)
          rescue StandardError
            nil
          end

          # admission.NewForbidden with the decision's reason and code, the
          # message repeated as a cause.
          def denial_error(attributes, denial)
            policy_name = denial.policy.dig("metadata", "name")
            message = if denial.binding
                        "ValidatingAdmissionPolicy '#{policy_name}' with binding '#{denial.binding.dig("metadata",
                                                                                                       "name")}' denied request: #{denial.decision.message}"
                      else
                        "ValidatingAdmissionPolicy '#{policy_name}' denied request: #{denial.decision.message}"
                      end
            reason = denial.decision.reason.to_s.empty? ? "Invalid" : denial.decision.reason
            code = {"Forbidden" => 403, "Unauthorized" => 401, "RequestEntityTooLarge" => 413, "Invalid" => 422}.fetch(reason, 422)
            resource = attributes.group.empty? ? attributes.resource : "#{attributes.resource}.#{attributes.group}"
            Rejected.new("#{resource} #{attributes.name.inspect} is forbidden: #{message}", code: code, reason: reason,
                                                                                            details: {"name" => attributes.name, "group" => attributes.group, "kind" => attributes.resource,
                                                                                                      "causes" => [{"message" => message}]}.reject do |key, value|
                                                                                              key == "group" && value.to_s.empty?
                                                                                            end,
                                                                                            plugin: name)
          end
        end
        Registry.register("ValidatingAdmissionPolicy") do |context, config|
          ValidatingAdmissionPolicy.new("ValidatingAdmissionPolicy", context: context, config: config)
        end

        # MutatingAdmissionPolicy (admission/plugin/policy/mutating and the
        # generic policy dispatcher, v1.36.2): each matching binding's
        # mutations in order -- an ApplyConfiguration merged the way
        # structured-merge-diff merges an apply, a JSONPatch applied -- and
        # the errors a Fail policy owes turned into one refusal.
        class MutatingAdmissionPolicy < Plugin
          include Helpers
          include PolicyCommon

          PolicyError = Struct.new(:policy, :binding, :message, :reason)
          MF = API::ManagedFields

          def reinvokable?
            true
          end

          def admit(attributes)
            errors = []
            invocations = []
            policies = @context.list("mutatingadmissionpolicies", nil, group: AdmissionWebhook::CONFIGURATION_GROUP)
            policies.sort_by { |policy| policy.dig("metadata", "name").to_s }.each do |policy|
              policy_name = policy.dig("metadata", "name").to_s
              next unless match_resources?(policy.dig("spec", "matchConstraints"), attributes)

              bindings_for(policy_name, "mutatingadmissionpolicybindings").each do |binding|
                next unless match_resources?(binding.dig("spec", "matchResources"), attributes)

                begin
                  resolve_params(policy, binding, attributes).each { |param| invocations << [policy, binding, param] }
                rescue Rejected => error
                  errors << PolicyError.new(policy, binding, error.message.delete_prefix("failed to configure binding: ").then { |m|
                    "failed to configure binding: #{m}"
                  }, nil)
                end
              end
            end
            dispatch_invocations(attributes, invocations, errors) if invocations.any?
            failing = errors.reject { |error| (error.policy.dig("spec", "failurePolicy") || "Fail") == "Ignore" }
            raise refusal(attributes, failing) unless failing.empty?
          end

          private

          # dispatcher.go dispatchInvocations: on the reinvocation pass only
          # the invocations whose key was promoted run; a change to the
          # object, or any applied patch at all (VersionedAttributes.Dirty),
          # asks the chain for that pass.
          def dispatch_invocations(attributes, invocations, errors)
            state = attributes.reinvocation_value(name) || attributes.set_reinvocation_value(name, ReinvokeState.new)
            state.require_reinvoking_previously_invoked if attributes.reinvocation? && state.output_changed?(attributes.object)
            mutated = false
            dirty = false
            invocations.each do |policy, binding, param|
              next unless match_conditions?(policy, binding, param, attributes, errors)

              key = invocation_key(policy, binding, param)
              next if attributes.reinvocation? && !state.should_reinvoke?(key)

              before = Marshal.load(Marshal.dump(attributes.object))
              mutations = Array(policy.dig("spec", "mutations"))
              mutated ||= mutations.any?
              dirty = true if apply_mutations(policy, binding, param, mutations, attributes, errors)
              unless Admission.semantically_equal?(before, attributes.object)
                state.require_reinvoking_previously_invoked
                attributes.request_reinvocation!
              end
              state.add_previously_invoked(key) if policy.dig("spec", "reinvocationPolicy") == "IfNeeded"
            end
            if mutated && !attributes.object.nil? && dirty
              state.require_reinvoking_previously_invoked
              attributes.request_reinvocation!
            end
          ensure
            state&.last_output = attributes.object
          end

          # keyFor: policy, binding and param as namespace/name.
          def invocation_key(policy, binding, param)
            [policy.dig("metadata", "namespace").to_s, policy.dig("metadata", "name").to_s,
             binding.dig("metadata", "namespace").to_s, binding.dig("metadata", "name").to_s,
             param&.dig("metadata", "namespace").to_s, param&.dig("metadata", "name").to_s]
          end

          # The policy's matchConditions (webhook/matchconditions/matcher.go
          # with the policy's failure policy): every condition is evaluated,
          # any false skips the invocation, otherwise evaluation errors are a
          # configuration error (reason Invalid) under Fail and a skip under
          # Ignore.
          def match_conditions?(policy, binding, param, attributes, errors)
            conditions = Array(policy.dig("spec", "matchConditions"))
            return true if conditions.empty?

            variables = cel_variables(attributes, params: param)
            failures = []
            results = conditions.map do |condition|
              expression = condition.fetch("expression").to_s
              cel.evaluate(expression, variables)
            rescue CEL::SyntaxError => error
              failures << cel_error_message(error)
              nil
            rescue CEL::Error => error
              failures << "expression '#{expression}' resulted in error: #{error.message}"
              nil
            end
            return false if results.any?(false)
            return true if failures.empty?
            return false if (policy.dig("spec", "failurePolicy") || "Fail") == "Ignore"

            # utilerrors.NewAggregate: one error reads as itself, several as "[a, b]".
            errors << PolicyError.new(policy, binding, failures.length == 1 ? failures.first : "[#{failures.join(", ")}]", "Invalid")
            false
          end

          # The invocation's mutations in order; true when at least one
          # patch was applied (dispatchOne marks the versioned object Dirty).
          def apply_mutations(policy, binding, param, mutations, attributes, errors)
            applied = false
            mutations.each do |mutation|
              next if attributes.object.nil?

              started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              begin
                mutated = mutate(policy, mutation, attributes, param)
                observe_mutation(policy, binding, "no_error", Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
                attributes.object = if @context.respond_to?(:default_object)
                                      @context.default_object(attributes.group, attributes.version,
                                                              attributes.kind, mutated)
                                    else
                                      mutated
                                    end
                applied = true
              rescue Rejected => error
                observe_mutation(policy, binding, mutation_error_type(error.message),
                                 Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
                raise
              rescue MutationError, CEL::Error => error
                message = error.is_a?(CEL::Error) ? cel_error_message(error) : error.message
                observe_mutation(policy, binding, mutation_error_type(message), Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
                errors << PolicyError.new(policy, binding, message, "Invalid")
              end
            end
            applied
          end

          class MutationError < StandardError; end

          def cel_error_message(error)
            error.is_a?(CEL::SyntaxError) ? "compilation error: #{error.message}" : error.message
          end

          def mutation_error_type(message)
            return "compile_error" if message.start_with?("compilation")
            return "out_of_budget" if message.start_with?("validation failed due to running out of cost budget")

            "invalid_error"
          end

          # A mutation's expression; a runtime failure is worded the way
          # plugin/cel/activation.go reports an evaluation error.
          def evaluate_mutation(expression, variables)
            cel.evaluate(expression, variables)
          rescue CEL::SyntaxError
            raise
          rescue CEL::Error => error
            raise MutationError, "expression '#{expression}' resulted in error: #{error.message}"
          end

          def mutate(policy, mutation, attributes, param)
            variables = evaluate_variables(policy, cel_variables(attributes, params: param))
            case mutation["patchType"]
            when "ApplyConfiguration"
              result = evaluate_mutation(mutation.dig("applyConfiguration", "expression").to_s, variables)
              unless result.is_a?(CEL::Values::ObjectVal)
                raise MutationError, "unsupported return type from ApplyConfiguration expression: #{cel_type_name(result)}"
              end

              mismatches = result.type_name_errors
              raise MutationError, "type mismatch: #{mismatches.join("\n")}" if mismatches.any?

              apply_structured_merge(attributes, deep_plain(result))
            when "JSONPatch"
              operations = evaluate_mutation(mutation.dig("jsonPatch", "expression").to_s, variables)
              raise MutationError, "type mismatch: JSONPatchType.expression should evaluate to array" unless operations.is_a?(Array)

              patch = operations.map { |operation| json_patch_operation(operation) }
              begin
                API::Patch.apply(attributes.object, patch, type: :json, resource: nil)
              rescue API::Patch::Error => error
                return attributes.object if error.message.include?("test")

                raise MutationError, "JSON Patch: #{error.message}"
              end
            else
              raise MutationError, "unsupported patch type #{mutation["patchType"].inspect}"
            end
          end

          # A JSONPatch{op, path, from, value} element (mutation.JSONPatchVal).
          def json_patch_operation(operation)
            unless operation.is_a?(CEL::Values::ObjectVal) && operation.type_name == "JSONPatch"
              raise MutationError, "type mismatch: JSONPatchType.expression should evaluate to array of JSONPatch: " \
                                   "type conversion error from '#{cel_type_name(operation)}' to 'JSONPatch'"
            end
            result = {"op" => operation["op"].to_s, "path" => operation["path"].to_s}
            result["from"] = operation["from"].to_s unless operation["from"].to_s.empty?
            if operation.key?("value")
              value = operation["value"]
              if value.is_a?(CEL::Values::ObjectVal)
                mismatches = value.type_name_errors
                raise MutationError, "type mismatch: #{mismatches.join("\n")}" if mismatches.any?
              end
              result["value"] = deep_plain(value)
            end
            result
          end

          def cel_type_name(value)
            case value
            when Hash then "map"
            when Array then "list"
            when String then "string"
            when Integer then "int"
            when true, false then "bool"
            when nil then "null_type"
            else value.class.name.downcase
            end
          end

          def deep_plain(value)
            case value
            when Hash then value.each_with_object({}) { |(key, item), out| out[key.to_s] = deep_plain(item) }
            when Array then value.map { |item| deep_plain(item) }
            else value
            end
          end

          # ApplyStructuredMergeDiff: the patch typed with the object's schema,
          # no atomic list, map or struct in it, merged into the live object.
          def apply_structured_merge(attributes, patch)
            type = @context.respond_to?(:type_for) ? @context.type_for(attributes.group, attributes.version, attributes.kind) : nil
            model, type_ref = type || [MF::Schema::DEDUCED_MODEL, MF::Schema::DEDUCED_TYPE]
            patch_typed = MF::TypedValue.new(patch, model, type_ref, typed: false)
            errors = patch_typed.validate
            raise MutationError, "error applying patch: failed to convert patch object to typed object: #{errors.join("; ")}" if errors.any?

            atomics = find_atomics([], model, type_ref, patch)
            if atomics.any?
              raise MutationError,
                    "error applying patch: invalid ApplyConfiguration: may not mutate atomic arrays, maps or structs: #{atomics.join(", ")}"
            end

            live = MF::TypedValue.new(attributes.object, model, type_ref, typed: false)
            live.merge(patch_typed).value
          rescue MF::TypedValue::Error => error
            raise MutationError, "error applying patch: failed to merge patch: #{error.message}"
          end

          def find_atomics(path, model, type_ref, value)
            atom = type_ref.empty? ? MF::Schema::DEDUCED_ATOM : model.resolve(type_ref)
            return [] if atom.nil?

            found = []
            if value.is_a?(Hash) && atom.map
              found << path_string(path) if atom.map.atomic?
              value.each do |key, item|
                field = atom.map.find_field(key.to_s)
                next unless field

                found.concat(find_atomics(path + [MF::FieldPath::PathElement.field(key)], model, field.type, item))
              end
            end
            if value.is_a?(Array) && atom.list
              found << path_string(path) if atom.list.atomic?
              value.each_with_index do |item, index|
                found.concat(find_atomics(path + [MF::FieldPath::PathElement.index(index)], model, atom.list.element_type, item))
              end
            end
            found
          end

          def path_string(path) = MF::FieldPath.path_string(path)

          # apiserver_mutating_admission_policy_check_total / _duration_seconds.
          def observe_mutation(policy, binding, error_type, seconds)
            return unless @metrics

            labels = {"policy" => policy.dig("metadata", "name").to_s, "policy_binding" => binding.dig("metadata", "name").to_s,
                      "error_type" => error_type}
            @metrics.increment("apiserver_mutating_admission_policy_check_total", labels)
            @metrics.observe("apiserver_mutating_admission_policy_check_duration_seconds", seconds, labels)
          rescue StandardError
            nil
          end

          # policy_dispatcher.go: admission.NewForbidden whose message is
          # the first error ("policy '<p>' with binding '<b>' denied request:
          # <message>"), its reason when it has one, every error a cause.
          def refusal(attributes, errors)
            messages = errors.map do |error|
              "policy '#{error.policy.dig("metadata",
                                          "name")}' with binding '#{error.binding.dig("metadata",
                                                                                      "name")}' denied request: #{error.message}"
            end
            details = {"name" => attributes.name, "group" => attributes.group, "kind" => attributes.resource,
                       "causes" => messages.map { |message| {"message" => message} }}
            details.delete("group") if attributes.group.empty?
            Rejected.new(messages.first, code: 403, reason: errors.first.reason || "Forbidden", details: details, plugin: name)
          end
        end
        Registry.register("MutatingAdmissionPolicy") do |context, config|
          MutatingAdmissionPolicy.new("MutatingAdmissionPolicy", context: context, config: config)
        end
      end
    end
  end
end
