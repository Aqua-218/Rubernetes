#!/usr/bin/env ruby
# frozen_string_literal: true

# M6 exit criterion 5: the request pipeline runs authentication, then
# authorization, then flow control, then mutating and validating admission,
# then storage, with audit at the end (spec/api/api-server.md 5.1.1), and
# error disclosure follows the specification: 401 for missing/invalid
# credentials, 403 (never 404) for an unauthorized principal, no internal
# class names, paths or tokens in any Status body, and admission rejections
# rendered as Forbidden/Invalid Status objects.  Every stage is a production
# component wrapped with an order recorder.

require_relative "m6_probe_support"

module M6SecurityPipelineProbe
  S = Rubernetes::Security

  class Recorder
    attr_reader :events

    def initialize
      @events = []
    end

    def record(stage)
      @events << stage
    end

    def reset
      @events.clear
    end
  end

  # Wrap a component so every call is logged before delegating.
  def self.observed(target, recorder, stage, method_name)
    wrapper = Object.new
    wrapper.define_singleton_method(method_name) do |*arguments, **keywords, &block|
      recorder.record(stage)
      target.public_send(method_name, *arguments, **keywords, &block)
    end
    wrapper.define_singleton_method(:method_missing) { |name, *arguments, **keywords, &block| target.public_send(name, *arguments, **keywords, &block) }
    wrapper.define_singleton_method(:respond_to_missing?) { |name, include_private = false| target.respond_to?(name, include_private) }
    wrapper
  end

  class OrderedMutator < S::Admission::Plugin
    def initialize(recorder)
      super("OrderedMutator")
      @recorder = recorder
    end

    def admit(attributes)
      @recorder.record("admission.mutating")
      attributes.object["metadata"]["labels"] = (attributes.object["metadata"]["labels"] || {}).merge("mutated" => "true") if attributes.object.is_a?(Hash)
    end
  end

  class OrderedValidator < S::Admission::Plugin
    def initialize(recorder)
      super("OrderedValidator")
      @recorder = recorder
    end

    def validate(attributes)
      @recorder.record("admission.validating")
      raise S::Admission::Rejected.new("configmaps \"denied\" is forbidden: name denied is reserved", plugin: name) if attributes.object&.dig("metadata", "name") == "denied"
    end
  end

  class RecordingStore
    def initialize(store, recorder)
      @store = store
      @recorder = recorder
    end

    def create(*arguments, **keywords, &block)
      @recorder.record("store.create")
      @store.create(*arguments, **keywords, &block)
    end

    def method_missing(name, *arguments, **keywords, &block)
      @store.public_send(name, *arguments, **keywords, &block)
    end

    def respond_to_missing?(name, include_private = false)
      @store.respond_to?(name, include_private)
    end
  end

  class RecordingAuditBackend
    def initialize(recorder, sink)
      @recorder = recorder
      @sink = sink
    end

    def process(event)
      @recorder.record("audit.#{event["stage"]}")
      @sink.process(event)
    end

    def flush(timeout: 0) = true
    def close = nil
  end

  module_function

  def build(recorder)
    tokens = S::Authentication::StaticTokenFile.new(S::Authentication::StaticTokenFile.parse("admin-token,admin,1,system:masters\nalice-token,alice,2\nbob-token,bob,3\n"))
    authenticator = observed(S::Authentication::Union.new(authenticators: [tokens]), recorder, "authentication", :authenticate)
    source = Object.new
    roles = [{"metadata" => {"name" => "cm-writer"}, "rules" => [{"apiGroups" => [""], "resources" => %w[configmaps], "verbs" => %w[create get list]}]}]
    bindings = [{"metadata" => {"name" => "alice"}, "roleRef" => {"kind" => "ClusterRole", "name" => "cm-writer"}, "subjects" => [{"kind" => "User", "name" => "alice"}]}]
    source.define_singleton_method(:cluster_roles) { roles }
    source.define_singleton_method(:cluster_role_bindings) { bindings }
    source.define_singleton_method(:roles) { |_ns| [] }
    source.define_singleton_method(:role_bindings) { |_ns| [] }
    authorizer = observed(S::Authorization::Union.new(authorizers: [S::Authorization::RBAC.new(source: source)]), recorder, "authorization", :authorize)
    plcs = [{"metadata" => {"name" => "all"}, "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 10, "limitResponse" => {"type" => "Queue", "queuing" => {"queues" => 8, "handSize" => 2, "queueLengthLimit" => 10}}}}}]
    schemas = [{"metadata" => {"name" => "all"}, "spec" => {"matchingPrecedence" => 1000, "priorityLevelConfiguration" => {"name" => "all"}, "distinguisherMethod" => {"type" => "ByUser"},
                                                             "rules" => [{"subjects" => [{"kind" => "Group", "group" => {"name" => "*"}}], "resourceRules" => [{"verbs" => ["*"], "apiGroups" => ["*"], "resources" => ["*"], "namespaces" => ["*"], "clusterScope" => true}],
                                                                          "nonResourceRules" => [{"verbs" => ["*"], "nonResourceURLs" => ["*"]}]}]}}]
    flow = observed(S::FlowControl::Controller.new(flow_schemas: schemas, priority_level_configurations: plcs), recorder, "flow_control", :enter)
    sink = S::Audit::MemoryBackend.new
    policy = S::Audit::Policy.from_h({"apiVersion" => "audit.k8s.io/v1", "kind" => "Policy", "rules" => [{"level" => "RequestResponse"}]})
    admission = S::Admission::Chain.new(plugins: [OrderedMutator.new(recorder), OrderedValidator.new(recorder)])
    pipeline = S::Pipeline.new(authenticator: authenticator, authorizer: authorizer, flow_control: flow, audit_policy: policy,
                               audit_backend: RecordingAuditBackend.new(recorder, sink), admission: admission)
    store = RecordingStore.new(Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil), recorder)
    [Rubernetes::API::Server.new(store: store, security: pipeline), sink]
  end

  def request(server, method, path, token: nil, body: nil)
    headers = {}
    headers["authorization"] = "Bearer #{token}" if token
    headers["content-type"] = "application/json" if body
    server.call(Rubernetes::API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body)))
  end

  def configmap(name)
    {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => name, "namespace" => "default"}, "data" => {"k" => "v"}}
  end

  def leak?(body)
    text = JSON.generate(body)
    text.match?(/Rubernetes::|#<|\.rb:\d+|NoMethodError|undefined method|admin-token|alice-token|bob-token|\/root\//)
  end

  def run
    started_at = M6ProbeSupport.now
    recorder = Recorder.new
    server, sink = build(recorder)
    cases = []

    recorder.reset
    created = request(server, "POST", "/api/v1/namespaces/default/configmaps", token: "alice-token", body: configmap("ordered"))
    # kube-apiserver emits the RequestReceived audit stage as soon as the
    # user is known (after authentication, before authorization); the
    # ResponseComplete stage is the final step of the pipeline.
    expected_order = %w[authentication audit.RequestReceived authorization flow_control admission.mutating admission.validating store.create audit.ResponseComplete]
    cases << {"id" => "stage_order_create", "status" => created.status, "observed" => recorder.events.dup, "expected" => expected_order,
              "mutated_label" => created.body.dig("metadata", "labels", "mutated"),
              "passed" => created.status == 201 && recorder.events == expected_order && created.body.dig("metadata", "labels", "mutated") == "true"}

    recorder.reset
    unauthorized = request(server, "POST", "/api/v1/namespaces/default/configmaps", token: "wrong", body: configmap("x"))
    cases << {"id" => "invalid_credentials_stop_at_authentication", "status" => unauthorized.status, "observed" => recorder.events.dup,
              "www_authenticate" => unauthorized.header("www-authenticate"), "reason" => unauthorized.body["reason"],
              "passed" => unauthorized.status == 401 && !recorder.events.include?("authorization") && !recorder.events.include?("admission.mutating") &&
                          unauthorized.header("www-authenticate") == "Bearer" && !leak?(unauthorized.body)}

    recorder.reset
    forbidden = request(server, "POST", "/api/v1/namespaces/default/configmaps", token: "bob-token", body: configmap("x"))
    cases << {"id" => "unauthorized_user_stops_before_admission_and_store", "status" => forbidden.status, "observed" => recorder.events.dup, "message" => forbidden.body["message"],
              "passed" => forbidden.status == 403 && recorder.events.include?("authentication") && recorder.events.include?("authorization") &&
                          !recorder.events.include?("admission.mutating") && !recorder.events.include?("store.create") &&
                          recorder.events.include?("audit.ResponseComplete") &&
                          forbidden.body["message"] == 'configmaps is forbidden: User "bob" cannot create resource "configmaps" in API group "" in the namespace "default"' && !leak?(forbidden.body)}

    recorder.reset
    hidden = request(server, "GET", "/api/v1/namespaces/default/configmaps/does-not-exist", token: "bob-token")
    cases << {"id" => "forbidden_before_not_found", "status" => hidden.status, "reason" => hidden.body["reason"],
              "passed" => hidden.status == 403 && hidden.body["reason"] == "Forbidden" && !leak?(hidden.body)}

    recorder.reset
    denied = request(server, "POST", "/api/v1/namespaces/default/configmaps", token: "alice-token", body: configmap("denied"))
    cases << {"id" => "validating_admission_rejects_after_mutation_before_store", "status" => denied.status, "observed" => recorder.events.dup, "message" => denied.body["message"],
              "passed" => denied.status == 403 && recorder.events.index("admission.mutating") < recorder.events.index("admission.validating") &&
                          !recorder.events.include?("store.create") && denied.body["reason"] == "Forbidden" && !leak?(denied.body)}

    recorder.reset
    malformed = request(server, "POST", "/api/v1/namespaces/default/configmaps", token: "alice-token", body: nil)
    malformed = server.call(Rubernetes::API::Request.new(method: "POST", path: "/api/v1/namespaces/default/configmaps",
                                                          headers: {"authorization" => "Bearer alice-token", "content-type" => "application/json"}, body: "{not json"))
    cases << {"id" => "malformed_body_is_400_without_internal_detail", "status" => malformed.status, "message" => malformed.body["message"],
              "passed" => malformed.status == 400 && malformed.body["reason"] == "BadRequest" && !leak?(malformed.body) && !recorder.events.include?("store.create")}

    audit_events = sink.events
    audit_bodies = JSON.generate(audit_events)
    cases << {"id" => "audit_records_every_outcome_without_credentials", "events" => audit_events.length,
              "stages" => audit_events.map { |event| event["stage"] }.tally,
              "codes" => audit_events.select { |event| event["stage"] == "ResponseComplete" }.map { |event| event.dig("responseStatus", "code") }.tally,
              "passed" => audit_events.count { |event| event["stage"] == "ResponseComplete" } >= 6 && !audit_bodies.include?("alice-token") && !audit_bodies.include?("wrong") &&
                          audit_events.any? { |event| event.dig("responseStatus", "code") == 401 } && audit_events.any? { |event| event.dig("responseStatus", "code") == 403 }}

    M6ProbeSupport.emit(M6ProbeSupport.report(
      kind: "m6_security_pipeline_trace", measurement_level: "integration_tested", started_at: started_at, cases: cases,
      extra: {"specified_order" => %w[tls request_id authentication authorization flow_control routing decode mutating_admission validating_admission strategy store encode audit],
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/security/pipeline.rb lib/rubernetes/api/server.rb lib/rubernetes/security/admission/framework.rb])}
    ))
  end
end

M6SecurityPipelineProbe.run if $PROGRAM_NAME == __FILE__
