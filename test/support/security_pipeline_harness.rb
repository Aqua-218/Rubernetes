# frozen_string_literal: true

# Shared harness extracted from unit/api_security_pipeline_test.rb; included by that
# test and by the tests that used to subclass it (a test file must not require
# another test file: its tests would run under both classes).
require "json"
require "rubernetes/api"
require "rubernetes/security"

module SecurityPipelineHarness
  S = Rubernetes::Security

  API = Rubernetes::API

  class RejectNamedPods < S::Admission::Plugin
    def validate(attributes)
      return unless attributes.resource == "pods"

      attributes.annotate("reject-named-pods.example.com/checked", attributes.object&.dig("metadata", "name").to_s)
      return unless attributes.object&.dig("metadata", "name") == "forbidden-pod"

      raise S::Admission::Rejected.new("pods \"forbidden-pod\" is forbidden: name is reserved", plugin: name)
    end
  end

  class LabelEverything < S::Admission::Plugin
    def admit(attributes)
      return unless attributes.object.is_a?(Hash)

      attributes.object["metadata"]["labels"] = (attributes.object["metadata"]["labels"] || {}).merge("admitted-by" => name)
    end
  end

  def setup
    @store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    rbac_source = Object.new
    roles = {"cluster_roles" => [{"metadata" => {"name" => "pod-reader"},
                                  "rules" => [{"apiGroups" => [""], "resources" => %w[pods], "verbs" => %w[get list create]}]},
                                 {"metadata" => {"name" => "system:public-info-viewer"},
                                  "rules" => [{"nonResourceURLs" => %w[/healthz /version /livez /readyz], "verbs" => %w[get]}]}],
             "cluster_role_bindings" => [{"metadata" => {"name" => "readers"}, "roleRef" => {"kind" => "ClusterRole", "name" => "pod-reader"},
                                          "subjects" => [{"kind" => "User", "name" => "alice"}]},
                                         {"metadata" => {"name" => "system:public-info-viewer"},
                                          "roleRef" => {"kind" => "ClusterRole", "name" => "system:public-info-viewer"},
                                          "subjects" => [{"kind" => "Group", "name" => "system:unauthenticated"},
                                                         {"kind" => "Group", "name" => "system:authenticated"}]}]}
    rbac_source.define_singleton_method(:cluster_roles) { roles["cluster_roles"] }
    rbac_source.define_singleton_method(:cluster_role_bindings) { roles["cluster_role_bindings"] }
    rbac_source.define_singleton_method(:roles) { |_ns| [] }
    rbac_source.define_singleton_method(:role_bindings) { |_ns| [] }
    tokens = S::Authentication::StaticTokenFile.new(S::Authentication::StaticTokenFile.parse("alice-token,alice,1\nbob-token,bob,2\n"))
    @audit = S::Audit::MemoryBackend.new
    policy = S::Audit::Policy.from_h({"apiVersion" => "audit.k8s.io/v1", "kind" => "Policy", "rules" => [{"level" => "RequestResponse"}]})
    @pipeline = S::Pipeline.new(
      authenticator: S::Authentication::Union.new(authenticators: [tokens],
                                                  anonymous: S::Authentication::Union::Anonymous.new(enabled: true, conditions: [{"path" => "/healthz"}])),
      authorizer: S::Authorization::Union.new(authorizers: [S::Authorization::RBAC.new(source: rbac_source)]),
      admission: S::Admission::Chain.new(plugins: [LabelEverything.new("LabelEverything"), RejectNamedPods.new("RejectNamedPods")]),
      audit_policy: policy, audit_backend: @audit
    )
    @server = API::Server.new(store: @store, security: @pipeline)
  end

  def request(method, path, token: nil, body: nil)
    headers = {}
    headers["authorization"] = "Bearer #{token}" if token
    headers["content-type"] = "application/json" if body
    API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body))
  end

  def pod(name)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default"},
     "spec" => {"containers" => [{"name" => "c", "image" => "registry.example/i@sha256:#{"0" * 64}"}]}}
  end
end
