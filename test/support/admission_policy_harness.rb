# frozen_string_literal: true

# Shared harness extracted from unit/security_admission_policy_test.rb; included by that
# test and by the tests that used to subclass it (a test file must not require
# another test file: its tests would run under both classes).
require "json"
require "rubernetes/api"
require "rubernetes/security"

module AdmissionPolicyHarness
  S = Rubernetes::Security

  A = S::Admission

  class FakeContext
    def initialize
      @objects = Hash.new { |hash, key| hash[key] = {} }
    end

    def put(resource, namespace, name, object, group: "")
      @objects[[group, resource, namespace.to_s]][name] = object
    end

    def get(resource, namespace, name, group: "", version: "v1") = @objects[[group, resource, namespace.to_s]][name]

    def list(resource, namespace = nil, group: "", version: "v1")
      return @objects.select { |(g, r, _), _| g == group && r == resource }.values.flat_map(&:values) if namespace.nil?

      @objects[[group, resource, namespace.to_s]].values
    end

    def namespace(name) = get("namespaces", nil, name)
    def feature_enabled?(_gate) = false
    def clock = -> { Time.now.utc }
    def authorizer = nil
    def cel = nil
    def resource_for_kind(_group, kind) = "#{kind.downcase}s"
  end

  def setup
    @context = FakeContext.new
    @context.put("namespaces", nil, "team", {"metadata" => {"name" => "team", "labels" => {"env" => "prod"}}})
  end

  def attributes(operation, object:, old: nil, resource: "deployments", group: "apps", kind: "Deployment", namespace: "team",
                 dry_run: false)
    A::Attributes.new(operation: operation, user: S::UserInfo.new(name: "alice"), group: group, version: "v1", resource: resource, kind: kind,
                      namespace: namespace, name: object.dig("metadata", "name"), object: object, old_object: old, dry_run: dry_run)
  end

  def deployment(replicas:, labels: {})
    {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "web", "namespace" => "team", "labels" => labels},
     "spec" => {"replicas" => replicas}}
  end

  def put_policy(name, validations:, failure_policy: "Fail", audit_annotations: nil, param_kind: nil)
    spec = {"failurePolicy" => failure_policy, "validations" => validations,
            "matchConstraints" => {"resourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => %w[CREATE],
                                                        "resources" => ["deployments"]}]}}
    spec["auditAnnotations"] = audit_annotations if audit_annotations
    spec["paramKind"] = param_kind if param_kind
    @context.put("validatingadmissionpolicies", nil, name, {"metadata" => {"name" => name}, "spec" => spec},
                 group: "admissionregistration.k8s.io")
  end

  def put_binding(name, policy, actions, param_ref: nil)
    spec = {"policyName" => policy, "validationActions" => actions}
    spec["paramRef"] = param_ref if param_ref
    @context.put("validatingadmissionpolicybindings", nil, name, {"metadata" => {"name" => name}, "spec" => spec},
                 group: "admissionregistration.k8s.io")
  end
end
