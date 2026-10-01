# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require_relative "../support/admission_policy_harness"
require "rubernetes/api"
require "rubernetes/security"

class SecurityAdmissionPolicyTest < Minitest::Test
  include AdmissionPolicyHarness

  def test_validating_admission_policy_denies_warns_and_audits_by_action
    @context.put("validatingadmissionpolicies", nil, "replica-limit",
                 {"metadata" => {"name" => "replica-limit"},
                  "spec" => {"failurePolicy" => "Fail",
                             "matchConstraints" => {"resourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["v1"],
                                                                         "operations" => %w[CREATE UPDATE], "resources" => ["deployments"]}]},
                             "paramKind" => {"apiVersion" => "v1", "kind" => "ConfigMap"},
                             "variables" => [{"name" => "limit", "expression" => "int(params.data.max)"}],
                             "validations" => [{"expression" => "object.spec.replicas <= variables.limit",
                                                "messageExpression" => "'replicas ' + string(object.spec.replicas) + ' exceed ' + " \
                                                                       "string(variables.limit)", "reason" => "Forbidden"}],
                             "auditAnnotations" => [{"key" => "replicas", "valueExpression" => "string(object.spec.replicas)"}]}},
                 group: "admissionregistration.k8s.io")
    @context.put("configmaps", "team", "limits", {"metadata" => {"name" => "limits"}, "data" => {"max" => "3"}})
    @context.put("validatingadmissionpolicybindings", nil, "deny",
                 {"metadata" => {"name" => "deny"}, "spec" => {"policyName" => "replica-limit", "validationActions" => %w[Deny Audit], "paramRef" => {"name" => "limits", "namespace" => "team"},
                                                               "matchResources" => {"namespaceSelector" => {"matchLabels" => {"env" => "prod"}}}}},
                 group: "admissionregistration.k8s.io")
    plugin = A::Registry.factories.fetch("ValidatingAdmissionPolicy").call(@context, {})
    metrics = Rubernetes::Observability::Metrics.new
    plugin.metrics = metrics
    ok = attributes("CREATE", object: deployment(replicas: 2))
    plugin.validate(ok)

    assert_equal "2", ok.annotations["replica-limit/replicas"]
    error = assert_raises(A::Rejected) { plugin.validate(attributes("CREATE", object: deployment(replicas: 5))) }
    assert_equal 403, error.code
    assert_match(/ValidatingAdmissionPolicy 'replica-limit' with binding 'deny' denied request: replicas 5 exceed 3/, error.message)
    text = metrics.render

    assert_includes text,
                    'apiserver_validating_admission_policy_check_total{enforcement_action="deny",error_type="invalid_error",policy="replica-limit",policy_binding="deny"} 1'
    assert_includes text,
                    'apiserver_validating_admission_policy_check_total{enforcement_action="audit",error_type="invalid_error",policy="replica-limit",policy_binding="deny"} 1'
    refute_match(/check_total\{enforcement_action="allow"/, text, "a plain admit is not counted")
    @context.put("validatingadmissionpolicybindings", nil, "deny",
                 {"metadata" => {"name" => "warn"}, "spec" => {"policyName" => "replica-limit", "validationActions" => %w[Warn], "paramRef" => {"name" => "limits", "namespace" => "team"}}}, group: "admissionregistration.k8s.io")
    warned = attributes("CREATE", object: deployment(replicas: 5))
    plugin.validate(warned)

    assert_match(/replicas 5 exceed 3/, warned.warnings.first)
    @context.put("namespaces", nil, "dev", {"metadata" => {"name" => "dev", "labels" => {"env" => "dev"}}})
    plugin.validate(attributes("CREATE", object: deployment(replicas: 9), namespace: "dev"))
  end

  # dispatcher.go: every policy is evaluated -- a later policy's warning and
  # audit annotations still land -- and the first denial is the answer,
  # worded by admission.NewForbidden on the group-qualified resource.
  def test_policies_are_all_evaluated_before_the_first_denial
    put_policy("a-deny", validations: [{"expression" => "object.spec.replicas < 3"}])
    put_binding("a-deny", "a-deny", %w[Deny])
    put_policy("b-warn", validations: [{"expression" => "false", "message" => "  second  "}],
                         audit_annotations: [{"key" => "size", "valueExpression" => "string(object.spec.replicas)"}])
    put_binding("b-warn", "b-warn", %w[Warn Audit])
    plugin = A::Registry.factories.fetch("ValidatingAdmissionPolicy").call(@context, {})
    attrs = attributes("CREATE", object: deployment(replicas: 5))
    error = assert_raises(A::Rejected) { plugin.validate(attrs) }
    assert_equal "deployments.apps \"web\" is forbidden: ValidatingAdmissionPolicy 'a-deny' with binding 'a-deny' denied request: " \
                 "failed expression: object.spec.replicas < 3", error.message
    assert_equal 422, error.code
    assert_equal "Invalid", error.reason
    assert_equal ["Validation failed for ValidatingAdmissionPolicy 'b-warn' with binding 'b-warn': second"], attrs.warnings
    assert_equal "5", attrs.annotations["b-warn/size"]
    failure = JSON.parse(attrs.annotations["validation.policy.admission.k8s.io/validation_failure"])

    assert_equal [{"message" => "second", "policy" => "b-warn", "binding" => "b-warn", "expressionIndex" => 0,
                   "validationActions" => %w[Warn Audit]}], failure
  end

  def test_configuration_errors_follow_the_failure_policy
    put_policy("needs-params", validations: [{"expression" => "true"}], param_kind: {"apiVersion" => "v1", "kind" => "ConfigMap"})
    put_binding("missing", "needs-params", %w[Deny], param_ref: {"name" => "absent", "parameterNotFoundAction" => "Deny"})
    plugin = A::Registry.factories.fetch("ValidatingAdmissionPolicy").call(@context, {})
    error = assert_raises(A::Rejected) { plugin.validate(attributes("CREATE", object: deployment(replicas: 1))) }
    assert_includes error.message,
                    "denied request: failed to configure binding: no params found for policy binding with `Deny` parameterNotFoundAction"
    put_policy("needs-params", validations: [{"expression" => "true"}], param_kind: {"apiVersion" => "v1", "kind" => "ConfigMap"},
                               failure_policy: "Ignore")
    plugin.validate(attributes("CREATE", object: deployment(replicas: 1)))
    put_binding("missing", "needs-params", %w[Deny], param_ref: {"name" => "absent", "parameterNotFoundAction" => "Allow"})
    put_policy("needs-params", validations: [{"expression" => "false"}], param_kind: {"apiVersion" => "v1", "kind" => "ConfigMap"})
    plugin.validate(attributes("CREATE", object: deployment(replicas: 1)))
  end

  def test_mutating_admission_policy_applies_configuration_and_json_patch
    @context.put("mutatingadmissionpolicies", nil, "label",
                 {"metadata" => {"name" => "label"},
                  "spec" => {"matchConstraints" => {"resourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["*"], "operations" => ["CREATE"], "resources" => ["deployments"]}]},
                             "reinvocationPolicy" => "IfNeeded",
                             "mutations" => [{"patchType" => "ApplyConfiguration", "applyConfiguration" => {"expression" => "Object{metadata: " \
                                                                                                                            "Object.metadata{labels: " \
                                                                                                                            "{'owner': 'policy'}}}"}},
                                             {"patchType" => "JSONPatch",
                                              "jsonPatch" => {"expression" => "[JSONPatch{op: 'add', path: '/spec/paused', value: true}]"}}]}},
                 group: "admissionregistration.k8s.io")
    @context.put("mutatingadmissionpolicybindings", nil, "label", {"metadata" => {"name" => "label"}, "spec" => {"policyName" => "label"}},
                 group: "admissionregistration.k8s.io")
    plugin = A::Registry.factories.fetch("MutatingAdmissionPolicy").call(@context, {})
    attrs = attributes("CREATE", object: deployment(replicas: 1, labels: {"app" => "web"}))
    plugin.admit(attrs)

    assert_equal({"app" => "web", "owner" => "policy"}, attrs.object.dig("metadata", "labels"))
    assert_equal true, attrs.object.dig("spec", "paused")
  end

  # patch/smd.go and json_patch.go: an ApplyConfiguration must be an Object,
  # is merged with structured-merge-diff (lists by key), and may not reach
  # into atomic fields; failures are worded by the generic dispatcher.
  def test_mutating_admission_policy_upstream_semantics
    registry = Rubernetes::API::FieldManagerRegistry.new(openapi: Rubernetes::API::OpenAPIRepository.new)
    @context.define_singleton_method(:type_for) do |group, version, kind|
      registry.type_converter(group, version).type_for(group, version, kind)
    end
    policy = lambda do |expression, failure: "Fail"|
      @context.put("mutatingadmissionpolicies", nil, "p",
                   {"metadata" => {"name" => "p"},
                    "spec" => {"failurePolicy" => failure,
                               "matchConstraints" => {"resourceRules" => [{"apiGroups" => ["apps"], "apiVersions" => ["*"],
                                                                           "operations" => ["CREATE"], "resources" => ["deployments"]}]},
                               "mutations" => [{"patchType" => "ApplyConfiguration",
                                                "applyConfiguration" => {"expression" => expression}}]}},
                   group: "admissionregistration.k8s.io")
    end
    @context.put("mutatingadmissionpolicybindings", nil, "b", {"metadata" => {"name" => "b"}, "spec" => {"policyName" => "p"}},
                 group: "admissionregistration.k8s.io")
    plugin = A::Registry.factories.fetch("MutatingAdmissionPolicy").call(@context, {})
    object = deployment(replicas: 1).merge("spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "web"}},
                                                      "template" => {"spec" => {"containers" => [{"name" => "app", "image" => "a:1"}]}}})

    policy.call("{'metadata': {'labels': {'x': 'y'}}}")
    error = assert_raises(A::Rejected) { plugin.admit(attributes("CREATE", object: Marshal.load(Marshal.dump(object)))) }
    assert_equal "policy 'p' with binding 'b' denied request: unsupported return type from ApplyConfiguration expression: map",
                 error.message
    assert_equal "Invalid", error.reason
    assert_equal 403, error.code

    policy.call("Object{spec: Object.spec{selector: Object.spec.selector{matchLabels: {'app': 'other'}}}}")
    error = assert_raises(A::Rejected) { plugin.admit(attributes("CREATE", object: Marshal.load(Marshal.dump(object)))) }
    assert_equal "policy 'p' with binding 'b' denied request: error applying patch: invalid ApplyConfiguration: " \
                 "may not mutate atomic arrays, maps or structs: .spec.selector", error.message

    policy.call("Object{spec: Object.spec{template: Object.spec.template{spec: Object.spec.template.spec{" \
                "containers: [Object.spec.template.spec.containers{name: 'sidecar', image: 's:1'}]}}}}")
    attrs = attributes("CREATE", object: Marshal.load(Marshal.dump(object)))
    plugin.admit(attrs)

    assert_equal([["app", "a:1"], ["sidecar", "s:1"]],
                 attrs.object.dig("spec", "template", "spec", "containers").map { |container| container.values_at("name", "image") })

    policy.call("{'x': 1}", failure: "Ignore")
    ignored = attributes("CREATE", object: Marshal.load(Marshal.dump(object)))
    plugin.admit(ignored)

    assert_equal object["spec"], ignored.object["spec"]
  end

  def test_webhooks_honour_match_policy_failure_policy_dry_run_and_patches
    calls = []
    client = Object.new
    client.define_singleton_method(:call) do |config, review, timeout_seconds:|
      calls << [config["url"], review["request"]["operation"], timeout_seconds]
      uid = review["request"]["uid"]
      case config["url"]
      when "https://mutate.example/"
        patch = [{"op" => "add", "path" => "/metadata/annotations", "value" => {"mutated" => "yes"}}]
        [200,
         {"apiVersion" => review["apiVersion"], "kind" => "AdmissionReview",
          "response" => {"uid" => uid, "allowed" => true, "patchType" => "JSONPatch", "patch" => [JSON.generate(patch)].pack("m0"),
                         "warnings" => ["be careful"]}}]
      when "https://deny.example/"
        [200,
         {"response" => {"uid" => uid, "allowed" => false,
                         "status" => {"message" => "replicas too high", "code" => 422, "reason" => "Invalid"}}}]
      when "https://broken.example/"
        raise A::Plugins::WebhookTimeout, "timed out"
      else
        [500, nil]
      end
    end
    rule = {"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}
    @context.put("mutatingwebhookconfigurations", nil, "m",
                 {"metadata" => {"name" => "m"},
                  "webhooks" => [{"name" => "mutate.example", "clientConfig" => {"url" => "https://mutate.example/"}, "rules" => [rule], "sideEffects" => "None",
                                  "admissionReviewVersions" => ["v1"], "timeoutSeconds" => 5,
                                  "reinvocationPolicy" => "IfNeeded"}]}, group: "admissionregistration.k8s.io")
    @context.put("validatingwebhookconfigurations", nil, "v",
                 {"metadata" => {"name" => "v"}, "webhooks" => [
                   {"name" => "deny.example", "clientConfig" => {"url" => "https://deny.example/"}, "rules" => [rule], "sideEffects" => "None", "admissionReviewVersions" => ["v1"],
                    "matchConditions" => [{"name" => "big", "expression" => "object.spec.replicas > 3"}]},
                   {"name" => "broken.example", "clientConfig" => {"url" => "https://broken.example/"}, "rules" => [rule], "sideEffects" => "Unknown",
                    "admissionReviewVersions" => ["v1"], "failurePolicy" => "Ignore"}
                 ]}, group: "admissionregistration.k8s.io")
    mutating = A::Registry.factories.fetch("MutatingAdmissionWebhook").call(@context, {"client" => client})
    validating = A::Registry.factories.fetch("ValidatingAdmissionWebhook").call(@context, {"client" => client})
    attrs = attributes("CREATE", object: deployment(replicas: 2))
    mutating.admit(attrs)

    assert_equal "yes", attrs.object.dig("metadata", "annotations", "mutated")
    assert_equal ["be careful"], attrs.warnings, "kube-apiserver surfaces webhook warnings verbatim"
    validating.validate(attrs)

    assert_equal "true", attrs.annotations["failed-open.validatingadmissionwebhook.admission.k8s.io/broken.example"],
                 "Ignore failure policy fails open with an audit annotation"
    refute calls.any? { |url, _, _| url == "https://deny.example/" }, "matchConditions excluded the small deployment"
    big = attributes("CREATE", object: deployment(replicas: 5))
    error = assert_raises(A::Rejected) { validating.validate(big) }
    assert_equal 422, error.code
    assert_match(/admission webhook "deny.example" denied the request: replicas too high/, error.message)
    dry = attributes("CREATE", object: deployment(replicas: 5), dry_run: true)
    calls.clear
    # sideEffects None webhooks still run (and may deny) on dry-run; the
    # sideEffects Unknown webhook must not be called at all.
    assert_raises(A::Rejected) { validating.validate(dry) }
    assert(calls.any? { |url, _, _| url == "https://deny.example/" })
    assert calls.none? { |url, _, _| url == "https://broken.example/" }, "sideEffects Unknown webhooks are skipped on dry-run"
    @context.put("validatingwebhookconfigurations", nil, "fail",
                 {"metadata" => {"name" => "fail"}, "webhooks" => [{"name" => "broken.example", "clientConfig" => {"url" => "https://broken.example/"}, "rules" => [rule], "sideEffects" => "None", "admissionReviewVersions" => ["v1"], "failurePolicy" => "Fail"}]}, group: "admissionregistration.k8s.io")
    error = assert_raises(A::Rejected) { validating.validate(attributes("CREATE", object: deployment(replicas: 1))) }
    assert_equal 500, error.code
    assert_match(/failed calling webhook "broken.example"/, error.message)
    update = attributes("UPDATE", object: deployment(replicas: 1), old: deployment(replicas: 1))
    calls.clear
    mutating.admit(update)

    assert_empty calls, "rules scoped to CREATE do not match UPDATE"
  end
end
