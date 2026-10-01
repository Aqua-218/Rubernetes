# frozen_string_literal: true

# PodSecurity admission as k8s.io/pod-security-admission (v1.36.2) behaves:
# ForbiddenDetail wording, namespace label validation, the warnings a
# tightened enforce level produces for existing Pods, exemptions, updates
# that are not significant, audit annotations and pod_security_* metrics.
require_relative "../test_helper"
require_relative "../support/security_admission_fake_context"
require "rubernetes/security"
require "rubernetes/security/admission/plugins/pod_security"
require "rubernetes/observability/metrics"

class PodSecurityAdmissionUpstreamTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission

  def setup
    @context = SecurityAdmissionFakeContext.new
    @context.put("namespaces", nil, "locked",
                 {"metadata" => {"name" => "locked", "labels" => {"pod-security.kubernetes.io/enforce" => "restricted"}}})
    @context.put("namespaces", nil, "open", {"metadata" => {"name" => "open"}})
  end

  def plugin(config = {})
    A::Registry.factories.fetch("PodSecurity").call(@context, config).tap do |instance|
      @metrics = Rubernetes::Observability::Metrics.new
      instance.metrics = @metrics
    end
  end

  def attributes(operation, resource:, object:, old: nil, namespace: "locked", group: "", subresource: "", user: "alice")
    A::Attributes.new(operation: operation, user: S::UserInfo.new(name: user), group: group, version: "v1", resource: resource,
                      kind: resource, namespace: namespace, name: object.dig("metadata", "name").to_s, object: object, old_object: old,
                      subresource: subresource)
  end

  def pod(name, spec)
    {"metadata" => {"name" => name, "namespace" => "locked"}, "spec" => spec}
  end

  def test_the_forbidden_message_and_audit_annotations
    admission = plugin
    bad = pod("web", {"containers" => [{"name" => "app", "image" => "i"}]})
    error = assert_raises(A::Rejected) { admission.validate(attributes("CREATE", resource: "pods", object: bad)) }
    expected = 'pods "web" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false ' \
               '(container "app" must set securityContext.allowPrivilegeEscalation=false), unrestricted capabilities ' \
               '(container "app" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "app" ' \
               'must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "app" must set ' \
               'securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")'

    assert_equal expected, error.message
    assert_equal 403, error.code
    text = @metrics.render

    assert_includes text,
                    %(pod_security_evaluations_total{decision="deny",mode="enforce",policy_level="restricted",policy_version="latest",) +
                    %(request_operation="create",resource="pod",subresource=""} 1)
  end

  def test_invalid_labels_are_refused_on_create
    admission = plugin
    namespace = {"metadata" => {"name" => "typo", "labels" => {"pod-security.kubernetes.io/enforce" => "strict"}}}
    error = assert_raises(A::Rejected) { admission.validate(attributes("CREATE", resource: "namespaces", object: namespace, namespace: "typo")) }
    assert_equal 422, error.code
    assert_equal %(Namespace "typo" is invalid: metadata.labels[pod-security.kubernetes.io/enforce]: Invalid value: "strict": ) +
                 "must be one of privileged, baseline, restricted", error.message
  end

  def test_tightening_enforce_warns_about_existing_pods
    @context.put("pods", "open", "a",
                 pod("a", {"hostNetwork" => true, "containers" => [{"name" => "c"}]}).merge("metadata" => {"name" => "a"}))
    @context.put("pods", "open", "b",
                 pod("b", {"hostNetwork" => true, "containers" => [{"name" => "c"}]}).merge("metadata" => {"name" => "b"}))
    admission = plugin
    old = {"metadata" => {"name" => "open"}}
    updated = {"metadata" => {"name" => "open", "labels" => {"pod-security.kubernetes.io/enforce" => "baseline"}}}
    attrs = attributes("UPDATE", resource: "namespaces", object: updated, old: old, namespace: "open")
    admission.validate(attrs)

    assert_equal ["existing pods in namespace \"open\" violate the new PodSecurity enforce level \"baseline:latest\"",
                  "a (and 1 other pod): host namespaces"], attrs.warnings
  end

  def test_exemptions_and_insignificant_updates
    admission = plugin("exemptions" => {"usernames" => ["system:admin"], "runtimeClasses" => ["kata"]})
    bad = pod("web", {"containers" => [{"name" => "app", "image" => "i"}]})
    attrs = attributes("CREATE", resource: "pods", object: bad, user: "system:admin")
    admission.validate(attrs)

    assert_equal({"pod-security.kubernetes.io/exempt" => "user"}, attrs.annotations)
    kata = pod("kata", {"runtimeClassName" => "kata", "containers" => [{"name" => "app", "image" => "i"}]})
    admission.validate(attributes("CREATE", resource: "pods", object: kata))
    relabelled = bad.merge("metadata" => bad["metadata"].merge("labels" => {"a" => "b"}))
    admission.validate(attributes("UPDATE", resource: "pods", object: relabelled, old: bad))

    assert_includes @metrics.render, %(pod_security_exemptions_total{request_operation="create",resource="pod",subresource=""} 2)
  end

  def test_workloads_warn_and_audit_but_are_not_enforced
    @context.put("namespaces", nil, "watched", {"metadata" => {"name" => "watched", "labels" => {"pod-security.kubernetes.io/enforce" => "restricted",
                                                                                                 "pod-security.kubernetes.io/audit" => "baseline"}}})
    admission = plugin
    deployment = {"metadata" => {"name" => "d"},
                  "spec" => {"template" => {"metadata" => {}, "spec" => {"hostPID" => true, "containers" => [{"name" => "c"}]}}}}
    attrs = attributes("CREATE", resource: "deployments", group: "apps", object: deployment, namespace: "watched")
    admission.validate(attrs)

    assert_equal 1, attrs.warnings.length
    assert_match(/\Awould violate PodSecurity "restricted:latest": host namespaces \(hostPID=true\), /, attrs.warnings.first)
    assert_equal "would violate PodSecurity \"baseline:latest\": host namespaces (hostPID=true)",
                 attrs.annotations["pod-security.kubernetes.io/audit-violations"]
    refute attrs.annotations.key?("pod-security.kubernetes.io/enforce-policy")
  end
end
