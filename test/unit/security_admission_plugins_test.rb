# frozen_string_literal: true

require "json"
require "securerandom"
require_relative "../test_helper"
require_relative "../support/security_admission_fake_context"
require "rubernetes/security"
require "rubernetes/security/admission/plugins/core"
require "rubernetes/security/admission/plugins/security"
require "rubernetes/security/admission/plugins/pod_security"

class SecurityAdmissionPluginsTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission

  FakeContext = SecurityAdmissionFakeContext

  def setup
    @context = FakeContext.new
    @context.put("namespaces", nil, "team", {"metadata" => {"name" => "team"}, "status" => {"phase" => "Active"}})
    @context.put("namespaces", nil, "dying", {"metadata" => {"name" => "dying"}, "status" => {"phase" => "Terminating"}})
    @context.put("serviceaccounts", "team", "default", {"metadata" => {"name" => "default", "uid" => "sa"}})
  end

  def attributes(operation, resource:, group: "", object: nil, old: nil, namespace: "team", name: nil, subresource: "", user: nil,
                 kind: nil)
    A::Attributes.new(operation: operation, user: user || S::UserInfo.new(name: "alice"), group: group, version: "v1", resource: resource,
                      kind: kind || resource.capitalize, namespace: namespace, name: name || object&.dig("metadata", "name") || old&.dig("metadata",
                                                                                                                                         "name") || "",
                      object: object, old_object: old, subresource: subresource)
  end

  def pod(name, containers: [{"name" => "c", "image" => "i"}], extra: {})
    {"metadata" => {"name" => name, "namespace" => "team"}, "spec" => {"containers" => containers}.merge(extra)}
  end

  def plugin(name)
    A::Registry.factories.fetch(name).call(@context, {})
  end

  def test_registry_covers_the_pinned_corpus_and_builds_the_default_chain
    assert_empty A::Registry.missing_implementations
    chain = A::Registry.default_chain(context: @context)

    assert_equal A::Registry.corpus["default_on"].sort, chain.names.sort
    assert_equal A::Registry.ordered_names.select { |name| chain.names.include?(name) }, chain.names, "chain keeps upstream order"
    assert_raises(S::ConfigurationError) { A::Registry.default_chain(context: @context, enable: ["NoSuchPlugin"]) }
    custom = A::Registry.default_chain(context: @context, enable: ["AlwaysPullImages"], disable: ["ServiceAccount"])

    assert_includes custom.names, "AlwaysPullImages"
    refute_includes custom.names, "ServiceAccount"
  end

  def test_namespace_lifecycle_blocks_terminating_namespaces_and_immortal_deletes
    lifecycle = plugin("NamespaceLifecycle")
    lifecycle.validate(attributes("CREATE", resource: "pods", object: pod("ok")))
    error = assert_raises(A::Rejected) { lifecycle.validate(attributes("CREATE", resource: "pods", object: pod("late"), namespace: "dying")) }
    assert_match(/being terminated/, error.message)
    assert_raises(A::Rejected) { lifecycle.validate(attributes("CREATE", resource: "pods", object: pod("x"), namespace: "missing")) }
    assert_raises(A::Rejected) do
      lifecycle.validate(attributes("DELETE", resource: "namespaces", namespace: "", name: "kube-system",
                                              old: {"metadata" => {"name" => "kube-system"}}))
    end
  end

  def test_service_account_defaults_and_mounts_projected_token
    sa = plugin("ServiceAccount")
    attrs = attributes("CREATE", resource: "pods", object: pod("web"))
    sa.admit(attrs)

    assert_equal "default", attrs.object.dig("spec", "serviceAccountName")
    volume = attrs.object.dig("spec", "volumes").find { |v| v["name"].start_with?("kube-api-access-") }

    refute_nil volume
    assert_equal "token", volume.dig("projected", "sources", 0, "serviceAccountToken", "path")
    assert_equal "/var/run/secrets/kubernetes.io/serviceaccount", attrs.object.dig("spec", "containers", 0, "volumeMounts", 0, "mountPath")
    missing = attributes("CREATE", resource: "pods", object: pod("x", extra: {"serviceAccountName" => "nope"}))
    assert_raises(A::Rejected) { sa.admit(missing) }
    off = attributes("CREATE", resource: "pods", object: pod("y", extra: {"automountServiceAccountToken" => false}))
    sa.admit(off)

    assert_nil off.object.dig("spec", "volumes")
  end

  def test_limit_ranger_defaults_and_enforces
    # A LimitRange that sets max for a resource must also default it, or every
    # Pod without that limit is rejected -- maxConstraint returns
    # "No limit is specified" (plugin/pkg/admission/limitranger/admission.go).
    @context.put("limitranges", "team", "limits",
                 {"spec" => {"limits" => [{"type" => "Container", "default" => {"cpu" => "500m", "memory" => "512Mi"},
                                           "defaultRequest" => {"cpu" => "100m",
                                                                "memory" => "256Mi"}, "max" => {"memory" => "1Gi"}, "min" => {"cpu" => "50m"}}]}})
    ranger = plugin("LimitRanger")
    attrs = attributes("CREATE", resource: "pods", object: pod("web"))
    ranger.admit(attrs)

    assert_equal "500m", attrs.object.dig("spec", "containers", 0, "resources", "limits", "cpu")
    assert_equal "100m", attrs.object.dig("spec", "containers", 0, "resources", "requests", "cpu")
    ranger.validate(attrs)
    big = attributes("CREATE", resource: "pods",
                               object: pod("big",
                                           containers: [{"name" => "c", "resources" => {"limits" => {"memory" => "2Gi"}, "requests" => {"memory" => "2Gi"}}}]))
    assert_raises(A::Rejected) { ranger.validate(big) }
    small = attributes("CREATE", resource: "pods",
                                 object: pod("small", containers: [{"name" => "c", "resources" => {"requests" => {"cpu" => "10m"}}}]))
    assert_raises(A::Rejected) { ranger.validate(small) }
  end

  # maxConstraint: a missing limit is itself a violation, and max is compared
  # against the REQUEST as well.  Skipping the check when the value was absent
  # let a Pod asking for 600Gi through a 1Gi max because it set no limit.
  def test_limit_ranger_rejects_a_request_over_max_with_no_limit
    @context.put("limitranges", "team", "limits",
                 {"spec" => {"limits" => [{"type" => "Container", "max" => {"memory" => "1Gi"}}]}})
    ranger = plugin("LimitRanger")
    over = attributes("CREATE", resource: "pods",
                                object: pod("over", containers: [{"name" => "c", "resources" => {"requests" => {"memory" => "600Gi"}}}]))

    assert_raises(A::Rejected) { ranger.validate(over) }
  end

  def test_limit_ranger_rejects_a_missing_request_when_min_is_set
    @context.put("limitranges", "team", "limits",
                 {"spec" => {"limits" => [{"type" => "Container", "min" => {"cpu" => "50m"}}]}})
    ranger = plugin("LimitRanger")
    bare = attributes("CREATE", resource: "pods",
                                object: pod("bare", containers: [{"name" => "c", "resources" => {}}]))

    assert_raises(A::Rejected) { ranger.validate(bare) }
  end

  def test_priority_default_toleration_and_taint_plugins
    @context.put("priorityclasses", nil, "high", {"metadata" => {"name" => "high"}, "value" => 1000, "preemptionPolicy" => "Never"},
                 group: "scheduling.k8s.io")
    priority = plugin("Priority")
    attrs = attributes("CREATE", resource: "pods", object: pod("p", extra: {"priorityClassName" => "high"}))
    priority.admit(attrs)

    assert_equal 1000, attrs.object.dig("spec", "priority")
    assert_equal "Never", attrs.object.dig("spec", "preemptionPolicy")
    assert_raises(A::Rejected) { priority.admit(attributes("CREATE", resource: "pods", object: pod("q", extra: {"priorityClassName" => "missing"}))) }
    critical = attributes("CREATE", resource: "pods", object: pod("r", extra: {"priorityClassName" => "system-node-critical"}))
    priority.admit(critical)

    assert_equal 2_000_001_000, critical.object.dig("spec", "priority"), "system classes resolve in any namespace (upstream)"
    tolerations = plugin("DefaultTolerationSeconds")
    attrs = attributes("CREATE", resource: "pods", object: pod("t"))
    tolerations.admit(attrs)

    assert_equal 2, attrs.object.dig("spec", "tolerations").length
    assert_equal 300, attrs.object.dig("spec", "tolerations", 0, "tolerationSeconds")
    taint = plugin("TaintNodesByCondition")
    node = attributes("CREATE", resource: "nodes", namespace: "", object: {"metadata" => {"name" => "n1"}, "spec" => {}})
    taint.admit(node)

    assert_equal "node.kubernetes.io/not-ready", node.object.dig("spec", "taints", 0, "key")
  end

  def test_storage_defaults_and_protection
    @context.put("storageclasses", nil, "fast",
                 {"metadata" => {"name" => "fast", "annotations" => {"storageclass.kubernetes.io/is-default-class" => "true"}},
                  "allowVolumeExpansion" => true}, group: "storage.k8s.io")
    claim = {"metadata" => {"name" => "data"}, "spec" => {"resources" => {"requests" => {"storage" => "1Gi"}}}}
    attrs = attributes("CREATE", resource: "persistentvolumeclaims", object: claim)
    plugin("DefaultStorageClass").admit(attrs)

    assert_equal "fast", attrs.object.dig("spec", "storageClassName")
    plugin("StorageObjectInUseProtection").admit(attrs)

    assert_includes attrs.object.dig("metadata", "finalizers"), "kubernetes.io/pvc-protection"
    resize = plugin("PersistentVolumeClaimResize")
    bound = claim.merge("spec" => claim["spec"].merge("storageClassName" => "fast"), "status" => {"phase" => "Bound"})
    grown = bound.merge("spec" => bound["spec"].merge("resources" => {"requests" => {"storage" => "2Gi"}}))
    resize.validate(attributes("UPDATE", resource: "persistentvolumeclaims", object: grown, old: bound))
    unbound = bound.merge("status" => {"phase" => "Pending"})
    assert_raises(A::Rejected) { resize.validate(attributes("UPDATE", resource: "persistentvolumeclaims", object: grown, old: unbound)) }
  end

  def test_node_restriction_limits_kubelets
    kubelet = S::UserInfo.new(name: "system:node:n1", groups: %w[system:nodes])
    restriction = plugin("NodeRestriction")
    @context.put("nodes", nil, "n1", {"metadata" => {"name" => "n1", "uid" => "node-uid"}})
    owner = {"apiVersion" => "v1", "kind" => "Node", "name" => "n1", "uid" => "node-uid", "controller" => true}
    mirror = pod("m", extra: {"nodeName" => "n1"}).tap do |p|
      p["metadata"]["annotations"] = {"kubernetes.io/config.mirror" => "x"}
      p["metadata"]["ownerReferences"] = [owner]
    end
    restriction.validate(attributes("CREATE", resource: "pods", object: mirror, user: kubelet))
    # noderestriction admitPodCreate: the Node must own it as controller,
    # with its own UID, and the Pod must reference no API object.
    {"with an owner reference set to itself" => [],
     "controller owner reference" => [owner.merge("controller" => false)],
     "UID mismatch: expected node-uid got stale" => [owner.merge("uid" => "stale")],
     "must not set blockOwnerDeletion" => [owner.merge("blockOwnerDeletion" => true)]}.each do |message, owners|
      bad = Marshal.load(Marshal.dump(mirror)).tap { |p| p["metadata"]["ownerReferences"] = owners }
      error = assert_raises(A::Rejected) { restriction.validate(attributes("CREATE", resource: "pods", object: bad, user: kubelet)) }
      assert_includes error.message, message
    end
    secret_mirror = Marshal.load(Marshal.dump(mirror)).tap do |p|
      p["spec"]["volumes"] = [{"name" => "s", "projected" => {"sources" => [{"serviceAccountToken" => {"path" => "t"}}]}}]
    end
    error = assert_raises(A::Rejected) { restriction.validate(attributes("CREATE", resource: "pods", object: secret_mirror, user: kubelet)) }
    assert_includes error.message, "can not create pods that reference serviceaccounts (via projected volumes)"
    assert_raises(A::Rejected) do
      restriction.validate(attributes("CREATE", resource: "pods", object: pod("plain", extra: {"nodeName" => "n1"}),
                                                user: kubelet))
    end
    other = pod("o", extra: {"nodeName" => "n2"}).tap { |p| p["metadata"]["annotations"] = {"kubernetes.io/config.mirror" => "x"} }
    assert_raises(A::Rejected) { restriction.validate(attributes("CREATE", resource: "pods", object: other, user: kubelet)) }
    assert_raises(A::Rejected) do
      restriction.validate(attributes("UPDATE", resource: "nodes", namespace: "", name: "n2",
                                                object: {"metadata" => {"name" => "n2"}}, old: {"metadata" => {"name" => "n2"}},
                                                user: kubelet))
    end
    labelled = {"metadata" => {"name" => "n1", "labels" => {"node-restriction.kubernetes.io/tier" => "gold"}}}
    assert_raises(A::Rejected) { restriction.validate(attributes("UPDATE", resource: "nodes", namespace: "", name: "n1", object: labelled, old: {"metadata" => {"name" => "n1"}}, user: kubelet)) }
    ok = {"metadata" => {"name" => "n1", "labels" => {"kubernetes.io/hostname" => "n1", "example.com/rack" => "r1"}}}
    restriction.validate(attributes("UPDATE", resource: "nodes", namespace: "", name: "n1", object: ok,
                                              old: {"metadata" => {"name" => "n1"}}, user: kubelet))
    restriction.validate(attributes("CREATE", resource: "pods", object: pod("any"), user: S::UserInfo.new(name: "alice")))
  end

  def test_resource_quota_rejects_when_exceeded
    @context.put("resourcequotas", "team", "q",
                 {"metadata" => {"name" => "q"}, "spec" => {"hard" => {"pods" => "2", "requests.cpu" => "1"}},
                  "status" => {"hard" => {"pods" => "2", "requests.cpu" => "1"}, "used" => {"pods" => "2", "requests.cpu" => "800m"}}})
    quota = plugin("ResourceQuota")
    third = pod("third", containers: [{"name" => "c", "resources" => {"requests" => {"cpu" => "100m"}}}])
    error = assert_raises(A::Rejected) { quota.validate(attributes("CREATE", resource: "pods", object: third)) }
    assert_match(/pods "third" is forbidden: exceeded quota: q, requested: pods=1, used: pods=2, limited: pods=2/, error.message)
    # pods.go Constraints: a quota on requests.cpu needs every container to request cpu ...
    error = assert_raises(A::Rejected) { quota.validate(attributes("CREATE", resource: "pods", object: pod("bare"))) }
    assert_match(/failed quota: q: must specify requests.cpu for: c/, error.message)
    # ... unless the Pod sets pod-level resources.
    pod_level = pod("pod-level").tap { |value| value["spec"]["resources"] = {"requests" => {"cpu" => "100m"}} }
    error = assert_raises(A::Rejected) { quota.validate(attributes("CREATE", resource: "pods", object: pod_level)) }
    assert_match(/exceeded quota: q, requested: pods=1/, error.message)
    @context.put("resourcequotas", "team", "q",
                 {"metadata" => {"name" => "q"}, "spec" => {"hard" => {"requests.cpu" => "1"}},
                  "status" => {"hard" => {"requests.cpu" => "1"}, "used" => {"requests.cpu" => "800m"}}})
    heavy = pod("heavy", containers: [{"name" => "c", "resources" => {"requests" => {"cpu" => "500m"}}}])
    assert_raises(A::Rejected) { quota.validate(attributes("CREATE", resource: "pods", object: heavy)) }
    light = pod("light", containers: [{"name" => "c", "resources" => {"requests" => {"cpu" => "100m"}}}])
    quota.validate(attributes("CREATE", resource: "pods", object: light))
    # The admitted request is charged, so the next one sees it before the
    # quota controller recomputes usage.
    assert_equal "900m", @context.get("resourcequotas", "team", "q").dig("status", "used", "requests.cpu")
    assert_raises(A::Rejected) { quota.validate(attributes("CREATE", resource: "pods", object: pod("light2", containers: [{"name" => "c", "resources" => {"requests" => {"cpu" => "200m"}}}]))) }
  end

  # plugin/pkg/admission/resourcequota: a failed quota lookup fails the request.
  # Answering "no quotas" to a lookup that raised admitted Pods past their
  # quota ("capture the life of a pod" saw an over-quota Pod created).
  def test_resource_quota_fails_closed_when_the_lookup_raises
    failing = Class.new(FakeContext) do
      def list!(*) = raise(IOError, "read index timed out")
    end.new
    quota = A::Registry.factories.fetch("ResourceQuota").call(failing, {})

    error = assert_raises(A::Rejected) { quota.validate(attributes("CREATE", resource: "pods", object: pod("p"))) }
    assert_match(/could not be read.*read index timed out/, error.message)
  end

  def test_resource_quota_admits_a_request_that_lands_exactly_on_the_limit
    @context.put("resourcequotas", "team", "q",
                 {"metadata" => {"name" => "q"}, "spec" => {"hard" => {"cpu" => "1"}}, "status" => {"hard" => {"cpu" => "1"}, "used" => {"cpu" => "500m"}}})
    quota = plugin("ResourceQuota")
    exact = pod("exact", containers: [{"name" => "c", "resources" => {"requests" => {"cpu" => "500m"}}}])

    quota.validate(attributes("CREATE", resource: "pods", object: exact))

    assert_equal "1", @context.get("resourcequotas", "team", "q").dig("status", "used", "cpu")
  end

  def test_pod_security_enforces_baseline_and_restricted
    @context.put("namespaces", nil, "locked",
                 {"metadata" => {"name" => "locked", "labels" => {"pod-security.kubernetes.io/enforce" => "restricted", "pod-security.kubernetes.io/warn" => "baseline"}}})
    pss = plugin("PodSecurity")
    privileged = pod("p", containers: [{"name" => "c", "securityContext" => {"privileged" => true}}])
    error = assert_raises(A::Rejected) { pss.validate(attributes("CREATE", resource: "pods", object: privileged, namespace: "locked")) }
    assert_match(/violates PodSecurity "restricted:latest"/, error.message)
    assert_match(/privileged/, error.message)
    compliant = pod("ok",
                    containers: [{"name" => "c",
                                  "securityContext" => {"allowPrivilegeEscalation" => false, "capabilities" => {"drop" => ["ALL"]}, "runAsNonRoot" => true,
                                                        "seccompProfile" => {"type" => "RuntimeDefault"}}}])
    attrs = attributes("CREATE", resource: "pods", object: compliant, namespace: "locked")
    pss.validate(attrs)

    assert_empty attrs.warnings
    host_net = pod("h", extra: {"hostNetwork" => true})
    assert_raises(A::Rejected) { pss.validate(attributes("CREATE", resource: "pods", object: host_net, namespace: "locked")) }
    deployment = {"metadata" => {"name" => "d"},
                  "spec" => {"template" => {"metadata" => {}, "spec" => {"hostPID" => true, "containers" => [{"name" => "c"}]}}}}
    attrs = attributes("CREATE", resource: "deployments", group: "apps", object: deployment, namespace: "locked", kind: "Deployment")
    pss.validate(attrs)

    assert_match(/would violate PodSecurity "baseline:latest": host namespaces/, attrs.warnings.first)
    pss.validate(attributes("CREATE", resource: "pods", object: privileged))
  end

  def test_certificate_subject_restriction_and_deny_external_ips
    key = OpenSSL::PKey::EC.generate("prime256v1")
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.new([["CN", "bad"], ["O", "system:masters"]])
    csr.public_key = key
    csr.sign(key, OpenSSL::Digest.new("SHA256"))
    object = {"metadata" => {"name" => "csr"},
              "spec" => {"signerName" => "kubernetes.io/kube-apiserver-client", "request" => [csr.to_pem].pack("m0")}}
    assert_raises(A::Rejected) { plugin("CertificateSubjectRestriction").validate(attributes("CREATE", resource: "certificatesigningrequests", group: "certificates.k8s.io", namespace: "", object: object)) }
    service = {"metadata" => {"name" => "svc"}, "spec" => {"externalIPs" => ["203.0.113.5"]}}
    error = assert_raises(A::Rejected) { plugin("DenyServiceExternalIPs").validate(attributes("CREATE", resource: "services", object: service)) }
    assert_equal 422, error.code
  end

  # admission/reinvocation.go: a mutation alone never reinvokes the chain;
  # once a plugin requests it, the whole chain -- in-tree plugins too -- runs
  # exactly once more.
  def test_chain_reinvokes_the_whole_chain_once_when_requested
    order = []
    first = Class.new(A::Plugin) do
      define_method(:admit) do |attrs|
        order << "first"
        attrs.object["a"] = 1
      end
    end.new("first")
    second = Class.new(A::Plugin) do
      define_method(:admit) do |attrs|
        order << "second"
        attrs.object["b"] = 2
      end
      define_method(:reinvokable?) do
        true
      end
    end.new("second")
    attrs = attributes("CREATE", resource: "pods", object: pod("c"))
    A::Chain.new(plugins: [first, second]).admit(attrs)

    assert_equal %w[first second], order, "an in-tree mutation does not ask for reinvocation"
    refute_predicate attrs, :reinvocation?

    order.clear
    requester = Class.new(A::Plugin) do
      define_method(:admit) do |attrs|
        order << "requester"
        attrs.request_reinvocation!
      end
    end.new("requester")
    attrs = attributes("CREATE", resource: "pods", object: pod("c"))
    A::Chain.new(plugins: [first, requester, second]).admit(attrs)

    assert_equal %w[first requester second first requester second], order
    assert_predicate attrs, :reinvocation?
  end
end
