# frozen_string_literal: true

require "openssl"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/security/admission/plugins/security"
require_relative "../support/security_admission_fake_context"

# NodeRestriction as plugin/pkg/admission/noderestriction (v1.36.2) admits a
# kubelet's writes: Pods only as mirror Pods (create/delete, never update),
# status without label or claim-status changes, evictions of its own Pods, its
# Node with registration taints but no reserved labels, claim resize status
# only, tokens bound to its Pods by UID, its own Lease / CSINode by the
# object's name on create, its own ResourceSlices, PodCertificateRequests
# behind their gate, and kubelet CSRs whose CN is the node.
class NodeRestrictionUpstreamTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission

  def setup
    @context = SecurityAdmissionFakeContext.new
    @kubelet = S::UserInfo.new(name: "system:node:n1", groups: %w[system:nodes])
    @plugin = A::Registry.factories.fetch("NodeRestriction").call(@context, {})
    @context.put("nodes", nil, "n1", {"metadata" => {"name" => "n1", "uid" => "node-uid"}})
    @context.put("pods", "team", "mine", {"metadata" => {"name" => "mine", "namespace" => "team", "uid" => "mine-uid"},
                                          "spec" => {"nodeName" => "n1", "serviceAccountName" => "sa"}})
    @context.put("pods", "team", "theirs", {"metadata" => {"name" => "theirs", "namespace" => "team", "uid" => "theirs-uid"},
                                            "spec" => {"nodeName" => "n2"}})
  end

  def admit(operation, resource, group: "", namespace: "team", name: "", object: nil, old: nil, subresource: "", user: @kubelet)
    @plugin.validate(A::Attributes.new(operation: operation, user: user, group: group, version: "v1", resource: resource, kind: "X",
                                       namespace: namespace, name: name, object: object, old_object: old, subresource: subresource))
  end

  def rejected(message = nil, &block)
    error = assert_raises(A::Rejected, &block)
    assert_includes error.message, message if message
    error
  end

  def test_pods
    rejected("can only create and delete mirror pods") do
      admit("UPDATE", "pods", name: "mine", object: {"spec" => {"nodeName" => "n1"}}, old: {"spec" => {"nodeName" => "n1"}})
    end
    admit("DELETE", "pods", name: "mine", old: {"spec" => {"nodeName" => "n1"}})
    rejected("can only delete pods with spec.nodeName set to itself") { admit("DELETE", "pods", name: "theirs") }
    error = rejected { admit("DELETE", "pods", name: "gone") }
    assert_equal 404, error.code
    rejected("unexpected pod subresource \"binding\"") { admit("CREATE", "pods", name: "mine", subresource: "binding", object: {}) }
  end

  def test_pod_status
    old = {"metadata" => {"labels" => {"a" => "1"}}, "spec" => {"nodeName" => "n1"},
           "status" => {"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => "c1"}]}}
    admit("UPDATE", "pods", name: "mine", subresource: "status", old: old, object: old.merge("status" => old["status"].merge("phase" => "Running")))
    rejected("cannot update labels through pod status") do
      admit("UPDATE", "pods", name: "mine", subresource: "status", old: old, object: old.merge("metadata" => {"labels" => {"a" => "2"}}))
    end
    rejected("cannot update resource claim statues") do
      admit("UPDATE", "pods", name: "mine", subresource: "status", old: old,
                              object: old.merge("status" => {"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => "c2"}]}))
    end
    rejected("cannot update extended resource claim status") do
      admit("UPDATE", "pods", name: "mine", subresource: "status", old: old,
                              object: old.merge("status" => old["status"].merge("extendedResourceClaimStatus" => {"resourceClaimName" => "x"})))
    end
    rejected("can only update pod status for pods with spec.nodeName set to itself") do
      admit("UPDATE", "pods", name: "theirs", subresource: "status", old: {"spec" => {"nodeName" => "n2"}}, object: {"spec" => {"nodeName" => "n2"}})
    end
  end

  def test_evictions
    admit("CREATE", "pods", name: "mine", subresource: "eviction", object: {"metadata" => {"name" => "mine"}})
    admit("CREATE", "pods", subresource: "eviction", object: {"metadata" => {"name" => "mine"}})
    rejected("can only evict pods with spec.nodeName set to itself") do
      admit("CREATE", "pods", name: "theirs", subresource: "eviction", object: {})
    end
    rejected("could not determine pod from request data") { admit("CREATE", "pods", subresource: "eviction", object: {}) }
  end

  def test_nodes
    registration = {"metadata" => {"name" => "n1", "labels" => {"kubernetes.io/hostname" => "n1", "example.com/rack" => "r"}},
                    "spec" => {"taints" => [{"key" => "dedicated", "effect" => "NoSchedule"}]}}
    admit("CREATE", "nodes", namespace: "", object: registration)
    rejected("not allowed to create pods with a non-nil configSource") do
      admit("CREATE", "nodes", namespace: "", object: registration.merge("spec" => {"configSource" => {}}))
    end
    rejected("not allowed to set the following labels: foo.k8s.io/x, node-restriction.kubernetes.io/tier") do
      admit("CREATE", "nodes", namespace: "", object: {"metadata" => {"name" => "n1",
                                                                     "labels" => {"node-restriction.kubernetes.io/tier" => "a", "foo.k8s.io/x" => "b",
                                                                                  "x.node.kubernetes.io/ok" => "c", "kubelet.kubernetes.io/ok" => "d"}}})
    end
    rejected("is not allowed to modify node \"n2\"") { admit("UPDATE", "nodes", namespace: "", name: "n2", object: {}, old: {}) }
    old = {"metadata" => {"name" => "n1", "labels" => {"kubernetes.io/arch" => "amd64"}}}
    rejected("not allowed to modify taints") do
      admit("UPDATE", "nodes", namespace: "", name: "n1", subresource: "status", old: old, object: old.merge("spec" => {"taints" => [{"key" => "k"}]}))
    end
    rejected("is not allowed to modify labels: kubernetes.io/role") do
      admit("UPDATE", "nodes", namespace: "", name: "n1", old: old,
                               object: {"metadata" => {"name" => "n1", "labels" => {"kubernetes.io/arch" => "amd64", "kubernetes.io/role" => "x"}}})
    end
    admit("UPDATE", "nodes", namespace: "", name: "n1", old: old,
                             object: {"metadata" => {"name" => "n1", "labels" => {"kubernetes.io/arch" => "arm64"}}})
  end

  def test_claims
    old = {"metadata" => {"name" => "c", "resourceVersion" => "1", "labels" => {"a" => "b"}},
           "spec" => {"resources" => {"requests" => {"storage" => "1Gi"}}}, "status" => {"phase" => "Bound", "capacity" => {"storage" => "1Gi"}}}
    resized = old.merge("metadata" => old["metadata"].merge("resourceVersion" => "2"),
                        "status" => {"phase" => "Bound", "capacity" => {"storage" => "2Gi"}, "conditions" => [],
                                     "allocatedResourceStatuses" => {"storage" => "NodeResizeInProgress"}})
    admit("UPDATE", "persistentvolumeclaims", name: "c", subresource: "status", old: old, object: resized)
    rejected("not allowed to update fields other than status.quantity and status.conditions") do
      admit("UPDATE", "persistentvolumeclaims", name: "c", subresource: "status", old: old,
                                                object: resized.merge("metadata" => {"name" => "c", "labels" => {"a" => "evil"}}))
    end
    rejected("not allowed to update fields other than") do
      admit("UPDATE", "persistentvolumeclaims", name: "c", subresource: "status", old: old,
                                                object: resized.merge("status" => resized["status"].merge("phase" => "Lost")))
    end
    rejected("may only update PVC status") { admit("UPDATE", "persistentvolumeclaims", name: "c", old: old, object: old) }
  end

  def token(ref)
    {"spec" => {"audiences" => [], "boundObjectRef" => ref}}
  end

  def test_tokens
    @context.feature_gates["ServiceAccountNodeAudienceRestriction"] = false
    ref = {"apiVersion" => "v1", "kind" => "Pod", "name" => "mine", "uid" => "mine-uid"}
    admit("CREATE", "serviceaccounts", name: "sa", subresource: "token", object: token(ref))
    rejected("node requested token not bound to a pod") { admit("CREATE", "serviceaccounts", name: "sa", subresource: "token", object: token(nil)) }
    rejected("node requested token not bound to a pod") do
      admit("CREATE", "serviceaccounts", name: "sa", subresource: "token", object: token(ref.merge("kind" => "Secret")))
    end
    rejected("without a uid") { admit("CREATE", "serviceaccounts", name: "sa", subresource: "token", object: token(ref.merge("uid" => ""))) }
    rejected("does not match the UID in record") do
      admit("CREATE", "serviceaccounts", name: "sa", subresource: "token", object: token(ref.merge("uid" => "stale")))
    end
    rejected("bound to a pod scheduled on a different node") do
      admit("CREATE", "serviceaccounts", name: "sa", subresource: "token", object: token(ref.merge("name" => "theirs", "uid" => "theirs-uid")))
    end
    admit("UPDATE", "serviceaccounts", name: "sa", object: {}, old: {})
  end

  def test_leases_csinodes_and_slices
    admit("CREATE", "leases", group: "coordination.k8s.io", namespace: "kube-node-lease", object: {"metadata" => {"name" => "n1"}})
    rejected("same name as the requesting node") do
      admit("CREATE", "leases", group: "coordination.k8s.io", namespace: "kube-node-lease", object: {"metadata" => {"name" => "n2"}})
    end
    rejected("kube-node-lease") { admit("UPDATE", "leases", group: "coordination.k8s.io", namespace: "default", name: "n1", object: {}, old: {}) }
    admit("CREATE", "csinodes", group: "storage.k8s.io", namespace: "", object: {"metadata" => {"name" => "n1"}})
    rejected("CSINode with the same name") { admit("CREATE", "csinodes", group: "storage.k8s.io", namespace: "", object: {"metadata" => {"name" => "n2"}}) }
    rejected("CSINode with the same name") { admit("UPDATE", "csinodes", group: "storage.k8s.io", namespace: "", name: "n2", object: {}, old: {}) }
    admit("CREATE", "resourceslices", group: "resource.k8s.io", namespace: "", object: {"spec" => {"nodeName" => "n1"}})
    rejected("can only create ResourceSlice") { admit("CREATE", "resourceslices", group: "resource.k8s.io", namespace: "", object: {"spec" => {}}) }
    rejected("can only delete ResourceSlice") do
      admit("DELETE", "resourceslices", group: "resource.k8s.io", namespace: "", name: "s", old: {"spec" => {"nodeName" => "n2"}})
    end
  end

  def csr(common_name)
    key = OpenSSL::PKey::EC.generate("prime256v1")
    request = OpenSSL::X509::Request.new
    request.subject = OpenSSL::X509::Name.new([["CN", common_name], ["O", "system:nodes"]])
    request.public_key = key
    request.sign(key, OpenSSL::Digest.new("SHA256"))
    [request.to_pem].pack("m0")
  end

  def test_kubelet_csrs_must_name_the_node
    object = {"spec" => {"signerName" => "kubernetes.io/kube-apiserver-client-kubelet", "request" => csr("system:node:n1")}}
    admit("CREATE", "certificatesigningrequests", group: "certificates.k8s.io", namespace: "", object: object)
    object = {"spec" => {"signerName" => "kubernetes.io/kubelet-serving", "request" => csr("system:node:n2")}}
    rejected("can only create a node CSR with CN=system:node:n1") do
      admit("CREATE", "certificatesigningrequests", group: "certificates.k8s.io", namespace: "", object: object)
    end
    other = {"spec" => {"signerName" => "example.com/custom", "request" => csr("anything")}}
    admit("CREATE", "certificatesigningrequests", group: "certificates.k8s.io", namespace: "", object: other)
    rejected("unable to parse csr") do
      admit("CREATE", "certificatesigningrequests", group: "certificates.k8s.io", namespace: "",
                                                    object: {"spec" => {"signerName" => "kubernetes.io/kubelet-serving", "request" => "bad"}})
    end
  end

  def test_pod_certificate_requests
    request = {"spec" => {"nodeName" => "n1", "nodeUID" => "node-uid", "podName" => "mine", "podUID" => "mine-uid",
                          "serviceAccountName" => "sa", "serviceAccountUID" => "sa-uid"}}
    rejected("PodCertificateRequest feature gate is disabled") do
      admit("CREATE", "podcertificaterequests", group: "certificates.k8s.io", object: request)
    end
    @context.feature_gates["PodCertificateRequest"] = true
    @context.put("serviceaccounts", "team", "sa", {"metadata" => {"name" => "sa", "uid" => "sa-uid"}})
    admit("CREATE", "podcertificaterequests", group: "certificates.k8s.io", object: request)
    error = rejected("names node UID") do
      admit("CREATE", "podcertificaterequests", group: "certificates.k8s.io", object: {"spec" => request["spec"].merge("nodeUID" => "old")})
    end
    assert_equal 500, error.code, "informer lag: not Forbidden"
    rejected("is not the requesting node") do
      admit("CREATE", "podcertificaterequests", group: "certificates.k8s.io", object: {"spec" => request["spec"].merge("nodeName" => "n2")})
    end
    rejected("differs from running pod") do
      admit("CREATE", "podcertificaterequests", group: "certificates.k8s.io", object: {"spec" => request["spec"].merge("serviceAccountName" => "x")})
    end
    rejected("unexpected operation") { admit("UPDATE", "podcertificaterequests", group: "certificates.k8s.io", object: request, old: request) }
  end

  def test_other_users_and_unnamed_nodes
    admit("UPDATE", "pods", name: "theirs", object: {}, old: {}, user: S::UserInfo.new(name: "alice"))
    rejected("could not determine node from user") do
      admit("UPDATE", "pods", name: "x", object: {}, old: {}, user: S::UserInfo.new(name: "system:node:", groups: %w[system:nodes]))
    end
  end
end
