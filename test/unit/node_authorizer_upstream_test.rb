# frozen_string_literal: true

# The node authorizer's per-resource rules (plugin/pkg/auth/authorizer/node,
# v1.36.2): graph-scoped reads (including a single named list/watch), PVC
# status writes, service account reads and token creation, own lease and
# CSINode only, ResourceSlices and Pods through the nodeName field selector,
# AuthorizeNodeWithSelectors for Node reads, NoOpinion instead of Deny, and a
# reference cache that re-reads Pods for a missing reference.

require_relative "../test_helper"
require "rubernetes/security"

class NodeAuthorizerUpstreamTest < Minitest::Test
  Z = Rubernetes::Security::Authorization

  class Graph
    attr_accessor :pods
    attr_reader :reads

    def initialize(pods)
      @pods = pods
      @reads = 0
    end

    def pods_on_node(node)
      @reads += 1
      @pods.select { |pod| pod.dig("spec", "nodeName") == node }
    end

    def persistent_volume_claim(namespace, name)
      {"data" => {"spec" => {"volumeName" => "pv-1"}}, "web-scratch" => {"spec" => {}}}[name] if namespace == "team"
    end

    def persistent_volume(name)
      return nil unless name == "pv-1"

      {"spec" => {"claimRef" => {"namespace" => "team", "name" => "data"},
                  "csi" => {"nodeStageSecretRef" => {"name" => "stage-key", "namespace" => "vault"},
                            "controllerPublishSecretRef" => {"name" => "controller-key", "namespace" => "vault"}}}}
    end

    def volume_attachment(name) = {"va-a" => {"spec" => {"nodeName" => "node-a"}}, "va-b" => {"spec" => {"nodeName" => "node-b"}}}[name]
    def resource_slice(name) = {"slice-a" => {"spec" => {"nodeName" => "node-a"}}}[name]
  end

  POD = {"metadata" => {"name" => "web", "namespace" => "team"},
         "spec" => {"nodeName" => "node-a", "serviceAccountName" => "web-sa", "imagePullSecrets" => [{"name" => "pull"}],
                    "initContainers" => [{"envFrom" => [{"configMapRef" => {"name" => "init-cfg"}}]}],
                    "containers" => [{"env" => [{"valueFrom" => {"secretKeyRef" => {"name" => "env-secret"}}}]}],
                    "volumes" => [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "data"}},
                                  {"name" => "scratch", "ephemeral" => {"volumeClaimTemplate" => {}}},
                                  {"name" => "inline", "csi" => {"driver" => "d", "nodePublishSecretRef" => {"name" => "csi-secret"}}},
                                  {"name" => "proj", "projected" => {"sources" => [{"configMap" => {"name" => "proj-cfg"}}]}}],
                    "resourceClaims" => [{"name" => "gpu", "resourceClaimTemplateName" => "t"}]},
         "status" => {"resourceClaimStatuses" => [{"name" => "gpu", "resourceClaimName" => "web-gpu-abc"}]}}.freeze

  def setup
    @now = 100.0
    @graph = Graph.new([POD])
    @node = Z::Node.new(graph: @graph, clock: -> { @now })
    @kubelet = Rubernetes::Security::UserInfo.new(name: "system:node:node-a", groups: %w[system:nodes system:authenticated])
  end

  def decide(verb, resource, group: "", namespace: "", name: "", subresource: nil, field_selector: nil)
    @node.authorize(Z::Attributes.new(user: @kubelet, verb: verb, resource: resource, api_group: group, namespace: namespace,
                                      name: name, subresource: subresource, field_selector: field_selector, resource_request: true))
  end

  def test_graph_references_follow_visit_pod_secret_and_configmap_names
    %w[pull env-secret csi-secret].each { |secret| assert decide("get", "secrets", namespace: "team", name: secret).allowed?, secret }
    %w[init-cfg proj-cfg].each { |cfg| assert decide("get", "configmaps", namespace: "team", name: cfg).allowed?, cfg }
    assert decide("get", "persistentvolumeclaims", namespace: "team", name: "web-scratch").allowed?, "ephemeral claim"
    assert decide("get", "persistentvolumes", name: "pv-1").allowed?
    assert decide("get", "secrets", namespace: "vault", name: "stage-key").allowed?, "PV node-stage secret"
    assert decide("get", "secrets", namespace: "vault", name: "controller-key").no_opinion?, "controller secrets are not kubelet-visible"
    assert decide("get", "resourceclaims", group: "resource.k8s.io", namespace: "team", name: "web-gpu-abc").allowed?
    assert decide("get", "secrets", namespace: "team", name: "other").no_opinion?
  end

  def test_single_object_list_and_watch_and_subresources
    assert decide("watch", "secrets", namespace: "team", name: "pull").allowed?
    assert decide("list", "configmaps", namespace: "team", name: "init-cfg").allowed?
    assert decide("list", "secrets", namespace: "team").no_opinion?
    assert decide("get", "secrets", namespace: "team", name: "pull", subresource: "x").no_opinion?
    assert decide("list", "persistentvolumeclaims", namespace: "team", name: "data").no_opinion?, "claims: get only"
  end

  def test_claim_status_updates_and_service_accounts
    assert decide("patch", "persistentvolumeclaims", namespace: "team", name: "data", subresource: "status").allowed?
    assert decide("update", "persistentvolumeclaims", namespace: "team", name: "other", subresource: "status").no_opinion?
    assert decide("create", "serviceaccounts", namespace: "team", name: "web-sa", subresource: "token").allowed?
    assert decide("create", "serviceaccounts", namespace: "team", name: "default", subresource: "token").no_opinion?
    assert decide("get", "serviceaccounts", namespace: "team", name: "web-sa").allowed?
    disabled = Z::Node.new(graph: @graph, features: {"KubeletServiceAccountTokenForCredentialProviders" => false})
    attributes = Z::Attributes.new(user: @kubelet, verb: "get", resource: "serviceaccounts", namespace: "team", name: "web-sa",
                                   resource_request: true)
    assert disabled.authorize(attributes).no_opinion?
  end

  def test_leases_and_csinodes_are_the_nodes_own
    assert decide("patch", "leases", group: "coordination.k8s.io", namespace: "kube-node-lease", name: "node-a").allowed?
    assert decide("create", "leases", group: "coordination.k8s.io", namespace: "kube-node-lease").allowed?
    assert decide("get", "leases", group: "coordination.k8s.io", namespace: "kube-node-lease", name: "node-b").no_opinion?
    assert decide("get", "leases", group: "coordination.k8s.io", namespace: "default", name: "node-a").no_opinion?
    assert decide("update", "csinodes", group: "storage.k8s.io", name: "node-a").allowed?
    assert decide("update", "csinodes", group: "storage.k8s.io", name: "node-b").no_opinion?
    assert decide("create", "csinodes", group: "storage.k8s.io").allowed?
  end

  def test_volume_attachments_and_resource_slices_through_the_graph
    assert decide("get", "volumeattachments", group: "storage.k8s.io", name: "va-a").allowed?
    assert decide("get", "volumeattachments", group: "storage.k8s.io", name: "va-b").no_opinion?
    assert decide("list", "volumeattachments", group: "storage.k8s.io").no_opinion?
    assert decide("create", "resourceslices", group: "resource.k8s.io").allowed?
    assert decide("update", "resourceslices", group: "resource.k8s.io", name: "slice-a").allowed?
    assert decide("delete", "resourceslices", group: "resource.k8s.io", name: "slice-b").no_opinion?
    assert decide("list", "resourceslices", group: "resource.k8s.io", field_selector: "spec.nodeName=node-a").allowed?
    assert decide("deletecollection", "resourceslices", group: "resource.k8s.io",
                                                        field_selector: "spec.nodeName=node-a,spec.driver=d").allowed?
    assert decide("watch", "resourceslices", group: "resource.k8s.io").no_opinion?
    assert decide("watch", "resourceslices", group: "resource.k8s.io", field_selector: "spec.nodeName=node-b").no_opinion?
  end

  def test_nodes_and_pods_with_selectors
    assert decide("get", "nodes", name: "node-a").allowed?
    assert decide("watch", "nodes", name: "node-a").allowed?, "metadata.name field selector"
    assert decide("list", "nodes").no_opinion?
    assert decide("get", "nodes", name: "node-b").no_opinion?
    assert decide("patch", "nodes", name: "node-a", subresource: "status").allowed?
    assert decide("watch", "pods", field_selector: "spec.nodeName=node-a").allowed?
    assert decide("list", "pods").no_opinion?
    assert decide("list", "pods", field_selector: "spec.nodeName!=node-a").no_opinion?
    assert decide("get", "pods", namespace: "team", name: "web").allowed?
    assert decide("get", "pods", namespace: "team", name: "elsewhere").no_opinion?
    assert decide("create", "pods", namespace: "team").allowed?
    assert decide("create", "pods", namespace: "team", name: "web", subresource: "eviction").allowed?
  end

  def test_static_rules_and_mirror_pods
    assert decide("list", "services").allowed?
    assert decide("create", "events", group: "events.k8s.io", namespace: "team").allowed?
    assert decide("get", "endpoints", namespace: "team", name: "x").allowed?
    assert decide("list", "endpoints", namespace: "team").no_opinion?
    assert decide("list", "clustertrustbundles", group: "certificates.k8s.io").allowed?
    mirror = POD.merge("metadata" => POD["metadata"].merge("annotations" => {"kubernetes.io/config.mirror" => "x"}))
    @graph.pods = [mirror]
    @now += 5
    assert decide("get", "secrets", namespace: "team", name: "pull").no_opinion?, "a mirror pod references nothing"
  end

  def test_a_missing_reference_rereads_the_pods_once
    assert decide("get", "secrets", namespace: "team", name: "pull").allowed?
    reads = @graph.reads
    assert decide("get", "configmaps", namespace: "team", name: "init-cfg").allowed?
    assert_equal reads, @graph.reads, "cached within the TTL"

    bound = {"metadata" => {"name" => "new", "namespace" => "team"}, "spec" => {"nodeName" => "node-a",
                                                                               "volumes" => [{"secret" => {"secretName" => "fresh"}}]}}
    @graph.pods = [POD, bound]
    @now += 0.05
    assert decide("get", "secrets", namespace: "team", name: "fresh").no_opinion?, "inside the refresh floor"
    @now += 0.1
    assert decide("get", "secrets", namespace: "team", name: "fresh").allowed?, "a missing key forces a re-read"
    assert_equal reads + 1, @graph.reads
  end

  def test_non_nodes_get_no_opinion
    alice = Rubernetes::Security::UserInfo.new(name: "alice", groups: %w[system:authenticated])
    attributes = Z::Attributes.new(user: alice, verb: "get", resource: "secrets", namespace: "team", name: "pull", resource_request: true)
    assert @node.authorize(attributes).no_opinion?
  end
end
