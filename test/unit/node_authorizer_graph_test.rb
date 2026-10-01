# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/storage/memory_store"
require "rubernetes/observability/metrics"

# The node authorizer's graph: what a node may read follows the Pods bound
# to it (and their claims' volumes), fed by the store's watches.
class NodeAuthorizerGraphTest < Minitest::Test
  Z = Rubernetes::Security::Authorization

  def pod(name, node:, secrets: [], claim: nil, mirror: false)
    volumes = secrets.map { |secret| {"name" => secret, "secret" => {"secretName" => secret}} }
    volumes << {"name" => "data", "persistentVolumeClaim" => {"claimName" => claim}} if claim
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns", "uid" => "u-#{name}",
                                                           "annotations" => mirror ? {"kubernetes.io/config.mirror" => "x"} : {}},
     "spec" => {"nodeName" => node, "serviceAccountName" => "sa-#{name}",
                "containers" => [{"name" => "c", "env" => [{"name" => "K", "valueFrom" => {"configMapKeyRef" => {"name" => "cm-#{name}", "key" => "k"}}}]}],
                "volumes" => volumes}}
  end

  def pv(name, claim:, secret: nil)
    csi = {"driver" => "d", "volumeHandle" => "h"}
    csi["nodeStageSecretRef"] = {"name" => secret, "namespace" => "ns"} if secret
    {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => name},
     "spec" => {"claimRef" => {"namespace" => "ns", "name" => claim}, "csi" => csi}}
  end

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    Z::NodeGraph.metrics = @metrics
  end

  def teardown
    Z::NodeGraph.metrics = nil
  end

  def test_graph_edges_and_lookups
    graph = Z::NodeGraph.new
    graph.add_pod(pod("web", node: "n1", secrets: ["tls"], claim: "data-claim"))
    graph.add_pod(pod("mirror", node: "n1", secrets: ["hidden"], mirror: true))
    graph.add_pv(pv("pv-1", claim: "data-claim", secret: "csi-secret"))
    graph.add_volume_attachment("va-1", "n1")
    graph.add_resource_slice("slice-1", "n2")
    graph.add_pod_certificate_request({"metadata" => {"name" => "pcr", "namespace" => "ns"}, "spec" => {"nodeName" => "n1"}})

    assert graph.references?("n1", :secrets, "ns", "tls")
    assert graph.references?("n1", :configmaps, "ns", "cm-web")
    assert graph.references?("n1", :serviceaccounts, "ns", "sa-web")
    assert graph.references?("n1", :pods, "ns", "web")
    assert graph.references?("n1", :persistentvolumeclaims, "ns", "data-claim")
    assert graph.references?("n1", :persistentvolumes, "", "pv-1"), "pv -> claim -> pod -> node"
    assert graph.references?("n1", :secrets, "ns", "csi-secret"), "secret -> pv -> claim -> pod -> node"
    refute graph.references?("n1", :secrets, "ns", "hidden"), "a mirror Pod grants nothing"
    refute graph.references?("n2", :secrets, "ns", "tls")
    assert graph.references?("n1", :volumeattachments, "", "va-1")
    refute graph.references?("n2", :volumeattachments, "", "va-1")
    assert graph.references?("n2", :resourceslices, "", "slice-1")
    assert graph.references?("n1", :podcertificaterequests, "ns", "pcr")

    graph.delete_pv("pv-1")

    refute graph.references?("n1", :secrets, "ns", "csi-secret")
    graph.delete_pod("ns", "web")

    refute graph.references?("n1", :secrets, "ns", "tls")
    graph.delete_volume_attachment("va-1")

    refute graph.references?("n1", :volumeattachments, "", "va-1")
    text = @metrics.render_own

    %w[AddPod DeletePod AddPV DeletePV AddVolumeAttachment DeleteVolumeAttachment AddResourceSlice
       AddPodCertificateRequest].each do |operation|
      assert_match(/node_authorizer_graph_actions_duration_seconds_count\{operation="#{operation}"\} \d/, text)
    end
  end

  def test_populator_follows_the_store_and_the_authorizer_uses_the_graph
    store = Rubernetes::Storage::MemoryStore.new
    store.create("registry/v1/pods/ns/early", pod("early", node: "n1", secrets: ["early-secret"]))
    graph = Z::NodeGraph.new
    populator = Z::NodeGraph::Populator.new(graph: graph, store: store)
    populator.start
    begin
      wait_until { graph.references?("n1", :secrets, "ns", "early-secret") }
      store.create("registry/v1/pods/ns/late", pod("late", node: "n2", secrets: ["late-secret"]))
      store.create("registry/v1/persistentvolumes/_cluster/pv-9", pv("pv-9", claim: "c9", secret: "s9"))
      store.create("registry/storage.k8s.io/v1/volumeattachments/_cluster/va-9",
                   {"metadata" => {"name" => "va-9"}, "spec" => {"nodeName" => "n2", "attacher" => "d"}})
      wait_until { graph.references?("n2", :secrets, "ns", "late-secret") && graph.references?("n2", :volumeattachments, "", "va-9") }
      store.delete("registry/v1/pods/ns/late")
      wait_until { !graph.references?("n2", :secrets, "ns", "late-secret") }

      authorizer = Z::Node.new(graph: graph)
      node = Rubernetes::Security::UserInfo.new(name: "system:node:n1", groups: ["system:nodes"])
      allowed = Z::Attributes.new(user: node, verb: "get", api_group: "", api_version: "v1", resource: "secrets", namespace: "ns",
                                  name: "early-secret")
      denied = Z::Attributes.new(user: node, verb: "get", api_group: "", api_version: "v1", resource: "secrets", namespace: "ns",
                                 name: "other")

      assert_predicate authorizer.authorize(allowed), :allowed?
      refute_predicate authorizer.authorize(denied), :allowed?
    ensure
      populator.stop
    end
  end

  def wait_until(timeout = 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    until yield
      raise "condition not met in #{timeout}s" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep 0.02
    end
  end
end
