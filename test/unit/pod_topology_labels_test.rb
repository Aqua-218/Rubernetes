# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/security"
require "rubernetes/security/admission/plugins/core"

# PodTopologyLabelsAdmission (Beta, on): the Node's zone and region labels
# reach the Pod.  The admission plugin put them on the Binding, but the
# binding subresource never copied a Binding's labels onto the Pod, so no
# Pod ever got them; a Pod created with spec.nodeName was not handled at all,
# and an existing label was not overwritten.
class PodTopologyLabelsTest < Minitest::Test
  S = Rubernetes::Security
  A = S::Admission
  API = Rubernetes::API

  class Nodes
    def initialize(nodes) = @nodes = nodes
    def get(resource, _namespace, name, **) = resource == "nodes" ? @nodes[name] : nil
  end

  NODE = {"metadata" => {"name" => "n1", "labels" => {"topology.kubernetes.io/zone" => "z1", "topology.kubernetes.io/region" => "r1",
                                                      "kubernetes.io/hostname" => "n1"}}}.freeze

  def admit(object, subresource: "")
    plugin = A::Registry.factories.fetch("PodTopologyLabels").call(Nodes.new("n1" => NODE), {})
    attributes = A::Attributes.new(operation: "CREATE", user: S::UserInfo.new(name: "scheduler"), group: "", version: "v1",
                                   resource: "pods", kind: subresource.empty? ? "Pod" : "Binding", namespace: "ns",
                                   name: object.dig("metadata", "name"), object: object, old_object: nil, subresource: subresource)
    plugin.admit(attributes)
    object
  end

  def test_a_binding_and_a_pod_created_on_a_node_get_the_topology_labels
    binding = admit({"metadata" => {"name" => "p"}, "target" => {"kind" => "Node", "name" => "n1"}}, subresource: "binding")
    assert_equal({"topology.kubernetes.io/zone" => "z1", "topology.kubernetes.io/region" => "r1"}, binding.dig("metadata", "labels"))
    pod = admit({"metadata" => {"name" => "p", "labels" => {"topology.kubernetes.io/zone" => "stale", "app" => "x"}},
                 "spec" => {"nodeName" => "n1"}})
    assert_equal({"topology.kubernetes.io/zone" => "z1", "app" => "x", "topology.kubernetes.io/region" => "r1"}, pod.dig("metadata", "labels"),
                 "overwritten, and only zone and region")
    unbound = admit({"metadata" => {"name" => "p"}, "spec" => {}})
    assert_nil unbound.dig("metadata", "labels")
  end

  def test_the_binding_subresource_copies_the_binding_labels_and_clears_the_nomination
    server = API::Server.new(registry: API::Registry.new, store: API::MemoryStore.new)
    call = ->(method, path, body) { server.call(API::Request.new(method: method, path: path, body: body)) }
    call.call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "ns"}})
    created = call.call("POST", "/api/v1/namespaces/ns/pods",
                        {"metadata" => {"name" => "p", "labels" => {"app" => "x", "topology.kubernetes.io/zone" => "old"}},
                         "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}})
    assert_equal 201, created.status
    call.call("PATCH", "/api/v1/namespaces/ns/pods/p/status", {"status" => {"nominatedNodeName" => "n1"}})
    bound = call.call("POST", "/api/v1/namespaces/ns/pods/p/binding",
                      {"apiVersion" => "v1", "kind" => "Binding", "metadata" => {"name" => "p", "labels" => {"topology.kubernetes.io/zone" => "z1"}},
                       "target" => {"kind" => "Node", "name" => "n1"}})
    assert_equal 201, bound.status, bound.body.inspect
    pod = call.call("GET", "/api/v1/namespaces/ns/pods/p", nil).body
    assert_equal({"app" => "x", "topology.kubernetes.io/zone" => "z1"}, pod.dig("metadata", "labels"))
    assert_nil pod.dig("status", "nominatedNodeName")
  end
end
