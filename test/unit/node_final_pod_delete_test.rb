# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/node"

# The API server sets a Pod's deletionTimestamp and then waits: only the node
# can say that the containers are gone, so the node issues the delete that
# actually removes the object.  Upstream's status manager sends grace 0 and a
# UID precondition for it (pkg/kubelet/status/status_manager.go), and without
# both halves the request does not remove anything -- a DELETE with the default
# grace period merely restarts it.
#
# The node's API adapter had no delete at all, so the agent's deleter resolved
# to nil and the step never happened: every gracefully deleted Pod was stopped
# on the node and left Terminating in the API for ever, and every spec that
# waits for a Pod to disappear timed out after five minutes.
class NodeFinalPodDeleteTest < Minitest::Test
  Node = Rubernetes::Node

  class RecordingClient
    attr_reader :requests

    def initialize = @requests = []

    def raw(method, path, body: nil, headers: {}, query: nil)
      @requests << {method: method, path: path, body: body && JSON.parse(body), query: query, headers: headers}
      {"kind" => "Status", "status" => "Success"}
    end
  end

  def adapter(client = RecordingClient.new)
    [client, Node::APIClientAdapter.new(client: client, node_name: "worker-0")]
  end

  def test_the_adapter_can_delete_a_pod
    client, api = adapter

    api.delete_pod(namespace: "ns", name: "web", uid: "pod-uid")

    request = client.requests.fetch(0)

    assert_equal("DELETE", request.fetch(:method))
    assert_equal("/api/v1/namespaces/ns/pods/web", request.fetch(:path))
  end

  # Grace 0 is the half that removes the object; the default grace period just
  # restarts the countdown on an object that is already counting down.
  def test_the_delete_asks_for_immediate_removal
    client, api = adapter

    api.delete_pod(namespace: "ns", name: "web", uid: "pod-uid")

    body = client.requests.fetch(0).fetch(:body)

    assert_equal("DeleteOptions", body.fetch("kind"))
    assert_equal(0, body.fetch("gracePeriodSeconds"))
  end

  # The name may already belong to a replacement Pod, and deleting that one
  # would kill a healthy workload.
  def test_the_delete_is_pinned_to_the_pod_uid
    client, api = adapter

    api.delete_pod(namespace: "ns", name: "web", uid: "pod-uid")

    assert_equal({"uid" => "pod-uid"}, client.requests.fetch(0).fetch(:body).fetch("preconditions"))
  end

  def test_no_precondition_is_sent_without_a_uid
    client, api = adapter

    api.delete_pod(namespace: "ns", name: "web")

    refute(client.requests.fetch(0).fetch(:body).key?("preconditions"))
  end

  def test_a_missing_namespace_defaults_the_way_the_api_does
    client, api = adapter

    api.delete_pod(namespace: "", name: "web")

    assert_equal("/api/v1/namespaces/default/pods/web", client.requests.fetch(0).fetch(:path))
  end

  # The agent builds its deleter from whatever API object it was given; an
  # adapter that can delete a Pod must produce one.
  def test_the_agent_builds_a_deleter_from_the_adapter
    _client, api = adapter
    agent = Node::Agent.allocate
    deleter = agent.send(:pod_deleter_for, api)

    refute_nil(deleter, "the agent must have a deleter when the adapter can delete")
  end

  def test_an_api_that_cannot_delete_yields_no_deleter
    agent = Node::Agent.allocate

    assert_nil(agent.send(:pod_deleter_for, Object.new))
  end
end
