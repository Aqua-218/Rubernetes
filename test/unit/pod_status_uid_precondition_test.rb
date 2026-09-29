# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"
require "rubernetes/node"

# A status report names the Pod's UID, and the API server refuses one for a
# different Pod of the same name.
class PodStatusUidPreconditionTest < Minitest::Test
  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new, namespace_lifecycle: true)
    @server.call(method: "POST", path: "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}})
    @pod = @server.call(method: "POST", path: "/api/v1/namespaces/dev/pods",
                        body: {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "ss-0"},
                               "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}).body
  end

  def status_patch(uid)
    @server.call(method: "PATCH", path: "/api/v1/namespaces/dev/pods/ss-0/status",
                 body: {"metadata" => {"uid" => uid}, "status" => {"phase" => "Failed"}},
                 headers: {"content-type" => "application/merge-patch+json"})
  end

  def test_a_report_for_a_previous_incarnation_is_refused
    response = status_patch("00000000-dead-beef-0000-000000000000")

    assert_equal 409, response.status
    assert_equal "Pending", @server.call(method: "GET", path: "/api/v1/namespaces/dev/pods/ss-0").body.dig("status", "phase"), "the stale Failed report must not land"
  end

  def test_a_report_naming_the_current_uid_is_applied
    response = status_patch(@pod.dig("metadata", "uid"))

    assert_equal 200, response.status
    assert_equal "Failed", @server.call(method: "GET", path: "/api/v1/namespaces/dev/pods/ss-0").body.dig("status", "phase")
  end

  class RecordingClient
    attr_reader :calls

    def initialize = @calls = []

    def patch(path, body, type: nil)
      @calls << [path, body, type]
      body
    end
  end

  def test_the_node_report_carries_the_pod_uid
    client = RecordingClient.new
    adapter = Rubernetes::Node::APIClientAdapter.new(client: client, node_name: "worker-0")
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "ss-0", "namespace" => "dev", "uid" => "abc"}}

    adapter.report(pod, {"phase" => "Running"})

    _path, body, _type = client.calls.first
    assert_equal({"uid" => "abc"}, body["metadata"])
    assert_equal "Running", body.dig("status", "phase")
  end
end
