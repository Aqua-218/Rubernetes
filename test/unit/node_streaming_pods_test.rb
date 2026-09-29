# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/node"

# kubelet serves the Pods it runs at /pods; the e2e framework's node dumps
# read it through nodes/<name>/proxy/pods after every failure.
class NodeStreamingPodsTest < Minitest::Test
  Lifecycle = Struct.new(:records)
  Request = Struct.new(:path, :method)

  def test_pods_lists_the_lifecycle_records_as_a_pod_list
    server = Rubernetes::Node::StreamingServer.allocate
    server.instance_variable_set(:@lifecycle, Lifecycle.new({"u1" => {pod: {"metadata" => {"name" => "p"}}}, "u2" => {}}))
    status, headers, body = server.call(Request.new("/pods", "GET"))
    assert_equal 200, status
    assert_equal "application/json", headers["content-type"]
    list = JSON.parse(body.join)
    assert_equal "PodList", list["kind"]
    assert_equal ["p"], list["items"].map { |pod| pod.dig("metadata", "name") }
  end
end
