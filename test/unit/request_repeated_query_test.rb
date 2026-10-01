# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api/request"
require "rubernetes/transport/request"

# A repeated query key answers its first value from `query_value`, as Go's
# url.Values.Get does; `query_values` keeps them all.  sonobuoy's retrieve
# sends `container=kube-sonobuoy&container=kube-sonobuoy` on its exec.
class RequestRepeatedQueryTest < Minitest::Test
  def test_api_request_first_value_of_a_repeated_key
    request = Rubernetes::API::Request.new(method: "POST", path: "/api/v1/namespaces/s/pods/p/exec",
                                           query: {"container" => %w[kube-sonobuoy kube-sonobuoy], "command" => %w[ls -l], "stdout" => "true"})

    assert_equal "kube-sonobuoy", request.query_value("container")
    assert_equal %w[kube-sonobuoy kube-sonobuoy], request.query_values("container")
    assert_equal "ls", request.query_value("command")
    assert_equal %w[ls -l], request.query_values("command")
    assert_equal "true", request.query_value("stdout")
    assert_nil request.query_value("missing")
    assert_equal "d", request.query_value("missing", "d")
  end

  def test_transport_request_first_value_of_a_repeated_key
    request = Rubernetes::Transport::Request.new(method: "GET", target: "/exec/s/p/c?container=a&container=b&tty=1")

    assert_equal "a", request.query_value("container")
    assert_equal %w[a b], request.query_values("container")
    assert_equal "1", request.query_value("tty")
  end
end
