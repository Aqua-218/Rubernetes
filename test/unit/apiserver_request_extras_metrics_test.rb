# frozen_string_literal: true

# The request series kube-apiserver records besides the request counter
# (endpoints/metrics MonitorRequest, handlers/metrics, v1.36.2): the body
# size of a read body, loopback requests, and the fieldValidation series.
require_relative "../test_helper"
require "json"
require "rubernetes/api"

class APIServerRequestExtrasMetricsTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(registry: API::Registry.new, store: API::MemoryStore.new, metrics: @metrics)
  end

  def call(method, path, body = nil, user: "admin")
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                  body: body && JSON.generate(body), identity: {"username" => user, "groups" => ["system:masters"]}))
  end

  def test_body_size_self_requests_and_field_validation
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "team"}}, user: "system:apiserver")
    body = JSON.generate({"metadata" => {"name" => "c"}, "data" => {"k" => "v"}})
    call("POST", "/api/v1/namespaces/team/configmaps?fieldValidation=Strict", JSON.parse(body))
    text = @metrics.render
    assert_includes text, %(apiserver_selfrequest_total{group="",resource="namespaces",subresource="",verb="POST"} 1)
    assert_includes text, %(apiserver_request_body_size_bytes_count{group="",resource="configmaps",verb="create"} 1)
    assert_includes text, %(apiserver_request_body_size_bytes_sum{group="",resource="configmaps",verb="create"} #{body.bytesize})
    assert_includes text, %(field_validation_request_duration_seconds_count{field_validation="Strict"} 0)
    assert_includes text, %(field_validation_request_duration_seconds_count{field_validation=""} 0)
    assert_includes text, "# HELP apiserver_request_total [STABLE] "
  end
end
