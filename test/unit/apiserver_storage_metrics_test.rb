# frozen_string_literal: true

# The storage layer's request metrics (etcd3 store RecordEtcdRequest):
# etcd_request_duration_seconds and etcd_requests_total by operation and
# group-resource, etcd_request_errors_total for failed operations.

require_relative "../test_helper"
require "json"
require "rubernetes/api"

class APIServerStorageMetricsTest < Minitest::Test
  def test_storage_operations_are_measured_by_type
    server = Rubernetes::API::Server.new(store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil))
    call = lambda do |method, path, body = nil|
      server.call(Rubernetes::API::Request.new(method: method, path: path, headers: body ? {"content-type" => "application/json"} : {},
                                               body: body && JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
    end
    call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
    call.call("POST", "/api/v1/namespaces/team/configmaps", {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "c"}})
    call.call("GET", "/api/v1/namespaces/team/configmaps/c")
    call.call("GET", "/api/v1/namespaces/team/configmaps/missing")
    call.call("GET", "/api/v1/namespaces/team/configmaps")
    text = server.metrics.render
    assert_match(/^etcd_requests_total\{group="",operation="create",resource="configmaps"\} 1/, text)
    assert_match(/^etcd_requests_total\{group="",operation="get",resource="configmaps"\} [2-9]/, text)
    assert_match(/^etcd_request_errors_total\{group="",operation="get",resource="configmaps"\} 1/, text)
    assert_match(/^etcd_request_duration_seconds_count\{group="",operation="list",resource="configmaps"\} 1/, text)
  end
end
