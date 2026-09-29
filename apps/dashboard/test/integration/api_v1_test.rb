# frozen_string_literal: true

require "test_helper"
require "support/fake_cluster"

class ApiV1Test < ActionDispatch::IntegrationTest
  setup do
    @now = (Time.now.to_f * 1000).to_i
    @runtime, @cluster, @dir = DashboardTestRuntime.build(now_ms: @now)
    Dashboard::Runtime.configure(@runtime)
  end

  teardown do
    Dashboard::Runtime.configure(nil)
    FileUtils.rm_rf(@dir)
  end

  def json
    JSON.parse(response.body)
  end

  test "instant query returns the Prometheus envelope" do
    get "/api/v1/query", params: {query: "sum(requests_total)"}
    assert_response :success
    assert_equal "success", json["status"]
    assert_equal "vector", json.dig("data", "resultType")
    assert_equal "123", json.dig("data", "result", 0, "value", 1)
    post "/api/v1/query", params: {query: "2 * 3"}
    assert_equal ["scalar", "6"], [json.dig("data", "resultType"), json.dig("data", "result", 1)]
  end

  test "range query with unix and RFC3339 times and duration steps" do
    get "/api/v1/query_range", params: {query: "history", start: (@now / 1000.0) - 60, end: @now / 1000.0, step: "15s"}
    assert_response :success
    values = json.dig("data", "result", 0, "values")
    assert_equal 5, values.length
    assert_equal({"__name__" => "history", "k" => "v"}, json.dig("data", "result", 0, "metric"))
    get "/api/v1/query_range", params: {query: "history", start: Time.at(@now / 1000 - 60).utc.iso8601, end: Time.at(@now / 1000).utc.iso8601, step: 30}
    assert_response :success
  end

  test "errors use Prometheus error types and status codes" do
    get "/api/v1/query", params: {query: "sum("}
    assert_response :bad_request
    assert_equal "bad_data", json["errorType"]
    get "/api/v1/query", params: {query: "requests_total / on(code) requests_total"}
    assert_response :success
    get "/api/v1/query_range", params: {query: "history", start: @now / 1000, end: @now / 1000 - 10, step: 15}
    assert_response :bad_request
    assert_match(/end timestamp must not be before start/, json["error"])
    get "/api/v1/query_range", params: {query: "history[5m]", start: @now / 1000 - 60, end: @now / 1000, step: 15}
    assert_response :unprocessable_content
    assert_equal "execution", json["errorType"]
  end

  test "series, labels and label values" do
    get "/api/v1/series", params: {"match[]" => ['requests_total{code="500"}']}
    assert_response :success
    assert_equal [{"__name__" => "requests_total", "code" => "500", "job" => "apiserver", "instance" => "127.0.0.1:39307", "process" => "apiserver-control-0"}],
                 json["data"]
    get "/api/v1/labels"
    assert_includes json["data"], "code"
    assert_includes json["data"], "__name__"
    get "/api/v1/label/job/values"
    assert_equal %w[apiserver kubelet kubelet-resource], json["data"].sort
    get "/api/v1/label/bad-name/values"
    assert_response :bad_request
  end

  test "targets, rules, alerts, metadata and status endpoints" do
    get "/api/v1/targets"
    assert_response :success
    active = json.dig("data", "activeTargets")
    assert_equal 3, active.length
    down = active.find { |t| t["health"] == "down" }
    assert_match(/ECONNREFUSED/, down["lastError"])
    assert_equal "kubelet", down["scrapePool"]

    get "/api/v1/rules"
    groups = json.dig("data", "groups")
    assert_equal ["test"], groups.map { |g| g["name"] }
    types = groups[0]["rules"].map { |r| r["type"] }
    assert_equal %w[alerting recording], types
    assert_equal "firing", groups[0]["rules"][0]["state"]
    get "/api/v1/rules", params: {type: "alerting"}
    assert_equal ["alerting"], json.dig("data", "groups", 0, "rules").map { |r| r["type"] }

    get "/api/v1/alerts"
    alerts = json.dig("data", "alerts")
    assert_equal 1, alerts.length
    assert_equal "worker-1 down", alerts[0]["annotations"]["summary"]

    get "/api/v1/metadata"
    assert_equal "counter", json.dig("data", "requests_total", 0, "type")
    get "/api/v1/metadata", params: {metric: "nothing"}
    assert_equal({}, json["data"])

    get "/api/v1/status/buildinfo"
    assert_match(/rubernetes-dashboard/, json.dig("data", "version"))
    get "/api/v1/status/tsdb"
    assert_operator json.dig("data", "headStats", "numSeries"), :>, 0
    get "/api/v1/status/runtimeinfo"
    assert_equal false, json.dig("data", "collectorRunning")
    get "/api/v1/status/config"
    assert_match(/scrape_interval/, json.dig("data", "yaml"))
  end

  test "the recording rule wrote a series the API can read" do
    get "/api/v1/query", params: {query: "job:up:avg"}
    values = json.dig("data", "result").to_h { |s| [s["metric"]["job"], s["value"][1]] }
    assert_equal({"apiserver" => "1", "kubelet" => "0", "kubelet-resource" => "1"}, values)
  end

  test "basic auth protects the API when a password is set" do
    with_env("DASHBOARD_PASSWORD" => "hunter2") do
      get "/api/v1/query", params: {query: "1"}
      assert_response :unauthorized
      get "/api/v1/query", params: {query: "1"}, headers: {"Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials("any", "hunter2")}
      assert_response :success
    end
  end

  private

  def with_env(values)
    saved = values.to_h { |k, _| [k, ENV[k]] }
    values.each { |k, v| ENV[k] = v }
    yield
  ensure
    saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end
end
