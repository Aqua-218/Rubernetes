# frozen_string_literal: true

require "test_helper"
require "support/fake_cluster"

class PagesTest < ActionDispatch::IntegrationTest
  setup do
    @runtime, @cluster, @dir = DashboardTestRuntime.build
    Dashboard::Runtime.configure(@runtime)
  end

  teardown do
    Dashboard::Runtime.configure(nil)
    FileUtils.rm_rf(@dir)
  end

  test "overview shows counts, unhealthy pods, nodes and warnings" do
    get "/"

    assert_response :success
    assert_select "h1", "Cluster overview"
    assert_select ".card .big", text: "1/2" # nodes ready
    assert_select "td", text: "crash-1"
    assert_select ".badge", text: "CrashLoopBackOff"
    assert_select "td", text: /Back-off restarting/
    assert_select ".card .big", text: "2/3" # targets up
  end

  test "nodes index and detail" do
    get "/nodes"

    assert_response :success
    assert_select "a[href='/nodes/worker-0']"
    assert_select ".badge", text: "NotReady"
    get "/nodes/worker-0"

    assert_response :success
    assert_select "h1", "Node worker-0"
    assert_select "td", text: "web-1"
    assert_select "dd", text: "v1.36.2"
  end

  test "namespaces, pods list, pod detail, logs, yaml" do
    get "/namespaces"

    assert_select "a[href='/namespaces/gitlab']"
    get "/namespaces/gitlab"

    assert_select ".card .sub", text: "pods"
    get "/namespaces/gitlab/pods"

    assert_select "td a", text: "web-1"
    get "/namespaces/gitlab/pods", params: {q: "crash"}

    assert_select "td a", text: "crash-1"
    assert_select "td a", text: "web-1", count: 0
    get "/namespaces/gitlab/pods/crash-1"

    assert_response :success
    assert_select ".badge", text: "CrashLoopBackOff"
    assert_select "td", text: "img:1"
    get "/namespaces/gitlab/pods/crash-1/logs"

    assert_response :success
    assert_select "pre#log", text: /line 1/
    get "/namespaces/gitlab/pods/crash-1/logs.text", params: {container: "c"}

    assert_equal "text/plain", response.media_type
    assert_includes response.body, "container=c"
    get "/namespaces/gitlab/pods/crash-1/yaml"

    assert_equal "text/yaml", response.media_type
    assert_includes response.body, "name: crash-1"
  end

  test "pod deletion goes to the API and is blocked when writes are disabled" do
    delete "/namespaces/gitlab/pods/crash-1"

    assert_redirected_to "/namespaces/gitlab/pods"
    assert_equal [[:delete, "pods", "crash-1", "gitlab", nil]], @cluster.writes
    ENV["DASHBOARD_ALLOW_WRITES"] = "0"
    delete "/namespaces/gitlab/pods/web-1"

    assert_response :forbidden
  ensure
    ENV.delete("DASHBOARD_ALLOW_WRITES")
  end

  test "generic resources: list, detail, scale, restart, delete, yaml, secrets redacted" do
    get "/namespaces/gitlab/deployments"

    assert_response :success
    assert_select "th", text: "Ready"
    assert_select "td", text: "1/2"
    get "/namespaces/gitlab/deployments/web"

    assert_response :success
    assert_select "td", text: "web-1" # related pod through the selector
    assert_select "td", text: "MinimumReplicasUnavailable"
    post "/namespaces/gitlab/deployments/web/scale", params: {replicas: 3}

    assert_redirected_to "/namespaces/gitlab/deployments/web"
    post "/namespaces/gitlab/deployments/web/restart"

    assert_redirected_to "/namespaces/gitlab/deployments/web"
    delete "/namespaces/gitlab/deployments/web"

    assert_redirected_to "/namespaces/gitlab/deployments"
    kinds = @cluster.writes.map(&:first)

    assert_equal %i[patch patch delete], kinds
    assert_equal({"spec" => {"replicas" => 3}}, @cluster.writes[0][4])
    assert_equal "kubectl.kubernetes.io/restartedAt", @cluster.writes[1][4].dig("spec", "template", "metadata", "annotations").keys.first
    get "/namespaces/gitlab/deployments/web/yaml"

    assert_equal "text/yaml", response.media_type
    get "/namespaces/gitlab/secrets/sec"

    assert_response :success
    assert_select "pre", text: /redacted/
    refute_includes response.body, "c2VjcmV0"
    get "/namespaces/gitlab/configmaps/cfg"

    assert_select "summary", text: /a/
    get "/namespaces/gitlab/services"

    assert_select "td", text: "10.96.0.10"
    get "/storageclasses"

    assert_response :success
    get "/namespaces/gitlab/nothingness"

    assert_response :not_found
  end

  test "events pages" do
    get "/events"

    assert_select "td", text: /Back-off/
    get "/events", params: {type: "Warning"}

    assert_response :success
    get "/namespaces/gitlab/events"

    assert_select "td", text: "BackOff"
  end

  test "monitoring pages: graph, targets, rules, alerts, status" do
    get "/graph", params: {g0_expr: "up"}

    assert_response :success
    assert_select "textarea[name=expr]", text: "up"
    assert_select "[data-graph-panel]"
    get "/targets"

    assert_select "h2", text: %r{apiserver \(1/1 up\)}
    assert_select ".badge", text: "down"
    get "/rules"

    assert_select "td b", text: "TargetDown"
    get "/alerts"

    assert_select ".badge", text: "firing"
    assert_select "td", text: /worker-1 down/
    get "/status"

    assert_select "dt", text: "kubeconfig"
    assert_select ".card .big", minimum: 3
  end

  test "an unreachable API renders an error page instead of a stack trace" do
    broken = Object.new
    broken.define_singleton_method(:get) { |*| raise "connection refused" }
    Dashboard::Runtime.configure(Dashboard::Runtime.new(client: broken, store: @runtime.store, engine: @runtime.engine,
                                                        rules: @runtime.rules))
    get "/nodes"

    assert_response :internal_server_error
    assert_select "h1", "RuntimeError"
    assert_select "pre", text: /connection refused/
  end

  test "host authorization admits the configured names and rejects others" do
    # localhost is always in Dashboard::Config.allowed_hosts; the public
    # Ingress name arrives through DASHBOARD_EXTERNAL_URL (see the config test).
    host! "localhost"
    get "/"

    assert_response :success
    host! "evil.example.net"
    get "/"

    assert_response :forbidden
    get "/up"

    assert_response :success, "/up is excluded so load balancers can probe by address"
  end
end
