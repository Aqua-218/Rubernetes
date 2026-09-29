# frozen_string_literal: true

# /metrics/slis (component-base/metrics/prometheus/slis): the root health
# handlers record each check they run in kubernetes_healthcheck and
# kubernetes_healthchecks_total by name, endpoint type and status; the
# registry holds only those and process_start_time_seconds.  The scheduler
# and controller manager serve it with reset (DELETE).

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

class HealthcheckSLIsMetricsTest < Minitest::Test
  def api(ready:)
    Rubernetes::API::Server.new(store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil), ready: ready)
  end

  def get(server, path)
    server.call(Rubernetes::API::Request.new(method: "GET", path: path, headers: {}, identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_the_api_server_records_its_health_checks
    ready = true
    server = api(ready: -> { ready })
    get(server, "/healthz")
    get(server, "/livez")
    get(server, "/readyz")
    ready = false
    assert_equal 500, get(server, "/readyz").status
    get(server, "/readyz/etcd")
    response = get(server, "/metrics/slis")
    text = response.body
    assert_equal 200, response.status
    assert_includes text, %(kubernetes_healthcheck{name="ping",type="healthz"} 1)
    assert_includes text, %(kubernetes_healthcheck{name="etcd-readiness",type="readyz"} 0)
    assert_includes text, %(kubernetes_healthchecks_total{name="ping",status="success",type="readyz"} 2)
    assert_includes text, %(kubernetes_healthchecks_total{name="etcd-readiness",status="success",type="readyz"} 1)
    assert_includes text, %(kubernetes_healthchecks_total{name="etcd-readiness",status="error",type="readyz"} 1)
    refute_match(/etcd-readiness.*type="(healthz|livez)"/, text)
    assert_match(/^# HELP kubernetes_healthchecks_total \[STABLE\] This metric records the results of all healthcheck\.$/, text)
    assert_match(/^process_start_time_seconds /, text)
    # Nothing else: the SLI registry is its own.
    refute_match(/^apiserver_request_total/, text)
    refute_match(/^kubernetes_healthcheck/, get(server, "/metrics").body)
  end

  def request(path, method: "GET")
    Rubernetes::Transport::Request.new(method: method, target: path, headers: Rubernetes::Transport::Headers.new)
  end

  def test_component_servers_serve_and_reset_their_slis
    ready = false
    subject = Rubernetes::Bootstrap::ComponentServer.new(component: "kube-controller-manager", config: {}, metrics: Rubernetes::Observability::Metrics.new(apiserver: false),
                                                         host: "127.0.0.1", port: 0, ready: -> { ready })
    subject.call(request("/healthz"))
    subject.call(request("/readyz"))
    ready = true
    subject.call(request("/readyz"))
    text = subject.call(request("/metrics/slis"))[2].join
    assert_includes text, %(kubernetes_healthcheck{name="leaderElection",type="readyz"} 1)
    assert_includes text, %(kubernetes_healthchecks_total{name="leaderElection",status="error",type="readyz"} 1)
    assert_includes text, %(kubernetes_healthchecks_total{name="ping",status="success",type="healthz"} 1)
    assert_equal [200, ["metrics reset\n"]], subject.call(request("/metrics/slis", method: "DELETE")).values_at(0, 2)
    refute_match(/^kubernetes_healthcheck/, subject.call(request("/metrics/slis"))[2].join)
  end
end
