# frozen_string_literal: true

require "json"
require_relative "../test_helper"
require "rubernetes/bootstrap"

# The scheduler's and controller-manager's serving endpoints (upstream
# --secure-port): opt-in, loopback-only, /healthz /livez /readyz /metrics
# /configz /statusz /flagz; and the STABLE kube-scheduler series recorded
# from each scheduling attempt.
class ComponentServerTest < Minitest::Test
  B = Rubernetes::Bootstrap

  def request(path, method: "GET", accept: nil)
    headers = Rubernetes::Transport::Headers.new
    headers.add("Accept", accept) if accept
    Rubernetes::Transport::Request.new(method: method, target: path, headers: headers)
  end

  def setup
    # The shared registry carries whatever earlier tests recorded (authorization
    # webhook, token cache ...); a scheduler process would never have those.
    # A fresh one is used for this test only and the original goes back in
    # teardown, because other tests hold references to it.
    @previous_global = Rubernetes::Observability::Metrics.replace_global!(
      Rubernetes::Observability::Metrics.new(apiserver: false, process: false)
    )
  end

  def teardown
    Rubernetes::Observability::Metrics.replace_global!(@previous_global)
  end

  def server(ready: -> { true })
    metrics = Rubernetes::Observability::Metrics.new(apiserver: false)
    B::ComponentServer.new(component: "kube-scheduler", config: {"serving" => {"enabled" => true, "port" => 1}, "lease" => {"name" => "x"}},
                           metrics: metrics, host: "127.0.0.1", port: 0, ready: ready)
  end

  def test_it_is_opt_in_and_loopback_only
    assert_nil B::ComponentServer.from_config(component: "c", config: {}, metrics: nil)
    assert_nil B::ComponentServer.from_config(component: "c", config: {"serving" => {"enabled" => false, "port" => 1}}, metrics: nil)
    assert_raises(B::Config::Error) do
      B::ComponentServer.new(component: "c", config: {}, metrics: nil, host: "0.0.0.0", port: 0)
    end
  end

  def test_the_endpoints
    subject = server

    assert_equal [200, ["ok\n"]], subject.call(request("/healthz")).values_at(0, 2)
    assert_equal 200, subject.call(request("/livez"))[0]
    assert_equal 500, server(ready: -> { false }).call(request("/readyz"))[0]
    assert_match(/^process_start_time_seconds /, subject.call(request("/metrics"))[2].join)
    refute_match(/apiserver_/, subject.call(request("/metrics"))[2].join)
    assert_equal({"name" => "x"}, JSON.parse(subject.call(request("/configz"))[2].join).dig("componentconfig", "lease"))
    assert_match(/\A\nkube-scheduler statusz\n/, subject.call(request("/statusz"))[2].join)
    flagz = JSON.parse(subject.call(request("/flagz", accept: "application/json;g=config.k8s.io;v=v1beta1;as=Flagz"))[2].join)

    assert_equal "x", flagz.dig("flags", "lease.name")
    assert_equal 404, subject.call(request("/nope"))[0]
    assert_equal 405, subject.call(request("/healthz", method: "POST"))[0]
  end

  Result = Struct.new(:status, :victims, keyword_init: true) do
    def unschedulable? = status == :unschedulable
    def gated? = false
    def dropped? = status == :dropped
  end

  def test_scheduling_attempts_are_counted_by_result
    service = B::SchedulerService.new(config: {}, logger: nil)
    service.send(:record_attempt, Result.new(status: :scheduled, victims: []), 0.003)
    service.send(:record_attempt, Result.new(status: :scheduled, victims: %w[a b]), 0.01)
    service.send(:record_attempt, Result.new(status: :unschedulable, victims: []), 0.002)
    service.send(:record_attempt, Result.new(status: :failed, victims: []), 0.002)
    service.send(:record_attempt, Result.new(status: :dropped, victims: []), 0.002)
    text = service.metrics.render

    assert_includes text, %(scheduler_schedule_attempts_total{profile="default-scheduler",result="scheduled"} 2)
    assert_includes text, %(scheduler_schedule_attempts_total{profile="default-scheduler",result="unschedulable"} 1)
    assert_includes text, %(scheduler_schedule_attempts_total{profile="default-scheduler",result="error"} 1)
    assert_includes text, "scheduler_preemption_attempts_total 1"
    assert_includes text, %(scheduler_preemption_victims_bucket{le="2"} 1)
    assert_includes text,
                    %(scheduler_scheduling_attempt_duration_seconds_bucket{profile="default-scheduler",result="scheduled",le="0.004"} 1)
    assert_includes text, %(leader_election_master_status{name="kube-scheduler"} 0)
  end
end
