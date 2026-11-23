# frozen_string_literal: true

require "json"
require "net/http"
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

  # A real result, as the framework hands them to the service.
  module Result
    POD = Rubernetes::Scheduler::Pod.new({"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u"},
                                          "spec" => {"containers" => []}})

    def self.new(status:, victims:)
      Rubernetes::Scheduler::ScheduleResult.new(status: status, pod: POD, trace: Rubernetes::Scheduler::Trace.new, victims: victims)
    end
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

class ProxyComponentHealthTest < Minitest::Test
  Bootstrap = Rubernetes::Bootstrap

  class Stream
    def initialize
      @events = Queue.new
    end

    def each
      while (event = @events.pop)
        yield event
      end
    end

    def publish(event) = @events.push(event)
    def close = @events.close
  end

  class Client
    attr_reader :node_list_queries, :node_watch_queries

    def initialize(node, services: [])
      @node = node
      @services = services
      @node_list_queries = []
      @node_watch_queries = Queue.new
      @streams = %w[services endpointslices nodes].to_h { |resource| [resource, Stream.new] }
    end

    def get(resource, namespace:, api_version:, query:)
      items = case resource
              when "nodes"
                @node_list_queries << query
                [@node].compact
              when "services" then @services
              else []
              end
      {"metadata" => {"resourceVersion" => "1"}, "items" => items}
    end

    def watch_each(resource, namespace:, api_version:, query:)
      @node_watch_queries << query if resource == "nodes"
      @streams.fetch(resource)
    end

    def node_event(type, node)
      @node = type == "DELETED" ? nil : node
      @streams.fetch("nodes").publish("type" => type, "object" => node)
    end
  end

  def test_health_uses_the_local_node_informer_and_liveness_excludes_node_eligibility
    start_proxy
    initial = wait_for_health(503)
    live = response("/livez")

    assert_equal false, initial.fetch("nodeEligible")
    assert_equal true, initial.fetch("healthy")
    assert_equal "200", live.code
    assert_equal "memory", http_response("/proxyMode").body
    refute JSON.parse(live.body).key?("nodeEligible")
    assert_equal [{"fieldSelector" => "metadata.name=worker"}], @client.node_list_queries
    assert_equal "metadata.name=worker", @client.node_watch_queries.pop(timeout: 3).fetch("fieldSelector")

    @now += 2
    @client.node_event("ADDED", node(2, taint: "node.kubernetes.io/not-ready"))
    eligible = wait_for_health(200)

    assert_equal true, eligible.fetch("nodeEligible")
    assert_equal @now.iso8601, eligible.fetch("lastUpdated")
    assert_equal eligible.fetch("currentTime"), eligible.fetch("lastUpdated")

    @client.node_event("MODIFIED", node(3, taint: "ToBeDeletedByClusterAutoscaler"))
    draining = wait_for_health(503)

    assert_equal true, draining.fetch("healthy")
    assert_equal false, draining.fetch("nodeEligible")
    assert_equal (@now - 2).iso8601, draining.fetch("lastUpdated")
    assert_equal "200", response("/livez").code

    @client.node_event("MODIFIED", node(4))
    wait_for_health(200)
    @client.node_event("MODIFIED", node(5, deleting: true))
    wait_for_health(503)
    @client.node_event("MODIFIED", node(6))
    wait_for_health(200)
    @client.node_event("DELETED", node(7))
    wait_for_health(503)

    assert_equal 1, @client.node_list_queries.length
    assert_nil response("/livez", method: Net::HTTP::Head).body
    assert_equal "200", response("/livez", method: Net::HTTP::Post).code
  ensure
    @service&.stop
  end

  def test_stale_ip_family_fails_both_checks_until_that_family_syncs
    start_proxy(node(1))
    wait_for_health(200)
    original_update = @now
    @now += 1
    @proxy_metrics.sync_queued(["IPv6"])
    @now += 9

    assert_equal "200", response("/livez").code

    @proxy_metrics.sync_queued(["IPv6"])
    @now += 1
    @proxy_metrics.synced(0.01, families: ["IPv4"])
    health = wait_for_health(503)
    live = response("/livez")

    assert_equal "503", live.code
    assert_equal health.reject { |field, _| field == "nodeEligible" }, JSON.parse(live.body)
    assert_equal false, health.fetch("healthy")
    assert_equal true, health.fetch("nodeEligible")
    assert_equal @now.iso8601, health.fetch("lastUpdated")
    assert_equal({"IPv4" => {"healthy" => true, "lastUpdated" => @now.iso8601},
                  "IPv6" => {"healthy" => false, "lastUpdated" => original_update.iso8601}}, health.fetch("status"))

    @now += 1
    @proxy_metrics.synced(0.01, families: ["IPv6"])

    assert_equal "200", response("/livez").code
    assert_equal true, wait_for_health(200).fetch("healthy")
    assert_match(/kubeproxy_proxy_healthz_total\{code="503"\} [1-9]/, @service.metrics.render)
    assert_match(/kubeproxy_proxy_livez_total\{code="503"\} 1/, @service.metrics.render)
  ensure
    @service&.stop
  end

  def test_node_zone_updates_reprogram_existing_rules_with_serving_disabled
    service = {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "api", "namespace" => "default"},
               "spec" => {"clusterIP" => "10.96.0.10", "ports" => [{"port" => 80}]}}
    start_proxy(node(1, zone: "zone-a"), serving: false, services: [service])

    assert_nil @port
    assert_equal "metadata.name=worker", @client.node_watch_queries.pop(timeout: 3).fetch("fieldSelector")
    wait_for_rule_zone("zone-a")

    @client.node_event("MODIFIED", node(2, zone: "zone-b"))
    wait_for_rule_zone("zone-b")

    @client.node_event("MODIFIED", node(3))
    wait_for_rule_zone(nil)

    @client.node_event("MODIFIED", node(4, zone: "zone-b"))
    wait_for_rule_zone("zone-b")

    @client.node_event("DELETED", node(5, zone: "zone-b"))
    wait_for_rule_zone(nil)
  ensure
    @service&.stop
  end

  def test_separate_health_listener_exposes_only_proxier_checks
    start_proxy(node(1), health_serving: {"healthz_port" => 0, "healthz_bind_address" => "0.0.0.0"})
    health_port = @health_port
    metrics_port = @port

    refute_equal metrics_port, health_port
    assert_equal true, wait_for_health(200, port: health_port).fetch("nodeEligible")
    assert_equal "200", response("/livez", port: health_port).code
    %w[/metrics /metrics/slis /configz /flagz /statusz /proxyMode].each do |path|
      assert_equal "404", http_response(path, port: health_port).code, path
    end

    assert_equal "200", http_response("/metrics").code
    assert_equal "ok\n", http_response("/healthz").body
    mode = http_response("/proxyMode", method: Net::HTTP::Post)

    assert_equal "200", mode.code
    assert_equal "text/plain; charset=utf-8", mode["content-type"]
    assert_equal "nosniff", mode["x-content-type-options"]
    assert_equal @service.proxy.backend_name, mode.body

    @service.stop

    [metrics_port, health_port].each do |port|
      assert_raises(Errno::ECONNREFUSED) { TCPSocket.open("127.0.0.1", port, &:close) }
    end
  ensure
    @service&.stop
  end

  def test_ipv6_metrics_loopback_and_wildcard_health_listener
    begin
      TCPServer.open("::1", 0, &:local_address)
    rescue Errno::EAFNOSUPPORT, Errno::EADDRNOTAVAIL
      skip "no IPv6 loopback"
    end
    start_proxy(node(1), health_serving: {"bind_address" => "::1", "healthz_port" => 0, "healthz_bind_address" => "::"})

    assert_equal "memory", http_response("/proxyMode", host: "::1").body
    assert_equal true, wait_for_health(200, host: "::1", port: @health_port).fetch("nodeEligible")
  ensure
    @service&.stop
  end

  def test_health_bind_failure_stops_the_metrics_listener_and_leaves_the_proxy_stopped
    TCPServer.open("127.0.0.1", 0) do |occupied|
      metrics_port = TCPServer.open("127.0.0.1", 0) { |socket| socket.local_address.ip_port }
      error = assert_raises(Rubernetes::Transport::ConfigurationError) do
        start_proxy(node(1), health_serving: {"port" => metrics_port, "healthz_port" => occupied.local_address.ip_port})
      end

      assert_match(/cannot bind HTTP listener/, error.message)
      refute_predicate @service, :started?
      assert_empty @service.subscriptions
      assert_raises(Errno::ECONNREFUSED) { TCPSocket.open("127.0.0.1", metrics_port, &:close) }
    end
  ensure
    @service&.stop
  end

  def test_separate_health_configuration_keys_are_proxy_only
    serving = {"enabled" => true, "port" => 10_249, "bind_address" => "::1", "healthz_port" => 10_256, "healthz_bind_address" => "::"}

    assert_equal serving, config_with_serving(serving).process.fetch("serving")
    assert_raises(Bootstrap::Config::Error) { config_with_serving(serving, process: "rubernetes-scheduler") }
    assert_raises(Bootstrap::Config::Error) { config_with_serving(serving.merge("healthz_port" => "10256")) }
    assert_raises(Bootstrap::Config::Error) { config_with_serving(serving.merge("healthz_bind_address" => "0.0.0.0/24")) }
    assert_raises(Bootstrap::Config::Error) { config_with_serving(serving.reject { |field, _| field == "healthz_port" }) }
  end

  def test_wildcard_metrics_binding_is_rejected_even_with_a_separate_health_listener
    error = assert_raises(Bootstrap::Config::Error) do
      start_proxy(node(1), health_serving: {"bind_address" => "0.0.0.0", "healthz_port" => 0, "healthz_bind_address" => "0.0.0.0"})
    end

    assert_match(/serving.bind_address.*loopback/, error.message)
    refute_predicate @service, :started?
  ensure
    @service&.stop
  end

  private

  def config_with_serving(serving, process: "rubernetes-proxy")
    data = {"version" => 1, "logging" => {"level" => "info"}, "processes" => {process => {"serving" => serving}}}
    Bootstrap::Config.new(process_name: process, data: data)
  end

  def start_proxy(local_node = nil, serving: true, services: [], health_serving: {})
    @now = Time.utc(2026, 11, 19, 18, 0, 0)
    @client = Client.new(local_node, services: services)
    config = {"node_name" => "worker", "backend" => "memory", "sync" => {"period_seconds" => 5},
              "serving" => {"enabled" => serving, "port" => 0}.merge(health_serving)}
    @service = Bootstrap::ProxyService.new(config: config, client: @client, clock: -> { @now }, logger: nil)
    @service.start
    @port = @service.instance_variable_get(:@component_server)&.port
    @health_port = @service.instance_variable_get(:@proxy_health_server)&.port
    @proxy_metrics = @service.proxy.metrics
  end

  def node(version, taint: nil, deleting: false, zone: nil)
    metadata = {"name" => "worker", "uid" => "node-uid", "resourceVersion" => version.to_s}
    metadata["deletionTimestamp"] = @now.iso8601 if deleting
    metadata["labels"] = {"topology.kubernetes.io/zone" => zone} if zone
    taints = taint ? [{"key" => taint, "effect" => "NoSchedule"}] : []
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => metadata, "spec" => {"taints" => taints}}
  end

  def wait_for_rule_zone(zone)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    loop do
      zones = @service.proxy.backend.rules.map { |rule| rule.metadata["zone"] }
      return if zones == [zone]

      flunk "expected backend rule for #{zone.inspect}, received #{zones.inspect}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      sleep 0.02
    end
  end

  def response(path, **)
    result = http_response(path, **)

    assert_equal "application/json", result["content-type"]
    assert_equal "nosniff", result["x-content-type-options"]
    result
  end

  def http_response(path, method: Net::HTTP::Get, host: "127.0.0.1", port: @port)
    http = Net::HTTP.new(host, port, nil)
    http.open_timeout = 2
    http.read_timeout = 2
    http.request(method.new(path))
  end

  def wait_for_health(code, **)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    loop do
      result = response("/healthz", **)
      return JSON.parse(result.body) if result.code.to_i == code

      flunk "expected /healthz to return #{code}, received #{result.code} with #{result.body}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      sleep 0.02
    end
  end
end
