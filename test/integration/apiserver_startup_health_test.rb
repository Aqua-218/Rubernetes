# frozen_string_literal: true

require "net/http"
require "stringio"
require "timeout"

require_relative "../test_helper"
require "rubernetes/bootstrap"

class APIServerStartupHealthTest < Minitest::Test
  BOOTSTRAP = Rubernetes::Bootstrap
  PRIORITY_CLASSES = "/apis/scheduling.k8s.io/v1/priorityclasses"
  LOCAL_CORE_SERVICE = "/apis/apiregistration.k8s.io/v1/apiservices/v1."
  PRIORITY_CHECK = "poststarthook/scheduling/bootstrap-system-priority-classes"

  def test_production_probes_report_persisted_bootstrap_objects_and_synced_informers
    logs = StringIO.new
    config = BOOTSTRAP::Config.load(process_name: "rubernetes-apiserver").process.merge("bind_address" => "127.0.0.1", "port" => 0)
    logger = BOOTSTRAP::StructuredLogger.new(io: logs, process_name: "apiserver-startup-test")
    service = BOOTSTRAP::APIServerService.new(config: config, logger: logger)

    pending = service.api_server.call(method: "GET", path: "/readyz")

    assert_equal 500, pending.status
    assert_includes pending.body, "[-]#{PRIORITY_CHECK} failed: reason withheld\n"
    assert_includes pending.body, "[-]autoregister-completion failed: reason withheld\n"
    assert_equal 404, service.api_server.call(method: "GET", path: LOCAL_CORE_SERVICE).status

    service.start
    port = service.http_server.port
    ready = wait_for_probe(port)

    assert_equal "200", ready.code, logs.string
    assert_includes ready.body, "[+]#{PRIORITY_CHECK} ok\n"
    assert_includes ready.body, "[+]autoregister-completion ok\n"
    assert_includes ready.body, "[+]informer-sync ok\n"
    assert_equal "ok", get(port, "/readyz/#{PRIORITY_CHECK}").body
    assert_equal "ok", get(port, "/livez").body
    refute_includes get(port, "/healthz?verbose").body, "[+]informer-sync ok\n"
    assert_equal "404", get(port, "/livez/not-a-check").code

    local = JSON.parse(get(port, LOCAL_CORE_SERVICE).body)

    assert_equal({"group" => "", "version" => "v1", "groupPriorityMinimum" => 18_000, "versionPriority" => 1}, local.fetch("spec"))
    assert_equal %w[Available True Local], local.fetch("status").fetch("conditions").first.values_at("type", "status", "reason")
    assert_equal 2_000_001_000, priority_value(port, "system-node-critical")
    assert_equal 2_000_000_000, priority_value(port, "system-cluster-critical")
  ensure
    service&.stop(reason: "test complete")
  end

  def test_excluding_a_failed_check_uses_kubernetes_verbose_output
    server = Rubernetes::API::Server.new(ready: false)
    path = "/livez?verbose=&exclude=etcd&exclude=unknown"
    result = server.call(method: "GET", path: path)

    assert_equal 200, result.status
    assert_equal "[+]ping ok\n[+]log ok\n[+]etcd excluded: ok\nwarn: some health checks cannot be excluded: no matches for \"unknown\"\nlivez check passed\n",
                 result.body
    failed = server.call(method: "GET", path: "/livez/etcd")

    assert_equal 500, failed.status
    assert_match(/\Ainternal server error: /, failed.body)
  end

  def test_logging_probe_expires_when_the_sink_cannot_flush
    elapsed = 0
    started = Queue.new
    blocked = Queue.new
    startup = Rubernetes::API::StartupHealth.new(clock: -> { elapsed })
    startup.monitor_log do
      started.push(true)
      blocked.pop
    end
    Timeout.timeout(2) { started.pop }
    elapsed = 119

    assert_predicate startup, :log_healthy?

    elapsed = 120

    refute_predicate startup, :log_healthy?
  ensure
    startup&.stop_log_monitor
  end

  private

  def get(port, path)
    Net::HTTP.start("127.0.0.1", port, nil) { |http| http.get(path) }
  end

  def priority_value(port, name)
    JSON.parse(get(port, "#{PRIORITY_CLASSES}/#{name}").body).fetch("value")
  end

  def wait_for_probe(port)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    loop do
      response = get(port, "/readyz?verbose=1")
      return response if response.code == "200" || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep(0.025)
    end
  end
end
