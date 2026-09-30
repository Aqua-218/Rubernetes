# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

class NodeProbeRestartTest < Minitest::Test
  class Runtime
    attr_accessor :exit_code

    def initialize(exit_code = 0)
      @exit_code = exit_code
    end

    def exec(_id, _command, tty: false)
      @exit_code
    end
  end

  class HTTP
    attr_accessor :status

    def initialize(status)
      @status = status
    end

    def get(_uri, headers:, timeout:, **_options)
      {"status" => @status, "headers" => headers, "timeout" => timeout}
    end
  end

  class TCP
    attr_accessor :result

    def initialize(result)
      @result = result
    end

    def connect(_host, _port, timeout:, **_options)
      @result
    end
  end

  def test_startup_probe_gates_liveness_and_readiness_until_success
    runtime = Runtime.new(1)
    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime, clock: -> { 0 })
    probes = {
      "startupProbe" => {"exec" => {"command" => ["/ready"]}, "failureThreshold" => 1},
      "livenessProbe" => {"exec" => {"command" => ["/live"]}},
      "readinessProbe" => {"exec" => {"command" => ["/ready"]}}
    }
    manager.register("container-1", probes: probes)

    first = manager.evaluate("container-1", probes: probes)

    assert_predicate first.fetch("startup"), :failed?
    assert_nil first.fetch("liveness")
    assert_nil first.fetch("readiness")

    runtime.exit_code = 0
    second = manager.evaluate("container-1", probes: probes)

    assert_predicate second.fetch("startup"), :success?
    assert_predicate second.fetch("liveness"), :success?
    assert_predicate second.fetch("readiness"), :success?
    assert manager.ready?("container-1")
  end

  def test_exec_http_and_tcp_probe_results_are_normalized
    runtime = Runtime.new(0)
    http = HTTP.new(204)
    tcp = TCP.new(true)
    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime, http_client: http, tcp_client: tcp)

    assert_predicate manager.check("exec", {"exec" => {"command" => ["true"]}}), :success?
    assert_predicate manager.check("http", {"httpGet" => {"host" => "127.0.0.1", "port" => 8080, "path" => "/health"}}), :success?
    assert_predicate manager.check("tcp", {"tcpSocket" => {"host" => "127.0.0.1", "port" => 8080}}), :success?

    http.status = 500

    refute_predicate manager.check("http", {"httpGet" => {"port" => 8080}}), :success?
  end

  def test_probe_failure_threshold_controls_liveness_failure
    runtime = Runtime.new(1)
    manager = Rubernetes::Node::ProbeManager.new(runtime: runtime)
    probe = {"exec" => {"command" => ["false"]}, "failureThreshold" => 2}
    manager.register("c", probes: {"livenessProbe" => probe})

    refute_nil manager.check("c", probe: probe, type: "liveness")
    refute manager.liveness_failed?("c")
    manager.check("c", probe: probe, type: "liveness")

    assert manager.liveness_failed?("c")
  end

  def test_restart_policies_and_backoff_reset
    clock = 0
    manager = Rubernetes::Node::RestartManager.new(clock: -> { clock }, sleeper: ->(_seconds) {})

    refute manager.should_restart?(policy: "Never", exit_code: 1)
    refute manager.should_restart?(policy: "OnFailure", exit_code: 0)
    assert manager.should_restart?(policy: "OnFailure", exit_code: 1)
    assert manager.should_restart?(policy: "Always", exit_code: 0)

    delays = Array.new(7) do
      manager.record_start("c", at: clock)
      manager.record_exit("c", policy: "Always", exit_code: 1, at: clock).delay_seconds
    end
    # kubelet: the first failure restarts at once, then 10 s doubling to 300 s.
    assert_equal [0, 10, 20, 40, 80, 160, 300], delays
    assert manager.crash_loop_backoff?("c")

    manager.record_start("c", at: clock)
    clock = 600
    reset = manager.record_exit("c", policy: "Always", exit_code: 1, at: clock)

    assert_equal 1, reset.failure_count
    assert_equal 0, reset.delay_seconds
    refute manager.crash_loop_backoff?("c")
  end
end
