# frozen_string_literal: true

require "test_helper"
require "net/http"
require "socket"
require "rubernetes/node/kubelet_healthz"

# kubelet keeps running when its /healthz port is taken and tries the port
# again every five seconds (cmd/kubelet/app/server.go).  Three agents on one
# host all defaulted to 127.0.0.1:10248 and two of them exited at start.
class KubeletHealthzTest < Minitest::Test
  class Log
    attr_reader :entries

    def initialize = @entries = []
    def error(event, **fields) = @entries << [event, fields]
    def method_missing(*) = nil
    def respond_to_missing?(*) = true
  end

  def test_a_taken_port_is_logged_and_retried_instead_of_raising
    holder = TCPServer.new("127.0.0.1", 0)
    port = holder.addr[1]
    log = Log.new
    healthz = Rubernetes::Node::KubeletHealthz.new(host: "127.0.0.1", port: port, ready: -> { true }, logger: log, retry_seconds: 0.1)

    healthz.start

    refute_predicate healthz, :listening?
    assert_equal "Failed to start healthz server", log.entries.first.first

    holder.close
    wait_until { healthz.listening? }

    assert_equal "ok", Net::HTTP.get(URI("http://127.0.0.1:#{port}/healthz"))
  ensure
    holder&.close unless holder&.closed?
    healthz&.stop
  end

  def test_a_free_port_serves_at_once_and_reports_readiness
    probe = TCPServer.new("127.0.0.1", 0)
    port = probe.addr[1]
    probe.close
    ready = false
    healthz = Rubernetes::Node::KubeletHealthz.new(host: "127.0.0.1", port: port, ready: -> { ready })

    healthz.start

    assert_predicate healthz, :listening?
    assert_equal "500", Net::HTTP.get_response(URI("http://127.0.0.1:#{port}/healthz")).code
    ready = true

    assert_equal "ok", Net::HTTP.get(URI("http://127.0.0.1:#{port}/healthz"))
  ensure
    healthz&.stop
  end

  def test_stopping_while_the_port_is_still_taken_ends_the_retry
    holder = TCPServer.new("127.0.0.1", 0)
    healthz = Rubernetes::Node::KubeletHealthz.new(host: "127.0.0.1", port: holder.addr[1], ready: -> { true }, logger: Log.new, retry_seconds: 0.1)

    healthz.start
    healthz.stop

    refute_predicate healthz, :listening?
  ensure
    holder&.close
  end

  private

  def wait_until(seconds: 5)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    sleep(0.02) until yield || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

    assert yield, "condition was not met within #{seconds}s"
  end
end
