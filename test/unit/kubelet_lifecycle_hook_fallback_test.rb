# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"
require_relative "../support/node_lifecycle_fakes"

# pkg/kubelet/lifecycle/handlers.go (v1.36.2): an HTTPS lifecycle hook that
# gets an HTTP answer is retried over HTTP without Authorization and
# reported as LifecycleHTTPFallback; a preStop sleep cut off by the grace
# period fails with "container terminated before sleep hook finished".
class KubeletLifecycleHookFallbackTest < Minitest::Test
  class Runtime < NodeLifecycleFakes::Runtime
    attr_reader :requests

    def initialize(plain: true)
      super()
      @plain = plain
      @requests = []
    end

    def http_get(_id, definition, timeout:)
      @requests << definition
      if definition["scheme"] == "HTTPS" && @plain
        raise OpenSSL::SSL::SSLError, "SSL_connect returned=1 errno=0 state=error: wrong version number"
      end

      {"status" => 200, "success" => true}
    end
  end

  def lifecycle(runtime)
    @entries = []
    @metrics = Rubernetes::Node::KubeletMetrics.new(node_name: "n")
    Rubernetes::Node::Lifecycle.new(runtime: runtime, reporter: NodeLifecycleFakes::Reporter.new, sleeper: ->(_seconds) {},
                                    event_sink: ->(_uid, entry) { @entries << entry }).tap { |value| value.metrics_observer = @metrics }
  end

  def record = {uid: "u", containers: [], events: [], state: "Running"}

  def test_an_https_hook_answered_in_http_falls_back
    runtime = Runtime.new
    subject = lifecycle(runtime)
    hook = {"httpGet" => {"scheme" => "HTTPS", "host" => "10.0.0.5", "port" => 8443, "path" => "/stop",
                          "httpHeaders" => [{"name" => "Authorization", "value" => "Bearer x"}, {"name" => "X", "value" => "y"}]}}
    subject.send(:execute_hook, "c1", hook, record: record)

    assert_equal(%w[HTTPS HTTP], runtime.requests.map { |request| request["scheme"] })
    assert_equal [{"name" => "X", "value" => "y"}], runtime.requests.last["httpHeaders"]
    fallback = @entries.find { |entry| entry["type"] == "hook.http_fallback" }
    reasons = Rubernetes::Node::KubeletEventPublisher::REASONS.fetch("hook.http_fallback")

    assert_equal %w[Warning LifecycleHTTPFallback], reasons.first(2)
    assert_equal "request to HTTPS lifecycle hook 10.0.0.5:8443 got HTTP response, retry with HTTP succeeded", reasons[2].call(fallback, {})
    assert_includes @metrics.registry.render, "kubelet_lifecycle_handler_http_fallbacks_total 1"
  end

  def test_other_https_failures_are_not_retried
    runtime = Class.new(Runtime) do
      def http_get(_id, definition, timeout:)
        @requests << definition
        raise OpenSSL::SSL::SSLError, "certificate verify failed"
      end
    end.new
    subject = lifecycle(runtime)
    assert_raises(OpenSSL::SSL::SSLError) { subject.send(:execute_hook, "c1", {"httpGet" => {"scheme" => "HTTPS", "port" => 1}}, record: record) }
    assert_equal 1, runtime.requests.length
  end

  def test_a_prestop_sleep_past_the_grace_period
    subject = lifecycle(Runtime.new)
    error = assert_raises(Rubernetes::Node::Lifecycle::LifecycleError) do
      subject.send(:execute_hook, "c1", {"sleep" => {"seconds" => 30}}, timeout: 5, record: record, grace_bounded: true)
    end
    assert_equal "container terminated before sleep hook finished", error.message
    assert_includes @metrics.registry.render, "kubelet_sleep_action_terminated_early_total 1"
    subject.send(:execute_hook, "c1", {"sleep" => {"seconds" => 60}}, record: record)
  end
end
