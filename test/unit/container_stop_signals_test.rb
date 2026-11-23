# frozen_string_literal: true

require "rbconfig"
require "timeout"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/node"
require "rubernetes/runtime/native"

class ContainerStopSignalsTest < Minitest::Test
  API = Rubernetes::API
  Native = Rubernetes::Runtime::Native
  ForkAdapter = Rubernetes::Platform::Linux::ProcessSupervisor::ForkAdapter
  PODS = "/api/v1/namespaces/default/pods"

  def server(enabled:, store: API::MemoryStore.new)
    API::Server.new(store: store, feature_gates: {"ContainerStopSignals" => enabled})
  end

  def request(server, method, path, body = nil, content_type: "application/json")
    server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                 body: body && JSON.generate(body),
                                 identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def pod(signal: "SIGUSR1", os: "linux", command: nil, name: "signals")
    container = {"name" => "main", "image" => "example/signal-handler"}
    container["lifecycle"] = {"stopSignal" => signal} if signal
    container["command"] = command if command
    spec = {"nodeName" => "worker", "restartPolicy" => "Never", "terminationGracePeriodSeconds" => 2, "containers" => [container]}
    spec["os"] = {"name" => os} if os
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default"}, "spec" => spec}
  end

  def test_disabled_gate_drops_only_the_stop_signal_and_preserves_an_existing_stored_value
    store = API::MemoryStore.new
    disabled = server(enabled: false, store: store)
    object = pod(name: "hooks", os: nil)
    hook = {"exec" => {"command" => ["/bin/true"]}}
    object.dig("spec", "containers", 0, "lifecycle")["preStop"] = hook
    response = request(disabled, "POST", PODS, object)

    assert_equal 201, response.status, response.body.inspect
    assert_equal({"preStop" => hook}, response.body.dig("spec", "containers", 0, "lifecycle"))

    enabled = server(enabled: true, store: store)

    assert_equal 201, request(enabled, "POST", PODS, pod).status
    path = "#{PODS}/signals"
    response = request(disabled, "PATCH", path, {"metadata" => {"labels" => {"stage" => "disabled"}}},
                       content_type: "application/merge-patch+json")

    assert_equal 200, response.status, response.body.inspect
    assert_equal "SIGUSR1", response.body.dig("spec", "containers", 0, "lifecycle", "stopSignal")
  end

  def test_enabled_gate_validates_the_os_and_signal
    enabled = server(enabled: true)
    [[nil, "SIGUSR1", "FieldValueForbidden"], %w[windows SIGUSR1 FieldValueNotSupported],
     %w[linux TERM FieldValueNotSupported]].each do |os, signal, reason|
      response = request(enabled, "POST", PODS, pod(os: os, signal: signal))

      assert_equal 422, response.status, response.body.inspect
      cause = response.body.dig("details", "causes").first

      assert_equal "spec.containers[0].lifecycle.stopSignal", cause["field"]
      assert_equal reason, cause["reason"]
    end
    response = request(enabled, "POST", PODS, pod(signal: "SIGRTMIN+7"))

    assert_equal 201, response.status, response.body.inspect
    assert_equal "SIGRTMIN+7", response.body.dig("spec", "containers", 0, "lifecycle", "stopSignal")

    updated = JSON.parse(JSON.generate(response.body))
    updated.dig("spec", "containers", 0, "lifecycle")["stopSignal"] = "SIGUSR2"
    rejected = request(enabled, "PUT", "#{PODS}/signals", updated)

    assert_equal 422, rejected.status, rejected.body.inspect
    assert_equal "spec", rejected.body.dig("details", "causes", 0, "field")
  end

  def test_pod_stop_signal_overrides_the_image_and_reaches_the_native_workload
    assert_workload_stop(enabled: true, custom: "SIGUSR1", image: "SIGUSR2", expected: "SIGUSR1", exit_code: 21)
  end

  def test_image_stop_signal_works_with_the_gate_disabled
    assert_workload_stop(enabled: false, custom: "SIGUSR1", image: "SIGUSR2", expected: "SIGUSR2", exit_code: 22)
  end

  def test_default_stop_signal_is_sigterm
    assert_workload_stop(enabled: true, custom: nil, image: nil, expected: "SIGTERM", exit_code: 23)
  end

  def test_unhandled_stop_signal_escalates_to_sigkill
    assert_workload_stop(enabled: true, custom: "SIGUSR1", image: nil, expected: nil, exit_code: 137,
                         ignore_custom: true)
  end

  private

  def assert_workload_stop(enabled:, custom:, image:, expected:, exit_code:, ignore_custom: false)
    Dir.mktmpdir("container-stop-signal") do |directory|
      ready = File.join(directory, "ready")
      received = File.join(directory, "received")
      program = <<~'RUBY'
        ready, received, ignore_custom = ARGV
        {"USR1" => 21, "USR2" => 22, "TERM" => 23}.each do |signal, exit_code|
          trap(signal) do
            next if ignore_custom == "true"

            File.write(received, "SIG#{signal}")
            exit(exit_code)
          end
        end
        File.write(ready, "")
        loop { sleep(1) }
      RUBY
      command = [RbConfig.ruby, "-e", program, ready, received, ignore_custom.to_s]
      api = server(enabled: true)
      response = request(api, "POST", PODS, pod(signal: custom, command: command))

      assert_equal 201, response.status, response.body.inspect

      resolver = Object.new
      resolver.define_singleton_method(:resolve) do |reference|
        {"reference" => reference, "digest" => "sha256:#{"a" * 64}", "config" => {"config" => {"StopSignal" => image}}}
      end
      resolver.define_singleton_method(:release) { |_resolved| true }
      runtime = Native.new(profile: :pure, log_root: directory, adapters: {process_adapter: ForkAdapter.new},
                           image_resolver: resolver)
      reported = nil
      report = lambda do |_pod, status|
        reported = request(api, "PATCH", "#{PODS}/signals/status", {"status" => status}, content_type: "application/merge-patch+json")
      end
      lifecycle = Rubernetes::Node::Agent.new(node_name: "worker", api: api, runtime: runtime,
                                              feature_gates: {"ContainerStopSignals" => enabled}, reporter: report).lifecycle
      result = lifecycle.reconcile(response.body, action: "ADDED")

      assert_equal "Running", result.state, result.error

      status = request(api, "GET", "#{PODS}/signals").body.dig("status", "containerStatuses", 0)
      if enabled
        assert_equal(custom || image || "SIGTERM", status["stopSignal"])
      else
        refute status.key?("stopSignal")
      end
      Timeout.timeout(5) { sleep(0.01) until File.exist?(ready) }

      deletion = request(api, "DELETE", "#{PODS}/signals", {"gracePeriodSeconds" => 2})

      assert_equal 200, deletion.status, deletion.body.inspect
      stopped = lifecycle.reconcile(deletion.body, action: "MODIFIED")

      assert_equal "Removed", stopped.state, (stopped.error || stopped.cleanup_errors.inspect)
      assert_equal 200, reported.status, reported.body.inspect
      assert_equal exit_code, reported.body.dig("status", "containerStatuses", 0, "state", "terminated", "exitCode")
      if expected
        assert_equal expected, File.read(received)
      else
        refute_path_exists received
      end
    ensure
      lifecycle&.terminate(response.body) if result&.state == "Running" && stopped.nil?
    end
  end
end
