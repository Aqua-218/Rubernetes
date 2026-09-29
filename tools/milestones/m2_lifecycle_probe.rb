#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m2_probe_support"
require_relative "m2_lifecycle_trace_support"
require_relative "m2_kubernetes_lifecycle_oracle"

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "json"
require "rubernetes/node"
require "rubernetes/runtime"
require "tmpdir"

module M2LifecycleProbe
  module_function

  class Adapter
    def initialize(failure_point: nil)
      @failure_point = failure_point
    end

    def allocate_workspace(config:, **)
      raise "injected workspace failure" if @failure_point == "workspace_allocated"

      resource("workspace", "workspace-1")
    end

    def create_isolation(config:, **)
      raise "injected isolation failure" if @failure_point == "isolation_created"

      resource("namespace", "namespace-1")
    end

    def attach_resources(**)
      resource("network", "network-1")
    end

    def hold_workload(**)
      resource("process", "process-1")
    end

    def cleanup_resource(_resource)
      true
    end

    private

    def resource(kind, id)
      {"kind" => kind, "id" => id, "identity" => "#{kind}:#{id}"}
    end
  end

  class NodeRuntime
    def initialize
      @containers = 0
    end

    def run_sandbox(_pod, **)
      "node-sandbox"
    end

    def create_container(_sandbox, _spec)
      @containers += 1
      "node-container-#{@containers}"
    end

    def start_container(_id)
      true
    end

    def stop_container(_id, timeout: _timeout)
      true
    end

    def remove_container(_id)
      true
    end

    def remove_sandbox(_id)
      true
    end
  end

  class NodeVolume
    def prepare(_pod)
      "node-volume"
    end

    def release(_id)
      true
    end
  end

  class NodeNetwork
    def add(_sandbox, _pod)
      "node-network"
    end

    def delete(_sandbox)
      true
    end
  end

  # In-process container runtime double for the lifecycle semantics matrix.
  # It records every runtime operation with the container name and emulates
  # the pinned fixture containers: probe commands exit by their command,
  # the graceful-termination container appends "preStop"/"TERM" to its
  # termination log and ignores SIGTERM (it exits 137 on SIGKILL), and every
  # other container stops on SIGTERM with exit 0.
  class SemanticsRuntime
    attr_reader :calls

    def initialize(stop_result: true, ignore_term: false)
      @calls = []
      @counter = 0
      @stop_result = stop_result
      @ignore_term = ignore_term
      @names = {}
      @logs = Hash.new { |hash, key| hash[key] = +"" }
      @killed = {}
    end

    def name_for(id)
      @names.fetch(id, id)
    end

    def run_sandbox(_pod, runtime_class: nil)
      @calls << ["sandbox", runtime_class]
      "sandbox-1"
    end

    def create_container(_sandbox, spec)
      @counter += 1
      id = "container-#{@counter}"
      @names[id] = spec.fetch("name")
      @calls << ["create", spec.fetch("name")]
      id
    end

    def start_container(id)
      @calls << ["start", name_for(id)]
      @killed.delete(id)
      true
    end

    def wait_container(id)
      @calls << ["wait", name_for(id)]
      {"state" => "terminated", "exitCode" => 0}
    end

    def exec(id, command, tty: false, timeout: nil, **_options)
      command = Array(command)
      @calls << ["exec", name_for(id), command, tty]
      @logs[id] << "preStop\n" if command.join(" ").include?("echo preStop")
      return 1 if %w[/live /bin/false].include?(command.first)

      0
    end

    def signal(id, signal)
      @calls << ["signal", name_for(id), signal]
      @logs[id] << "TERM\n" if signal.to_s == "TERM" && @ignore_term
      true
    end

    def stop_container(id, timeout:)
      @calls << ["stop", name_for(id), timeout]
      return {"running" => false, "exitCode" => 137} if @killed[id]
      return false if @ignore_term

      @stop_result
    end

    def kill_container(id, signal:)
      @calls << ["kill", name_for(id), signal]
      @killed[id] = true
      true
    end

    def container_status(id)
      return {"state" => "terminated", "terminated" => {"exitCode" => 137, "reason" => "Error", "message" => @logs[id].dup}} if @killed[id]

      {"state" => "running", "running" => {}}
    end

    def remove_container(id)
      @calls << ["remove", name_for(id)]
      true
    end

    def remove_sandbox(id)
      @calls << ["sandbox_remove", id]
      true
    end
  end

  class ProbeRuntime
    def exec(_id, command, tty: _tty, timeout: _timeout)
      %w[/live /bin/false].include?(command.first) ? 1 : 0
    end
  end

  # These comparisons validate production Ruby lifecycle policy classes in
  # process. Kernel-effect execution remains in the separate Native flow,
  # SIGKILL matrix, and L3 cycle evidence below.
  # Observables of the pinned kubelet (kubernetes v1.36.2 kind node oracle,
  # test/conformance/kubernetes/m2_lifecycle_oracle/harness.rb derivation) that
  # Rubernetes' production semantics must reproduce.
  EXPECTED_LIFECYCLE_OBSERVABLES = JSON.parse(<<~'JSON').freeze
{
      "init_sidecar_app_order": {
        "operations": [
          "create:prepare",
          "start:prepare",
          "wait:prepare",
          "create:sidecar",
          "start:sidecar",
          "create:app",
          "start:app"
        ],
        "phase": "Running",
        "status": {
          "initContainerStatuses": [
            {
              "name": "prepare",
              "state": "terminated",
              "restartCount": 0,
              "ready": true,
              "started": false,
              "exitCode": 0
            },
            {
              "name": "sidecar",
              "state": "running",
              "restartCount": 0,
              "ready": true,
              "started": true
            }
          ],
          "containerStatuses": [
            {
              "name": "app",
              "state": "running",
              "restartCount": 0,
              "ready": true,
              "started": true
            }
          ]
        }
      },
      "startup_liveness_readiness_thresholds": {
        "startup": {
          "probe": "exec:/bin/true",
          "successThreshold": 1,
          "failureThreshold": 3,
          "periodSeconds": 1,
          "result": "succeeded",
          "started": true
        },
        "readiness": {
          "probe": "exec:/bin/true",
          "successThreshold": 2,
          "failureThreshold": 1,
          "periodSeconds": 1,
          "result": "succeeded",
          "ready": true,
          "ready_before_liveness_kill": true
        },
        "liveness": {
          "probe": "exec:/bin/false",
          "failureThreshold": 2,
          "periodSeconds": 1,
          "initialDelaySeconds": 10,
          "result": "failed",
          "failures_before_kill": 2,
          "kill_reason": "Killing",
          "kill_message": "Container app failed liveness probe, will be restarted",
          "restartCount_after_kill": 1
        }
      },
      "restart_policy_and_backoff": {
        "restartPolicy": {
          "always_exit_0": "Always",
          "on_failure_exit_0": "OnFailure",
          "on_failure_exit_1": "OnFailure",
          "never_exit_1": "Never"
        },
        "restartCount": {
          "always_exit_0": 2,
          "on_failure_exit_0": 0,
          "on_failure_exit_1": 2,
          "never_exit_1": 0
        },
        "phase": {
          "always_exit_0": "Running",
          "on_failure_exit_0": "Succeeded",
          "on_failure_exit_1": "Running",
          "never_exit_1": "Failed"
        },
        "status": {
          "always_exit_0": {
            "state": "waiting",
            "reason": "CrashLoopBackOff",
            "exitCode": null,
            "lastState": "terminated",
            "lastReason": "Completed",
            "lastExitCode": 0
          },
          "on_failure_exit_0": {
            "state": "terminated",
            "reason": "Completed",
            "exitCode": 0,
            "lastState": null,
            "lastReason": null,
            "lastExitCode": null
          },
          "on_failure_exit_1": {
            "state": "waiting",
            "reason": "CrashLoopBackOff",
            "exitCode": null,
            "lastState": "terminated",
            "lastReason": "Error",
            "lastExitCode": 1
          },
          "never_exit_1": {
            "state": "terminated",
            "reason": "Error",
            "exitCode": 1,
            "lastState": null,
            "lastReason": null,
            "lastExitCode": null
          }
        },
        "backoff_seconds": {
          "always_exit_0": [
            "10s",
            "20s"
          ],
          "on_failure_exit_1": [
            "10s",
            "20s"
          ]
        }
      },
      "graceful_termination_oracle": {
        "operations": [
          "exec:preStop",
          "signal:TERM",
          "wait:2",
          "signal:KILL"
        ],
        "events": [
          "Killing"
        ],
        "phase": "Failed",
        "status": {
          "state": "terminated",
          "exitCode": 137,
          "reason": "Error",
          "message": "preStop\nTERM\n"
        },
        "terminationGracePeriodSeconds": 2,
        "killed_after_grace_period": true
      }
    }
  JSON

  # The observables mirror test/conformance/kubernetes/m2_lifecycle_oracle/
  # harness.rb, which derives the same shapes from the pinned kubelet.
  def lifecycle_semantics_matrix
    fixtures = M2KubernetesLifecycleOracle.fixture_cases
    [
      init_order_case(fixtures.fetch("init_sidecar_app_order")),
      probe_thresholds_case(fixtures.fetch("startup_liveness_readiness_thresholds")),
      restart_policy_case(fixtures.fetch("restart_policy_and_backoff")),
      graceful_termination_case(fixtures.fetch("graceful_termination_oracle"))
    ]
  end

  def semantics_clock(now = 0)
    state = {now: now}
    [state, -> { Time.at(state[:now]).utc }]
  end

  def container_summary(status)
    kind = status.fetch("state").keys.first
    summary = {
      "name" => status.fetch("name"),
      "state" => kind,
      "restartCount" => status.fetch("restartCount"),
      "ready" => status.fetch("ready") == true,
      "started" => status.fetch("started") == true
    }
    summary["exitCode"] = status.fetch("state").fetch("terminated")["exitCode"] if kind == "terminated"
    summary
  end

  def restart_status_summary(status)
    kind = status.fetch("state").keys.first
    details = status.fetch("state").fetch(kind)
    last_kind = status["lastState"].is_a?(Hash) ? status["lastState"].keys.first : nil
    last = last_kind ? status["lastState"].fetch(last_kind) : {}
    {
      "state" => kind,
      "reason" => details["reason"],
      "exitCode" => kind == "terminated" ? details["exitCode"] : nil,
      "lastState" => last_kind,
      "lastReason" => last["reason"],
      "lastExitCode" => last_kind == "terminated" ? last["exitCode"] : nil
    }
  end

  def init_order_case(fixture)
    pod = fixture.fetch("pod")
    runtime = SemanticsRuntime.new
    _clock_state, clock = semantics_clock
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, clock: clock, sleeper: ->(_seconds) {})
    result = lifecycle.start(pod)
    operations = runtime.calls.filter_map do |call|
      case call.first
      when "create", "start", "wait" then "#{call.first}:#{call[1]}"
      end
    end
    spec = pod.fetch("spec")
    observed = {
      "operations" => operations,
      "phase" => result.phase,
      "status" => {
        "initContainerStatuses" => Array(spec["initContainers"]).map { |container| container_summary(result.status.fetch("initContainerStatuses").find { |status| status["name"] == container.fetch("name") }) },
        "containerStatuses" => Array(spec["containers"]).map { |container| container_summary(result.status.fetch("containerStatuses").find { |status| status["name"] == container.fetch("name") }) }
      }
    }
    lifecycle.terminate(pod)
    expected = EXPECTED_LIFECYCLE_OBSERVABLES.fetch("init_sidecar_app_order")
    semantics_case(
      "init_sidecar_app_order", expected, observed, expected == observed,
      production_classes: [lifecycle.class.name, Rubernetes::Node::ProbeManager.name],
      support_classes: [runtime.class.name],
      support_doubles: %w[clock sleeper]
    )
  end

  def probe_label(probe)
    "exec:#{Array(probe.dig("exec", "command")).first}"
  end

  def probe_thresholds_case(fixture)
    pod = fixture.fetch("pod")
    container = pod.fetch("spec").fetch("containers").first
    name = container.fetch("name")
    startup = container.fetch("startupProbe")
    liveness = container.fetch("livenessProbe")
    readiness = container.fetch("readinessProbe")
    runtime = SemanticsRuntime.new
    clock_state, clock = semantics_clock
    probes = Rubernetes::Node::ProbeManager.new(runtime: runtime, clock: clock)
    restarts = Rubernetes::Node::RestartManager.new(clock: -> { clock_state[:now] }, sleeper: ->(_seconds) {})
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, probe_manager: probes, restart_manager: restarts,
                                                clock: clock, sleeper: ->(_seconds) {})
    lifecycle.start(pod)
    started_before_kill = false
    ready_before_kill = false
    ready_restart_count = nil
    failures_before_kill = 0
    kill_event = nil
    # One probe cycle per second until the liveness failureThreshold restarts
    # the container (initialDelaySeconds 10 + failureThreshold 2).
    (0..20).each do |second|
      clock_state[:now] = second
      container_id = lifecycle.record(pod).fetch(:containers).first[:id]
      lifecycle.probe(pod, now: second)
      status = lifecycle.record(pod).fetch(:status).fetch("containerStatuses").first
      events = lifecycle.record(pod).fetch(:events)
      kill_event = events.find { |event| event["reason"] == "Killing" }
      if kill_event.nil?
        started_before_kill ||= status["started"] == true
        if status["ready"] == true
          ready_before_kill = true
          ready_restart_count = status["restartCount"]
        end
      end
      # Liveness failures of the container that was (or is about to be) killed:
      # the kubelet counts the Unhealthy events recorded before the Killing event.
      failures_before_kill = probes.failure_count(container_id, type: "liveness") if kill_event.nil? || failures_before_kill.zero? || status["restartCount"].to_i >= 1
      break if status["restartCount"].to_i >= 1
    end
    final = lifecycle.record(pod).fetch(:status).fetch("containerStatuses").first
    observed = {
      "startup" => {
        "probe" => probe_label(startup),
        "successThreshold" => startup.fetch("successThreshold", 1),
        "failureThreshold" => startup.fetch("failureThreshold", 3),
        "periodSeconds" => startup.fetch("periodSeconds", 10),
        "result" => started_before_kill ? "succeeded" : "failed",
        "started" => started_before_kill
      },
      "readiness" => {
        "probe" => probe_label(readiness),
        "successThreshold" => readiness.fetch("successThreshold", 1),
        "failureThreshold" => readiness.fetch("failureThreshold", 3),
        "periodSeconds" => readiness.fetch("periodSeconds", 10),
        "result" => ready_before_kill ? "succeeded" : "failed",
        "ready" => ready_before_kill,
        "ready_before_liveness_kill" => ready_before_kill && ready_restart_count.to_i.zero?
      },
      "liveness" => {
        "probe" => probe_label(liveness),
        "failureThreshold" => liveness.fetch("failureThreshold", 3),
        "periodSeconds" => liveness.fetch("periodSeconds", 10),
        "initialDelaySeconds" => liveness.fetch("initialDelaySeconds", 0),
        "result" => "failed",
        "failures_before_kill" => failures_before_kill,
        "kill_reason" => kill_event ? kill_event["reason"] : nil,
        "kill_message" => kill_event ? kill_event["message"] : nil,
        "restartCount_after_kill" => final["restartCount"]
      }
    }
    lifecycle.terminate(pod)
    expected = EXPECTED_LIFECYCLE_OBSERVABLES.fetch("startup_liveness_readiness_thresholds")
    semantics_case(
      "startup_liveness_readiness_thresholds", expected, observed, expected == observed,
      production_classes: [lifecycle.class.name, probes.class.name, restarts.class.name],
      support_classes: [runtime.class.name],
      support_doubles: %w[clock sleeper]
    )
  end

  # Lifecycle#restart_identity: the backoff is keyed by Pod UID and container
  # name, not by the container instance.
  def restart_key_for(pod, container)
    "#{pod.fetch("metadata").fetch("uid")}/#{container.fetch("name")}"
  end

  def restart_policy_case(fixture)
    variants = fixture.fetch("variants")
    restarting = %w[always_exit_0 on_failure_exit_1]
    observed = {"restartPolicy" => {}, "restartCount" => {}, "phase" => {}, "status" => {}, "backoff_seconds" => {}}
    production = []
    variants.each do |variant, document|
      pod = {"metadata" => {"name" => "restart-#{variant.tr("_", "-")}", "namespace" => "m2", "uid" => "restart-#{variant}"}, "spec" => document.fetch("spec")}
      container = document.fetch("spec").fetch("containers").first
      exit_code = Integer(container.fetch("command").last.split.last)
      runtime = SemanticsRuntime.new
      clock_state, clock = semantics_clock
      backoffs = []
      lifecycle = nil
      sleeper = ->(seconds) { clock_state[:now] += seconds }
      restarts = Rubernetes::Node::RestartManager.new(clock: -> { clock_state[:now] }, sleeper: sleeper)
      lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, restart_manager: restarts, clock: clock, sleeper: sleeper)
      production = [lifecycle.class.name, restarts.class.name]
      lifecycle.start(pod)
      settled = nil
      # kubelet holds a crash-looping container in CrashLoopBackOff and starts
      # it again on the sync that finds the backoff elapsed -- it never sleeps
      # through the wait.  Advancing this clock and reconciling is the same
      # sequence a node performs.
      6.times do
        clock_state[:now] += 1
        lifecycle.handle_container_exit(pod, container_name: container.fetch("name"), exit_code: exit_code, now: clock_state[:now])
        status = lifecycle.record(pod).fetch(:status)
        container_status = status.fetch("containerStatuses").first
        backoffs << container_status if container_status.dig("state", "waiting", "reason") == "CrashLoopBackOff"
        if restarting.include?(variant)
          candidate = backoffs.find { |entry| entry["restartCount"].to_i >= 2 }
          if candidate
            settled = [status.fetch("phase"), candidate]
            break
          end
          clock_state[:now] += restarts.backoff(restart_key_for(pod, container)) + 1
          lifecycle.reconcile(pod)
        elsif %w[Succeeded Failed].include?(status.fetch("phase"))
          settled = [status.fetch("phase"), status.fetch("containerStatuses").first]
          break
        end
      end
      raise "restart variant #{variant} did not settle" unless settled
      phase, status = settled
      observed["restartPolicy"][variant] = document.fetch("spec").fetch("restartPolicy")
      observed["restartCount"][variant] = status.fetch("restartCount")
      observed["phase"][variant] = phase
      observed["status"][variant] = restart_status_summary(status)
      if restarting.include?(variant)
        observed["backoff_seconds"][variant] = backoffs.first(2).map { |entry| entry.dig("state", "waiting", "message")[/back-off (\d+s)/, 1] }.uniq
      end
    end
    expected = EXPECTED_LIFECYCLE_OBSERVABLES.fetch("restart_policy_and_backoff")
    semantics_case(
      "restart_policy_and_backoff", expected, observed, expected == observed,
      production_classes: production,
      support_classes: [SemanticsRuntime.name],
      support_doubles: %w[clock sleeper]
    )
  end

  def graceful_termination_case(fixture)
    pod = fixture.fetch("pod")
    grace = pod.fetch("spec").fetch("terminationGracePeriodSeconds")
    runtime = SemanticsRuntime.new(stop_result: false, ignore_term: true)
    clock_state, clock = semantics_clock
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, clock: clock, sleeper: ->(seconds) { clock_state[:now] += seconds })
    lifecycle.start(pod)
    deletion_at = clock_state[:now]
    result = lifecycle.terminate(pod)
    operations = runtime.calls.filter_map do |call|
      case call.first
      when "exec" then "exec:preStop" if call[2].join(" ").include?("preStop")
      when "signal" then "signal:#{call[2]}"
      when "kill" then "signal:#{call[2]}"
      end
    end
    kill_call_index = runtime.calls.index { |call| call.first == "kill" }
    terminated = result.status.fetch("containerStatuses").first
    finished_at = clock_state[:now]
    # kubelet: exit 137 only once the full grace period has elapsed since the
    # delete request (the kind harness measures the same interval on its
    # wall clock; here the fake clock advances exactly by the waited grace).
    killed_after_grace = terminated.dig("state", "terminated", "exitCode") == 137 && finished_at - deletion_at >= grace
    operations.insert(operations.index("signal:KILL"), "wait:#{grace}") if killed_after_grace && operations.include?("signal:KILL") && kill_call_index
    observed = {
      "operations" => operations,
      "events" => result.events.filter_map { |event| event["reason"] }.uniq,
      "phase" => result.phase,
      "status" => {
        "state" => terminated.fetch("state").keys.first,
        "exitCode" => terminated.dig("state", "terminated", "exitCode"),
        "reason" => terminated.dig("state", "terminated", "reason"),
        "message" => terminated.dig("state", "terminated", "message").to_s
      },
      "terminationGracePeriodSeconds" => grace,
      "killed_after_grace_period" => killed_after_grace
    }
    expected = EXPECTED_LIFECYCLE_OBSERVABLES.fetch("graceful_termination_oracle")
    semantics_case(
      "graceful_termination_oracle", expected, observed, result.state == "Removed" && expected == observed,
      production_classes: [lifecycle.class.name],
      support_classes: [runtime.class.name],
      support_doubles: %w[clock sleeper]
    )
  end

  def semantics_case(name, expected, observed, passed, production_classes:, support_classes:, support_doubles:)
    actual_provenance = {
      "source" => M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE,
      "execution_mode" => "in_process",
      "native_effects_executed" => false,
      "production_classes" => production_classes,
      "support_classes" => support_classes,
      "support_doubles" => support_doubles
    }
    payload = {
      "name" => name,
      "expected" => expected,
      "observed" => observed,
      "actual_provenance" => actual_provenance,
      "passed" => passed == true
    }
    payload["evidence_sha256"] = M2Gate.canonical_document_digest(payload)
    payload
  end

  def run(input)
    Dir.mktmpdir("rubernetes-m2-lifecycle-") do |directory|
      node_runtime = NodeRuntime.new
      node_lifecycle = Rubernetes::Node::Lifecycle.new(
        runtime: node_runtime,
        volume: NodeVolume.new,
        network: NodeNetwork.new,
        sleeper: ->(_seconds) {}
      )
      pod = {
        "metadata" => {"name" => "m2-probe", "uid" => "m2-probe"},
        "spec" => {"containers" => [{"name" => "app", "image" => "example/app"}]}
      }
      node_started = node_lifecycle.start(pod)
      node_finished = node_lifecycle.terminate(pod)
      raise "Node lifecycle did not reach Removed/Succeeded" unless node_started.phase == "Running" && node_finished.state == "Removed" && node_finished.phase == "Succeeded"

      # RuntimeLifecycle trace: replayed from the production Native runtime's
      # hash-chained ownership journal (one real L3 lifecycle plus one real
      # effect-point failure injection); kernel facets come from the Native
      # kernel observer readback at each durable effect point.
      trace_measurement = M2LifecycleTraceSupport.native_lifecycle_measurement
      trace = trace_measurement.fetch("trace")
      live = trace_measurement.fetch("live_resource_count")
      sigkill_matrix = M2ProbeSupport.measure_sigkill_matrix(
        effect_points: M2Gate::REQUIRED_EFFECT_POINTS,
        image_digest: "sha256:" + ("c" * 64)
      )
      inventory_measurement = M2ProbeSupport.inventory_measurement_from(sigkill_matrix)
      subresource_e2e, subresource_e2e_sha256, apply_lifecycle_native_flow = M2ProbeSupport.subresource_e2e_measurement
      apply_lifecycle_native_flow["measurement_source"] = "production_native_lifecycle"
      kernel_l3_available = M2ProbeSupport.l3_available?
      l3_available = kernel_l3_available && inventory_measurement.fetch("missing_resource_kinds").empty?
      matrix_passed = sigkill_matrix.all? do |entry|
        entry["kill_observed"] == true && entry["restart_observed"] == true && entry["wal_replayed"] == true &&
          entry["live_wrong_deletion_count"] == 0 && entry["dead_residual_count"] == 0
      end
      subresources_passed = subresource_e2e.values.all? { |entry| entry["passed"] == true }
      semantics_matrix = lifecycle_semantics_matrix
      lifecycle_oracle = M2KubernetesLifecycleOracle.run(input: input, actual_cases: semantics_matrix)
      oracle_difference_count = if lifecycle_oracle["executed"] == true
                                 Array(lifecycle_oracle["comparisons"]).count { |entry| entry["passed"] != true }
                               else
                                 M2Gate::REQUIRED_LIFECYCLE_SEMANTICS.length
                               end
      errors = []
      errors << "L3 kernel isolation profile is unavailable" unless kernel_l3_available
      errors << "L3 resource inventory is incomplete: #{inventory_measurement.fetch("missing_resource_kinds").join(", ")}" unless inventory_measurement.fetch("missing_resource_kinds").empty?
      errors << "subresource E2E requires a real Native adapter" unless subresources_passed
      errors << "Native lifecycle trace left kernel resources: #{trace_measurement.fetch("cleanup_readback").length}" unless trace_measurement.fetch("cleanup_readback").empty?
      errors << "Native lifecycle trace did not end in Removed" unless trace.any? { |event| event["to"] == "Removed" }
      errors << "lifecycle semantic oracle has #{oracle_difference_count} differences" unless oracle_difference_count.zero?
      errors.concat(Array(lifecycle_oracle["errors"])) unless lifecycle_oracle["errors"].nil?
      unless apply_lifecycle_native_flow["apply_preceded_lifecycle"] == true &&
             apply_lifecycle_native_flow["node_lifecycle_class"] == "Rubernetes::Node::Lifecycle" &&
             apply_lifecycle_native_flow["runtime_class"] == "Rubernetes::Runtime::Native" &&
             apply_lifecycle_native_flow["finish_state"] == "Removed"
        errors << "Apply -> Node::Lifecycle -> Native flow was not completed"
      end
      {
        "trace" => trace,
        "trace_sha256" => Digest::SHA256.hexdigest(JSON.generate(trace)),
        "trace_measurement" => trace_measurement.reject { |key, _| key == "trace" },
        "trace_measurement_source" => trace_measurement.fetch("measurement_source"),
        "node_lifecycle" => {"start_phase" => node_started.phase, "finish_state" => node_finished.state,
                              "finish_phase" => node_finished.phase},
        "lifecycle_semantics_measurement_source" => M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE,
        "lifecycle_semantics_matrix" => semantics_matrix,
        "lifecycle_semantics_matrix_sha256" => M2Gate.canonical_document_digest(semantics_matrix),
        "lifecycle_oracle" => lifecycle_oracle,
        "lifecycle_fixture_sha256" => lifecycle_oracle["fixture_sha256"],
        "lifecycle_timeline_sha256" => lifecycle_oracle["timeline_sha256"],
        "oracle_difference_count" => oracle_difference_count,
        "failure_injection_count" => sigkill_matrix.length,
        "live_leak_count" => live + sigkill_matrix.sum { |entry| entry.fetch("dead_residual_count", 1) },
        "orphan_count" => sigkill_matrix.sum { |entry| Array(entry.dig("recovery", "errors")).length },
        "measurement_level" => l3_available ? "L3" : "L2",
        "measurement_source" => "production_native_lifecycle",
        "formal_claims" => ["RuntimeLifecycle"],
        "sigkill_matrix" => sigkill_matrix,
        "inventory_measurement" => inventory_measurement,
        "subresource_e2e" => subresource_e2e,
        "subresource_e2e_sha256" => subresource_e2e_sha256,
        "apply_lifecycle_native_flow" => apply_lifecycle_native_flow,
        "resource_kinds" => inventory_measurement.fetch("resource_kinds"),
        "l3_available" => l3_available,
        "passed" => l3_available && matrix_passed && subresources_passed && lifecycle_oracle["executed"] == true && oracle_difference_count.zero? && live.zero? &&
                     sigkill_matrix.all? { |entry| entry["dead_residual_count"] == 0 } && errors.empty?,
        "errors" => errors
      }
    end
  end
end

M2ProbeSupport.run_probe("m2_pod_lifecycle_trace", "m2-lifecycle-probe") do |_current, _input|
  M2LifecycleProbe.run(_input)
end
