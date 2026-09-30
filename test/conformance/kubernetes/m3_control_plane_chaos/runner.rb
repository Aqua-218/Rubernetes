#!/usr/bin/env ruby
# frozen_string_literal: true

# External M3 control-plane chaos harness.
#
# This runner is intentionally separate from the milestone probes. It owns the
# actual process boundary: a shared worker-restart API/store, two controller-manager
# processes or two scheduler processes, lease observation, SIGKILL/restart, and
# the project-owned watch/effect fault controls. The API server is deliberately
# kept alive while workers are killed; M5 disk-durable Raft/API-server HA is not
# part of this M3 proof.

require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "securerandom"
require "shellwords"
require "socket"
require "tempfile"
require "time"
require "yaml"

module M3ControlPlaneChaosRunner
  ROOT = File.expand_path("../../../..", __dir__).freeze
  RUNNER_PATH = File.expand_path(__FILE__).freeze
  require File.join(ROOT, "lib", "rubernetes", "controller", "effect_journal")
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  BLOCKER = "M3 external-process evidence is blocked: no worker-restart shared API/store with replayable watch history, compare-and-swap leases, and effect IDs is configured; M3 requires the shared API/store process to survive worker SIGKILL, but does not require M5 disk-durable Raft or API-server HA. Provide a project-owned shared API/store or set RUBERNETES_M3_DURABLE_API_COMMAND, RUBERNETES_M3_DURABLE_API_ENDPOINT, and RUBERNETES_M3_DURABLE_API_CAPABILITIES before running the controller/scheduler chaos harness"

  BUILT_IN_CAPABILITIES = {
    "backend" => "project_owned_apiserver_memorystore",
    "project_owned" => true,
    "capability_scope" => "worker_restart",
    "worker_restart_shared_api" => true,
    "worker_restart_shared_store" => true,
    "worker_restart_durable" => true,
    "watch_replay" => true,
    "lease_cas" => true,
    "effect_ids" => true,
    "event_injection" => true,
    "effect_control" => true,
    "m5_disk_durable" => false,
    "m5_api_ha" => false
  }.freeze

  REQUIRED_CAPABILITIES = %w[
    worker_restart_shared_api worker_restart_shared_store watch_replay lease_cas effect_ids
  ].freeze
  REQUIRED_REQUEST_KEYS = %w[schema_version suite scenario components].freeze
  REQUIRED_COMPONENTS = %w[controller-manager scheduler].freeze
  FORBIDDEN_EVIDENCE_OVERRIDES = %w[
    RUBERNETES_M3_DURABLE_API_COMMAND RUBERNETES_M3_DURABLE_API_ENDPOINT
    RUBERNETES_M3_DURABLE_API_CAPABILITIES RUBERNETES_M3_CONTROLLER_MANAGER_COMMAND
    RUBERNETES_M3_SCHEDULER_COMMAND RUBERNETES_M3_WATCH_CHAOS_COMMAND
    RUBERNETES_M3_EFFECT_CHAOS_COMMAND RUBERNETES_M3_PROCESS_CHAOS_COMMAND
  ].freeze
  LEASE_NAMES = {
    "controller-manager" => "m3-controller-manager",
    "scheduler" => "m3-scheduler"
  }.freeze
  API_VERSIONS = {
    "Deployment" => "apps/v1",
    "ReplicaSet" => "apps/v1",
    "Pod" => "v1",
    "Node" => "v1",
    "Namespace" => "v1",
    "Lease" => "coordination.k8s.io/v1"
  }.freeze
  REQUIRED_QUEUE_PROPERTIES = %w[
    duplicate_suppression out_of_order_delivery watch_reconnect resync
  ].freeze
  REQUIRED_WATCH_COUNTERS = %w[
    duplicate_loss_count out_of_order_count reconnect_loss_count resync_loss_count
  ].freeze
  REQUIRED_EFFECT_COUNTERS = %w[
    duplicate_side_effect_count stale_side_effect_count double_side_effect_count
  ].freeze

  module_function

  def canonical_value(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_value(value.fetch(source))
      end
    when Array
      value.map { |child| canonical_value(child) }
    when Time
      value.utc.iso8601(6)
    else
      value
    end
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical_value(value)))
  end

  def valid_digest?(value)
    value.is_a?(String) && value.match?(SHA256_PATTERN)
  end

  def iso8601_now
    Time.now.utc.iso8601(6)
  end

  def monotonic_time
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def parse_request
    request = JSON.parse($stdin.read, max_nesting: 512)
    raise ArgumentError, "M3 chaos request must be an object" unless request.is_a?(Hash)

    missing = REQUIRED_REQUEST_KEYS.reject { |key| request.key?(key) }
    raise ArgumentError, "M3 chaos request is missing #{missing.join(", ")}" unless missing.empty?
    raise ArgumentError, "M3 chaos request schema_version must be 1" unless request["schema_version"] == 1
    raise ArgumentError, "M3 chaos request components are incomplete" unless Array(request["components"]).sort == REQUIRED_COMPONENTS.sort

    request
  end

  def capabilities
    path = ENV["RUBERNETES_M3_DURABLE_API_CAPABILITIES"].to_s
    return BUILT_IN_CAPABILITIES.dup if path.empty?
    return nil unless File.file?(path)

    document = JSON.parse(File.binread(path), max_nesting: 128)
    return nil unless document.is_a?(Hash)

    document
  rescue Errno::ENOENT, Errno::EACCES, JSON::ParserError
    nil
  end

  def capability_errors(document, request = nil)
    return [BLOCKER] unless document.is_a?(Hash)

    external_values = %w[
      RUBERNETES_M3_DURABLE_API_COMMAND
      RUBERNETES_M3_DURABLE_API_ENDPOINT
      RUBERNETES_M3_DURABLE_API_CAPABILITIES
    ].map { |key| ENV[key].to_s.strip }
    external_requested = external_values.any? { |value| !value.empty? }
    return [BLOCKER] if FORBIDDEN_EVIDENCE_OVERRIDES.any? { |key| !ENV[key].to_s.strip.empty? }
    return [BLOCKER] if external_requested && external_values.any?(&:empty?)

    missing = REQUIRED_CAPABILITIES.reject { |key| document[key] == true }
    watch_required = request.is_a?(Hash) && request["scenario"] == "watch-queue-chaos"
    missing << "event_injection" if watch_required && document["event_injection"] != true
    missing << "effect_control" if document["effect_control"] != true
    return [] if missing.empty?

    [BLOCKER]
  end

  def external_runner_provenance(request)
    {
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "test/conformance/kubernetes/m3_control_plane_chaos/runner.rb",
      "runner_sha256" => Digest::SHA256.file(RUNNER_PATH).hexdigest,
      "command" => [RbConfig.ruby, RUNNER_PATH],
      "source" => {"root" => ROOT, "runner_source" => RUNNER_PATH,
                   "runner_sha256" => Digest::SHA256.file(RUNNER_PATH).hexdigest},
      "process_id" => Process.pid,
      "request_sha256" => digest(request),
      "started_at" => iso8601_now
    }
  end

  def blocked_report(request)
    provenance = external_runner_provenance(request)
    provenance["finished_at"] = iso8601_now
    provenance["provenance_sha256"] = digest(provenance)
    {
      "schema_version" => 1,
      "suite" => request["suite"],
      "scenario" => request["scenario"],
      "status" => "BLOCKED",
      "executed" => false,
      "passed" => false,
      "blocker" => BLOCKER,
      "runner" => provenance,
      "processes" => [],
      "events" => [],
      "trace" => [],
      "component_runs" => [],
      "lease_observations" => [],
      "effect_ids" => [],
      "raw_trace_sha256" => nil,
      "canonical_trace_sha256" => nil,
      "errors" => [BLOCKER]
    }
  end

  class ProcessSupervisor
    attr_reader :records

    def initialize(directory:)
      @directory = directory
      @records = []
      @handles = {}
      FileUtils.mkdir_p(File.join(directory, "logs"))
    end

    def spawn(role:, identity:, command:, environment: {})
      argv = Array(command).map(&:to_s)
      raise ArgumentError, "#{role} command is empty" if argv.empty?

      log_path = File.join(@directory, "logs", "#{role}-#{identity}.log")
      log_io = File.open(log_path, "ab")
      pid = Process.spawn(environment, *argv, out: log_io, err: log_io)
      log_io.close
      record = {
        "role" => role,
        "identity" => identity,
        "pid" => pid,
        "start_time" => proc_start_time(pid),
        "command" => argv,
        "namespace" => namespace_snapshot(pid),
        "log_path" => log_path,
        "spawned_at" => M3ControlPlaneChaosRunner.iso8601_now,
        "observed_exit" => false
      }
      record["generation"] = generation_for(record)
      @records << record
      @handles[record.object_id] = pid
      record
    rescue SystemCallError => error
      raise "could not spawn #{role}/#{identity}: #{error.message}"
    end

    def kill(record, signal: "KILL", timeout: 10.0)
      pid = Integer(record.fetch("pid"))
      current_start_time = proc_start_time(pid)
      raise "pid #{pid} start time changed before #{signal}" unless current_start_time == record.fetch("start_time")

      Process.kill(signal, pid)
      wait(record, timeout: timeout)
    rescue Errno::ESRCH
      record["observed_exit"] = true
      record["exit_status"] ||= 1
      record
    end

    def wait(record, timeout: 10.0)
      deadline = M3ControlPlaneChaosRunner.monotonic_time + Float(timeout)
      status = nil
      loop do
        status = Process.waitpid(record.fetch("pid"), Process::WNOHANG)
        break if status
        break if M3ControlPlaneChaosRunner.monotonic_time >= deadline

        sleep 0.02
      end
      unless status
        record["observed_exit"] = false
        return false
      end

      process_status = $?
      record["observed_exit"] = true
      record["exit_status"] = if process_status.exited?
                                process_status.exitstatus
                              elsif process_status.signaled?
                                128 + process_status.termsig
                              else
                                1
                              end
      record["exit_signal"] = process_status.termsig if process_status.signaled?
      true
    rescue Errno::ECHILD
      record["observed_exit"] = true
      record["exit_status"] ||= 1
      true
    end

    # A PID is not a process identity. Verify both the kernel start time and
    # the generation captured at spawn so a recycled PID cannot satisfy a
    # leader-recovery observation.
    def alive?(record)
      pid = Integer(record.fetch("pid"))
      return false unless Process.kill(0, pid)

      current_start_time = proc_start_time(pid)
      return false unless current_start_time == Integer(record.fetch("start_time"))

      expected_generation = record.fetch("generation")
      generation_for(record.merge("start_time" => current_start_time)) == expected_generation
    rescue Errno::ESRCH, Errno::EPERM, Errno::ENOENT, Errno::EACCES, IndexError, ArgumentError
      false
    end

    def stop_all
      stop_records(@records)
    end

    def stop_role(role)
      stop_records(@records.select { |record| record["role"] == role })
    end

    private

    def stop_records(records)
      Array(records).reverse_each do |record|
        next if record["observed_exit"]

        begin
          Process.kill("TERM", record.fetch("pid"))
        rescue Errno::ESRCH
          record["observed_exit"] = true
          record["exit_status"] ||= 1
          next
        end
        wait(record, timeout: 5.0)
        next if record["observed_exit"]

        begin
          Process.kill("KILL", record.fetch("pid"))
        rescue Errno::ESRCH
          record["observed_exit"] = true
          record["exit_status"] ||= 1
        end
        wait(record, timeout: 5.0) unless record["observed_exit"]
      end
    end

    def proc_start_time(pid)
      text = File.read("/proc/#{pid}/stat")
      tail = text.rpartition(") ").last
      fields = tail.split(" ")
      value = fields.fetch(19)
      Integer(value)
    rescue Errno::ENOENT, Errno::EACCES, IndexError, ArgumentError
      raise "could not read kernel start time for pid #{pid}"
    end

    def generation_for(record)
      [record.fetch("identity"), record.fetch("pid"), record.fetch("start_time")].join(":")
    end

    def namespace_snapshot(pid)
      %w[pid mnt net ipc uts user].each_with_object({}) do |name, result|
        result[name] = File.readlink("/proc/#{pid}/ns/#{name}")
      rescue Errno::ENOENT, Errno::EACCES
        result[name] = nil
      end
    end
  end

  class Harness
    attr_reader :request, :capabilities, :directory

    def initialize(request, capabilities)
      @request = request
      @capabilities = capabilities
      @directory = Dir.mktmpdir("rubernetes-m3-chaos-")
      @effect_journal_path = File.join(@directory, "effect-journal.jsonl")
      @supervisor = ProcessSupervisor.new(directory: @directory)
      @raw_traces = []
      @lease_observations = []
      @effect_ids = []
      @events = []
      @properties = []
      @component_runs = []
      @api = nil
      @api_record = nil
      @api_endpoint = nil
      @api_config_path = nil
      @api_survival_observations = []
      @runner_provenance = M3ControlPlaneChaosRunner.external_runner_provenance(@request)
      @runner_provenance["storage_contract"] = storage_contract
    end

    def run
      start_shared_api!
      @request.fetch("components").each do |component|
        @component_runs << run_component(component)
        # Keep the shared API/store alive, but do not let a completed
        # controller-manager run saturate it while the scheduler run performs
        # 410 compaction and reconnect faults (or vice versa).
        @supervisor.stop_role(component)
      end
      @supervisor.stop_all
      journal = effect_journal_report
      @runner_provenance["storage_contract"] = storage_contract
      pass = @component_runs.all? { |run| run["passed"] == true } && journal.fetch("duplicate_effect_count") == 0
      trace = build_trace
      response = {
        "schema_version" => 1,
        "suite" => @request["suite"],
        "scenario" => @request["scenario"],
        "status" => pass ? "PASS" : "INCOMPLETE",
        "executed" => true,
        "passed" => pass,
        "runner" => @runner_provenance,
        "storage_contract" => storage_contract,
        "shared_api_survival_observations" => @api_survival_observations,
        "processes" => process_report,
        "events" => @events,
        "properties" => aggregate_properties,
        "trace" => trace,
        "component_runs" => @component_runs,
        "lease_observations" => @lease_observations,
        "effect_ids" => @effect_ids,
        "effect_journal" => journal,
        "api_mutations" => journal.fetch("api_mutations"),
        "api_events" => journal.fetch("api_events"),
        "provider_events" => journal.fetch("provider_events"),
        "journal_duplicate_side_effect_count" => journal.fetch("duplicate_effect_count"),
        "double_side_effect_count" => @component_runs.sum { |run| run.fetch("double_side_effect_count") },
        "duplicate_side_effect_count" => @component_runs.sum { |run| run.fetch("duplicate_side_effect_count") },
        "stale_side_effect_count" => @component_runs.sum { |run| run.fetch("stale_side_effect_count") },
        "duplicate_loss_count" => @component_runs.sum { |run| run.fetch("duplicate_loss_count", 0) },
        "out_of_order_count" => @component_runs.sum { |run| run.fetch("out_of_order_count", 0) },
        "reconnect_loss_count" => @component_runs.sum { |run| run.fetch("reconnect_loss_count", 0) },
        "resync_loss_count" => @component_runs.sum { |run| run.fetch("resync_loss_count", 0) },
        "quorum_recovered" => @component_runs.all? { |run| run["quorum_recovered"] == true },
        "recovery_seconds" => @component_runs.map { |run| run.fetch("recovery_seconds") }.max,
        "raw_trace_sha256" => M3ControlPlaneChaosRunner.digest(@raw_traces),
        "canonical_trace_sha256" => M3ControlPlaneChaosRunner.digest(trace),
        "errors" => @component_runs.flat_map { |run| Array(run["errors"]) }
      }
      response["runner"]["finished_at"] = M3ControlPlaneChaosRunner.iso8601_now
      response["runner"]["provenance_sha256"] = M3ControlPlaneChaosRunner.digest(response["runner"])
      response
    rescue StandardError => error
      diagnostics = @supervisor.records.map do |record|
        log = begin
          File.binread(record.fetch("log_path"))
        rescue Errno::ENOENT, Errno::EACCES
          ""
        end
        {
          "role" => record["role"], "identity" => record["identity"],
          "pid" => record["pid"], "start_time" => record["start_time"],
          "alive" => process_alive?(record), "observed_exit" => record["observed_exit"],
          "exit_status" => record["exit_status"],
          "log_tail" => log.byteslice([log.bytesize - 4_000, 0].max, 4_000).to_s
        }
      end
      raise "#{error.class}: #{error.message}; process_diagnostics=#{JSON.generate(diagnostics)}"
    ensure
      @supervisor.stop_all
      FileUtils.remove_entry(@directory) if @directory && File.directory?(@directory)
    end

    private

    def process_report
      @supervisor.records.map do |record|
        log = begin
          File.binread(record.fetch("log_path"))
        rescue Errno::ENOENT, Errno::EACCES
          ""
        end
        record.merge(
          "alive" => process_alive?(record),
          "log_tail" => log.byteslice([log.bytesize - 4_000, 0].max, 4_000).to_s,
          "log_sha256" => Digest::SHA256.hexdigest(log)
        )
      end
    end

    def storage_contract
      {
        "backend" => @capabilities.fetch("backend", "external_shared_api_store"),
        "capability_scope" => @capabilities.fetch("capability_scope", "worker_restart"),
        "worker_restart_durable" => @capabilities.fetch("worker_restart_durable", true),
        "m5_disk_durable" => @capabilities.fetch("m5_disk_durable", false),
        "m5_api_ha" => @capabilities.fetch("m5_api_ha", false),
        "shared_api_process_survives_worker_kill" => if @api_survival_observations.empty?
                                                       nil
                                                     else
                                                       @api_survival_observations.all? { |observation| observation["alive"] == true }
                                                     end,
        "worker_process_count_per_component" => 2
      }
    end

    def start_shared_api!
      external_values = %w[
        RUBERNETES_M3_DURABLE_API_COMMAND
        RUBERNETES_M3_DURABLE_API_ENDPOINT
        RUBERNETES_M3_DURABLE_API_CAPABILITIES
      ].map { |key| ENV[key].to_s.strip }
      external_requested = external_values.any? { |value| !value.empty? }
      command, endpoint, capability_path = if external_requested
                                             raise ArgumentError, BLOCKER if external_values.any?(&:empty?)

                                             [Shellwords.split(external_values.fetch(0)), external_values.fetch(1),
                                              external_values.fetch(2)]
                                           else
                                             [built_in_api_command, @api_endpoint, nil]
                                           end
      raise ArgumentError, "shared API command is empty" if command.empty?
      raise ArgumentError, "shared API endpoint must be an absolute HTTP(S) URL" unless endpoint.match?(%r{\Ahttps?://[^\s]+\z})

      @api_endpoint = endpoint

      environment = {
        "RUBERNETES_M3_API_ENDPOINT" => endpoint,
        "RUBERNETES_M3_RUN_DIRECTORY" => @directory
      }
      environment["RUBERNETES_M3_CAPABILITIES"] = capability_path if capability_path
      identity = external_requested ? "external" : "project-owned-apiserver"
      @api_record = @supervisor.spawn(role: "shared-api", identity: identity, command: command, environment: environment)
      @api = Rubernetes::Client::KubernetesClient.new(server: endpoint)
      wait_until(timeout: 30.0) do
        response = @api.raw("GET", "/healthz")
        response.respond_to?(:success?) && response.success?
      rescue Rubernetes::Client::Error, Rubernetes::Client::TransportError
        false
      end
      raise "shared API did not become ready" unless @api_record && process_alive?(@api_record)

      @runner_provenance["storage_contract"] = storage_contract
    end

    def built_in_api_command
      port_socket = TCPServer.new("127.0.0.1", 0)
      port = port_socket.addr.fetch(1)
      port_socket.close
      @api_endpoint = "http://127.0.0.1:#{port}"
      @api_config_path = File.join(@directory, "shared-api.yml")
      document = {
        "version" => 1,
        "logging" => {"level" => "info"},
        "processes" => {
          "rubernetes-apiserver" => {
            "bind_address" => "127.0.0.1",
            "port" => port,
            "max_body_bytes" => 3_145_728,
            # Keep enough history for normal worker reconnects while making a
            # compacted 410 boundary reachable by the watch control.
            "watch_history_limit" => 128
          }
        }
      }
      File.binwrite(@api_config_path, Psych.dump(document))
      [RbConfig.ruby, "-I", File.join(ROOT, "lib"), File.join(ROOT, "exe", "rubernetes-apiserver"), "--config", @api_config_path]
    end

    def run_component(component)
      namespace = "m3-chaos-#{Process.pid}-#{component.tr("-", "")}"
      names = {
        "namespace" => namespace,
        "lease" => LEASE_NAMES.fetch(component),
        "fixture" => "m3-#{component}-#{Process.pid}"
      }
      prepare_fixture!(component, names)
      initial = spawn_pair(component, names)
      wait_for_lease!(names.fetch("lease"), namespace: "kube-system")
      acquire_event = observation_event("acquire", component, initial, names)
      @events << acquire_event
      @raw_traces << acquire_event

      watch_result = nil
      if @request.fetch("scenario") == "watch-queue-chaos"
        watch_result = invoke_watch_faults(component, names)
        @raw_traces << watch_result
        record_watch_events!(watch_result, component)
        Array(watch_result["properties"]).each do |property|
          next unless property.is_a?(Hash)

          @properties << property.merge("component" => component)
          @events << observation_event(
            property.fetch("id", property.fetch("property", "unknown")), component, initial, names,
            passed: property["passed"] == true,
            extra: {"property" => property, "watch_trace_sha256" => watch_result["raw_trace_sha256"]}
          )
        end
      end

      leader = wait_for_leader(initial, lease_name: names.fetch("lease"))
      raise "#{component} did not elect a leader" unless leader

      old_lease = latest_lease_object(names.fetch("lease"))
      raise "#{component} leader lease observation is missing before kill" unless old_lease.is_a?(Hash)

      before = control_effect(component, phase: "before_effect", leader: leader, names: names)
      # Measure convergence from the actual kill boundary, not from the
      # preceding effect-controller RPC.
      kill_started = M3ControlPlaneChaosRunner.monotonic_time
      killed = @supervisor.kill(leader, signal: "KILL")
      observe_shared_api!(phase: "after_#{component}_worker_sigkill")
      process_kill_event = observation_event("process_kill", component, [leader], names,
                                             passed: killed && leader["observed_exit"] == true &&
                                                     leader["exit_signal"] == Signal.list.fetch("KILL"),
                                             extra: {"killed" => killed, "signal" => "SIGKILL", "phase" => "before_effect"})
      @events << process_kill_event
      @raw_traces << before
      @raw_traces << process_kill_event
      after = control_effect(component, phase: "after_effect", leader: leader, names: names)
      @raw_traces << after

      leader_lost = wait_for_leader_loss(initial, old_identity: leader.fetch("identity"),
                                                  lease_name: names.fetch("lease"))
      loss_event = observation_event("loss", component, [leader], names,
                                     passed: leader_lost,
                                     extra: {"old_leader" => leader.fetch("identity"), "lease_resource_version" => latest_lease_rv(names.fetch("lease"))})
      @events << loss_event
      # Observe the fence while the killed identity is still absent. Restarting
      # the same logical identity before this check would make an old PID and a
      # new PID indistinguishable in the lease holder field.
      fence = control_effect(component, phase: "fence_check", leader: leader, names: names)
      @raw_traces << fence
      restarted = spawn_one(component, leader.fetch("identity"), names)
      recovered_at = wait_for_recovery(initial, restarted, lease_name: names.fetch("lease"), started_at: kill_started,
                                                           old_identity: leader.fetch("identity"), old_lease: old_lease)
      # The recovery observation identifies the process generation that
      # actually holds the Lease. It may be the surviving peer (the restarted
      # process is allowed to remain a follower), so the post-recovery effect
      # must be attributed to that measured holder rather than to a logical
      # identity guessed from the restart request.
      recovery_identity = recovered_at["holder_identity"].to_s
      recovery_leader = (initial + [restarted]).find { |record| record.fetch("identity") == recovery_identity }
      raise "recovery Lease holder has no live process record" unless recovery_leader

      recovery = control_effect(component, phase: "after_recovery", leader: recovery_leader, names: names)
      @raw_traces << recovery
      fence_event = observation_event("fence", component, [leader], names,
                                      passed: leader.fetch("observed_exit") &&
                                              Integer(fence.fetch("stale_side_effect_count")) == 0 &&
                                              fence.fetch("passed") == true,
                                      extra: {"stale_process_exit" => leader.fetch("observed_exit"), "effect_ids" => Array(fence["effect_ids"])})
      recovery_event = observation_event("recovery", component, [restarted], names,
                                         passed: recovered_at.fetch("recovered") &&
                                                 recovered_at.fetch("seconds") <= 60.0 &&
                                                 recovery.fetch("passed") == true,
                                         extra: {"recovery_seconds" => recovered_at.fetch("seconds"),
                                                 "recovery_observation" => recovered_at,
                                                 "effect_ids" => Array(recovery["effect_ids"])})
      @events.concat([fence_event, recovery_event])
      component_effect_ids = Array(before["effect_ids"]) + Array(after["effect_ids"]) +
                             Array(fence["effect_ids"]) + Array(recovery["effect_ids"])
      @effect_ids.concat(component_effect_ids)

      duplicate_ids = duplicate_count(component_effect_ids) +
                      [before, after, fence, recovery].sum { |effect| Integer(effect.fetch("duplicate_side_effect_count")) }
      stale_count = [before, after, fence, recovery].sum { |effect| Integer(effect.fetch("stale_side_effect_count")) }
      double_count = [before, after, fence, recovery].sum { |effect| Integer(effect.fetch("double_side_effect_count")) }
      watch_loss_free = watch_result.nil? || REQUIRED_WATCH_COUNTERS.all? do |key|
        Integer(watch_result.fetch(key)) == 0
      end
      component_events = [acquire_event, process_kill_event, loss_event, fence_event, recovery_event]
      passed = component_events.all? { |event| event["passed"] == true } &&
               [before, after, fence, recovery].all? { |effect| effect["passed"] == true } &&
               duplicate_ids.zero? && stale_count.zero? && double_count.zero? &&
               recovered_at.fetch("seconds") <= 60.0 &&
               watch_loss_free &&
               (watch_result.nil? || Array(watch_result["properties"]).all? { |property| property["passed"] == true })
      {
        "component" => component,
        "namespace" => namespace,
        "lease_name" => names.fetch("lease"),
        "lease_resource_versions" => @lease_observations.filter_map do |observation|
          observation["resource_version"] if observation["component"] == component
        end.uniq,
        "process_identities" => [initial, restarted].flatten.map { |record| record.fetch("identity") },
        "passed" => passed,
        "quorum_recovered" => recovered_at.fetch("recovered"),
        "recovery_seconds" => recovered_at.fetch("seconds"),
        "recovery_observation" => recovered_at,
        "duplicate_side_effect_count" => duplicate_ids,
        "double_side_effect_count" => double_count,
        "stale_side_effect_count" => stale_count,
        "duplicate_loss_count" => Integer(watch_result&.fetch("duplicate_loss_count", 0) || 0),
        "out_of_order_count" => Integer(watch_result&.fetch("out_of_order_count", 0) || 0),
        "reconnect_loss_count" => Integer(watch_result&.fetch("reconnect_loss_count", 0) || 0),
        "resync_loss_count" => Integer(watch_result&.fetch("resync_loss_count", 0) || 0),
        "effect_ids" => component_effect_ids,
        "properties" => Array(watch_result&.fetch("properties", [])),
        "errors" => passed ? [] : ["#{component} external process chaos did not satisfy fencing and recovery invariants"]
      }
    end

    def record_watch_events!(watch_result, component)
      Array(watch_result.fetch("events")).each do |event|
        id = (event["id"] || event["event"] || event["fault"]).to_s
        observation = event.fetch("observation").merge("component" => component)
        @events << {
          "id" => id,
          "event" => id,
          "passed" => event["passed"] == true,
          "attempt_count" => event.fetch("attempt_count"),
          "observed_at" => event.fetch("observed_at"),
          "observation" => observation
        }
      end
    end

    def prepare_fixture!(component, names)
      create_resource(
        "Namespace",
        {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => names.fetch("namespace")}},
        api_version: "v1"
      )
      if component == "controller-manager"
        create_resource(
          "Deployment",
          {
            "apiVersion" => "apps/v1", "kind" => "Deployment",
            "metadata" => {"name" => names.fetch("fixture"), "namespace" => names.fetch("namespace")},
            "spec" => {
              "replicas" => 1,
              "selector" => {"matchLabels" => {"app" => names.fetch("fixture")}},
              "template" => {"metadata" => {"labels" => {"app" => names.fetch("fixture")}},
                             "spec" => {"containers" => [{"name" => "app", "image" => "example/app:1"}]}}
            }
          },
          namespace: names.fetch("namespace"), api_version: "apps/v1"
        )
      else
        create_resource(
          "Node",
          {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => names.fetch("fixture")},
           "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}], "allocatable" => {"cpu" => "4"}}},
          api_version: "v1"
        )
        create_resource(
          "Pod",
          {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => names.fetch("fixture"), "namespace" => names.fetch("namespace")},
           "spec" => {"schedulerName" => "default-scheduler", "containers" => [{"name" => "app", "image" => "example/app:1"}]}},
          namespace: names.fetch("namespace"), api_version: "v1"
        )
      end
    end

    def create_resource(kind, object, namespace: nil, api_version: API_VERSIONS.fetch(kind))
      @api.create(object, namespace: namespace, api_version: api_version)
    rescue Rubernetes::Client::APIError => error
      raise "fixture #{kind} could not be created: HTTP #{error.status}"
    end

    def spawn_pair(component, names)
      %w[a b].map { |suffix| spawn_one(component, "m3-#{component}-#{suffix}", names) }
    end

    def spawn_one(component, identity, names)
      config_path = write_config(component, identity, names)
      env_name = component == "controller-manager" ? "RUBERNETES_M3_CONTROLLER_MANAGER_COMMAND" : "RUBERNETES_M3_SCHEDULER_COMMAND"
      command = configured_command(env_name, default_executable(component))
      command += ["--config", config_path] unless command.include?("--config")
      @supervisor.spawn(
        role: component,
        identity: identity,
        command: command,
        environment: {"RUBERNETES_M3_PROCESS_ROLE" => component, "RUBERNETES_M3_PROCESS_IDENTITY" => identity,
                      "RUBERNETES_M3_CONFIG" => config_path,
                      "RUBERNETES_M3_API_ENDPOINT" => @api_endpoint,
                      "RUBERNETES_M3_RUN_DIRECTORY" => @directory,
                      "RUBERNETES_M3_EFFECT_JOURNAL" => @effect_journal_path}
      )
    end

    def default_executable(component)
      if component == "controller-manager"
        [RbConfig.ruby, File.join(ROOT, "test", "conformance", "kubernetes", "m3_control_plane_chaos", "controller_manager_worker.rb")]
      else
        [RbConfig.ruby, "-I", File.join(ROOT, "lib"), File.join(ROOT, "exe", "rubernetes-scheduler")]
      end
    end

    def configured_command(env_name, default)
      value = ENV[env_name].to_s.strip
      raise "#{env_name} command overrides are forbidden in M3 evidence mode" unless value.empty?

      default
    end

    def write_config(component, identity, _names)
      require "yaml"
      path = File.join(@directory, "#{component}-#{identity}.yml")
      process = {
        "api_server" => @api_endpoint,
        "identity" => identity,
        "sync" => {"interval_seconds" => component == "scheduler" ? 0.05 : 0.1}
      }
      if component == "controller-manager"
        # The chaos fixture mutates a Deployment and observes its ReplicaSet.
        # Restrict the worker to that real production controller slice so
        # feature-gated APIs (for example ClusterTrustBundle) that the shared
        # API intentionally does not serve cannot terminate an unrelated
        # leader-election proof.
        process["controllers"] = %w[deployment-controller replicaset-controller]
      end
      process["lease"] = {
        "namespace" => "kube-system",
        "name" => LEASE_NAMES.fetch(component),
        "lease_duration_seconds" => 5,
        "renew_deadline_seconds" => 3,
        "retry_period_seconds" => 0.1
      }
      document = {"version" => 1, "logging" => {"level" => "info"}, "processes" => {component_name(component) => process}}
      File.binwrite(path, Psych.dump(document))
      path
    end

    def component_name(component)
      "rubernetes-#{component}"
    end

    def wait_for_lease!(name, namespace:)
      wait_until(timeout: 30.0) { latest_lease(name, namespace: namespace) }
    end

    def latest_lease(name, namespace: "kube-system")
      latest_lease_object(name, namespace: namespace)
    end

    def latest_lease_rv(name, namespace: "kube-system")
      object = latest_lease_object(name, namespace: namespace)
      object && object.dig("metadata", "resourceVersion")
    end

    def latest_lease_object(name, namespace: "kube-system")
      object = @api.get("leases", name, namespace: namespace, api_version: "coordination.k8s.io/v1")
      observation = {
        "component" => lease_component(name),
        "namespace" => namespace,
        "name" => name,
        "resource_version" => object.dig("metadata", "resourceVersion").to_s,
        "holder_identity" => object.dig("spec", "holderIdentity").to_s,
        "renew_time" => object.dig("spec", "renewTime"),
        "observed_at" => M3ControlPlaneChaosRunner.iso8601_now
      }
      @lease_observations << observation
      object
    rescue Rubernetes::Client::APIError => error
      return nil if error.status == 404

      raise
    end

    def lease_component(name)
      LEASE_NAMES.key(name) || "unknown"
    end

    def wait_for_leader(records, lease_name:)
      wait_until(timeout: 30.0) do
        object = latest_lease_object(lease_name)
        holder = object&.dig("spec", "holderIdentity").to_s
        records.find { |record| record.fetch("identity") == holder && process_alive?(record) }
      end
    end

    def wait_for_leader_loss(records, old_identity:, lease_name:)
      !!wait_until(timeout: 30.0) do
        object = latest_lease_object(lease_name)
        holder = object&.dig("spec", "holderIdentity").to_s
        next false if holder.empty? || holder == old_identity

        records.any? do |record|
          record.fetch("identity") == holder && process_alive?(record)
        end
      end
    end

    def wait_for_recovery(initial, restarted, lease_name:, started_at:, old_identity:, old_lease:)
      old_holder = old_lease.dig("spec", "holderIdentity").to_s
      old_resource_version = old_lease.dig("metadata", "resourceVersion").to_s
      old_renew_time = parse_lease_time(old_lease.dig("spec", "renewTime"))
      old_record = initial.find { |record| record.fetch("identity") == old_identity }
      old_generation = old_record && old_record["generation"]
      observation = nil
      recovered = wait_until(timeout: 60.0) do
        next false unless process_alive?(restarted)

        object = latest_lease_object(lease_name)
        holder = object&.dig("spec", "holderIdentity").to_s
        next false if holder.empty?

        holder_record = if restarted.fetch("identity") == holder
                          restarted
                        else
                          initial.find { |record| record.fetch("identity") == holder }
                        end
        next false unless holder_record && process_alive?(holder_record)

        current_resource_version = object.dig("metadata", "resourceVersion").to_s
        current_renew_time = parse_lease_time(object.dig("spec", "renewTime"))
        resource_version_changed = !old_resource_version.empty? && current_resource_version != old_resource_version
        renew_time_changed = if old_renew_time && current_renew_time
                               current_renew_time > old_renew_time
                             else
                               !current_renew_time.nil? && current_renew_time != old_renew_time
                             end
        generation_changed = holder_record["generation"].to_s != old_generation.to_s
        holder_transition = holder != old_holder || generation_changed
        next false unless resource_version_changed && renew_time_changed && holder_transition

        observation = {
          "old_holder_identity" => old_holder,
          "holder_identity" => holder,
          "old_process_generation" => old_generation,
          "process_generation" => holder_record["generation"],
          "restarted_process_alive" => process_alive?(restarted),
          "resource_version_before" => old_resource_version,
          "resource_version_after" => current_resource_version,
          "renew_time_before" => old_lease.dig("spec", "renewTime"),
          "renew_time_after" => object.dig("spec", "renewTime"),
          "resource_version_changed" => resource_version_changed,
          "renew_time_changed" => renew_time_changed,
          "holder_transition" => holder_transition,
          "generation_changed" => generation_changed,
          "observed_at" => M3ControlPlaneChaosRunner.iso8601_now
        }

        true
      end
      elapsed = M3ControlPlaneChaosRunner.monotonic_time - started_at
      # The Lease/process transition proof is reported flat next to the
      # timing fields; the M3 gate reads restarted_process_alive,
      # resource_version_before/after, renew_time_changed, holder_transition,
      # generation_changed and process_generation directly from this record.
      (observation || {}).merge(
        "recovered" => !!recovered,
        "seconds" => elapsed,
        "within_deadline" => elapsed <= 60.0
      )
    end

    def parse_lease_time(value)
      return nil if value.to_s.empty?

      Time.iso8601(value.to_s)
    rescue ArgumentError
      nil
    end

    def observation_event(id, component, records, names, passed: true, extra: {})
      lease = latest_lease_object(names.fetch("lease"))
      observation = {
        "component" => component,
        "processes" => records.map do |record|
          {"pid" => record.fetch("pid"), "start_time" => record.fetch("start_time"), "identity" => record.fetch("identity"),
           "alive" => process_alive?(record)}
        end,
        "namespace" => names.fetch("namespace"),
        "lease_name" => names.fetch("lease"),
        "lease_resource_version" => lease&.dig("metadata", "resourceVersion"),
        "lease_holder" => lease&.dig("spec", "holderIdentity"),
        "observed_at" => M3ControlPlaneChaosRunner.iso8601_now
      }.merge(extra)
      {"id" => id, "event" => id, "passed" => passed == true, "attempt_count" => 1, "observed_at" => observation.fetch("observed_at"),
       "observation" => observation}
    end

    def control_effect(component, phase:, leader:, names:)
      command = [RbConfig.ruby, File.join(ROOT, "test", "conformance", "kubernetes", "m3_control_plane_chaos", "effect_control.rb")]

      effect_type = case phase
                    when "before_effect", "after_recovery" then "reconcile"
                    when "after_effect" then "stale_reconcile"
                    else phase
                    end
      result = invoke_control(command, {
                                "schema_version" => 1,
                                "scenario" => @request.fetch("scenario"),
                                "component" => component,
                                "phase" => phase,
                                "leader" => leader,
                                "lease" => {"name" => names.fetch("lease"), "namespace" => "kube-system",
                                            "resource_version" => latest_lease_rv(names.fetch("lease"))},
                                "target" => effect_target(component, names),
                                "required_effect_ids" => true,
                                "reconcile_key" => effect_reconcile_key(component, names),
                                "effect_type" => effect_type
                              })
      validate_effect_result!(result, phase, payload: {
                                "component" => component,
                                "leader" => leader,
                                "reconcile_key" => effect_reconcile_key(component, names),
                                "effect_type" => effect_type
                              })
      result
    end

    def invoke_watch_faults(component, names)
      command = [RbConfig.ruby, File.join(ROOT, "test", "conformance", "kubernetes", "m3_control_plane_chaos", "watch_control.rb")]

      result = invoke_control(command, {
                                "schema_version" => 1,
                                "scenario" => @request.fetch("scenario"),
                                "component" => component,
                                "watch_faults" => @request.fetch("watch_faults"),
                                "lease" => {"name" => names.fetch("lease"), "namespace" => "kube-system"},
                                "target" => effect_target(component, names)
                              })
      validate_watch_result!(result)
      result
    end

    def effect_target(component, names)
      if component == "controller-manager"
        {"kind" => "Deployment", "api_version" => "apps/v1", "namespace" => names.fetch("namespace"), "name" => names.fetch("fixture")}
      else
        {"kind" => "Pod", "api_version" => "v1", "namespace" => names.fetch("namespace"), "name" => names.fetch("fixture")}
      end
    end

    def invoke_control(command, payload)
      raise ArgumentError, "external chaos control command is empty" if command.empty?

      started_at = M3ControlPlaneChaosRunner.iso8601_now
      environment = {
        "RUBERNETES_M3_API_ENDPOINT" => @api_endpoint,
        "RUBERNETES_M3_RUN_DIRECTORY" => @directory,
        "RUBERNETES_M3_CAPABILITY_SCOPE" => @capabilities.fetch("capability_scope", "worker_restart"),
        "RUBERNETES_M3_EFFECT_JOURNAL" => @effect_journal_path,
        "RUBERNETES_M3_PROCESS_ROLE" => payload.fetch("component", "chaos-control"),
        "RUBERNETES_M3_PROCESS_IDENTITY" => payload.dig("leader", "identity").to_s
      }
      stdout, stderr, status = Open3.capture3(environment, *command, stdin_data: JSON.generate(payload), chdir: ROOT)
      raw_sha256 = Digest::SHA256.hexdigest(stdout.to_s)
      unless status.success?
        raise "external chaos control failed: #{stderr.to_s.strip.empty? ? "exit status #{status.exitstatus || 1}" : stderr.to_s.strip}"
      end

      result = JSON.parse(stdout, max_nesting: 512)
      raise "external chaos control must return an object" unless result.is_a?(Hash)

      result["raw_trace_sha256"] ||= raw_sha256
      result["control_command"] ||= command
      result["started_at"] ||= started_at
      result["finished_at"] ||= M3ControlPlaneChaosRunner.iso8601_now
      result["effect_ids"] = Array(result["effect_ids"]).map(&:to_s).reject(&:empty?)
      if payload["required_effect_ids"] == true && result["effect_ids"].empty?
        raise "external chaos control returned no effect IDs for #{payload.fetch("phase")}"
      end

      @raw_traces << {"payload" => payload, "result" => result, "raw_sha256" => raw_sha256}
      result
    rescue JSON::ParserError => error
      raise "external chaos control returned invalid JSON: #{error.message}"
    end

    def validate_effect_result!(result, phase, payload: {})
      REQUIRED_EFFECT_COUNTERS.each do |key|
        value = result[key]
        raise "external effect control #{phase} must return non-negative integer #{key}" unless value.is_a?(Integer) && value >= 0
      end
      raise "external effect control #{phase} did not pass" unless result["passed"] == true
      raise "external effect control #{phase} must return deterministic effect identity" unless
        result["effect_key"].to_s == [payload.fetch("component"), payload.fetch("reconcile_key"), payload.fetch("effect_type")].join("|") &&
        result["reconcile_key"].to_s == payload.fetch("reconcile_key") &&
        result["effect_type"].to_s == payload.fetch("effect_type") &&
        result["generation"].to_s == payload.dig("leader", "generation").to_s &&
        result["effect_ids"].all? { |effect_id| effect_id.to_s.include?(payload.dig("leader", "generation").to_s) }

      return unless phase == "after_effect"
      return if result["stale_rejected"] == true && result["mutation_count"] == 0

      raise "external effect control after_effect must reject the stale leader"
    end

    def validate_watch_result!(result)
      expected_faults = Array(@request["watch_faults"]).map(&:to_s).uniq
      actual_faults = Array(result["faults"] || result["watch_faults"]).map(&:to_s).uniq
      missing_faults = expected_faults - actual_faults
      raise "external watch control omitted faults: #{missing_faults.join(", ")}" unless missing_faults.empty?

      REQUIRED_WATCH_COUNTERS.each do |key|
        value = result[key]
        raise "external watch control must return non-negative integer #{key}" unless value.is_a?(Integer) && value >= 0
      end
      properties = Array(result["properties"])
      property_ids = properties.filter_map do |property|
        property.is_a?(Hash) ? (property["id"] || property["property"]) : nil
      end.map(&:to_s)
      unless property_ids.sort == REQUIRED_QUEUE_PROPERTIES.sort &&
             property_ids.uniq.length == REQUIRED_QUEUE_PROPERTIES.length
        raise "external watch control must return the four required queue properties"
      end

      properties.each_with_index do |property, index|
        unless property.is_a?(Hash) && property["passed"] == true && property["attempt_count"] == 1 &&
               property["measurement_source"] == "production_module"
          raise "external watch control property #{index} is not a single passing production observation"
        end
      end
      events = result["events"]
      unless events.is_a?(Array) && expected_faults.all? do |fault|
               events.any? do |event|
                 event.is_a?(Hash) && (event["id"] || event["event"] || event["fault"]).to_s == fault
               end
             end
        raise "external watch control must return structured events for every requested fault"
      end

      events.each_with_index do |event, index|
        unless event.is_a?(Hash) && event["passed"] == true && event["attempt_count"] == 1 &&
               event["observed_at"].is_a?(String) && event["observation"].is_a?(Hash)
          raise "external watch control event #{index} is not a structured runtime observation: #{JSON.generate(event)}"
        end
      end
      raise "external watch control did not pass" unless result["passed"] == true
    end

    def build_trace
      ids = %w[acquire loss process_kill fence recovery]
      ids.map do |id|
        entries = @events.select { |event| event["id"] == id }
        {
          "id" => id,
          "event" => id,
          "passed" => !entries.empty? && entries.all? { |entry| entry["passed"] == true },
          "attempt_count" => 1,
          "component_count" => entries.length,
          "observation" => entries.map { |entry| entry.fetch("observation") }
        }
      end
    end

    def aggregate_properties
      @properties.group_by { |property| property["id"] || property["property"] }.map do |id, entries|
        {
          "id" => id,
          "property" => id,
          "passed" => entries.all? { |entry| entry["passed"] == true },
          "attempt_count" => 1,
          "measurement_source" => "production_module",
          "components" => entries.map { |entry| entry["component"] }.uniq,
          "observations" => entries
        }
      end.sort_by { |property| property.fetch("id").to_s }
    end

    def effect_journal_report
      entries = Rubernetes::Controller::EffectJournal.read(@effect_journal_path)
      mutations = entries.select { |entry| entry.is_a?(Hash) && entry["kind"] == "api_mutation" }
      # Lease creation/renewal is control-plane liveness bookkeeping. It is
      # intentionally repeated while a leader renews and therefore must stay
      # in the raw API mutation transcript, but it is not a replayed workload
      # side effect. Duplicate semantic-effect accounting excludes only these
      # lease records and keeps every other API mutation fail-closed.
      semantic_mutations = mutations.reject { |entry| lease_mutation?(entry) }
      api_events = entries.select { |entry| entry.is_a?(Hash) && entry["kind"] == "controller_event" }
      provider_events = entries.select { |entry| entry.is_a?(Hash) && entry["kind"] == "provider_event" }
      inventory = semantic_mutations.group_by { |entry| entry["effect_key"].to_s }.map do |key, values|
        duplicate_mutation_count = values.group_by do |entry|
          [entry["action"].to_s, entry["object_sha256"].to_s]
        end.values.sum { |duplicates| [duplicates.length - 1, 0].max }
        {
          "effect_key" => key,
          "effect_ids" => values.map { |entry| entry["effect_id"] }.compact.uniq.sort,
          "reconcile_key" => values.map { |entry| entry["reconcile_key"] }.compact.uniq.sort,
          "effect_types" => values.map { |entry| entry["effect_type"] }.compact.uniq.sort,
          "actions" => values.map { |entry| entry["action"] }.compact.uniq.sort,
          "mutation_count" => values.length,
          "duplicate_mutation_count" => duplicate_mutation_count,
          "object_digests" => values.map { |entry| entry["object_sha256"] }.compact.uniq.sort
        }
      end.sort_by { |entry| entry.fetch("effect_key") }
      canonical_entries = Rubernetes::Controller::EffectJournal.canonical(entries)
      raw_bytes = File.file?(@effect_journal_path) ? File.binread(@effect_journal_path) : ""
      {
        "path" => "effect-journal.jsonl",
        "entries" => canonical_entries,
        "entry_count" => canonical_entries.length,
        "api_mutations" => mutations,
        "api_events" => api_events,
        "provider_events" => provider_events,
        "inventory" => inventory,
        "inventory_sha256" => Rubernetes::Controller::EffectJournal.digest(inventory),
        "raw_sha256" => Digest::SHA256.hexdigest(raw_bytes),
        "canonical_sha256" => Rubernetes::Controller::EffectJournal.digest(canonical_entries),
        "duplicate_effect_count" => inventory.sum { |entry| entry.fetch("duplicate_mutation_count") }
      }
    end

    def lease_mutation?(entry)
      reconcile_key = entry["reconcile_key"].to_s
      effect_type = entry["effect_type"].to_s
      reconcile_key.include?("/leases/") || %w[lease lease_update renew].include?(effect_type)
    end

    def duplicate_count(ids)
      values = Array(ids).map(&:to_s).reject(&:empty?)
      values.length - values.uniq.length
    end

    def process_alive?(record)
      return @supervisor.alive?(record) if @supervisor.respond_to?(:alive?)

      Process.kill(0, record.fetch("pid"))
      expected_start = Integer(record.fetch("start_time"))
      current = File.read("/proc/#{record.fetch("pid")}/stat").rpartition(") ").last.split(" ").fetch(19).to_i
      current == expected_start
    rescue Errno::ESRCH, Errno::EPERM, Errno::ENOENT, Errno::EACCES, IndexError, ArgumentError
      false
    end

    def effect_reconcile_key(component, names)
      target = effect_target(component, names)
      [target.fetch("api_version"), target.fetch("kind"), target["namespace"], target.fetch("name")].compact.join("/")
    end

    def observe_shared_api!(phase:)
      record = @api_record
      observation = {
        "phase" => phase,
        "pid" => record && record["pid"],
        "start_time" => record && record["start_time"],
        "alive" => record && process_alive?(record),
        "observed_at" => M3ControlPlaneChaosRunner.iso8601_now
      }
      @api_survival_observations << observation
      raise "shared API/store did not survive worker SIGKILL at #{phase}" unless observation["alive"] == true

      observation
    end

    def wait_until(timeout:)
      deadline = M3ControlPlaneChaosRunner.monotonic_time + Float(timeout)
      loop do
        value = yield
        return value if value
        return nil if M3ControlPlaneChaosRunner.monotonic_time >= deadline

        sleep 0.05
      end
    end
  end

  def failure_report(request, error)
    provenance = external_runner_provenance(request)
    provenance["finished_at"] = iso8601_now
    provenance["provenance_sha256"] = digest(provenance)
    {
      "schema_version" => 1,
      "suite" => request["suite"],
      "scenario" => request["scenario"],
      "status" => "INCOMPLETE",
      "executed" => false,
      "passed" => false,
      "runner" => provenance,
      "processes" => [],
      "events" => [],
      "trace" => [],
      "component_runs" => [],
      "lease_observations" => [],
      "effect_ids" => [],
      "raw_trace_sha256" => nil,
      "canonical_trace_sha256" => nil,
      "errors" => [error]
    }
  end

  def run
    request = parse_request
    capability_errors = capability_errors(capabilities, request)
    report = if capability_errors.any?
               blocked_report(request)
             else
               require File.join(ROOT, "lib", "rubernetes", "client")
               Harness.new(request, capabilities).run
             end
    puts JSON.pretty_generate(report)
    0
  rescue StandardError => error
    request ||= {"suite" => "m3-control-plane-chaos", "scenario" => "unknown"}
    puts JSON.pretty_generate(failure_report(request, "external M3 chaos harness failed: #{error.class}: #{error.message}"))
    0
  end
end

exit M3ControlPlaneChaosRunner.run if $PROGRAM_NAME == __FILE__
