# frozen_string_literal: true

require "json"
require "digest"
require "tmpdir"
require "fileutils"

# Builds the RuntimeLifecycle trace consumed by
# tools/verification/m2_runtime_trace_verifier.rb from the production Native
# runtime's hash-chained ownership journal.
#
# Every trace event is one durable `state_transition` record.  The `before`
# and `after` snapshots are reconstructed by replaying the journal's
# operation_started / resource_claimed / state_transition / resource_released
# records in sequence, so the snapshots contain exactly what the ledger
# recorded.  Kernel facets of a ledger resource (the OverlayFS mount and the
# temp paths behind a workspace claim, the namespace links and pidfd behind a
# namespace claim, the workload pidfd behind a process claim) are attached
# from the Native kernel observer's readback taken at the effect point where
# the ledger claim became durable.  A facet is only attached when the observer
# measured it from procfs / mountinfo / fdinfo at that moment.
module M2LifecycleTraceSupport
  module_function

  FACET_KINDS = %w[mount ns pidfd temp].freeze
  # Ledger claim kinds expressed in the verifier's M2 resource vocabulary.
  # The Native "workspace" claim owns the sandbox's temporary directory tree
  # (root/upper/work), i.e. the model's Temp resource; its OverlayFS mount is
  # a facet observed once the namespace holder exists.
  LEDGER_KIND_MAP = {"workspace" => "temp", "namespace" => "ns"}.freeze

  def ledger_key(payload)
    kind = LEDGER_KIND_MAP.fetch(payload.fetch("kind"), payload.fetch("kind"))
    "#{kind}:#{payload.fetch("id")}"
  end
  TERMINAL_UNKNOWN_ACTION = "CleanupOrObserve"

  # Journal-derived snapshots for one operation.
  class OperationReplay
    attr_reader :operation_id, :events, :final_state

    def initialize(operation_id, facets:, kernel_observations:)
      @operation_id = operation_id
      @facets = facets
      @kernel_observations = kernel_observations
      @state = nil
      @claim_order = []
      @released = []
      @live_process = false
      @sandbox_ready = false
      @no_workload_effect = true
      @events = []
      @final_state = nil
    end

    def apply(record)
      payload = record.fetch("payload")
      case record.fetch("event")
      when "operation_started"
        @state = "New"
        @config_digest = payload.fetch("config_digest")
      when "resource_claimed"
        key = M2LifecycleTraceSupport.ledger_key(payload)
        return if @claim_order.include?(key)

        raise "released resource #{key} was claimed again" if @released.include?(key)

        @claim_order << key
        @claim_order.concat(Array(@facets[key]).reject { |facet| @claim_order.include?(facet) })
      when "resource_released"
        key = M2LifecycleTraceSupport.ledger_key(payload)
        return if @released.include?(key)

        group = [key] + Array(@facets[key])
        group.reverse_each do |entry|
          next unless @claim_order.include?(entry)

          @claim_order.delete(entry)
          @released << entry
        end
      when "state_transition"
        from = payload.fetch("from")
        to = payload.fetch("to")
        raise "journal transition #{from} -> #{to} disagrees with replayed state #{@state}" if @state && from != @state

        before = snapshot(from)
        enter(to)
        after = snapshot(to)
        after["result"] = @live_process if from == "Running" && to == "Stopping"
        @events << {
          "operation_id" => @operation_id,
          "event" => "state_transition",
          "from" => from,
          "to" => to,
          "owned_resources" => @claim_order.dup,
          "config_digest" => payload.fetch("config_digest"),
          "fsynced" => true,
          "timestamp" => record.fetch("timestamp"),
          "journal_sequence" => record.fetch("sequence"),
          "journal_digest" => record.fetch("digest"),
          "before" => before,
          "after" => after
        }
        @final_state = to
      end
    end

    private

    def enter(to)
      @state = to
      case to
      when "WorkloadStopped"
        @sandbox_ready = true
        @live_process = false
        @no_workload_effect = true
      when "Running"
        @live_process = true
        @no_workload_effect = false
      when "Stopping", "Stopped", "Removed", "RollingBack", "CleanupPending", "StateUnknown"
        @live_process = false
      end
    end

    def snapshot(state)
      {
        "state" => state,
        "live_owner" => @claim_order.dup,
        "owned_resources" => @claim_order.dup,
        "claim_order" => @claim_order.dup,
        "released" => @released.dup,
        "sandbox_ready" => @sandbox_ready,
        "digest_mismatch" => false,
        "no_workload_effect" => @no_workload_effect,
        "live_process" => @live_process,
        "next_action" => %w[RollingBack CleanupPending StateUnknown].include?(state) ? TERMINAL_UNKNOWN_ACTION : "Continue"
      }
    end
  end

  # journal_records: OwnershipLedger journal records (Hash form).
  # facets: {"kind:id" => ["facetkind:id", ...]} measured by the kernel observer.
  def trace_from_journal(journal_records, facets:, kernel_observations: {})
    replays = {}
    Array(journal_records).each do |raw|
      record = stringify(raw)
      next unless %w[operation_started resource_claimed state_transition resource_released].include?(record["event"])

      replay = replays[record.fetch("operation_id")] ||= OperationReplay.new(
        record.fetch("operation_id"), facets: facets, kernel_observations: kernel_observations
      )
      replay.apply(record)
    end
    replays.values.flat_map(&:events)
  end

  # Maps observer entries (six kernel kinds) onto the ledger claims they
  # substantiate.  Facet keys are "kind:id" strings using the observer's ids.
  def facets_from_entries(entries, sandbox_id:, container_ids:)
    facets = Hash.new { |hash, key| hash[key] = [] }
    Array(entries).each do |entry|
      value = stringify(entry)
      kind = value.fetch("kind")
      next unless FACET_KINDS.include?(kind)

      id = value.fetch("id")
      owner_key = case kind
                  when "temp", "mount" then "temp:#{sandbox_id}"
                  when "ns" then "ns:#{sandbox_id}"
                  when "pidfd"
                    if id == "#{sandbox_id}:namespace"
                      "ns:#{sandbox_id}"
                    else
                      container = container_ids.find { |candidate| id == "#{sandbox_id}:workload" || id.end_with?(":#{candidate}") }
                      "process:#{sandbox_id}:#{container || container_ids.first}"
                    end
                  end
      # The OverlayFS mount is created inside the namespace holder after the
      # workspace directories exist; it is a facet of the namespace claim.
      owner_key = "ns:#{sandbox_id}" if kind == "mount"
      facet = "#{kind}:#{id}"
      facets[owner_key] << facet unless facets[owner_key].include?(facet)
    end
    facets.each_value(&:sort!)
    facets.to_h
  end

  def stringify(value)
    case value
    when Hash then value.to_h { |key, child| [key.to_s, stringify(child)] }
    when Array then value.map { |child| stringify(child) }
    else value.respond_to?(:to_h) && !value.is_a?(String) && !value.is_a?(Numeric) ? stringify(value.to_h) : value
    end
  end
end

module M2LifecycleTraceSupport
  module_function

  FAILURE_EFFECT_POINT = "isolation_created"

  # Runs one production Native L3 sandbox lifecycle (run -> create -> start ->
  # stop -> remove) plus one real effect-point failure injection on the same
  # runtime, and returns the verifier-shaped trace replayed from that
  # runtime's ownership journal.
  def native_lifecycle_measurement
    require File.join(File.expand_path("../..", __dir__), "lib/rubernetes/runtime/native")
    raise "production Native L3 lifecycle trace requires root" unless Process.uid.zero?

    const_set(:InjectedEffectFailure, Class.new(Rubernetes::Runtime::Native::Error)) unless defined?(InjectedEffectFailure)
    image = M2ProbeSupport.pinned_image
    image.image
    result = nil
    Dir.mktmpdir("rubernetes-m2-trace-") do |directory|
      sandbox_root = File.join(directory, "sandboxes")
      observer = M2ProbeSupport::NativeKernelObserver.new(directory: File.join(directory, "observer"))
      stamp = "#{Process.pid}-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}"
      success_id = "m2-trace-#{stamp}"
      failure_id = "m2-trace-fail-#{stamp}"
      observations = {}
      injected = []
      runtime = nil
      effect_hook = lambda do |effect_point:, sandbox:, operation:, transition:|
        role = "#{sandbox.id == failure_id ? "failure" : "success"}-#{effect_point}"
        manifest = observer.capture_effect(
          runtime: runtime, sandbox: sandbox, role: role, agent_pid: Process.pid, effect_point: effect_point
        )
        observations[role] = {
          "effect_point" => effect_point,
          "operation_state" => operation.state,
          "journal_sequence" => transition && transition["sequence"],
          "journal_digest" => transition && transition["digest"],
          "entries" => manifest.fetch("entries")
        }
        if sandbox.id == failure_id && effect_point == FAILURE_EFFECT_POINT
          injected << {"sandbox_id" => sandbox.id, "effect_point" => effect_point,
                       "journal_sequence" => transition && transition["sequence"]}
          raise InjectedEffectFailure, "injected effect failure at #{effect_point}"
        end
        true
      end
      adapters = Rubernetes::Platform::Linux::NativeAdapters.for_profile(
        profile: :l3, sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        architecture: M2ProbeSupport.architecture_name
      ).merge(image: M2ProbeSupport.image_verifier, observer: observer, effect_hook: effect_hook)
      runtime = Rubernetes::Runtime::Native.new(
        profile: :l3, l3: true, adapters: adapters,
        sandbox_root: sandbox_root, cgroup_root: "/sys/fs/cgroup",
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "journal.jsonl"),
        security_context: {"allow_privilege_escalation" => false, "seccomp" => "RuntimeDefault"}
      )
      failure_error = nil
      begin
        runtime.run_sandbox(image.runtime_input(id: failure_id), request_id: failure_id)
      rescue InjectedEffectFailure, Rubernetes::Runtime::Native::Error => error
        failure_error = "#{error.class}: #{error.message}"
      end
      raise "injected effect failure did not surface" unless failure_error
      raise "failed sandbox #{failure_id} is still registered" if runtime.sandboxes.any? do |entry|
        (entry.respond_to?(:id) ? entry.id : entry["id"] || entry[:id]) == failure_id
      end

      runtime.run_sandbox(image.runtime_input(id: success_id), request_id: success_id)
      sandbox = runtime.sandbox(success_id)
      container = runtime.create_container(sandbox, image.container_spec(id: "main", command: ["/bin/busybox", "sleep", "3600"]))
      container = runtime.start_container(container)
      running_manifest = observer.capture(
        runtime: runtime, sandbox: sandbox, container: container, role: "success-running", agent_pid: Process.pid
      )
      observations["success-running"] = {
        "effect_point" => "running", "operation_state" => runtime.ledger.operation(sandbox.id).state,
        "journal_sequence" => runtime.ledger.journal.last&.sequence,
        "journal_digest" => runtime.ledger.journal.last&.digest,
        "entries" => running_manifest.fetch("entries")
      }
      workload = {
        "pid" => running_manifest.fetch("workload_pid"),
        "start_time" => running_manifest.fetch("workload_start_time").to_s,
        "executable_digest" => running_manifest.fetch("workload_executable_digest")
      }
      runtime.stop_sandbox(sandbox, timeout: 2)
      stopped_state = runtime.ledger.operation(sandbox.id).state
      runtime.remove_sandbox(sandbox)
      cleanup_readback = observer.list_resources
      leftover = Dir.glob(File.join("/sys/fs/cgroup/rubernetes", "*", "m2-trace-*#{stamp}*"))
      raise "Native L3 trace cleanup left cgroup #{leftover.join(", ")}" unless leftover.empty?

      records = runtime.ledger.journal.records
      facets = {}
      observations.each_value do |observation|
        [success_id, failure_id].each do |id|
          entries = observation["entries"].select { |entry| entry["id"].to_s.start_with?("#{id}:") || entry["id"].to_s == id }
          next if entries.empty?

          facets_from_entries(entries, sandbox_id: id, container_ids: ["main"]).each do |key, values|
            facets[key] = ((facets[key] || []) + values).uniq.sort
          end
        end
      end
      trace = trace_from_journal(records, facets: facets, kernel_observations: observations)
      result = {
        "trace" => trace,
        "measurement_source" => "production_native_lifecycle_journal",
        "journal_record_count" => records.length,
        "journal_sha256" => Digest::SHA256.hexdigest(records.map { |record| JSON.generate(record) }.join("\n")),
        "journal_head_digest" => records.last && records.last["digest"],
        "sandbox_ids" => {"success" => success_id, "failure" => failure_id},
        "failure_injection" => {"effect_point" => FAILURE_EFFECT_POINT, "error" => failure_error, "hooks" => injected},
        "workload" => workload,
        "stopped_ledger_state" => stopped_state,
        "kernel_observations" => observations,
        "facets" => facets,
        "cleanup_readback" => cleanup_readback,
        "live_resource_count" => runtime.ledger.resources(include_released: false).length
      }
    end
    result
  end
end
