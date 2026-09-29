#!/usr/bin/env ruby
# frozen_string_literal: true

# Dependency-free verifier for M2 Native runtime traces.  The verifier is the
# executable fallback when TLC or Lean is not available on a validation host;
# it is deliberately strict about missing safety observations and never turns
# an unavailable external proof profile into a passing result.

require "json"
require "optparse"

module Rubernetes
  module Verification
    class M2RuntimeTraceVerifier
      TRACE_SCHEMA = "rubernetes.runtime.trace.v1"

      STATES = %w[
        New Validated ImagePinned WorkspaceAllocated IsolationCreated
        ResourcesAttached WorkloadStopped Running Stopping Stopped Removed
        RollingBack CleanupPending StateUnknown
      ].freeze

      RESOURCE_KINDS = %w[mount ns cgroup process pidfd temp].freeze
      RESOURCE_KIND_ALIASES = {
        "namespace" => "ns",
        "pid_fd" => "pidfd",
        "temporary" => "temp",
        "temporary_file" => "temp"
      }.freeze

      STATE_ALIASES = {
        "Unknown" => "StateUnknown",
        "unknown" => "StateUnknown",
        "state_unknown" => "StateUnknown",
        "state-unknown" => "StateUnknown"
      }.freeze

      ALLOWED_TRANSITIONS = {
        "New" => %w[Validated StateUnknown],
        "Validated" => %w[ImagePinned StateUnknown],
        "ImagePinned" => %w[WorkspaceAllocated],
        "WorkspaceAllocated" => %w[IsolationCreated RollingBack StateUnknown],
        "IsolationCreated" => %w[ResourcesAttached RollingBack StateUnknown],
        "ResourcesAttached" => %w[WorkloadStopped RollingBack StateUnknown],
        "WorkloadStopped" => %w[Running RollingBack StateUnknown],
        "Running" => %w[Stopping StateUnknown],
        "Stopping" => %w[Stopped],
        "Stopped" => %w[Removed CleanupPending],
        "Removed" => [],
        "RollingBack" => %w[Stopped CleanupPending],
        "CleanupPending" => %w[RollingBack],
        "StateUnknown" => %w[Stopping]
      }.freeze

      SNAPSHOT_ALIASES = {
        state: %w[state phase],
        live_owner: %w[live_owner liveOwner live_owners liveOwners],
        released: %w[released released_resources releasedResources],
        owned_resources: %w[owned_resources ownedResources resources],
        sandbox_ready: %w[sandbox_ready sandboxReady],
        digest_mismatch: %w[digest_mismatch digestMismatch],
        no_workload_effect: %w[no_workload_effect noWorkloadEffect],
        next_action: %w[next_action nextAction],
        live_process: %w[live_process liveProcess],
        live_processes: %w[live_processes liveProcesses],
        digest_status: %w[digest_status digestStatus],
        workload_effect: %w[workload_effect workloadEffect],
        workload_started: %w[workload_started workloadStarted],
        workload_instructions: %w[workload_instructions workloadInstructions],
        effect_count: %w[effect_count effectCount],
        result: %w[result operation_result operationResult stop_result stopResult],
        claim_order: %w[claim_order claimOrder acquisition_order acquisitionOrder],
        restored_from: %w[restored_from restoredFrom previous_identity previousIdentity],
        identity: %w[identity restored_identity restoredIdentity]
      }.freeze

      EFFECT_KEYS = %w[
        workload_effect workload_started workload_instructions effect_count
        workload_effects instructions_executed
      ].freeze

      EVENT_TYPES = %w[
        operation_started state_transition resource_claimed resource_released
        digest_mismatch workload_effect observation snapshot
      ].freeze

      class VerificationError < StandardError
        attr_reader :report

        def initialize(report)
          @report = report
          super(report.fetch("violations").map { |violation| violation.fetch("message") }.join("; "))
        end
      end

      class << self
        def load_file(path)
          content = File.binread(path)
          begin
            JSON.parse(content)
          rescue JSON::ParserError
            lines = content.each_line.filter_map do |line|
              next if line.strip.empty?

              JSON.parse(line, create_additions: false)
            end
            {"schema" => TRACE_SCHEMA, "events" => lines}
          end
        end

        def verify_file(path, **options)
          new(load_file(path), source: path, **options).verify
        rescue Errno::ENOENT, Errno::EACCES, JSON::ParserError => error
          failure_report(source: path, error: error)
        end

        def failure_report(source:, error:)
          {
            "success" => false,
            "schema" => TRACE_SCHEMA,
            "source" => source,
            "event_count" => 0,
            "transition_count" => 0,
            "snapshot_count" => 0,
            "violations" => [{
              "code" => "trace_unreadable",
              "event" => nil,
              "message" => "cannot read runtime trace: #{error.class}: #{error.message}"
            }],
            "warnings" => [],
            "invariants" => invariant_catalog
          }
        end

        def invariant_catalog
          {
            "live_owner_not_released" => "LiveOwner(resource) => not Released(resource)",
            "running_requires_sandbox_ready" => "Running(container) => SandboxReady(container.sandbox)",
            "running_requires_workload_effect" => "Running(container) => workload effect is enabled",
            "running_requires_live_process" => "Running(container) => LiveProcessOwnedBy(container)",
            "digest_mismatch_has_no_workload_effect" => "DigestMismatch => NoWorkloadEffect",
            "unknown_only_cleanup_or_observe" => "State = Unknown => NextAction in CleanupOrObserve",
            "unknown_stop_requires_observation" => "StateUnknown -> Stopping => observed and LiveProcess=false",
            "running_stop_result" => "Running -> Stopping => result=false and LiveProcess=false",
            "failure_rollback_preconditions" => "Failure -> RollingBack => no workload effect, no live process, cleanup action",
            "workload_stopped_has_no_effect" => "WorkloadStopped => NoWorkloadEffect and no live process",
            "stopped_has_no_live_process" => "Stopped(sandbox) => no LiveProcessOwnedBy(sandbox)",
            "removed_has_no_owned_resources" => "Removed(sandbox) => OwnedResources(sandbox) = {}",
            "resource_identity_non_reuse" => "Released(resource) => resource identity is never owned again",
            "cleanup_reverse_acquisition" => "Cleanup removes resources in reverse acquisition order",
            "required_resource_kinds" => RESOURCE_KINDS.join(", ")
          }
        end
      end

      attr_reader :trace, :source

      def initialize(trace, source: nil, strict: true)
        @trace = trace
        @source = source
        @strict = strict
      end

      def verify
        report = {
          "success" => false,
          "schema" => TRACE_SCHEMA,
          "source" => source,
          "event_count" => 0,
          "transition_count" => 0,
          "snapshot_count" => 0,
          "violations" => [],
          "warnings" => [],
          "invariants" => self.class.invariant_catalog
        }

        events = extract_events(report)
        return finalize(report) if events.nil?

        report["event_count"] = events.length
        if events.empty?
          violation(report, "trace_empty", nil, "runtime trace must contain at least one event")
          return finalize(report)
        end

        previous_state = nil
        first_state = nil
        current_operation_id = nil
        previous_snapshot = nil
        released_history = []
        observed_snapshot = false
        unknown_observation_seen = false
        events.each_with_index do |raw_event, index|
          event = normalize_event(raw_event, index, report)
          next unless event

          operation_id = event["operation_id"] || event.dig("payload", "operation_id")
          if operation_id && current_operation_id && operation_id.to_s != current_operation_id.to_s
            validate_initial_state(report, first_state, index - 1)
            previous_state = nil
            first_state = nil
            previous_snapshot = nil
            released_history = []
            unknown_observation_seen = false
          end
          current_operation_id ||= operation_id
          current_operation_id = operation_id if operation_id

          before, after = snapshots_for(event, previous_state, report)
          [before, after].compact.each do |snapshot|
            observed_snapshot = true
            report["snapshot_count"] += 1
            check_snapshot(snapshot, index, report)
            check_snapshot_sequence(previous_snapshot, snapshot, index, report, released_history)
            previous_snapshot = snapshot
            first_state ||= snapshot[:state] if snapshot.key?(:state)
          end

          from, to = transition_for(event, before, after, previous_state, report)
          if from || to
            report["transition_count"] += 1
            check_transition(from, to, index, report, before: before, after: after,
                             observation_seen: unknown_observation_seen, event: event)
            previous_state = to if to
          elsif after && after.key?(:state)
            state = after[:state]
            if previous_state && state != previous_state
              report["transition_count"] += 1
              check_transition(previous_state, state, index, report, before: before, after: after,
                               observation_seen: unknown_observation_seen, event: event)
            end
            previous_state = state
          end

          check_event_effects(event, after, index, report)
          if observation_event?(event, after)
            if live_process_value(after, index, report) != false
              violation(report, "unknown_observation_with_live_process", index,
                        "StateUnknown observation must establish live_process=false before stopping")
            end
            unknown_observation_seen = true
          elsif to && to != "StateUnknown"
            unknown_observation_seen = false
          end
        end

        unless observed_snapshot
          violation(report, "missing_safety_observations", nil,
                    "runtime trace must expose snapshots with ownership and safety fields")
        end
        validate_initial_state(report, first_state, 0)
        if report["snapshot_count"] > 0 && report["transition_count"] == 0
          report["warnings"] << "trace contains observations but no explicit state transition"
        end

        finalize(report)
      rescue StandardError => error
        violation(report, "verifier_error", nil, "trace verification failed: #{error.class}: #{error.message}")
        finalize(report)
      end

      def verify!
        report = verify
        raise VerificationError, report unless report.fetch("success")

        report
      end

      private

      def extract_events(report)
        value = @trace
        if value.is_a?(Array)
          return value
        end
        unless value.is_a?(Hash)
          violation(report, "trace_shape", nil, "trace must be an object or event array")
          return nil
        end

        schema = value["schema"] || value[:schema]
        if schema && schema.to_s != TRACE_SCHEMA
          violation(report, "trace_schema", nil,
                    "unsupported trace schema #{schema.inspect}; expected #{TRACE_SCHEMA.inspect}")
        end
        events = value["events"] || value[:events] || value["trace"] || value[:trace]
        unless events.is_a?(Array)
          violation(report, "trace_events", nil, "trace object must contain an events array")
          return nil
        end
        events
      end

      def normalize_event(raw_event, index, report)
        unless raw_event.is_a?(Hash)
          violation(report, "event_shape", index, "event must be a JSON object")
          return nil
        end

        event = stringify_keys(raw_event)
        payload = event["payload"]
        event = stringify_keys(payload).merge(event) if payload.is_a?(Hash)
        event["event"] = event["event"].to_s if event.key?("event")
        type = event["event"]
        if type && !type.empty? && !EVENT_TYPES.include?(type)
          report["warnings"] << "event #{index}: unrecognized event type #{type.inspect}; fields are still checked"
        end
        event
      end

      def snapshots_for(event, previous_state, report)
        before_value = event["before"] || event["previous"]
        after_value = event["after"] || event["snapshot"] || event["state_snapshot"]

        if before_value.nil? && after_value.nil? && snapshot_field_present?(event)
          after_value = event
        elsif after_value.nil? && (event.key?("to") || event.key?("next_state"))
          after_value = event
        end

        before = snapshot_from(before_value, previous_state, report) if before_value
        after = snapshot_from(after_value, previous_state, report) if after_value
        [before, after]
      end

      def snapshot_field_present?(event)
        SNAPSHOT_ALIASES.values.flatten.any? { |key| event.key?(key) }
      end

      def snapshot_from(value, previous_state, report)
        unless value.is_a?(Hash)
          violation(report, "snapshot_shape", nil, "snapshot must be a JSON object")
          return nil
        end
        fields = stringify_keys(value)
        snapshot = {}
        SNAPSHOT_ALIASES.each do |canonical, aliases|
          key = aliases.find { |candidate| fields.key?(candidate) }
          snapshot[canonical] = fields[key] if key
        end
        snapshot[:state] = previous_state if !snapshot.key?(:state) && previous_state
        snapshot
      end

      def transition_for(event, before, after, previous_state, report)
        explicit_transition = event.key?("from") || event.key?("to") ||
          event.key?("previous_state") || event.key?("next_state") ||
          event["event"] == "state_transition"
        return [nil, nil] unless explicit_transition

        from_value = event["from"] || event["previous_state"]
        to_value = event["to"] || event["next_state"]
        from_value ||= before[:state] if before && before.key?(:state)
        to_value ||= after[:state] if after && after.key?(:state)

        from = normalize_state(from_value, report, nil) if from_value
        to = normalize_state(to_value, report, nil) if to_value
        from ||= previous_state if to && previous_state
        if from && before && before[:state] && from != before[:state]
          violation(report, "transition_before_mismatch", nil,
                    "transition from #{from.inspect} disagrees with before state #{before[:state].inspect}")
        end
        if to && after && after[:state] && to != after[:state]
          violation(report, "transition_after_mismatch", nil,
                    "transition to #{to.inspect} disagrees with after state #{after[:state].inspect}")
        end
        [from, to]
      end

      def check_transition(from, to, index, report, before: nil, after: nil,
                           observation_seen: false, event: {})
        if from.nil? || to.nil?
          violation(report, "transition_missing_state", index,
                    "state_transition requires both from and to states")
          return
        end
        unless STATES.include?(from) && STATES.include?(to)
          violation(report, "transition_unknown_state", index,
                    "unknown state transition #{from.inspect} -> #{to.inspect}")
          return
        end
        unless ALLOWED_TRANSITIONS.fetch(from).include?(to)
          violation(report, "invalid_transition", index,
                    "invalid runtime transition #{from} -> #{to}")
        end
        check_running_transition(from, to, before, after, index, report) if to == "Running"
        check_stopping_transition(from, to, before, after, index, report,
                                  observation_seen: observation_seen, event: event)
        check_failure_transition(from, to, before, after, index, report)
        check_rollback_transition(from, to, before, after, index, report)
      end

      def check_stopping_transition(from, to, before, after, index, report,
                                    observation_seen:, event:)
        return unless from == "StateUnknown" && to == "Stopping" || from == "Running" && to == "Stopping"

        unless after
          violation(report, "stopping_missing_snapshot", index,
                    "#{from} -> Stopping must expose the resulting safety snapshot")
          return
        end

        live_process = live_process_value(after, index, report)
        if live_process != false
          code = from == "StateUnknown" ? "unknown_stopping_with_live_process" : "stopping_with_live_process"
          violation(report, code, index,
                    "#{from} -> Stopping requires live_process=false")
        end

        if from == "StateUnknown"
          unless observation_seen
            violation(report, "unknown_stopping_without_observation", index,
                      "StateUnknown -> Stopping requires an observation before reconciliation")
          end
          # The observation event establishes the false process result. The
          # resulting transition must preserve that observation in `after`.
        else
          result = event_value(event, after, :result)
          if result.nil?
            violation(report, "stopping_missing_result", index,
                      "Running -> Stopping must record a false stop result")
          elsif normalized_boolean(result, :result, index, report) != false
            violation(report, "stopping_result_true", index,
                      "Running -> Stopping requires result=false")
          end
        end
      end

      def check_failure_transition(from, to, _before, after, index, report)
        return unless to == "RollingBack"

        unless %w[WorkspaceAllocated IsolationCreated ResourcesAttached WorkloadStopped].include?(from)
          return
        end
        unless after
          violation(report, "rollback_missing_snapshot", index,
                    "failure transition to RollingBack must expose the resulting safety snapshot")
          return
        end
        action = normalize_next_action(after[:next_action]) if after.key?(:next_action)
        violation(report, "rollback_missing_action", index,
                  "failure transition to RollingBack requires next_action=CleanupOrObserve") unless action == "CleanupOrObserve"
        no_effect = normalized_boolean(after[:no_workload_effect], :no_workload_effect, index, report) if after.key?(:no_workload_effect)
        violation(report, "rollback_with_workload_effect", index,
                  "failure transition to RollingBack requires no_workload_effect=true") unless no_effect == true
        live_process = live_process_value(after, index, report)
        violation(report, "rollback_with_live_process", index,
                  "failure transition to RollingBack requires live_process=false") unless live_process == false
      end

      def check_rollback_transition(from, to, _before, after, index, report)
        return unless from == "RollingBack" || from == "CleanupPending" || from == "Stopped"
        return unless after

        case [from, to]
        when ["RollingBack", "CleanupPending"]
          required_snapshot_field(after, :owned_resources, index, report)
          owned = normalize_resource_collection(after[:owned_resources], :owned_resources, index, report) if after.key?(:owned_resources)
          violation(report, "cleanup_pending_without_resources", index,
                    "RollingBack -> CleanupPending requires owned resources") if owned && owned.empty?
          violation(report, "cleanup_pending_with_live_process", index,
                    "RollingBack -> CleanupPending requires live_process=false") unless live_process_value(after, index, report) == false
          require_cleanup_action(after, index, report)
        when ["CleanupPending", "RollingBack"]
          required_snapshot_field(after, :owned_resources, index, report)
          violation(report, "cleanup_retry_with_live_process", index,
                    "CleanupPending -> RollingBack requires live_process=false") unless live_process_value(after, index, report) == false
          require_cleanup_action(after, index, report)
        when ["RollingBack", "Stopped"]
          required_snapshot_field(after, :owned_resources, index, report)
          owned = normalize_resource_collection(after[:owned_resources], :owned_resources, index, report) if after.key?(:owned_resources)
          violation(report, "rollback_stopped_with_resources", index,
                    "RollingBack -> Stopped requires owned_resources to be empty") unless owned && owned.empty?
          live_process = live_process_value(after, index, report)
          violation(report, "rollback_stopped_with_live_process", index,
                    "RollingBack -> Stopped requires live_process=false") unless live_process == false
        when ["Stopped", "Removed"]
          required_snapshot_field(after, :owned_resources, index, report)
          owned = normalize_resource_collection(after[:owned_resources], :owned_resources, index, report) if after.key?(:owned_resources)
          violation(report, "removed_with_resources", index,
                    "Stopped -> Removed requires owned_resources to be empty") unless owned && owned.empty?
          live_process = live_process_value(after, index, report)
          violation(report, "removed_with_live_process", index,
                    "Stopped -> Removed requires live_process=false") unless live_process == false
        end
      end

      def require_cleanup_action(snapshot, index, report)
        action = normalize_next_action(snapshot[:next_action]) if snapshot.key?(:next_action)
        violation(report, "cleanup_action_missing", index,
                  "cleanup transition requires next_action=CleanupOrObserve") unless action == "CleanupOrObserve"
      end

      def event_value(event, snapshot, field)
        return snapshot[field] if snapshot && snapshot.key?(field)

        event[field.to_s]
      end

      def observation_event?(event, snapshot)
        type = event["event"].to_s.downcase
        return false unless %w[observation observe_process observeprocess].include?(type)

        snapshot && snapshot[:state] == "StateUnknown"
      end

      def check_running_transition(from, to, before, after, index, report)
        return unless from == "WorkloadStopped" && to == "Running"

        [before, after].compact.each do |snapshot|
          if snapshot.key?(:digest_mismatch) &&
             normalized_boolean(snapshot[:digest_mismatch], :digest_mismatch, index, report) == true
            violation(report, "running_after_digest_mismatch", index,
                      "WorkloadStopped -> Running is impossible after digest mismatch")
          end
        end

        unless after
          violation(report, "running_missing_snapshot", index,
                    "WorkloadStopped -> Running must expose the resulting safety snapshot")
          return
        end

        required_snapshot_field(after, :digest_mismatch, index, report)
        required_snapshot_field(after, :no_workload_effect, index, report)
        required_snapshot_field(after, :live_process, index, report)
        mismatch = digest_mismatch(after, index, report)
        if mismatch == true
          violation(report, "running_after_digest_mismatch", index,
                    "WorkloadStopped -> Running cannot set digest_mismatch=true")
        end
        no_effect = normalized_boolean(after[:no_workload_effect], :no_workload_effect, index, report) if after.key?(:no_workload_effect)
        if no_effect != false
          violation(report, "running_without_workload_effect", index,
                    "WorkloadStopped -> Running requires no_workload_effect=false")
        end
        live_process = live_process_value(after, index, report)
        if live_process != true
          violation(report, "running_without_live_process", index,
                    "WorkloadStopped -> Running requires live_process=true")
        end
      end

      def check_snapshot(snapshot, index, report)
        required_snapshot_field(snapshot, :live_owner, index, report)
        required_snapshot_field(snapshot, :released, index, report)

        live_owner = normalize_resource_collection(snapshot[:live_owner], :live_owner, index, report)
        released = normalize_resource_collection(snapshot[:released], :released, index, report)
        if live_owner && released
          overlap = live_owner & released
          unless overlap.empty?
            violation(report, "live_owner_released", index,
                      "live owner resource(s) are marked released: #{overlap.sort.join(", ")}")
          end
        end

        state = normalize_state(snapshot[:state], report, index) if snapshot.key?(:state)
        if state == "Running"
          required_snapshot_field(snapshot, :owned_resources, index, report)
          required_snapshot_field(snapshot, :digest_mismatch, index, report)
          required_snapshot_field(snapshot, :no_workload_effect, index, report)
          required_snapshot_field(snapshot, :live_process, index, report)
          ready = normalized_boolean(snapshot[:sandbox_ready], :sandbox_ready, index, report)
          if ready != true
            violation(report, "running_without_sandbox_ready", index,
                      "Running requires sandbox_ready=true")
          end
          mismatch = digest_mismatch(snapshot, index, report)
          violation(report, "running_after_digest_mismatch", index,
                    "Running requires digest_mismatch=false") if mismatch == true
          no_effect = normalized_boolean(snapshot[:no_workload_effect], :no_workload_effect, index, report)
          violation(report, "running_without_workload_effect", index,
                    "Running requires no_workload_effect=false") unless no_effect == false
          live_process = live_process_value(snapshot, index, report)
          violation(report, "running_without_live_process", index,
                    "Running requires live_process=true") unless live_process == true
          check_required_resource_kinds(snapshot, index, report)
        end

        if state == "WorkloadStopped"
          required_snapshot_field(snapshot, :no_workload_effect, index, report)
          required_snapshot_field(snapshot, :live_process, index, report)
          no_effect = normalized_boolean(snapshot[:no_workload_effect], :no_workload_effect, index, report)
          violation(report, "workload_stopped_with_effect", index,
                    "WorkloadStopped requires no_workload_effect=true") unless no_effect == true
          live_process = live_process_value(snapshot, index, report)
          violation(report, "workload_stopped_with_live_process", index,
                    "WorkloadStopped requires live_process=false") unless live_process == false
        end

        mismatch = digest_mismatch(snapshot, index, report)
        if mismatch == true
          no_effect = workload_effect_free?(snapshot, index, report)
          if no_effect != true
            violation(report, "digest_mismatch_workload_effect", index,
                      "digest mismatch requires no_workload_effect=true and no workload effect")
          end
        end

        if state == "StateUnknown"
          required_snapshot_field(snapshot, :next_action, index, report)
          action = normalize_next_action(snapshot[:next_action])
          unless action == "CleanupOrObserve"
            violation(report, "unknown_action", index,
                      "StateUnknown permits only next_action=CleanupOrObserve")
          end
        end

        if state == "Stopped"
          live_process = live_process_value(snapshot, index, report)
          if live_process != false
            violation(report, "stopped_with_live_process", index,
                      "Stopped requires no live process owned by the sandbox")
          end
        end

        if state == "Removed"
          required_snapshot_field(snapshot, :owned_resources, index, report)
          resources = normalize_resource_collection(snapshot[:owned_resources], :owned_resources, index, report)
          if resources && !resources.empty?
            violation(report, "removed_with_resources", index,
                      "Removed requires owned_resources to be empty")
          end
        end

        check_restored_identity(snapshot, index, report)
      end

      def check_required_resource_kinds(snapshot, index, report)
        resources = normalize_resource_collection(snapshot[:owned_resources], :owned_resources, index, report)
        return unless resources

        kinds = resources.map { |resource| resource_kind(resource) }.uniq
        missing = RESOURCE_KINDS - kinds
        return if missing.empty?

        violation(report, "running_missing_resource_kinds", index,
                  "Running must own all M2 resource kinds; missing #{missing.join(", ")}")
      end

      def check_event_effects(event, snapshot, index, report)
        return unless snapshot

        mismatch = digest_mismatch(snapshot, index, report)
        return unless mismatch == true

        EFFECT_KEYS.each do |key|
          next unless event.key?(key)

          value = event[key]
          if effect_value?(value)
            violation(report, "digest_mismatch_event_effect", index,
                      "event #{key.inspect} records a workload effect after digest mismatch")
          end
        end
      end

      def check_snapshot_sequence(previous, current, index, report, released_history)
        current_released = resource_values(current, :released, index, report)
        return unless current_released

        previous_released = resource_values(previous, :released, index, report) if previous
        previous_released ||= []
        removed_from_tombstones = previous_released - current_released
        unless removed_from_tombstones.empty?
          violation(report, "released_identity_reappeared", index,
                    "released resource tombstones must be monotonic: #{removed_from_tombstones.join(", ")}")
        end

        active = resource_values(current, :live_owner, index, report).to_a |
          resource_values(current, :owned_resources, index, report).to_a
        reused = active & released_history
        unless reused.empty?
          violation(report, "resource_identity_reused", index,
                    "released resource identity was claimed again: #{reused.join(", ")}")
        end

        newly_released = current_released - previous_released
        unless newly_released.empty?
          state = normalize_state(current[:state], report, index) if current.key?(:state)
          unless %w[Stopped RollingBack].include?(state)
            violation(report, "cleanup_before_stop", index,
                      "resource cleanup is permitted only in Stopped or RollingBack")
          end

          active_before = resource_values(previous, :claim_order, index, report) if previous
          active_before = resource_values(previous, :owned_resources, index, report) if active_before.nil? || active_before.empty?
          if active_before.nil? || active_before.empty?
            violation(report, "cleanup_order_missing", index,
                      "resource release must identify the active acquisition order")
          else
            expected = active_before.last(newly_released.length).reverse
            unless newly_released == expected
              violation(report, "cleanup_order_violation", index,
                        "cleanup must release resources in reverse acquisition order; expected #{expected.join(", ")}, got #{newly_released.join(", ")}")
            end
            active_after = resource_values(current, :claim_order, index, report) if current.key?(:claim_order)
            active_after = resource_values(current, :owned_resources, index, report) if active_after.nil? || active_after.empty?
            expected_remaining = active_before[0, active_before.length - newly_released.length]
            if active_after && active_after != expected_remaining
              violation(report, "cleanup_ownership_mismatch", index,
                        "cleanup must remove only the reverse-order owner stack suffix")
            end
          end
        end

        released_history.concat(current_released).uniq!
      end

      def resource_values(snapshot, field, index, report)
        return [] unless snapshot
        return nil unless snapshot.key?(field)

        normalize_resource_collection(snapshot[field], field, index, report)
      end

      def validate_initial_state(report, state, index)
        if state.nil?
          violation(report, "missing_initial_state", index,
                    "runtime lifecycle traces must expose an initial state")
        elsif state != "New"
          violation(report, "trace_must_start_new", index,
                    "runtime lifecycle traces must start in New")
        end
      end

      def check_restored_identity(snapshot, index, report)
        old_identity = snapshot[:restored_from] || snapshot[:previous_identity]
        new_identity = snapshot[:identity] || snapshot[:restored_identity]
        return if old_identity.nil? || new_identity.nil?

        if old_identity == new_identity
          violation(report, "identity_reused", index,
                    "restored identity must differ from the source identity")
        end
      end

      def digest_mismatch(snapshot, index, report)
        return normalized_boolean(snapshot[:digest_mismatch], :digest_mismatch, index, report) if snapshot.key?(:digest_mismatch)
        return true if snapshot[:digest_status].to_s.casecmp("mismatch").zero?

        nil
      end

      def workload_effect_free?(snapshot, index, report)
        return normalized_boolean(snapshot[:no_workload_effect], :no_workload_effect, index, report) if snapshot.key?(:no_workload_effect)

        effect_keys = EFFECT_KEYS.select { |key| snapshot.key?(key) }
        if effect_keys.empty?
          violation(report, "missing_no_workload_effect", index,
                    "digest mismatch observation must include no_workload_effect")
          return nil
        end
        effect_keys.none? { |key| effect_value?(snapshot[key]) }
      end

      def effect_value?(value)
        case value
        when true then true
        when false, nil then false
        when Numeric then !value.zero?
        when String then !value.empty? && !%w[false 0 none].include?(value.downcase)
        when Array, Hash then !value.empty?
        else true
        end
      end

      def live_process_value(snapshot, index, report)
        if snapshot.key?(:live_process)
          value = snapshot[:live_process]
          return normalized_boolean(value, :live_process, index, report)
        end
        if snapshot.key?(:live_processes)
          processes = normalize_resource_collection(snapshot[:live_processes], :live_processes, index, report)
          return processes&.any?
        end

        required_snapshot_field(snapshot, :live_process, index, report)
        nil
      end

      def normalize_state(value, report, index)
        state = value.to_s
        state = STATE_ALIASES.fetch(state, state)
        unless STATES.include?(state)
          violation(report, "unknown_state", index, "unknown runtime state #{value.inspect}")
          return nil
        end
        state
      end

      def normalize_next_action(value)
        case value
        when Array
          return "CleanupOrObserve" if value.length == 1 && normalize_next_action(value.first) == "CleanupOrObserve"
        when String
          normalized = value.gsub(/[_\-\s]/, "").downcase
          return "CleanupOrObserve" if normalized == "cleanuporobserve"
        end
        nil
      end

      def normalized_boolean(value, field, index, report)
        case value
        when true, false then value
        when 1, "1", "true", "TRUE" then true
        when 0, "0", "false", "FALSE" then false
        else
          violation(report, "invalid_boolean", index, "#{field} must be boolean")
          nil
        end
      end

      def normalize_resource_collection(value, field, index, report)
        unless value.is_a?(Array) || value.is_a?(Hash)
          violation(report, "invalid_resource_collection", index,
                    "#{field} must be an array or object")
          return nil
        end
        values = value.is_a?(Array) ? value : value.keys
        normalized = values.map do |resource|
          if resource.is_a?(Hash)
            hash = stringify_keys(resource)
            kind = normalize_resource_kind(hash["kind"] || hash["type"])
            id = hash["id"] || hash["name"]
            kind && id ? "#{kind}:#{id}" : hash.to_json
          else
            resource.to_s
          end
        end
        duplicates = normalized.group_by(&:itself).select { |_resource, entries| entries.length > 1 }.keys
        unless duplicates.empty?
          violation(report, "duplicate_resource_identity", index,
                    "#{field} contains duplicate resource identities: #{duplicates.join(", ")}")
        end
        normalized.each do |resource|
          kind = resource_kind(resource)
          unless RESOURCE_KINDS.include?(kind)
            violation(report, "unknown_resource_kind", index,
                      "#{field} contains unsupported M2 resource kind #{kind.inspect}; expected #{RESOURCE_KINDS.join(", ")}")
          end
        end
        normalized.uniq
      end

      def normalize_resource_kind(value)
        RESOURCE_KIND_ALIASES.fetch(value.to_s.downcase, value.to_s.downcase)
      end

      def resource_kind(resource)
        normalize_resource_kind(resource.to_s.split(":", 2).first)
      end

      def required_snapshot_field(snapshot, field, index, report)
        return if snapshot.key?(field)

        violation(report, "missing_#{field}", index,
                  "snapshot must include #{field}")
      end

      def stringify_keys(value)
        value.each_with_object({}) { |(key, child), result| result[key.to_s] = child }
      end

      def violation(report, code, index, message)
        report["violations"] << {"code" => code, "event" => index, "message" => message}
      end

      def finalize(report)
        report["success"] = report["violations"].empty?
        report
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {trace: nil, pretty: false}
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ruby m2_runtime_trace_verifier.rb --trace TRACE.json [--pretty]"
    opts.on("--trace PATH", "Runtime trace JSON or JSONL path") { |path| options[:trace] = path }
    opts.on("--pretty", "Pretty-print the JSON report") { options[:pretty] = true }
  end

  begin
    parser.parse!
    raise OptionParser::MissingArgument, "--trace PATH is required" unless options[:trace]

    report = Rubernetes::Verification::M2RuntimeTraceVerifier.verify_file(options[:trace])
    output = options[:pretty] ? JSON.pretty_generate(report) : JSON.generate(report)
    puts output
    exit(report.fetch("success") ? 0 : 1)
  rescue OptionParser::ParseError => error
    warn error.message
    warn parser
    exit 2
  end
end
