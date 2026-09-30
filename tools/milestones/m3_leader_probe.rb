#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture leader-loss evidence from the external controller-manager/scheduler
# process harness. The Ruby probe deliberately does not use an in-process store,
# sequential election instances, or object-watch doubles: those paths do not
# prove a cross-process lease fence.

require "rbconfig"
require_relative "m3_probe_support"

RUNNER = File.expand_path("../../test/conformance/kubernetes/m3_control_plane_chaos/runner.rb", __dir__).freeze

M3ProbeSupport.run_report(kind: "m3_leader_loss_trace", adapter_name: "leader-loss-probe", load_production: false) do |_input, errors|
  chaos = M3ProbeSupport.run_external_json(
    env_keys: %w[RUBERNETES_M3_LEADER_CHAOS_COMMAND RUBERNETES_M3_PROCESS_CHAOS_COMMAND],
    default_command: [RbConfig.ruby, RUNNER],
    input: {
      "schema_version" => 1,
      "suite" => "m3-control-plane-leader-chaos",
      "scenario" => "leader-loss",
      "components" => %w[controller-manager scheduler],
      "required_events" => %w[acquire process_kill fence recovery],
      "required_properties" => %w[duplicate_effects_zero recovery_within_60_seconds]
    },
    errors: errors,
    label: "leader-loss process chaos runner"
  )

  unless chaos.is_a?(Hash)
    errors << "leader-loss process chaos runner did not return a structured report"
    next {"measurement_source" => "missing_external_process_harness", "trace" => [], "chaos" => {}}
  end

  if chaos["status"] == "BLOCKED"
    blocker = chaos["blocker"]
    errors << blocker if blocker.is_a?(String) && !blocker.empty? && !errors.include?(blocker)
  elsif chaos["status"] != "PASS"
    errors << "leader-loss process chaos runner did not pass"
  end

  trace = Array(chaos["trace"])
  unless chaos["status"] == "BLOCKED"
    trace.each do |entry|
      errors << "leader-loss event #{entry["id"] || entry["event"]} failed" unless entry.is_a?(Hash) && entry["passed"] == true
    end
  end

  {
    # M3Gate treats production_module as the source of the exercised service;
    # independent process identity is recorded inside chaos.execution_mode.
    "measurement_source" => "production_module",
    "execution_mode" => "external_process",
    "adapter_class" => "Rubernetes::Controller::LeaseElector",
    "trace" => trace,
    "events" => Array(chaos["events"]),
    "quorum_recovered" => chaos["quorum_recovered"] == true,
    "recovery_seconds" => chaos["recovery_seconds"],
    "double_side_effect_count" => chaos["double_side_effect_count"],
    "duplicate_side_effect_count" => chaos["duplicate_side_effect_count"],
    "stale_side_effect_count" => chaos["stale_side_effect_count"],
    "chaos" => chaos,
    "blocker" => chaos["blocker"]
  }
end
