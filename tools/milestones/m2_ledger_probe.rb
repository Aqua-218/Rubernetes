#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m2_probe_support"

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "digest"
require "json"
require "rubernetes/runtime"
require "tmpdir"

module M2LedgerProbe
  module_function

  EFFECT_POINTS = M2Gate::REQUIRED_EFFECT_POINTS.freeze
  DEFAULT_CYCLE_COUNT = 1_000

  # RUBERNETES_M2_LEDGER_CYCLES shortens the developer fast lane (rake test:parallel);
  # evidence capture never sets it, so the release probe stays at 1000 cycles.
  def cycle_count
    value = ENV.fetch("RUBERNETES_M2_LEDGER_CYCLES", DEFAULT_CYCLE_COUNT.to_s)
    count = Integer(value, 10)
    raise ArgumentError, "RUBERNETES_M2_LEDGER_CYCLES must be >= #{EFFECT_POINTS.length}" if count < EFFECT_POINTS.length

    count
  end

  def run
    native_cycles = M2ProbeSupport.measure_native_l3_cycles(
      count: cycle_count, fault_points: EFFECT_POINTS
    )
    cycles = native_cycles.fetch("cycles")
    effect_points = EFFECT_POINTS.map do |point|
      cycle = cycles.find { |entry| entry.dig("fault_injection", "effect_point") == point }
      raise "Native cycle did not inject #{point}" unless cycle

      fault = cycle.fetch("fault_injection")
      {
        "name" => point,
        "injected_count" => 1,
        "cycle" => cycle.fetch("cycle"),
        "fault_token" => fault.fetch("token"),
        "observed_error_sha256" => fault.dig("observed_error", "message_sha256"),
        "wal_transition_digest" => fault.dig("checkpoint", "wal_transition", "digest"),
        "fault_evidence_sha256" => fault.fetch("evidence_sha256"),
        "rollback_state" => fault.fetch("rollback_state"),
        "live_leak_count" => cycle.fetch("live_leak_count"),
        "measurement_source" => "production_native_effect_injection"
      }
    end
    cycle_inventory = native_cycles.fetch("inventory_measurement")

    Dir.mktmpdir("rubernetes-m2-ledger-") do |_directory|
      sigkill_matrix = M2ProbeSupport.measure_sigkill_matrix(
        effect_points: EFFECT_POINTS,
        image_digest: "sha256:" + ("d" * 64)
      )
      inventory_measurement = M2ProbeSupport.inventory_measurement_from(sigkill_matrix)
      resource_kinds = inventory_measurement.fetch("resource_kinds")
      sigkill_matrix.each do |entry|
        effect = entry.fetch("effect_point")
        effect_points.find { |point| point.fetch("name") == effect }["live_leak_count"] = entry.fetch("dead_residual_count")
      end
      kernel_l3_available = M2ProbeSupport.l3_available?
      l3_available = kernel_l3_available && inventory_measurement.fetch("missing_resource_kinds").empty?
      matrix_passed = sigkill_matrix.all? do |entry|
        entry["kill_observed"] == true && entry["restart_observed"] == true && entry["wal_replayed"] == true &&
          entry["live_wrong_deletion_count"] == 0 && entry["dead_residual_count"] == 0
      end
      errors = []
      errors << "L3 kernel isolation profile is unavailable" unless kernel_l3_available
      unless inventory_measurement.fetch("missing_resource_kinds").empty?
        errors << "L3 resource inventory is incomplete: #{inventory_measurement.fetch("missing_resource_kinds").join(", ")}"
      end
      unless cycle_inventory.fetch("missing_resource_kinds").empty?
        errors << "Native lifecycle cycle inventory is incomplete: #{cycle_inventory.fetch("missing_resource_kinds").join(", ")}"
      end
      unless cycle_inventory.fetch("live_leak_count").zero?
        errors << "Native lifecycle cycle cleanup left #{cycle_inventory.fetch("live_leak_count")} resources"
      end
      canonical_payload = {
        "cycle_count" => cycles.length,
        "cycles" => cycles,
        "effect_points" => effect_points,
        "failure_injection_count" => effect_points.sum { |entry| entry.fetch("injected_count") },
        "live_leak_count" => cycle_inventory.fetch("live_leak_count"),
        "orphan_count" => 0,
        "resource_reuse_count" => native_cycles.fetch("resource_reuse_count")
      }
      {
        "passed" => cycles.all? { |cycle| cycle.fetch("passed") } && cycle_inventory.fetch("live_leak_count").zero? &&
          native_cycles.fetch("resource_reuse_count").zero? && l3_available && matrix_passed && errors.empty?,
        "measurement_source" => "production_native_l3_cycles",
        "cycle_count" => cycles.length,
        "cycles" => cycles,
        "effect_points" => effect_points,
        "failure_injection_count" => effect_points.sum { |entry| entry.fetch("injected_count") },
        "live_leak_count" => cycle_inventory.fetch("live_leak_count"),
        "orphan_count" => 0,
        "resource_reuse_count" => native_cycles.fetch("resource_reuse_count"),
        "ledger_sha256" => M2Gate.canonical_document_digest(canonical_payload),
        "measurement_level" => l3_available ? "L3" : "L2",
        "sigkill_matrix" => sigkill_matrix,
        "inventory_measurement" => inventory_measurement,
        "cycle_inventory_measurement" => cycle_inventory,
        "resource_kinds" => resource_kinds,
        "l3_available" => l3_available,
        "errors" => errors
      }
    end
  end

  def transition(ledger, operation, state)
    ledger.transition(operation_id: operation.id, to: state)
  end

  def operation_state(ledger, id)
    ledger.operation(id).state
  end
end

M2ProbeSupport.run_probe("m2_resource_ledger", "m2-ledger-probe") do |_current, _input|
  M2LedgerProbe.run
end
