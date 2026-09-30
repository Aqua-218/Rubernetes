#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m3_probe_support"

require "rbconfig"

RUNNER = File.expand_path("../../test/conformance/kubernetes/m3_control_plane_chaos/runner.rb", __dir__).freeze

M3ProbeSupport.run_report(kind: "m3_queue_informer_property", adapter_name: "queue-informer-probe",
                          load_production: false) do |_input, errors|
  chaos = M3ProbeSupport.run_external_json(
    env_keys: %w[RUBERNETES_M3_QUEUE_CHAOS_COMMAND RUBERNETES_M3_WATCH_CHAOS_COMMAND],
    default_command: [RbConfig.ruby, RUNNER],
    input: {
      "schema_version" => 1,
      "suite" => "m3-control-plane-queue-chaos",
      "scenario" => "watch-queue-chaos",
      "components" => %w[controller-manager scheduler],
      "required_events" => %w[process_kill duplicate_suppression out_of_order_delivery watch_reconnect resync],
      "watch_faults" => %w[duplicate out_of_order bookmark eof gone_410 reconnect resync]
    },
    errors: errors,
    label: "queue/informer process chaos runner"
  )

  unless chaos.is_a?(Hash)
    errors << "queue/informer process chaos runner did not return a structured report"
    next {"measurement_source" => "missing_external_process_harness", "properties" => [], "chaos" => {}}
  end

  if chaos["status"] == "BLOCKED"
    blocker = chaos["blocker"]
    errors << blocker if blocker.is_a?(String) && !blocker.empty? && !errors.include?(blocker)
  elsif chaos["status"] != "PASS"
    errors << "queue/informer process chaos runner did not pass"
  end

  properties = Array(chaos["properties"])
  unless chaos["status"] == "BLOCKED"
    properties.each do |entry|
      errors << "queue/informer property #{entry["id"] || entry["property"]} failed" unless entry.is_a?(Hash) && entry["passed"] == true
    end
  end

  {
    "measurement_source" => "production_module",
    "execution_mode" => "external_process",
    "adapter_classes" => %w[Rubernetes::Watch::DeltaFIFO Rubernetes::Watch::Indexer Rubernetes::Watch::WorkQueue Rubernetes::Watch::Informer],
    "properties" => properties,
    "duplicate_loss_count" => chaos["duplicate_loss_count"],
    "out_of_order_count" => chaos["out_of_order_count"],
    "reconnect_loss_count" => chaos["reconnect_loss_count"],
    "resync_loss_count" => chaos["resync_loss_count"],
    "blocker" => chaos["blocker"],
    "chaos" => chaos || {}
  }
end
