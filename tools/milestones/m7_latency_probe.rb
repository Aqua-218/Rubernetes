#!/usr/bin/env ruby
# frozen_string_literal: true

# M7 exit criterion 6: Pod start latency from the cached base snapshot.
# Each sample is one complete Pod start through the production backend:
# run_sandbox (restore, identity ACK), network attach, create_container,
# start_container (network ACK, gate ACK, guest container start) until the
# workload is running.  Raw samples are recorded; p95 must be <= 1.5 s.

require_relative "m7_probe_support"

module M7LatencyProbe
  S = M7ProbeSupport
  SAMPLES = Integer(ENV.fetch("RUBERNETES_M7_LATENCY_SAMPLES", "20"))
  BOUND_SECONDS = 1.5

  module_function

  def run
    started_at = S.now
    S.require_root!
    cases = []
    runtime, root = S.build_runtime("latency", use_base_snapshot: false)
    network = S::ProbeNetwork.new(6)
    samples = []
    begin
      runtime.prepare_base!(request_id: "latency-base")
      runtime.adapter.instance_variable_set(:@use_base_snapshot, true)
      warm = S.start_pod(runtime, network, "latency-warm")
      S.stop_pod(runtime, network, warm)
      SAMPLES.times do |index|
        pod = S.start_pod(runtime, network, "latency-#{index}")
        session = pod["session"]
        samples << {"index" => index, "total" => pod["timings"]["total"], "phases" => pod["timings"].reject { |key, _| key == "total" },
                    "session" => session.timings, "guest_identity" => session.acks.dig("identity.apply", "timings"), "base" => session.base&.id}
        S.stop_pod(runtime, network, pod)
      end
    ensure
      network.detach_all
      S.cleanup_runtime_root(root)
    end
    totals = samples.map { |sample| sample["total"] }
    p50 = S.percentile(totals, 0.5)
    p95 = S.percentile(totals, 0.95)
    cases << {"id" => "pod_start_from_base_snapshot", "samples" => samples.length, "p50_seconds" => p50, "p95_seconds" => p95, "max_seconds" => totals.max,
              "min_seconds" => totals.min, "bound_seconds" => BOUND_SECONDS, "raw_samples" => samples,
              "passed" => samples.length >= SAMPLES && !p95.nil? && p95 <= BOUND_SECONDS}
    S.emit(S.report(
      kind: "m7_startup_latency_samples", measurement_level: "L4", started_at: started_at, cases: cases,
      extra: {"host" => S.host_facts, "measurement_source" => "real_snapshot_restores", "samples" => SAMPLES,
              "sources" => M5ProbeSupport.source_files(%w[lib/rubernetes/runtime/microvm/session.rb lib/rubernetes/runtime/microvm/adapter.rb lib/rubernetes/runtime/microvm/guest/supervisor.rb])}
    ))
  end
end

M7LatencyProbe.run if $PROGRAM_NAME == __FILE__
