#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m2_probe_support"

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "digest"
require "json"
require "socket"
require "tmpdir"
require "rubernetes/runtime/native"

module M2RuntimeProbe
  module_function

  def run_for(architecture)
    levels = [
      exercise_level("L0", :pure, architecture) { |runtime|
        sandbox = runtime.run_sandbox({"request_id" => "m2-l0"})
        container = runtime.create_container(sandbox, {"id" => "m2-l0-container", "command" => ["/bin/true"]})
        runtime.start_container(container)
        runtime.stop_container(container)
        runtime.stop_sandbox(sandbox)
        runtime.remove_sandbox(sandbox)
        runtime.sandboxes.empty?
      },
      exercise_level("L1", :fake_io, architecture) { |runtime|
        sandbox = runtime.run_sandbox({"request_id" => "m2-l1"})
        container = runtime.create_container(sandbox, {"id" => "m2-container", "command" => ["/bin/true"]})
        runtime.start_container(container)
        runtime.stop_container(container)
        runtime.stop_sandbox(sandbox)
        runtime.remove_sandbox(sandbox)
        runtime.sandboxes.empty?
      },
      exercise_l2(architecture)
    ]
    l3 = exercise_l3(architecture)
    levels << l3
    failures = levels.reject { |level| level.fetch("passed") }
    {
      "architecture" => architecture,
      "available" => failures.empty?,
      "status" => failures.empty? ? "PASS" : "INCOMPLETE",
      "passed" => failures.empty?,
      "skip" => false,
      "profile_sha256" => Digest::SHA256.hexdigest(JSON.generate(levels)),
      "levels" => levels,
      "errors" => failures.map { |level| level.fetch("error", "#{level.fetch("level")} unavailable") }
    }
  end

  def exercise_l2(architecture)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = nil
    passed = false
    details = {}
    Dir.mktmpdir("rubernetes-m2-l2-") do |directory|
      runtime = Rubernetes::Runtime::Native.new(
        profile: :pure,
        architecture: architecture,
        sandbox_root: File.join(directory, "sandboxes"),
        log_root: File.join(directory, "logs"),
        journal_path: File.join(directory, "runtime.wal"),
        process_adapter: Rubernetes::Platform::Linux::ProcessSupervisor::ForkAdapter.new
      )
      sandbox = runtime.run_sandbox({"request_id" => "m2-l2"})
      container = runtime.create_container(sandbox, {"id" => "m2-l2-container", "command" => ["/bin/true"]})
      runtime.start_container(container)
      result = runtime.wait_container(container, timeout: 5)

      filesystem_path = File.join(directory, "fsync-probe")
      File.open(filesystem_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        file.write("m2-l2")
        file.flush
        file.fsync
      end
      left, right = UNIXSocket.pair
      left.write("ping")
      socket_round_trip = right.read(4) == "ping"
      left.close
      right.close

      runtime.stop_sandbox(sandbox)
      runtime.remove_sandbox(sandbox)
      passed = result.fetch("exitCode") == 0 && File.binread(filesystem_path) == "m2-l2" &&
               socket_round_trip && runtime.sandboxes.empty?
      details = {"real_process_exit_code" => result.fetch("exitCode"), "fsync_file" => true,
                 "unix_socket_round_trip" => socket_round_trip}
      error = "L2 host integration exercise returned false" unless passed
    end
    evidence = {"level" => "L2", "profile" => "host_integration", "architecture" => architecture,
                "passed" => passed, "details" => details, "error" => error,
                "elapsed_ms" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round}
    level_result("L2", passed, evidence, error)
  rescue StandardError => caught
    error = "#{caught.class}: #{caught.message}"
    evidence = {"level" => "L2", "profile" => "host_integration", "architecture" => architecture,
                "passed" => false, "details" => details || {}, "error" => error,
                "elapsed_ms" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round}
    level_result("L2", false, evidence, error)
  end

  def level_result(level, passed, evidence, error)
    {
      "level" => level,
      "status" => passed ? "PASS" : "INCOMPLETE",
      "passed" => passed,
      "attempt_count" => 1,
      "failure_count" => passed ? 0 : 1,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "evidence_sha256" => Digest::SHA256.hexdigest(JSON.generate(evidence)),
      "evidence" => evidence,
      "error" => error
    }
  end

  def exercise_level(level, profile, architecture)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = nil
    passed = false
    begin
      runtime = Rubernetes::Runtime::Native.new(profile: profile, architecture: architecture)
      passed = yield(runtime) == true
      error = "#{level} runtime exercise returned false" unless passed
    rescue StandardError => caught
      error = "#{caught.class}: #{caught.message}"
    end
    evidence = {"level" => level, "profile" => profile.to_s, "architecture" => architecture,
                "passed" => passed, "error" => error,
                "elapsed_ms" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round}
    {
      "level" => level,
      "status" => passed ? "PASS" : "INCOMPLETE",
      "passed" => passed,
      "attempt_count" => 1,
      "failure_count" => passed ? 0 : 1,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "evidence_sha256" => Digest::SHA256.hexdigest(JSON.generate(evidence)),
      "evidence" => evidence,
      "error" => error
    }
  end

  def exercise_l3(architecture)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = nil
    passed = false
    details = {}
    begin
      cgroup = Rubernetes::Platform::Linux::CgroupV2.new
      cgroup_probe = cgroup.probe
      security_probe = Rubernetes::Platform::Linux::Security::CapabilityProbe.new(architecture: architecture).call
      details = {"cgroup" => cgroup_probe.to_h, "security" => security_probe.to_h}
      missing = []
      missing << "cgroup_v2" unless cgroup_probe.available?
      missing << "no_new_privs" unless security_probe.available?(:no_new_privs)
      missing << "seccomp" unless security_probe.available?(:seccomp)
      missing << "landlock" unless security_probe.available?(:landlock)
      if missing.empty?
        smoke = M2ProbeSupport.native_l3_smoke_measurement(architecture: architecture)
        details["native_workload"] = smoke
        passed = smoke.fetch("passed") == true
        error = "L3 Native workload exercise returned false" unless passed
      else
        error = "L3 kernel isolation unavailable: #{missing.join(", ")}"
      end
    rescue StandardError => caught
      error = "#{caught.class}: #{caught.message}"
    end
    evidence = {"level" => "L3", "profile" => "l3", "architecture" => architecture,
                "passed" => passed, "details" => details, "error" => error,
                "elapsed_ms" => ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round}
    {
      "level" => "L3",
      "status" => passed ? "PASS" : "INCOMPLETE",
      "passed" => passed,
      "attempt_count" => 1,
      "failure_count" => passed ? 0 : 1,
      "unexpected_skip_count" => 0,
      "unclassified_count" => 0,
      "evidence_sha256" => Digest::SHA256.hexdigest(JSON.generate(evidence)),
      "evidence" => evidence,
      "error" => error
    }
  end
end

M2ProbeSupport.run_probe("m2_runtime_profiles", "m2-runtime-probe") do |_current, _input|
  current_architecture = M2ProbeSupport.architecture_name
  errors = []
  profiles = M2Gate::REQUIRED_ARCHITECTURES.map do |architecture|
    if architecture == current_architecture
      profile = M2RuntimeProbe.run_for(architecture)
      errors.concat(profile.fetch("errors")) unless profile.fetch("available")
      profile
    else
      reason = "architecture #{architecture} is not the current execution architecture"
      errors << reason
      M2ProbeSupport.unavailable_profile(architecture, reason)
    end
  end
  {
    "passed" => errors.empty? && profiles.all? { |profile| profile.fetch("available") },
    "measurement_source" => "production_native_runtime",
    "required_architectures" => M2Gate::REQUIRED_ARCHITECTURES,
    "profiles" => profiles,
    "errors" => errors
  }
end
