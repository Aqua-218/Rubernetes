#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "m2_probe_support"

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "digest"
require "etc"
require "json"
require "rubernetes/runtime/native"

module M2KernelProbe
  module_function

  def current_profile(architecture)
    cgroup = Rubernetes::Platform::Linux::CgroupV2.new.probe
    security = Rubernetes::Platform::Linux::Security::CapabilityProbe.new(architecture: architecture).call
    native = M2ProbeSupport.native_kernel_inventory_measurement(architecture: architecture)
    kernel = Etc.uname
    cgroup_state = {
      "available" => cgroup.available?,
      "controllers" => Array(cgroup.controllers).sort,
      "subtree_control" => Array(cgroup.subtree_control).sort,
      "reason" => cgroup.reason
    }
    security_state = {
      "architecture" => security.architecture,
      "capabilities" => security.capabilities.keys.sort.to_h { |key| [key, security.capabilities.fetch(key)] },
      "no_new_privs" => security.no_new_privs,
      "no_new_privs_supported" => security.available?(:no_new_privs),
      "seccomp" => security.seccomp,
      "landlock" => security.landlock
    }
    objects = M2Gate::REQUIRED_RESOURCE_KINDS.map do |kind|
      object(
        "native_#{kind}", "#{architecture}:#{kind}",
        before: JSON.generate(native.fetch("baseline").fetch(kind)),
        active: JSON.generate(native.fetch("active").fetch(kind)),
        after: JSON.generate(native.fetch("final").fetch(kind))
      )
    end
    objects.push(
      object("host", "architecture", before: architecture, active: architecture, after: architecture),
      object("kernel", "release", before: kernel.fetch(:release), active: kernel.fetch(:release),
                                  after: kernel.fetch(:release)),
      object("cgroup_v2", "/sys/fs/cgroup", before: JSON.generate(cgroup_state), active: JSON.generate(cgroup_state),
                                            after: JSON.generate(cgroup_state)),
      object("security_capabilities", architecture, before: JSON.generate(security_state), active: JSON.generate(security_state),
                                                    after: JSON.generate(security_state)),
      object(
        "child_security", "#{architecture}:native-workload",
        before: JSON.generate(native.fetch("parent_security")),
        active: JSON.generate(native.fetch("child_security")),
        after: JSON.generate(M2ProbeSupport.proc_status_security_fields(File.binread("/proc/self/status")))
      )
    )
    missing = []
    missing << "cgroup_v2" unless cgroup.available?
    missing << "no_new_privs" unless security.available?(:no_new_privs)
    missing << "seccomp" unless security.available?(:seccomp)
    missing << "landlock" unless security.available?(:landlock)
    missing << "native_l3_workload" unless native.fetch("passed") == true
    missing << "child_no_new_privs" unless native.dig("child_security", "NoNewPrivs") == "1"
    missing << "child_seccomp_filter" unless native.dig("child_security", "Seccomp") == "2"
    missing << "child_landlock_enforcement" unless native.dig("child_security", "blocked_read_denied") == true
    available = missing.empty?
    baseline = native.fetch("baseline_sha256")
    final = native.fetch("final_sha256")
    {
      "architecture" => architecture,
      "available" => available,
      "status" => available ? "PASS" : "INCOMPLETE",
      "passed" => available,
      "skip" => false,
      "profile_sha256" => Digest::SHA256.hexdigest(JSON.generate(objects)),
      "objects" => objects,
      "inventory_sha256" => M2Gate.canonical_kernel_inventory_digest(objects),
      "baseline_sha256" => baseline,
      "final_sha256" => final,
      "difference_count" => native.fetch("difference_count"),
      "difference_keys" => native.fetch("difference_keys"),
      "live_leak_count" => native.fetch("live_leak_count"),
      "orphan_count" => 0,
      "errors" => (available ? [] : ["kernel isolation unavailable: #{missing.join(", ")}"])
    }
  rescue StandardError => error
    {
      "architecture" => architecture,
      "available" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "skip" => false,
      "profile_sha256" => Digest::SHA256.hexdigest("kernel-error:#{architecture}:#{error.class}:#{error.message}"),
      "objects" => [],
      "inventory_sha256" => Digest::SHA256.hexdigest(""),
      "baseline_sha256" => Digest::SHA256.hexdigest("baseline:#{architecture}"),
      "final_sha256" => Digest::SHA256.hexdigest("final:#{architecture}"),
      "difference_count" => 1,
      "live_leak_count" => 1,
      "orphan_count" => 1,
      "errors" => ["#{error.class}: #{error.message}"]
    }
  end

  def object(kind, identity, before:, active:, after:)
    {
      "kind" => kind,
      "identity" => identity,
      "before" => String(before),
      "active" => String(active),
      "after" => String(after),
      "measurement_source" => "production_native_adapter",
      "active_sha256" => Digest::SHA256.hexdigest(String(active))
    }
  end
end

M2ProbeSupport.run_probe("m2_kernel_inventory", "m2-kernel-probe") do |_current, _input|
  current_architecture = M2ProbeSupport.architecture_name
  errors = []
  profiles = M2Gate::REQUIRED_ARCHITECTURES.map do |architecture|
    if architecture == current_architecture
      profile = M2KernelProbe.current_profile(architecture)
      errors.concat(profile.fetch("errors")) unless profile.fetch("available")
      profile
    else
      reason = "architecture #{architecture} is not the current execution architecture"
      errors << reason
      M2ProbeSupport.unavailable_kernel_profile(architecture, reason)
    end
  end
  {
    "passed" => errors.empty? && profiles.all? { |profile| profile.fetch("available") },
    "measurement_source" => "production_native_kernel",
    "required_architectures" => M2Gate::REQUIRED_ARCHITECTURES,
    "architectures" => profiles,
    "errors" => errors
  }
end
