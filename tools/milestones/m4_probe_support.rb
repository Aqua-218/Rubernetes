#!/usr/bin/env ruby
# frozen_string_literal: true

# M4 probes share the source/provenance machinery with M3 but use a separate
# input namespace so an M3 adapter cannot accidentally satisfy a data-plane
# evidence run.

require "digest"
require "fileutils"
require "json"
require "rbconfig"
require "tmpdir"
require_relative "m3_probe_support"

module M4ProbeSupport
  module_function

  def run_report(kind:, adapter_name:, measurement_level: "L3", &)
    M3ProbeSupport.run_report(
      kind: kind,
      adapter_name: adapter_name,
      measurement_level: measurement_level,
      milestone: "M4",
      input_env_prefix: "RUBERNETES_M4",
      &
    )
  end

  def respond_to_production?(value, method_name)
    value.respond_to?(method_name.to_sym)
  end

  def production_candidates(names, required_methods: [])
    M3ProbeSupport.production_candidates(names, required_methods: required_methods)
  end

  def constant(path)
    M3ProbeSupport.constant(path)
  end

  def first_constant(paths)
    M3ProbeSupport.first_constant(paths)
  end

  def instantiate(klass, keyword_sets: [], positional_sets: [[]])
    M3ProbeSupport.instantiate(klass, keyword_sets: keyword_sets, positional_sets: positional_sets)
  end

  def invoke(target, method_name, positional: [], keywords: {})
    M3ProbeSupport.invoke(target, method_name, positional: positional, keywords: keywords)
  end

  def digest(value)
    M3ProbeSupport.digest(value)
  end

  def normalize(value)
    M3ProbeSupport.normalize(value)
  end

  def report_runner_sha256
    M3ProbeSupport.report_runner_sha256
  end

  def run_external_json(env_keys:, input:, errors:, label:)
    M3ProbeSupport.run_external_json(env_keys: env_keys, input: input, errors: errors, label: label)
  end

  # Kernel/container observations are produced by an external runner that
  # watches a separate worker process: the production volume stack driving a
  # real lifecycle inside a private mount namespace.  The probe only starts
  # the worker, hands its process identity and control directory to the
  # runner, and records the worker's own result beside the runner document.
  # Without a configured runner command the observation stays empty and the
  # probe reports the missing command.
  OBSERVED_WORKER_TIMEOUT = 90

  def run_observed_worker(worker:, env_keys:, label:, scenario:, required_observations:, errors:, extra_input: {})
    keys = Array(env_keys)
    unless keys.any? { |key| ENV.key?(key) && !ENV.fetch(key).strip.empty? }
      errors << "#{label} command is unavailable; set #{keys.join(" or ")}"
      return nil
    end
    unless File.file?(worker)
      errors << "#{label} worker is missing at #{worker}"
      return nil
    end

    Dir.mktmpdir("rubernetes-m4-observed-worker") do |directory|
      control_dir = File.join(directory, "control")
      root = File.join(directory, "root")
      FileUtils.mkdir_p(control_dir)
      FileUtils.mkdir_p(root)
      stdout_read, stdout_write = IO.pipe
      stderr_read, stderr_write = IO.pipe
      command = ["unshare", "--mount", "--propagation", "private", "--fork", "--", RbConfig.ruby,
                 "-I#{File.join(M3ProbeSupport::ROOT, "lib")}", worker, "--control-dir", control_dir, "--root", root]
      started_at = M3ProbeSupport.iso8601_now
      pid = Process.spawn(*command, in: File::NULL, out: stdout_write, err: stderr_write, pgroup: true, chdir: M3ProbeSupport::ROOT)
      stdout_write.close
      stderr_write.close
      worker_status = nil
      worker_path = File.join(control_dir, "worker.json")
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + OBSERVED_WORKER_TIMEOUT
      until File.file?(worker_path)
        reaped = Process.waitpid2(pid, Process::WNOHANG)
        if reaped
          worker_status = reaped.last
          break
        end
        break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.02
      end
      identity = File.file?(worker_path) ? JSON.parse(File.binread(worker_path)) : nil
      document = nil
      if identity.is_a?(Hash) && identity["pid"].is_a?(Integer)
        document = run_external_json(
          env_keys: keys,
          input: {"scenario" => scenario, "required_observations" => required_observations,
                  "control_dir" => control_dir, "root" => root, "require_rotation" => extra_input.fetch("require_rotation", false),
                  "worker" => identity.slice("pid", "start_time_ticks", "mount_namespace_inode")}.merge(extra_input),
          errors: errors,
          label: label
        )
      else
        errors << "#{label} worker did not publish its identity"
      end
      File.binwrite(File.join(control_dir, "done"), "done\n")
      unless worker_status
        finish_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + OBSERVED_WORKER_TIMEOUT
        loop do
          reaped = Process.waitpid2(pid, Process::WNOHANG)
          if reaped
            worker_status = reaped.last
            break
          end
          if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= finish_deadline
            begin
              Process.kill("KILL", -pid)
            rescue Errno::ESRCH
              nil
            end
            _, worker_status = Process.waitpid2(pid)
            break
          end
          sleep 0.02
        end
      end
      worker_stdout = stdout_read.read.to_s
      worker_stderr = stderr_read.read.to_s
      stdout_read.close
      stderr_read.close
      worker_result = begin
        JSON.parse(worker_stdout)
      rescue JSON::ParserError
        nil
      end
      worker_record = {
        "worker_path" => worker.delete_prefix("#{M3ProbeSupport::ROOT}/"),
        "worker_sha256" => Digest::SHA256.file(worker).hexdigest,
        "command" => command, "identity" => identity, "started_at" => started_at,
        "exit_status" => worker_status&.exitstatus, "signaled" => worker_status&.signaled? == true,
        "result" => worker_result, "stderr" => worker_stderr.byteslice(-4096..) || worker_stderr
      }
      unless worker_status&.success? && worker_result.is_a?(Hash) && worker_result["passed"] == true
        errors << "#{label} worker did not complete its scenario: #{(worker_result && worker_result.dig("error",
                                                                                                        "message")) || worker_stderr.strip.lines.last}"
      end
      document.is_a?(Hash) ? document.merge("observed_worker" => worker_record) : document
    end
  end

  def kernel_version(value)
    match = value.to_s.match(/\A(\d+)\.(\d+)/)
    match && [match[1].to_i, match[2].to_i]
  end

  def kernel_at_least?(value, major: 6, minor: 12)
    version = kernel_version(value)
    version && (version[0] > major || (version[0] == major && version[1] >= minor))
  end
end
