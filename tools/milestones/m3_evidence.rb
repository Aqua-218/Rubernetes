#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture the cumulative, content-addressed M3 control-loop evidence bundle.

require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"

require_relative "m3_gate"
require_relative "m3_evidence_support"

ROOT = M34EvidenceSupport::ROOT
REPORT_SPECS = {
  "controller_registry" => {filename: "controller-registry.json", kind: "m3_controller_registry",
                            default: [RbConfig.ruby, "tools/milestones/m3_controller_registry_probe.rb"]},
  "reconcile_idempotency" => {filename: "reconcile-idempotency.json", kind: "m3_reconcile_idempotency",
                              default: [RbConfig.ruby, "tools/milestones/m3_idempotency_probe.rb"]},
  "scheduler" => {filename: "scheduler-differential.json", kind: "m3_scheduler_differential",
                  default: [RbConfig.ruby, "tools/milestones/m3_scheduler_probe.rb"]},
  "workload" => {filename: "workload-differential.json", kind: "m3_workload_differential",
                 default: [RbConfig.ruby, "tools/milestones/m3_workload_probe.rb"]},
  "leader_loss" => {filename: "leader-loss-trace.json", kind: "m3_leader_loss_trace",
                    default: [RbConfig.ruby, "tools/milestones/m3_leader_probe.rb"]},
  "queue_informer" => {filename: "queue-informer-property.json", kind: "m3_queue_informer_property",
                       default: [RbConfig.ruby, "tools/milestones/m3_queue_probe.rb"]}
}.freeze

options = {
  run_id: Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"),
  output_root: File.join(ROOT, "artifacts/milestones/M3"),
  m0_manifest: ENV.fetch("RUBERNETES_M3_M0_MANIFEST", nil),
  m1_manifest: ENV.fetch("RUBERNETES_M3_M1_MANIFEST", nil),
  m2_manifest: ENV.fetch("RUBERNETES_M3_M2_MANIFEST", nil),
  reports: {},
  commands: {}
}

OptionParser.new do |parser|
  parser.banner = "Usage: m3_evidence.rb [options]"
  parser.on("--run-id ID", "evidence run identifier") { |value| options[:run_id] = value }
  parser.on("--output-root PATH", "milestone evidence root") { |value| options[:output_root] = File.expand_path(value) }
  parser.on("--m0-manifest PATH", "copy and verify COMPLETE M0 evidence") { |value| options[:m0_manifest] = File.expand_path(value) }
  parser.on("--m1-manifest PATH", "copy and verify COMPLETE M1 evidence") { |value| options[:m1_manifest] = File.expand_path(value) }
  parser.on("--m2-manifest PATH", "copy and verify COMPLETE M2 evidence for the same input") do |value|
    options[:m2_manifest] = File.expand_path(value)
  end
  REPORT_SPECS.each_key do |name|
    cli_name = name.tr("_", "-")
    parser.on("--#{name}-report PATH", "--#{cli_name}-report PATH", "copy a machine-readable #{name} report") do |value|
      options[:reports][name] = File.expand_path(value)
    end
    parser.on("--#{name}-command COMMAND", "--#{cli_name}-command COMMAND", "run the #{name} adapter and read JSON from stdout") do |value|
      options[:commands][name] = value
    end
  end
end.parse!(ARGV)

REPORT_SPECS.each_key do |name|
  command_key = "RUBERNETES_M3_#{name.upcase}_COMMAND"
  report_key = "RUBERNETES_M3_#{name.upcase}_REPORT"
  options[:commands][name] = ENV.fetch(command_key) if ENV.key?(command_key) && !options[:commands].key?(name)
  if ENV.key?(report_key) && !options[:commands].key?(name) && !options[:reports].key?(name)
    options[:reports][name] =
      File.expand_path(ENV.fetch(report_key))
  end
end

abort "run ID may contain only letters, digits, dot, underscore, and hyphen" unless options[:run_id].to_s.match?(/\A[0-9A-Za-z._-]+\z/)

directory = File.join(options[:output_root], options[:run_id])
FileUtils.mkdir_p(directory)
started_at = M34EvidenceSupport.now
starting_input = M34EvidenceSupport.source_identity(M3Gate)
starting_git_metadata = M34EvidenceSupport.git_metadata_paths
commands = []
prior_milestones = {}

def copy_prior_manifest(source, destination, gate_path, gate_name, commands, evidence_directory)
  source_manifest = File.realpath(source)
  source_directory = File.dirname(source_manifest)
  M34EvidenceSupport.copy_tree(source_directory, destination)
  copied_manifest = File.join(destination, File.basename(source_manifest))
  started = M34EvidenceSupport.now
  stdout, stderr, status = Open3.capture3(RbConfig.ruby, gate_path, copied_manifest, chdir: ROOT)
  gate_result = File.join(destination, "gate-result.json")
  File.binwrite(gate_result, stdout)
  commands << M34EvidenceSupport.command_record(
    gate_name,
    [RbConfig.ruby, gate_path.delete_prefix("#{ROOT}/"), copied_manifest.delete_prefix("#{ROOT}/")],
    started,
    M34EvidenceSupport.now,
    status.exitstatus || 1,
    stdout: stdout,
    stderr: stderr
  )
  document = M34EvidenceSupport.json_document(copied_manifest)
  reference = {
    "manifest_path" => copied_manifest.delete_prefix("#{evidence_directory}/"),
    "manifest_sha256" => Digest::SHA256.file(copied_manifest).hexdigest,
    "gate_result_path" => gate_result.delete_prefix("#{evidence_directory}/"),
    "gate_result_sha256" => Digest::SHA256.file(gate_result).hexdigest,
    "input_sha256" => document["input_sha256"],
    "input_file_count" => document["input_file_count"],
    "gate_passed" => status.success?
  }
  [document, reference]
rescue StandardError => error
  commands << M34EvidenceSupport.command_record(
    gate_name,
    [RbConfig.ruby, gate_path, source.to_s],
    started || M34EvidenceSupport.now,
    M34EvidenceSupport.now,
    1,
    error: "prior evidence could not be copied or gated: #{error.class}: #{error.message}"
  )
  [nil, nil]
end

if options[:m2_manifest]
  m2_document, m2_reference = copy_prior_manifest(options[:m2_manifest], File.join(directory, "m2"),
                                                  File.join(ROOT, "tools/milestones/m2_gate.rb"), "m2_gate", commands, directory)
  if m2_document && m2_reference
    prior_milestones["M2"] = m2_reference
    prior = m2_document["prior_milestones"]
    if prior.is_a?(Hash)
      prior.each do |milestone, reference|
        next unless reference.is_a?(Hash)

        prior_milestones[milestone] = reference.merge(
          "manifest_path" => File.join("m2", reference.fetch("manifest_path")),
          "gate_result_path" => File.join("m2", reference.fetch("gate_result_path"))
        )
      end
    end
  end
else
  commands << M34EvidenceSupport.command_record(
    "m2_gate",
    ["<missing M2 manifest: set RUBERNETES_M3_M2_MANIFEST or --m2-manifest>"],
    M34EvidenceSupport.now,
    M34EvidenceSupport.now,
    127,
    error: "M3 requires COMPLETE M2 evidence from the same source input"
  )
end

# Direct M0/M1 options are accepted for diagnostics and for preparing a chain,
# but an M2 bundle remains authoritative for cumulative M3 completion.
unless prior_milestones.key?("M1")
  if options[:m1_manifest]
    m1_document, m1_reference = copy_prior_manifest(options[:m1_manifest], File.join(directory, "m1"),
                                                    File.join(ROOT, "tools/milestones/m1_gate.rb"), "m1_gate", commands, directory)
    prior_milestones["M1"] = m1_reference if m1_document && m1_reference
    if m1_document && m1_document["prior_milestones"].is_a?(Hash)
      reference = m1_document["prior_milestones"]["M0"]
      if reference.is_a?(Hash)
        prior_milestones["M0"] = reference.merge(
          "manifest_path" => File.join("m1", reference.fetch("manifest_path")),
          "gate_result_path" => File.join("m1", reference.fetch("gate_result_path"))
        )
      end
    end
  else
    commands << M34EvidenceSupport.command_record("m1_gate", ["<missing M1 prerequisite>"], M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                  error: "M3 requires COMPLETE M1 evidence from the same source input")
  end
end

unless prior_milestones.key?("M0")
  if options[:m0_manifest]
    _m0_document, m0_reference = copy_prior_manifest(options[:m0_manifest], File.join(directory, "m0"),
                                                     File.join(ROOT, "tools/milestones/m0_gate.rb"), "m0_gate", commands, directory)
    prior_milestones["M0"] = m0_reference if m0_reference
  else
    commands << M34EvidenceSupport.command_record("m0_gate", ["<missing M0 prerequisite>"], M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                  error: "M3 requires COMPLETE M0 evidence from the same source input")
  end
end

chain_ready = %w[M0 M1 M2].all? do |milestone|
  reference = prior_milestones[milestone]
  reference.is_a?(Hash) && reference["gate_passed"] == true &&
    reference["input_sha256"] == starting_input.fetch("sha256") &&
    reference["input_file_count"] == starting_input.fetch("file_count")
end

REPORT_SPECS.each do |name, specification|
  destination = File.join(directory, specification.fetch(:filename))
  if !chain_ready
    report = {
      "schema_version" => 1,
      "milestone" => "M3",
      "kind" => specification.fetch(:kind),
      "input_sha256" => starting_input.fetch("sha256"),
      "input_file_count" => starting_input.fetch("file_count"),
      "input_stable" => true,
      "status" => "INCOMPLETE",
      "passed" => false,
      "available" => false,
      "errors" => ["M3 probes were not run because COMPLETE M0 -> M2 evidence for the identical source input is unavailable"]
    }
    M34EvidenceSupport.write_json(destination, report)
    commands << M34EvidenceSupport.command_record("m3_#{name}", ["<not run: incomplete M0 -> M2 prerequisite chain>"],
                                                  M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                  error: report.fetch("errors").first)
  elsif options[:commands].key?(name)
    command = M34EvidenceSupport.command_words(options[:commands].fetch(name))
    commands << if command.empty?
                  M34EvidenceSupport.command_record("m3_#{name}", ["<empty adapter command>"], M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                    error: "adapter command is empty")
                else
                  M34EvidenceSupport.run_command("m3_#{name}", command, destination, starting_input, env_prefix: "RUBERNETES_M3")
                end
  elsif options[:reports].key?(name)
    started = M34EvidenceSupport.now
    begin
      M34EvidenceSupport.copy_report(options[:reports].fetch(name), destination)
      commands << M34EvidenceSupport.command_record("m3_#{name}_report_copy", ["copy", options[:reports].fetch(name)], started,
                                                    M34EvidenceSupport.now, 0)
    rescue StandardError => error
      commands << M34EvidenceSupport.command_record("m3_#{name}_report_copy", ["copy", options[:reports].fetch(name)], started, M34EvidenceSupport.now, 1,
                                                    error: error.message)
    end
  else
    commands << M34EvidenceSupport.run_command("m3_#{name}", specification.fetch(:default), destination, starting_input,
                                               env_prefix: "RUBERNETES_M3")
  end
end

inventory = {
  "schema_version" => 1,
  "milestone" => "M3",
  "kind" => "m3_source_inventory",
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => true,
  "entries" => starting_input.fetch("entries")
}
M34EvidenceSupport.write_json(File.join(directory, "source-inventory.json"), inventory)

finished_input = M34EvidenceSupport.source_identity(M3Gate)
finished_git_metadata = M34EvidenceSupport.git_metadata_paths
input_stable = starting_input.fetch("sha256") == finished_input.fetch("sha256") &&
               starting_input.fetch("file_count") == finished_input.fetch("file_count")
artifacts = M34EvidenceSupport.artifact_entries(directory)
manifest = {
  "schema_version" => 3,
  "milestone" => "M3",
  "run_id" => options[:run_id],
  "status" => "INCOMPLETE",
  "host" => M34EvidenceSupport.host_identity,
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => input_stable,
  "input_capture" => {
    "stable" => input_stable,
    "start" => {"sha256" => starting_input.fetch("sha256"), "file_count" => starting_input.fetch("file_count")},
    "finish" => {"sha256" => finished_input.fetch("sha256"), "file_count" => finished_input.fetch("file_count")}
  },
  "git_metadata_capture" => {"stable" => starting_git_metadata == finished_git_metadata,
                             "start_paths" => starting_git_metadata, "finish_paths" => finished_git_metadata,
                             "count" => (starting_git_metadata | finished_git_metadata).length},
  "started_at" => started_at,
  "finished_at" => M34EvidenceSupport.now,
  "commands" => commands,
  "prior_milestones" => prior_milestones,
  "result_counts" => {
    "commands" => commands.length,
    "command_failures" => commands.count { |command| command.fetch("exit_status") != 0 },
    "artifacts" => artifacts.length,
    "subjects" => 0,
    "reports" => REPORT_SPECS.length,
    "source_files" => starting_input.fetch("file_count")
  },
  "artifacts" => artifacts,
  "subjects" => []
}

candidate_complete = chain_ready && input_stable && starting_git_metadata == finished_git_metadata && commands.all? do |command|
  command["exit_status"] == 0
end
manifest["status"] = "COMPLETE" if candidate_complete
manifest_path = File.join(directory, "manifest.json")
M34EvidenceSupport.write_json(manifest_path, manifest)

stdout, stderr, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m3_gate.rb"), manifest_path, chdir: ROOT)
$stdout.write(stdout)
$stderr.write(stderr)
unless status.success?
  manifest["status"] = "INCOMPLETE"
  M34EvidenceSupport.write_json(manifest_path, manifest)
  # Re-evaluate the final manifest so callers always see the result for the
  # artifact actually written to disk.
  final_stdout, final_stderr, final_status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m3_gate.rb"), manifest_path,
                                                            chdir: ROOT)
  $stdout.write(final_stdout) unless final_stdout == stdout
  $stderr.write(final_stderr) unless final_stderr == stderr
  exit(final_status.exitstatus || 1)
end
exit(0)
