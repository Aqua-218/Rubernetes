#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture the cumulative, content-addressed M5 durable-HA evidence bundle.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"

require_relative "m5_gate"
require_relative "m3_evidence_support"

ROOT = M34EvidenceSupport::ROOT
REPORT_SPECS = {
  "linearizability" => {filename: "linearizability-histories.json", kind: "m5_linearizability_histories",
                        default: [RbConfig.ruby, "tools/milestones/m5_linearizability_probe.rb"]},
  "fault_matrix" => {filename: "fault-matrix.json", kind: "m5_fault_matrix",
                     default: [RbConfig.ruby, "tools/milestones/m5_fault_matrix_probe.rb"]},
  "corruption" => {filename: "wal-snapshot-corruption-corpus.json", kind: "m5_corruption_corpus",
                   default: [RbConfig.ruby, "tools/milestones/m5_corruption_probe.rb"]},
  "rto_rpo" => {filename: "rto-rpo-report.json", kind: "m5_rto_rpo_report",
                default: [RbConfig.ruby, "tools/milestones/m5_rto_rpo_probe.rb"]},
  "ownership" => {filename: "resource-ownership-ledger.json", kind: "m5_resource_ownership_ledger",
                  default: [RbConfig.ruby, "tools/milestones/m5_ownership_probe.rb"]}
}.freeze

options = {
  run_id: Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"),
  output_root: File.join(ROOT, "artifacts/milestones/M5"),
  m4_manifest: ENV.fetch("RUBERNETES_M5_M4_MANIFEST", nil),
  reports: {},
  commands: {}
}

OptionParser.new do |parser|
  parser.banner = "Usage: m5_evidence.rb [options]"
  parser.on("--run-id ID", "evidence run identifier") { |value| options[:run_id] = value }
  parser.on("--output-root PATH", "milestone evidence root") { |value| options[:output_root] = File.expand_path(value) }
  parser.on("--m4-manifest PATH", "copy and verify COMPLETE M4 evidence for the same input") do |value|
    options[:m4_manifest] = File.expand_path(value)
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
  command_key = "RUBERNETES_M5_#{name.upcase}_COMMAND"
  report_key = "RUBERNETES_M5_#{name.upcase}_REPORT"
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
starting_input = M34EvidenceSupport.source_identity(M5Gate)
starting_git_metadata = M34EvidenceSupport.git_metadata_paths
commands = []
prior_milestones = {}

if options[:m4_manifest]
  begin
    m4_document, references = M34EvidenceSupport.copy_prior_bundle(options[:m4_manifest], File.join(directory, "m4"),
                                                                   File.join(ROOT, "tools/milestones/m4_gate.rb"), "m4_gate", M4Gate, commands)
    references.each do |milestone, reference|
      prior_milestones[milestone.upcase] = reference.merge(
        "manifest_path" => reference.fetch("manifest_path").delete_prefix("#{File.basename(directory)}/"),
        "gate_result_path" => reference.fetch("gate_result_path").delete_prefix("#{File.basename(directory)}/")
      )
    end
    prior_milestones["M4"]["input_sha256"] = m4_document["input_sha256"]
  rescue StandardError => error
    commands << M34EvidenceSupport.command_record("m4_gate", [RbConfig.ruby, "tools/milestones/m4_gate.rb", options[:m4_manifest]],
                                                  M34EvidenceSupport.now, M34EvidenceSupport.now, 1,
                                                  error: "prior evidence could not be copied or gated: #{error.class}: #{error.message}")
  end
else
  commands << M34EvidenceSupport.command_record("m4_gate", ["<missing M4 manifest: set RUBERNETES_M5_M4_MANIFEST or --m4-manifest>"],
                                                M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                error: "M5 requires COMPLETE M4 evidence from the same source input")
end

chain_ready = %w[M0 M1 M2 M3 M4].all? do |milestone|
  reference = prior_milestones[milestone]
  reference.is_a?(Hash) && reference["gate_passed"] == true &&
    reference["input_sha256"] == starting_input.fetch("sha256") &&
    reference["input_file_count"] == starting_input.fetch("file_count")
end

REPORT_SPECS.each do |name, specification|
  destination = File.join(directory, specification.fetch(:filename))
  if !chain_ready
    report = {
      "schema_version" => 1, "milestone" => "M5", "kind" => specification.fetch(:kind),
      "input_sha256" => starting_input.fetch("sha256"), "input_file_count" => starting_input.fetch("file_count"),
      "input_stable" => true, "status" => "INCOMPLETE", "passed" => false, "available" => false,
      "errors" => ["M5 probes were not run because COMPLETE M0 -> M4 evidence for the identical source input is unavailable"]
    }
    M34EvidenceSupport.write_json(destination, report)
    commands << M34EvidenceSupport.command_record("m5_#{name}", ["<not run: incomplete M0 -> M4 prerequisite chain>"],
                                                  M34EvidenceSupport.now, M34EvidenceSupport.now, 127, error: report.fetch("errors").first)
  elsif options[:commands].key?(name)
    command = M34EvidenceSupport.command_words(options[:commands].fetch(name))
    commands << if command.empty?
                  M34EvidenceSupport.command_record("m5_#{name}", ["<empty adapter command>"], M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                    error: "adapter command is empty")
                else
                  M34EvidenceSupport.run_command("m5_#{name}", command, destination, starting_input, env_prefix: "RUBERNETES_M5")
                end
  elsif options[:reports].key?(name)
    started = M34EvidenceSupport.now
    begin
      M34EvidenceSupport.copy_report(options[:reports].fetch(name), destination)
      commands << M34EvidenceSupport.command_record("m5_#{name}_report_copy", ["copy", options[:reports].fetch(name)], started,
                                                    M34EvidenceSupport.now, 0)
    rescue StandardError => error
      commands << M34EvidenceSupport.command_record("m5_#{name}_report_copy", ["copy", options[:reports].fetch(name)], started,
                                                    M34EvidenceSupport.now, 1, error: error.message)
    end
  else
    commands << M34EvidenceSupport.run_command("m5_#{name}", specification.fetch(:default), destination, starting_input,
                                               env_prefix: "RUBERNETES_M5")
  end
end

inventory = {
  "schema_version" => 1, "milestone" => "M5", "kind" => "m5_source_inventory",
  "input_sha256" => starting_input.fetch("sha256"), "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => true, "entries" => starting_input.fetch("entries")
}
M34EvidenceSupport.write_json(File.join(directory, "source-inventory.json"), inventory)

finished_input = M34EvidenceSupport.source_identity(M5Gate)
finished_git_metadata = M34EvidenceSupport.git_metadata_paths
input_stable = starting_input.fetch("sha256") == finished_input.fetch("sha256") && starting_input.fetch("file_count") == finished_input.fetch("file_count")
artifacts = M34EvidenceSupport.artifact_entries(directory)
manifest = {
  "schema_version" => 3,
  "milestone" => "M5",
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
if chain_ready && input_stable && starting_git_metadata == finished_git_metadata && commands.all? do |command|
  command["exit_status"] == 0
end
  manifest["status"] =
    "COMPLETE"
end
manifest_path = File.join(directory, "manifest.json")
M34EvidenceSupport.write_json(manifest_path, manifest)

stdout, stderr, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m5_gate.rb"), manifest_path, chdir: ROOT)
$stdout.write(stdout)
$stderr.write(stderr)
unless status.success?
  manifest["status"] = "INCOMPLETE"
  M34EvidenceSupport.write_json(manifest_path, manifest)
  final_stdout, final_stderr, final_status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m5_gate.rb"), manifest_path,
                                                            chdir: ROOT)
  $stdout.write(final_stdout) unless final_stdout == stdout
  $stderr.write(final_stderr) unless final_stderr == stderr
  exit(final_status.exitstatus || 1)
end
exit(0)
