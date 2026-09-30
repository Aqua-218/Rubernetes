#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture the cumulative, content-addressed M6 complete-API-surface evidence bundle.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"

require_relative "m6_gate"
require_relative "m3_evidence_support"

ROOT = M34EvidenceSupport::ROOT
REPORT_SPECS = {
  "api_coverage" => {filename: "api-coverage-ledger.json", kind: "m6_api_coverage_ledger",
                     default: [RbConfig.ruby, "tools/milestones/m6_api_coverage_probe.rb"]},
  "feature_gate" => {filename: "feature-gate-matrix.json", kind: "m6_feature_gate_matrix",
                     default: [RbConfig.ruby, "tools/milestones/m6_feature_gate_probe.rb"]},
  "crd" => {filename: "crd-aggregation-differential.json", kind: "m6_crd_aggregation_differential",
            default: [RbConfig.ruby, "tools/milestones/m6_crd_differential_probe.rb"]},
  "webhook" => {filename: "webhook-differential.json", kind: "m6_webhook_differential",
                default: [RbConfig.ruby, "tools/milestones/m6_webhook_differential_probe.rb"]},
  "security" => {filename: "security-pipeline-trace.json", kind: "m6_security_pipeline_trace",
                 default: [RbConfig.ruby, "tools/milestones/m6_security_pipeline_probe.rb"]},
  "fuzz" => {filename: "fuzz-summary.json", kind: "m6_fuzz_summary", default: [RbConfig.ruby, "tools/milestones/m6_fuzz_probe.rb"]}
}.freeze

options = {
  run_id: Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"),
  output_root: File.join(ROOT, "artifacts/milestones/M6"),
  m5_manifest: ENV.fetch("RUBERNETES_M6_M5_MANIFEST", nil),
  reports: {},
  commands: {}
}

OptionParser.new do |parser|
  parser.banner = "Usage: m6_evidence.rb [options]"
  parser.on("--run-id ID", "evidence run identifier") { |value| options[:run_id] = value }
  parser.on("--output-root PATH", "milestone evidence root") { |value| options[:output_root] = File.expand_path(value) }
  parser.on("--m5-manifest PATH", "copy and verify COMPLETE M5 evidence for the same input") do |value|
    options[:m5_manifest] = File.expand_path(value)
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
  command_key = "RUBERNETES_M6_#{name.upcase}_COMMAND"
  report_key = "RUBERNETES_M6_#{name.upcase}_REPORT"
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
starting_input = M34EvidenceSupport.source_identity(M6Gate)
starting_git_metadata = M34EvidenceSupport.git_metadata_paths
commands = []
prior_milestones = {}

if options[:m5_manifest]
  begin
    m5_document, references = M34EvidenceSupport.copy_prior_bundle(options[:m5_manifest], File.join(directory, "m5"),
                                                                   File.join(ROOT, "tools/milestones/m5_gate.rb"), "m5_gate", M5Gate, commands)
    references.each do |milestone, reference|
      prior_milestones[milestone.upcase] = reference.merge(
        "manifest_path" => reference.fetch("manifest_path").delete_prefix("#{File.basename(directory)}/"),
        "gate_result_path" => reference.fetch("gate_result_path").delete_prefix("#{File.basename(directory)}/")
      )
    end
    prior_milestones["M5"]["input_sha256"] = m5_document["input_sha256"]
  rescue StandardError => error
    commands << M34EvidenceSupport.command_record("m5_gate", [RbConfig.ruby, "tools/milestones/m5_gate.rb", options[:m5_manifest]],
                                                  M34EvidenceSupport.now, M34EvidenceSupport.now, 1,
                                                  error: "prior evidence could not be copied or gated: #{error.class}: #{error.message}")
  end
else
  commands << M34EvidenceSupport.command_record("m5_gate", ["<missing M5 manifest: set RUBERNETES_M6_M5_MANIFEST or --m5-manifest>"],
                                                M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                error: "M6 requires COMPLETE M5 evidence from the same source input")
end

chain_ready = %w[M0 M1 M2 M3 M4 M5].all? do |milestone|
  reference = prior_milestones[milestone]
  reference.is_a?(Hash) && reference["gate_passed"] == true &&
    reference["input_sha256"] == starting_input.fetch("sha256") &&
    reference["input_file_count"] == starting_input.fetch("file_count")
end

REPORT_SPECS.each do |name, specification|
  destination = File.join(directory, specification.fetch(:filename))
  if !chain_ready
    report = {
      "schema_version" => 1, "milestone" => "M6", "kind" => specification.fetch(:kind),
      "input_sha256" => starting_input.fetch("sha256"), "input_file_count" => starting_input.fetch("file_count"),
      "input_stable" => true, "status" => "INCOMPLETE", "passed" => false, "available" => false,
      "errors" => ["M6 probes were not run because COMPLETE M0 -> M5 evidence for the identical source input is unavailable"]
    }
    M34EvidenceSupport.write_json(destination, report)
    commands << M34EvidenceSupport.command_record("m6_#{name}", ["<not run: incomplete M0 -> M5 prerequisite chain>"],
                                                  M34EvidenceSupport.now, M34EvidenceSupport.now, 127, error: report.fetch("errors").first)
  elsif options[:commands].key?(name)
    command = M34EvidenceSupport.command_words(options[:commands].fetch(name))
    commands << if command.empty?
                  M34EvidenceSupport.command_record("m6_#{name}", ["<empty adapter command>"], M34EvidenceSupport.now, M34EvidenceSupport.now, 127,
                                                    error: "adapter command is empty")
                else
                  M34EvidenceSupport.run_command("m6_#{name}", command, destination, starting_input, env_prefix: "RUBERNETES_M6")
                end
  elsif options[:reports].key?(name)
    started = M34EvidenceSupport.now
    begin
      M34EvidenceSupport.copy_report(options[:reports].fetch(name), destination)
      commands << M34EvidenceSupport.command_record("m6_#{name}_report_copy", ["copy", options[:reports].fetch(name)], started,
                                                    M34EvidenceSupport.now, 0)
    rescue StandardError => error
      commands << M34EvidenceSupport.command_record("m6_#{name}_report_copy", ["copy", options[:reports].fetch(name)], started,
                                                    M34EvidenceSupport.now, 1, error: error.message)
    end
  else
    commands << M34EvidenceSupport.run_command("m6_#{name}", specification.fetch(:default), destination, starting_input,
                                               env_prefix: "RUBERNETES_M6")
  end
end

inventory = {
  "schema_version" => 1, "milestone" => "M6", "kind" => "m6_source_inventory",
  "input_sha256" => starting_input.fetch("sha256"), "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => true, "entries" => starting_input.fetch("entries")
}
M34EvidenceSupport.write_json(File.join(directory, "source-inventory.json"), inventory)

finished_input = M34EvidenceSupport.source_identity(M6Gate)
finished_git_metadata = M34EvidenceSupport.git_metadata_paths
input_stable = starting_input.fetch("sha256") == finished_input.fetch("sha256") && starting_input.fetch("file_count") == finished_input.fetch("file_count")
artifacts = M34EvidenceSupport.artifact_entries(directory)
manifest = {
  "schema_version" => 3,
  "milestone" => "M6",
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

stdout, stderr, status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m6_gate.rb"), manifest_path, chdir: ROOT)
$stdout.write(stdout)
$stderr.write(stderr)
unless status.success?
  manifest["status"] = "INCOMPLETE"
  M34EvidenceSupport.write_json(manifest_path, manifest)
  final_stdout, final_stderr, final_status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m6_gate.rb"), manifest_path,
                                                            chdir: ROOT)
  $stdout.write(final_stdout) unless final_stdout == stdout
  $stderr.write(final_stderr) unless final_stderr == stderr
  exit(final_status.exitstatus || 1)
end
exit(0)
