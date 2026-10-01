#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture the content-addressed evidence bundle for Milestone M2.
#
# Every adapter is explicit. The default adapters are deliberately fail-closed
# probes, so an environment without a real Native Runtime cannot accidentally
# produce a successful M2 bundle.

require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "shellwords"
require "time"

require_relative "m2_gate"

ROOT = File.expand_path("../..", __dir__) unless defined?(ROOT)
# Keep the temporary generator exclusion anchored to a root-level mktemp name;
# broad prefixes would let a real source directory disappear from the input.
unless defined?(SOURCE_EXCLUSIONS)
  SOURCE_EXCLUSIONS = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}
end
REPORT_SPECS = {
  "runtime" => {filename: "runtime-report.json", kind: "m2_runtime_profiles",
                default: [RbConfig.ruby, "tools/milestones/m2_runtime_probe.rb"]},
  "attacks" => {filename: "oci-attack-corpus.json", kind: "m2_oci_attack_corpus",
                default: [RbConfig.ruby, "tools/milestones/m2_attack_probe.rb"]},
  "lifecycle" => {filename: "pod-lifecycle-trace.json", kind: "m2_pod_lifecycle_trace",
                  default: [RbConfig.ruby, "tools/milestones/m2_lifecycle_probe.rb"]},
  "ledger" => {filename: "resource-ledger.json", kind: "m2_resource_ledger",
               default: [RbConfig.ruby, "tools/milestones/m2_ledger_probe.rb"]},
  "kernel" => {filename: "kernel-inventory.json", kind: "m2_kernel_inventory",
               default: [RbConfig.ruby, "tools/milestones/m2_kernel_probe.rb"]}
}.freeze
FORMAL_REPORT_SPEC = {
  filename: "formal-report.json",
  kind: "m2_formal_verification",
  default: [RbConfig.ruby, "tools/verification/m2_formal_verify.rb"]
}.freeze

def source_identity
  paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
    next false unless File.file?(path)

    !path.delete_prefix("#{ROOT}/").match?(SOURCE_EXCLUSIONS)
  end.sort
  entries = paths.map do |path|
    {
      "path" => path.delete_prefix("#{ROOT}/"),
      "sha256" => Digest::SHA256.file(path).hexdigest,
      "bytes" => File.size(path)
    }
  end
  {
    "sha256" => M2Gate.canonical_inventory_digest(entries),
    "file_count" => entries.length,
    "entries" => entries
  }
end

def git_metadata_paths
  Dir.glob(File.join(ROOT, "**/.git"), File::FNM_DOTMATCH).map { |path| path.delete_prefix("#{ROOT}/") }.sort
end

def iso8601_now
  Time.now.utc.iso8601(6)
end

def command_words(value)
  value.is_a?(Array) ? value : Shellwords.split(value.to_s)
rescue ArgumentError => error
  raise OptionParser::InvalidArgument, "invalid command: #{error.message}"
end

def command_record(name, command, started_at, finished_at, status, stdout: "", stderr: "", error: nil)
  record = {
    "name" => name,
    "command" => command,
    "started_at" => started_at,
    "finished_at" => finished_at,
    "exit_status" => status,
    "stdout" => stdout,
    "stderr" => stderr
  }
  record["error"] = error if error
  record
end

EMBEDDED_STDOUT_LIMIT = 4 * 1024 * 1024

def capture_command(name, command, destination_path, input)
  started_at = iso8601_now
  environment = {
    "RUBERNETES_M2_INPUT_SHA256" => input.fetch("sha256"),
    "RUBERNETES_M2_INPUT_FILE_COUNT" => input.fetch("file_count").to_s
  }
  stdout, stderr, status = Open3.capture3(environment, *command, chdir: ROOT)
  File.binwrite(destination_path, stdout)
  record = command_record(name, command, started_at, iso8601_now, status.exitstatus || 1, stdout: stdout, stderr: stderr)
  # The adapter report is the content-addressed artifact; a very large
  # report (the 1,000-cycle resource ledger) is referenced by digest instead
  # of being embedded a second time, so the manifest stays within the gate's
  # JSON limit.
  if stdout.bytesize > EMBEDDED_STDOUT_LIMIT
    record["stdout"] = ""
    record["stdout_sha256"] = Digest::SHA256.hexdigest(stdout)
    record["stdout_bytes"] = stdout.bytesize
    record["stdout_artifact"] = File.basename(destination_path)
  end
  record
rescue SystemCallError => error
  command_record(name, command, started_at, iso8601_now, 127, error: "adapter command could not be executed: #{error.message}")
end

def copy_report(source_path, destination_path)
  raise "report path does not exist: #{source_path}" unless File.file?(source_path)

  FileUtils.cp(source_path, destination_path)
end

def copy_tree(source_path, destination_directory)
  FileUtils.mkdir_p(destination_directory)
  FileUtils.cp_r(File.join(source_path, "."), destination_directory, preserve: true)
end

def formal_runtime_claim?(report_path)
  return false unless File.file?(report_path)

  document = JSON.parse(File.binread(report_path), max_nesting: 512)
  claims = document["formal_claims"]
  claims.is_a?(Array) && claims.include?("RuntimeLifecycle")
rescue JSON::ParserError, Errno::ENOENT, Errno::EACCES
  false
end

def prior_reference(document, prefix, name)
  reference = document.dig("prior_milestones", name)
  return nil unless reference.is_a?(Hash)

  reference.merge(
    "manifest_path" => File.join(prefix, reference.fetch("manifest_path")),
    "gate_result_path" => File.join(prefix, reference.fetch("gate_result_path"))
  )
end

options = {
  run_id: Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"),
  output_root: File.join(ROOT, "artifacts/milestones/M2"),
  m0_manifest: ENV.fetch("RUBERNETES_M2_M0_MANIFEST", nil),
  m1_manifest: ENV.fetch("RUBERNETES_M2_M1_MANIFEST", nil),
  reports: {},
  formal_report: nil,
  formal_command: nil,
  commands: {}
}
OptionParser.new do |parser|
  parser.banner = "Usage: m2_evidence.rb [options]"
  parser.on("--run-id ID", "evidence run identifier") { |value| options[:run_id] = value }
  parser.on("--output-root PATH", "milestone evidence root") { |value| options[:output_root] = File.expand_path(value) }
  parser.on("--m0-manifest PATH", "copy and verify COMPLETE M0 evidence") { |value| options[:m0_manifest] = File.expand_path(value) }
  parser.on("--m1-manifest PATH", "copy and verify COMPLETE M1 evidence for the same input") do |value|
    options[:m1_manifest] = File.expand_path(value)
  end
  REPORT_SPECS.each_key do |name|
    parser.on("--#{name}-report PATH", "copy a machine-readable #{name} report") do |value|
      options[:reports][name] = File.expand_path(value)
    end
    parser.on("--#{name}-command COMMAND", "run the #{name} adapter and read JSON from stdout") { |value| options[:commands][name] = value }
  end
  parser.on("--formal-report PATH", "copy a RuntimeLifecycle formal verification report") do |value|
    options[:formal_report] = File.expand_path(value)
  end
  parser.on("--formal-command COMMAND", "run the RuntimeLifecycle formal verifier") { |value| options[:formal_command] = value }
end.parse!(ARGV)

REPORT_SPECS.each_key do |name|
  command_key = "RUBERNETES_M2_#{name.upcase}_COMMAND"
  report_key = "RUBERNETES_M2_#{name.upcase}_REPORT"
  options[:commands][name] = ENV.fetch(command_key) if ENV.key?(command_key) && !options[:commands].key?(name)
  if ENV.key?(report_key) && !options[:commands].key?(name) && !options[:reports].key?(name)
    options[:reports][name] =
      File.expand_path(ENV.fetch(report_key))
  end
end
options[:formal_command] = ENV.fetch("RUBERNETES_M2_FORMAL_COMMAND") if
  ENV.key?("RUBERNETES_M2_FORMAL_COMMAND") && !options[:formal_command]
options[:formal_report] = File.expand_path(ENV.fetch("RUBERNETES_M2_FORMAL_REPORT")) if
  ENV.key?("RUBERNETES_M2_FORMAL_REPORT") && !options[:formal_command] && !options[:formal_report]

abort "run ID may contain only letters, digits, dot, underscore, and hyphen" unless options[:run_id].match?(/\A[0-9A-Za-z._-]+\z/)

directory = File.join(options[:output_root], options[:run_id])
FileUtils.mkdir_p(directory)
started_at = iso8601_now
starting_input = source_identity
starting_git_metadata = git_metadata_paths
commands = []
prior_milestones = {}

# Copy M1 as a complete subtree. This preserves M1's own M0 copy and lets the
# M2 gate verify every nested artifact by digest rather than trusting a path.
if options[:m1_manifest]
  m1_started = iso8601_now
  begin
    source_manifest = File.realpath(options[:m1_manifest])
    source_directory = File.dirname(source_manifest)
    copy_tree(source_directory, File.join(directory, "m1"))
    copied_manifest = File.join(directory, "m1", File.basename(source_manifest))
    gate_stdout, gate_stderr, gate_status = Open3.capture3(
      RbConfig.ruby,
      File.join(ROOT, "tools/milestones/m1_gate.rb"),
      copied_manifest,
      chdir: ROOT
    )
    gate_result_path = File.join(directory, "m1", "gate-result.json")
    File.binwrite(gate_result_path, gate_stdout)
    commands << command_record(
      "m1_gate",
      [RbConfig.ruby, "tools/milestones/m1_gate.rb", "m1/#{File.basename(copied_manifest)}"],
      m1_started,
      iso8601_now,
      gate_status.exitstatus || 1,
      stdout: gate_stdout,
      stderr: gate_stderr
    )
    prior_document = JSON.parse(File.binread(copied_manifest), max_nesting: 512)
    prior_milestones["M1"] = {
      "manifest_path" => "m1/#{File.basename(copied_manifest)}",
      "manifest_sha256" => Digest::SHA256.file(copied_manifest).hexdigest,
      "gate_result_path" => "m1/gate-result.json",
      "gate_result_sha256" => Digest::SHA256.file(gate_result_path).hexdigest,
      "input_sha256" => prior_document["input_sha256"],
      "input_file_count" => prior_document["input_file_count"],
      "gate_passed" => gate_status.success?
    }
    m0_reference = prior_reference(prior_document, "m1", "M0")
    prior_milestones["M0"] = m0_reference if m0_reference
  rescue StandardError => error
    commands << command_record(
      "m1_gate",
      [RbConfig.ruby, "tools/milestones/m1_gate.rb", options[:m1_manifest].to_s],
      m1_started,
      iso8601_now,
      1,
      error: "M1 evidence could not be copied or validated: #{error.class}: #{error.message}"
    )
  end
else
  commands << command_record(
    "m1_gate",
    ["<missing M1 manifest: set RUBERNETES_M2_M1_MANIFEST or --m1-manifest>"],
    iso8601_now,
    iso8601_now,
    127,
    error: "M2 requires COMPLETE M1 evidence from the same source input"
  )
end

# A direct M0 path is useful when preparing the cumulative chain before M1 is
# copied. It is ignored when M1 already carries the content-addressed M0.
if options[:m0_manifest] && !prior_milestones.key?("M0")
  m0_started = iso8601_now
  begin
    source_manifest = File.realpath(options[:m0_manifest])
    source_directory = File.dirname(source_manifest)
    copy_tree(source_directory, File.join(directory, "m0"))
    copied_manifest = File.join(directory, "m0", File.basename(source_manifest))
    gate_stdout, gate_stderr, gate_status = Open3.capture3(
      RbConfig.ruby,
      File.join(ROOT, "tools/milestones/m0_gate.rb"),
      copied_manifest,
      chdir: ROOT
    )
    gate_result_path = File.join(directory, "m0", "gate-result.json")
    File.binwrite(gate_result_path, gate_stdout)
    commands << command_record(
      "m0_gate",
      [RbConfig.ruby, "tools/milestones/m0_gate.rb", "m0/#{File.basename(copied_manifest)}"],
      m0_started,
      iso8601_now,
      gate_status.exitstatus || 1,
      stdout: gate_stdout,
      stderr: gate_stderr
    )
    prior_document = JSON.parse(File.binread(copied_manifest), max_nesting: 512)
    prior_milestones["M0"] = {
      "manifest_path" => "m0/#{File.basename(copied_manifest)}",
      "manifest_sha256" => Digest::SHA256.file(copied_manifest).hexdigest,
      "gate_result_path" => "m0/gate-result.json",
      "gate_result_sha256" => Digest::SHA256.file(gate_result_path).hexdigest,
      "input_sha256" => prior_document["input_sha256"],
      "input_file_count" => prior_document["input_file_count"],
      "gate_passed" => gate_status.success?
    }
  rescue StandardError => error
    commands << command_record(
      "m0_gate",
      [RbConfig.ruby, "tools/milestones/m0_gate.rb", options[:m0_manifest].to_s],
      m0_started,
      iso8601_now,
      1,
      error: "M0 evidence could not be copied or validated: #{error.class}: #{error.message}"
    )
  end
end

chain_ready = %w[M0 M1].all? do |milestone|
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
      "milestone" => "M2",
      "kind" => specification.fetch(:kind),
      "input_sha256" => starting_input.fetch("sha256"),
      "input_file_count" => starting_input.fetch("file_count"),
      "input_stable" => true,
      "status" => "INCOMPLETE",
      "passed" => false,
      "errors" => ["M2 probes were not run because the COMPLETE M0 -> M1 prerequisite chain is unavailable"]
    }
    File.write(destination, JSON.pretty_generate(report) << "\n")
    commands << command_record(
      "m2_#{name}",
      ["<not run: incomplete M0 -> M1 prerequisite chain>"],
      iso8601_now,
      iso8601_now,
      127,
      error: report.fetch("errors").first
    )
  elsif options[:commands].key?(name)
    command = command_words(options[:commands].fetch(name))
    commands << if command.empty?
                  command_record("m2_#{name}", ["<empty adapter command>"], iso8601_now, iso8601_now, 127,
                                 error: "adapter command is empty")
                else
                  capture_command("m2_#{name}", command, destination, starting_input)
                end
  elsif options[:reports].key?(name)
    copy_started = iso8601_now
    begin
      copy_report(options[:reports].fetch(name), destination)
      commands << command_record("m2_#{name}_report_copy", ["copy", options[:reports].fetch(name)], copy_started, iso8601_now, 0)
    rescue StandardError => error
      commands << command_record("m2_#{name}_report_copy", ["copy", options[:reports].fetch(name)], copy_started, iso8601_now, 1,
                                 error: error.message)
    end
  else
    commands << capture_command("m2_#{name}", specification.fetch(:default), destination, starting_input)
  end
end

formal_report_path = File.join(directory, FORMAL_REPORT_SPEC.fetch(:filename))
lifecycle_report_path = File.join(directory, REPORT_SPECS.fetch("lifecycle").fetch(:filename))
formal_claimed = formal_runtime_claim?(lifecycle_report_path)
formal_requested = false
if formal_claimed
  formal_requested = true
  if options[:formal_command]
    command = command_words(options.fetch(:formal_command))
    command += ["--trace", lifecycle_report_path] unless command.include?("--trace")
    commands << if command.empty?
                  command_record("m2_formal", ["<empty formal command>"], iso8601_now, iso8601_now, 127,
                                 error: "formal command is empty")
                else
                  capture_command("m2_formal", command, formal_report_path, starting_input)
                end
  elsif options[:formal_report]
    copy_started = iso8601_now
    begin
      copy_report(options.fetch(:formal_report), formal_report_path)
      commands << command_record("m2_formal_report_copy", ["copy", options.fetch(:formal_report)], copy_started, iso8601_now, 0)
    rescue StandardError => error
      commands << command_record("m2_formal_report_copy", ["copy", options.fetch(:formal_report)], copy_started, iso8601_now, 1,
                                 error: error.message)
    end
  else
    command = FORMAL_REPORT_SPEC.fetch(:default) + ["--trace", lifecycle_report_path]
    commands << capture_command("m2_formal", command, formal_report_path, starting_input)
  end
end

inventory_path = File.join(directory, "source-inventory.json")
inventory_document = {
  "schema_version" => 1,
  "milestone" => "M2",
  "kind" => "m2_source_inventory",
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => true,
  "entries" => starting_input.fetch("entries")
}
File.write(inventory_path, JSON.pretty_generate(inventory_document) << "\n")

finished_input = source_identity
finished_git_metadata = git_metadata_paths
input_stable = starting_input.fetch("sha256") == finished_input.fetch("sha256") &&
               starting_input.fetch("file_count") == finished_input.fetch("file_count")
artifact_paths = Dir.glob(File.join(directory, "**/*"), File::FNM_DOTMATCH).select do |path|
  File.file?(path) && path != File.join(directory, "manifest.json")
end.sort
artifacts = artifact_paths.map do |path|
  {"path" => path.delete_prefix("#{directory}/"), "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
end

uname = Etc.uname
identity = {"sha256" => starting_input.fetch("sha256"), "file_count" => starting_input.fetch("file_count")}
manifest = {
  "schema_version" => 3,
  "milestone" => "M2",
  "run_id" => options[:run_id],
  "status" => "INCOMPLETE",
  "host" => {
    "architecture" => RbConfig::CONFIG.fetch("host_cpu").sub("amd64", "x86_64").sub("arm64", "aarch64"),
    "kernel" => uname.fetch(:release),
    "sysname" => uname.fetch(:sysname),
    "ruby" => RUBY_DESCRIPTION
  },
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => input_stable,
  "input_capture" => {"stable" => input_stable, "start" => identity,
                      "finish" => {"sha256" => finished_input.fetch("sha256"), "file_count" => finished_input.fetch("file_count")}},
  "git_metadata_capture" => {"stable" => starting_git_metadata == finished_git_metadata, "start_paths" => starting_git_metadata,
                             "finish_paths" => finished_git_metadata, "count" => (starting_git_metadata | finished_git_metadata).length},
  "started_at" => started_at,
  "finished_at" => iso8601_now,
  "commands" => commands,
  "prior_milestones" => prior_milestones,
  "result_counts" => {"commands" => commands.length, "command_failures" => commands.count do |command|
    command.fetch("exit_status") != 0
  end, "artifacts" => artifacts.length, "subjects" => 0, "reports" => REPORT_SPECS.length + (formal_requested && File.file?(formal_report_path) ? 1 : 0),
                      "source_files" => starting_input.fetch("file_count")},
  "artifacts" => artifacts,
  "subjects" => []
}

manifest_path = File.join(directory, "manifest.json")
File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
manifest["status"] = "COMPLETE"
File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
candidate = M2Gate.evaluate(manifest_path)
unless candidate.fetch("passed")
  manifest["status"] = "INCOMPLETE"
  File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
end

gate_stdout, gate_stderr, gate_status = Open3.capture3(RbConfig.ruby, File.join(ROOT, "tools/milestones/m2_gate.rb"), manifest_path,
                                                       chdir: ROOT)
$stdout.write(gate_stdout)
$stderr.write(gate_stderr)
exit(gate_status.exitstatus)
