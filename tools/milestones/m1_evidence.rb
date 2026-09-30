#!/usr/bin/env ruby
# frozen_string_literal: true

# Capture the content-addressed evidence bundle for Milestone M1.
#
# The runner intentionally delegates schema, API, and kubectl execution to
# commands supplied by the caller. No guessed command is run: an absent adapter
# becomes an explicit failed command and the resulting bundle cannot pass M1.

require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "shellwords"
require "time"

require_relative "m1_gate"

ROOT = File.expand_path("../..", __dir__)
# Keep the temporary generator exclusion anchored to a root-level mktemp name;
# broad prefixes would let a real source directory disappear from the input.
SOURCE_EXCLUSIONS = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}
REPORT_SPECS = {
  "corpus" => {filename: "corpus-coverage.json", kind: "m1_corpus_coverage"},
  "generation" => {filename: "generation-diff.json", kind: "m1_generation_diff"},
  "roundtrip" => {filename: "roundtrip-report.json", kind: "m1_roundtrip_report"},
  "api" => {filename: "api-differential.json", kind: "m1_api_differential"},
  "kubectl" => {filename: "kubectl-transcript.json", kind: "m1_kubectl_transcript"}
}.freeze

def source_identity
  paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
    next false unless File.file?(path)

    relative = path.delete_prefix("#{ROOT}/")
    !relative.match?(SOURCE_EXCLUSIONS)
  end.sort
  entries = paths.map do |path|
    {
      "path" => path.delete_prefix("#{ROOT}/"),
      "sha256" => Digest::SHA256.file(path).hexdigest,
      "bytes" => File.size(path)
    }
  end
  {
    "sha256" => M1Gate.canonical_inventory_digest(entries),
    "file_count" => entries.length,
    "entries" => entries
  }
end

def git_metadata_paths
  Dir.glob(File.join(ROOT, "**/.git"), File::FNM_DOTMATCH).map do |path|
    path.delete_prefix("#{ROOT}/")
  end.sort
end

def iso8601_now
  Time.now.utc.iso8601(6)
end

def command_words(value)
  Shellwords.split(value.to_s)
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

def copy_report(source_path, destination_path)
  raise "report path does not exist: #{source_path}" unless File.file?(source_path)

  File.binwrite(destination_path, File.binread(source_path))
end

def capture_command(name, command, destination_path, input)
  started_at = iso8601_now
  environment = {
    "RUBERNETES_M1_INPUT_SHA256" => input.fetch("sha256"),
    "RUBERNETES_M1_INPUT_FILE_COUNT" => input.fetch("file_count").to_s
  }
  stdout, stderr, status = Open3.capture3(environment, *command, chdir: ROOT)
  finished_at = iso8601_now
  File.binwrite(destination_path, stdout)
  command_record(
    name,
    command,
    started_at,
    finished_at,
    status.exitstatus || 1,
    stdout: stdout,
    stderr: stderr
  )
rescue SystemCallError => error
  finished_at = iso8601_now
  command_record(
    name,
    command,
    started_at,
    finished_at,
    127,
    error: "adapter command could not be executed: #{error.message}"
  )
end

options = {
  run_id: Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"),
  output_root: File.join(ROOT, "artifacts/milestones/M1"),
  m0_manifest: ENV.fetch("RUBERNETES_M1_M0_MANIFEST", nil),
  reports: {},
  commands: {}
}
OptionParser.new do |parser|
  parser.banner = "Usage: m1_evidence.rb [options]"
  parser.on("--run-id ID", "evidence run identifier") { |value| options[:run_id] = value }
  parser.on("--output-root PATH", "milestone evidence root") { |value| options[:output_root] = File.expand_path(value) }
  parser.on("--m0-manifest PATH", "copy and verify COMPLETE M0 evidence for the same source input") do |value|
    options[:m0_manifest] = File.expand_path(value)
  end
  REPORT_SPECS.each_key do |name|
    parser.on("--#{name}-report PATH", "copy a machine-readable #{name} report") do |value|
      options[:reports][name] = File.expand_path(value)
    end
    parser.on("--#{name}-command COMMAND", "run the #{name} adapter and read JSON from stdout") { |value| options[:commands][name] = value }
  end
end.parse!(ARGV)

REPORT_SPECS.each_key do |name|
  command_environment_key = "RUBERNETES_M1_#{name.upcase}_COMMAND"
  report_environment_key = "RUBERNETES_M1_#{name.upcase}_REPORT"
  options[:commands][name] = ENV.fetch(command_environment_key) if ENV.key?(command_environment_key) && !options[:commands].key?(name)
  options[:reports][name] = File.expand_path(ENV.fetch(report_environment_key)) if ENV.key?(report_environment_key) &&
                                                                                   !options[:commands].key?(name) && !options[:reports].key?(name)
end

abort "run ID may contain only letters, digits, dot, underscore, and hyphen" unless options[:run_id].match?(/\A[0-9A-Za-z._-]+\z/)

directory = File.join(options[:output_root], options[:run_id])
FileUtils.mkdir_p(directory)
started_at = iso8601_now
starting_input = source_identity
starting_git_metadata = git_metadata_paths
commands = []
prior_milestones = {}

if options[:m0_manifest]
  prior_started = iso8601_now
  begin
    source_manifest = File.realpath(options[:m0_manifest])
    source_directory = File.dirname(source_manifest)
    prior_directory = File.join(directory, "m0")
    FileUtils.mkdir_p(prior_directory)
    FileUtils.cp_r(File.join(source_directory, "."), prior_directory, preserve: true)
    copied_manifest = File.join(prior_directory, File.basename(source_manifest))
    gate_stdout, gate_stderr, gate_status = Open3.capture3(
      RbConfig.ruby,
      File.join(ROOT, "tools/milestones/m0_gate.rb"),
      copied_manifest,
      chdir: ROOT
    )
    gate_result_path = File.join(prior_directory, "gate-result.json")
    File.binwrite(gate_result_path, gate_stdout)
    commands << command_record(
      "m0_gate",
      [RbConfig.ruby, "tools/milestones/m0_gate.rb", "m0/manifest.json"],
      prior_started,
      iso8601_now,
      gate_status.exitstatus || 1,
      stdout: gate_stdout,
      stderr: gate_stderr
    )
    prior_document = JSON.parse(File.binread(copied_manifest), max_nesting: 100)
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
      prior_started,
      iso8601_now,
      1,
      error: "M0 evidence could not be copied or validated: #{error.class}: #{error.message}"
    )
  end
else
  commands << command_record(
    "m0_gate",
    ["<missing M0 manifest: set RUBERNETES_M1_M0_MANIFEST or --m0-manifest>"],
    iso8601_now,
    iso8601_now,
    127,
    error: "M1 requires COMPLETE privileged M0 evidence from the same source input"
  )
end

REPORT_SPECS.each do |name, specification|
  destination = File.join(directory, specification.fetch(:filename))
  if options[:commands].key?(name)
    command = command_words(options[:commands].fetch(name))
    commands << if command.empty?
                  command_record(
                    "m1_#{name}",
                    ["<empty adapter command>"],
                    iso8601_now,
                    iso8601_now,
                    127,
                    error: "adapter command is empty"
                  )
                else
                  capture_command("m1_#{name}", command, destination, starting_input)
                end
  elsif options[:reports].key?(name)
    copy_started = iso8601_now
    begin
      copy_report(options[:reports].fetch(name), destination)
      commands << command_record(
        "m1_#{name}_report_copy",
        ["copy", options[:reports].fetch(name)],
        copy_started,
        iso8601_now,
        0
      )
    rescue StandardError => error
      commands << command_record(
        "m1_#{name}_report_copy",
        ["copy", options[:reports].fetch(name)],
        copy_started,
        iso8601_now,
        1,
        error: error.message
      )
    end
  else
    commands << command_record(
      "m1_#{name}",
      ["<missing adapter:#{name}>"],
      iso8601_now,
      iso8601_now,
      127,
      error: "no adapter command or report was supplied"
    )
  end
end

inventory_path = File.join(directory, "source-inventory.json")
inventory_document = {
  "schema_version" => 1,
  "kind" => "m1_source_inventory",
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
  name = path.delete_prefix("#{directory}/")
  next unless File.file?(path)

  {"path" => name, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
end.compact

uname = Etc.uname
manifest = {
  "schema_version" => 3,
  "milestone" => "M1",
  "run_id" => options[:run_id],
  "status" => "INCOMPLETE",
  "host" => {
    "architecture" => RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64").sub("amd64", "x86_64"),
    "kernel" => uname.fetch(:release),
    "sysname" => uname.fetch(:sysname),
    "ruby" => RUBY_DESCRIPTION
  },
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => input_stable,
  "input_capture" => {
    "stable" => input_stable,
    "start" => {
      "sha256" => starting_input.fetch("sha256"),
      "file_count" => starting_input.fetch("file_count")
    },
    "finish" => {
      "sha256" => finished_input.fetch("sha256"),
      "file_count" => finished_input.fetch("file_count")
    }
  },
  "git_metadata_capture" => {
    "stable" => starting_git_metadata == finished_git_metadata,
    "start_paths" => starting_git_metadata,
    "finish_paths" => finished_git_metadata,
    "count" => (starting_git_metadata | finished_git_metadata).length
  },
  "started_at" => started_at,
  "finished_at" => iso8601_now,
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

manifest_path = File.join(directory, "manifest.json")
File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")

# Let the gate decide whether report semantics are complete. If a report is
# malformed or incomplete, rewrite the manifest as INCOMPLETE so the artifact
# cannot accidentally claim completion even when inspected without the gate.
manifest["status"] = "COMPLETE"
File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
candidate = M1Gate.evaluate(manifest_path)
unless candidate.fetch("passed")
  manifest["status"] = "INCOMPLETE"
  File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
end

gate_stdout, gate_stderr, gate_status = Open3.capture3(
  RbConfig.ruby,
  File.join(ROOT, "tools/milestones/m1_gate.rb"),
  manifest_path,
  chdir: ROOT
)
$stdout.write(gate_stdout)
$stderr.write(gate_stderr)
exit(gate_status.exitstatus)
