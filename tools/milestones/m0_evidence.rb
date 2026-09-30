#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "time"
require_relative "m0_source_inventory"

ROOT = File.expand_path("../..", __dir__)
EXECUTABLES = %w[
  rubectl
  rubernetes-apiserver
  rubernetes-controller-manager
  rubernetes-scheduler
  rubernetes-agent
  rubernetes-proxy
].freeze
def source_inventory
  paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
    next false unless regular_source_file?(path)

    relative = path.delete_prefix("#{ROOT}/")
    !M0SourceInventory.excluded?(relative)
  end.sort
  entries = paths.map do |path|
    {
      "path" => path.delete_prefix("#{ROOT}/"),
      "sha256" => Digest::SHA256.file(path).hexdigest,
      "bytes" => File.size(path)
    }
  end
  content = entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
  {
    "sha256" => Digest::SHA256.hexdigest(content),
    "file_count" => entries.length,
    "entries" => entries
  }
end

def regular_source_file?(path)
  return false unless File.lstat(path).file?

  current = ROOT
  return false if File.symlink?(current)

  path.delete_prefix("#{ROOT}/").split("/").each do |component|
    next if component.empty? || component == "."

    current = File.join(current, component)
    return false if File.lstat(current).symlink?
  end
  true
rescue Errno::ENOENT
  false
end

options = {
  run_id: Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ"),
  output_root: File.join(ROOT, "artifacts/milestones/M0")
}
OptionParser.new do |parser|
  parser.on("--run-id ID", "evidence run identifier") { |value| options[:run_id] = value }
  parser.on("--output-root PATH", "milestone evidence root") { |value| options[:output_root] = File.expand_path(value) }
end.parse!(ARGV)

abort "run ID may contain only letters, digits, dot, underscore, and hyphen" unless options[:run_id].match?(/\A[0-9A-Za-z._-]+\z/)

directory = File.join(options[:output_root], options[:run_id])
FileUtils.mkdir_p(directory)
started_at = Time.now.utc
starting_input = source_inventory
commands = []

source_inventory_path = File.join(directory, "source-inventory.json")
File.write(
  source_inventory_path,
  JSON.pretty_generate(
    "schema_version" => 1,
    "kind" => "m0_source_inventory",
    "input_sha256" => starting_input.fetch("sha256"),
    "input_file_count" => starting_input.fetch("file_count"),
    "entries" => starting_input.fetch("entries")
  ) << "\n"
)

run_command = lambda do |name, command, environment = {}|
  command_started = Time.now.utc
  stdout, stderr, status = Open3.capture3(environment, *command, chdir: ROOT)
  record = {
    "name" => name,
    "command" => command,
    "started_at" => command_started.iso8601(6),
    "finished_at" => Time.now.utc.iso8601(6),
    "exit_status" => status.exitstatus,
    "stdout" => stdout,
    "stderr" => stderr,
    "environment" => environment,
    "tool_path" => {
      "gem_build" => "rubernetes.gemspec",
      "rake_test" => "Gemfile",
      "executables" => "tools/milestones/executables_probe.rb",
      "native_boundary_scan" => "tools/milestones/native_boundary_scan.rb",
      "rbs_validate" => "Gemfile",
      "kernel_probe_x86_64" => "tools/milestones/m0_kernel_probe.rb"
    }.fetch(name),
    "tool_sha256" => Digest::SHA256.file(File.join(ROOT, {
      "gem_build" => "rubernetes.gemspec",
      "rake_test" => "Gemfile",
      "executables" => "tools/milestones/executables_probe.rb",
      "native_boundary_scan" => "tools/milestones/native_boundary_scan.rb",
      "rbs_validate" => "Gemfile",
      "kernel_probe_x86_64" => "tools/milestones/m0_kernel_probe.rb"
    }.fetch(name))).hexdigest
  }
  commands << record
  record
end

version = File.read(File.join(ROOT, "lib/rubernetes/version.rb"))[/VERSION\s*=\s*"([^"]+)"/, 1]
gem_path = File.join(directory, "rubernetes-#{version}.gem")
gem_build = run_command.call("gem_build", ["gem", "build", "rubernetes.gemspec", "--output", gem_path])
File.write(File.join(directory, "gem-build.json"), JSON.pretty_generate(gem_build) << "\n")

junit_path = File.join(directory, "junit.xml")
rake_command = %w[bundle exec rake test]
test_entries = starting_input.fetch("entries").select { |entry| entry.fetch("path").match?(%r{\Atest/.*_test\.rb\z}) }
test_inventory_content = test_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
run_command.call(
  "rake_test",
  rake_command,
  {
    "RUBERNETES_JUNIT" => junit_path,
    "RUBERNETES_JUNIT_COMMAND_SHA256" => Digest::SHA256.hexdigest(JSON.generate(rake_command)),
    "RUBERNETES_JUNIT_TEST_PATTERN" => "test/**/*_test.rb",
    "RUBERNETES_JUNIT_TEST_INVENTORY_SHA256" => Digest::SHA256.hexdigest(test_inventory_content),
    "RUBERNETES_JUNIT_TEST_INVENTORY_COUNT" => test_entries.length.to_s,
    # The gate requires zero skips, so the opt-in privileged kernel tests must
    # actually run.  They are enabled here, in the recorded `environment`,
    # rather than being exported by whoever invokes the capture: a manifest
    # whose command does not reproduce its own result is not evidence.
    "RUBERNETES_NFTABLES_KERNEL_TEST" => "1",
    "RUBERNETES_NFTABLES_PACKET_TEST" => "1"
  }
)

executables_path = File.join(directory, "executables.json")
run_command.call(
  "executables",
  [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", executables_path]
)

native_scan_path = File.join(directory, "native-boundary-scan.json")
run_command.call(
  "native_boundary_scan",
  [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output", native_scan_path]
)

run_command.call("rbs_validate", ["bundle", "exec", "rbs", "-I", "sig", "-I", "generated/rbs", "validate"])

architecture = RbConfig::CONFIG.fetch("host_cpu").sub("arm64", "aarch64").sub("amd64", "x86_64")
abi_probe_path = File.join(directory, "abi-probe-#{architecture}.json")
run_command.call(
  "kernel_probe_#{architecture}",
  [
    RbConfig.ruby,
    "-I#{File.join(ROOT, "build/ext/rubernetes_linux")}",
    "tools/milestones/m0_kernel_probe.rb",
    "--output",
    abi_probe_path
  ]
)

evidence_names = ["gem-build.json", "junit.xml", "executables.json", "native-boundary-scan.json", "source-inventory.json"]
evidence_names.concat(Dir.glob(File.join(directory, "abi-probe-*.json")).map { |path| File.basename(path) })
artifacts = evidence_names.uniq.sort.filter_map do |name|
  path = File.join(directory, name)
  next unless File.file?(path)

  {"path" => name, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
end

subject_paths = EXECUTABLES.map { |name| File.join(ROOT, "exe", name) }
subject_paths.concat(Dir.glob(File.join(ROOT, "generated/platform/linux/abi/*.json")))
native_extension = File.join(ROOT, "build/ext/rubernetes_linux/rubernetes_linux.so")
subject_paths << native_extension if File.file?(native_extension)
subject_paths << gem_path if File.file?(gem_path)
subjects = subject_paths.sort.map do |path|
  {
    "path" => File.join("subjects", File.basename(path)),
    "source_path" => path.delete_prefix("#{ROOT}/"),
    "sha256" => Digest::SHA256.file(path).hexdigest,
    "bytes" => File.size(path)
  }
end
subjects.each do |subject|
  source = File.join(ROOT, subject.fetch("source_path"))
  source = gem_path if subject.fetch("source_path").start_with?(directory.delete_prefix("#{ROOT}/"))
  destination = File.join(directory, subject.fetch("path"))
  FileUtils.mkdir_p(File.dirname(destination))
  FileUtils.cp(source, destination)
end

abi_documents = Dir.glob(File.join(directory, "abi-probe-*.json")).map { |path| JSON.parse(File.read(path)) }
finished_input = source_inventory
preconditions = [
  starting_input == finished_input,
  commands.all? { |command| command.fetch("exit_status") == 0 },
  abi_documents.map { |document| document["architecture"] } == %w[x86_64],
  abi_documents.all? { |document| document["failure_count"] == 0 },
  abi_documents.all? do |document|
    document["schema_version"] == 2 && document["kind"] == "m0_abi_probe" &&
      document["input_stable"] == true &&
      document["input_sha256"] == starting_input.fetch("sha256") &&
      document["input_file_count"] == starting_input.fetch("file_count")
  end
]
uname = Etc.uname
manifest = {
  "schema_version" => 3,
  "milestone" => "M0",
  "run_id" => options[:run_id],
  "status" => preconditions.all? ? "COMPLETE" : "INCOMPLETE",
  "host" => {
    "architecture" => architecture,
    "kernel" => uname[:release],
    "sysname" => uname[:sysname],
    "ruby" => RUBY_DESCRIPTION
  },
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => starting_input == finished_input,
  "input_capture" => {
    "stable" => starting_input == finished_input,
    "start" => starting_input.slice("sha256", "file_count"),
    "finish" => finished_input.slice("sha256", "file_count")
  },
  "started_at" => started_at.iso8601(6),
  "finished_at" => Time.now.utc.iso8601(6),
  "commands" => commands,
  "result_counts" => {
    "commands" => commands.length,
    "command_failures" => commands.count { |command| command.fetch("exit_status") != 0 },
    "artifacts" => artifacts.length,
    "subjects" => subjects.length,
    "architecture_profiles" => abi_documents.length,
    "source_files" => starting_input.fetch("file_count")
  },
  "artifacts" => artifacts,
  "subjects" => subjects
}
manifest_path = File.join(directory, "manifest.json")
File.write(manifest_path, JSON.pretty_generate(manifest) << "\n")
puts(manifest_path)

gate_stdout, gate_stderr, gate_status = Open3.capture3(
  RbConfig.ruby,
  File.join(ROOT, "tools/milestones/m0_gate.rb"),
  manifest_path,
  chdir: ROOT
)
$stdout.write(gate_stdout)
$stderr.write(gate_stderr)
exit(gate_status.exitstatus)
