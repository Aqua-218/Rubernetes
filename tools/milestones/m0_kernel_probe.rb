#!/usr/bin/env ruby
# frozen_string_literal: true

require "etc"
require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "time"
require_relative "m0_source_inventory"

ROOT = File.expand_path("../..", __dir__)
STARTED_AT = Time.now.utc
# The evidence gate binds this report to the exact argv the runner used:
# the interpreter, the -I flag for the compiled extension (visible only
# through $LOAD_PATH), the repository-relative script path, and the options.
EXTENSION_INCLUDES = $LOAD_PATH.select { |entry| File.expand_path(entry).start_with?(File.join(ROOT, "build/ext/")) }
                              .map { |entry| "-I#{File.expand_path(entry)}" }.freeze
COMMAND = [RbConfig.ruby, *EXTENSION_INCLUDES,
           File.expand_path($PROGRAM_NAME).delete_prefix("#{ROOT}/"), *ARGV].freeze
$LOAD_PATH.unshift(File.join(ROOT, "lib"))
require "rubernetes/platform/linux"
require "rubernetes/platform/linux/namespace_process"

Linux = Rubernetes::Platform::Linux

class ProbeSuite
  def initialize
    @results = []
  end

  attr_reader :results

  def probe(name)
    started_at = Time.now.utc
    value = yield
    @results << {
      "name" => name,
      "started_at" => started_at.iso8601(6),
      "finished_at" => Time.now.utc.iso8601(6),
      "passed" => true,
      "result" => json_value(value)
    }
  rescue Linux::Error => error
    @results << failure(name, started_at, error.to_h)
  rescue RuntimeError, SystemCallError, IOError, ArgumentError => error
    @results << failure(name, started_at, {class: error.class.name, message: error.message})
  end

  private

  def failure(name, started_at, error)
    {
      "name" => name,
      "started_at" => started_at.iso8601(6),
      "finished_at" => Time.now.utc.iso8601(6),
      "passed" => false,
      "error" => json_value(error)
    }
  end

  def json_value(value)
    case value
    when Data
      json_value(value.to_h)
    when Hash
      value.to_h { |key, child| [String(key), json_value(child)] }
    when Array
      value.map { |child| json_value(child) }
    when String, Numeric, TrueClass, FalseClass, NilClass
      value
    else
      String(value)
    end
  end
end

def namespace_probe
  reader, writer = IO.pipe
  process = Linux::NamespaceProcess.new
  spawn = process.spawn(
    command: ["/usr/bin/ps", "-e", "-o", "pid=,comm="],
    output_fd: writer.fileno,
    resource_id: "sandbox:m0-namespace-probe"
  )
  writer.close
  result = process.wait(
    spawn: spawn,
    timeout: 10.0,
    resource_id: "sandbox:m0-namespace-probe"
  )
  output = reader.read
  pids = output.lines.filter_map { |line| line[/\A\s*(\d+)\s+/, 1]&.to_i }
  unless result.wait_result.exit_status == 0 && pids == [1]
    raise "namespace probe failed: wait=#{result.wait_result.inspect} pids=#{pids.inspect} output=#{output.inspect}"
  end

  {pid: result.pid, pidfd: result.pidfd, exit_status: result.wait_result.exit_status, ps_pids: pids, ps_output: output}
ensure
  reader&.close unless reader&.closed?
  writer&.close unless writer&.closed?
  IO.for_fd(spawn.pidfd).close if spawn && spawn.pidfd
end

def source_input_identity
  paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
    next false unless regular_source_file?(path)

    relative = path.delete_prefix("#{ROOT}/")
    !M0SourceInventory.excluded?(relative)
  end.sort
  content = paths.map do |path|
    "#{path.delete_prefix("#{ROOT}/")}\0#{Digest::SHA256.file(path).hexdigest}\n"
  end.join
  {"sha256" => Digest::SHA256.hexdigest(content), "file_count" => paths.length}
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

def native_extension_identity
  expected = File.join(ROOT, "build/ext/rubernetes_linux/rubernetes_linux.so")
  loaded = $LOADED_FEATURES.find do |feature|
    File.basename(feature) == "rubernetes_linux.so" && File.file?(feature)
  end
  raise "native extension was not loaded by the kernel probe" unless loaded
  raise "kernel probe loaded an unexpected native extension #{loaded}" unless File.realpath(loaded) == File.realpath(expected)
  raise "native extension path is symlinked" unless regular_source_file?(expected)

  source_paths = Dir.glob(File.join(ROOT, "ext/rubernetes_linux/**/*.{c,cc,h,rb}")).select { |path| regular_source_file?(path) }.sort
  source_entries = source_paths.map do |path|
    {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
  end
  source_content = source_entries.map { |entry| "#{entry.fetch("path")}\0#{entry.fetch("sha256")}\n" }.join
  {
    "path" => "build/ext/rubernetes_linux/rubernetes_linux.so",
    "loaded_feature" => File.realpath(loaded).delete_prefix("#{ROOT}/"),
    "sha256" => Digest::SHA256.file(expected).hexdigest,
    "bytes" => File.size(expected),
    "source_sha256" => Digest::SHA256.hexdigest(source_content),
    "source_file_count" => source_entries.length,
    "source_files" => source_entries
  }
end

options = {output: nil}
OptionParser.new do |parser|
  parser.on("--output PATH", "write JSON evidence to PATH") { |path| options[:output] = path }
end.parse!(ARGV)

starting_input = source_input_identity
suite = ProbeSuite.new
manifest = Linux::ABIManifest.load
native_extension = native_extension_identity
suite.probe("abi_manifest") do
  manifest.verify_ruby_layouts!
  generator = File.join(ROOT, "tools/platform/generate_abi_manifest.rb")
  stdout, stderr, status = Open3.capture3(
    RbConfig.ruby,
    generator,
    "--check",
    manifest.path,
    chdir: ROOT
  )
  raise "#{stdout}#{stderr}" unless status.success?

  {
    manifest: manifest.path.delete_prefix("#{ROOT}/"),
    manifest_sha256: Digest::SHA256.file(manifest.path).hexdigest,
    manifest_bytes: File.size(manifest.path),
    mismatch_count: 0
  }
end
suite.probe("clone3_pid_namespace_mount_proc_pidfd_wait") { namespace_probe }
suite.probe("netlink_ack") do
  ack = Linux::Netlink.new.get_link(index: 1, sequence: 60_000)
  {sequence: ack.sequence, message_types: ack.messages.map(&:type)}
end
suite.probe("bpf_verifier") do
  program = Linux::BPF.new.probe(resource_id: "bpf:m0-kernel-probe")
  {fd: program.fd, verifier_log: program.verifier_log}
ensure
  program&.close
end
suite.probe("kvm_capability") { Linux::KVM.new.probe(resource_id: "kvm:m0-kernel-probe") }
suite.probe("errno_clone3") do
  begin
    Linux::Clone3.new.call(
      args: Linux::Clone3::Args.new(flags: 0),
      structure_size: 0,
      resource_id: "intentional:clone3"
    )
    raise "intentional clone3 failure unexpectedly succeeded"
  rescue Linux::Error => error
    raise unless error.errno.positive? && error.operation == "clone3" && error.resource_id == "intentional:clone3"

    error.to_h
  end
end
suite.probe("errno_pidfd") do
  begin
    Linux::Pidfd.new.open(pid: -1, resource_id: "intentional:pidfd")
    raise "intentional pidfd failure unexpectedly succeeded"
  rescue Linux::Error => error
    raise unless error.errno.positive? && error.operation == "pidfd_open" && error.resource_id == "intentional:pidfd"

    error.to_h
  end
end
suite.probe("errno_mount") do
  begin
    Linux::Mount.new.mount(
      source: "none",
      target: "/rubernetes/m0/intentional-missing",
      filesystem: "none",
      resource_id: "intentional:mount"
    )
    raise "intentional mount failure unexpectedly succeeded"
  rescue Linux::Error => error
    raise unless error.errno.positive? && error.operation == "mount" && error.resource_id == "intentional:mount"

    error.to_h
  end
end
suite.probe("errno_netlink") do
  begin
    Linux::Netlink.new.get_link(index: -1, sequence: 60_001, resource_id: "intentional:netlink")
    raise "intentional netlink failure unexpectedly succeeded"
  rescue Linux::Error => error
    raise unless error.errno.positive? && error.operation == "netlink_ack" && error.resource_id == "intentional:netlink"

    error.to_h
  end
end
suite.probe("errno_bpf") do
  begin
    unexpected_program = Linux::BPF.new.load(
      instructions: [Linux::BPF::Instruction.new(code: 0xff, destination: 0, source: 0, offset: 0, immediate: 0)],
      resource_id: "intentional:bpf"
    )
    unexpected_program.close
    raise "intentional BPF failure unexpectedly succeeded"
  rescue Linux::BPF::VerifierError => error
    raise unless error.errno.positive? && error.operation == "bpf(BPF_PROG_LOAD)" && error.resource_id == "intentional:bpf"

    error.to_h.merge(verifier_log: error.verifier_log)
  end
end
suite.probe("errno_kvm") do
  begin
    Linux::KVM.new(path: "/rubernetes/m0/missing-kvm").probe(resource_id: "intentional:kvm")
    raise "intentional KVM failure unexpectedly succeeded"
  rescue Linux::Error => error
    raise unless error.errno.positive? && error.operation == "kvm_probe" && error.resource_id == "intentional:kvm"

    error.to_h
  end
end
suite.probe("errno_namespace_exec") do
  reader, writer = IO.pipe
  process = Linux::NamespaceProcess.new
  spawn = process.spawn(
    command: ["/rubernetes/m0/missing-executable"],
    output_fd: writer.fileno,
    resource_id: "intentional:namespace-exec"
  )
  writer.close
  begin
    process.wait(spawn: spawn, timeout: 5.0, resource_id: "intentional:namespace-exec")
    raise "intentional namespace exec failure unexpectedly succeeded"
  rescue Linux::Error => error
    raise unless error.errno.positive? && error.operation == "execve" && error.resource_id == "intentional:namespace-exec"

    error.to_h
  ensure
    reader.close
    IO.for_fd(spawn.pidfd).close
  end
end

finished_input = source_input_identity
suite.probe("source_input_stability") do
  raise "source input changed during kernel probe" unless finished_input == starting_input

  finished_input
end

uname = Etc.uname
document = {
  "schema_version" => 2,
  "kind" => "m0_abi_probe",
  "architecture" => manifest.architecture,
  "input_sha256" => starting_input.fetch("sha256"),
  "input_file_count" => starting_input.fetch("file_count"),
  "input_stable" => starting_input == finished_input,
  "command" => COMMAND,
  "output_path" => options[:output] && File.expand_path(options[:output]),
  "tool_path" => "tools/milestones/m0_kernel_probe.rb",
  "tool_sha256" => Digest::SHA256.file(File.expand_path($PROGRAM_NAME)).hexdigest,
  "started_at" => STARTED_AT.iso8601(6),
  "finished_at" => Time.now.utc.iso8601(6),
  "host" => {
    "sysname" => uname[:sysname],
    "release" => uname[:release],
    "machine" => uname[:machine],
    "ruby" => RUBY_DESCRIPTION
  },
  "native_extension" => native_extension,
  "probe_count" => suite.results.length,
  "failure_count" => suite.results.count { |result| !result.fetch("passed") },
  "results" => suite.results
}
json = JSON.pretty_generate(document) << "\n"
if options[:output]
  FileUtils.mkdir_p(File.dirname(options[:output]))
  File.write(options[:output], json)
else
  $stdout.write(json)
end
exit(document.fetch("failure_count").zero? ? 0 : 1)
