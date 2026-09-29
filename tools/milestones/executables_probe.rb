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

ROOT = File.expand_path("../..", __dir__)
EXECUTABLES = %w[
  rubectl
  rubernetes-apiserver
  rubernetes-controller-manager
  rubernetes-scheduler
  rubernetes-agent
  rubernetes-proxy
].freeze

options = {output: nil}
OptionParser.new do |parser|
  parser.on("--output PATH", "write JSON evidence to PATH") { |path| options[:output] = path }
end.parse!(ARGV)

report_started_at = Time.now.utc
results = EXECUTABLES.flat_map do |executable|
  %w[--help --version].map do |option|
    path = File.join(ROOT, "exe", executable)
    command = [RbConfig.ruby, "-I#{File.join(ROOT, "lib")}", path, "--config", "/unreadable/m0-side-effect-sentinel", option]
    case_started_at = Time.now.utc
    stdout, stderr, status = Open3.capture3(*command, chdir: ROOT)
    finished_at = Time.now.utc
    {
      "executable" => executable,
      "option" => option,
      "command" => command,
      "started_at" => case_started_at.iso8601(6),
      "finished_at" => finished_at.iso8601(6),
      "exit_status" => status.exitstatus,
      "stdout" => stdout,
      "stderr" => stderr,
      "binary_sha256" => Digest::SHA256.file(path).hexdigest,
      "passed" => status.success? && stderr.empty? && !stdout.empty?
    }
  end
end

finished_at = Time.now.utc
output_path = options[:output] && File.expand_path(options[:output])
uname = Etc.uname

document = {
  "schema_version" => 1,
  "kind" => "m0_executables",
  "command" => [RbConfig.ruby, "tools/milestones/executables_probe.rb", "--output", output_path].compact,
  "output_path" => output_path,
  "tool_path" => "tools/milestones/executables_probe.rb",
  "tool_sha256" => Digest::SHA256.file(File.expand_path($PROGRAM_NAME)).hexdigest,
  "started_at" => report_started_at.iso8601(6),
  "finished_at" => finished_at.iso8601(6),
  "host" => {"sysname" => uname[:sysname], "release" => uname[:release], "machine" => uname[:machine], "ruby" => RUBY_DESCRIPTION},
  "count" => results.length,
  "failure_count" => results.count { |result| !result.fetch("passed") },
  "results" => results
}
json = JSON.pretty_generate(document) << "\n"
if options[:output]
  FileUtils.mkdir_p(File.dirname(options[:output]))
  File.write(options[:output], json)
else
  $stdout.write(json)
end
exit(document.fetch("failure_count").zero? ? 0 : 1)
