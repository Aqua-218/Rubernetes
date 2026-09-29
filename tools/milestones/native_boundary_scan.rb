#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "digest"
require "etc"
require "json"
require "optparse"
require "rbconfig"
require "time"

ROOT = File.expand_path("../..", __dir__)
SOURCE_GLOBS = %w[ext/rubernetes_linux/**/*.{c,cc,h}].freeze
FORBIDDEN = {
  "authorization" => /\bauthori[sz](?:e|ation)\b/i,
  "retry" => /\b(?:retry|backoff)\b/i,
  "state_machine" => /\bstate[_ ]?machine\b/i,
  "orchestration_policy" => /\b(?:reconcile|scheduler|admission|policy_decision)\b/i
}.freeze

options = {output: nil}
OptionParser.new do |parser|
  parser.on("--output PATH", "write JSON evidence to PATH") { |path| options[:output] = path }
end.parse!(ARGV)

started_at = Time.now.utc

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

files = SOURCE_GLOBS.flat_map { |pattern| Dir.glob(File.join(ROOT, pattern)) }.select { |path| regular_source_file?(path) }.uniq.sort
findings = files.flat_map do |path|
  relative_path = path.delete_prefix("#{ROOT}/")
  File.readlines(path, chomp: true).flat_map.with_index(1) do |line, line_number|
    FORBIDDEN.filter_map do |rule, expression|
      next unless line.match?(expression)

      {"rule" => rule, "path" => relative_path, "line" => line_number, "text" => line.strip}
    end
  end
end
finished_at = Time.now.utc
uname = Etc.uname
document = {
  "schema_version" => 2,
  "kind" => "native_boundary_scan",
  "command" => [RbConfig.ruby, "tools/milestones/native_boundary_scan.rb", "--output", options[:output] && File.expand_path(options[:output])].compact,
  "output_path" => options[:output] && File.expand_path(options[:output]),
  "tool_path" => "tools/milestones/native_boundary_scan.rb",
  "tool_sha256" => Digest::SHA256.file(File.expand_path($PROGRAM_NAME)).hexdigest,
  "started_at" => started_at.iso8601(6),
  "finished_at" => finished_at.iso8601(6),
  "host" => {"sysname" => uname[:sysname], "release" => uname[:release], "machine" => uname[:machine], "ruby" => RUBY_DESCRIPTION},
  "source_files" => files.map do |path|
    {
      "path" => path.delete_prefix("#{ROOT}/"),
      "sha256" => Digest::SHA256.file(path).hexdigest,
      "bytes" => File.size(path)
    }
  end,
  "policy_branch_count" => findings.length,
  "retry_count" => findings.count { |finding| finding.fetch("rule") == "retry" },
  "authorization_count" => findings.count { |finding| finding.fetch("rule") == "authorization" },
  "state_machine_count" => findings.count { |finding| finding.fetch("rule") == "state_machine" },
  "findings" => findings,
  "passed" => findings.empty?
}
json = JSON.pretty_generate(document) << "\n"
if options[:output]
  FileUtils.mkdir_p(File.dirname(options[:output]))
  File.write(options[:output], json)
else
  $stdout.write(json)
end
exit(document.fetch("passed") ? 0 : 1)
