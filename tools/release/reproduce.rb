#!/usr/bin/env ruby
# frozen_string_literal: true

# Reproducibility check (spec/delivery/milestones.md#milestone-m9 exit 2):
# rebuilding from the same source must produce byte-identical artifact digests.
#
# The same-host run proves the build is deterministic given identical inputs.
# It does NOT prove the independent clean-host criterion, and says so: that one
# needs a second machine and is reported as `clean_host: "not attempted here"`.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"
require "tmpdir"

module Release
  module Reproduce
    ROOT = File.expand_path("../..", __dir__)

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/release/reproducibility.json"), rounds: 2}
      OptionParser.new do |parser|
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--rounds N", Integer, "number of independent rebuilds (default 2)") { |v| options[:rounds] = v }
      end.parse!(argv)

      rounds = Array.new(options[:rounds]) { |index| build_round(index) }
      digests = rounds.map { |round| round.fetch("artifacts") }
      identical = digests.uniq.length == 1 && rounds.all? { |round| round.fetch("built") }
      report = {
        "schema_version" => 1,
        "kind" => "release_reproducibility",
        "generated_at" => Time.now.utc.iso8601,
        "host" => {"ruby" => RUBY_DESCRIPTION, "platform" => RbConfig::CONFIG["host"]},
        "rounds" => rounds,
        "same_host_identical" => identical,
        "clean_host" => "not attempted here: exit criterion 2 requires an independent clean x86_64 host, " \
                        "which this run cannot provide; run tools/release/reproduce.rb there and compare " \
                        "artifacts[].sha256 against this report",
        "passed" => identical
      }
      FileUtils.mkdir_p(File.dirname(options[:output]))
      File.write(options[:output], "#{JSON.pretty_generate(report)}\n")
      puts JSON.pretty_generate(report)
      identical ? 0 : 1
    end

    # Each round builds the gem into its own directory so one round cannot see
    # another's output.
    def build_round(index)
      Dir.mktmpdir("rubernetes-repro-#{index}-") do |directory|
        gemspec = Dir.glob(File.join(ROOT, "*.gemspec")).first
        return {"round" => index, "built" => false, "reason" => "no gemspec", "artifacts" => []} if gemspec.nil?

        env = {
          # Anything that varies per run must be pinned or the build is not
          # reproducible by construction.
          "SOURCE_DATE_EPOCH" => "0",
          "TZ" => "UTC",
          "LC_ALL" => "C",
          "GEM_HOME" => File.join(directory, "gem")
        }
        stdout, stderr, status = Open3.capture3(env, "gem", "build", File.basename(gemspec),
                                                "--output", File.join(directory, "rubernetes.gem"), chdir: ROOT)
        built = status.success? && File.file?(File.join(directory, "rubernetes.gem"))
        {
          "round" => index,
          "built" => built,
          "exit_status" => status.exitstatus,
          "stderr" => built ? nil : stderr.lines.last(3).join.strip,
          "artifacts" => built ? [{"name" => "rubernetes.gem",
                                   "sha256" => Digest::SHA256.file(File.join(directory, "rubernetes.gem")).hexdigest,
                                   "bytes" => File.size(File.join(directory, "rubernetes.gem"))}] : []
        }
      end
    end
  end
end

exit(Release::Reproduce.run) if $PROGRAM_NAME == __FILE__
