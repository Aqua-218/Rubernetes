#!/usr/bin/env ruby
# frozen_string_literal: true

# Builds the upstream Ginkgo e2e.test binary from the pinned Kubernetes
# checkout into build/conformance/bin/e2e.test (K3).
#
# The source tree is verified against third_party/locks before anything is
# built: K3 evidence is only meaningful if the binary came from the commit the
# lock names, so a checkout at a different commit is refused rather than built.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"

require_relative "lock"

module Conformance
  module BuildE2E
    L = Conformance::Lock
    ROOT = L::ROOT
    BIN = File.join(ROOT, "build/conformance/bin")
    TARGETS = %w[test/e2e/e2e.test].freeze

    module_function

    def run(argv = ARGV)
      options = {source_root: ENV.fetch("RUBERNETES_KUBERNETES_SOURCE", "/tmp/kubernetes-v1.36.2")}
      OptionParser.new do |parser|
        parser.on("--source-root PATH", "pinned Kubernetes checkout") { |v| options[:source_root] = v }
      end.parse!(argv)

      source = options[:source_root]
      unless File.directory?(source)
        abort JSON.pretty_generate(failure("the pinned Kubernetes checkout #{source} does not exist"))
      end

      observed = git(source, "rev-parse", "HEAD")
      expected = L.source_commit
      unless observed == expected
        abort JSON.pretty_generate(failure("checkout is at #{observed}, but the lock pins #{expected}"))
      end

      FileUtils.mkdir_p(BIN)
      built = TARGETS.map { |target| build(source, target) }

      report = {"schema_version" => 1, "kind" => "conformance_e2e_build", "source_root" => source,
                "commit" => observed, "targets" => built,
                "passed" => built.all? { |entry| entry.fetch("installed") }}
      puts JSON.pretty_generate(report)
      report.fetch("passed") ? 0 : 1
    end

    def build(source, target)
      name = File.basename(target)
      started = Time.now
      _stdout, stderr, status = Open3.capture3({"GOTOOLCHAIN" => ENV.fetch("GOTOOLCHAIN", "auto")},
                                               "make", "WHAT=#{target}", chdir: source)
      produced = File.join(source, "_output/bin", name)
      installed = false
      if status.success? && File.file?(produced)
        FileUtils.cp(produced, File.join(BIN, name))
        File.chmod(0o755, File.join(BIN, name))
        installed = true
      end

      {"target" => target, "installed" => installed, "exit_status" => status.exitstatus,
       "elapsed_seconds" => (Time.now - started).round(1),
       "sha256" => installed ? Digest::SHA256.file(File.join(BIN, name)).hexdigest : nil,
       "stderr" => installed ? nil : stderr.to_s[-4000..] || stderr.to_s}
    end

    def git(source, *arguments)
      stdout, _stderr, status = Open3.capture3("git", "-C", source, *arguments)
      status.success? ? stdout.strip : nil
    end

    def failure(detail)
      {"schema_version" => 1, "kind" => "conformance_e2e_build", "passed" => false, "detail" => detail}
    end
  end
end

exit(Conformance::BuildE2E.run) if $PROGRAM_NAME == __FILE__
