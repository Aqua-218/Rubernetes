#!/usr/bin/env ruby
# frozen_string_literal: true

# Installs the pinned conformance runners into build/conformance/bin.
#
# Every artifact is verified against third_party/locks/conformance-runners.json
# before it is unpacked: an archive whose digest does not match the lock is a
# supply-chain failure, not something to retry or work around.  Nothing here
# resolves "latest" anything.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"

require_relative "lock"

module Conformance
  module InstallTools
    L = Conformance::Lock
    ROOT = L::ROOT
    BIN = File.join(ROOT, "build/conformance/bin")
    DOWNLOADS = File.join(ROOT, "build/conformance/downloads")

    RELEASE_URLS = {
      "hydrophone" => lambda { |runner, artifact|
        "https://github.com/kubernetes-sigs/hydrophone/releases/download/#{runner.fetch("tag")}/#{artifact.fetch("name")}"
      },
      "sonobuoy" => lambda { |runner, artifact|
        "https://github.com/vmware-tanzu/sonobuoy/releases/download/#{runner.fetch("tag")}/#{artifact.fetch("name")}"
      }
    }.freeze

    module_function

    def run(argv = ARGV)
      options = {platform: "linux/amd64", tools: RELEASE_URLS.keys}
      OptionParser.new do |parser|
        parser.on("--platform NAME", "target platform (default linux/amd64)") { |v| options[:platform] = v }
        parser.on("--only LIST", "comma-separated subset of #{RELEASE_URLS.keys.join(",")}") do |v|
          options[:tools] = v.split(",").map(&:strip)
        end
      end.parse!(argv)

      unknown = options[:tools] - RELEASE_URLS.keys
      raise ArgumentError, "unknown tools: #{unknown.join(", ")}" unless unknown.empty?

      FileUtils.mkdir_p([BIN, DOWNLOADS])
      report = options[:tools].map { |name| install(name, options[:platform]) }
      puts JSON.pretty_generate({"schema_version" => 1, "kind" => "conformance_tools",
                                 "platform" => options[:platform], "tools" => report})
      report.all? { |entry| entry.fetch("installed") } ? 0 : 1
    end

    def install(name, platform)
      runner = L.runner(name)
      artifact = L.runner_artifact(name, platform)
      archive = File.join(DOWNLOADS, artifact.fetch("name"))
      expected = artifact.fetch("sha256")

      download(RELEASE_URLS.fetch(name).call(runner, artifact), archive) unless digest(archive) == expected

      observed = digest(archive)
      unless observed == expected
        return {"tool" => name, "installed" => false, "expected_sha256" => expected, "observed_sha256" => observed,
                "detail" => "archive digest does not match third_party/locks/conformance-runners.json"}
      end

      extract(archive, name)
      binary = File.join(BIN, name)
      {"tool" => name, "installed" => File.executable?(binary), "version" => runner.fetch("tag"),
       "sha256" => expected, "path" => binary.delete_prefix("#{ROOT}/"),
       "binary_sha256" => File.file?(binary) ? Digest::SHA256.file(binary).hexdigest : nil}
    end

    def download(url, destination)
      _stdout, stderr, status = Open3.capture3("curl", "--fail", "--location", "--silent", "--show-error",
                                               "--output", destination, url)
      raise "download failed for #{url}: #{stderr}" unless status.success?
    end

    def extract(archive, name)
      _stdout, stderr, status = Open3.capture3("tar", "-xzf", archive, "-C", BIN, name)
      raise "cannot unpack #{name} from #{archive}: #{stderr}" unless status.success?

      File.chmod(0o755, File.join(BIN, name))
    end

    def digest(path)
      File.file?(path) ? Digest::SHA256.file(path).hexdigest : nil
    end
  end
end

exit(Conformance::InstallTools.run) if $PROGRAM_NAME == __FILE__
