#!/usr/bin/env ruby
# frozen_string_literal: true

# Builds the upstream Ginkgo e2e.test or e2e_node.test binary from the pinned
# Kubernetes checkout into build/conformance/bin (K3 and K4).
#
# The source tree is verified against third_party/locks before anything is
# built: K3 evidence is only meaningful if the binary came from the commit the
# lock names, so a checkout at a different commit is refused rather than built.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "tmpdir"

require_relative "lock"
require_relative "k3_build_receipt"

module Conformance
  module BuildE2E
    L = Conformance::Lock
    ROOT = L::ROOT
    BIN = File.join(ROOT, "build/conformance/bin")

    module_function

    def run(argv = ARGV)
      options = {source_root: ENV.fetch("RUBERNETES_KUBERNETES_SOURCE", "/tmp/kubernetes-v1.36.2")}
      OptionParser.new do |parser|
        parser.on("--source-root PATH", "pinned Kubernetes checkout") { |v| options[:source_root] = v }
        parser.on("--node", "Build the K4 Node Conformance executable") { options[:node] = true }
      end.parse!(argv)

      source = options[:source_root]
      abort JSON.pretty_generate(failure("the pinned Kubernetes checkout #{source} does not exist")) unless File.directory?(source)

      observed = git(source, "rev-parse", "HEAD")
      expected = L.source_commit
      abort JSON.pretty_generate(failure("checkout is at #{observed}, but the lock pins #{expected}")) unless observed == expected

      FileUtils.mkdir_p(BIN)
      built = [options[:node] ? build_node(source, observed) : build(source, observed)]

      report = {"schema_version" => 1, "kind" => K3BuildReceipt::KIND, "source_root" => source,
                "commit" => observed, "targets" => built,
                "passed" => built.all? { |entry| entry.fetch("installed") }}
      bytes = "#{JSON.pretty_generate(report)}\n"
      publish_stock_receipt(bytes) if !options[:node] && report.fetch("passed")
      print bytes
      report.fetch("passed") ? 0 : 1
    end

    def build_node(source, commit)
      raise ArgumentError, "Node Conformance requires a clean pinned source checkout" unless git(source, "status", "--porcelain") == ""

      Dir.mktmpdir("e2e-node-", BIN) do |directory|
        path = File.join(directory, "e2e_node.test")
        ginkgo = File.join(directory, "ginkgo-k4")
        command = ["go", "test", "-mod=vendor", "-trimpath", "-c", "-o", path, "./test/e2e_node"]
        ginkgo_command = ["go", "build", "-mod=vendor", "-trimpath", "-o", ginkgo, "github.com/onsi/ginkgo/v2/ginkgo"]
        env = {"GOTOOLCHAIN" => ENV.fetch("GOTOOLCHAIN", "auto"), "GOOS" => "linux", "GOARCH" => "amd64"}
        output, status = Open3.capture2e(env, *command, chdir: source)
        if status.success?
          ginkgo_output, status = Open3.capture2e(env, *ginkgo_command, chdir: source)
          output << ginkgo_output
        end
        installed = status.success? && File.executable?(path) && File.executable?(ginkgo) && git(source, "rev-parse", "HEAD") == commit &&
                    git(source, "status", "--porcelain") == ""
        version, version_status = Open3.capture2e(env, "go", "version", chdir: source)
        installed &&= version_status.success?
        result = {"target" => "e2e_node.test", "installed" => installed, "exit_status" => status.exitstatus,
                  "source_commit" => commit, "platform" => "linux/amd64", "go" => version.strip,
                  "command" => command, "ginkgo_command" => ginkgo_command}
        if installed
          result["sha256"] = Digest::SHA256.file(path).hexdigest
          result["ginkgo_sha256"] = Digest::SHA256.file(ginkgo).hexdigest
          File.rename(path, File.join(BIN, "e2e_node.test"))
          File.rename(ginkgo, File.join(BIN, "ginkgo-k4"))
          File.write(File.join(BIN, "e2e_node.test.build.json"), "#{JSON.pretty_generate(result)}\n")
        else
          result["error"] = output
        end
        result
      end
    end

    def build(source, commit)
      raise ArgumentError, "K3 requires a clean pinned source checkout" unless git(source, "status", "--porcelain") == ""

      name = File.basename(K3BuildReceipt::TARGET)
      started = Time.now
      env = {"GOTOOLCHAIN" => ENV.fetch("GOTOOLCHAIN", "auto"), "KUBE_BUILD_PLATFORMS" => K3BuildReceipt::PLATFORM}
      _stdout, stderr, status = Open3.capture3(env, *K3BuildReceipt::COMMAND, chdir: source)
      produced = File.join(source, "_output/bin", name)
      clean = git(source, "rev-parse", "HEAD") == commit && git(source, "status", "--porcelain") == ""
      platform = K3BuildReceipt.go_platform(produced) if status.success? && File.executable?(produced)
      installed = clean && platform == K3BuildReceipt::PLATFORM
      digest = install_stock_binary(produced, name) if installed

      {"target" => name, "installed" => installed, "exit_status" => status.exitstatus,
       "elapsed_seconds" => (Time.now - started).round(1), "sha256" => digest,
       "source_commit" => commit, "source_clean" => clean, "platform" => platform, "command" => K3BuildReceipt::COMMAND,
       "stderr" => installed ? nil : stderr.to_s[-4000..] || stderr.to_s}
    end

    def install_stock_binary(produced, name)
      Dir.mktmpdir("e2e-stock-", BIN) do |directory|
        path = File.join(directory, name)
        FileUtils.cp(produced, path)
        File.chmod(0o755, path)
        digest = Digest::SHA256.file(path).hexdigest
        File.rename(path, File.join(BIN, name))
        digest
      end
    end

    def publish_stock_receipt(bytes)
      Dir.mktmpdir("e2e-stock-receipt-", BIN) do |directory|
        path = File.join(directory, K3BuildReceipt::ARTIFACT)
        File.binwrite(path, bytes)
        File.rename(path, File.join(BIN, K3BuildReceipt::ARTIFACT))
      end
    end

    def git(source, *)
      stdout, _stderr, status = Open3.capture3("git", "-C", source, *)
      status.success? ? stdout.strip : nil
    end

    def failure(detail)
      {"schema_version" => 1, "kind" => "conformance_e2e_build", "passed" => false, "detail" => detail}
    end
  end
end

exit(Conformance::BuildE2E.run) if $PROGRAM_NAME == __FILE__
