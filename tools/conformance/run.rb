#!/usr/bin/env ruby
# frozen_string_literal: true

# Kubernetes compatibility runner (spec/verification/kubernetes-compatibility.md).
#
# Executes the K0-K7 lanes against a real Rubernetes cluster and writes the
# run manifest required by the "Evidence Manifest" section.  The runner never
# fabricates a lane result: a lane whose prerequisites are absent reports
# `status: "INCOMPLETE"` with the reason, which the M8 gate treats as a
# failure.  No lane may narrow a focus, add a skip, extend a timeout or
# rewrite a failed run.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "securerandom"
require "time"

require_relative "lock"
require_relative "k0_input_integrity"
require_relative "lanes"

module Conformance
  module Runner
    L = Conformance::Lock
    ROOT = L::ROOT
    LANES = %w[K0 K1 K2 K3 K4 K5 K6 K7].freeze

    module_function

    def parse(argv)
      options = {
        lanes: LANES.dup,
        profile: nil,
        kubeconfig: ENV["RUBERNETES_CONFORMANCE_KUBECONFIG"],
        oracle_kubeconfig: ENV["RUBERNETES_CONFORMANCE_ORACLE_KUBECONFIG"],
        source_root: ENV.fetch("RUBERNETES_KUBERNETES_SOURCE", "/tmp/kubernetes-v1.36.2"),
        output_root: File.join(ROOT, "artifacts/conformance"),
        platform: "linux/amd64"
      }
      OptionParser.new do |parser|
        parser.on("--lanes LIST", "Comma-separated lanes (default: all)") { |v| options[:lanes] = v.split(",").map(&:strip) }
        parser.on("--profile NAME", "Cluster profile from profiles.yml") { |v| options[:profile] = v }
        parser.on("--kubeconfig PATH", "Rubernetes cluster kubeconfig") { |v| options[:kubeconfig] = v }
        parser.on("--oracle-kubeconfig PATH", "Kubernetes oracle kubeconfig (K5)") { |v| options[:oracle_kubeconfig] = v }
        parser.on("--source-root PATH", "Pinned Kubernetes v1.36.2 checkout") { |v| options[:source_root] = v }
        parser.on("--output-root PATH", "Artifact root") { |v| options[:output_root] = v }
        parser.on("--platform NAME", "Target platform (default linux/amd64)") { |v| options[:platform] = v }
      end.parse!(argv)
      unknown = options[:lanes] - LANES
      raise ArgumentError, "unknown lanes: #{unknown.join(", ")}" unless unknown.empty?

      options
    end

    def run(argv = ARGV)
      options = parse(argv)
      profile = resolve_profile(options[:profile])
      run_id = SecureRandom.uuid
      started_at = Time.now.utc.iso8601
      directory = File.join(options[:output_root], "#{Time.now.utc.strftime("%Y%m%dT%H%M%S.%6NZ")}-#{profile.fetch("name")}")
      FileUtils.mkdir_p(directory)

      results = options[:lanes].map do |lane|
        execute_lane(lane, options: options, profile: profile, directory: directory)
      end

      manifest = {
        "schemaVersion" => 1,
        "schema_version" => 1,
        "suite" => "K0-K7-kubernetes-compatibility",
        "runId" => run_id,
        "sourceCommit" => L.source_commit,
        "rubernetesCommit" => rubernetes_commit,
        "profile" => profile.fetch("name"),
        "profileDefinition" => profile,
        "inputsLock" => "third_party/locks/kubernetes-v1.36.2.json",
        "platform" => options[:platform],
        "startedAt" => started_at,
        "finishedAt" => Time.now.utc.iso8601,
        "lanes" => results,
        "summary" => summarize(results),
        "artifacts" => artifact_entries(directory)
      }
      path = File.join(directory, "manifest.json")
      File.write(path, "#{JSON.pretty_generate(manifest)}\n")
      manifest["artifacts"] = artifact_entries(directory)
      File.write(path, "#{JSON.pretty_generate(manifest)}\n")
      puts JSON.pretty_generate(manifest.reject { |key, _| key == "lanes" }.merge("lanes" => results.map { |lane| lane.slice("lane", "status", "passed", "reason") }))
      manifest.fetch("summary").fetch("passed") ? 0 : 1
    end

    def execute_lane(lane, options:, profile:, directory:)
      lane_directory = File.join(directory, lane.downcase)
      FileUtils.mkdir_p(lane_directory)
      started = Time.now.utc.iso8601
      result =
        case lane
        when "K0"
          K0.run(source_root: options[:source_root], platform: options[:platform],
                 kubeconfig: options[:kubeconfig], oracle_kubeconfig: options[:oracle_kubeconfig])
        when "K1" then Lanes::K1.run(options: options, profile: profile, directory: lane_directory)
        when "K2" then Lanes::K2.run(options: options, profile: profile, directory: lane_directory)
        when "K3" then Lanes::K3.run(options: options, profile: profile, directory: lane_directory)
        when "K4" then Lanes::K4.run(options: options, profile: profile, directory: lane_directory)
        when "K5" then Lanes::K5.run(options: options, profile: profile, directory: lane_directory)
        when "K6" then Lanes::K6.run(options: options, profile: profile, directory: lane_directory)
        when "K7" then Lanes::K7.run(options: options, profile: profile, directory: lane_directory)
        end
      result = {"lane" => lane, "passed" => false, "status" => "INCOMPLETE", "reason" => "lane produced no result"} if result.nil?
      result["lane"] ||= lane
      result["status"] ||= result.fetch("passed", false) ? "COMPLETE" : "FAILED"
      result["startedAt"] = started
      result["finishedAt"] = Time.now.utc.iso8601
      File.write(File.join(lane_directory, "result.json"), "#{JSON.pretty_generate(result)}\n")
      result
    rescue StandardError => error
      # A crashed lane is a lane failure, never a silently missing lane.
      {"lane" => lane, "passed" => false, "status" => "FAILED",
       "reason" => "#{error.class}: #{error.message}", "backtrace" => error.backtrace&.first(5),
       "startedAt" => started, "finishedAt" => Time.now.utc.iso8601}
    end

    def summarize(results)
      {
        "lanes" => results.length,
        "complete" => results.count { |lane| lane["status"] == "COMPLETE" },
        "incomplete" => results.count { |lane| lane["status"] == "INCOMPLETE" },
        "failed" => results.count { |lane| lane["status"] == "FAILED" },
        "passed" => results.all? { |lane| lane["status"] == "COMPLETE" && lane["passed"] == true }
      }
    end

    def resolve_profile(name)
      profiles = L.profiles.fetch("profiles")
      return profiles.first if name.nil?

      profiles.find { |profile| profile.fetch("name") == name } ||
        raise(ArgumentError, "unknown profile #{name.inspect}; known: #{profiles.map { |p| p.fetch("name") }.join(", ")}")
    end

    def rubernetes_commit
      out, _err, status = Open3.capture3("git", "-C", ROOT, "rev-parse", "HEAD")
      return out.strip if status.success? && out.strip.match?(/\A[0-9a-f]{40}\z/)

      # A tree without .git still identifies itself: the content digest of the
      # tracked source inventory stands in, marked so it cannot be mistaken
      # for a commit id.
      "sha256:#{Conformance::Lanes.source_tree_digest}"
    end

    def artifact_entries(directory)
      Dir.glob(File.join(directory, "**", "*")).select { |path| File.file?(path) }.sort.map do |path|
        {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest}
      end
    end
  end
end

exit(Conformance::Runner.run) if $PROGRAM_NAME == __FILE__
