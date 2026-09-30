#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate the external proof profile consumed by m2_formal_verify.rb.
#
# The profile pins the three proof tools (TLC, Lean, Apalache) by executable
# digest and version, binds each to the selected formal sources, and records
# tool_output_sha256: the digest of the tools' actual (timestamp-normalized)
# results.  The verifier re-executes every tool and refuses the profile when
# any digest, version, or result differs, so the profile can only ever
# describe proofs that really ran on this host.
#
#   ruby tools/verification/m2_proof_profile.rb [--output verification/proof-profile.json]
#     [--tlc-jar third_party/cache/tla2tools.jar] [--apalache PATH/bin/apalache-mc]
#     [--lean PATH/lean] [--apalache-length 18]

require "digest"
require "json"
require "open3"
require "optparse"

require_relative "m2_formal_verify"

module Rubernetes
  module Verification
    module M2ProofProfile
      ROOT = M2FormalVerifier::ROOT

      module_function

      def real_executable(path, label)
        resolved = File.realpath(path)
        raise "#{label} #{path} is not an executable file" unless File.file?(resolved) && File.executable?(resolved)

        resolved
      end

      def version_string(command, pattern, label)
        stdout, stderr, status = Open3.capture3(*command)
        output = stdout.to_s + stderr.to_s
        match = output.match(pattern)
        raise "#{label} version could not be read from #{command.join(" ")}: #{output[0, 200]}" unless status.success? && match

        match[1]
      end

      def build(options)
        verifier = M2FormalVerifier.new(trace_path: File.join(ROOT, "verification", "traces", "unused.json"))
        manifest = verifier.send(:formal_source_manifest)
        raise "formal sources unavailable: #{manifest["error"]}" if manifest["error"]

        java = real_executable(options.fetch(:java), "java")
        jar = File.expand_path(options.fetch(:tlc_jar), ROOT)
        raise "TLC jar is missing at #{jar}" unless File.file?(jar)

        lean = real_executable(options.fetch(:lean), "lean")
        apalache = real_executable(options.fetch(:apalache), "apalache-mc")
        tla_source = M2FormalVerifier::TLA_SOURCE
        tla_config = M2FormalVerifier::TLA_CONFIG
        apalache_config = M2FormalVerifier::APALACHE_CONFIG
        lean_source = M2FormalVerifier::LEAN_SOURCE

        # TLC has no zero-exit version flag; a run of the (small) model prints
        # "TLC2 Version ..." and exits 0 when the specification holds.
        # A single worker with a fixed seed and fingerprint function makes the
        # breadth-first search order, and therefore the report, deterministic.
        tlc_run = [java, "-cp", jar, "tlc2.TLC", "-workers", "1", "-seed", "1", "-fp", "1", "-config", tla_config, tla_source]
        tlc_version_command = tlc_run
        lean_version_command = [lean, "--version"]
        apalache_version_command = [apalache, "version"]
        tools = [
          {
            "name" => "tlc",
            "command" => tlc_run,
            "version_command" => tlc_version_command,
            "version" => version_string(tlc_version_command, /TLC2 Version (\d+\.\d+)/, "TLC"),
            "executable_sha256" => Digest::SHA256.file(java).hexdigest,
            "jar_path" => jar.delete_prefix("#{ROOT}/"),
            "jar_sha256" => Digest::SHA256.file(jar).hexdigest,
            "properties" => M2FormalVerifier::TLA_PROPERTIES,
            "source_bindings" => verifier.send(:formal_bindings_for, "tlc", manifest)
          },
          {
            "name" => "lean",
            "command" => [lean, lean_source],
            "version_command" => lean_version_command,
            "version" => version_string(lean_version_command, /version (\d+\.\d+\.\d+)/, "Lean"),
            "executable_sha256" => Digest::SHA256.file(lean).hexdigest,
            "properties" => M2FormalVerifier::LEAN_PROPERTIES,
            "source_bindings" => verifier.send(:formal_bindings_for, "lean", manifest)
          },
          {
            "name" => "apalache",
            "command" => [apalache, "check", "--config=#{apalache_config}", "--length=#{Integer(options.fetch(:apalache_length))}",
                          tla_source],
            "version_command" => apalache_version_command,
            "version" => version_string(apalache_version_command, /(\d+\.\d+\.\d+)/, "Apalache"),
            "executable_sha256" => Digest::SHA256.file(apalache).hexdigest,
            "properties" => M2FormalVerifier::APALACHE_PROPERTIES,
            "source_bindings" => verifier.send(:formal_bindings_for, "apalache", manifest)
          }
        ]
        executions = verifier.send(:execute_profile_tools, tools, manifest)
        failed = executions.reject { |execution| execution["success"] == true }
        unless failed.empty?
          detail = failed.map do |execution|
            "#{execution["name"]}: #{execution["status"]} #{execution["message"] || execution["stderr"].to_s[-400..]}"
          end
          raise "proof tools did not pass: #{detail.join(" | ")}"
        end
        records = executions.map do |execution|
          {"name" => execution["name"], "exit_status" => execution["exit_status"],
           "output_sha256" => execution["output_sha256"], "version_sha256" => execution["version_sha256"]}
        end
        profile = {
          "schema_version" => M2FormalVerifier::EXTERNAL_PROFILE_SCHEMA,
          "kind" => M2FormalVerifier::EXTERNAL_PROFILE_KIND,
          "claim" => "RuntimeLifecycle",
          "generated_at" => Time.now.utc.iso8601(6),
          "host" => {"kernel" => File.read("/proc/sys/kernel/osrelease").strip, "hostname" => File.read("/etc/hostname").strip},
          "source_files" => manifest.fetch("files"),
          "source_sha256" => manifest.fetch("sha256"),
          "tools" => tools,
          "tool_output_sha256" => M2Gate.canonical_document_digest(records),
          "tool_results" => records,
          "output_normalization" => M2FormalVerifier::OUTPUT_NORMALIZATION
        }
        profile["profile_sha256"] = M2Gate.canonical_document_digest(profile, excluded_keys: ["profile_sha256"])
        [profile, executions]
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  require "time"
  options = {
    output: File.join(Rubernetes::Verification::M2ProofProfile::ROOT, "verification", "proof-profile.json"),
    java: "/usr/bin/java",
    tlc_jar: "third_party/cache/tla2tools.jar",
    lean: ENV.fetch("LEAN", "#{Dir.home}/.elan/bin/lean"),
    apalache: ENV.fetch("APALACHE",
                        File.join(Rubernetes::Verification::M2ProofProfile::ROOT, "build/tools/apalache/apalache-0.62.2/bin/apalache-mc")),
    apalache_length: 18
  }
  OptionParser.new do |parser|
    parser.on("--output PATH") { |value| options[:output] = File.expand_path(value) }
    parser.on("--java PATH") { |value| options[:java] = value }
    parser.on("--tlc-jar PATH") { |value| options[:tlc_jar] = value }
    parser.on("--lean PATH") { |value| options[:lean] = value }
    parser.on("--apalache PATH") { |value| options[:apalache] = value }
    parser.on("--apalache-length N") { |value| options[:apalache_length] = Integer(value) }
  end.parse!(ARGV)
  profile, executions = Rubernetes::Verification::M2ProofProfile.build(options)
  File.write(options[:output], JSON.pretty_generate(profile) + "\n")
  puts JSON.generate("output" => options[:output], "profile_sha256" => profile["profile_sha256"],
                     "tools" => executions.map { |execution| execution.slice("name", "status", "exit_status", "output_sha256") })
end
