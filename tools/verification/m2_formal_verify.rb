#!/usr/bin/env ruby
# frozen_string_literal: true

# M2 verification gate.  This command runs the dependency-free Ruby trace
# checker first, then invokes TLC and Lean when their local proof tools are
# available. External profiles are authoritative only after the verifier runs
# the pinned TLC, Lean, and Apalache commands itself in an isolated directory.
# Missing tools and failed parsers are reported as INCOMPLETE, never as proof.

require "json"
require "digest"
require "open3"
require "optparse"
require "rbconfig"
require "shellwords"
require "tmpdir"

require_relative "../milestones/m2_gate"
require_relative "m2_runtime_trace_verifier"

module Rubernetes
  module Verification
    class M2FormalVerifier
      ROOT = File.expand_path("../..", __dir__)
      TLA_SOURCE = File.join(ROOT, "verification", "tla", "RuntimeLifecycle.tla")
      TLA_CONFIG = File.join(ROOT, "verification", "tla", "RuntimeLifecycle.cfg")
      # Apalache checks the safety invariants only: it has no fairness
      # semantics, so the liveness property is TLC's (complete state space).
      APALACHE_CONFIG = File.join(ROOT, "verification", "tla", "RuntimeLifecycle.apalache.cfg")
      LEAN_SOURCE = File.join(ROOT, "verification", "lean", "RuntimeLifecycle.lean")
      RUBY_TRACE_SOURCE = File.join(ROOT, "tools", "verification", "m2_runtime_trace_verifier.rb")
      RUBY_FORMAL_SOURCE = File.join(ROOT, "tools", "verification", "m2_formal_verify.rb")
      EXTERNAL_PROFILE_SCHEMA = 1
      EXTERNAL_PROFILE_KIND = "m2_external_proof_profile"
      FORMAL_TOOL_NAMES = %w[tlc lean apalache].freeze
      REQUIRED_FORMAL_TOOL_NAMES = FORMAL_TOOL_NAMES
      TLA_PROPERTIES = %w[
        TypeOK ActiveResourceInvariant IdentityNonReuseInvariant CleanupOrderInvariant
        LiveOwnerInvariant RunningInvariant DigestMismatchInvariant WorkloadStoppedInvariant
        UnknownInvariant StoppedInvariant RemovedInvariant EventuallyStoppedOrRemoved
      ].freeze
      APALACHE_PROPERTIES = (TLA_PROPERTIES - %w[EventuallyStoppedOrRemoved]).freeze
      LEAN_PROPERTIES = %w[initial_is_safe step_preserves_safety reachable_is_safe].freeze
      RUBY_PROPERTIES = %w[
        live_owner_not_released running_requires_sandbox_ready running_requires_workload_effect
        running_requires_live_process digest_mismatch_has_no_workload_effect unknown_only_cleanup_or_observe
        unknown_stop_requires_observation running_stop_result failure_rollback_preconditions
        workload_stopped_has_no_effect stopped_has_no_live_process removed_has_no_owned_resources
        resource_identity_non_reuse cleanup_reverse_acquisition
      ].freeze
      FORMAL_PROPERTY_BINDINGS = {
        "tla" => TLA_PROPERTIES,
        "apalache" => APALACHE_PROPERTIES,
        "lean" => LEAN_PROPERTIES,
        "ruby" => RUBY_PROPERTIES
      }.freeze
      MAX_PROFILE_BYTES = 16 * 1024 * 1024

      class DuplicateProfileKeyError < StandardError; end

      class DuplicateCheckingHash < Hash
        def []=(key, value)
          raise DuplicateProfileKeyError, "duplicate JSON object key #{key.inspect}" if key?(key)

          super
        end
      end

      def initialize(trace_path:, tla_source: TLA_SOURCE, tla_config: TLA_CONFIG,
                     lean_source: LEAN_SOURCE, proof_profile: nil, ruby_only: false)
        @trace_path = File.expand_path(trace_path)
        @tla_source = File.expand_path(tla_source)
        @tla_config = File.expand_path(tla_config)
        @lean_source = File.expand_path(lean_source)
        @proof_profile = proof_profile && File.expand_path(proof_profile)
        @ruby_only = ruby_only
      end

      def verify
        trace = M2RuntimeTraceVerifier.verify_file(@trace_path)
        formal_sources = formal_source_manifest
        external_profile = verify_profile
        tla_result = verify_tla
        lean_result = verify_lean
        report = {
          "schema_version" => 1,
          "milestone" => "M2",
          "kind" => "m2_formal_verification",
          "claim" => "RuntimeLifecycle",
          "success" => false,
          "passed" => false,
          "status" => "INCOMPLETE",
          "trace" => trace,
          "trace_sha256" => trace_digest,
          "ruby_trace_verifier" => {
            "available" => true,
            "success" => trace.fetch("success"),
            "properties" => FORMAL_PROPERTY_BINDINGS.fetch("ruby")
          },
          "tla" => tla_result,
          "lean" => lean_result,
          "formal_sources" => formal_sources,
          "properties" => FORMAL_PROPERTY_BINDINGS,
          "property_results" => property_results(trace, tla_result, lean_result, external_profile),
          "external_proof_profile" => external_profile,
          "fail_closed" => true
        }

        checks = [
          report.dig("ruby_trace_verifier", "success"),
          report.dig("tla", "success"),
          report.dig("lean", "success"),
          report.dig("external_proof_profile", "success")
        ]
        report["success"] = checks.all? && !@ruby_only
        report["passed"] = report["success"]
        report["status"] = report["success"] ? "PASS" : "INCOMPLETE"
        if @ruby_only
          report["success"] = false
          report["trace_passed"] = trace.fetch("success")
          report["evidence_status"] = "trace_only"
          report["warnings"] = [
            "ruby_only was requested; external model/proof checks are explicitly not counted as release evidence"
          ]
        end
        report["errors"] = formal_errors(report)
        report["report_sha256"] = M2Gate.canonical_document_digest(report, excluded_keys: ["report_sha256"])
        report
      rescue StandardError => error
        report = {
          "schema_version" => 1,
          "milestone" => "M2",
          "kind" => "m2_formal_verification",
          "claim" => "RuntimeLifecycle",
          "success" => false,
          "passed" => false,
          "status" => "INCOMPLETE",
          "trace" => {"success" => false, "violations" => []},
          "trace_sha256" => nil,
          "ruby_trace_verifier" => {"available" => true, "success" => false},
          "tla" => unavailable("orchestrator_error", error),
          "lean" => unavailable("orchestrator_error", error),
          "external_proof_profile" => unavailable("orchestrator_error", error),
          "formal_sources" => formal_source_manifest,
          "properties" => FORMAL_PROPERTY_BINDINGS,
          "errors" => ["formal verifier failed: #{error.class}: #{error.message}"],
          "fail_closed" => true
        }
        report["report_sha256"] = M2Gate.canonical_document_digest(report, excluded_keys: ["report_sha256"])
        report
      end

      private

      def verify_profile
        unless @proof_profile
          return {
            "requested" => false,
            "available" => false,
            "success" => false,
            "status" => "not_requested",
            "authoritative" => true,
            "message" => "no external proof profile was requested; formal evidence is not a pass"
          }
        end

        unless File.file?(@proof_profile)
          return {
            "requested" => true,
            "available" => false,
            "success" => false,
            "status" => "missing",
            "authoritative" => true,
            "path" => @proof_profile,
            "message" => "external proof profile is missing; this is not a pass"
          }
        end
        size = File.size(@proof_profile)
        return profile_failure("empty", "external proof profile is empty") if size.zero?
        return profile_failure("too_large", "external proof profile exceeds #{MAX_PROFILE_BYTES} bytes") if size > MAX_PROFILE_BYTES

        profile = begin
          JSON.parse(
            File.binread(@proof_profile).force_encoding(Encoding::UTF_8),
            object_class: DuplicateCheckingHash,
            allow_nan: false,
            max_nesting: 100
          )
        rescue JSON::ParserError, DuplicateProfileKeyError, EncodingError => error
          return profile_failure("invalid", "external proof profile is not strict JSON: #{error.message}")
        end
        return profile_failure("invalid_schema", "external proof profile root must be an object") unless profile.is_a?(Hash)

        errors = []
        errors << "schema_version must be #{EXTERNAL_PROFILE_SCHEMA}" unless profile["schema_version"] == EXTERNAL_PROFILE_SCHEMA
        errors << "kind must be #{EXTERNAL_PROFILE_KIND}" unless profile["kind"] == EXTERNAL_PROFILE_KIND
        errors << "claim must be RuntimeLifecycle" unless profile["claim"] == "RuntimeLifecycle"
        errors << "source_sha256 must be a SHA-256 digest" unless M2Gate::SHA256_PATTERN.match?(profile["source_sha256"].to_s)
        source_manifest = formal_source_manifest
        if source_manifest["error"]
          errors << "selected formal source files are unavailable: #{source_manifest.fetch("error")}"
        else
          source_files = profile["source_files"]
          errors << "source_files must exactly match the selected formal source files" unless source_files == source_manifest["files"]
          if M2Gate::SHA256_PATTERN.match?(profile["source_sha256"].to_s) && profile["source_sha256"] != source_manifest["sha256"]
            errors << "source_sha256 does not match the selected formal source files"
          end
        end
        if profile["skip"] == true || profile["skipped"] == true || profile["ruby_only"] == true || profile["available"] == false
          errors << "proof profile cannot use skip, ruby_only, or unavailable escape hatches"
        end
        tools = profile["tools"]
        errors << "tools must contain exactly #{REQUIRED_FORMAL_TOOL_NAMES.join(", ")}" unless
          tools.is_a?(Array) && tools.length == REQUIRED_FORMAL_TOOL_NAMES.length &&
          tools.all? { |tool| tool.is_a?(Hash) && REQUIRED_FORMAL_TOOL_NAMES.include?(tool["name"]) } &&
          tools.map { |tool| tool["name"] }.uniq.sort == REQUIRED_FORMAL_TOOL_NAMES.sort
        tool_declarations = []
        Array(tools).each_with_index do |tool, index|
          unless tool.is_a?(Hash)
            errors << "tool #{index} must be an object"
            next
          end
          label = "tool #{index}"
          errors << "#{label} name is required" unless non_empty_string?(tool["name"])
          if non_empty_string?(tool["name"])
            errors << "#{label} name is not an approved formal tool" unless FORMAL_TOOL_NAMES.include?(tool["name"])
            errors << "#{label} name is duplicated" if tool_declarations.any?(tool["name"])
            tool_declarations << tool["name"]
          end
          if tool["skip"] == true || tool["skipped"] == true || tool["ruby_only"] == true || tool["available"] == false
            errors << "#{label} cannot use skip, ruby_only, or unavailable escape hatches"
          end
          command = tool["command"]
          errors << "#{label} command must be a non-empty argv" unless command.is_a?(Array) && !command.empty? && command.all? do |part|
            non_empty_string?(part)
          end
          validate_tool_declaration(tool, label, errors, source_manifest)
        end
        errors << "profile_sha256 is required" unless M2Gate::SHA256_PATTERN.match?(profile["profile_sha256"].to_s)
        if M2Gate::SHA256_PATTERN.match?(profile["profile_sha256"].to_s) && profile["profile_sha256"] != M2Gate.canonical_document_digest(
          profile, excluded_keys: ["profile_sha256"]
        )
          errors << "profile_sha256 does not match profile content"
        end
        return profile_failure("invalid_schema", errors.join("; ")) unless errors.empty?

        executions = execute_profile_tools(tools, source_manifest)
        tool_output_records = executions.map do |execution|
          {"name" => execution["name"], "exit_status" => execution["exit_status"],
           "output_sha256" => execution["output_sha256"], "version_sha256" => execution["version_sha256"]}
        end
        expected_tool_digest = M2Gate.canonical_document_digest(tool_output_records)
        declared_tool_digest = profile["tool_output_sha256"]
        if !M2Gate::SHA256_PATTERN.match?(declared_tool_digest.to_s)
          executions << {"name" => "profile", "success" => false, "status" => "failed",
                         "message" => "tool_output_sha256 is required and must bind actual tool results"}
        elsif declared_tool_digest != expected_tool_digest
          executions << {"name" => "profile", "success" => false, "status" => "failed",
                         "message" => "tool_output_sha256 does not match actual tool results"}
        end
        all_tools_passed = executions.length == REQUIRED_FORMAL_TOOL_NAMES.length && executions.all? { |entry| entry["success"] == true }
        {
          "requested" => true,
          "available" => executions.all? { |entry| entry["available"] != false },
          "success" => all_tools_passed,
          "status" => all_tools_passed ? "PASS" : "INCOMPLETE",
          "authoritative" => true,
          "path" => @proof_profile,
          "schema_version" => profile["schema_version"],
          "kind" => profile["kind"],
          "tool_count" => tools.length,
          "profile_sha256" => profile["profile_sha256"],
          "tool_output_sha256" => expected_tool_digest,
          "source_sha256" => profile["source_sha256"],
          "source_files" => profile["source_files"],
          "tools" => executions
        }
      end

      def validate_tool_declaration(tool, label, errors, source_manifest)
        name = tool["name"]
        return unless non_empty_string?(name)

        version_command = tool["version_command"]
        errors << "#{label} version_command must be a non-empty argv" unless
          version_command.is_a?(Array) && !version_command.empty? && version_command.all? { |part| non_empty_string?(part) }
        errors << "#{label} version is required" unless non_empty_string?(tool["version"])
        errors << "#{label} executable_sha256 is required" unless M2Gate::SHA256_PATTERN.match?(tool["executable_sha256"].to_s)
        errors << "#{label} properties must bind the complete #{name} property set" unless
          tool["properties"] == FORMAL_PROPERTY_BINDINGS.fetch(
            {"tlc" => "tla", "apalache" => "apalache", "lean" => "lean"}.fetch(name, name), []
          )

        expected_bindings = formal_bindings_for(name, source_manifest)
        errors << "#{label} source_bindings must bind the selected formal sources" unless tool["source_bindings"] == expected_bindings
        command = tool["command"]
        return unless command.is_a?(Array) && !command.empty?

        executable_name = File.basename(command.first.to_s)
        valid_executable = case name
                           when "tlc"
                             %w[tlc java].include?(executable_name) && (executable_name != "java" || command.include?("tlc2.TLC"))
                           when "lean"
                             executable_name == "lean"
                           when "apalache"
                             %w[apalache-mc apalache].include?(executable_name)
                           else
                             false
                           end
        errors << "#{label} command executable is not the pinned #{name} tool" unless valid_executable
        bindings = expected_bindings.values.map { |binding| binding.fetch("path") }
        missing_binding = bindings.reject do |path|
          # A bound path may also be carried as an option value (Apalache's
          # --config=PATH form).
          command.any? do |part|
            part == path || part == File.join(ROOT,
                                              path) || part.end_with?("/#{path}") || part.end_with?("=#{path}") || part.end_with?("=#{File.join(ROOT,
                                                                                                                                                path)}")
          end
        end
        errors << "#{label} command must bind every selected source/config path" unless missing_binding.empty?
        if name == "tlc"
          errors << "#{label} command must bind RuntimeLifecycle.cfg with -config" unless
            command.each_cons(2).any? { |left, right| left == "-config" && bindings.include?(right.delete_prefix("#{ROOT}/")) }
        elsif name == "apalache"
          errors << "#{label} command must invoke the Apalache check subcommand" unless command.include?("check")
        end
      end

      def formal_bindings_for(name, source_manifest)
        labels = case name
                 when "tlc" then %w[tla_source tla_config]
                 when "lean" then %w[lean_source]
                 when "apalache" then %w[tla_source apalache_config]
                 else []
                 end
        source_manifest.fetch("files", []).select { |entry| labels.include?(entry["label"]) }
          .to_h do |entry|
          [entry.fetch("label"), {
              "path" => entry.fetch("path"),
              "sha256" => entry.fetch("sha256")
            }]
        end
      end

      def execute_profile_tools(tools, source_manifest)
        Array(tools).map do |tool|
          execute_profile_tool(tool, source_manifest)
        end
      end

      def execute_profile_tool(tool, _source_manifest)
        name = tool["name"]
        command = tool["command"]
        version_command = tool["version_command"]
        executable_path = resolve_executable(command&.first)
        unless executable_path && File.file?(executable_path) && File.executable?(executable_path)
          return unavailable_tool_result(name, command, "tool_unavailable", "pinned executable is unavailable")
        end
        unless !File.symlink?(executable_path) &&
               Digest::SHA256.file(executable_path).hexdigest == tool["executable_sha256"]
          return unavailable_tool_result(name, command, "pin_mismatch", "pinned executable SHA-256 does not match")
        end

        Dir.mktmpdir("m2-formal-profile-") do |working_directory|
          version_stdout, version_stderr, version_status = Open3.capture3(*version_command, chdir: working_directory)
          version_output = version_stdout.to_s + version_stderr.to_s
          version_ok = version_status.success? && version_output.include?(tool["version"].to_s)
          unless version_ok
            return profile_tool_result(tool, command, version_status.exitstatus,
                                       version_stdout, version_stderr, version_output,
                                       success: false, status: "version_failed",
                                       version_output: version_output,
                                       isolated_workdir: true)
          end

          stdout, stderr, status = Open3.capture3(*command, chdir: working_directory)
          output = stdout.to_s + stderr.to_s
          success = status.success? && tool_output_success?(name, stdout.to_s, stderr.to_s)
          profile_tool_result(tool, command, status.exitstatus, stdout, stderr, output,
                              success: success,
                              status: success ? "PASS" : "failed",
                              version_output: version_output,
                              isolated_workdir: true)
        end
      rescue SystemCallError => error
        unavailable_tool_result(name, command, "execution_error", "#{error.class}: #{error.message}")
      rescue StandardError => error
        unavailable_tool_result(name, command, "execution_error", "#{error.class}: #{error.message}")
      end

      def profile_tool_result(tool, command, exit_status, stdout, stderr, output,
                              success:, status:, version_output:, isolated_workdir:)
        {
          "name" => tool["name"],
          "available" => true,
          "executed" => true,
          "success" => success,
          "status" => status,
          "command" => command,
          "argv" => command,
          "exit_status" => exit_status,
          "stdout" => stdout.to_s.byteslice(0, 16_384),
          "stderr" => stderr.to_s.byteslice(0, 16_384),
          "output_sha256" => Digest::SHA256.hexdigest(normalize_tool_output(output.to_s)),
          "output_normalization" => OUTPUT_NORMALIZATION,
          "version_output" => version_output.to_s.byteslice(0, 4_096),
          "version_sha256" => Digest::SHA256.hexdigest(normalize_tool_output(version_output.to_s)),
          "isolated_workdir" => isolated_workdir,
          "properties" => tool["properties"],
          "source_bindings" => tool["source_bindings"]
        }
      end

      def unavailable_tool_result(name, command, status, message)
        {
          "name" => name,
          "available" => false,
          "executed" => false,
          "success" => false,
          "status" => status,
          "command" => command,
          "argv" => command,
          "message" => message,
          "isolated_workdir" => true
        }
      end

      def tool_output_success?(name, stdout, stderr)
        output = "#{stdout}\n#{stderr}"
        # TLC and Apalache report a successful run with the phrase
        # "No error ...".  Remove that explicit success sentence before
        # looking for failure markers; otherwise a valid bounded proof is
        # rejected merely because it says that no error was found.
        failure_scan = output.downcase.gsub(/\bno errors?\b(?:\s+has been found)?/, "")
        case name
        when "tlc"
          output.match?(/model checking completed/i) &&
            !failure_scan.match?(/\berrors?\b|violat(?:ed|ion|ions)|deadlock|counterexample/)
        when "lean"
          !output.match?(/\berror\s*:|sorry|admit/i)
        when "apalache"
          !failure_scan.match?(/\berrors?\b|counterexample|violat(?:ed|ion|ions)/) &&
            output.match?(/pass|no error|success|finished|completed/i)
        else
          false
        end
      end

      OUTPUT_NORMALIZATION = "timestamps-durations-workdir-v1"

      # Model checkers print wall-clock timestamps, durations, and the
      # per-run scratch directory.  Those bytes are not evidence of what was
      # proven; the digest binds the verdict text and every other line so a
      # proof profile can pin the real tool output across runs.
      def normalize_tool_output(text)
        text.to_s.each_line.grep_v(/Total time|It took me|Finished in|Finished computing|Finished checking|Progress\(|Starting\.\.\.|Starting SANY|Parsing file|Semantic processing|Checking temporal|initial state|states generated|at \(|_apalache-out|m2-formal-|Created by|Output directory|Check the trace|Loading configuration|Writing|Generated|Running in|Tool home|Warning: Please run|Finished by|Running breadth-first|\[pid:|heap and|seed/i).map do |line|
          line.gsub(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?/, "<timestamp>")
            .gsub(/[IEW]@\d{2}:\d{2}:\d{2}\.\d{3}/, "<log>")
            .gsub(/\b\d{2}:\d{2}:\d{2}\b/, "<time>")
            .gsub(%r{/tmp/[^\s]+}, "<workdir>")
        end.join
      end

      def resolve_executable(value)
        return nil unless non_empty_string?(value)
        return File.realpath(value) if value.include?(File::SEPARATOR) && File.file?(value)

        executable(value)
      rescue Errno::ENOENT, Errno::EACCES
        nil
      end

      def profile_failure(status, message)
        {
          "requested" => true,
          "available" => true,
          "success" => false,
          "status" => status,
          "authoritative" => true,
          "path" => @proof_profile,
          "message" => message
        }
      end

      def non_empty_string?(value)
        value.is_a?(String) && !value.empty?
      end

      def formal_source_manifest
        files = [
          ["tla_source", @tla_source],
          ["tla_config", @tla_config],
          ["apalache_config", APALACHE_CONFIG],
          ["lean_source", @lean_source],
          ["ruby_trace_verifier", RUBY_TRACE_SOURCE],
          ["ruby_formal_verifier", RUBY_FORMAL_SOURCE]
        ].map do |label, path|
          {
            "label" => label,
            "path" => source_display_path(path),
            "sha256" => Digest::SHA256.file(path).hexdigest
          }
        end
        {
          "files" => files,
          "sha256" => M2Gate.canonical_document_digest(files)
        }
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR => error
        {
          "files" => [],
          "sha256" => nil,
          "error" => "#{error.class}: #{error.message}"
        }
      end

      def source_display_path(path)
        expanded = File.expand_path(path)
        root_prefix = "#{ROOT}#{File::SEPARATOR}"
        expanded.start_with?(root_prefix) ? expanded.delete_prefix(root_prefix) : expanded
      end

      # The M2 gate binds the formal report to the lifecycle report through
      # the digest of the trace events themselves (SHA-256 of the JSON event
      # array), not of the surrounding document, so a lifecycle document
      # carrying extra measurements shares the same trace identity.
      def trace_digest
        document = M2RuntimeTraceVerifier.load_file(@trace_path)
        events = document.is_a?(Hash) ? (document["trace"] || document["events"]) : document
        return Digest::SHA256.hexdigest(JSON.generate(events)) if events.is_a?(Array)

        Digest::SHA256.file(@trace_path).hexdigest
      rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR, JSON::ParserError
        nil
      end

      def formal_errors(report)
        errors = []
        errors << "Ruby trace verifier did not pass" unless report.dig("ruby_trace_verifier", "success") == true
        errors << "TLC result is unavailable or did not pass" unless report.dig("tla", "success") == true
        errors << "Lean result is unavailable or did not pass" unless report.dig("lean", "success") == true
        errors << "external proof profile did not execute and pass all required tools" unless
          report.dig("external_proof_profile", "success") == true
        errors << "formal source manifest is unavailable" if report.dig("formal_sources", "error")
        errors
      end

      def property_results(trace, tla, lean, external_profile)
        {
          "tla" => FORMAL_PROPERTY_BINDINGS.fetch("tla").to_h do |property|
                     [property, {"success" => tla["success"] == true, "binding" => source_display_path(@tla_config)}]
                   end,
          "lean" => FORMAL_PROPERTY_BINDINGS.fetch("lean").to_h do |property|
                      [property, {"success" => lean["success"] == true, "binding" => source_display_path(@lean_source)}]
                    end,
          "ruby" => FORMAL_PROPERTY_BINDINGS.fetch("ruby").to_h do |property|
                      [property, {"success" => trace["success"] == true, "binding" => source_display_path(RUBY_TRACE_SOURCE)}]
                    end,
          "external" => FORMAL_TOOL_NAMES.to_h do |tool|
                          [tool, {"success" => external_profile["success"] == true, "binding" => "external_proof_profile"}]
                        end
        }
      end

      def verify_tla
        missing = [@tla_source, @tla_config].reject { |path| File.file?(path) }
        unless missing.empty?
          return {
            "available" => false,
            "success" => false,
            "status" => "missing_source",
            "missing" => missing
          }
        end

        unless tlc_command
          return {
            "available" => false,
            "success" => false,
            "status" => "tool_unavailable",
            "properties" => TLA_PROPERTIES,
            "message" => "TLC is not installed; Ruby trace verification remains available"
          }
        end

        command = tlc_command + ["-config", @tla_config, @tla_source]
        run_external(command, "tlc").merge("properties" => TLA_PROPERTIES,
                                           "source_bindings" => {"tla_source" => source_display_path(@tla_source),
                                                                 "tla_config" => source_display_path(@tla_config)})
      end

      def verify_lean
        unless File.file?(@lean_source)
          return {
            "available" => false,
            "success" => false,
            "status" => "missing_source",
            "properties" => LEAN_PROPERTIES,
            "missing" => [@lean_source]
          }
        end

        lean = executable("lean")
        unless lean
          return {
            "available" => false,
            "success" => false,
            "status" => "tool_unavailable",
            "properties" => LEAN_PROPERTIES,
            "message" => "Lean is not installed; Ruby trace verification remains available"
          }
        end

        run_external([lean, @lean_source], "lean").merge("properties" => LEAN_PROPERTIES,
                                                         "source_bindings" => {"lean_source" => source_display_path(@lean_source)})
      end

      def tlc_command
        return Shellwords.split(ENV.fetch("TLC_COMMAND")) if ENV["TLC_COMMAND"] && !ENV["TLC_COMMAND"].strip.empty?

        jar = ENV.fetch("TLC_JAR", nil)
        jar ||= [
          File.join(ROOT, "third_party", "cache", "tla2tools.jar"),
          "/opt/tla/tla2tools.jar"
        ].find { |candidate| File.file?(candidate) }
        if jar && File.file?(jar)
          java = executable("java")
          return [java, "-cp", File.expand_path(jar), "tlc2.TLC"] if java
        end
        tlc = executable("tlc")
        tlc && [tlc]
      end

      def executable(name)
        ENV.fetch("PATH", "").split(File::PATH_SEPARATOR).each do |directory|
          path = File.join(directory, name)
          return path if File.file?(path) && File.executable?(path)
        end
        nil
      end

      def run_external(command, tool)
        # TLC writes its default state directory and Apalache writes its
        # default _apalache-out directory relative to the working directory.
        # Keep those tool-owned artifacts out of the source tree, while
        # retaining the exact argv in the report for reproducible evidence.
        Dir.mktmpdir("m2-formal-") do |working_directory|
          stdout, stderr, status = Open3.capture3(*command, chdir: working_directory)
          result = {
            "available" => true,
            "success" => status.success? && tool_output_success?(tool, stdout, stderr),
            "status" => status.success? && tool_output_success?(tool, stdout, stderr) ? "passed" : "failed",
            "tool" => tool,
            "command" => command,
            "argv" => command,
            "exit_status" => status.exitstatus,
            "stdout" => stdout.byteslice(0, 16_384),
            "stderr" => stderr.byteslice(0, 16_384),
            "isolated_workdir" => true
          }
          result["output_sha256"] = Digest::SHA256.hexdigest(normalize_tool_output(stdout.to_s + stderr.to_s))
          result["output_normalization"] = OUTPUT_NORMALIZATION
          result
        end
      rescue StandardError => error
        unavailable("execution_error", error).merge("tool" => tool, "command" => command)
      end

      def unavailable(status, error)
        {
          "available" => false,
          "success" => false,
          "status" => status,
          "message" => "#{error.class}: #{error.message}"
        }
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {
    trace: nil,
    proof_profile: nil,
    ruby_only: false,
    pretty: false
  }
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: ruby m2_formal_verify.rb --trace TRACE.json [options]"
    opts.on("--trace PATH", "Runtime trace JSON or JSONL path") { |path| options[:trace] = path }
    opts.on("--proof-profile PATH", "External proof profile; missing path fails closed") do |path|
      options[:proof_profile] = path
    end
    opts.on("--ruby-only", "Run only the dependency-free trace checker; not release evidence") do
      options[:ruby_only] = true
    end
    opts.on("--pretty", "Pretty-print the JSON report") { options[:pretty] = true }
  end

  begin
    parser.parse!
    raise OptionParser::MissingArgument, "--trace PATH is required" unless options[:trace]

    verifier = Rubernetes::Verification::M2FormalVerifier.new(
      trace_path: options.fetch(:trace),
      proof_profile: options[:proof_profile],
      ruby_only: options[:ruby_only]
    )
    report = verifier.verify
    puts(options[:pretty] ? JSON.pretty_generate(report) : JSON.generate(report))
    exit(report.fetch("success") ? 0 : 1)
  rescue OptionParser::ParseError => error
    warn error.message
    warn parser
    exit 2
  end
end
