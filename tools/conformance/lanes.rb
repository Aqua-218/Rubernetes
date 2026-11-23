#!/usr/bin/env ruby
# frozen_string_literal: true

# K1-K7 lane implementations (spec/verification/kubernetes-compatibility.md).
#
# Every lane executes the real upstream tool against a real cluster.  When a
# prerequisite is missing the lane returns INCOMPLETE with the precise reason;
# it never substitutes a mock, narrows a focus, adds a skip or reuses another
# run's result.  The M8 gate rejects any INCOMPLETE lane.

require "digest"
require "fileutils"
require "find"
require "json"
require "open3"
require "rbconfig"
require "securerandom"
require "shellwords"
require "time"

require_relative "lock"
require_relative "k1_evidence"
require_relative "k1_ginkgo_report"
require_relative "k3_internal_contract_index"
require_relative "k3_local_volume_contract_index"
require_relative "k3_csi_contract_index"
require_relative "k3_junit"
require_relative "k3_build_receipt"
require_relative "k4_node_conformance"
require_relative "k7_evidence"
require_relative "k6_evidence"
require_relative "../milestones/m0_source_inventory"

module Conformance
  module Lanes
    L = Conformance::Lock
    ROOT = L::ROOT
    SOURCE_INPUTS = %w[
      .gitignore .ruby-version Gemfile Gemfile.lock LICENSE NOTICE README.ja.md README.md Rakefile
      apps benchmarks config deploy examples exe ext generated kubelet.conf.d lib packaging
      rubernetes.gemspec ruby schema sig spec spec.md test third_party tools verification
    ].freeze
    SOURCE_CACHE = %r{(?:\A|/)(?:\.git|\.bundle|\.cache|node_modules|build|artifacts|cache)(?:/|\z)}
    SOURCE_SCRATCH = %r{\A(?:apps/[^/]+/(?:log|tmp|storage|vendor/bundle)|verification/tla/states)(?:/|\z)|\Athird_party/(?!locks(?:/|\z))}
    SOURCE_BUILD_OUTPUT = /\.(?:gem|log|o|so)\z/

    module_function

    # A dirty checkout or source export has no commit that identifies its
    # actual inputs. Read the source and packaged configuration without
    # walking runtime data or following links to other trees.
    def source_tree_digest(root: ROOT)
      roots = SOURCE_INPUTS.filter_map do |input|
        path = File.join(root, input)
        path if File.exist?(path) || File.symlink?(path)
      end
      files = Find.find(*roots).filter_map do |path|
        relative = path.delete_prefix("#{root}/")
        Find.prune if SOURCE_CACHE.match?(relative) || SOURCE_SCRATCH.match?(relative)
        Find.prune if M0SourceInventory.dashboard_local?(relative) { File.lstat(path).directory? }
        next if SOURCE_BUILD_OUTPUT.match?(relative)

        stat = File.lstat(path)
        [relative, stat] if stat.file? || stat.symlink?
      end

      digest = Digest::SHA256.new
      files.sort_by(&:first).each do |relative, stat|
        path = File.join(root, relative)
        digest << relative << "\0"
        if stat.symlink?
          digest << "link\0" << File.readlink(path) << "\0"
        else
          digest << (stat.mode.nobits?(0o111) ? "file\0" : "executable\0")
          digest << Digest::SHA256.file(path).digest
        end
      end
      digest.hexdigest
    end

    def incomplete(lane, reason, **extra)
      {"lane" => lane, "passed" => false, "status" => "INCOMPLETE", "reason" => reason}.merge(extra)
    end

    def tool_path(name)
      path = File.join(ROOT, "build/conformance/bin", name)
      return path if File.executable?(path)

      ENV.fetch("PATH", "").split(File::PATH_SEPARATOR)
        .map { |dir| File.join(dir, name) }.find { |candidate| File.executable?(candidate) }
    end

    def cluster_reachable?(kubeconfig)
      return false if kubeconfig.nil? || !File.file?(kubeconfig)

      kubectl = File.join(ROOT, "build/tools/kubectl-v1.36.2")
      kubectl = "kubectl" unless File.executable?(kubectl)
      _out, _err, status = Open3.capture3({"KUBECONFIG" => kubeconfig}, *in_cluster_namespace([kubectl, "version", "--output=json"]))
      status.success?
    rescue Errno::ENOENT
      false
    end

    # A cluster brought up inside a network namespace (tools/conformance/
    # netns_env.sh; the IPv6 and dual-stack profiles) is reachable at its
    # kubeconfig's loopback endpoint only from inside that namespace, so the
    # runners are entered into it.  The namespace is named by
    # RUBERNETES_M8_NETNS; unset, commands run where the lane runs.
    def in_cluster_namespace(command)
      namespace = ENV.fetch("RUBERNETES_M8_NETNS", "").strip
      return command if namespace.empty?
      raise ArgumentError, "RUBERNETES_M8_NETNS must be a namespace name" unless namespace.match?(/\A[A-Za-z0-9_.-]+\z/)

      ["ip", "netns", "exec", namespace, *command]
    end

    # A runner that never returns is indistinguishable from a slow lane, and an
    # upstream runner will happily wait forever on a pod that can never start.
    # The deadline is enforced here so the lane records a real result instead
    # of hanging; the runner leads its own process group so the whole tree
    # goes down with it.
    def capture(command, env: {}, chdir: ROOT, timeout: nil, stdin_data: nil, stdout: +"", stderr: +"")
      command = in_cluster_namespace(command)
      started = Time.now.utc
      status = nil
      timed_out = false
      Open3.popen3(env, *command, chdir: chdir, pgroup: true) do |stdin, out, err, thread|
        begin
          stdin.write(stdin_data) if stdin_data
        rescue Errno::EPIPE
          # The command failed before reading its input. Capture its error.
        end
        stdin.close
        readers = {out => stdout, err => stderr}
        deadline = timeout && (Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout))
        until readers.empty?
          remaining = deadline && (deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC))
          if remaining && remaining <= 0
            timed_out = true
            break
          end
          ready = IO.select(readers.keys, nil, nil, remaining ? [remaining, 1.0].min : 1.0)
          next if ready.nil? && thread.alive?
          break if ready.nil? && !thread.alive?

          Array(ready && ready.first).each do |io|
            begin
              chunk = io.readpartial(65_536)
            rescue EOFError
              readers.delete(io)
              next
            end
            readers.fetch(io) << chunk
          end
        end
        if timed_out
          terminate_group(thread.pid)
          stderr << "\nlane runner exceeded #{timeout}s and was terminated\n"
        end
        status = thread.value
      rescue IOError, SystemCallError, Zlib::Error
        terminate_group(thread.pid) if thread.alive?
        raise
      end
      {
        "command" => command,
        "exit_status" => status&.exitstatus,
        "timed_out" => timed_out,
        "timeout_seconds" => timeout,
        "stdout" => stdout,
        "stderr" => stderr,
        "started_at" => started.iso8601,
        "finished_at" => Time.now.utc.iso8601,
        "elapsed_seconds" => (Time.now.utc - started).round(3)
      }.compact
    end

    # Drain both pipes directly to their gzip streams, including arbitrary
    # bytes from diagnostics. Return only the command and stream identities.
    def capture_archived(command, directory:, basename:, timeout:)
      stdout_name = "#{basename}.stdout.gz"
      stderr_name = "#{basename}.stderr.gz"
      Zlib::GzipWriter.open(File.join(directory, stdout_name)) do |stdout|
        Zlib::GzipWriter.open(File.join(directory, stderr_name)) do |stderr|
          result = capture(command, timeout: timeout, stdout: stdout, stderr: stderr)
          result.except("stdout", "stderr").merge("stdout_artifact" => stdout_name, "stderr_artifact" => stderr_name,
                                                  "stdout_bytes" => stdout.pos, "stderr_bytes" => stderr.pos)
        end
      end
    end

    def artifact_for(path)
      {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest}
    end

    def terminate_group(pid)
      Process.kill("TERM", -pid)
      40.times do
        return if Process.waitpid(pid, Process::WNOHANG)

        sleep 0.25
      end
      Process.kill("KILL", -pid)
    rescue Errno::ESRCH, Errno::ECHILD
      nil
    end

    def record(directory, name, content)
      path = File.join(directory, name)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, content.is_a?(String) ? content : "#{JSON.pretty_generate(content)}\n")
      {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest}
    end

    # ---------------------------------------------------------------- K1 ----
    # Upstream [Conformance] via Hydrophone, argv-equivalent to the spec.
    module K1
      module_function

      # Upstream hydrophone waits on the conformance pod indefinitely once it
      # exists, so a pod that can never start (an exhausted disk, a missing
      # image) hangs the lane rather than failing it.
      HYDROPHONE_TIMEOUT_SECONDS = Integer(ENV.fetch("RUBERNETES_M8_K1_TIMEOUT", "2700"))

      def run(options:, profile:, directory:)
        kubeconfig = options[:kubeconfig]
        return Lanes.incomplete("K1", "no kubeconfig: set --kubeconfig or RUBERNETES_CONFORMANCE_KUBECONFIG") if kubeconfig.nil?
        return Lanes.incomplete("K1", "kubeconfig #{kubeconfig} does not reach a cluster") unless Lanes.cluster_reachable?(kubeconfig)

        hydrophone = Lanes.tool_path("hydrophone")
        return Lanes.incomplete("K1", "hydrophone binary is not installed; run `rake m8:tools`") if hydrophone.nil?

        begin
          definition, codenames = K1Evidence.definition(options.fetch(:source_root))
        rescue ArgumentError, Errno::ENOENT => error
          return Lanes.incomplete("K1", "pinned conformance definition unavailable: #{error.message}")
        end
        definition_artifact = Lanes.record(directory, "conformance-definition.yaml", definition)
        output = File.join(directory, "hydrophone")
        FileUtils.mkdir_p(output)
        # Hydrophone refuses to deploy when its namespace survives an earlier
        # run (aborted pod, killed runner). --cleanup is a standalone action,
        # so it runs as a separate preparatory invocation and is recorded too.
        cleanup = Lanes.capture([hydrophone, "--kubeconfig", kubeconfig, "--cleanup"])
        command = [
          hydrophone,
          "--kubeconfig", kubeconfig,
          "--conformance",
          "--conformance-image", L.reference_by_digest(L.kubernetes.fetch("conformance_image")),
          "--busybox-image", L.reference_by_digest(L.support_images.fetch("busybox")),
          "--parallel", "1",
          K1GinkgoReport::FLAG,
          "--output-dir", output
        ]
        execution = K1GinkgoReport.capture(kubeconfig, output) do
          Lanes.capture_archived(command, directory: directory, basename: "hydrophone", timeout: HYDROPHONE_TIMEOUT_SECONDS)
        end
        artifacts = [definition_artifact, Lanes.record(directory, "hydrophone-cleanup.json", cleanup),
                     Lanes.record(directory, "hydrophone-command.json", execution)]
        stdout = File.join(directory, execution.fetch("stdout_artifact"))
        artifacts << Lanes.artifact_for(stdout) << Lanes.artifact_for(File.join(directory, execution.fetch("stderr_artifact")))
        archive = File.join(output, K1GinkgoReport::ARCHIVE)
        recorder_log = File.join(output, K1GinkgoReport::RECORDER_LOG)
        [archive, recorder_log, File.join(output, "e2e.log")].each do |path|
          artifacts << Lanes.artifact_for(path) if File.file?(path)
        end
        junit = Dir.glob(File.join(output, "**", "*.xml")).first
        if junit.nil?
          reason = if execution["timed_out"]
                     "hydrophone exceeded #{execution.fetch("timeout_seconds")}s and was terminated"
                   else
                     "hydrophone produced no JUnit report"
                   end
          progress = begin
            Zlib::GzipReader.open(stdout) { |log| Lanes.ginkgo_progress(log) }
          rescue StandardError
            # Reporting how far a run got must never be the reason a lane fails.
            nil
          end
          extra = {"execution" => execution.slice("exit_status", "timed_out", "stderr_artifact"), "artifacts" => artifacts}
          if progress
            extra["progress"] = progress
            artifacts << Lanes.record(directory, "ginkgo-progress.json", progress)
          end
          return Lanes.incomplete("K1", reason, **extra)
        end

        summary, joined, junit_cases = Zlib::GzipReader.open(stdout) { |log| K1Evidence.junit(junit, codenames: codenames, stdout: log) }
        artifacts << Lanes.artifact_for(junit)
        artifacts << Lanes.record(directory, "codename-join.json", joined)
        expected = L.profiles.fetch("conformance").fetch("expected_tests")
        ginkgo = ginkgo_join(archive, junit_cases, expected)
        artifacts << Lanes.record(directory, "ginkgo-join.json", ginkgo)
        suite_passed = execution["exit_status"] == 0 && !execution["timed_out"] &&
                       K1Evidence.complete?(summary, joined, expected: expected)
        status = if !suite_passed
                   "FAILED"
                 elsif ginkgo["passed"]
                   "COMPLETE"
                 elsif !File.file?(archive)
                   "INCOMPLETE"
                 else
                   "FAILED"
                 end
        {
          "lane" => "K1", "passed" => status == "COMPLETE", "status" => status, "reason" => ginkgo["reason"],
          "profile" => profile.fetch("name"), "summary" => summary, "codenames" => joined,
          "ginkgo" => ginkgo, "artifacts" => artifacts
        }.compact
      end

      def ginkgo_join(archive, junit, expected)
        return {"passed" => false, "reason" => "stock Ginkgo JSON report was not captured"} unless File.file?(archive)

        result = K1GinkgoReport.join(archive, junit, expected: expected)
        result["reason"] = "stock Ginkgo JSON disagrees with the JUnit cases or the locked execution" unless result["passed"]
        result
      rescue JSON::ParserError, Zlib::Error, EOFError, KeyError, ArgumentError, TypeError => error
        {"passed" => false, "reason" => "invalid stock Ginkgo JSON report: #{error.message}"}
      end
    end

    # ---------------------------------------------------------------- K2 ----
    module K2
      module_function

      RUN_TIMEOUT = Integer(ENV.fetch("RUBERNETES_M8_K2_TIMEOUT", "7200"))

      def run(options:, profile:, directory:)
        kubeconfig = options[:kubeconfig]
        return Lanes.incomplete("K2", "no kubeconfig for the certified-conformance run") if kubeconfig.nil?
        return Lanes.incomplete("K2", "kubeconfig #{kubeconfig} does not reach a cluster") unless Lanes.cluster_reachable?(kubeconfig)

        sonobuoy = Lanes.tool_path("sonobuoy")
        return Lanes.incomplete("K2", "sonobuoy binary is not installed; run `rake m8:tools`") if sonobuoy.nil?

        require_relative "k2_evidence"
        begin
          definition, codenames = K1Evidence.definition(options.fetch(:source_root))
        rescue ArgumentError, Errno::ENOENT => error
          return Lanes.incomplete("K2", "pinned conformance definition unavailable: #{error.message}")
        end
        artifacts = [Lanes.record(directory, "conformance-definition.yaml", definition)]
        namespace = "sonobuoy-k2-#{SecureRandom.hex(6)}"
        connection = ["--namespace", namespace, "--kubeconfig", kubeconfig]
        # sonobuoy's preflight looks for kube-dns/CoreDNS Pods in kube-system;
        # Rubernetes serves cluster DNS from the node agent, so only that
        # check is skipped.  The conformance run itself is untouched.
        command = [
          sonobuoy, "run", "--mode=certified-conformance", "--skip-preflight=dnscheck",
          *connection,
          "--kubernetes-version=v#{L.profiles.fetch("kubernetes").fetch("tag").delete_prefix("v")}",
          "--kube-conformance-image=#{L.reference_by_digest(L.kubernetes.fetch("conformance_image"))}",
          "--sonobuoy-image=#{L.reference_by_digest(L.runner("sonobuoy").fetch("image"))}",
          "--wait"
        ]
        archive = File.join(directory, "sonobuoy-results.tar.gz")
        begin
          execution = Lanes.capture(command, timeout: RUN_TIMEOUT)
          artifacts << Lanes.record(directory, "sonobuoy-command.json", execution)
          retrieve = Lanes.capture([sonobuoy, "retrieve", directory, "--filename", File.basename(archive), *connection], timeout: 180)
          artifacts << Lanes.record(directory, "sonobuoy-retrieve.json", retrieve)
        ensure
          cleanup = Lanes.capture([sonobuoy, "delete", "--wait", *connection], timeout: 240)
          artifacts << Lanes.record(directory, "sonobuoy-delete.json", cleanup)
        end
        unless File.file?(archive)
          return Lanes.incomplete("K2", "sonobuoy produced no results archive",
                                  "execution" => execution.slice("exit_status", "stderr"), "artifacts" => artifacts)
        end

        artifacts << {"path" => archive.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(archive).hexdigest}
        evidence = K2Evidence.read(archive, codenames: codenames)
        artifacts << Lanes.record(directory, "sonobuoy-conformance.json", evidence)
        passed = [execution, retrieve, cleanup].all? { |step| step.fetch("exit_status") == 0 } && evidence.fetch("passed")
        {"lane" => "K2", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "profile" => profile.fetch("name"), "archive" => archive.delete_prefix("#{ROOT}/"), "artifacts" => artifacts}
      end
    end

    # ---------------------------------------------------------------- K3 ----
    # Portable upstream Linux e2e, with the selection ledger the spec requires.
    module K3
      LEDGER = File.join(ROOT, "test/compatibility/api/selection-ledger.json")

      module_function

      def run(options:, profile:, directory:)
        return Lanes.incomplete("K3", "selection ledger #{LEDGER.delete_prefix("#{ROOT}/")} is missing") unless File.file?(LEDGER)

        ledger_bytes = File.binread(LEDGER)
        ledger = JSON.parse(ledger_bytes)
        inventory = ledger.fetch("tests", [])
        classified = inventory.group_by { |entry| entry["classification"] }
        unclassified = inventory.reject do |entry|
          %w[required platform-inapplicable provider-private implementation-internal].include?(entry["classification"])
        end
        unlinked = inventory.select do |entry|
          %w[provider-private implementation-internal].include?(entry["classification"]) &&
            entry["external_contract"] == true && !linked_replacement?(entry)
        end
        artifacts = [Lanes.record(directory, "selection-ledger-summary.json",
                                  {"total" => inventory.length,
                                   "by_classification" => classified.transform_values(&:length),
                                   "unclassified" => unclassified.length,
                                   "unlinked_external_contracts" => unlinked.length})]
        artifacts << Lanes.record(directory, "unlinked-contracts.json", replacement_backlog(unlinked))
        kubeconfig = options[:kubeconfig]
        unless Lanes.cluster_reachable?(kubeconfig)
          return Lanes.incomplete("K3", "ledger is well formed but no cluster is reachable to execute the required tests",
                                  "ledger" => {"total" => inventory.length, "unclassified" => unclassified.length},
                                  "artifacts" => artifacts)
        end

        binary = Lanes.tool_path("e2e.test")
        if binary.nil?
          return Lanes.incomplete("K3", "upstream e2e.test binary is not built; run `rake m8:e2e_build`",
                                  "artifacts" => artifacts)
        end

        binary_sha = Digest::SHA256.file(binary).hexdigest
        receipt = K3BuildReceipt.local(binary, sha256: binary_sha, platform: options.fetch(:platform, K3BuildReceipt::PLATFORM))
        artifacts << Lanes.record(directory, K3BuildReceipt::ARTIFACT, receipt) if receipt
        replacements = run_replacements(inventory, kubeconfig, directory, artifacts, source: options.fetch(:source_root), binary: binary)
        required = inventory.select { |entry| entry["classification"] == "required" }
        # One focus regex over all required specs is far above the kernel's
        # per-argument limit (MAX_ARG_STRLEN, 128 KiB), so the selection is
        # executed in chunks, each its own e2e.test process with its own
        # report directory; a chunk's exit status is upstream's verdict on
        # those specs and nothing is retried or re-interpreted.
        chunks, executions = run_required(binary, kubeconfig, directory, required) do |planned_chunks|
          selection = {"kubernetes_tag" => ledger.dig("source", "kubernetes_tag"), "profile" => profile.fetch("name"),
                       "ledger_sha256" => Digest::SHA256.hexdigest(ledger_bytes),
                       "binary_path" => binary, "binary_sha256" => binary_sha, "chunks" => planned_chunks}
          artifacts << Lanes.record(directory, "upstream-selection.json", selection)
        end
        executions.each_with_index do |execution, index|
          command_name = format("e2e-command-%03d.json", index)
          [command_name, *execution.values_at("stdout_artifact", "stderr_artifact")].each do |name|
            artifacts << Lanes.artifact_for(File.join(directory, name))
          end
        end
        totals = junit_totals(directory, chunks, executions: executions)
        artifacts << Lanes.record(directory, "e2e-totals.json", totals)
        binary_unchanged = Digest::SHA256.file(binary).hexdigest == binary_sha
        passed = binary_unchanged && required.any? && executions.all? { |execution| execution["exit_status"] == 0 && !execution["timed_out"] } &&
                 totals.fetch("reports") == chunks.length && totals.fetch("passed") == required.length &&
                 totals.fetch("incomplete_chunks").empty? && unclassified.empty? && unlinked.empty? && replacements.fetch("passed")
        {"lane" => "K3", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "required" => required.length, "unclassified" => unclassified.length,
         "unlinked_external_contracts" => unlinked.length, "chunks" => chunks.length, "totals" => totals,
         "replacement_totals" => replacements, "artifacts" => artifacts}
      end

      FOCUS_BYTES = 96 * 1024
      SPECS_PER_CHUNK = 32
      SUITE_NAME = "Kubernetes e2e suite"
      CONCURRENCY = Integer(ENV.fetch("RUBERNETES_M8_K3_PARALLEL", "4"))
      CHUNK_TIMEOUT = Integer(ENV.fetch("RUBERNETES_M8_K3_CHUNK_TIMEOUT", "7200"))

      def replacement_exists?(path)
        return false if path.to_s.empty?

        full_path = File.expand_path(path, ROOT)
        full_path.start_with?("#{ROOT}/") && File.exist?(full_path)
      end

      def linked_replacement?(entry)
        path = entry["replacement_test"]
        return false unless replacement_exists?(path)

        case entry["classification"]
        when "implementation-internal"
          expected = K3InternalContractIndex::CASES[entry["id"]]
          expected && path == K3InternalContractIndex::RUNNER && expected == entry["replacement_case"]
        when "provider-private"
          index = [K3LocalVolumeContractIndex, K3CSIContractIndex].find { |candidate| path == candidate::RUNNER }
          expected = index&.case_for(entry["id"], entry["file"])
          expected && expected == entry["replacement_case"]
        end
      end

      def run_replacements(inventory, kubeconfig, directory, artifacts, source:, binary:)
        results = [run_internal_replacements(inventory, kubeconfig, directory, artifacts),
                   run_local_volume_replacements(inventory, kubeconfig, directory, artifacts),
                   run_csi_replacements(inventory, kubeconfig, directory, artifacts, source: source, binary: binary)]
        {"expected" => results.sum { |result| result.fetch("expected") },
         "successful" => results.sum { |result| result.fetch("successful") },
         "passed" => results.all? { |result| result.fetch("passed") }}
      end

      def run_internal_replacements(inventory, kubeconfig, directory, artifacts)
        entries = inventory.select { |entry| entry["classification"] == "implementation-internal" && entry["external_contract"] == true }
        run_indexed_replacements(entries, kubeconfig, directory, artifacts, index: K3InternalContractIndex,
                                                                            artifact: "internal-replacements-command.json")
      end

      def run_local_volume_replacements(inventory, kubeconfig, directory, artifacts)
        entries = inventory.select { |entry| entry["replacement_test"] == K3LocalVolumeContractIndex::RUNNER && linked_replacement?(entry) }
        run_indexed_replacements(entries, kubeconfig, directory, artifacts, index: K3LocalVolumeContractIndex,
                                                                            artifact: "local-volume-replacements-command.json",
                                                                            source_files: K3LocalVolumeContractIndex::FILES)
      end

      def run_csi_replacements(inventory, kubeconfig, directory, artifacts, source:, binary:)
        entries = inventory.select { |entry| entry["replacement_test"] == K3CSIContractIndex::RUNNER && linked_replacement?(entry) }
        reports = File.join(directory, "csi-replacements")
        env = {"RUBERNETES_KUBERNETES_SOURCE" => File.expand_path(source), "RUBERNETES_K3_CSI_REPORTS" => reports,
               "RUBERNETES_K3_E2E_BINARY" => binary, "RUBERNETES_K3_CSI_CASE_IDS" => JSON.generate(entries.map { |entry| entry.fetch("id") })}
        result = run_indexed_replacements(
          entries, kubeconfig, directory, artifacts, index: K3CSIContractIndex, artifact: "csi-replacements-command.json",
                                                     source_files: K3CSIContractIndex::FILES, env: env
        )
        artifacts.concat(Dir.glob(File.join(reports, "**", "*")).select { |path| File.file?(path) }.map do |path|
          {"path" => path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(path).hexdigest}
        end)
        result
      end

      def run_indexed_replacements(entries, kubeconfig, directory, artifacts, index:, artifact:, source_files: nil, env: {})
        expected = entries.to_h { |entry| [entry.fetch("id"), entry["replacement_case"]] }
        cases = index::CASES.values.uniq.select { |key| expected.value?(key) }
        return {"expected" => expected.size, "successful" => 0, "passed" => expected.empty?} if cases.empty?

        command = [RbConfig.ruby, File.join(ROOT, index::RUNNER), *cases]
        execution = Lanes.capture(command, env: env.merge("KUBECONFIG" => kubeconfig, "RUBERNETES_K7_CLUSTER_ROOT" => nil), timeout: 5_400)
        artifacts << Lanes.record(directory, artifact, execution)
        results = JSON.parse(execution.fetch("stdout")).fetch("results")
        successful = results.group_by { |result| result.fetch("id") }.count do |id, rows|
          row = rows.first
          rows.one? && expected.key?(id) && expected[id] == row["replacement_case"] && row["passed"] == true &&
            (!source_files || row["file"] == source_files.fetch(expected[id]))
        end
        {"expected" => expected.size, "successful" => successful,
         "passed" => execution.fetch("exit_status") == 0 && successful == expected.size && results.size == expected.size}
      rescue JSON::ParserError, KeyError => error
        {"expected" => expected.size, "successful" => 0, "passed" => false, "reason" => error.message}
      end

      def replacement_backlog(entries)
        groups = entries.group_by { |entry| entry.fetch("id")[/\[Driver: ([^\]]+)\]/, 1] || entry.fetch("classification") }
        groups.sort.to_h.transform_values do |group|
          {"count" => group.length, "by_source_file" => group.map { |entry| entry.fetch("file") }.tally.sort.to_h,
           "contracts" => group.map { |entry| entry.slice("id", "file", "classification", "reason", "replacement_test", "replacement_case") }}
        end
      end

      def escape_focus(id)
        Regexp.escape(id).gsub("\\ ", " ")
      end

      def focus_pattern(ids)
        "\\A#{SUITE_NAME} (#{ids.map { |id| escape_focus(id) }.join("|")})\\z"
      end

      def focus_chunks(ids)
        chunks = [[]]
        pattern_overhead = focus_pattern([]).bytesize
        current_size = pattern_overhead
        ids.each do |id|
          size = escape_focus(id).bytesize + 1
          current = chunks.last
          if !current.empty? && (current_size + size > FOCUS_BYTES || current.length >= SPECS_PER_CHUNK)
            chunks << []
            current = chunks.last
            current_size = pattern_overhead
          end
          current << id
          current_size += size
        end
        chunks.reject(&:empty?)
      end

      def run_required(binary, kubeconfig, directory, required)
        # Each e2e.test process is a separate Ginkgo suite. Join all ordinary
        # suites before starting a Serial spec, as Ginkgo would in one suite.
        serial, ordinary = required.partition { |entry| entry.fetch("labels").include?("Serial") }
        chunks = focus_chunks(ordinary.map { |entry| entry.fetch("id") })
        serial_chunks = focus_chunks(serial.map { |entry| entry.fetch("id") })
        selection = chunks + serial_chunks
        yield selection if block_given?
        executions = run_chunks(binary, kubeconfig, directory, chunks)
        executions.concat(run_chunks(binary, kubeconfig, directory, serial_chunks, concurrency: 1, offset: chunks.length))
        [selection, executions]
      end

      def run_chunks(binary, kubeconfig, directory, chunks, concurrency: CONCURRENCY, offset: 0)
        # Each normal lane invocation has a fresh output directory. Reserve
        # chunk paths before starting anything so a stale retry cannot reuse
        # evidence from an earlier attempt.
        report_dirs = chunks.each_index.map do |index|
          path = File.join(directory, format("chunk-%03d", offset + index))
          Dir.mkdir(path)
          path
        end
        queue = chunks.each_with_index.to_a
        mutex = Mutex.new
        results = Array.new(chunks.length)
        workers = Array.new([concurrency, chunks.length].min) do
          Thread.new do
            loop do
              chunk, index = mutex.synchronize { queue.shift }
              break if chunk.nil?

              report_dir = report_dirs.fetch(index)
              basename = format("e2e-command-%03d", offset + index)
              command = [binary, "--provider=skeleton", "--kubeconfig", kubeconfig,
                         "--kubectl-path", File.join(ROOT, "build/tools/kubectl-v1.36.2"),
                         "--ginkgo.focus=#{focus_pattern(chunk)}", "--report-dir=#{report_dir}"]
              execution = Lanes.capture_archived(command, directory: directory, basename: basename, timeout: CHUNK_TIMEOUT)
              if execution["exit_status"] && !execution["timed_out"]
                archive = K3JUnit.archive_completed(report_dir)
                execution["junit_report"] = archive if archive
              end
              # Publish only after archiving the report. A later interrupted
              # chunk must leave every completed chunk independently readable.
              path = File.join(directory, "#{basename}.json")
              File.write("#{path}.partial", "#{JSON.pretty_generate(execution)}\n")
              File.rename("#{path}.partial", path)
              results[index] = execution
            end
          end
        end
        workers.each(&:join)
        results
      end

      def junit_totals(directory, chunks, executions: [])
        totals = {"tests" => chunks.sum(&:length), "passed" => 0, "reports" => 0, "incomplete_chunks" => []}
        chunks.each_with_index do |ids, index|
          report_dir = File.join(directory, format("chunk-%03d", index))
          paths = K3JUnit.paths(report_dir)
          unless paths.one?
            totals.fetch("incomplete_chunks") << {"chunk" => index, "reason" => "expected one JUnit report"}
            next
          end

          digest = K3JUnit.recorded_digest(executions[index]&.fetch("junit_report", nil), paths.first)
          summary = junit_chunk(paths.first, ids, sha256: digest)
          totals["reports"] += 1
          totals["passed"] += summary.fetch("passed")
          totals.fetch("incomplete_chunks") << summary.merge("chunk" => index) unless summary.fetch("complete")
        rescue REXML::ParseException, K3JUnit::Error, SystemCallError => error
          totals.fetch("incomplete_chunks") << {"chunk" => index, "reason" => error.message}
        end
        totals
      end

      def junit_chunk(path, ids, sha256: nil)
        document = K3JUnit.with_xml(path, sha256: sha256) { |xml| REXML::Document.new(xml) }
        suites = REXML::XPath.match(document, "/testsuite | /testsuites/testsuite")
        return {"passed" => 0, "complete" => false, "reason" => "expected one Ginkgo suite"} unless suites.one?

        suite = suites.first
        specs, hooks = suite.get_elements("testcase").partition { |entry| entry.attributes["name"].to_s.start_with?("[It] ") }
        outcomes = specs.group_by { |entry| junit_spec_id(entry.attributes["name"]) }
        missed = ids.reject do |id|
          rows = outcomes.fetch(id, [])
          rows.one? && K1Evidence.outcome(rows.first) == "passed"
        end
        expected = ids.to_h { |id| [id, true] }
        unexpected = outcomes.keys.reject do |id|
          expected.key?(id) || outcomes.fetch(id).all? { |entry| K1Evidence.outcome(entry) == "skipped" }
        end
        suite_passed = suite.get_elements("properties/property").any? do |property|
          property.attributes["name"] == "SuiteSucceeded" && property.attributes["value"] == "true"
        end
        suite_passed &&= hooks.all? { |entry| K1Evidence.outcome(entry) == "passed" }
        {"passed" => ids.length - missed.length, "suite_passed" => suite_passed,
         "missing_failed_or_duplicate" => missed, "unexpected_executions" => unexpected,
         "complete" => suite_passed && missed.empty? && unexpected.empty?}
      end

      # The pinned Kubernetes WithKubeletMinVersion wrapper sets both the ID's
      # tag and Ginkgo's component constraint. Only JUnit appends the second.
      def junit_spec_id(name)
        raw = name.delete_prefix("[It] ")
        annotated = /\A(.+) \[kubelet: \[>=(\d+\.\d+(?:\.\d+)?)\]\]\z/.match(raw)
        return raw unless annotated

        id, version = annotated.captures
        id.scan(/\[KubeletMinVersion:([^\]]+)\]/).flatten == [version] ? id : raw
      end
    end

    # ---------------------------------------------------------------- K5 ----
    # API/wire differential against the pinned Kubernetes oracle.
    module K5
      module_function

      def run(options:, profile:, directory:)
        oracle = options[:oracle_kubeconfig]
        return Lanes.incomplete("K5", "no oracle kubeconfig: K5 compares against a real Kubernetes v1.36.2 cluster") if oracle.nil?
        return Lanes.incomplete("K5", "oracle kubeconfig does not reach a cluster") unless Lanes.cluster_reachable?(oracle)
        unless Lanes.cluster_reachable?(options[:kubeconfig])
          return Lanes.incomplete("K5",
                                  "no Rubernetes kubeconfig to compare against the oracle")
        end

        differential = File.join(ROOT, "tools/conformance/k5_differential.rb")
        execution = Lanes.capture([RbConfig.ruby, differential,
                                   "--kubeconfig", options[:kubeconfig],
                                   "--oracle-kubeconfig", oracle,
                                   *(["--cbor-enabled"] if options[:cbor_enabled]), "--output", directory])
        artifacts = [Lanes.record(directory, "k5-command.json", execution)]
        report_path = File.join(directory, "differential.json")
        return Lanes.incomplete("K5", "differential produced no report", "artifacts" => artifacts) unless File.file?(report_path)

        artifacts << Lanes.artifact_for(report_path)
        report = JSON.parse(File.read(report_path))
        require_relative "k5_evidence"
        verdict = K5Evidence.verify(report, cbor_enabled: options.fetch(:cbor_enabled, false))
        passed = execution["exit_status"] == 0 && !execution["timed_out"] && verdict.fetch("passed")
        {"lane" => "K5", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "reason" => verdict["detail"],
         "observables" => report["observables"], "differences" => report.fetch("differences", []).length,
         "artifacts" => artifacts}
      end
    end

    # ---------------------------------------------------------------- K6 ----
    module K6
      CORPUS = File.join(ROOT, "test/compatibility/projects/corpus.yml")

      module_function

      def run(options:, profile:, directory:)
        return Lanes.incomplete("K6", "project corpus #{CORPUS.delete_prefix("#{ROOT}/")} is missing") unless File.file?(CORPUS)

        require "yaml"
        corpus = YAML.safe_load_file(CORPUS)
        projects = corpus.fetch("projects", [])
        shape = Lanes.corpus_shape(projects)
        artifacts = [Lanes.record(directory, "corpus-shape.json", shape)]
        unless Lanes.cluster_reachable?(options[:kubeconfig])
          return Lanes.incomplete("K6", "corpus is well formed but no cluster is reachable to install the projects",
                                  "shape" => shape, "artifacts" => artifacts)
        end

        runner = File.join(ROOT, "tools/conformance/k6_corpus.rb")
        command = [RbConfig.ruby, runner, "--kubeconfig", options[:kubeconfig], "--output", directory]
        command << "--clients-only" unless shape.fetch("satisfies_minimums")
        execution = Lanes.capture(command)
        artifacts << Lanes.record(directory, "k6-command.json", execution)
        report_path = File.join(directory, K6Evidence::REPORT)
        return Lanes.incomplete("K6", "corpus runner produced no report", "artifacts" => artifacts) unless File.file?(report_path)

        artifacts << Lanes.artifact_for(report_path)
        report = JSON.parse(File.read(report_path))
        checks_passed = execution.fetch("exit_status") == 0 && report.fetch("failures", []).empty? && report.fetch("residue", []).empty?
        corpus_ready = shape.fetch("satisfies_minimums")
        evidence = K6Evidence.verify(report, execution, projects: projects, corpus_sha256: L.digest_file(CORPUS)) if corpus_ready
        status = if !checks_passed
                   "FAILED"
                 elsif evidence&.fetch("passed")
                   "COMPLETE"
                 else
                   "INCOMPLETE"
                 end
        reason = if corpus_ready
                   evidence["detail"]
                 else
                   "project corpus lacks the required immutable pins or coverage"
                 end
        {"lane" => "K6", "passed" => status == "COMPLETE", "status" => status,
         "reason" => reason, "runtime_evidence" => evidence,
         "shape" => shape, "failures" => report.fetch("failures", []).length,
         "residue" => report.fetch("residue", []).length, "artifacts" => artifacts}
      end
    end

    # ---------------------------------------------------------------- K7 ----
    module K7
      module_function

      def run(options:, profile:, directory:)
        unless Lanes.cluster_reachable?(options[:kubeconfig])
          return Lanes.incomplete("K7",
                                  "no reachable cluster for the upgrade and recovery lane")
        end

        runner = File.join(ROOT, "tools/conformance/k7_lifecycle.rb")
        command = [RbConfig.ruby, runner, "--kubeconfig", File.expand_path(options.fetch(:kubeconfig)), "--output", File.expand_path(directory)]
        command.push("--oracle-kubeconfig", File.expand_path(options[:oracle_kubeconfig])) if options[:oracle_kubeconfig]
        execution = Lanes.capture(command)
        artifacts = [Lanes.record(directory, K7Evidence::COMMAND, execution)]
        report_path = File.join(directory, K7Evidence::REPORT)
        return Lanes.incomplete("K7", "lifecycle runner produced no report", "artifacts" => artifacts) unless File.file?(report_path)

        report = JSON.parse(File.read(report_path))
        artifacts << {"path" => report_path.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(report_path).hexdigest}
        return Lanes.incomplete("K7", "lifecycle original does not contain a report", "artifacts" => artifacts) unless report.is_a?(Hash)

        verdict = K7Evidence.verify(report, execution, directory: directory)
        checked_artifacts = Array(verdict["artifacts"]).map { |file| file.merge("path" => file.fetch("path").delete_prefix("#{ROOT}/")) }
        stages = Array(report["stages"]).grep(Hash)
        passed = verdict.fetch("passed")
        status = if passed
                   "COMPLETE"
                 elsif stages.any? { |stage| stage.fetch("status") == "FAILED" }
                   "FAILED"
                 else
                   "INCOMPLETE"
                 end
        {"lane" => "K7", "passed" => passed, "status" => status,
         "stages" => stages, "artifacts" => artifacts + checked_artifacts, "reason" => verdict["detail"],
         "baseline_missing" => report.fetch("baseline_missing", [])}
      rescue JSON::ParserError
        Lanes.incomplete("K7", "lifecycle original is not valid JSON", "artifacts" => artifacts)
      end
    end

    # --------------------------------------------------------------- util ---
    # Recover per-spec outcomes from the Ginkgo stream when no JUnit report
    # exists.  Hydrophone only copies the report out after the whole suite
    # finishes, so a lane that is terminated on timeout otherwise leaves no
    # record of what actually failed -- the 2026-09-13 run #44 had to be
    # reconstructed by hand from 2.4MB of captured stdout.
    def ginkgo_progress(stdout)
      failures = []
      completed = 0
      duration = nil
      saw_output = false
      stdout.each_line do |raw|
        saw_output = true
        line = raw.dup.force_encoding(Encoding::UTF_8).scrub("?").delete_suffix("\n")
        failures << {"seconds" => duration, "spec" => line.strip} if duration && !line.empty?
        duration = nil
        next unless line.start_with?("•")

        completed += 1
        match = /\A• \[FAILED\] \[([\d.]+) seconds\]\z/.match(line)
        duration = match[1].to_f if match
      end
      return unless saw_output

      passed = completed - failures.length
      {
        "source" => "ginkgo_stdout",
        "completed" => completed,
        "passed" => passed.negative? ? 0 : passed,
        "failed" => failures.length,
        "failures" => failures
      }
    end

    def corpus_shape(projects)
      categories = projects.flat_map { |project| Array(project["categories"]) }.tally
      domains = projects.flat_map { |project| Array(project["domains"]) }.uniq.sort
      required_domains = %w[ingress certificate observability database message-queue autoscaling gitops storage security]
      pinned = projects.select do |project|
        project["source_commit"].to_s.match?(%r{(?:\A|[@/])[0-9a-f]{40}\z}) &&
          project["chart_sha256"].to_s.match?(/\A[0-9a-f]{64}\z/) && !project["license"].to_s.empty? &&
          !Array(project["images"]).empty? &&
          Array(project["images"]).all? { |image| image.to_s.match?(/@sha256:[0-9a-f]{64}\z/) } &&
          !project["install"].to_s.empty?
      end
      {
        "total" => projects.length,
        "categories" => categories,
        "domains" => domains,
        "missing_domains" => required_domains - domains,
        "fully_pinned" => pinned.length,
        "incomplete_pins" => (projects - pinned).map { |project| project["name"] },
        "satisfies_minimums" =>
          projects.length >= 30 &&
            categories.fetch("helm-chart", 0) >= 10 &&
            categories.fetch("operator", 0) >= 10 &&
            categories.fetch("crd-webhook", 0) >= 5 &&
            categories.fetch("statefulset-pvc", 0) >= 5 &&
            (required_domains - domains).empty? &&
            pinned.length == projects.length
      }
    end
  end
end
