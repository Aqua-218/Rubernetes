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
require "json"
require "open3"
require "shellwords"
require "time"

require_relative "lock"

module Conformance
  module Lanes
    L = Conformance::Lock
    ROOT = L::ROOT

    module_function

    # Content identity of the tracked project source, used when the tree has
    # no .git directory.
    def source_tree_digest
      @source_tree_digest ||= begin
        files = Dir.glob(File.join(ROOT, "{lib,exe,tools,spec,test,verification}/**/*"))
                   .select { |path| File.file?(path) }.sort
        digest = Digest::SHA256.new
        files.each do |path|
          digest << path.delete_prefix("#{ROOT}/")
          digest << "\0"
          digest << Digest::SHA256.file(path).digest
        end
        digest.hexdigest
      end
    end

    def incomplete(lane, reason, **extra)
      {"lane" => lane, "passed" => false, "status" => "INCOMPLETE", "reason" => reason}.merge(extra)
    end

    def tool_path(name)
      path = File.join(ROOT, "build/conformance/bin", name)
      return path if File.executable?(path)

      found = ENV.fetch("PATH", "").split(File::PATH_SEPARATOR)
                 .map { |dir| File.join(dir, name) }.find { |candidate| File.executable?(candidate) }
      found
    end

    def cluster_reachable?(kubeconfig)
      return false if kubeconfig.nil? || !File.file?(kubeconfig)

      _out, _err, status = Open3.capture3({"KUBECONFIG" => kubeconfig}, *in_cluster_namespace(["kubectl", "version", "--output=json"]))
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
    def capture(command, env: {}, chdir: ROOT, timeout: nil)
      command = in_cluster_namespace(command)
      started = Time.now.utc
      status = nil
      timed_out = false
      stdout = +""
      stderr = +""
      Open3.popen3(env, *command, chdir: chdir, pgroup: true) do |stdin, out, err, thread|
        stdin.close
        readers = {out => stdout, err => stderr}
        deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + Float(timeout)
        until readers.empty?
          remaining = deadline && deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          if remaining && remaining <= 0
            timed_out = true
            break
          end
          ready = IO.select(readers.keys, nil, nil, remaining ? [remaining, 1.0].min : 1.0)
          next if ready.nil? && thread.alive?
          break if ready.nil? && !thread.alive?

          Array(ready && ready.first).each do |io|
            begin
              readers.fetch(io) << io.readpartial(65_536)
            rescue EOFError, IOError
              readers.delete(io)
            end
          end
        end
        if timed_out
          terminate_group(thread.pid)
          stderr << "\nlane runner exceeded #{timeout}s and was terminated\n"
        end
        status = thread.value
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
          "--output-dir", output
        ]
        execution = Lanes.capture(command, timeout: HYDROPHONE_TIMEOUT_SECONDS)
        artifacts = [Lanes.record(directory, "hydrophone-cleanup.json", cleanup),
                     Lanes.record(directory, "hydrophone-command.json", execution)]
        junit = Dir.glob(File.join(output, "**", "*.xml")).sort.first
        if junit.nil?
          reason = if execution["timed_out"]
                     "hydrophone exceeded #{execution.fetch("timeout_seconds")}s and was terminated"
                   else
                     "hydrophone produced no JUnit report"
                   end
          progress = begin
            Lanes.ginkgo_progress(execution["stdout"])
          rescue StandardError
            # Reporting how far a run got must never be the reason a lane fails.
            nil
          end
          extra = {"execution" => execution.slice("exit_status", "timed_out", "stderr"), "artifacts" => artifacts}
          if progress
            extra["progress"] = progress
            artifacts << Lanes.record(directory, "ginkgo-progress.json", progress)
          end
          return Lanes.incomplete("K1", reason, **extra)
        end

        summary = Lanes.junit_summary(junit)
        joined = Lanes.join_conformance_codenames(junit)
        artifacts << {"path" => junit.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(junit).hexdigest}
        artifacts << Lanes.record(directory, "codename-join.json", joined)
        expected = L.profiles.fetch("conformance").fetch("expected_tests")
        passed = execution.fetch("exit_status").zero? &&
                 summary.fetch("selected") == expected && summary.fetch("passed") == expected &&
                 summary.fetch("failed").zero? && summary.fetch("skipped").zero? && summary.fetch("flaked").zero? &&
                 joined.fetch("unmatched_codenames").empty? && joined.fetch("duplicate_codenames").empty?
        {
          "lane" => "K1", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
          "profile" => profile.fetch("name"), "summary" => summary, "codenames" => joined,
          "artifacts" => artifacts
        }
      end
    end

    # ---------------------------------------------------------------- K2 ----
    module K2
      module_function

      def run(options:, profile:, directory:)
        kubeconfig = options[:kubeconfig]
        return Lanes.incomplete("K2", "no kubeconfig for the certified-conformance run") if kubeconfig.nil?
        return Lanes.incomplete("K2", "kubeconfig #{kubeconfig} does not reach a cluster") unless Lanes.cluster_reachable?(kubeconfig)

        sonobuoy = Lanes.tool_path("sonobuoy")
        return Lanes.incomplete("K2", "sonobuoy binary is not installed; run `rake m8:tools`") if sonobuoy.nil?

        command = [
          sonobuoy, "run", "--mode=certified-conformance",
          "--kubeconfig", kubeconfig,
          "--kubernetes-version=v#{L.profiles.fetch("kubernetes").fetch("tag").delete_prefix("v")}",
          "--kube-conformance-image=#{L.reference_by_digest(L.kubernetes.fetch("conformance_image"))}",
          "--sonobuoy-image=#{L.runner("sonobuoy").fetch("image").fetch("reference")}",
          "--wait"
        ]
        execution = Lanes.capture(command)
        artifacts = [Lanes.record(directory, "sonobuoy-command.json", execution)]
        retrieve = Lanes.capture([sonobuoy, "retrieve", directory, "--kubeconfig", kubeconfig])
        artifacts << Lanes.record(directory, "sonobuoy-retrieve.json", retrieve)
        archive = Dir.glob(File.join(directory, "*.tar.gz")).sort.first
        return Lanes.incomplete("K2", "sonobuoy produced no results archive", "execution" => execution.slice("exit_status", "stderr")) if archive.nil?

        artifacts << {"path" => archive.delete_prefix("#{ROOT}/"), "sha256" => Digest::SHA256.file(archive).hexdigest}
        passed = execution.fetch("exit_status").zero? && retrieve.fetch("exit_status").zero?
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

        ledger = JSON.parse(File.read(LEDGER))
        inventory = ledger.fetch("tests", [])
        classified = inventory.group_by { |entry| entry["classification"] }
        unclassified = inventory.reject { |entry| %w[required platform-inapplicable provider-private implementation-internal].include?(entry["classification"]) }
        unlinked = inventory.select do |entry|
          %w[provider-private implementation-internal].include?(entry["classification"]) &&
            entry["external_contract"] == true && entry["replacement_test"].to_s.empty?
        end
        artifacts = [Lanes.record(directory, "selection-ledger-summary.json",
                                  {"total" => inventory.length,
                                   "by_classification" => classified.transform_values(&:length),
                                   "unclassified" => unclassified.length,
                                   "unlinked_external_contracts" => unlinked.length})]
        kubeconfig = options[:kubeconfig]
        unless Lanes.cluster_reachable?(kubeconfig)
          return Lanes.incomplete("K3", "ledger is well formed but no cluster is reachable to execute the required tests",
                                  "ledger" => {"total" => inventory.length, "unclassified" => unclassified.length},
                                  "artifacts" => artifacts)
        end

        binary = Lanes.tool_path("e2e.test")
        return Lanes.incomplete("K3", "upstream e2e.test binary is not built; run `rake m8:e2e_build`", "artifacts" => artifacts) if binary.nil?

        required = inventory.select { |entry| entry["classification"] == "required" }
        execution = Lanes.capture([binary, "--provider=skeleton", "--kubeconfig", kubeconfig,
                                   "--ginkgo.focus=#{required.map { |e| Regexp.escape(e.fetch("id")) }.join("|")}",
                                   "--report-dir=#{directory}"])
        artifacts << Lanes.record(directory, "e2e-command.json", execution)
        passed = execution.fetch("exit_status").zero? && unclassified.empty? && unlinked.empty?
        {"lane" => "K3", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "required" => required.length, "unclassified" => unclassified.length,
         "unlinked_external_contracts" => unlinked.length, "artifacts" => artifacts}
      end
    end

    # ---------------------------------------------------------------- K4 ----
    module K4
      module_function

      def run(options:, profile:, directory:)
        return Lanes.incomplete("K4", "node conformance requires amd64") unless options[:platform] == "linux/amd64"

        kubeconfig = options[:kubeconfig]
        return Lanes.incomplete("K4", "no reachable cluster for node conformance") unless Lanes.cluster_reachable?(kubeconfig)

        image = L.support_images["node_conformance"]
        return Lanes.incomplete("K4", "node conformance image is not pinned in third_party/locks/kubernetes-v1.36.2.json") if image.nil?

        execution = Lanes.capture(["docker", "run", "--rm", "--privileged", "--net=host", "--pid=host",
                                   "-v", "/:/rootfs", "-v", "/var/run:/var/run",
                                   L.reference_by_digest(image)])
        artifacts = [Lanes.record(directory, "node-conformance.json", execution)]
        passed = execution.fetch("exit_status").zero?
        {"lane" => "K4", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED", "artifacts" => artifacts}
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
        return Lanes.incomplete("K5", "no Rubernetes kubeconfig to compare against the oracle") unless Lanes.cluster_reachable?(options[:kubeconfig])

        differential = File.join(ROOT, "tools/conformance/k5_differential.rb")
        execution = Lanes.capture([RbConfig.ruby, differential,
                                   "--kubeconfig", options[:kubeconfig],
                                   "--oracle-kubeconfig", oracle,
                                   "--output", directory])
        artifacts = [Lanes.record(directory, "k5-command.json", execution)]
        report_path = File.join(directory, "differential.json")
        return Lanes.incomplete("K5", "differential produced no report", "artifacts" => artifacts) unless File.file?(report_path)

        report = JSON.parse(File.read(report_path))
        passed = execution.fetch("exit_status").zero? && report.fetch("differences", []).empty?
        {"lane" => "K5", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
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
        corpus = YAML.safe_load(File.read(CORPUS))
        projects = corpus.fetch("projects", [])
        shape = Lanes.corpus_shape(projects)
        artifacts = [Lanes.record(directory, "corpus-shape.json", shape)]
        unless shape.fetch("satisfies_minimums")
          return {"lane" => "K6", "passed" => false, "status" => "FAILED",
                  "reason" => "corpus does not satisfy the spec minimums", "shape" => shape, "artifacts" => artifacts}
        end
        unless Lanes.cluster_reachable?(options[:kubeconfig])
          return Lanes.incomplete("K6", "corpus is well formed but no cluster is reachable to install the projects",
                                  "shape" => shape, "artifacts" => artifacts)
        end

        runner = File.join(ROOT, "tools/conformance/k6_corpus.rb")
        execution = Lanes.capture([RbConfig.ruby, runner, "--kubeconfig", options[:kubeconfig], "--output", directory])
        artifacts << Lanes.record(directory, "k6-command.json", execution)
        report_path = File.join(directory, "corpus-results.json")
        return Lanes.incomplete("K6", "corpus runner produced no report", "artifacts" => artifacts) unless File.file?(report_path)

        report = JSON.parse(File.read(report_path))
        passed = execution.fetch("exit_status").zero? && report.fetch("failures", []).empty? && report.fetch("residue", []).empty?
        {"lane" => "K6", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "shape" => shape, "failures" => report.fetch("failures", []).length,
         "residue" => report.fetch("residue", []).length, "artifacts" => artifacts}
      end
    end

    # ---------------------------------------------------------------- K7 ----
    module K7
      module_function

      def run(options:, profile:, directory:)
        return Lanes.incomplete("K7", "no reachable cluster for the upgrade and recovery lane") unless Lanes.cluster_reachable?(options[:kubeconfig])

        runner = File.join(ROOT, "tools/conformance/k7_lifecycle.rb")
        execution = Lanes.capture([RbConfig.ruby, runner, "--kubeconfig", options[:kubeconfig], "--output", directory])
        artifacts = [Lanes.record(directory, "k7-command.json", execution)]
        report_path = File.join(directory, "lifecycle.json")
        return Lanes.incomplete("K7", "lifecycle runner produced no report", "artifacts" => artifacts) unless File.file?(report_path)

        report = JSON.parse(File.read(report_path))
        passed = execution.fetch("exit_status").zero? &&
                 report.fetch("data_loss", []).empty? && report.fetch("stuck_operations", []).empty?
        {"lane" => "K7", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "stages" => report["stages"], "artifacts" => artifacts}
      end
    end

    # --------------------------------------------------------------- util ---
    def junit_summary(path)
      xml = File.read(path)
      totals = {"selected" => 0, "passed" => 0, "failed" => 0, "skipped" => 0, "flaked" => 0}
      xml.scan(/<testsuite\b[^>]*>/).each do |tag|
        totals["selected"] += tag[/tests="(\d+)"/, 1].to_i
        totals["failed"] += tag[/failures="(\d+)"/, 1].to_i
        totals["skipped"] += tag[/skipped="(\d+)"/, 1].to_i
        totals["flaked"] += tag[/flakes="(\d+)"/, 1].to_i
      end
      totals["passed"] = totals["selected"] - totals["failed"] - totals["skipped"]
      totals
    end

    # Recover per-spec outcomes from the Ginkgo stream when no JUnit report
    # exists.  Hydrophone only copies the report out after the whole suite
    # finishes, so a lane that is terminated on timeout otherwise leaves no
    # record of what actually failed -- the 2026-09-13 run #44 had to be
    # reconstructed by hand from 2.4MB of captured stdout.
    def ginkgo_progress(stdout)
      text = stdout.to_s
      return nil if text.empty?

      # Captured process output is BINARY.  Matching a UTF-8 pattern (the
      # spec bullet) against it raises Encoding::CompatibilityError, which
      # would fail the whole lane at the point where it reports results --
      # exactly when there is the most to lose.  Scrub rather than assume:
      # a conformance log carries arbitrary bytes from the objects it dumps.
      text = text.dup.force_encoding(Encoding::UTF_8)
      text = text.scrub("?") unless text.valid_encoding?

      failures = text.scan(/^\u2022 \[FAILED\] \[([\d.]+) seconds\]\n(.+)$/).map do |seconds, title|
        {"seconds" => seconds.to_f, "spec" => title.strip}
      end
      completed = text.scan(/^\u2022/).length
      passed = completed - failures.length
      {
        "source" => "ginkgo_stdout",
        "completed" => completed,
        "passed" => passed.negative? ? 0 : passed,
        "failed" => failures.length,
        "failures" => failures
      }
    end

    # Join the JUnit case names onto the pinned conformance.yaml codenames so a
    # run cannot silently select a different set of tests.
    def join_conformance_codenames(junit_path)
      definition = File.join(ROOT, "third_party/kubernetes/v1.36.2/conformance.yaml")
      codenames = if File.file?(definition)
                    File.read(definition).scan(/^\s*codename:\s*(.+)$/).flatten.map { |name| name.strip.delete_prefix("'").delete_suffix("'") }
                  else
                    []
                  end
      names = File.read(junit_path).scan(/<testcase\b[^>]*\bname="([^"]*)"/).flatten
      counts = names.tally
      {
        "definition_available" => !codenames.empty?,
        "definition_count" => codenames.length,
        "executed_count" => names.length,
        "duplicate_codenames" => counts.select { |_name, count| count > 1 }.keys,
        "unmatched_codenames" => codenames.empty? ? [] : codenames.reject { |codename| names.any? { |name| name.include?(codename) } }
      }
    end

    def corpus_shape(projects)
      categories = projects.flat_map { |project| Array(project["categories"]) }.tally
      domains = projects.flat_map { |project| Array(project["domains"]) }.uniq.sort
      required_domains = %w[ingress certificate observability database message-queue autoscaling gitops storage security]
      pinned = projects.select do |project|
        !project["source_commit"].to_s.empty? && !project["license"].to_s.empty? &&
          !Array(project["images"]).empty? &&
          Array(project["images"]).all? { |image| image.to_s.include?("@sha256:") } &&
          !project["install"].to_s.empty?
      end
      {
        "total" => projects.length,
        "categories" => categories,
        "domains" => domains,
        "missing_domains" => required_domains - domains,
        "fully_pinned" => pinned.length,
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
