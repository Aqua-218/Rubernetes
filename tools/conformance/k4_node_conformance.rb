# frozen_string_literal: true

require "socket"
require "rbconfig"

require_relative "k3_junit"
require_relative "k4_evidence"
require_relative "k4_junit"
require_relative "k4_rro"
require_relative "lock"

module Conformance
  module Lanes
    # Runs e2e_node on the dedicated node that the kubeconfig reaches. The
    # upstream suite runs privileged node-local checks, including system
    # validation against /rootfs in its Node Conformance mode.
    module K4
      LABEL = "NodeConformance"
      REPORT = "ginkgo.json"
      JUNIT = "ginkgo.junit.xml"
      FRAMEWORK_JUNIT = "junit_01.xml"
      SHA256 = /\A[0-9a-f]{64}\z/
      INVENTORY = "inventory.json"
      SUITE_TIMEOUT = "24h"

      module_function

      def run(options:, profile:, directory:)
        unless options[:platform] == "linux/amd64" && RbConfig::CONFIG["host_os"].include?("linux") && RbConfig::CONFIG["host_cpu"] == "x86_64"
          return Lanes.incomplete("K4", "node conformance requires amd64 Linux")
        end

        node = options[:node_conformance_node]
        return Lanes.incomplete("K4", "set --node-conformance-node on the dedicated Linux test node") if node.to_s.empty?
        unless Process.euid.zero? && File.directory?("/rootfs")
          return Lanes.incomplete("K4", "node conformance requires root and a view of the test node at /rootfs")
        end

        binary = Lanes.tool_path("e2e_node.test")
        build = verified_build(binary)
        return Lanes.incomplete("K4", "build the pinned runner with tools/conformance/build_e2e.rb --node") unless build

        kubeconfig = options[:kubeconfig]
        return Lanes.incomplete("K4", "no reachable test cluster") unless Lanes.cluster_reachable?(kubeconfig)

        connection = node_connection(kubeconfig, node)
        run_suite(binary, build: build, connection: connection, kubeconfig: kubeconfig, directory: directory)
      rescue ArgumentError => error
        Lanes.incomplete("K4", error.message)
      end

      def run_suite(binary, build:, connection:, kubeconfig:, directory:)
        arguments = node_arguments(connection, directory)
        artifacts = [Lanes.record(directory, "build.json", build), Lanes.record(directory, "node.json", connection.fetch("node")),
                     Lanes.record(directory, "host.json", {"hostname" => Socket.gethostname, "kernel" => kernel_release})]
        dry_run = capture(ginkgo_command(binary, arguments, File.join(directory, INVENTORY), dry_run: true),
                          token: connection.fetch("token"), kubeconfig: kubeconfig)
        artifacts << record_capture(directory, "inventory-execution.json", dry_run)
        expected, inventory = suite_evidence(directory, INVENTORY, dry_run: true)
        return failed(artifacts, "upstream Node Conformance inventory failed") unless dry_run["exit_status"] == 0 && expected && pinned_inventory?(expected)

        artifacts << K4Evidence.retain(File.join(directory, INVENTORY), bytes: inventory)

        node_command = K4RRO.node_list_command(connection.fetch("kubectl"), connection.fetch("endpoint"), kubeconfig)
        before = capture(node_command, token: connection.fetch("token"), kubeconfig: kubeconfig, timeout: K4RRO::SNAPSHOT_TIMEOUT)
        execution = capture(ginkgo_command(binary, arguments, File.join(directory, REPORT), dry_run: false),
                            token: connection.fetch("token"), kubeconfig: kubeconfig)
        after = capture(node_command, token: connection.fetch("token"), kubeconfig: kubeconfig, timeout: K4RRO::SNAPSHOT_TIMEOUT)
        artifacts << record_capture(directory, K4RRO::BEFORE, before)
        artifacts << record_capture(directory, "execution.json", execution)
        artifacts << record_capture(directory, K4RRO::AFTER, after)
        actual, report = suite_evidence(directory, REPORT, dry_run: false)
        return failed(artifacts, "upstream Node Conformance execution did not produce a valid report") unless actual

        artifacts << K4Evidence.retain(File.join(directory, REPORT), bytes: report)
        reports = junit_artifacts(directory)
        artifacts.concat(reports)

        support = K4RRO.observed_support(before, after, node: connection.fetch("node"), execution: execution)
        outcomes = compare(expected, actual, rro_supported: support)
        artifacts << Lanes.record(directory, "coverage.json", outcomes)
        passed = execution["exit_status"] == 0 && complete_coverage?(expected, actual, outcomes)
        if passed && !junit_matches?(directory, actual, reports)
          return failed(artifacts, "stock Node Conformance JUnit does not match the execution").merge("coverage" => outcomes)
        end

        {"lane" => "K4", "passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
         "coverage" => outcomes, "artifacts" => artifacts}
      end

      def verified_build(binary)
        return nil if binary.nil?

        build = JSON.parse(File.binread("#{binary}.build.json"))
        return nil unless valid_build_record?(build) && build["sha256"] == Digest::SHA256.file(binary).hexdigest &&
                          build["ginkgo_sha256"] == Digest::SHA256.file(ginkgo_binary(binary)).hexdigest

        build
      rescue JSON::ParserError, Errno::ENOENT
        nil
      end

      def valid_build_record?(build)
        return false unless build.is_a?(Hash) && build["source_commit"] == Lock.source_commit && build["target"] == "e2e_node.test" &&
                            build["platform"] == "linux/amd64" && build["installed"] == true && build["exit_status"] == 0 &&
                            %r{\Ago version go\S+ linux/amd64\z}.match?(build["go"].to_s) &&
                            build.values_at("sha256", "ginkgo_sha256").all? { |digest| SHA256.match?(digest.to_s) }

        command, ginkgo = build.values_at("command", "ginkgo_command")
        node_output = command[6] if command.is_a?(Array)
        ginkgo_output = ginkgo[5] if ginkgo.is_a?(Array)
        node_output.is_a?(String) && ginkgo_output.is_a?(String) &&
          File.basename(node_output) == "e2e_node.test" && File.basename(ginkgo_output) == "ginkgo-k4" &&
          File.dirname(node_output) == File.dirname(ginkgo_output) &&
          command == ["go", "test", "-mod=vendor", "-trimpath", "-c", "-o", node_output, "./test/e2e_node"] &&
          ginkgo == ["go", "build", "-mod=vendor", "-trimpath", "-o", ginkgo_output, "github.com/onsi/ginkgo/v2/ginkgo"]
      end

      def node_connection(kubeconfig, node)
        kubectl = File.join(Lanes::ROOT, "build/tools/kubectl-v1.36.2")
        raise ArgumentError, "pinned kubectl is unavailable on the test node" unless File.executable?(kubectl)

        command = [kubectl, "--kubeconfig=#{kubeconfig}"]
        config = kubectl_json(command, "config", "view", "--raw", "--minify")
        endpoint = config.dig("clusters", 0, "cluster", "server")
        user = config.dig("users", 0, "user") || {}
        token = user["token"]
        token ||= File.read(File.expand_path(user.fetch("tokenFile"), File.dirname(kubeconfig))).strip if user["tokenFile"]
        if endpoint.to_s.empty? || token.to_s.empty?
          raise ArgumentError, "the test kubeconfig needs its API endpoint and a bearer token for /nodes/proxy/configz"
        end

        nodes = kubectl_json(command, "get", "nodes").fetch("items")
        target = nodes.first
        unless nodes.one? && target.dig("metadata", "name") == node &&
               Array(target.dig("status", "conditions")).any? { |condition| condition["type"] == "Ready" && condition["status"] == "True" }
          raise ArgumentError, "K4 requires exactly one Ready node named #{node.inspect} in the test cluster"
        end

        configuration = node_configuration(command, node)
        dns_domain = configuration["clusterDomain"]
        {"node" => target, "name" => node, "kubectl" => kubectl, "endpoint" => endpoint, "token" => token,
         "dns_domain" => dns_domain.is_a?(String) ? dns_domain : "cluster.local",
         "runtime_endpoint" => configuration["containerRuntimeEndpoint"]}
      rescue Errno::ENOENT, JSON::ParserError, KeyError => error
        raise ArgumentError, "could not inspect the Node Conformance kubeconfig or node: #{error.class}"
      end

      def kubectl_json(command, *arguments)
        result = Lanes.capture(command + arguments + ["--output=json"], timeout: 30)
        raise ArgumentError, "could not inspect the test cluster with pinned kubectl" unless result["exit_status"] == 0

        JSON.parse(result.fetch("stdout"))
      end

      def node_configuration(command, node)
        result = Lanes.capture(command + ["get", "--raw", "/api/v1/nodes/#{node}/proxy/configz"], timeout: 30)
        return {} unless result["exit_status"] == 0

        document = JSON.parse(result.fetch("stdout"))
        configuration = document["kubeletconfig"] if document.is_a?(Hash)
        configuration.is_a?(Hash) ? configuration : {}
      rescue JSON::ParserError
        {}
      end

      def node_arguments(connection, directory)
        arguments = ["--conformance=true", "--start-services=false", "--prepull-images=false", "--dns-domain=#{connection.fetch("dns_domain")}",
                     "--host=#{connection.fetch("endpoint")}", "--node-name=#{connection.fetch("name")}",
                     "--bearer-token=#{connection.fetch("token")}", "--kubectl-path=#{connection.fetch("kubectl")}", "--report-dir=#{directory}"]
        runtime = connection["runtime_endpoint"]
        arguments << "--container-runtime-endpoint=#{runtime}" if runtime.is_a?(String)
        arguments
      end

      def ginkgo_binary(binary)
        File.join(File.dirname(binary), "ginkgo-k4")
      end

      def ginkgo_command(binary, arguments, report, dry_run:)
        command = [ginkgo_binary(binary), "--label-filter=#{LABEL}", "--fail-on-empty", "--json-report=#{report}"]
        if dry_run
          command << "--dry-run"
        else
          command.push("--nodes=8", "--timeout=#{SUITE_TIMEOUT}", "--junit-report=#{File.join(File.dirname(report), JUNIT)}")
        end
        command + [binary, "--", *arguments]
      end

      def capture(command, token:, kubeconfig:, timeout: nil)
        result = Lanes.capture(command, env: {"KUBECONFIG" => kubeconfig}, timeout: timeout)
        result["command"] = result.fetch("command").map { |argument| argument.gsub(token, "[redacted]") }
        %w[stdout stderr].each do |key|
          result[key] = result.fetch(key).force_encoding(Encoding::UTF_8).scrub.gsub(token, "[redacted]")
        end
        result
      end

      def kernel_release
        File.read("/proc/sys/kernel/osrelease").strip
      end

      def load_suite(directory, name, dry_run:)
        suite_evidence(directory, name, dry_run: dry_run)&.first
      end

      def suite_evidence(directory, name, dry_run:)
        bytes = K4Evidence.read(File.join(directory, name))
        suite = parse_suite(bytes, dry_run: dry_run)
        [suite, bytes] if suite
      rescue Errno::ENOENT, K4Evidence::Error
        nil
      end

      def parse_suite(bytes, dry_run:)
        suites = JSON.parse(bytes)
        return unless suites.is_a?(Array) && suites.one? && suites.first.is_a?(Hash)

        suite = suites.first
        suite if stock_suite?(suite, dry_run: dry_run)
      rescue JSON::ParserError
        nil
      end

      def stock_suite?(suite, dry_run:)
        config = suite["SuiteConfig"]
        suite["SuiteDescription"] == "E2eNode Suite" && suite["SuiteHasProgrammaticFocus"] == false &&
          suite["SpecReports"].is_a?(Array) && suite["SpecReports"].all?(Hash) && config.is_a?(Hash) &&
          [true, false].include?(suite["SuiteSucceeded"]) &&
          config.values_at("LabelFilter", "DryRun", "FailOnEmpty", "FailFast", "FlakeAttempts", "MustPassRepeatedly", "SemVerFilter") ==
            [LABEL, dry_run, true, false, 0, 0, ""] &&
          config.values_at("FocusStrings", "FocusFiles", "SkipStrings", "SkipFiles").all? { |filter| filter.nil? || filter == [] }
      end

      # The stock v1.36.2 registration differs with AppArmor availability. Lock
      # the selected full text and source locations for both observed variants.
      def inventory_identity(suite)
        selected = cases(suite).select { |entry| entry["State"] == "passed" }
        ids = selected.map { |entry| case_id(entry).values }
        return unless ids.uniq.size == ids.size && !ids.empty?

        {"registered" => cases(suite).size, "selected" => ids.size,
         "selection_sha256" => Digest::SHA256.hexdigest(JSON.generate(ids.sort))}
      end

      def pinned_inventory?(suite)
        return false unless suite["SuiteSucceeded"] == true && cases(suite).all? { |entry| entry["NumAttempts"] == 0 }

        identity = inventory_identity(suite)
        pin = Lock.kubernetes.fetch("node_conformance")
        stats = suite["PreRunStats"]
        pin.fetch("label") == LABEL && pin.fetch("inventories").value?(identity) &&
          stats == {"TotalSpecs" => identity.fetch("registered"), "SpecsThatWillRun" => identity.fetch("selected")}
      end

      def record_capture(directory, name, capture)
        bytes = "#{JSON.pretty_generate(capture)}\n"
        Lanes.record(directory, name, bytes)
        K4Evidence.retain(File.join(directory, name), bytes: bytes.b)
      end

      def junit_artifacts(directory)
        # Ginkgo and the e2e framework can each write JUnit into the report directory.
        Dir.glob([JUNIT, "junit_*.xml"], base: directory).filter_map do |name|
          path = File.join(directory, name)
          next unless File.lstat(path).file?

          bytes = File.binread(path)
          K3JUnit.complete_xml?(bytes) ? K4Evidence.retain(path, bytes: bytes) : Lanes.artifact_for(path)
        end
      end

      def junit_matches?(directory, actual, artifacts)
        names = artifacts.map { |artifact| File.basename(artifact.fetch("path")).delete_suffix(".gz") }
        [FRAMEWORK_JUNIT, JUNIT].all? do |name|
          names.include?(name) && K4JUnit.matches?(K4Evidence.read(File.join(directory, name)), actual, framework: name == FRAMEWORK_JUNIT)
        end
      end

      def complete_coverage?(expected, actual, coverage)
        return false unless coverage.fetch("complete") && expected["PreRunStats"] == actual["PreRunStats"] &&
                            Array(actual["SpecialSuiteFailureReasons"]).empty?

        wanted = cases(expected).map { |entry| case_id(entry) }.tally
        observed = cases(actual).map { |entry| case_id(entry) }.tally
        wanted == observed
      end

      def compare(expected, actual, rro_supported: nil)
        selection = cases(expected).select { |entry| entry["State"] == "passed" }
        selected = selection.to_h { |entry| [case_id(entry), true] }
        observations = cases(actual).group_by { |entry| case_id(entry) }
        expected_skips = if !rro_supported.nil? && stock_suite?(expected, dry_run: true) && pinned_inventory?(expected) && stock_suite?(actual, dry_run: false)
                           K4RRO.expected_skips(rro_supported, selected, observations, suite: actual)
                         else
                           []
                         end
        required_passes = selected.keys - expected_skips.map { |entry| entry.fetch("id") }
        failures = required_passes.filter_map do |id|
          results = observations.fetch(id, [])
          unless results.one? && results.first.values_at("State", "NumAttempts") == ["passed", 1]
            {"id" => id, "states" => results.map { |entry| entry["State"] }}
          end
        end
        unexpected = observations.reject { |id, _entries| selected.key?(id) }.filter_map do |id, entries|
          id unless entries.all? { |entry| entry["NumAttempts"] == 0 && %w[skipped pending].include?(entry["State"]) }
        end
        complete = actual["SuiteSucceeded"] == true && !selected.empty? && selection.size == selected.size &&
                   failures.empty? && unexpected.empty?
        coverage = {"complete" => complete, "selected" => selected.size, "passed" => required_passes.size - failures.size,
                    "missing_failed_or_skipped" => failures, "unexpected_executions" => unexpected}
        coverage["expected_skips"] = expected_skips unless expected_skips.empty?
        coverage
      end

      def cases(suite)
        Array(suite["SpecReports"]).select { |entry| entry["LeafNodeType"] == "It" }
      end

      def case_id(entry)
        location = entry.fetch("LeafNodeLocation")
        {"name" => (Array(entry["ContainerHierarchyTexts"]) + [entry["LeafNodeText"]]).join(" "),
         "file" => location["FileName"], "line" => location["LineNumber"]}
      end

      def failed(artifacts, reason)
        {"lane" => "K4", "passed" => false, "status" => "FAILED", "artifacts" => artifacts, "reason" => reason}
      end
    end
  end
end
