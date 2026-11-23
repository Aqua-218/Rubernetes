# frozen_string_literal: true

require "digest"
require "json"
require "zlib"

module Conformance
  # Hydrophone downloads its fixed JUnit and log files, then deletes the Pod.
  # Read the additional stock Ginkgo report from the same output container.
  module K1GinkgoReport
    FLAG = "--extra-args=--report-complete-ginkgo=true"
    ARCHIVE = "ginkgo-report.json.gz"
    RECORDER_LOG = "ginkgo-recorder.log"
    WAIT_FOR_REPORT = <<~SH
      while [ ! -f /tmp/results/ginkgo/report.xml ]; do
        printf '.' >&2
        sleep 0.25
      done
      exec gzip -c /tmp/results/ginkgo/report.json
    SH
    RETRY_EXEC = <<~SH
      destination=$1
      shift
      while :; do
        if "$@" > "$destination.partial" && [ -s "$destination.partial" ]; then
          mv -- "$destination.partial" "$destination"
          exit $?
        fi
        sleep 1
      done
    SH

    module_function

    def capture(kubeconfig, output)
      archive = File.join(output, ARCHIVE)
      command = [kubectl, "--kubeconfig", kubeconfig, "-n", "conformance", "exec", "e2e-conformance-test",
                 "-c", "output-container", "--", "sh", "-ec", WAIT_FOR_REPORT]
      runner = ["sh", "-ec", RETRY_EXEC, "ginkgo-recorder", archive, *Lanes.in_cluster_namespace(command)]
      pid = Process.spawn(*runner, in: File::NULL, out: File::NULL, err: File.join(output, RECORDER_LOG), pgroup: true)
      result = yield
      reaped = wait_for_collector(pid)
      result
    ensure
      Lanes.terminate_group(pid) if pid && !reaped
    end

    def kubectl
      pinned = File.join(Lock::ROOT, "build/tools/kubectl-v1.36.2")
      File.executable?(pinned) ? pinned : "kubectl"
    end

    def wait_for_collector(pid)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
      loop do
        return true if Process.waitpid(pid, Process::WNOHANG)
        return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep(0.05)
      end
    end

    def join(archive, junit, expected:)
      report, digest, bytes = read_report(archive)
      raise ArgumentError, "Ginkgo JSON must contain one suite object" unless report.is_a?(Array) && report.length == 1 && report.first.is_a?(Hash)

      suite = report.first
      config = suite.fetch("SuiteConfig")
      raise ArgumentError, "Ginkgo suite must contain a configuration object" unless config.is_a?(Hash)

      cases = specification_cases(suite.fetch("SpecReports"))
      selected, other = cases.partition { |codename, _state, _attempts| codename.include?("[Conformance]") }
      result = {
        "raw_sha256" => digest, "raw_bytes" => bytes,
        "selected" => selected.length,
        "outcomes" => selected.group_by { |_codename, state, _attempts| state }.transform_values(&:length),
        "unexpected_attempts" => selected.select { |_codename, state, attempts| state == "passed" && attempts != 1 }.map(&:first),
        "unexpected_executions" => other.reject { |_codename, state, _attempts| %w[skipped pending].include?(state) }.map(&:first),
        "junit_cases_match" => selected.map { |codename, state, _attempts| [codename, state] }.sort == junit.fetch("cases").sort,
        "random_seed_match" => config.fetch("RandomSeed").to_s == junit.fetch("random_seed"),
        "suite_passed" => suite.fetch("SuiteSucceeded") == true && Array(suite.fetch("SpecialSuiteFailureReasons", nil)).empty?,
        "execution_properties_match" => execution_properties_match?(suite, config)
      }
      result.merge("passed" => complete?(result, expected))
    end

    def specification_cases(specs)
      raise ArgumentError, "Ginkgo suite must contain spec reports" unless specs.is_a?(Array)

      specs.filter_map do |spec|
        raise ArgumentError, "Ginkgo spec report must be an object" unless spec.is_a?(Hash)
        next unless spec.fetch("LeafNodeType") == "It"

        codename = [*spec.fetch("ContainerHierarchyTexts"), spec.fetch("LeafNodeText")].reject { |text| text == "" }.join(" ").strip
        [codename, spec.fetch("State"), spec.fetch("NumAttempts")]
      end
    end

    def read_report(archive)
      digest = Digest::SHA256.new
      raw = +"".b
      Zlib::GzipReader.open(archive) do |gzip|
        while (chunk = gzip.read(64 * 1024))
          digest.update(chunk)
          raw << chunk
        end
      end
      [JSON.parse(raw), digest.hexdigest, raw.bytesize]
    end

    def execution_properties_match?(suite, config)
      properties = config.transform_values { |value| value.is_a?(Array) ? value.join(",") : value.to_s }
      properties["SuiteHasProgrammaticFocus"] = suite.fetch("SuiteHasProgrammaticFocus").to_s
      K1Evidence.execution_properties_match?(properties)
    end

    def complete?(result, expected)
      result["selected"] == expected && result["outcomes"] == {"passed" => expected} &&
        result["unexpected_attempts"].empty? && result["unexpected_executions"].empty? &&
        result.values_at("junit_cases_match", "random_seed_match", "suite_passed", "execution_properties_match").all?
    end
  end
end
