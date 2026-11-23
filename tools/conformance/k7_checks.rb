# frozen_string_literal: true

require "rexml/document"
require_relative "k7_contract"
require_relative "lanes"

module Conformance
  module K7Checks
    ROOT = Lock::ROOT
    E2E = File.join(ROOT, "build/conformance/bin/e2e.test")
    SMOKE_SPECS = K7Contract::SMOKE_SPECS

    module_function

    def run(id, options)
      output = File.join(options.fetch(:output), id)
      FileUtils.mkdir_p(output)
      {"k1_smoke" => smoke(options.fetch(:kubeconfig), output),
       "k5_differential" => differential(options, output)}
    end

    def smoke(kubeconfig, output)
      return incomplete("build the pinned e2e.test with rake m8:e2e_build") unless File.executable?(E2E)

      junit = File.join(output, "k1-smoke.xml")
      focus = K7Contract.smoke_focus
      execution = Lanes.capture([E2E, "--provider=skeleton", "--kubeconfig", kubeconfig,
                                 "--kubectl-path", K7Lifecycle::KUBECTL, "--ginkgo.focus=#{focus}",
                                 "--ginkgo.junit-report=#{junit}", "--ginkgo.no-color"],
                                env: {"NO_PROXY" => "*", "no_proxy" => "*"}, timeout: 300)
      command = Lanes.record(output, "k1-smoke-command.json", execution)
      cases = File.file?(junit) ? REXML::XPath.match(REXML::Document.new(File.binread(junit)), "//testcase") : []
      specs = cases.select { |testcase| testcase.attributes["name"].to_s.start_with?("[It] ") }
      observed = SMOKE_SPECS.map do |id|
        matching = specs.select { |testcase| testcase.attributes["name"].start_with?("[It] #{id} [") }
        {"id" => id, "status" => matching.one? ? matching.first.attributes["status"] : "not uniquely reported"}
      end
      passed = execution["exit_status"] == 0 && specs.count { |testcase| testcase.attributes["status"] == "passed" } == SMOKE_SPECS.length &&
               observed.all? { |testcase| testcase.fetch("status") == "passed" }
      cleaned = passed && wait_for_smoke_cleanup(kubeconfig, execution.fetch("stdout"))
      passed &&= cleaned
      {"passed" => passed, "status" => passed ? "COMPLETE" : "FAILED", "cases" => observed,
       "namespaces_cleaned_up" => cleaned,
       "binary_sha256" => (@e2e_sha256 ||= Digest::SHA256.file(E2E).hexdigest),
       "command_sha256" => command.fetch("sha256"),
       "junit_sha256" => (Digest::SHA256.file(junit).hexdigest if File.file?(junit))}
    rescue REXML::ParseException
      {"passed" => false, "status" => "FAILED", "reason" => "upstream smoke report could not be parsed"}
    end

    def wait_for_smoke_cleanup(kubeconfig, stdout)
      run_id = stdout[/Starting e2e run "([0-9a-f-]+)"/, 1]
      return false unless run_id

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 60
      loop do
        namespaces = api_object(kubeconfig, "/api/v1/namespaces?labelSelector=e2e-run%3D#{run_id}")
        return true if namespaces && namespaces.fetch("items").empty?
        return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 1
      end
    end

    def differential(options, output)
      oracle = options[:oracle_kubeconfig]
      return incomplete("supply a Kubernetes v1.36.2 oracle kubeconfig") unless oracle && File.file?(oracle)

      kubeconfig = options.fetch(:kubeconfig)
      return incomplete("the target and Kubernetes oracle must be separate clusters") if File.identical?(kubeconfig, oracle)

      version = api_object(oracle, "/version")
      return incomplete("cannot read the Kubernetes oracle version") unless version

      return incomplete("the Kubernetes oracle must serve the pinned Kubernetes source commit") unless version.fetch("gitCommit", nil) == Lock.source_commit

      oracle_namespace = api_object(oracle, "/api/v1/namespaces/default")
      target_namespace = api_object(kubeconfig, "/api/v1/namespaces/default")
      return incomplete("cannot read the default namespace from both clusters") if oracle_namespace.nil? || target_namespace.nil?
      if oracle_namespace.dig("metadata", "uid") == target_namespace.dig("metadata", "uid")
        return incomplete("the target and Kubernetes oracle must be separate clusters")
      end

      runner = File.join(__dir__, "k5_differential.rb")
      execution = Lanes.capture([RbConfig.ruby, runner, "--kubeconfig", kubeconfig,
                                 "--oracle-kubeconfig", oracle, "--output", output],
                                env: {"NO_PROXY" => "*", "no_proxy" => "*"}, timeout: 300)
      command = Lanes.record(output, "k5-differential-command.json", execution)
      report = File.join(output, "differential.json")
      passed = execution["exit_status"] == 0 && File.file?(report)
      {"passed" => passed, "status" => passed ? "COMPLETE" : "FAILED",
       "command_sha256" => command.fetch("sha256"),
       "report_sha256" => (Digest::SHA256.file(report).hexdigest if File.file?(report))}
    end

    def api_object(kubeconfig, path)
      out, _err, status = Open3.capture3({"NO_PROXY" => "*", "no_proxy" => "*"}, K7Lifecycle::KUBECTL,
                                         "--kubeconfig", kubeconfig, "--request-timeout=10s", "get", "--raw", path)
      JSON.parse(out) if status.success?
    rescue JSON::ParserError
      nil
    end

    def incomplete(reason)
      {"passed" => false, "status" => "INCOMPLETE", "reason" => reason}
    end
  end
end
