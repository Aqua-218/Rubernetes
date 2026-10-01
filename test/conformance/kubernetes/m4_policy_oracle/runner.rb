#!/usr/bin/env ruby
# frozen_string_literal: true

# External NetworkPolicy oracle for the M4 policy differential.
#
# The oracle is the pinned Kubernetes v1.36.2 node image booted by kind
# (the same digest-locked image, kindnetd, containerd and runc the M2
# lifecycle oracle verifies) with kindnetd enforcing NetworkPolicy.  For each
# case the runner applies the policy fixture it received, then measures the
# reachability from a client pod to a server pod with a static connectivity
# tool (netprobe, TCP and SCTP) copied into the node and mounted into busybox
# pods.  The measured verdict is the oracle observable; the probe compares its
# own PolicyEngine verdict against it.  The runner never receives the probe's
# expected answer.
#
# Request (stdin): {"kubernetes_version", "source_commit", "case_ids",
#                   "cases": [{"id", "fixture": {"policy", "source",
#                   "destination", "direction", "protocol", "port", "end_port"}}]}

require "digest"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "securerandom"
require "time"

ROOT = File.expand_path("../../../..", __dir__)
require_relative "../m2_lifecycle_oracle/harness"
require_relative "../m2_lifecycle_oracle/node_image"

module M4PolicyOracleRunner
  RUNNER_PATH = File.expand_path(__FILE__)
  NETPROBE_DIR = File.join(__dir__, "netprobe")
  BUILD_DIR = File.join(ROOT, "build/tools/m4-policy-oracle")
  NODE_NETPROBE_PATH = "/opt/rubernetes/netprobe"
  IMPLEMENTATION = "kindnetd NetworkPolicy enforcement in the digest-pinned Kubernetes v1.36.2 kind node image (netprobe reachability measurement)"
  SERVER_PORTS = {"tcp" => [8080, 8001], "sctp" => [9999]}.freeze
  NAMED_PORTS = {"http" => 8080}.freeze
  CONNECT_TIMEOUT = 4
  CONNECT_ATTEMPTS = 3
  SETTLE_SECONDS = 3

  module_function

  def canonical(value)
    case value
    when Hash then value.keys.map(&:to_s).sort.to_h do |key|
                     [key, canonical(value.fetch(value.keys.find do |k|
                       k.to_s == key
                     end))]
                   end
    when Array then value.map { |child| canonical(child) }
    else value
    end
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
  end

  def netprobe_source_sha256
    files = Dir.glob(File.join(NETPROBE_DIR, "*")).select { |path| File.file?(path) }.sort
    Digest::SHA256.hexdigest(files.map { |path| "#{File.basename(path)}\0#{Digest::SHA256.file(path).hexdigest}\n" }.join)
  end

  def build_netprobe!
    source_sha = netprobe_source_sha256
    binary = File.join(BUILD_DIR, "netprobe-#{source_sha[0, 16]}")
    return [binary, source_sha] if File.executable?(binary)

    FileUtils.mkdir_p(BUILD_DIR)
    environment = {"GOTOOLCHAIN" => "auto", "GOWORK" => "off", "CGO_ENABLED" => "0"}
    _stdout, stderr, status = Open3.capture3(environment, "go", "build", "-trimpath", "-ldflags", "-s -w", "-o", binary, ".",
                                             chdir: NETPROBE_DIR)
    raise "go build of netprobe failed: #{stderr.strip}" unless status.success?

    [binary, source_sha]
  end

  class PolicyRun < M2LifecycleOracleHarness::Run
    NAMESPACE = M2LifecycleOracleHarness::NAMESPACE

    def initialize(input, cases:, netprobe:)
      super(input)
      @cases = cases
      @netprobe = netprobe
      @results = []
      @verifications = {}
    end

    attr_reader :results, :source, :runtime_identity

    # The M2 fixture inventory is irrelevant here; the identity checks are.
    def validate_inputs!
      @fixture_cases = M2LifecycleOracleHarness::REQUIRED_CASES.to_h { |name| [name, {}] }
      super
    end

    def execute
      @scratch = Dir.mktmpdir("rubernetes-m4-policy-oracle-", ENV.fetch("RUBERNETES_M2_LIFECYCLE_SCRATCH", Dir.tmpdir))
      validate_inputs!
      create_network!
      create_cluster!
      verify_cluster_identity!
      verify_network_isolation!
      verify_runtime_identity!
      verify_cni!
      import_workload_image!
      install_netprobe!
      deploy_pods!
      verify_baseline!
      @cases.each { |kase| @results << measure_case(kase) }
      {"source" => @source, "runtime" => @runtime, "cni" => @cni, "pods" => @pods, "baseline" => @baseline,
       "verifications" => @verifications, "cluster" => @cluster, "trace" => @trace}
    ensure
      teardown!
    end

    private

    def install_netprobe!
      node_exec("mkdir", "-p", File.dirname(NODE_NETPROBE_PATH))
      M2LifecycleOracleHarness.docker("cp", @netprobe, "#{@node}:#{NODE_NETPROBE_PATH}")
      node_exec("chmod", "0755", NODE_NETPROBE_PATH)
      sha, = node_exec("sha256sum", NODE_NETPROBE_PATH)
      @verifications["netprobe"] = {"path" => NODE_NETPROBE_PATH, "sha256" => sha.split.first, "runner_sha256" => Digest::SHA256.file(@netprobe).hexdigest}
      unless sha.split.first == Digest::SHA256.file(@netprobe).hexdigest
        raise M2LifecycleOracleHarness::HarnessError, "netprobe inside the node differs from the runner binary"
      end

      step("netprobe_installed", sha256: sha.split.first)
    end

    def pod_document(name, labels, command, ports: [])
      {
        "apiVersion" => "v1", "kind" => "Pod",
        "metadata" => {"name" => name, "namespace" => NAMESPACE, "labels" => labels.merge("rubernetes.io/m4-policy-oracle" => @cluster)},
        "spec" => {
          "restartPolicy" => "Never", "terminationGracePeriodSeconds" => 1,
          "volumes" => [{"name" => "netprobe", "hostPath" => {"path" => NODE_NETPROBE_PATH, "type" => "File"}}],
          "containers" => [{
            "name" => "main", "image" => @busybox_reference, "command" => command,
            "volumeMounts" => [{"name" => "netprobe", "mountPath" => "/netprobe", "readOnly" => true}],
            "ports" => ports
          }]
        }
      }
    end

    def deploy_pods!
      server_ports = [{"name" => "http", "containerPort" => 8080, "protocol" => "TCP"},
                      {"name" => "alt", "containerPort" => 8001, "protocol" => "TCP"},
                      {"name" => "sctp", "containerPort" => 9999, "protocol" => "SCTP"}]
      server = pod_document("m4-policy-server", {"app" => "server"},
                            ["/netprobe", "serve", "--tcp", SERVER_PORTS.fetch("tcp").join(","), "--sctp", SERVER_PORTS.fetch("sctp").join(",")],
                            ports: server_ports)
      client = pod_document("m4-policy-client", {"role" => "client"}, ["sh", "-c", "trap 'exit 0' TERM; while true; do sleep 1; done"])
      kubectl("apply", "-f", "-", stdin_data: JSON.generate({"apiVersion" => "v1", "kind" => "List", "items" => [server, client]}))
      @pods = {}
      wait_until("policy oracle pods running", M2LifecycleOracleHarness::TIMEOUTS.fetch(:cases)) do
        pods = kubectl_json("get", "pods", "-n", NAMESPACE, "-l", "rubernetes.io/m4-policy-oracle=#{@cluster}")
        items = pods.fetch("items")
        next false unless items.length == 2 && items.all? do |item|
          item.dig("status", "phase") == "Running" && item.dig("status", "podIP").to_s != ""
        end

        items.each do |item|
          @pods[item.dig("metadata", "name")] = {"ip" => item.dig("status", "podIP"), "ips" => Array(item.dig("status", "podIPs")).map do |entry|
            entry["ip"]
          end,
                                                 "labels" => item.dig("metadata", "labels"), "node" => item.dig("spec", "nodeName"),
                                                 "uid" => item.dig("metadata", "uid")}
        end
        true
      end
      step("pods_running", pods: @pods)
    end

    def connect_once(protocol, port)
      target = @pods.fetch("m4-policy-server").fetch("ip")
      stdout, stderr, status = kubectl("exec", "-n", NAMESPACE, "m4-policy-client", "--", "/netprobe", "connect",
                                       "--proto", protocol, "--addr", target, "--port", port.to_s, "--timeout", "#{CONNECT_TIMEOUT}s",
                                       allow_failure: true, timeout: CONNECT_TIMEOUT + 30)
      parsed = begin
        JSON.parse(stdout.lines.last.to_s)
      rescue JSON::ParserError
        {"connected" => false, "error" => "netprobe output unreadable: #{stdout.strip} #{stderr.strip}"[0, 300]}
      end
      parsed.merge("exit_status" => status.exitstatus)
    end

    # A verdict is "allowed" when any attempt connects and "denied" when every
    # attempt fails; the attempts are recorded so a flaky measurement is
    # visible rather than hidden.
    def measure_reachability(protocol, port)
      attempts = []
      CONNECT_ATTEMPTS.times do
        attempt = connect_once(protocol, port)
        attempts << attempt
        break if attempt["connected"] == true

        sleep 0.5
      end
      {"allowed" => attempts.any? do |attempt|
        attempt["connected"] == true
      end, "attempts" => attempts, "protocol" => protocol, "port" => port}
    end

    def verify_baseline!
      @baseline = {}
      {"tcp" => 8080, "tcp_alt" => 8001, "sctp" => 9999}.each do |label, port|
        protocol = label.start_with?("sctp") ? "sctp" : "tcp"
        @baseline[label] = measure_reachability(protocol, port)
        next if @baseline[label]["allowed"]

        raise M2LifecycleOracleHarness::HarnessError,
              "baseline #{protocol}/#{port} is unreachable without any policy: #{JSON.generate(@baseline[label])[0,
                                                                                                                 400]}"
      end
      step("baseline_verified")
    end

    def resolve_port(fixture)
      port = fixture["port"]
      port = 8080 if port.nil?
      port = NAMED_PORTS.fetch(port) if port.is_a?(String) && !port.match?(/\A\d+\z/)
      Integer(port)
    end

    def measure_case(kase)
      id = kase.fetch("id")
      fixture = kase.fetch("fixture")
      policy = JSON.parse(JSON.generate(fixture.fetch("policy")))
      policy["apiVersion"] ||= "networking.k8s.io/v1"
      policy["kind"] ||= "NetworkPolicy"
      policy["metadata"] =
        (policy["metadata"] || {}).merge("namespace" => NAMESPACE, "labels" => {"rubernetes.io/m4-policy-oracle" => @cluster})
      protocol = fixture["protocol"].to_s.downcase
      protocol = "tcp" if protocol.empty?
      port = resolve_port(fixture)
      kubectl("apply", "-f", "-", stdin_data: JSON.generate(policy))
      applied = wait_until("policy #{id} visible", 30) do
        stdout, _stderr, status = kubectl("get", "networkpolicy", "-n", NAMESPACE, policy.dig("metadata", "name"), "-o", "json",
                                          allow_failure: true)
        status.success? ? JSON.parse(stdout) : nil
      end
      sleep SETTLE_SECONDS
      measurement = measure_reachability(protocol, port)
      confirmation = measure_reachability(protocol, port)
      kubectl("delete", "networkpolicy", "-n", NAMESPACE, policy.dig("metadata", "name"), "--wait=true")
      sleep 1
      restored = measure_reachability(protocol, port)
      step("case_measured", case: id, allowed: measurement["allowed"], confirmed: confirmation["allowed"], restored: restored["allowed"])
      {
        "id" => id, "policy_name" => policy.dig("metadata", "name"), "policy_uid" => applied.dig("metadata", "uid"),
        "policy_resource_version" => applied.dig("metadata", "resourceVersion"),
        "protocol" => protocol.upcase, "port" => port, "requested_port" => fixture["port"], "end_port" => fixture["end_port"],
        "direction" => fixture["direction"], "server_ip" => @pods.fetch("m4-policy-server").fetch("ip"),
        "client_ip" => @pods.fetch("m4-policy-client").fetch("ip"),
        "measurement" => measurement, "confirmation" => confirmation, "restored_without_policy" => restored,
        "policy_sha256" => M4PolicyOracleRunner.digest(fixture.fetch("policy"))
      }
    end
  end

  def main
    started_at = Time.now.utc.iso8601(6)
    raw = $stdin.read.to_s
    request = raw.strip.empty? ? {} : JSON.parse(raw)
    cases = Array(request["cases"]).select { |entry| entry.is_a?(Hash) && entry["id"] && entry["fixture"].is_a?(Hash) }
    raise "request carries no NetworkPolicy cases" if cases.empty?

    netprobe, netprobe_sha = build_netprobe!
    image = M2LifecycleOracleNodeImage.report("kubernetes_version" => M2LifecycleOracleHarness::KUBERNETES_VERSION,
                                              "source_commit" => M2LifecycleOracleHarness::KUBERNETES_SOURCE_COMMIT)
    input = {"request" => {"cases" => {}}, "node_image" => image.fetch("image"), "runtime" => image.fetch("runtime"),
             "node_image_document" => image}
    run = PolicyRun.new(input, cases: cases, netprobe: netprobe)
    trace = run.trace
    cluster = run.execute
    comparisons = run.results.map do |result|
      expected = {"allowed" => result.fetch("measurement").fetch("allowed")}
      actual = {"allowed" => result.fetch("confirmation").fetch("allowed")}
      {"id" => result.fetch("id"), "case" => result.fetch("id"),
       "expected_observable" => expected, "actual_observable" => actual,
       "expected_sha256" => digest(expected), "actual_sha256" => digest(actual),
       "passed" => digest(expected) == digest(actual),
       "measurement_source" => "kind_cluster_netprobe", "detail" => result}
    end
    errors = []
    comparisons.each { |entry| errors << "case #{entry["id"]} measurement was not stable between attempts" unless entry["passed"] }
    run.results.each do |result|
      errors << "case #{result["id"]} connectivity did not recover after the policy was deleted" unless result.dig("restored_without_policy",
                                                                                                                   "allowed")
    end
    finished_at = Time.now.utc.iso8601(6)
    runner = {
      "runner_sha256" => Digest::SHA256.file(RUNNER_PATH).hexdigest,
      "command" => [RbConfig.ruby, RUNNER_PATH.delete_prefix("#{ROOT}/")] + ARGV,
      "argv" => [RbConfig.ruby, RUNNER_PATH] + ARGV,
      "process_id" => Process.pid, "mode" => "external", "self_comparison" => false,
      "implementation" => IMPLEMENTATION, "started_at" => started_at, "finished_at" => finished_at,
      "version" => M2LifecycleOracleHarness::KUBERNETES_VERSION, "source_commit" => M2LifecycleOracleHarness::KUBERNETES_SOURCE_COMMIT,
      "node_image" => image.fetch("image"), "node_image_id" => image.fetch("image_id"),
      "cni" => cluster.fetch("cni"), "cluster" => cluster.fetch("source"),
      "netprobe" => {"source_sha256" => netprobe_sha, "binary_sha256" => Digest::SHA256.file(netprobe).hexdigest}
    }
    document = {
      "schema_version" => 1, "suite" => "m4-network-policy-oracle", "executed" => true,
      "runner" => runner, "runner_sha256" => runner.fetch("runner_sha256"), "request_sha256" => digest(request),
      "kubernetes_version" => M2LifecycleOracleHarness::KUBERNETES_VERSION, "source_commit" => M2LifecycleOracleHarness::KUBERNETES_SOURCE_COMMIT,
      "comparisons" => comparisons, "comparison_count" => comparisons.length,
      "cases" => run.results, "cluster" => cluster.reject { |key, _| key == "trace" }, "trace" => trace,
      "measurement_source" => "kind_cluster_netprobe", "errors" => errors, "failure_count" => errors.length, "passed" => errors.empty?
    }
    document["document_sha256"] = digest(document)
    puts JSON.generate(document)
    exit(errors.empty? ? 0 : 1)
  rescue StandardError => error
    warn "#{error.class}: #{error.message}"
    warn error.backtrace.first(12).join("\n")
    puts JSON.generate({"executed" => false, "passed" => false, "errors" => ["#{error.class}: #{error.message}"],
                        "trace" => (defined?(trace) ? trace : [])})
    exit 2
  end
end

M4PolicyOracleRunner.main if $PROGRAM_NAME == __FILE__
