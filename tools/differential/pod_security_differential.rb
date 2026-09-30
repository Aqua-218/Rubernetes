#!/usr/bin/env ruby
# frozen_string_literal: true

# The Pod Security Standards checks (lib/rubernetes/security/pod_security.rb)
# against upstream's policy package: random Pods over every level and a
# spread of versions go to test/conformance/kubernetes/podsecurity_oracle
# (compiled into k8s.io/pod-security-admission/policy through a go test
# overlay) and to the port; decision, reason and detail must match.
#
#   ruby tools/differential/pod_security_differential.rb [--seed N] [--cases N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/security/pod_security"

module PodSecurityDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/podsecurity_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  PS = Rubernetes::Security::PodSecurity
  VERSIONS = %w[latest v1.0 v1.8 v1.18 v1.19 v1.22 v1.23 v1.24 v1.25 v1.26 v1.27 v1.28 v1.29 v1.30 v1.31 v1.32 v1.33 v1.34 v1.35 v1.36
                v1.40].freeze

  module_function

  def pick(random, list) = list.sample(random: random)
  def maybe(random, probability = 0.3) = random.rand < probability

  def security_context(random)
    context = {}
    context["privileged"] = pick(random, [true, false]) if maybe(random, 0.15)
    context["allowPrivilegeEscalation"] = pick(random, [true, false]) if maybe(random, 0.5)
    context["runAsNonRoot"] = pick(random, [true, false]) if maybe(random, 0.4)
    context["runAsUser"] = pick(random, [0, 1000]) if maybe(random, 0.3)
    context["procMount"] = pick(random, %w[Default Unmasked]) if maybe(random, 0.15)
    if maybe(random, 0.5)
      caps = {}
      caps["drop"] = pick(random, [["ALL"], ["NET_RAW"], []]) if maybe(random, 0.7)
      caps["add"] = pick(random, [["NET_BIND_SERVICE"], ["SYS_ADMIN"], %w[CHOWN NET_ADMIN], []]) if maybe(random, 0.5)
      context["capabilities"] = caps
    end
    context["seccompProfile"] = {"type" => pick(random, %w[RuntimeDefault Localhost Unconfined])} if maybe(random, 0.4)
    context["appArmorProfile"] = {"type" => pick(random, %w[RuntimeDefault Localhost Unconfined])} if maybe(random, 0.15)
    if maybe(random, 0.15)
      context["seLinuxOptions"] = {"type" => pick(random, ["", "container_t", "container_engine_t", "spc_t"])}
      context["seLinuxOptions"]["user"] = "u" if maybe(random, 0.2)
      context["seLinuxOptions"]["role"] = "r" if maybe(random, 0.2)
    end
    context["windowsOptions"] = {"hostProcess" => pick(random, [true, false])} if maybe(random, 0.1)
    context
  end

  def container(random, name)
    item = {"name" => name, "image" => "img"}
    item["securityContext"] = security_context(random) if maybe(random, 0.7)
    item["ports"] = [{"containerPort" => 80, "hostPort" => pick(random, [0, 8080, 9090])}] if maybe(random, 0.2)
    item["livenessProbe"] = {"httpGet" => {"port" => 80, "host" => pick(random, ["", "1.2.3.4", "example.com"])}} if maybe(random, 0.15)
    item["lifecycle"] = {"preStop" => {"tcpSocket" => {"port" => 80, "host" => pick(random, ["", "10.0.0.1"])}}} if maybe(random, 0.1)
    item
  end

  def pod(random)
    spec = {"containers" => Array.new(random.rand(1..3)) { |i| container(random, "c#{i}") }}
    spec["initContainers"] = [container(random, "init")] if maybe(random, 0.2)
    spec["ephemeralContainers"] = [container(random, "debug")] if maybe(random, 0.1)
    %w[hostNetwork hostPID hostIPC].each { |field| spec[field] = true if maybe(random, 0.08) }
    spec["hostUsers"] = pick(random, [true, false]) if maybe(random, 0.2)
    spec["os"] = {"name" => pick(random, %w[linux windows])} if maybe(random, 0.15)
    pod_context = {}
    pod_context["runAsNonRoot"] = pick(random, [true, false]) if maybe(random, 0.4)
    pod_context["runAsUser"] = pick(random, [0, 1000]) if maybe(random, 0.2)
    pod_context["seccompProfile"] = {"type" => pick(random, %w[RuntimeDefault Localhost Unconfined])} if maybe(random, 0.4)
    if maybe(random, 0.2)
      pod_context["sysctls"] = [{"name" => pick(random, %w[kernel.shm_rmid_forced net.ipv4.tcp_rmem kernel.msgmax net.ipv4.tcp_keepalive_time]),
                                 "value" => "1"}]
    end
    pod_context["seLinuxOptions"] = {"type" => pick(random, %w[container_t spc_t])} if maybe(random, 0.1)
    pod_context["windowsOptions"] = {"hostProcess" => true} if maybe(random, 0.05)
    pod_context["appArmorProfile"] = {"type" => pick(random, %w[RuntimeDefault Unconfined])} if maybe(random, 0.1)
    spec["securityContext"] = pod_context unless pod_context.empty?
    volumes = []
    volumes << {"name" => "cfg", "configMap" => {"name" => "x"}} if maybe(random, 0.3)
    volumes << {"name" => "host", "hostPath" => {"path" => "/"}} if maybe(random, 0.15)
    volumes << {"name" => "nfs", "nfs" => {"server" => "s", "path" => "/"}} if maybe(random, 0.1)
    volumes << {"name" => "img", "image" => {"reference" => "x"}} if maybe(random, 0.1)
    spec["volumes"] = volumes if volumes.any?
    annotations = {}
    annotations["container.apparmor.security.beta.kubernetes.io/c0"] = pick(random, %w[runtime/default unconfined localhost/p]) if maybe(
      random, 0.1
    )
    annotations["seccomp.security.alpha.kubernetes.io/pod"] = pick(random, %w[runtime/default unconfined docker/default]) if maybe(random,
                                                                                                                                   0.1)
    annotations["container.seccomp.security.alpha.kubernetes.io/c0"] = pick(random, %w[unconfined localhost/x]) if maybe(random, 0.05)
    metadata = {"name" => "p"}
    metadata["annotations"] = annotations if annotations.any?
    {"metadata" => metadata, "spec" => spec}
  end

  def cases(random, count)
    Array.new(count) do
      {"level" => pick(random, %w[privileged baseline restricted]), "version" => pick(random, VERSIONS), "pod" => pod(random)}
    end
  end

  def run_port(evaluator, test_case)
    version, = PS.parse_version(test_case["version"])
    result = PS.aggregate(evaluator.evaluate(PS::LevelVersion.new(test_case["level"], version),
                                             test_case["pod"]["metadata"], test_case["pod"]["spec"]))
    {"allowed" => result.allowed, "reason" => result.forbidden_reason, "detail" => result.forbidden_detail}
  end

  def run_oracle(cases)
    Dir.mktmpdir("podsecurity-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate(cases))
      package = File.join(File.realpath(SOURCE), "staging/src/k8s.io/pod-security-admission/policy")
      File.write(overlay, JSON.generate("Replace" => {File.join(package, "zz_rubernetes_oracle_test.go") => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, "k8s.io/pod-security-admission/policy",
                                       "-run", "TestRubernetesPodSecurityOracle", "-count=1", chdir: SOURCE)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output))
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_925
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 3000
    list = cases(Random.new(seed), count)
    evaluator = PS::Evaluator.new
    mismatches = list.zip(run_oracle(list)).filter_map do |test_case, want|
      got = run_port(evaluator, test_case)
      [test_case, want, got] unless got == want
    end
    mismatches.first(4).each do |test_case, want, got|
      puts "MISMATCH #{JSON.generate(test_case)[0, 900]}"
      puts "  upstream: #{want}"
      puts "  port:     #{got}"
    end
    puts "#{list.length - mismatches.length}/#{list.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(PodSecurityDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
