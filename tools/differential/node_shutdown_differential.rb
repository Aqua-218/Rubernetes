#!/usr/bin/env ruby
# frozen_string_literal: true

# Graceful node shutdown's configuration and Pod grouping
# (lib/rubernetes/node/shutdown_manager.rb) against kubelet's
# pkg/kubelet/nodeshutdown: generated configurations (shutdownGracePeriod and
# shutdownGracePeriodCriticalPods with fractional seconds, or
# shutdownGracePeriodByPodPriority), both feature gates, and Pods with or
# without a priority and terminationGracePeriodSeconds.  Compared: whether
# NewManager builds a manager, periodRequested, the sorted groups, which Pods
# fall in each and the grace period killPods gives each.
#
#   ruby tools/differential/node_shutdown_differential.rb [--cases N] [--seed N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/node/shutdown_manager"

module NodeShutdownDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/nodeshutdown_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/srv/rubernetes/kubernetes-v1.36.2")
  SM = Rubernetes::Node::ShutdownManager
  PRIORITIES = [-2_147_483_648, -100, -1, 0, 1, 999, 1_000, 5_000, 10_000, 100_000, 1_000_000_000,
                2_000_000_000, 2_000_001_000, 2_147_483_647].freeze

  module_function

  # Durations as the agent's configuration writes them: whole or tenths
  # of seconds, as integer nanoseconds for Go.
  def duration_nanos(random)
    case random.rand(6)
    when 0 then 0
    when 1 then random.rand(1..120) * 1_000_000_000
    else random.rand(10..1200) * 100_000_000
    end
  end

  def cases(random, count)
    Array.new(count) do |index|
      grace = duration_nanos(random)
      critical = random.rand < 0.2 ? 0 : [duration_nanos(random), grace + (random.rand < 0.1 ? 1_000_000_000 : 0)].min
      by_priority = if random.rand < 0.4
                      PRIORITIES.sample(random.rand(0..5), random: random).map do |priority|
                        {"priority" => priority, "shutdown_grace_period_seconds" => random.rand(0..60)}
                      end
                    else
                      []
                    end
      pods = Array.new(random.rand(0..8)) do |number|
        pod = {"name" => "pod-#{number}"}
        pod["priority"] = random.rand < 0.5 ? PRIORITIES.sample(random: random) : random.rand(-5_000..200_000) if random.rand < 0.8
        pod["grace_period"] = random.rand(0..90) if random.rand < 0.7
        pod
      end
      {"name" => "case-#{index}", "grace_period_nanos" => grace, "critical_grace_period_nanos" => critical,
       "by_priority" => by_priority, "gate" => gate = random.rand >= 0.1, "based_on_priority" => gate && random.rand >= 0.2, "pods" => pods}
    end
  end

  def run_port(test_case)
    manager = SM.build(gate: test_case["gate"], based_on_priority: test_case["based_on_priority"],
                       grace_period: test_case["grace_period_nanos"] / 1e9,
                       critical_grace_period: test_case["critical_grace_period_nanos"] / 1e9,
                       by_priority: test_case["by_priority"],
                       active_pods: -> { [] }, kill_pod: nil, pod_terminated: nil)
    result = {"name" => test_case["name"], "manager" => !manager.nil?, "period_requested" => 0, "groups" => []}
    return result unless manager

    pods = test_case["pods"].map do |pod|
      spec = {}
      spec["priority"] = pod["priority"] if pod.key?("priority")
      spec["terminationGracePeriodSeconds"] = pod["grace_period"] if pod.key?("grace_period")
      {"metadata" => {"name" => pod["name"]}, "spec" => spec}
    end
    result["period_requested"] = manager.period_requested
    result["groups"] = manager.group_by_priority(pods).map do |period, members|
      {"priority" => period.priority, "seconds" => period.seconds,
       "pods" => members.map { |pod| {"name" => pod.dig("metadata", "name"), "grace" => manager.kill_grace(period, pod)} }}
    end
    result
  end

  def run_oracle(cases)
    Dir.mktmpdir("node-shutdown-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      source = File.realpath(SOURCE)
      target = File.join(source, "pkg/kubelet/nodeshutdown/zz_rubernetes_nodeshutdown_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output},
                                       "go", "test", "-overlay", overlay, "./pkg/kubelet/nodeshutdown",
                                       "-run", "TestRubernetesNodeShutdownOracle", "-count=1", chdir: source)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 3000
    # Unique priorities: upstream sorts with the unstable sort.Slice.
    all = cases(Random.new(seed), count)
    expected = run_oracle(all)
    mismatches = all.zip(expected).filter_map do |test_case, want|
      got = run_port(test_case)
      [test_case, want, got] unless got == want
    end
    mismatches.first(5).each do |test_case, want, got|
      puts "MISMATCH #{JSON.generate(test_case)}"
      puts "  upstream: #{JSON.generate(want)}"
      puts "  port:     #{JSON.generate(got)}"
    end
    puts "#{all.length - mismatches.length}/#{all.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(NodeShutdownDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
