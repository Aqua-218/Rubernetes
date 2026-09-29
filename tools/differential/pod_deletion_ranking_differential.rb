#!/usr/bin/env ruby
# frozen_string_literal: true

# The ReplicaSet scale-down order (lib/rubernetes/controller/pod_deletion_ranking.rb)
# against pkg/controller ActivePodsWithRanks: generated Pods (node, phase,
# readiness and its transition time, pod-deletion-cost annotations valid and
# not, restarts of containers and sidecars, creation times from seconds to
# weeks ago) with doubled-up ranks go to
# test/conformance/kubernetes/pod_ranking_oracle (a go test overlay) and to
# the port; the sorted orders are compared.
#
#   ruby tools/differential/pod_deletion_ranking_differential.rb [--cases N] [--seed N] [--show]

require "json"
require "open3"
require "tmpdir"
require "time"
require_relative "../../lib/rubernetes/controller/pod_deletion_ranking"

module PodDeletionRankingDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/pod_ranking_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/srv/rubernetes/kubernetes-v1.36.2")
  Ranking = Rubernetes::Controller::PodDeletionRanking
  COSTS = [nil, "0", "5", "-3", "100", "007", "+4", "abc", "2147483648", "-2147483648", "-007", ""].freeze
  AGES = [0, 1, 2, 3, 7, 30, 61, 300, 3_600, 7_200, 86_400, 604_800].freeze

  module_function

  def stamp(now, seconds) = (now - seconds).utc.iso8601

  def pod(random, index, now)
    ready = random.rand < 0.6
    phase = %w[Pending Running Running Unknown Failed Succeeded].sample(random: random)
    conditions = []
    if random.rand < 0.85
      conditions << {"type" => "Ready", "status" => ready ? "True" : "False",
                     "lastTransitionTime" => stamp(now, AGES.sample(random: random) + random.rand(0..3))}
    end
    metadata = {"name" => "p#{index}", "uid" => format("uid-%03d", random.rand(1000)), "namespace" => "ns"}
    metadata["creationTimestamp"] = stamp(now, AGES.sample(random: random) + random.rand(0..5)) if random.rand < 0.95
    cost = COSTS.sample(random: random)
    metadata["annotations"] = {Ranking::DELETION_COST_ANNOTATION => cost} if cost
    spec = {"containers" => [{"name" => "app", "image" => "x"}]}
    spec["nodeName"] = %w[n1 n2 n3].sample(random: random) if random.rand < 0.8
    sidecar = random.rand < 0.3
    spec["initContainers"] = [{"name" => "side", "image" => "x", "restartPolicy" => "Always"}] if sidecar
    status = {"phase" => phase, "conditions" => conditions,
              "containerStatuses" => [{"name" => "app", "restartCount" => [0, 0, 1, 3].sample(random: random), "ready" => ready,
                                       "image" => "x", "imageID" => "", "state" => {}}]}
    if sidecar
      status["initContainerStatuses"] = [{"name" => "side", "restartCount" => [0, 2].sample(random: random), "ready" => true,
                                          "image" => "x", "imageID" => "", "state" => {}}]
    end
    {"metadata" => metadata, "spec" => spec, "status" => status}
  end

  def cases(random, count)
    now = Time.utc(2026, 9, 24, 5, 0, 0) + Rational(random.rand(1_000_000_000), 1_000_000_000)
    Array.new(count) do |index|
      pods = Array.new(random.rand(2..9)) { |i| pod(random, i, now) }
      {"name" => "case-#{index}", "now" => now.iso8601(9), "pods" => pods, "ranks" => pods.map { random.rand(0..3) }}
    end
  end

  def run_port(test_case)
    now = Time.iso8601(test_case["now"])
    order = Ranking.ranked_order(test_case["pods"], test_case["ranks"], now)
    {"name" => test_case["name"], "order" => order.map { |pod| pod.dig("metadata", "name") }}
  end

  def run_oracle(cases)
    Dir.mktmpdir("pod-ranking-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      target = File.join(File.realpath(SOURCE), "pkg/controller/zz_rubernetes_pod_ranking_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      env = {"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output}
      stdout, status = Open3.capture2e(env, "go", "test", "-overlay", overlay, "./pkg/controller",
                                       "-run", "TestRubernetesPodRankingOracle", "-count=1", chdir: File.realpath(SOURCE))
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  def main(argv)
    show = argv.include?("--show")
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_924
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 2000
    all = cases(Random.new(seed), count)
    expected = run_oracle(all)
    mismatches = all.zip(expected).reject { |test_case, want| run_port(test_case) == want }
    mismatches.first(show ? mismatches.length : 3).each do |test_case, want|
      puts "MISMATCH #{test_case["name"]}"
      puts "  upstream: #{want["order"].inspect}"
      puts "  port:     #{run_port(test_case)["order"].inspect}"
      test_case["pods"].each_with_index do |pod, index|
        puts "    #{pod.dig("metadata", "name")} rank=#{test_case["ranks"][index]} #{pod.slice("metadata", "status").to_json[0, 400]}"
      end
    end
    puts "#{all.length - mismatches.length}/#{all.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(PodDeletionRankingDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
