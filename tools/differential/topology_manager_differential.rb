#!/usr/bin/env ruby
# frozen_string_literal: true

# The topology manager's policies (lib/rubernetes/node/topology_manager.rb)
# against upstream's Merge: random provider hints over 1-8 NUMA nodes go to
# test/conformance/kubernetes/topologymanager_oracle (compiled into
# pkg/kubelet/cm/topologymanager through a go test overlay) and to the port.
#
#   ruby tools/differential/topology_manager_differential.rb [--seed N] [--cases N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/node/topology_manager"

module TopologyManagerDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/topologymanager_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  TM = Rubernetes::Node::TopologyManager

  module_function

  def cases(random, count)
    Array.new(count) do |index|
      nodes = Array.new([1, 2, 2, 4, 4, 8].sample(random: random)) { |i| i }
      distances = nodes.to_h { |a| [a, nodes.map { |b| a == b ? 10 : [11, 12, 20, 21, 32].sample(random: random) }] }
      options = {}
      options["prefer-closest-numa-nodes"] = %w[true false].sample(random: random) if random.rand < 0.4
      options["max-allowable-numa-nodes"] = %w[8 9 4 x].sample(random: random) if random.rand < 0.05
      providers = Array.new(random.rand(0..3)) do
        next nil if random.rand < 0.1

        Array.new(random.rand(1..2)) { |r| "resource-#{r}" }.to_h do |resource|
          hints = if random.rand < 0.1
                    nil
                  else
                    Array.new(random.rand(0..4)) do
                      affinity = random.rand < 0.1 ? nil : nodes.select { random.rand < 0.4 }.then { |bits| bits.empty? ? [nodes.sample(random: random)] : bits }
                      {"affinity" => affinity, "preferred" => random.rand < 0.5}
                    end
                  end
          [resource, hints]
        end
      end
      {"name" => "merge/#{index}", "nodes" => nodes, "distances" => distances,
       "policy" => %w[best-effort restricted single-numa-node none].sample(random: random), "options" => options, "providers" => providers}
    end
  end

  def run_port(test_case)
    options = TM::Options.parse(test_case["options"])
    info = TM::NUMAInfo.new(test_case["nodes"], test_case["distances"].transform_keys(&:to_i))
    policy = case test_case["policy"]
             when "best-effort" then TM::BestEffortPolicy.new(info, options)
             when "restricted" then TM::RestrictedPolicy.new(info, options)
             when "single-numa-node" then TM::SingleNumaNodePolicy.new(info, options)
             else TM::NonePolicy.new
             end
    providers = test_case["providers"].map do |provider|
      provider&.transform_values do |hints|
        hints&.map { |hint| TM::Hint.new(hint["affinity"] && TM::BitMask.of(*hint["affinity"]), hint["preferred"]) }
      end
    end
    hint, admit = policy.merge(providers)
    {"name" => test_case["name"], "affinity" => hint.affinity&.bits, "any" => hint.affinity.nil?, "preferred" => hint.preferred, "admit" => admit}
  rescue TM::Error => error
    {"name" => test_case["name"], "error" => error.message}
  end

  def run_oracle(cases)
    Dir.mktmpdir("topologymanager-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      target = File.join(File.realpath(SOURCE), "pkg/kubelet/cm/topologymanager/zz_rubernetes_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      stdout, status = Open3.capture2e({"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output}, "go", "test", "-overlay", overlay,
                                       "./pkg/kubelet/cm/topologymanager", "-run", "TestRubernetesTopologyOracle", "-count=1", chdir: SOURCE)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_923
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 2000
    list = cases(Random.new(seed), count)
    mismatches = list.zip(run_oracle(list)).filter_map do |test_case, want|
      got = run_port(test_case)
      want = want.compact
      got = got.compact
      want.delete("affinity") if want["any"]
      want = want.slice("name", "error") if want["error"]
      [test_case, want, got] unless got == want
    end
    mismatches.first(4).each do |test_case, want, got|
      puts "MISMATCH #{test_case.to_json[0, 600]}"
      puts "  upstream: #{want}"
      puts "  port:     #{got}"
    end
    puts "#{list.length - mismatches.length}/#{list.length} match"
    mismatches.empty? ? 0 : 1
  end
end

exit(TopologyManagerDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
