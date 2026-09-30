#!/usr/bin/env ruby
# frozen_string_literal: true

# The kubelet memory manager port (lib/rubernetes/node/memory_manager.rb)
# against the pinned upstream package: generated NUMA machines, reservations
# and allocate/remove/hint scripts go to
# test/conformance/kubernetes/memorymanager_oracle (compiled into
# pkg/kubelet/cm/memorymanager through a go test overlay) and to the port;
# machine states, assignments, hints, errors and checkpoint files are
# compared.  Blocks are compared sorted by type: upstream orders them by Go
# map iteration.
#
#   ruby tools/differential/memory_manager_differential.rb [--show] [--seed N] [--cases N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/node/memory_manager"

module MemoryManagerDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/memorymanager_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  MM = Rubernetes::Node::MemoryManager
  TM = Rubernetes::Node::TopologyManager
  GI = 1024**3
  MI = 1024**2

  module_function

  # Every NUMA node lists the same page sizes (sysfs does, even with zero
  # pages); upstream dereferences a missing size's table and panics.
  def machine(random, nodes)
    sizes = []
    sizes << 2048 if random.rand < 0.5
    sizes << 1_048_576 if random.rand < 0.3
    Array.new(nodes) do |id|
      hugepages = sizes.map { |size| {"page_size" => size, "num_pages" => size == 2048 ? random.rand(0..512) : random.rand(0..2)} }
      {"id" => id, "memory" => random.rand(4..16) * GI, "hugepages" => hugepages}
    end
  end

  def policy_cases(random, count)
    cases = []
    [1, 2, 4].each do |nodes|
      count.times do |index|
        machine = machine(random, nodes)
        reservations = machine.select { random.rand < 0.8 }.map do |node|
          limits = {"memory" => "#{random.rand(1..4) * 256}Mi"}
          limits["hugepages-2Mi"] = "#{random.rand(0..2) * 2}Mi" if node["hugepages"].any? do |page|
            page["page_size"] == 2048
          end && random.rand < 0.4
          {"numa_node" => node["id"], "limits" => limits}
        end
        reservations = [{"numa_node" => 0, "limits" => {"memory" => "512Mi"}}] if reservations.empty?
        totals = Hash.new(0)
        reservations.each { |entry| entry["limits"].each { |name, value| totals[name] += Rubernetes::ResourceHelpers::Quantity.from_json(value).value.to_i } }
        allocatable = totals.transform_values { |bytes| "#{bytes / MI}Mi" }
        allocatable["memory"] = "#{(totals["memory"] / MI) + 256}Mi" if random.rand < 0.08
        steps = []
        pods = []
        random.rand(3..9).times do |step|
          action = pods.empty? ? "allocate" : %w[allocate allocate remove hints podHints].sample(random: random)
          uid = "pod-#{index}-#{step}"
          case action
          when "allocate", "hints", "podHints"
            containers = Array.new(random.rand(1..3)) do |i|
              memory = "#{[256, 512, 1024, 2048, 4096, 8192, 12_288].sample(random: random)}Mi"
              requests = {"memory" => memory, "cpu" => "1"}
              requests["hugepages-2Mi"] = "#{random.rand(1..8) * 2}Mi" if machine.first["hugepages"].any? do |page|
                page["page_size"] == 2048
              end && random.rand < 0.3
              guaranteed = random.rand < 0.85
              {"name" => "c#{i}", "requests" => requests, "limits" => guaranteed ? requests.dup : {"memory" => memory},
               "init" => i.zero? && random.rand < 0.3, "sidecar" => false}
            end
            if action == "allocate"
              affinity = random.rand < 0.4 ? Array.new(random.rand(1..nodes)) { |k| k }.uniq : nil
              pods << [uid, containers]
              steps << {"action" => "allocate", "podUID" => uid, "containers" => containers, "affinity" => affinity,
                        "preferred" => random.rand < 0.5}
            else
              steps << {"action" => action, "podUID" => uid, "containers" => containers, "container" => containers.last["name"]}
            end
          when "remove"
            pod_uid, containers = pods.sample(random: random)
            steps << {"action" => "remove", "podUID" => pod_uid, "containers" => containers,
                      "container" => containers.sample(random: random)["name"]}
          end
        end
        cases << {"name" => "numa-#{nodes}/policy/#{index}", "op" => "policy", "machine" => machine, "reservedMemory" => reservations,
                  "nodeAllocatable" => allocatable, "steps" => steps}
      end
    end
    cases
  end

  # PodLevelResourceManagers: pod-level Pods (spec.resources) allocated as
  # one bubble (allocatePod), mixed with exclusive and shared containers,
  # sidecars and init containers, then removed container by container.
  def pod_level_cases(random, count)
    [1, 2].flat_map do |nodes|
      Array.new(count) do |index|
        machine = machine(random, nodes)
        reservations = machine.map { |node| {"numa_node" => node["id"], "limits" => {"memory" => "512Mi"}} }
        allocatable = {"memory" => "#{512 * nodes}Mi"}
        hugepages = machine.first["hugepages"].any? { |page| page["page_size"] == 2048 && page["num_pages"] >= 16 }
        steps = []
        pods = []
        random.rand(3..8).times do |step|
          action = pods.empty? ? "allocatePod" : %w[allocatePod allocatePod remove podHints hints].sample(random: random)
          if action == "remove"
            uid, containers = pods.sample(random: random)
            steps << {"action" => "remove", "podUID" => uid, "containers" => containers,
                      "container" => containers.sample(random: random)["name"]}
            next
          end
          uid = "pl-#{index}-#{step}"
          pod_memory = [2048, 3072, 4096, 6144].sample(random: random)
          pod_requests = {"cpu" => "4", "memory" => "#{pod_memory}Mi"}
          pod_requests["hugepages-2Mi"] = "#{random.rand(2..8) * 2}Mi" if hugepages && random.rand < 0.3
          containers = Array.new(random.rand(1..3)) do |i|
            memory = [nil, "512Mi", "1Gi", "#{pod_memory}Mi"].sample(random: random)
            requests = memory ? {"memory" => memory, "cpu" => "1"} : {}
            guaranteed = memory && random.rand < 0.7
            init = i.zero? && random.rand < 0.35
            {"name" => "c#{i}", "requests" => requests, "limits" => guaranteed ? requests.dup : {},
             "init" => init, "sidecar" => init && random.rand < 0.5}
          end
          entry = {"action" => action, "podUID" => uid, "containers" => containers, "container" => containers.last["name"],
                   "podRequests" => pod_requests, "podLimits" => pod_requests.dup}
          if action == "allocatePod" && random.rand < 0.4
            entry["affinity"] = Array.new(random.rand(1..nodes)) { |k| k }.uniq
            entry["preferred"] = random.rand < 0.5
          end
          pods << [uid, containers] if action == "allocatePod"
          steps << entry
        end
        {"name" => "numa-#{nodes}/pod-level/#{index}", "op" => "policy", "machine" => machine, "reservedMemory" => reservations,
         "nodeAllocatable" => allocatable, "steps" => steps, "podLevel" => true}
      end
    end
  end

  def checkpoint_cases
    table = lambda { |total, reserved, free|
      {"total" => total, "systemReserved" => 0, "allocatable" => total, "reserved" => reserved, "free" => free}
    }
    [
      {"name" => "checkpoint/empty", "op" => "checkpoint", "policyName" => "Static", "machineState" => {}, "entries" => {}},
      {"name" => "checkpoint/state", "op" => "checkpoint", "policyName" => "Static",
       "machineState" => {"0" => {"numberOfAssignments" => 2, "memoryMap" => {"memory" => table.call(4 * GI, GI, 3 * GI),
                                                                              "hugepages-2Mi" => table.call(64 * MI, 0, 64 * MI)},
                                  "cells" => [0, 1]},
                          "1" => {"numberOfAssignments" => 1, "memoryMap" => {"memory" => table.call(4 * GI, 0, 4 * GI)},
                                  "cells" => [0, 1]}},
       "entries" => {"pod-b" => {"app" => [{"numaAffinity" => [0, 1], "type" => "memory", "size" => GI}]},
                     "pod-a" => {"x" => [{"numaAffinity" => [0], "type" => "hugepages-2Mi", "size" => 4 * MI},
                                         {"numaAffinity" => [0], "type" => "memory", "size" => 512 * MI}]}}},
      {"name" => "checkpoint/pod-level-empty", "op" => "checkpoint", "policyName" => "Static", "podLevel" => true,
       "machineState" => {"0" => {"numberOfAssignments" => 0, "memoryMap" => {"memory" => table.call(4 * GI, 0, 4 * GI)}, "cells" => [0]}},
       "entries" => {}, "podEntries" => {}},
      {"name" => "checkpoint/pod-level", "op" => "checkpoint", "policyName" => "Static", "podLevel" => true,
       "machineState" => {"0" => {"numberOfAssignments" => 2, "memoryMap" => {"memory" => table.call(4 * GI, 2 * GI, 2 * GI)}, "cells" => [0]}},
       "entries" => {"pod-a" => {"app" => [{"numaAffinity" => [0], "type" => "memory", "size" => GI}],
                                 "side" => [{"numaAffinity" => [0], "type" => "memory", "size" => GI}]}},
       "podEntries" => {"pod-z" => {"memoryBlocks" => [{"numaAffinity" => [0], "type" => "memory", "size" => 2 * GI}]},
                        "pod-a" => {"memoryBlocks" => [{"numaAffinity" => [0], "type" => "hugepages-2Mi", "size" => 4 * MI},
                                                       {"numaAffinity" => [0], "type" => "memory", "size" => 2 * GI}]}}}
    ]
  end

  class FixedAffinity
    Policy = Struct.new(:name)

    def initialize = @affinity = {}
    def policy = Policy.new("none")
    def set(uid, name, bits, preferred) = @affinity["#{uid}/#{name}"] = TM::Hint.new(TM::BitMask.of(*bits), preferred)
    def affinity(uid, name) = @affinity["#{uid}/#{name}"] || TM::Hint.new(nil, false)
  end

  def pod(uid, containers, requests: nil, limits: nil)
    spec = {"containers" => [], "initContainers" => []}
    spec["resources"] = {"requests" => requests || {}, "limits" => limits || {}} if requests || limits
    containers.each do |c|
      entry = {"name" => c["name"], "resources" => {"requests" => c["requests"], "limits" => c["limits"]}}
      entry["restartPolicy"] = "Always" if c["sidecar"]
      (c["init"] ? spec["initContainers"] : spec["containers"]) << entry
    end
    {"metadata" => {"name" => "p-#{uid}", "namespace" => "ns", "uid" => uid}, "spec" => spec}
  end

  def render_machine(machine) = machine.to_h { |id, node| [id.to_s, node.to_h] }

  def render_assignments(assignments)
    assignments.transform_values do |containers|
      containers.transform_values { |blocks| blocks.sort_by(&:type).map(&:to_h) }
    end
  end

  def render_hints(hints)
    hints.transform_values do |list|
      list.map do |hint|
        {"affinity" => hint.affinity ? hint.affinity.bits : [], "preferred" => hint.preferred}
      end
    end
  end

  def run_policy(test_case)
    store = FixedAffinity.new
    machine = test_case["machine"].map do |node|
      {id: node["id"], memory: node["memory"], hugepages: node["hugepages"].map do |page|
        {page_size: page["page_size"], num_pages: page["num_pages"]}
      end}
    end
    reservations = test_case["reservedMemory"].map { |entry| {numa_node: entry["numa_node"], limits: entry["limits"]} }
    result = {"name" => test_case["name"]}
    begin
      manager = MM::Manager.new(policy: MM::POLICY_STATIC, machine: machine, reserved_memory: reservations,
                                node_allocatable_reservation: test_case["nodeAllocatable"], affinity: store,
                                pod_level: test_case["podLevel"] == true)
      manager.start
    rescue MM::Error => error
      return result.merge("error" => error.message)
    end
    policy = manager.policy
    state = manager.state
    result["allocatable"] = policy.allocatable_memory(state).map(&:to_h)
    result["steps"] = test_case["steps"].map do |step|
      out = {}
      pod = pod(step["podUID"], step["containers"], requests: step["podRequests"], limits: step["podLimits"])
      containers = Array(pod.dig("spec", "initContainers")) + pod.dig("spec", "containers")
      case step["action"]
      when "allocate"
        containers.each { |c| store.set(step["podUID"], c["name"], step["affinity"], step["preferred"]) } if step["affinity"]
        begin
          containers.each { |container| policy.allocate(state, pod, container) }
        rescue MM::Error => error
          out["error"] = error.message
        end
      when "allocatePod"
        containers.each { |c| store.set(step["podUID"], c["name"], step["affinity"], step["preferred"]) } if step["affinity"]
        begin
          policy.allocate_pod(state, pod)
        rescue MM::Error, Rubernetes::Node::TopologyManager::AdmissionError => error
          out["error"] = error.message
        end
      when "remove"
        policy.remove_container(state, step["podUID"], step["container"])
      when "hints", "podHints"
        hints = if step["action"] == "podHints"
                  policy.pod_topology_hints(state, pod)
                else
                  policy.topology_hints(state, pod, containers.find { |c| c["name"] == step["container"] })
                end
        hints.nil? ? out["hintsNil"] = true : out["hints"] = render_hints(hints)
      end
      out["machine"] = render_machine(state.machine_state)
      out["assignments"] = render_assignments(state.assignments)
      if test_case["podLevel"] && !state.pod_memory_assignments.empty?
        out["podBlocks"] = state.pod_memory_assignments.transform_values { |blocks| blocks.sort_by(&:type).map(&:to_h) }
      end
      out
    end
    result
  end

  def run_checkpoint(test_case)
    machine = test_case["machineState"].to_h { |id, node| [Integer(id), MM::NodeState.from_h(node)] }
    entries = test_case["entries"].to_h do |pod, containers|
      [pod, containers.to_h { |name, blocks| [name, blocks.map { |block| MM::Block.from_h(block) }] }]
    end
    pod_blocks = if test_case["podLevel"]
                   (test_case["podEntries"] || {}).to_h do |pod, entry|
                     [pod, Array(entry["memoryBlocks"]).map { |block| MM::Block.from_h(block) }]
                   end
                 end
    {"name" => test_case["name"], "checkpoint" => MM::CheckpointState.encode(test_case["policyName"], machine, entries, pod_blocks: pod_blocks)}
  end

  def run_port(test_case) = test_case["op"] == "policy" ? run_policy(test_case) : run_checkpoint(test_case)

  def run_oracle(cases)
    Dir.mktmpdir("memorymanager-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      target = File.join(File.realpath(SOURCE), "pkg/kubelet/cm/memorymanager/zz_rubernetes_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      env = {"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output}
      stdout, status = Open3.capture2e(env, "go", "test", "-overlay", overlay, "./pkg/kubelet/cm/memorymanager",
                                       "-run", "TestRubernetesMemoryOracle", "-count=1", chdir: SOURCE)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  # Go's omitempty and nil-map shapes, normalised on both sides.
  def normalise(result)
    result = result.dup
    result.delete("forHash")
    result.delete("allocatable") if result["allocatable"].nil? || result["allocatable"].empty?
    result["steps"] = result["steps"]&.map do |step|
      step = step.compact
      step.delete("hints") if step["hints"] == {}
      step["assignments"] = step["assignments"].to_h { |pod, containers| [pod, containers.transform_values { |blocks| blocks || [] }] }
      step["machine"] = (step["machine"] || {}).transform_values do |node|
        node.merge("memoryMap" => (node["memoryMap"] || {}).sort.to_h, "cells" => node["cells"] || [])
      end
      step
    end
    result.compact
  end

  def compare(cases, show: false)
    expected = run_oracle(cases)
    mismatches = []
    cases.zip(expected).each do |test_case, want|
      got = run_port(test_case)
      next if normalise(got) == normalise(want)

      mismatches << [test_case, normalise(want), normalise(got)]
    end
    mismatches.first(show ? mismatches.length : 4).each do |test_case, want, got|
      puts "MISMATCH #{test_case["name"]} #{test_case.slice("machine", "reservedMemory", "nodeAllocatable").to_json[0, 400]}"
      if want["steps"] && got["steps"]
        index = want["steps"].zip(got["steps"]).index { |a, b| a != b }
        if index
          puts "  step #{index}: #{test_case["steps"][index].to_json[0, 400]}"
          puts "  upstream: #{want["steps"][index].to_json[0, 900]}"
          puts "  port:     #{got["steps"][index].to_json[0, 900]}"
          next
        end
      end
      puts "  upstream: #{want.to_json[0, 900]}"
      puts "  port:     #{got.to_json[0, 900]}"
    end
    puts "#{cases.length - mismatches.length}/#{cases.length} match"
    mismatches.empty?
  end

  def main(argv)
    show = argv.include?("--show")
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_923
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 40
    random = Random.new(seed)
    compare(policy_cases(random, count) + pod_level_cases(random, [count / 4, 4].max) + checkpoint_cases, show: show) ? 0 : 1
  end
end

exit(MemoryManagerDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
