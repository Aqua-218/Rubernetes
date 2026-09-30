#!/usr/bin/env ruby
# frozen_string_literal: true

# The kubelet CPU manager port (lib/rubernetes/node/cpu_manager) against the
# pinned upstream package: generated topologies and availability go to
# test/conformance/kubernetes/cpumanager_oracle (compiled into
# pkg/kubelet/cm/cpumanager through a go test overlay, so the source tree
# stays clean) and to the port, and the CPU sets, errors, discovered
# topologies, static-policy traces and checkpoints are compared.
#
#   ruby tools/differential/cpu_manager_differential.rb [--show] [--seed N] [--cases N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/node/cpu_manager"

module CPUManagerDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/cpumanager_oracle/oracle_test.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  M = Rubernetes::Node::CPUManager

  module_function

  # A synthetic machine: +sockets+ packages; either +numa_per_socket+ NUMA
  # nodes in each (numa-first) or +sockets_per_numa+ packages per node
  # (sockets-first); +cores+ physical cores per NUMA node (or per socket in
  # the sockets-first shape), +threads+ per core, +uncore+ caches per NUMA
  # node.  :sibling_offset numbers the second thread of core c as c+ncores
  # (Linux x86 style); :adjacent numbers threads consecutively.
  def topology(sockets:, cores:, threads:, numa_per_socket: 1, sockets_per_numa: 1, uncore: 1, numbering: :sibling_offset)
    numas = sockets_per_numa > 1 ? sockets / sockets_per_numa : sockets * numa_per_socket
    physical = sockets_per_numa > 1 ? sockets * cores : numas * cores
    details = {}
    core_index = 0
    placements = []
    if sockets_per_numa > 1
      sockets.times do |socket|
        cores.times do |c|
          numa = socket / sockets_per_numa
          uncore_id = (numa * uncore) + (c * uncore / cores)
          placements << [numa, socket, uncore_id, core_index]
          core_index += 1
        end
      end
    else
      numas.times do |numa|
        socket = numa / numa_per_socket
        cores.times do |c|
          uncore_id = (numa * uncore) + (c * uncore / cores)
          placements << [numa, socket, uncore_id, core_index]
          core_index += 1
        end
      end
    end
    placements.each do |numa, socket, uncore_id, index|
      thread_ids = Array.new(threads) do |t|
        numbering == :adjacent ? (index * threads) + t : index + (t * physical)
      end
      thread_ids.each do |cpu|
        details[cpu] = [numa, socket, thread_ids.min, uncore_id]
      end
    end
    uncore_ids = details.values.map(&:last).uniq.length
    {"numCPUs" => details.length, "numCores" => physical, "numSockets" => sockets, "numNUMANodes" => numas,
     "numUncoreCache" => uncore_ids, "details" => details.transform_keys(&:to_s)}
  end

  TOPOLOGIES = {
    "single-socket-ht" => {sockets: 1, cores: 4, threads: 2},
    "dual-socket-ht" => {sockets: 2, cores: 3, threads: 2},
    "dual-socket-no-ht" => {sockets: 2, cores: 4, threads: 1},
    "dual-socket-multi-numa-ht" => {sockets: 2, cores: 10, threads: 2, numa_per_socket: 2},
    "quad-socket-4way-ht" => {sockets: 4, cores: 4, threads: 4},
    "sub-numa-sockets-first" => {sockets: 4, cores: 6, threads: 2, sockets_per_numa: 2},
    "uncore-single-socket" => {sockets: 1, cores: 16, threads: 2, uncore: 4},
    "uncore-dual-socket-no-ht" => {sockets: 2, cores: 8, threads: 1, uncore: 2},
    "uncore-multi-numa" => {sockets: 2, cores: 8, threads: 2, numa_per_socket: 2, uncore: 2},
    "eight-numa-no-ht" => {sockets: 2, cores: 4, threads: 1, numa_per_socket: 4},
    "adjacent-dual-socket-ht" => {sockets: 2, cores: 4, threads: 2, numbering: :adjacent},
    "adjacent-quad-numa" => {sockets: 1, cores: 3, threads: 2, numa_per_socket: 4, numbering: :adjacent}
  }.freeze

  def to_topology(value)
    details = value["details"].to_h do |cpu, (numa, socket, core, uncore)|
      [Integer(cpu), M::Topology::CPUInfo.new(numa_node_id: numa, socket_id: socket, core_id: core, uncore_cache_id: uncore)]
    end
    M::Topology::CPUTopology.new(num_cpus: value["numCPUs"], num_cores: value["numCores"], num_sockets: value["numSockets"],
                                 num_numa_nodes: value["numNUMANodes"], num_uncore_cache: value["numUncoreCache"],
                                 cpu_details: M::Topology::CPUDetails.new(details))
  end

  def assignment_cases(random, count)
    cases = []
    TOPOLOGIES.each do |name, shape|
      topo = topology(**shape)
      all = topo["details"].keys.map { |cpu| Integer(cpu) }.sort
      count.times do |index|
        available = random.rand < 0.3 ? all : all.select { random.rand < 0.75 }
        available = all if available.empty?
        requested = random.rand(0..[available.length + 1, 1].max)
        strategy = random.rand < 0.25 ? "spread" : "packed"
        base = {"topology" => topo, "available" => M::CPUSet.new(available).to_s, "count" => requested, "strategy" => strategy}
        cases << base.merge("name" => "#{name}/packed/#{index}", "op" => "packed", "uncore" => random.rand < 0.4 && strategy == "packed")
        group = [1, topo["numCPUs"] / topo["numCores"]].sample(random: random)
        cases << base.merge("name" => "#{name}/distributed/#{index}", "op" => "distributed", "groupSize" => group,
                            "count" => (requested / group) * group)
      end
    end
    cases
  end

  def container(name, cpu: nil, memory: "1Gi", guaranteed: true, init: false, sidecar: false)
    requests = {"memory" => memory}
    requests["cpu"] = cpu if cpu
    limits = guaranteed ? requests.dup : {}
    {"name" => name, "requests" => requests, "limits" => limits, "init" => init, "sidecar" => sidecar}
  end

  # Static-policy scripts: reserve, then allocate/remove/hint sequences.
  def policy_cases(random, count)
    cases = []
    %w[dual-socket-ht dual-socket-multi-numa-ht quad-socket-4way-ht uncore-single-socket sub-numa-sockets-first
       adjacent-quad-numa dual-socket-no-ht].each do |name|
      topo = topology(**TOPOLOGIES.fetch(name))
      total = topo["numCPUs"]
      count.times do |index|
        options = {}
        options["full-pcpus-only"] = "true" if random.rand < 0.3
        options["strict-cpu-reservation"] = "true" if random.rand < 0.2
        if random.rand < 0.2
          options["distribute-cpus-across-numa"] = "true"
        elsif random.rand < 0.2
          options["prefer-align-cpus-by-uncorecache"] = "true"
        end
        reserved = random.rand(1..3)
        explicit = if random.rand < 0.3
                     M::CPUSet.new(topo["details"].keys.map do |cpu|
                       Integer(cpu)
                     end.sample(reserved, random: random)).to_s
                   else
                     ""
                   end
        steps = []
        pods = []
        random.rand(3..8).times do |step|
          action = pods.empty? ? "allocate" : %w[allocate allocate remove hints].sample(random: random)
          case action
          when "allocate", "hints"
            uid = "pod-#{index}-#{step}"
            containers = Array.new(random.rand(1..3)) do |i|
              cpu = [nil, "500m", "1", "2", "3", "4", (total / 4).to_s, "1500m"].sample(random: random)
              container("c#{i}", cpu: cpu, guaranteed: random.rand < 0.85, init: i.zero? && random.rand < 0.3,
                                 sidecar: false)
            end
            affinity = random.rand < 0.4 ? [random.rand(topo["numNUMANodes"])] : nil
            if action == "allocate"
              pods << [uid, containers]
              steps << {"action" => "allocate", "podUID" => uid, "containers" => containers, "affinity" => affinity}
            else
              steps << {"action" => "hints", "podUID" => uid, "containers" => containers, "container" => containers.last["name"]}
            end
          when "remove"
            uid, containers = pods.sample(random: random)
            steps << {"action" => "remove", "podUID" => uid, "container" => containers.sample(random: random)["name"]}
          end
        end
        cases << {"name" => "#{name}/policy/#{index}", "op" => "policy", "topology" => topo, "numReserved" => reserved,
                  "reserved" => explicit, "options" => options, "steps" => steps}
      end
    end
    cases
  end

  # PodLevelResourceManagers scripts: Guaranteed Pods with pod-level
  # resources whose containers are, or are not, Guaranteed on their own.
  def pod_level_cases(random, count)
    %w[dual-socket-ht dual-socket-multi-numa-ht dual-socket-no-ht].flat_map do |name|
      topo = topology(**TOPOLOGIES.fetch(name))
      Array.new(count) do |index|
        steps = []
        pods = []
        random.rand(3..7).times do |step|
          action = pods.empty? ? "allocatePod" : %w[allocatePod allocatePod remove podHints allocate].sample(random: random)
          if action == "remove"
            uid, containers = pods.sample(random: random)
            steps << {"action" => "remove", "podUID" => uid, "container" => containers.sample(random: random)["name"]}
            next
          end
          uid = "pl-#{index}-#{step}"
          pod_cpu = [2, 3, 4, 6].sample(random: random)
          containers = Array.new(random.rand(1..3)) do |i|
            cpu = [nil, "1", "2", "500m"].sample(random: random)
            container("c#{i}", cpu: cpu, guaranteed: random.rand < 0.7, init: i.zero? && random.rand < 0.3,
                               sidecar: i.zero? && random.rand < 0.2)
          end
          entry = {"action" => action, "podUID" => uid, "containers" => containers,
                   "podRequests" => {"cpu" => pod_cpu.to_s, "memory" => "4Gi"}, "podLimits" => {"cpu" => pod_cpu.to_s, "memory" => "4Gi"}}
          entry["affinity"] = [random.rand(topo["numNUMANodes"])] if random.rand < 0.3
          pods << [uid, containers] if action.start_with?("allocate")
          steps << entry
        end
        {"name" => "#{name}/pod-level/#{index}", "op" => "policy", "topology" => topo, "numReserved" => random.rand(1..2),
         "reserved" => "", "options" => {}, "steps" => steps, "podLevel" => true}
      end
    end
  end

  def checkpoint_cases
    [
      {"name" => "checkpoint/pod-level", "op" => "checkpoint", "policyName" => "static", "defaultCpuSet" => "0,5-7",
       "entries" => {"pod-a" => {"x" => "1-2"}}, "podLevel" => true, "podEntries" => {"pod-a" => "1-4"}},
      {"name" => "checkpoint/pod-level-empty", "op" => "checkpoint", "policyName" => "static", "defaultCpuSet" => "0-7",
       "entries" => {}, "podLevel" => true, "podEntries" => {}},
      {"name" => "checkpoint/empty", "op" => "checkpoint", "policyName" => "static", "defaultCpuSet" => "0-7", "entries" => {}},
      {"name" => "checkpoint/none", "op" => "checkpoint", "policyName" => "none", "defaultCpuSet" => "", "entries" => {}},
      {"name" => "checkpoint/entries", "op" => "checkpoint", "policyName" => "static", "defaultCpuSet" => "0,3-5,9",
       "entries" => {"pod-b" => {"app" => "1-2", "side" => "6"}, "pod-a" => {"x" => "7-8,10"}}}
    ]
  end

  def oracle_pod(uid, containers, requests: nil, limits: nil)
    spec = {"containers" => [], "initContainers" => []}
    spec["resources"] = {"requests" => requests || {}, "limits" => limits || {}} if requests || limits
    containers.each do |c|
      entry = {"name" => c["name"], "resources" => {"requests" => c["requests"], "limits" => c["limits"]}}
      entry["restartPolicy"] = "Always" if c["sidecar"]
      (c["init"] ? spec["initContainers"] : spec["containers"]) << entry
    end
    {"metadata" => {"name" => "p-#{uid}", "namespace" => "ns", "uid" => uid}, "spec" => spec}
  end

  # A topology-manager Store with fixed affinities (the oracle's fakeStore).
  class FixedAffinity
    Policy = Struct.new(:name)

    def initialize = @affinity = {}
    def policy = Policy.new("none")

    def set(uid, name, bits)
      @affinity["#{uid}/#{name}"] = Rubernetes::Node::TopologyManager::Hint.new(Rubernetes::Node::TopologyManager::BitMask.of(*bits), true)
    end

    def affinity(uid, name) = @affinity["#{uid}/#{name}"] || Rubernetes::Node::TopologyManager::Hint.new(nil, false)
  end

  def run_policy(test_case)
    topo = to_topology(test_case["topology"])
    store = FixedAffinity.new
    reserved = M::CPUSet.parse(test_case["reserved"].to_s)
    begin
      policy = M::StaticPolicy.new(topology: topo, num_reserved: test_case["numReserved"], reserved_cpus: reserved, affinity: store,
                                   options: test_case["options"], pod_level: test_case["podLevel"] == true)
      state = M::MemoryState.new
      policy.start(state)
    rescue M::Error => error
      return {"name" => test_case["name"], "error" => error.message}
    end
    steps = test_case["steps"].map do |step|
      result = {}
      case step["action"]
      when "allocatePod"
        pod = oracle_pod(step["podUID"], step["containers"], requests: step["podRequests"], limits: step["podLimits"])
        step["containers"].each { |c| store.set(step["podUID"], c["name"], step["affinity"]) } if step["affinity"]
        begin
          policy.allocate_pod(state, pod)
        rescue StandardError => error
          result["error"] = error.message
        end
      when "podHints"
        pod = oracle_pod(step["podUID"], step["containers"], requests: step["podRequests"], limits: step["podLimits"])
        hints = policy.pod_topology_hints(state, pod)
        if hints.nil?
          result["hintsNil"] = true
        else
          result["hints"] = hints["cpu"].map do |hint|
            {"affinity" => hint.affinity ? hint.affinity.bits : [], "preferred" => hint.preferred}
          end
        end
      when "allocate"
        pod = oracle_pod(step["podUID"], step["containers"], requests: step["podRequests"], limits: step["podLimits"])
        step["containers"].each { |c| store.set(step["podUID"], c["name"], step["affinity"]) } if step["affinity"]
        begin
          M::PodResources.containers(pod).each { |container| policy.allocate(state, pod, container) }
        rescue StandardError => error
          result["error"] = error.message
        end
      when "remove"
        policy.remove_container(state, step["podUID"], step["container"])
      when "hints"
        pod = oracle_pod(step["podUID"], step["containers"])
        container = M::PodResources.containers(pod).find { |entry| entry["name"] == step["container"] }
        hints = policy.topology_hints(state, pod, container)
        if hints.nil?
          result["hintsNil"] = true
        else
          result["hints"] = hints["cpu"].map do |hint|
            {"affinity" => hint.affinity ? hint.affinity.bits : [], "preferred" => hint.preferred}
          end
        end
      end
      result["assignments"] = state.assignments.transform_values { |containers| containers.transform_values(&:to_s) }
      result["default"] = state.default_cpu_set.to_s
      result["podSets"] = state.pod_cpu_sets.transform_values(&:to_s) if test_case["podLevel"] && !state.pod_cpu_sets.empty?
      result
    end
    {"name" => test_case["name"], "reserved" => policy.reserved_cpus.to_s, "steps" => steps}
  end

  def run_checkpoint(test_case)
    entries = test_case["entries"].to_h { |pod, containers| [pod, containers.transform_values { |cpus| M::CPUSet.parse(cpus) }] }
    pods = test_case["podLevel"] ? (test_case["podEntries"] || {}).transform_values { |cpus| M::CPUSet.parse(cpus) } : nil
    {"name" => test_case["name"],
     "checkpoint" => M::CheckpointState.encode(test_case["policyName"], M::CPUSet.parse(test_case["defaultCpuSet"]), entries,
                                               pod_cpu_sets: pods)}
  end

  def run_port(test_case)
    return run_policy(test_case) if test_case["op"] == "policy"
    return run_checkpoint(test_case) if test_case["op"] == "checkpoint"

    case test_case["op"]
    when "packed", "distributed"
      topo = to_topology(test_case["topology"])
      available = M::CPUSet.parse(test_case["available"])
      cpus = if test_case["op"] == "packed"
               M::Assignment.take_by_topology_numa_packed(topo, available, test_case["count"], strategy: test_case["strategy"],
                                                                                               prefer_align_by_uncore_cache: test_case["uncore"])
             else
               M::Assignment.take_by_topology_numa_distributed(topo, available, test_case["count"], test_case["groupSize"],
                                                               strategy: test_case["strategy"])
             end
      {"name" => test_case["name"], "cpus" => cpus.to_s}
    else
      raise ArgumentError, "unknown op #{test_case["op"]}"
    end
  rescue M::Assignment::Error => error
    {"name" => test_case["name"], "error" => error.message}
  end

  def run_oracle(cases)
    Dir.mktmpdir("cpumanager-oracle") do |dir|
      input = File.join(dir, "in.json")
      output = File.join(dir, "out.json")
      overlay = File.join(dir, "overlay.json")
      File.write(input, JSON.generate("cases" => cases))
      # go resolves the working directory through symlinks; the overlay key must match.
      target = File.join(File.realpath(SOURCE), "pkg/kubelet/cm/cpumanager/zz_rubernetes_oracle_test.go")
      File.write(overlay, JSON.generate("Replace" => {target => ORACLE}))
      env = {"RUBERNETES_ORACLE_IN" => input, "RUBERNETES_ORACLE_OUT" => output}
      stdout, status = Open3.capture2e(env, "go", "test", "-overlay", overlay, "./pkg/kubelet/cm/cpumanager",
                                       "-run", "TestRubernetesOracle", "-count=1", chdir: SOURCE)
      raise "oracle failed:\n#{stdout}" unless status.success?

      JSON.parse(File.read(output)).fetch("results")
    end
  end

  def compare(cases, show: false)
    expected = run_oracle(cases)
    mismatches = []
    hangs = 0
    cases.zip(expected).each do |test_case, want|
      got = run_port(test_case)
      # Upstream never returns here (the distributed remainder loop spins
      # forever on a NUMA node whose free CPUs are not a multiple of the
      # group size); the port skips that subset and must still answer.
      if want["hang"]
        hangs += 1
        mismatches << [test_case, want, got] unless got.key?("cpus") || got.key?("error")
        next
      end
      want = want.slice("name", "cpus", "error") if %w[packed distributed].include?(test_case["op"])
      want = want.slice("name", "checkpoint", "error") if test_case["op"] == "checkpoint"
      if test_case["op"] == "policy"
        # Go omits empty strings / false; compare on the port's shape.
        want = {"name" => want["name"], "error" => want["error"], "reserved" => want["reserved"],
                "steps" => want["steps"]&.map do |step|
                  step.slice("error", "assignments", "default", "hints", "hintsNil", "podSets").compact
                end}.compact
        # omitempty drops an empty hint list, as it does upstream.
        got = got.merge("steps" => got["steps"]&.map { |step| step.compact.reject { |key, value| key == "hints" && value.empty? } }).compact
      end
      next if got == want

      mismatches << [test_case, want, got]
    end
    mismatches.first(show ? mismatches.length : 5).each do |test_case, want, got|
      puts "MISMATCH #{test_case["name"]} #{test_case.except("topology", "steps").to_json[0, 300]}"
      puts "  upstream: #{want.inspect}"
      puts "  port:     #{got.inspect}"
    end
    puts "#{cases.length - mismatches.length}/#{cases.length} match (#{hangs} where upstream hangs)"
    mismatches.empty?
  end

  def main(argv)
    show = argv.include?("--show")
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_923
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 40
    random = Random.new(seed)
    cases = []
    cases.concat(assignment_cases(random, count)) unless argv.include?("--policy-only")
    cases.concat(policy_cases(random, [count / 2, 5].max))
    cases.concat(checkpoint_cases)
    cases.concat(pod_level_cases(random, [count / 4, 4].max))
    compare(cases, show: show) ? 0 : 1
  end
end

exit(CPUManagerDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
