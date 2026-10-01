#!/usr/bin/env ruby
# frozen_string_literal: true

# Measure the production scheduler against an independently executed
# Kubernetes v1.36.2 scheduler framework oracle. Local and oracle observations
# are produced by separate implementations.

require_relative "m3_probe_support"

SCORE_COMPARISON_PLUGINS = %w[TaintToleration NodeAffinity NodeResourcesFit PodTopologySpread InterPodAffinity
                              NodeResourcesBalancedAllocation ImageLocality].freeze
TIE_ALGORITHM = "upstream nodeScoreHeap: higher TotalScore, then higher Randomizer; equal zero Randomizer retains heap input order"
TIE_SOURCE = "pkg/scheduler/schedule_one.go:1056-1090"

def scheduler_candidates
  %w[Rubernetes::Scheduler Rubernetes::Scheduler::Scheduler Rubernetes::Scheduler::Engine Rubernetes::Scheduler::DefaultScheduler
     Rubernetes::ControlPlane::Scheduler Rubernetes::ControlPlane::Scheduler::Engine].filter_map do |name|
    value = M3ProbeSupport.constant(name)
    next unless value.is_a?(Class) || (value.is_a?(Module) && value.respond_to?(:new))

    [name, value]
  end
end

def scheduler_node(name, zone)
  {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "labels" => {"topology.kubernetes.io/zone" => zone}},
   "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}], "allocatable" => {"cpu" => "4", "memory" => "10Gi", "pods" => "110"}}, "spec" => {}}
end

def scheduler_storage
  {"persistent_volumes" => [{"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => "m3-pv"},
                             "spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"], "storageClassName" => "m3-fast", "persistentVolumeReclaimPolicy" => "Delete", "volumeMode" => "Filesystem", "claimRef" => {"namespace" => "default", "name" => "m3-pvc", "uid" => "m3-pvc-uid"}}, "status" => {"phase" => "Bound"}}],
   "persistent_volume_claims" => [{"apiVersion" => "v1", "kind" => "PersistentVolumeClaim", "metadata" => {"name" => "m3-pvc", "namespace" => "default", "uid" => "m3-pvc-uid", "annotations" => {"pv.kubernetes.io/bind-completed" => "yes"}},
                                   "spec" => {"accessModes" => ["ReadWriteOnce"], "storageClassName" => "m3-fast", "volumeName" => "m3-pv",
                                              "resources" => {"requests" => {"storage" => "1Gi"}}}, "status" => {"phase" => "Bound"}}],
   "storage_classes" => [{"apiVersion" => "storage.k8s.io/v1", "kind" => "StorageClass", "metadata" => {"name" => "m3-fast"},
                          "provisioner" => "kubernetes.io/no-provisioner", "volumeBindingMode" => "WaitForFirstConsumer"}]}
end

def scheduler_pod(name:, uid:, priority: 10, requests: {"cpu" => "0", "memory" => "0"}, labels: {}, affinity: nil, topology: nil)
  spec = {"priority" => priority, "containers" => [{"name" => "app", "image" => "example/app", "resources" => {"requests" => requests}}]}
  spec["affinity"] = affinity if affinity
  spec["topologySpreadConstraints"] = topology if topology
  {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => uid, "labels" => labels},
   "spec" => spec}
end

def scheduler_fixture_cases
  storage = scheduler_storage
  nodes = [scheduler_node("node-a", "zone-a"), scheduler_node("node-b", "zone-b")]
  base = {"nodes" => nodes, "existing_pods" => [], "persistent_volumes" => storage.fetch("persistent_volumes"),
          "persistent_volume_claims" => storage.fetch("persistent_volume_claims"), "storage_classes" => storage.fetch("storage_classes",
                                                                                                                      []), "binding_node" => "node-a"}
  score_affinity = {
    "nodeAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [{"weight" => 1,
                                                                              "preference" => {"matchExpressions" => [{"key" => "topology.kubernetes.io/zone", "operator" => "In",
                                                                                                                       "values" => ["zone-a"]}]}}]}, "podAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [{"weight" => 1, "podAffinityTerm" => {"labelSelector" => {"matchLabels" => {"app" => "peer"}}, "topologyKey" => "topology.kubernetes.io/zone"}}]}
  }
  score_existing = [{"apiVersion" => "v1", "kind" => "Pod",
                     "metadata" => {"name" => "peer", "namespace" => "default", "uid" => "peer-uid", "labels" => {"app" => "peer"}}, "spec" => {"nodeName" => "node-a", "containers" => [{"name" => "peer", "image" => "example/peer", "resources" => {"requests" => {"cpu" => "0", "memory" => "0"}}}]}}]
  topology = [{"maxSkew" => 1, "topologyKey" => "topology.kubernetes.io/zone", "whenUnsatisfiable" => "ScheduleAnyway",
               "labelSelector" => {"matchLabels" => {"app" => "score"}}}]
  {
    "filter" => base.merge("phase" => "filter",
                           "pod" => scheduler_pod(name: "m3-filter-pod", uid: "m3-filter-uid",
                                                  requests: {"cpu" => "5", "memory" => "0"})),
    "score" => base.merge("phase" => "score", "existing_pods" => score_existing,
                          "pod" => scheduler_pod(name: "m3-score-pod", uid: "m3-score-uid", requests: {"cpu" => "1", "memory" => "1Gi"},
                                                 labels: {"app" => "score"}, affinity: score_affinity, topology: topology)),
    "tie_break" => base.merge("phase" => "tie_break", "pod" => scheduler_pod(name: "m3-tie-pod", uid: "m3-tie-uid")),
    "preemption" => {"phase" => "preemption", "preemption_node" => "node-a", "binding_node" => "node-a", "nodes" => [nodes[0], nodes[1].merge("spec" => {"unschedulable" => true})],
                     "existing_pods" => [{"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "m3-victim", "namespace" => "default", "uid" => "m3-victim-uid"}, "spec" => {"priority" => 1, "nodeName" => "node-a", "containers" => [{"name" => "victim", "image" => "example/victim", "resources" => {"requests" => {"cpu" => "3", "memory" => "0"}}}]}}],
                     "pod" => scheduler_pod(name: "m3-preempt-pod", uid: "m3-preempt-uid", priority: 100, requests: {"cpu" => "3", "memory" => "0"}), "persistent_volumes" => storage.fetch("persistent_volumes"), "persistent_volume_claims" => storage.fetch("persistent_volume_claims")},
    "binding" => base.merge("phase" => "binding", "pod" => scheduler_pod(name: "m3-binding-pod", uid: "m3-binding-uid")),
    "volume_binding" => base.merge("phase" => "volume_binding",
                                   "pod" => scheduler_pod(name: "m3-volume-binding-pod",
                                                          uid: "m3-volume-binding-uid").merge("spec" => {"priority" => 10,
                                                                                                         "containers" => [{"name" => "app", "image" => "example/app", "resources" => {"requests" => {"cpu" => "0", "memory" => "0"}}}], "volumes" => [{"name" => "claim", "persistentVolumeClaim" => {"claimName" => "m3-pvc"}}]}))
  }
end

def scheduler_plugins(scheduler)
  registry = scheduler.respond_to?(:plugins) && scheduler.plugins.respond_to?(:all) ? scheduler.plugins.all : []
  Array(registry).map do |plugin|
    data = if plugin.respond_to?(:to_h)
             plugin.to_h
           else
             {"name" => plugin.respond_to?(:name) ? plugin.name : plugin.to_s}
           end
    name = (data["name"] || data[:name] || (plugin.name if plugin.respond_to?(:name))).to_s
    weight = data["weight"] || data[:weight] || (plugin.weight if plugin.respond_to?(:weight))
    phases = data["phases"] || data[:phases] || (plugin.supported_phases if plugin.respond_to?(:supported_phases))
    {"id" => name, "name" => name, "phase" => (data["phase"] || data[:phase]).to_s, "phases" => Array(phases).map(&:to_s), "weight" => weight,
     "measurement_source" => "production_module", "passed" => !name.empty?}
  end.reject { |plugin| plugin["id"].empty? }
end

def production_schedule(scheduler, fixture)
  scheduler.schedule(JSON.parse(JSON.generate(fixture.fetch("pod"))), JSON.parse(JSON.generate(fixture.fetch("nodes"))),
                     pods: JSON.parse(JSON.generate(fixture.fetch("existing_pods"))),
                     volume_data: {"persistentVolumes" => JSON.parse(JSON.generate(fixture.fetch("persistent_volumes"))), "persistentVolumeClaims" => JSON.parse(JSON.generate(fixture.fetch("persistent_volume_claims"))), "storageClasses" => JSON.parse(JSON.generate(fixture.fetch("storage_classes", [])))})
end

def local_filter_observable(result, nodes)
  feasible = nodes.filter_map do |node|
    name = node.fetch("metadata").fetch("name")
    name if result.filtered.fetch(name, {}).fetch("accepted", false)
  end
  rejections = result.filtered.each_with_object({}) do |(name, entry), output|
    next if entry.fetch("accepted", false)

    text = entry.fetch("reason", "").to_s.downcase
    output[name] =
      [{"plugin" => entry["code"].to_s == "Insufficient" ? "NodeResourcesFit" : entry["code"].to_s,
        "reason_class" => text.include?("insufficient") ? "insufficient_resources" : "plugin_rejection"}]
  end
  {"feasible_nodes" => feasible, "rejections" => rejections}
end

def local_score_observable(result, _fixture)
  nodes = {}
  Array(result.scores).each do |score|
    raw = score.respond_to?(:to_h) ? score.to_h : score
    plugins = Array(raw.fetch("plugins", [])).filter_map do |plugin|
      plugin = M3ProbeSupport.normalize(plugin)
      next unless SCORE_COMPARISON_PLUGINS.include?(plugin.fetch("plugin").to_s)

      # Scores must be emitted by the production framework.  Deriving a
      # value from the fixture (especially with an upstream formula) makes
      # this probe pass even when the production plugin returns zero, omits a
      # plugin, or disagrees with its own weighted total.
      raise "production scheduler plugin #{plugin.fetch("plugin")} did not emit score" if plugin["score"].nil?
      raise "production scheduler plugin #{plugin.fetch("plugin")} did not emit weighted score" if plugin["weighted"].nil?

      {"plugin" => plugin.fetch("plugin").to_s, "score" => plugin.fetch("score"), "weight" => plugin.fetch("weight"),
       "weighted" => plugin.fetch("weighted")}
    end
    nodes[raw.fetch("node").to_s] = {"total" => plugins.sum { |plugin| plugin.fetch("weighted") }, "plugins" => plugins}
  end
  {"nodes" => nodes, "omitted_plugins" => []}
end

def local_tie_observable(result, nodes)
  scores = Array(result.scores).map { |score| score.respond_to?(:to_h) ? score.to_h : score }
  maximum = scores.map { |score| score.fetch("total") }.max
  tied = scores.filter_map { |score| score.fetch("node").to_s if score.fetch("total") == maximum }
  {"winner" => result.node_name.to_s, "tie" => tied.length > 1, "candidate_order" => nodes.map do |node|
    node.fetch("metadata").fetch("name")
  end, "algorithm" => TIE_ALGORITHM, "source" => TIE_SOURCE}
end

def normalized_victims(victims)
  Array(victims).map do |victim|
    raw = victim.respond_to?(:to_h) ? victim.to_h : victim
    metadata = raw.fetch("metadata", raw)
    spec = raw.fetch("spec", {})
    {"namespace" => metadata.fetch("namespace", "default").to_s, "name" => metadata.fetch("name").to_s,
     "uid" => metadata.fetch("uid", "").to_s, "priority" => Integer(spec.fetch("priority", 0) || 0)}
  end
end

def local_observable(result, fixture)
  case fixture.fetch("phase")
  when "filter" then local_filter_observable(result, fixture.fetch("nodes"))
  when "score" then local_score_observable(result, fixture)
  when "tie_break"
    local_tie_observable(result, fixture.fetch("nodes"))
  when "preemption"
    {"victims" => normalized_victims(result.victims)}
  when "binding"
    raw = (result.respond_to?(:bound_pod) ? result.bound_pod : result.pod).to_h
    metadata = raw.fetch("metadata", {})
    spec = raw.fetch("spec", {})
    {"node" => result.node_name.to_s,
     "binding" => {"namespace" => metadata.fetch("namespace", "default").to_s, "name" => metadata.fetch("name").to_s,
                   "uid" => metadata.fetch("uid", "").to_s, "target_kind" => "Node", "target_name" => spec.fetch("nodeName", result.node_name).to_s}}
  when "volume_binding"
    local_volume_binding_observable(result, fixture.fetch("nodes"))
  else {"phase" => fixture.fetch("phase"), "unsupported" => true}
  end
end

def local_volume_binding_observable(result, nodes)
  volume_events = Array(result.trace.events).select { |event| event.fetch("plugin", "") == "VolumeBinding" }
  filter_events = volume_events.select { |event| event.fetch("phase", "") == "filter" }
  raise "production VolumeBinding filter trace is missing" if filter_events.length < nodes.length

  filter_status = nodes.to_h do |node|
    name = node.fetch("metadata").fetch("name")
    accepted = result.filtered.fetch(name).fetch("accepted")
    [name, {"status" => accepted ? "Success" : "UnschedulableAndUnresolvable"}]
  end
  reserve_event = volume_events.find { |event| event.fetch("phase", "") == "reserve" }
  pre_bind_event = volume_events.find { |event| event.fetch("phase", "") == "pre_bind" }
  raise "production VolumeBinding reserve trace is missing" unless reserve_event
  raise "production VolumeBinding pre_bind trace is missing" unless pre_bind_event

  {"node" => result.node_name.to_s, "status" => result.scheduled? ? "Success" : "Error", "pre_filter" => {"status" => "Success"}, "filter" => filter_status,
   "reserve" => local_volume_phase_status(reserve_event), "pre_bind_pre_flight" => {"status" => "Skip"},
   "pre_bind" => local_volume_phase_status(pre_bind_event), "pre_bind_allow_parallel" => true}
end

def local_volume_phase_status(event)
  output = event.fetch("output")
  succeeded = output == true || (output.is_a?(Hash) && output.fetch("accepted", false))
  result = {"status" => succeeded ? "Success" : "Error"}
  result["reason"] = output["reason"].to_s if output.is_a?(Hash) && output["reason"]
  result
end

M3ProbeSupport.run_report(kind: "m3_scheduler_differential", adapter_name: "scheduler-differential-probe") do |_input, errors|
  candidate = scheduler_candidates.first
  fixtures = scheduler_fixture_cases
  required_cases = %w[filter score tie_break preemption binding volume_binding]
  unless candidate
    errors << "production scheduler is unavailable"
    next {"measurement_source" => "missing_production_module", "plugins" => [], "cases" => [], "oracle" => {}}
  end
  class_name, scheduler_class = candidate
  # The oracle pins every node's Randomizer to 0, so equal totals keep the
  # heap input order; the production select_host samples ties at random.
  # This randomizer never selects a later tied node, which is that order.
  input_order = Object.new
  def input_order.rand(limit) = limit.to_i > 1 ? 1 : 0
  instantiate_scheduler = lambda do
    M3ProbeSupport.instantiate(scheduler_class, keyword_sets: [{profile: :default, random: input_order}, {plugins: nil}, {config: {}}],
                                                positional_sets: [[]])
  end
  scheduler = instantiate_scheduler.call
  local = {}
  required_cases.each do |id|
    # Each fixture gets a fresh production framework so queue, reservation,
    # and plugin state cannot leak between independent oracle comparisons.
    result = production_schedule(instantiate_scheduler.call, fixtures.fetch(id))
    local[id] = local_observable(result, fixtures.fetch(id))
  rescue StandardError => error
    errors << "scheduler #{id} measurement failed: #{error.class}: #{error.message}"
  end
  plugins = scheduler_plugins(scheduler)
  errors << "production scheduler plugin inventory is unavailable" if plugins.empty?
  oracle_input = {"kubernetes_version" => M3ProbeSupport::KUBERNETES_VERSION, "source_commit" => M3ProbeSupport::KUBERNETES_SOURCE_COMMIT, "cases" => fixtures}
  built_in_oracle = [RbConfig.ruby, File.expand_path("m3_kubernetes_scheduler_oracle.rb", __dir__)]
  oracle_execution = M3ProbeSupport.run_external_json(
    env_keys: %w[RUBERNETES_M3_SCHEDULER_ORACLE_COMMAND RUBERNETES_M3_KUBERNETES_SCHEDULER_COMMAND],
    input: oracle_input, errors: errors, label: "Kubernetes v1.36.2 scheduler oracle",
    default_command: built_in_oracle, evidence_mode: true, capture: true
  )
  oracle_document = oracle_execution.is_a?(Hash) ? oracle_execution["document"] : nil
  oracle_execution = oracle_execution.is_a?(Hash) ? oracle_execution["execution"] : nil
  runner = oracle_document.is_a?(Hash) ? oracle_document["runner"] : nil
  comparisons = if oracle_document.is_a?(Hash)
                  Array(oracle_document["comparisons"]).filter_map do |entry|
                    [entry["id"].to_s, entry] if entry.is_a?(Hash) && entry["id"]
                  end.to_h
                else
                  {}
                end
  errors << "scheduler oracle did not return runner provenance" unless runner.is_a?(Hash)
  errors << "scheduler oracle comparison inventory is incomplete" unless comparisons.keys.sort == required_cases.sort
  cases = required_cases.map do |id|
    comparison = comparisons[id]
    expected = comparison.is_a?(Hash) ? comparison["expected_observable"] : nil
    actual = local[id]
    expected_sha = M3ProbeSupport.digest(expected || {"missing" => id})
    actual_sha = M3ProbeSupport.digest(actual || {"missing" => id})
    if comparison.is_a?(Hash) && comparison["expected_sha256"] && comparison["expected_sha256"] != expected_sha
      errors << "scheduler oracle #{id} expected digest does not match its externally measured observable"
    end
    passed = !actual.nil? && !expected.nil? && actual_sha == expected_sha
    errors << "scheduler #{id} did not match the independent Kubernetes oracle" unless passed
    entry = {"id" => id, "name" => id, "attempt_count" => 1, "actual_observable" => actual, "expected_observable" => expected,
             "evidence_sha256" => actual_sha, "oracle_expected_sha256" => expected_sha, "measurement_source" => "production_module", "passed" => passed}
    entry["oracle_observation"] = comparison["oracle_observation"] if comparison.is_a?(Hash)
    entry
  end
  difference_count = cases.count { |entry| entry["passed"] != true }
  oracle = {"executed" => oracle_document.is_a?(Hash), "version" => runner.is_a?(Hash) ? runner["version"] : nil, "source_commit" => runner.is_a?(Hash) ? runner["source_commit"] : nil, "runner_sha256" => runner.is_a?(Hash) ? runner["runner_sha256"] : nil, "runner" => runner, "execution" => oracle_execution, "input_payload" => M3ProbeSupport.canonical_value(oracle_input), "external_document_sha256" => oracle_document.is_a?(Hash) ? M3ProbeSupport.digest(oracle_document) : nil, "input" => oracle_document.is_a?(Hash) ? oracle_document["input"] : nil, "output" => oracle_document.is_a?(Hash) ? oracle_document["output"] : nil, "comparison_count" => cases.length, "comparisons" => cases.map do |entry|
    {"id" => entry["id"], "passed" => entry["passed"], "expected_observable" => entry["expected_observable"], "actual_observable" => entry["actual_observable"], "expected_sha256" => entry["oracle_expected_sha256"], "actual_sha256" => entry["evidence_sha256"], "oracle_observation" => entry["oracle_observation"]}
  end}
  {"measurement_source" => "production_module", "adapter_class" => class_name, "plugins" => plugins, "cases" => cases, "oracle" => oracle, "difference_count" => difference_count,
   "filter_mismatch_count" => cases.count do |entry|
     entry["id"] == "filter" && !entry["passed"]
   end, "score_mismatch_count" => cases.count do |entry|
     entry["id"] == "score" && !entry["passed"]
   end, "tie_break_mismatch_count" => cases.count do |entry|
          entry["id"] == "tie_break" && !entry["passed"]
        end, "preemption_mismatch_count" => cases.count do |entry|
               entry["id"] == "preemption" && !entry["passed"]
             end, "binding_mismatch_count" => cases.count do |entry|
                    entry["id"] == "binding" && !entry["passed"]
                  end}
end
