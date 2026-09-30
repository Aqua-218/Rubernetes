#!/usr/bin/env ruby
# frozen_string_literal: true

# Scheduler sizing of Pods with pod-level resources (PodLevelResources), overhead,
# sidecars and BestEffort Pods: the production scheduler and the pinned upstream
# v1.36.2 scheduler framework (test/conformance/kubernetes/m3_scheduler_oracle,
# default feature gates) filter and score the same fixtures and the observables
# are compared.  Needs KUBERNETES_SOURCE_ROOT (the pinned checkout) and Go.

require "json"
require "open3"
require "rubernetes/scheduler"

PROBE = File.expand_path("../milestones/m3_scheduler_probe.rb", __dir__)
eval(File.read(PROBE).split("\nM3ProbeSupport.run_report", 2).first, TOPLEVEL_BINDING, PROBE, 1)

module SchedulerPodLevelDifferential
  module_function

  def pod(name, containers:, resources: nil, init: nil, overhead: nil, node: nil)
    spec = {"priority" => 10, "containers" => containers.each_with_index.map do |value, index|
      {"name" => "c#{index}", "image" => "example/app"}.merge(value)
    end}
    if init
      spec["initContainers"] = init.each_with_index.map do |value, index|
        {"name" => "i#{index}", "image" => "example/init"}.merge(value)
      end
    end
    spec["resources"] = resources if resources
    spec["overhead"] = overhead if overhead
    spec["nodeName"] = node if node
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "default", "uid" => "#{name}-uid"},
     "spec" => spec}
  end

  def res(requests: nil, limits: nil)
    value = {}
    value["requests"] = requests if requests
    value["limits"] = limits if limits
    {"resources" => value}
  end

  def cases
    storage = scheduler_storage
    nodes = [scheduler_node("node-a", "zone-a"), scheduler_node("node-b", "zone-b")]
    base = {"nodes" => nodes, "existing_pods" => [], "persistent_volumes" => storage.fetch("persistent_volumes"),
            "persistent_volume_claims" => storage.fetch("persistent_volume_claims"), "storage_classes" => storage.fetch("storage_classes", []),
            "binding_node" => "node-a"}
    busy = [pod("busy", containers: [res(requests: {"cpu" => "100m"})], resources: {"requests" => {"cpu" => "3", "memory" => "4Gi"}},
                        node: "node-a")]
    besteffort = [pod("be1", containers: [{}], node: "node-a"), pod("be2", containers: [{}], node: "node-a")]
    tainted = [
      nodes[0].merge("spec" => {"taints" => [{"key" => "a", "effect" => "PreferNoSchedule"}]}),
      nodes[1].merge("spec" => {"taints" => [{"key" => "a", "effect" => "PreferNoSchedule"},
                                             {"key" => "b", "effect" => "PreferNoSchedule"}]})
    ]
    hosts = nodes.map do |node|
      node.merge("metadata" => node["metadata"].merge("labels" => node["metadata"]["labels"].merge("kubernetes.io/hostname" => node["metadata"]["name"])))
    end
    labeled = lambda do |name, node, labels, affinity = nil|
      value = pod(name, containers: [{}], node: node)
      value["metadata"]["labels"] = labels
      value["spec"]["affinity"] = affinity if affinity
      value
    end
    preferred_to_web = {"podAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [
      {"weight" => 7,
       "podAffinityTerm" => {"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "topology.kubernetes.io/zone"}}
    ]}}
    required_to_web = {"podAffinity" => {"requiredDuringSchedulingIgnoredDuringExecution" => [
      {"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "topology.kubernetes.io/zone"}
    ]}}
    web = lambda do |name, extra = {}|
      value = pod(name, containers: [res(requests: {"cpu" => "100m"})])
      value["metadata"]["labels"] = {"app" => "web"}
      value["spec"].merge!(extra)
      value
    end
    spread = lambda do |key, skew, when_unsatisfiable = "ScheduleAnyway"|
      {"maxSkew" => skew, "topologyKey" => key, "whenUnsatisfiable" => when_unsatisfiable,
       "labelSelector" => {"matchLabels" => {"app" => "web"}}}
    end
    {
      "taint-normalize" => base.merge("phase" => "score", "nodes" => tainted,
                                      "pod" => pod("tn", containers: [res(requests: {"cpu" => "100m"})])),
      "ipa-existing-preferred" => base.merge("phase" => "score", "existing_pods" => [labeled.call("peer", "node-a", {"x" => "y"}, preferred_to_web)],
                                             "pod" => web.call("ipe")),
      "ipa-existing-required" => base.merge("phase" => "score", "existing_pods" => [labeled.call("peer", "node-b", {"x" => "y"}, required_to_web)],
                                            "pod" => web.call("ipr")),
      "ipa-own-anti" => base.merge("phase" => "score", "existing_pods" => [labeled.call("w1", "node-a", {"app" => "web"})],
                                   "pod" => web.call("ipa", "affinity" => {"podAntiAffinity" => {"preferredDuringSchedulingIgnoredDuringExecution" => [
                                                       {"weight" => 5, "podAffinityTerm" => {"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "topology.kubernetes.io/zone"}}
                                                     ]}})),
      "pts-soft-zone" => base.merge("phase" => "score", "existing_pods" => [labeled.call("w1", "node-a", {"app" => "web"}), labeled.call("w2", "node-a", {"app" => "web"})],
                                    "pod" => web.call("pts", "topologySpreadConstraints" => [spread.call("topology.kubernetes.io/zone", 1)])),
      "pts-hostname-mixed" => base.merge("phase" => "score", "nodes" => hosts,
                                         "existing_pods" => [labeled.call("w1", "node-b", {"app" => "web"})],
                                         "pod" => web.call("ptm", "topologySpreadConstraints" => [spread.call("kubernetes.io/hostname", 2),
                                                                                                  spread.call("topology.kubernetes.io/zone",
                                                                                                              3, "DoNotSchedule")])),
      "pod-level-filter" => base.merge("phase" => "filter",
                                       "pod" => pod("plf", containers: [res(requests: {"cpu" => "100m"})],
                                                           resources: {"requests" => {"cpu" => "5"}})),
      "pod-level-fits" => base.merge("phase" => "filter",
                                     "pod" => pod("plo", containers: [res(requests: {"cpu" => "5"})],
                                                         resources: {"requests" => {"cpu" => "5"}, "limits" => {"cpu" => "6"}})),
      "pod-level-existing" => base.merge("phase" => "filter", "existing_pods" => busy,
                                         "pod" => pod("ple", containers: [res(requests: {"cpu" => "2"})])),
      "pod-level-score" => base.merge("phase" => "score", "existing_pods" => busy,
                                      "pod" => pod("pls", containers: [res(requests: {"cpu" => "100m"})], resources: {"requests" => {"cpu" => "1", "memory" => "1Gi"}})),
      "besteffort-score" => base.merge("phase" => "score", "existing_pods" => besteffort, "pod" => pod("bes", containers: [{}])),
      # The oracle's score phase scores every node without filtering, so a
      # score case keeps every node feasible.
      "sidecar-overhead-score" => base.merge("phase" => "score", "existing_pods" => besteffort,
                                             "pod" => pod("sos", containers: [res(requests: {"cpu" => "500m", "memory" => "1Gi"})],
                                                                 init: [res(requests: {"cpu" => "1"}).merge("restartPolicy" => "Always"), res(requests: {"cpu" => "2"})],
                                                                 overhead: {"cpu" => "250m", "memory" => "128Mi"}))
    }
  end

  def oracle(fixtures)
    root = ENV.fetch("KUBERNETES_SOURCE_ROOT")
    input = JSON.generate({"kubernetes_version" => "v1.36.2", "source_commit" => M3ProbeSupport::KUBERNETES_SOURCE_COMMIT,
                           "cases" => fixtures})
    main = File.expand_path("../../test/conformance/kubernetes/m3_scheduler_oracle/main.go", __dir__)
    stdout, stderr, status = Open3.capture3({"GOWORK" => "off"}, "go", "run", "-mod=mod", main, stdin_data: input, chdir: root)
    raise "oracle failed: #{stderr}" unless status.success?

    JSON.parse(stdout).fetch("comparisons")
  end

  def run
    fixtures = cases
    local = fixtures.to_h do |id, fixture|
      result = production_schedule(Rubernetes::Scheduler.new, fixture)
      [id, local_observable(result, fixture)]
    end
    expected = oracle(fixtures)
    failures = 0
    fixtures.each_key do |id|
      want = expected.dig(id, "normalized_observable")
      next if want == local[id]

      failures += 1
      puts "MISMATCH #{id}\n  oracle: #{JSON.generate(want)}\n  local:  #{JSON.generate(local[id])}"
    end
    puts "#{fixtures.length - failures}/#{fixtures.length} cases match"
    exit(failures.zero? ? 0 : 1)
  end
end

SchedulerPodLevelDifferential.run if $PROGRAM_NAME == __FILE__
