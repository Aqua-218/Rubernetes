#!/usr/bin/env ruby
# frozen_string_literal: true

# The DRA structured allocator (lib/rubernetes/dra/allocator.rb) against the
# pinned upstream one: every case goes to
# test/conformance/kubernetes/dra_allocator_oracle (k8s.io/dynamic-resource-
# allocation/structured v1.36.2, default features) and to the port, and the
# allocation results or errors are compared.  Share IDs are renumbered
# ("share-<n>" in order of appearance) on both sides.  CEL compile errors are
# compared up to "CEL compile error: " (cel-go's diagnostics are not ported).
#
#   ruby tools/differential/dra_allocator_differential.rb [--show]

require "json"
require "open3"
require_relative "../../lib/rubernetes"
require_relative "../../lib/rubernetes/dra"

module DRAAllocatorDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/kubernetes/dra_allocator_oracle/main.go")
  SOURCE = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")
  DRIVER = "gpu.example.com"

  module_function

  def node(name = "node-1", labels = {"zone" => "a"}) = {"metadata" => {"name" => name, "labels" => labels}}

  def klass(name, selectors: [], config: nil)
    spec = {}
    spec["selectors"] = selectors.map { |expression| {"cel" => {"expression" => expression}} } unless selectors.empty?
    spec["config"] = config if config
    {"metadata" => {"name" => name}, "spec" => spec}
  end

  def device(name, attributes: {}, capacity: {}, **extra)
    value = {"name" => name}
    value["attributes"] = attributes unless attributes.empty?
    value["capacity"] = capacity.to_h { |key, entry| [key.to_s, entry.is_a?(Hash) ? entry : {"value" => entry}] } unless capacity.empty?
    value.merge(extra.transform_keys(&:to_s))
  end

  def slice(name, devices, driver: DRIVER, pool: "node-1", node_name: "node-1", generation: 1, count: 1, **extra)
    spec = {"driver" => driver, "pool" => {"name" => pool, "generation" => generation, "resourceSliceCount" => count},
            "devices" => devices}
    spec["nodeName"] = node_name if node_name
    {"metadata" => {"name" => name}, "spec" => spec.merge(extra.transform_keys(&:to_s))}
  end

  def exactly(klass_name, count: 1, mode: "ExactCount", selectors: [], **extra)
    value = {"deviceClassName" => klass_name, "allocationMode" => mode}
    value["count"] = count if mode == "ExactCount"
    value["selectors"] = selectors.map { |expression| {"cel" => {"expression" => expression}} } unless selectors.empty?
    value.merge(extra.transform_keys(&:to_s))
  end

  def claim(name, requests, constraints: nil, config: nil, allocation: nil)
    devices = {"requests" => requests}
    devices["constraints"] = constraints if constraints
    devices["config"] = config if config
    value = {"metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}"}, "spec" => {"devices" => devices}}
    value["status"] = {"allocation" => allocation} if allocation
    value
  end

  def request(name, **exact) = {"name" => name, "exactly" => exactly(exact.delete(:klass) || "gpu", **exact)}

  def gpus(count, **attributes)
    (0...count).map { |index| device("gpu-#{index}", attributes: {"index" => {"int" => index}}.merge(attributes)) }
  end

  GPU = klass("gpu", selectors: ["device.driver == \"#{DRIVER}\""])

  def cases
    list = []
    add = lambda { |name, **fields|
      list << {"name" => name, "node" => node, "classes" => [GPU], "slices" => [], "claims" => [],
               "allocatedClaims" => []}.merge(fields.transform_keys(&:to_s))
    }

    add.call("count-2", slices: [slice("s1", gpus(3))], claims: [claim("c", [request("r", count: 2)])])
    add.call("not-enough", slices: [slice("s1", gpus(1))], claims: [claim("c", [request("r", count: 2)])])
    add.call("other-node", slices: [slice("s1", gpus(2), node_name: "node-2", pool: "node-2")], claims: [claim("c", [request("r")])])
    add.call("missing-class", slices: [slice("s1", gpus(1))], claims: [claim("c", [request("r", klass: "nope")])])
    add.call("all-mode", slices: [slice("s1", gpus(3))], claims: [claim("c", [request("r", mode: "All")])])
    add.call("all-mode-none", slices: [slice("s1", [device("x")], driver: "other.example.com")],
                              claims: [claim("c", [request("r", mode: "All")])])
    add.call("request-selector", slices: [slice("s1", gpus(4))],
                                 claims: [claim("c", [request("r", count: 2, selectors: ["device.attributes[\"#{DRIVER}\"].index >= 2"])])])
    add.call("selector-runtime-error", slices: [slice("s1", gpus(2))],
                                       claims: [claim("c", [request("r", selectors: ["device.attributes[\"#{DRIVER}\"].missing == 1"])])])
    add.call("selector-non-bool", slices: [slice("s1", gpus(2))],
                                  claims: [claim("c", [request("r", selectors: ["device.attributes[\"#{DRIVER}\"].index"])])])
    add.call("selector-compile-error", slices: [slice("s1", gpus(2))], claims: [claim("c", [request("r", selectors: ["device.driver"])])])
    add.call("unknown-domain", slices: [slice("s1", gpus(2))],
                               claims: [claim("c", [request("r", selectors: ["device.attributes[\"other.example.com\"].index == 1"])])])
    add.call("string-and-version", slices: [slice("s1", [device("a", attributes: {"model" => {"string" => "a100"}, "driverVersion" => {"version" => "1.2.3"}}),
                                                         device("b",
                                                                attributes: {"model" => {"string" => "h100"},
                                                                             "driverVersion" => {"version" => "2.0.0-rc.1"}})])],
                                   claims: [claim("c", [request("r", selectors: ["device.attributes[\"#{DRIVER}\"].driverVersion.isGreaterThan(semver(\"1.5.0\"))"])])])
    add.call("capacity-selector", slices: [slice("s1", [device("a", capacity: {"memory" => "16Gi"}), device("b", capacity: {"memory" => "80Gi"})])],
                                  claims: [claim("c", [request("r", selectors: ["device.capacity[\"#{DRIVER}\"].memory.compareTo(quantity(\"40Gi\")) >= 0"])])])
    add.call("cel-bind", slices: [slice("s1", gpus(3))],
                         claims: [claim("c", [request("r", selectors: ["cel.bind(i, device.attributes[\"#{DRIVER}\"].index, i == 1 || i == 2)"], count: 2)])])
    add.call("class-selector", classes: [GPU, klass("big", selectors: ["device.attributes[\"#{DRIVER}\"].index > 0"])],
                               slices: [slice("s1", gpus(2))], claims: [claim("c", [request("r", klass: "big")])])
    add.call("allocated-elsewhere", slices: [slice("s1", gpus(2))], claims: [claim("c", [request("r")])],
                                    allocatedClaims: [claim("old", [request("r")], allocation: {"devices" => {"results" => [
                                                              {"request" => "r", "driver" => DRIVER, "pool" => "node-1", "device" => "gpu-0"}
                                                            ]}})])
    add.call("all-allocated", slices: [slice("s1", gpus(1))], claims: [claim("c", [request("r")])],
                              allocatedClaims: [claim("old", [request("r")], allocation: {"devices" => {"results" => [
                                                        {"request" => "r", "driver" => DRIVER, "pool" => "node-1", "device" => "gpu-0"}
                                                      ]}})])
    add.call("admin-access", slices: [slice("s1", gpus(1))], claims: [claim("c", [request("r", adminAccess: true)])],
                             allocatedClaims: [claim("old", [request("r")], allocation: {"devices" => {"results" => [
                                                       {"request" => "r", "driver" => DRIVER, "pool" => "node-1", "device" => "gpu-0"}
                                                     ]}})])
    add.call("two-claims", slices: [slice("s1", gpus(3))],
                           claims: [claim("a", [request("r", count: 2)]), claim("b", [request("r", count: 1)])])
    add.call("two-claims-too-many", slices: [slice("s1", gpus(2))],
                                    claims: [claim("a", [request("r", count: 2)]), claim("b", [request("r")])])
    add.call("two-requests", slices: [slice("s1", gpus(3))], claims: [claim("c", [request("a"), request("b", count: 2)])])
    add.call("match-attribute", slices: [slice("s1", [device("a", attributes: {"numa" => {"int" => 0}}), device("b", attributes: {"numa" => {"int" => 1}}),
                                                      device("c", attributes: {"numa" => {"int" => 1}})])],
                                claims: [claim("c", [request("r", count: 2)], constraints: [{"matchAttribute" => "#{DRIVER}/numa"}])])
    add.call("match-attribute-requests",
             slices: [slice("s1", [device("a", attributes: {"numa" => {"int" => 0}}), device("b", attributes: {"numa" => {"int" => 1}}),
                                   device("c", attributes: {"numa" => {"int" => 1}})])],
             claims: [claim("c", [request("x"), request("y")],
                            constraints: [{"requests" => %w[x y], "matchAttribute" => "#{DRIVER}/numa"}])])
    add.call("distinct-attribute", slices: [slice("s1", [device("a", attributes: {"numa" => {"int" => 0}}), device("b", attributes: {"numa" => {"int" => 0}}),
                                                         device("c", attributes: {"numa" => {"int" => 1}})])],
                                   claims: [claim("c", [request("x"), request("y")], constraints: [{"distinctAttribute" => "#{DRIVER}/numa"}])])
    add.call("match-attribute-missing", slices: [slice("s1", gpus(2))],
                                        claims: [claim("c", [request("r", count: 2)], constraints: [{"matchAttribute" => "#{DRIVER}/numa"}])])
    add.call("first-available", classes: [GPU, klass("small", selectors: ["device.attributes[\"#{DRIVER}\"].index == 5"])],
                                slices: [slice("s1", gpus(2))],
                                claims: [claim("c", [{"name" => "r", "firstAvailable" => [
                                                 {"name" => "big", "deviceClassName" => "small", "allocationMode" => "ExactCount",
                                                  "count" => 1},
                                                 {"name" => "any", "deviceClassName" => "gpu", "allocationMode" => "ExactCount",
                                                  "count" => 2}
                                               ]}])])
    add.call("first-available-config", classes: [GPU],
                                       slices: [slice("s1", gpus(2))],
                                       claims: [claim("c", [{"name" => "r", "firstAvailable" => [
                                                        {"name" => "one", "deviceClassName" => "gpu", "allocationMode" => "ExactCount",
                                                         "count" => 3},
                                                        {"name" => "two", "deviceClassName" => "gpu", "allocationMode" => "ExactCount",
                                                         "count" => 1}
                                                      ]}], config: [{"requests" => ["r/two"], "opaque" => {"driver" => DRIVER, "parameters" => {"a" => 1}}},
                                                                    {"requests" => ["r/one"],
                                                                     "opaque" => {"driver" => DRIVER, "parameters" => {"a" => 2}}},
                                                                    {"opaque" => {"driver" => DRIVER, "parameters" => {"all" => true}}}])])
    add.call("class-and-claim-config", classes: [klass("gpu", selectors: ["device.driver == \"#{DRIVER}\""],
                                                              config: [{"opaque" => {"driver" => DRIVER, "parameters" => {"from" => "class"}}}])],
                                       slices: [slice("s1", gpus(3))],
                                       claims: [claim("c", [request("a"), request("b")], config: [{"requests" => ["a"], "opaque" => {"driver" => DRIVER, "parameters" => {"from" => "claim"}}}])])
    add.call("incomplete-pool", slices: [slice("s1", gpus(2), count: 2)], claims: [claim("c", [request("r")])])
    add.call("incomplete-pool-all", slices: [slice("s1", gpus(2), count: 2)], claims: [claim("c", [request("r", mode: "All")])])
    add.call("pool-two-slices", slices: [slice("s2", [device("b")], count: 2), slice("s1", [device("a")], count: 2)],
                                claims: [claim("c", [request("r", count: 2)])])
    add.call("stale-generation", slices: [slice("s1", [device("old")], generation: 1), slice("s2", [device("new")], generation: 2)],
                                 claims: [claim("c", [request("r")])])
    add.call("duplicate-device", slices: [slice("s1", [device("a")], count: 2), slice("s2", [device("a")], count: 2)],
                                 claims: [claim("c", [request("r")])])
    add.call("all-nodes", slices: [slice("s1", gpus(1), node_name: nil, pool: "shared", allNodes: true)],
                          claims: [claim("c", [request("r")])])
    add.call("node-selector-slice", slices: [slice("s1", gpus(1), node_name: nil, pool: "zone-a",
                                                                  nodeSelector: {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "zone", "operator" => "In", "values" => ["a"]}]}]})],
                                    claims: [claim("c", [request("r")])])
    add.call("node-selector-no-match", slices: [slice("s1", gpus(1), node_name: nil, pool: "zone-b",
                                                                     nodeSelector: {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "zone", "operator" => "In", "values" => ["b"]}]}]})],
                                       claims: [claim("c", [request("r")])])
    add.call("per-device-node-selection", slices: [slice("s1", [device("a", nodeName: "node-2"), device("b", nodeName: "node-1"), device("c", allNodes: true)],
                                                         node_name: nil, pool: "pd", perDeviceNodeSelection: true)],
                                          claims: [claim("c", [request("r", count: 2)])])
    add.call("taint-no-schedule", slices: [slice("s1", [device("a", taints: [{"key" => "broken", "effect" => "NoSchedule"}]), device("b")])],
                                  claims: [claim("c", [request("r")])])
    add.call("taint-tolerated", slices: [slice("s1", [device("a", taints: [{"key" => "broken", "value" => "yes", "effect" => "NoExecute"}])])],
                                claims: [claim("c", [request("r", tolerations: [{"key" => "broken", "operator" => "Equal", "value" => "yes", "effect" => "NoExecute"}])])])
    add.call("taint-none-effect", slices: [slice("s1", [device("a", taints: [{"key" => "x", "effect" => "None"}])])],
                                  claims: [claim("c", [request("r")])])
    add.call("binding-conditions-last",
             slices: [slice("s1", [device("bound", bindingConditions: ["ready"], bindingFailureConditions: ["failed"])], pool: "a-pool"),
                      slice("s2", [device("plain")], pool: "b-pool")],
             claims: [claim("c", [request("r")])])
    add.call("binds-to-node", slices: [slice("s1", [device("a", bindsToNode: true, bindingConditions: ["ready"], bindingFailureConditions: ["failed"])],
                                             node_name: nil, pool: "shared", allNodes: true)],
                              claims: [claim("c", [request("r")])])
    counters = [{"name" => "gpu-0-counters", "counters" => {"memory" => {"value" => "40Gi"}}}]
    partition = lambda { |name, memory|
      device(name, consumesCounters: [{"counterSet" => "gpu-0-counters", "counters" => {"memory" => {"value" => memory}}}])
    }
    add.call("partitionable", slices: [slice("counters", [], count: 2, sharedCounters: counters).tap do |entry|
      entry["spec"].delete("devices")
    end,
                                       slice("devices",
                                             [partition.call("half-a", "20Gi"), partition.call("half-b", "20Gi"), partition.call("full", "40Gi")], count: 2)],
                              claims: [claim("c", [request("r", count: 2)])])
    add.call("partitionable-exhausted", slices: [slice("counters", [], count: 2, sharedCounters: counters).tap do |entry|
      entry["spec"].delete("devices")
    end,
                                                 slice("devices", [partition.call("full", "40Gi"), partition.call("half", "20Gi")],
                                                       count: 2)],
                                        claims: [claim("c", [request("r", count: 2)])])
    add.call("partitionable-allocated", slices: [slice("counters", [], count: 2, sharedCounters: counters).tap do |entry|
      entry["spec"].delete("devices")
    end,
                                                 slice("devices", [partition.call("full", "40Gi"), partition.call("half", "20Gi")],
                                                       count: 2)],
                                        claims: [claim("c", [request("r")])],
                                        allocatedClaims: [claim("old", [request("r")], allocation: {"devices" => {"results" => [
                                                                  {"request" => "r", "driver" => DRIVER, "pool" => "node-1", "device" => "half"}
                                                                ]}})])
    add.call("unknown-counter-set", slices: [slice("devices", [partition.call("x", "1Gi")])], claims: [claim("c", [request("r")])])
    shared = ->(name, **capacity) { device(name, allowMultipleAllocations: true, capacity: capacity) }
    add.call("consumable-capacity", slices: [slice("s1", [shared.call("nic", bandwidth: "10G")])],
                                    claims: [claim("a", [request("r", capacity: {"requests" => {"bandwidth" => "4G"}})]),
                                             claim("b", [request("r", capacity: {"requests" => {"bandwidth" => "4G"}})])])
    add.call("consumable-capacity-full", slices: [slice("s1", [shared.call("nic", bandwidth: "10G")])],
                                         claims: [claim("a", [request("r", capacity: {"requests" => {"bandwidth" => "6G"}})]),
                                                  claim("b", [request("r", capacity: {"requests" => {"bandwidth" => "6G"}})])])
    add.call("consumable-default-is-full", slices: [slice("s1", [shared.call("nic", bandwidth: "10G")])],
                                           claims: [claim("a", [request("r")]), claim("b", [request("r")])])
    add.call("consumable-policy-step", slices: [slice("s1", [shared.call("mem", memory: {"value" => "8Gi", "requestPolicy" => {"default" => "1Gi",
                                                                                                                               "validRange" => {
                                                                                                                                 "min" => "1Gi", "step" => "1Gi"
                                                                                                                               }}})])],
                                       claims: [claim("a", [request("r", capacity: {"requests" => {"memory" => "1500Mi"}})]), claim("b", [request("r")])])
    add.call("consumable-policy-values", slices: [slice("s1", [shared.call("mem", memory: {"value" => "8Gi", "requestPolicy" => {"default" => "2Gi",
                                                                                                                                 "validValues" => %w[
                                                                                                                                   2Gi 4Gi
                                                                                                                                 ]}})])],
                                         claims: [claim("a", [request("r", capacity: {"requests" => {"memory" => "3Gi"}})])])
    add.call("consumable-policy-max", slices: [slice("s1", [shared.call("mem", memory: {"value" => "8Gi", "requestPolicy" => {"validRange" => {"min" => "1Gi", "max" => "2Gi"}}})])],
                                      claims: [claim("a", [request("r", capacity: {"requests" => {"memory" => "3Gi"}})])])
    add.call("consumable-undefined", slices: [slice("s1", [shared.call("nic", bandwidth: "10G")])],
                                     claims: [claim("a", [request("r", capacity: {"requests" => {"memory" => "1Gi"}})])])
    add.call("consumable-already-used", slices: [slice("s1", [shared.call("nic", bandwidth: "10G")])],
                                        claims: [claim("b", [request("r", capacity: {"requests" => {"bandwidth" => "5G"}})])],
                                        allocatedClaims: [claim("a", [request("r")], allocation: {"devices" => {"results" => [
                                                                  {"request" => "r", "driver" => DRIVER, "pool" => "node-1", "device" => "nic", "shareID" => "11111111-1111-1111-1111-111111111111",
                                                                   "consumedCapacity" => {"bandwidth" => "6G"}}
                                                                ]}})])
    add.call("allow-multiple-selector", slices: [slice("s1", [shared.call("nic", bandwidth: "10G"), device("plain")])],
                                        claims: [claim("a", [request("r", selectors: ["device.allowMultipleAllocations"])])])
    add.call("max-size", slices: [slice("s1", (0...40).map do |index|
      device("d#{index}")
    end)], claims: [claim("c", [request("r", count: 33)])])
    add.call("all-mode-max", slices: [slice("s1", (0...33).map do |index|
      device("d#{index}")
    end)], claims: [claim("c", [request("r", mode: "All")])])
    add.call("multi-driver-order", slices: [slice("z", [device("z0")], driver: "b.example.com", pool: "p"), slice("a", [device("a0")], driver: "a.example.com", pool: "p")],
                                   classes: [klass("any")], claims: [claim("c", [request("r", klass: "any", count: 2)])])
    list
  end

  def oracle(cases)
    stdout, stderr, status = Open3.capture3({"GOWORK" => "off"}, "go", "run", "-mod=mod", ORACLE,
                                            stdin_data: JSON.generate("cases" => cases), chdir: SOURCE)
    raise "oracle failed: #{stderr}" unless status.success?

    JSON.parse(stdout).fetch("results").to_h { |result| [result["name"], result] }
  end

  def local(test_case)
    allocated = Rubernetes::DRA::Allocator::AllocatedState.from_claims(test_case["allocatedClaims"])
    result = Rubernetes::DRA::Allocator.allocate(node: test_case["node"], claims: test_case["claims"], slices: test_case["slices"],
                                                 classes: test_case["classes"], allocated_state: allocated)
    {"allocations" => result, "error" => nil}
  rescue Rubernetes::DRA::Allocator::Error => error
    {"allocations" => nil, "error" => error.message}
  end

  # Drop empty values, renumber share IDs, canonical quantities.
  def normalize(value, shares = {})
    case value
    when Hash
      value.each_with_object({}) do |(key, item), result|
        item = shares[item] ||= "share-#{shares.length}" if key == "shareID" && item
        normalized = normalize(item, shares)
        result[key] = normalized unless normalized.nil? || (normalized.respond_to?(:empty?) && normalized.empty?)
      end
    when Array then value.map { |item| normalize(item, shares) }
    else value
    end
  end

  def comparable_error(message)
    return nil if message.nil?

    index = message.index("CEL compile error: ")
    index ? message[0, index + "CEL compile error: ".length] : message
  end

  def run(show: false)
    list = cases
    expected = oracle(list)
    failures = 0
    list.each do |test_case|
      want = expected.fetch(test_case["name"])
      got = local(test_case)
      want_allocations = normalize(want["allocations"] || [])
      got_allocations = normalize(got["allocations"] || [])
      same = want_allocations == got_allocations && comparable_error(want["error"]) == comparable_error(got["error"])
      failures += 1 unless same
      puts "#{same ? "ok  " : "DIFF"} #{test_case["name"]}"
      next if same && !show

      puts "  upstream: #{JSON.generate(want_allocations)} error=#{want["error"].inspect}"
      puts "  ours:     #{JSON.generate(got_allocations)} error=#{got["error"].inspect}"
    end
    puts "#{list.length - failures}/#{list.length} match"
    failures.zero?
  end
end

exit(DRAAllocatorDifferential.run(show: ARGV.include?("--show")) ? 0 : 1) if $PROGRAM_NAME == __FILE__
