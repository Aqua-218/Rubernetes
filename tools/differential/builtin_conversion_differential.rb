#!/usr/bin/env ruby
# frozen_string_literal: true

# Built-in version conversion (lib/rubernetes/api/builtin_conversion.rb and
# hpa_conversion.rb) against upstream's scheme: random HPAs in autoscaling/v1
# and v2 and DRA objects in resource.k8s.io v1beta1, v1beta2 and v1 are
# converted by legacyscheme (decode, encode to the target, decode and encode
# again so the target's defaults apply as on a read from storage) and by the
# port, both directly and through the storage version the registry keys the
# resource under.
#
#   ruby tools/differential/builtin_conversion_differential.rb [--seed N] [--cases N]

require "json"
require "optparse"
require_relative "printers_oracle"
require_relative "../../lib/rubernetes/api/builtin_conversion"

module BuiltinConversionDifferential
  BC = Rubernetes::API::BuiltinConversion

  class Generator
    def initialize(random)
      @r = random
    end

    def pick(*values) = values.flatten.sample(random: @r)
    def chance(probability) = @r.rand < probability
    def int(range) = @r.rand(range)
    def quantity = pick(%w[1 100m 1Gi 500M 2 0])

    def metadata(annotations = {})
      meta = {"name" => "o-#{int(0..999)}", "namespace" => "ns", "uid" => "u-#{int(1..99)}", "resourceVersion" => int(1..99).to_s,
              "creationTimestamp" => "@T-600"}
      meta["labels"] = {"app" => "a"} if chance(0.3)
      meta["annotations"] = annotations.merge(chance(0.3) ? {"note" => "x"} : {}) unless annotations.empty? && !chance(0.3)
      meta["annotations"] ||= {"note" => "x"} if meta.key?("annotations")
      meta
    end

    def selector = chance(0.5) ? {"matchLabels" => {"k" => "v"}} : nil

    def v2_metric
      case pick(%w[Resource Pods Object External ContainerResource])
      when "Resource"
        target = if chance(0.5) then {"type" => "Utilization", "averageUtilization" => pick(50, 80)}
                 else {"type" => "AverageValue", "averageValue" => quantity}
                 end
        {"type" => "Resource", "resource" => {"name" => pick("cpu", "memory"), "target" => target}}
      when "ContainerResource"
        target = chance(0.5) ? {"type" => "Utilization", "averageUtilization" => 60} : {"type" => "AverageValue", "averageValue" => quantity}
        {"type" => "ContainerResource", "containerResource" => {"name" => "cpu", "container" => "c", "target" => target}}
      when "Pods"
        {"type" => "Pods", "pods" => {"metric" => {"name" => "qps", "selector" => selector}.compact, "target" => {"type" => "AverageValue", "averageValue" => quantity}}}
      when "Object"
        target = if chance(0.5) then {"type" => "Value", "value" => quantity}
                 else {"type" => "AverageValue", "averageValue" => quantity, "value" => chance(0.3) ? quantity : nil}.compact
                 end
        {"type" => "Object", "object" => {"metric" => {"name" => "rps"}, "describedObject" => {"kind" => "Service", "name" => "s", "apiVersion" => pick("v1", nil)}.compact,
                                          "target" => target}}
      else
        target = chance(0.5) ? {"type" => "Value", "value" => quantity} : {"type" => "AverageValue", "averageValue" => quantity}
        {"type" => "External", "external" => {"metric" => {"name" => "queue", "selector" => selector}.compact, "target" => target}}
      end
    end

    def v2_status(metric)
      case metric["type"]
      when "Resource"
        current = {"averageValue" => quantity}
        current["averageUtilization"] = 40 if chance(0.6)
        {"type" => "Resource", "resource" => {"name" => metric.dig("resource", "name"), "current" => current}}
      when "ContainerResource" then {"type" => "ContainerResource", "containerResource" => {"name" => "cpu", "container" => "c", "current" => {"averageValue" => quantity, "averageUtilization" => 30}}}
      when "Pods" then {"type" => "Pods", "pods" => {"metric" => {"name" => "qps"}, "current" => {"averageValue" => quantity}}}
      when "Object" then {"type" => "Object", "object" => {"metric" => {"name" => "rps"}, "describedObject" => {"kind" => "Service", "name" => "s"}, "current" => {"value" => quantity, "averageValue" => chance(0.5) ? quantity : nil}.compact}}
      else {"type" => "External", "external" => {"metric" => {"name" => "queue"}, "current" => {"value" => quantity, "averageValue" => chance(0.5) ? quantity : nil}.compact}}
      end
    end

    def behavior_rules
      rules = {}
      rules["stabilizationWindowSeconds"] = int(0..600) if chance(0.5)
      rules["selectPolicy"] = pick("Max", "Min", "Disabled") if chance(0.5)
      rules["policies"] = Array.new(int(1..2)) { {"type" => pick("Pods", "Percent"), "value" => int(1..100), "periodSeconds" => int(1..1800)} } if chance(0.5)
      rules
    end

    def hpa_v2
      metrics = Array.new(int(0..3)) { v2_metric }
      spec = {"scaleTargetRef" => {"kind" => "Deployment", "name" => "d", "apiVersion" => "apps/v1"}, "maxReplicas" => int(1..10), "metrics" => metrics}
      spec["minReplicas"] = int(1..3) if chance(0.7)
      if chance(0.4)
        behavior = {}
        behavior["scaleUp"] = behavior_rules if chance(0.7)
        behavior["scaleDown"] = behavior_rules if chance(0.7)
        spec["behavior"] = behavior
      end
      status = {"currentReplicas" => int(0..5), "desiredReplicas" => int(0..5)}
      status["observedGeneration"] = int(1..9) if chance(0.5)
      status["lastScaleTime"] = "@T-120" if chance(0.4)
      status["currentMetrics"] = metrics.map { |metric| v2_status(metric) } if chance(0.7)
      if chance(0.5)
        status["conditions"] = Array.new(int(1..3)) do
          {"type" => pick("AbleToScale", "ScalingActive", "ScalingLimited"), "status" => pick("True", "False"),
           "lastTransitionTime" => "@T-30", "reason" => pick("R", ""), "message" => pick("m", "")}.reject { |_, v| v == "" }
        end
      end
      {"apiVersion" => "autoscaling/v2", "kind" => "HorizontalPodAutoscaler", "metadata" => metadata, "spec" => spec, "status" => status}
    end

    def hpa_v1
      annotations = {}
      if chance(0.4)
        annotations["autoscaling.alpha.kubernetes.io/metrics"] = JSON.generate(Array.new(int(1..2)) do
          pick({"type" => "Pods", "pods" => {"metricName" => "qps", "targetAverageValue" => quantity}},
               {"type" => "External", "external" => {"metricName" => "q", "targetAverageValue" => quantity}},
               {"type" => "External", "external" => {"metricName" => "q", "targetValue" => quantity}},
               {"type" => "Object", "object" => {"target" => {"kind" => "Service", "name" => "s"}, "metricName" => "m", "targetValue" => quantity}},
               {"type" => "Resource", "resource" => {"name" => "memory", "targetAverageValue" => quantity}})
        end)
      end
      annotations["autoscaling.alpha.kubernetes.io/behavior"] = JSON.generate({"ScaleUp" => {"StabilizationWindowSeconds" => 30, "SelectPolicy" => "Min", "Policies" => [{"Type" => "Pods", "Value" => 2, "PeriodSeconds" => 60}]}}) if chance(0.2)
      if chance(0.3)
        annotations["autoscaling.alpha.kubernetes.io/conditions"] = JSON.generate([{"type" => "AbleToScale", "status" => "True", "lastTransitionTime" => "2026-09-23T10:00:00Z", "reason" => "SucceededRescale"}])
      end
      if chance(0.3)
        annotations["autoscaling.alpha.kubernetes.io/current-metrics"] = JSON.generate([{"type" => "Pods", "pods" => {"metricName" => "qps", "currentAverageValue" => quantity}}])
      end
      spec = {"scaleTargetRef" => {"kind" => "Deployment", "name" => "d", "apiVersion" => pick("apps/v1", nil)}.compact, "maxReplicas" => int(1..10)}
      spec["minReplicas"] = int(1..3) if chance(0.7)
      spec["targetCPUUtilizationPercentage"] = pick(50, 80) if chance(0.6)
      status = {"currentReplicas" => int(0..3), "desiredReplicas" => 1}
      status["currentCPUUtilizationPercentage"] = 33 if chance(0.5)
      status["lastScaleTime"] = "@T-60" if chance(0.3)
      {"apiVersion" => "autoscaling/v1", "kind" => "HorizontalPodAutoscaler", "metadata" => metadata(annotations), "spec" => spec, "status" => status}
    end

    def selectors = Array.new(int(0..2)) { {"cel" => {"expression" => "device.driver == \"gpu.example.com\""}} }
    def tolerations = Array.new(int(0..2)) { {"key" => "k", "operator" => pick("Exists", "Equal"), "effect" => pick("NoSchedule", "NoExecute")} }

    def request(version)
      request = {"name" => "r#{int(0..9)}"}
      main = {}
      main["deviceClassName"] = "gpu.example.com" if chance(0.9)
      main["selectors"] = selectors if chance(0.5)
      main["allocationMode"] = pick("ExactCount", "All") if chance(0.6)
      main["count"] = int(1..3) if chance(0.5) && main["allocationMode"] != "All"
      main["adminAccess"] = pick(true, false) if chance(0.2)
      main["tolerations"] = tolerations if chance(0.3)
      main["capacity"] = {"requests" => {"memory" => quantity}} if chance(0.2)
      if chance(0.15)
        request["firstAvailable"] = Array.new(int(1..2)) { |index| {"name" => "s#{index}", "deviceClassName" => "gpu.example.com", "allocationMode" => "ExactCount", "count" => 1} }
        return request
      end
      version == "v1beta1" ? request.merge(main) : request.merge("exactly" => main.merge("deviceClassName" => main["deviceClassName"] || "gpu.example.com"))
    end

    def claim(version, kind)
      devices = {"requests" => Array.new(int(1..3)) { request(version) }.uniq { |entry| entry["name"] }}
      devices["constraints"] = [{"requests" => [devices["requests"].first["name"]], "matchAttribute" => "gpu.example.com/numa"}] if chance(0.2)
      spec = {"devices" => devices}
      body = kind == "ResourceClaim" ? {"spec" => spec} : {"spec" => {"metadata" => {"labels" => {"a" => "b"}}, "spec" => spec}}
      object = {"apiVersion" => "resource.k8s.io/#{version}", "kind" => kind, "metadata" => metadata}.merge(body)
      if kind == "ResourceClaim" && chance(0.5)
        object["status"] = {"allocation" => {"devices" => {"results" => [{"request" => devices["requests"].first["name"], "driver" => "gpu.example.com", "pool" => "p", "device" => "gpu-0"}]}},
                            "reservedFor" => [{"resource" => "pods", "name" => "p", "uid" => "u"}]}
      end
      object
    end

    def device(version)
      fields = {}
      fields["attributes"] = {"model" => {"string" => "a100"}, "numa" => {"int" => int(0..3)}} if chance(0.7)
      fields["capacity"] = {"memory" => {"value" => quantity}} if chance(0.6)
      fields["taints"] = [{"key" => "k", "value" => "v", "effect" => "NoSchedule"}] if chance(0.2)
      fields["bindsToNode"] = pick(true, false) if chance(0.2)
      fields["allowMultipleAllocations"] = pick(true, false) if chance(0.2)
      fields["consumesCounters"] = [{"counterSet" => "cs", "counters" => {"mem" => {"value" => "1Gi"}}}] if chance(0.15)
      device = {"name" => "gpu-#{int(0..9)}"}
      version == "v1beta1" ? device.merge("basic" => fields) : device.merge(fields)
    end

    def slice(version)
      spec = {"driver" => "gpu.example.com", "pool" => {"name" => "p", "generation" => 1, "resourceSliceCount" => 1}}
      case int(0..2)
      when 0 then spec["nodeName"] = "node-1"
      when 1 then spec["allNodes"] = true
      else spec["nodeSelector"] = {"nodeSelectorTerms" => [{"matchExpressions" => [{"key" => "k", "operator" => "In", "values" => ["v"]}]}]}
      end
      spec["devices"] = Array.new(int(0..3)) { device(version) }.uniq { |entry| entry["name"] }
      {"apiVersion" => "resource.k8s.io/#{version}", "kind" => "ResourceSlice", "metadata" => metadata.except("namespace"), "spec" => spec}
    end

    def device_class(version)
      {"apiVersion" => "resource.k8s.io/#{version}", "kind" => "DeviceClass", "metadata" => metadata.except("namespace"),
       "spec" => {"selectors" => selectors, "config" => [{"opaque" => {"driver" => "gpu.example.com", "parameters" => {"a" => 1}}}]}}
    end
  end

  RESOURCE_VERSIONS = %w[v1beta1 v1beta2 v1].freeze
  STORAGE = {"autoscaling" => "v2", "resource.k8s.io" => "v1"}.freeze

  module_function

  def cases(random, count)
    generator = Generator.new(random)
    Array.new(count) do |index|
      if random.rand < 0.5
        object = random.rand < 0.5 ? generator.hpa_v2 : generator.hpa_v1
        to = object["apiVersion"] == "autoscaling/v1" ? "autoscaling/v2" : "autoscaling/v1"
      else
        version = RESOURCE_VERSIONS.sample(random: random)
        object = case %w[ResourceClaim ResourceClaimTemplate ResourceSlice DeviceClass].sample(random: random)
                 when "ResourceClaim" then generator.claim(version, "ResourceClaim")
                 when "ResourceClaimTemplate" then generator.claim(version, "ResourceClaimTemplate")
                 when "ResourceSlice" then generator.slice(version)
                 else generator.device_class(version)
                 end
        to = "resource.k8s.io/#{(RESOURCE_VERSIONS - [version]).sample(random: random)}"
      end
      {"name" => "convert/#{index}/#{object["kind"]}/#{object["apiVersion"]}->#{to}", "convertor" => "convert", "to" => to, "object" => object}
    end
  end

  def canonical(value)
    case value
    when Hash then value.reject { |key, _| key == "managedFields" }.sort.to_h { |key, item| [key, canonical(item)] }
    when Array then value.map { |item| canonical(item) }
    else value
    end
  end

  def run(seed:, count:)
    test_cases = cases(Random.new(seed), count)
    oracle = PrintersOracle.run("cases" => test_cases)
    mismatches = []
    test_cases.zip(oracle).each do |test_case, expected|
      if expected["decodeError"] || expected["error"]
        mismatches << [test_case["name"], expected["decodeError"] || expected["error"], nil] if expected["decodeError"]
        next
      end
      served = expected.fetch("served")
      group, to_version = test_case["to"].split("/", 2)
      converter = BC::Converter.new(group: group, resource: served["kind"])
      direct = converter.convert([served], to_version: to_version).first
      stored = converter.convert([served], to_version: STORAGE.fetch(group)).first
      chained = converter.convert([stored], to_version: to_version).first
      want = canonical(expected.fetch("converted"))
      [["direct", direct], ["chained", chained]].each do |route, got|
        got = canonical(got)
        mismatches << ["#{test_case["name"]} (#{route})", want, got] unless got == want
      end
    rescue BC::ConversionError => error
      mismatches << [test_case["name"], expected["converted"], "ConversionError: #{error.message}"]
    end
    [test_cases.length, mismatches]
  end

  def diff(want, got, path = "")
    return [] if want == got
    return ["#{path}: oracle=#{JSON.generate(want)[0, 300]} port=#{JSON.generate(got)[0, 300]}"] unless want.is_a?(Hash) && got.is_a?(Hash)

    (want.keys | got.keys).flat_map do |key|
      next ["#{path}.#{key}: only in oracle (#{JSON.generate(want[key])[0, 200]})"] unless got.key?(key)
      next ["#{path}.#{key}: only in port (#{JSON.generate(got[key])[0, 200]})"] unless want.key?(key)

      diff(want[key], got[key], "#{path}.#{key}")
    end
  end
end

if $PROGRAM_NAME == __FILE__
  seed = Random.new_seed % 1_000_000
  count = 400
  OptionParser.new do |parser|
    parser.on("--seed N", Integer) { |value| seed = value }
    parser.on("--cases N", Integer) { |value| count = value }
  end.parse!
  total, mismatches = BuiltinConversionDifferential.run(seed: seed, count: count)
  puts "seed=#{seed} cases=#{total} mismatches=#{mismatches.length}"
  mismatches.first(10).each do |name, want, got|
    puts "--- #{name}"
    if want.is_a?(Hash) && got.is_a?(Hash)
      BuiltinConversionDifferential.diff(want, got).first(6).each { |line| puts "  #{line}" }
    else
      puts "  oracle: #{JSON.generate(want)[0, 600]}"
      puts "  port:   #{got.to_s[0, 600]}"
    end
  end
  exit(mismatches.empty? ? 0 : 1)
end
