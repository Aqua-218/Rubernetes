#!/usr/bin/env ruby
# frozen_string_literal: true

# ValidatePodUpdate's spec refusal (lib/rubernetes/schema/kubernetes_validator/
# pod_update.rb) against upstream: random v1 Pods -- every field of the v1
# PodSpec reachable, generated from the imported layout -- and mutated copies
# go to test/conformance/kubernetes/internal_pod_spec (compiled into
# k8s.io/kubernetes/pkg/apis/core/v1 through a go test overlay), which
# converts them with the real scheme.  json.MarshalIndent of both internal
# specs, diff.Diff between them and the "spec" error of ValidatePodUpdate must
# match the port byte for byte.
#
#   ruby tools/differential/pod_update_diff_differential.rb [--seed N] [--cases N]

require "json"
$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "rubernetes"
require "rubernetes/schema/kubernetes_validator"
require_relative "../schema/import_internal_pod_spec"

module PodUpdateDiffDifferential
  KV = Rubernetes::Schema::KubernetesValidator
  IPS = KV::InternalPodSpec
  STRINGS = ["", "a", "b", "web", "x<y>&z", "ünï", "tab\there", "line\nbreak", "q\"uote", "back\\slash", " "].freeze
  QUANTITIES = %w[0 1 100m 1000m 0.5 1Gi 1024Mi 2e3 1.5Gi 250m 1k].freeze

  module_function

  def pick(random, list) = list.sample(random: random)
  def maybe(random, probability) = random.rand < probability

  def value(random, type, depth)
    case type["k"]
    when "string" then pick(random, STRINGS)
    when "int", "uint" then pick(random, [0, 1, 2, 5, 30, 100, -1])
    when "float" then pick(random, [0.5, 1.0, 2.25])
    when "bool" then pick(random, [true, false])
    when "ptr" then value(random, type["e"], depth)
    when "slice"
      return [] if maybe(random, 0.15)

      Array.new(random.rand(1..2)) { value(random, type["e"], depth + 1) }
    when "map"
      return {} if maybe(random, 0.15)

      Array.new(random.rand(1..2)) { [pick(random, %w[cpu memory a b c.example/x]), value(random, type["e"], depth + 1)] }.to_h
    when "struct" then struct(random, type["n"], depth + 1)
    when "quantity" then pick(random, QUANTITIES)
    when "intorstring" then maybe(random, 0.5) ? pick(random, [0, 80, 8080]) : pick(random, ["http", "50%", "a"])
    when "time" then "2026-09-27T01:02:03Z"
    when "bytes" then ["x\u0000y"].pack("m0")
    when "fieldsv1" then {"f:a" => {}}
    end
  end

  def struct(random, name, depth)
    fields = IPS.layout.fetch("types").fetch(name)
    chance = depth <= 1 ? 0.35 : [0.5 / depth, 0.08].max
    fields.each_with_object({}) do |field, out|
      next unless maybe(random, chance)
      next if depth > 6 && %w[struct slice map ptr].include?(field["type"]["k"])

      out[field["key"]] = value(random, field["type"], depth)
    end
  end

  def container(random, name)
    item = struct(random, "k8s.io/api/core/v1.Container", 2)
    item.merge("name" => name, "image" => pick(random, %w[busybox nginx:1 registry.k8s.io/pause:3.10]))
  end

  def pod(random)
    spec = struct(random, IPS.layout.fetch("v1"), 1)
    spec["containers"] = Array.new(random.rand(1..2)) { |i| container(random, "c#{i}") }
    spec["initContainers"] = [container(random, "init")] if maybe(random, 0.2)
    spec.delete("activeDeadlineSeconds") if maybe(random, 0.5)
    spec.delete("schedulingGates") if maybe(random, 0.6)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "default"}, "spec" => spec}
  end

  # A random change: a field of the spec rewritten, or one of the updatable
  # ones (images, the deadline, tolerations, gates, the grace period).
  def mutate(random, original)
    pod = Marshal.load(Marshal.dump(original))
    spec = pod["spec"]
    Array.new(random.rand(1..2)) do
      case random.rand(9)
      when 0 then spec["containers"].sample(random: random)["image"] = "busybox:#{random.rand(9)}"
      when 1 then spec["activeDeadlineSeconds"] = pick(random, [10, 50, 200])
      when 2 then (spec["tolerations"] ||= []) << {"key" => "k#{random.rand(3)}", "operator" => "Exists"}
      when 3 then spec["schedulingGates"] = Array(spec["schedulingGates"]).first(random.rand(2))
      when 4 then spec["terminationGracePeriodSeconds"] = pick(random, [1, 30, -5])
      when 5 then spec["containers"] << container(random, "extra") if maybe(random, 0.3)
      else
        fields = IPS.layout.fetch("types").fetch(IPS.layout.fetch("v1"))
        field = pick(random, fields)
        next if field["key"] == "containers"

        spec[field["key"]] = value(random, field["type"], 1)
      end
    end
    pod
  end

  def cases(random, count)
    Array.new(count) do
      old = pod(random)
      {"old" => old, "new" => maybe(random, 0.1) ? Marshal.load(Marshal.dump(old)) : mutate(random, old)}
    end
  end

  def run_port(test_case)
    old_spec = IPS.convert(test_case["old"])
    new_spec = IPS.convert(test_case["new"], keep_empty: true)
    spec_issue = KV.pod_update_errors(test_case["new"], "Pod", :update, test_case["old"]).find do |issue|
      issue.path == ["spec"] && issue.code == :forbidden
    end
    {"old" => IPS.render(old_spec), "new" => IPS.render(new_spec),
     "diff" => KV::GoDiffLib.unified_diff(KV::GoDiffLib.split_lines(IPS.render(old_spec)), KV::GoDiffLib.split_lines(IPS.render(new_spec))),
     "error" => spec_issue ? spec_issue.message : ""}
  end

  def main(argv)
    seed = argv.include?("--seed") ? Integer(argv[argv.index("--seed") + 1]) : 20_260_927
    count = argv.include?("--cases") ? Integer(argv[argv.index("--cases") + 1]) : 500
    list = cases(Random.new(seed), count)
    oracle = InternalPodSpecImporter.run("TestRubernetesInternalPodSpecOracle", list)
    mismatches = list.zip(oracle).filter_map do |test_case, want|
      want = want.except("errors")
      got = run_port(test_case)
      [test_case, want, got] unless got == want
    end
    mismatches.first(3).each do |_test_case, want, got|
      key = %w[old new diff error].find { |name| want[name] != got[name] }
      puts "MISMATCH in #{key}"
      want_lines = want[key].lines
      got_lines = got[key].lines
      index = want_lines.zip(got_lines).index { |a, b| a != b } || [want_lines.length, got_lines.length].min
      puts "  first difference at line #{index + 1}"
      puts "  upstream: #{want_lines[[index - 2, 0].max, 5].join.inspect}"
      puts "  port:     #{got_lines[[index - 2, 0].max, 5].join.inspect}"
    end
    forbidden = oracle.count { |result| !result["error"].empty? }
    puts "#{list.length - mismatches.length}/#{list.length} match (#{forbidden} refused with a diff)"
    mismatches.empty? ? 0 : 1
  end
end

exit(PodUpdateDiffDifferential.main(ARGV)) if $PROGRAM_NAME == __FILE__
