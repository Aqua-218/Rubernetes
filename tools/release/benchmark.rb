#!/usr/bin/env ruby
# frozen_string_literal: true

# Release performance benchmark (spec/delivery/milestones.md#milestone-m9
# exit 4): the targets must be met against a Kubernetes v1.36.2 oracle on the
# same hardware.
#
# Both clusters run the identical request sequence from one seed.  Without an
# oracle the run reports INCOMPLETE: a number with nothing to compare it to is
# not evidence for this criterion.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

module Release
  module Benchmark
    ROOT = File.expand_path("../..", __dir__)
    KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")

    SCENARIOS = [
      {"id" => "namespace_list", "argv" => %w[get namespaces -o json], "iterations" => 50},
      {"id" => "configmap_create_delete", "argv" => :configmap_cycle, "iterations" => 25},
      {"id" => "pod_list_all", "argv" => %w[get pods --all-namespaces -o json], "iterations" => 50},
      {"id" => "api_resources", "argv" => %w[api-resources --no-headers], "iterations" => 20},
      {"id" => "watch_establish", "argv" => %w[get pods --all-namespaces --watch-only --request-timeout=2s], "iterations" => 10}
    ].freeze

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/release/benchmark.json"),
                 tolerance: Float(ENV.fetch("RUBERNETES_BENCH_TOLERANCE", 1.5))}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--oracle-kubeconfig PATH") { |v| options[:oracle] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
        parser.on("--tolerance X", Float, "allowed p95 ratio against the oracle") { |v| options[:tolerance] = v }
      end.parse!(argv)

      report = {
        "schema_version" => 1, "kind" => "release_benchmark",
        "generated_at" => Time.now.utc.iso8601,
        "host" => {"platform" => RbConfig::CONFIG["host"], "ruby" => RUBY_DESCRIPTION},
        "tolerance" => options[:tolerance]
      }
      if options[:kubeconfig].nil? || options[:oracle].nil?
        report.merge!("status" => "INCOMPLETE", "passed" => false,
                      "reason" => "both --kubeconfig and --oracle-kubeconfig are required: the exit criterion is " \
                                  "a comparison against a Kubernetes v1.36.2 oracle on the same hardware")
        write(report, options[:output])
        return 1
      end

      scenarios = SCENARIOS.map do |scenario|
        ours = measure(scenario, options[:kubeconfig])
        theirs = measure(scenario, options[:oracle])
        ratio = theirs.fetch("p95_ms").positive? ? (ours.fetch("p95_ms") / theirs.fetch("p95_ms")).round(4) : nil
        {
          "id" => scenario.fetch("id"), "iterations" => scenario.fetch("iterations"),
          "rubernetes" => ours, "kubernetes" => theirs, "p95_ratio" => ratio,
          "passed" => ratio.nil? ? false : ratio <= options[:tolerance]
        }
      end
      report.merge!("status" => "COMPLETE", "scenarios" => scenarios,
                    "passed" => scenarios.all? { |scenario| scenario.fetch("passed") })
      write(report, options[:output])
      report.fetch("passed") ? 0 : 1
    end

    def measure(scenario, kubeconfig)
      samples = Array.new(scenario.fetch("iterations")) do
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        if scenario.fetch("argv") == :configmap_cycle
          name = "bench-#{SecureRandom.hex(4)}"
          Open3.capture3(KUBECTL, "--kubeconfig", kubeconfig, "create", "configmap", name, "--from-literal=a=b")
          Open3.capture3(KUBECTL, "--kubeconfig", kubeconfig, "delete", "configmap", name, "--ignore-not-found")
        else
          Open3.capture3(KUBECTL, "--kubeconfig", kubeconfig, *scenario.fetch("argv"))
        end
        ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round(3)
      end.sort
      {
        "samples" => samples.length,
        "p50_ms" => samples[(samples.length * 0.50).floor].to_f,
        "p95_ms" => samples[[(samples.length * 0.95).floor, samples.length - 1].min].to_f,
        "max_ms" => samples.last.to_f
      }
    end

    def write(report, path)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, "#{JSON.pretty_generate(report)}\n")
      puts JSON.pretty_generate(report)
    end
  end
end

require "securerandom"
exit(Release::Benchmark.run) if $PROGRAM_NAME == __FILE__
