#!/usr/bin/env ruby
# frozen_string_literal: true

# Request latency of the API server, seen by a client: the number a refactor
# of the write and read paths must not make worse.
#
#   ruby tools/bench/api_latency.rb --kubeconfig PATH [--count N] [--label TEXT]
#
# One client, one connection, requests one after another, so the figures are
# the server's own time per request and not a measure of concurrency.  Prints
# one JSON document: per operation the median, p90 and p99 in milliseconds.
# Compare runs taken on the same host under the same load; the host this
# project is developed on is shared, so take several and look at medians.

require "json"
require "optparse"

$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "rubernetes/client"

module Bench
  module APILatency
    module_function

    def percentile(sorted, fraction) = sorted[[(sorted.length * fraction).ceil - 1, 0].max]

    def time(count)
      Array.new(count) do |index|
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        yield(index)
        (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
      end.sort
    end

    def summarize(samples)
      {"median_ms" => percentile(samples, 0.5).round(2), "p90_ms" => percentile(samples, 0.9).round(2), "p99_ms" => percentile(samples, 0.99).round(2)}
    end

    def configmap(namespace, index, value)
      {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "bench-#{index}", "namespace" => namespace}, "data" => {"k" => value}}
    end

    def pod(namespace, index)
      {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "bench-#{index}", "namespace" => namespace, "labels" => {"app" => "bench"}},
       "spec" => {"nodeName" => "bench-no-such-node", "containers" => [{"name" => "c", "image" => "busybox:1.36", "command" => %w[sleep 1]}]}}
    end

    def run(client, count)
      namespace = "bench-#{Process.pid}"
      client.create({"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => namespace}})
      base = "/api/v1/namespaces/#{namespace}"
      results = {}
      results["configmap_create"] = time(count) { |index| client.create(configmap(namespace, index, "a")) }
      results["configmap_get"] = time(count) { |index| client.raw("GET", "#{base}/configmaps/bench-#{index}") }
      results["configmap_update"] = time(count) do |index|
        client.raw("PATCH", "#{base}/configmaps/bench-#{index}", body: JSON.generate({"data" => {"k" => "b"}}),
                                                                 headers: {"Content-Type" => "application/merge-patch+json"})
      end
      results["configmap_list_#{count}"] = time([count / 10, 5].max) { client.raw("GET", "#{base}/configmaps") }
      results["pod_create"] = time(count) { |index| client.create(pod(namespace, index)) }
      results["pod_list_#{count}"] = time([count / 10, 5].max) { client.raw("GET", "#{base}/pods") }
      results["configmap_delete"] = time(count) { |index| client.raw("DELETE", "#{base}/configmaps/bench-#{index}") }
      results.transform_values { |samples| summarize(samples) }
    ensure
      client.raw("DELETE", "/api/v1/namespaces/#{namespace}", raise_for_status: false)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {count: 200, label: nil}
  OptionParser.new do |parser|
    parser.on("--kubeconfig PATH") { |value| options[:kubeconfig] = value }
    parser.on("--count N", Integer) { |value| options[:count] = value }
    parser.on("--label TEXT") { |value| options[:label] = value }
  end.parse!
  client = Rubernetes::Client::KubernetesClient.from_kubeconfig(path: options.fetch(:kubeconfig))
  puts JSON.pretty_generate({"label" => options[:label], "count" => options[:count], "load_average" => File.read("/proc/loadavg").split.first.to_f,
                             "operations" => Bench::APILatency.run(client, options[:count])})
end
