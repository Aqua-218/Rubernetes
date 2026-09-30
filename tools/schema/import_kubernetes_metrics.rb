#!/usr/bin/env ruby
# frozen_string_literal: true

# Import the v1.36.2 metric inventory (test/instrumentation/documentation/
# documentation-list.yaml, generated upstream by static analysis of every
# component-base metric) into schema/kubernetes/v1.36.2-defaults/metrics.json:
# for each fully qualified name, its type, help, stability level, deprecated
# version, label names, buckets and the components that serve it.
#
# Usage: KUBERNETES_SOURCE_ROOT=/path/to/kubernetes-v1.36.2 ruby tools/schema/import_kubernetes_metrics.rb

require "digest"
require "json"
require "yaml"

module KubernetesMetricsImporter
  ROOT = File.expand_path("../..", __dir__)
  OUTPUT = File.join(ROOT, "schema/kubernetes/v1.36.2-defaults/metrics.json")
  SOURCE = "test/instrumentation/documentation/documentation-list.yaml"

  module_function

  def source_root = ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2")

  def main
    path = File.join(source_root, SOURCE)
    text = File.read(path)
    metrics = {}
    YAML.safe_load(text).each do |entry|
      name = [entry["namespace"], entry["subsystem"], entry["name"]].compact.reject(&:empty?).join("_")
      record = metrics[name] ||= {"type" => entry["type"], "help" => entry["help"].to_s, "stabilityLevel" => entry["stabilityLevel"],
                                  "labels" => Array(entry["labels"]), "components" => []}
      # YAML 1.1 reads "1e-05" (no dot) as a string: bucket bounds are floats.
      record["buckets"] = entry["buckets"].map { |bound| bound.is_a?(String) ? Float(bound) : bound } if entry["buckets"]
      record["deprecatedVersion"] = entry["deprecatedVersion"] if entry["deprecatedVersion"]
      record["constLabels"] = entry["constLabels"] if entry["constLabels"]
      record["components"] |= Array(entry["componentEndpoints"]).map { |endpoint| endpoint["component"] }
      record["endpoints"] ||= {}
      Array(entry["componentEndpoints"]).each do |endpoint|
        (record["endpoints"][endpoint["component"]] ||= []) << endpoint["endpoint"]
        record["endpoints"][endpoint["component"]].uniq!
      end
    end
    document = {"source" => SOURCE, "sha256" => Digest::SHA256.hexdigest(text),
                "metrics" => metrics.keys.sort.to_h { |name| [name, metrics[name]] }}
    File.write(OUTPUT, "#{JSON.pretty_generate(document)}\n")
    puts "#{metrics.length} metrics -> #{OUTPUT}"
  end
end

KubernetesMetricsImporter.main if $PROGRAM_NAME == __FILE__
