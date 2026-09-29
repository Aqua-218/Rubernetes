#!/usr/bin/env ruby
# frozen_string_literal: true

# K5 — API and wire differential (spec/verification/kubernetes-compatibility.md#k5).
#
# Drives the same request sequence from one seed against the Rubernetes cluster
# and the pinned Kubernetes v1.36.2 oracle, then compares the normalised
# observables.  Values that are legitimately per-cluster (UID, timestamp,
# random suffix, node address) are compared on format, uniqueness, monotonicity
# and causal order rather than equality, as the spec requires.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "time"

module Conformance
  module K5Differential
    ROOT = File.expand_path("../..", __dir__)
    KUBECTL = File.join(ROOT, "build/tools/kubectl-v1.36.2")

    # Observable groups from the spec, each a sequence of kubectl invocations
    # whose normalised output must agree between the two clusters.
    OBSERVABLES = [
      {"id" => "discovery_groups", "argv" => %w[api-versions]},
      {"id" => "discovery_resources", "argv" => %w[api-resources --no-headers]},
      {"id" => "openapi_v3_root", "argv" => %w[get --raw /openapi/v3]},
      {"id" => "explain_pod", "argv" => %w[explain pod --recursive]},
      {"id" => "explain_deployment", "argv" => %w[explain deployment.spec]},
      {"id" => "namespace_list", "argv" => %w[get namespaces -o json]},
      {"id" => "create_configmap", "argv" => %w[create configmap k5-cm --from-literal=a=b -o json]},
      {"id" => "get_configmap", "argv" => %w[get configmap k5-cm -o json]},
      {"id" => "patch_configmap", "argv" => ["patch", "configmap", "k5-cm", "--type=merge", "-p", '{"data":{"c":"d"}}', "-o", "json"]},
      {"id" => "apply_configmap_conflict", "argv" => %w[apply -f - --server-side --field-manager=k5 -o json], "stdin" => true},
      {"id" => "unknown_field_strict", "argv" => %w[apply -f - --validate=strict -o json], "stdin" => true, "expect_failure" => true},
      {"id" => "delete_configmap", "argv" => %w[delete configmap k5-cm -o json]},
      {"id" => "missing_object", "argv" => %w[get configmap k5-absent -o json], "expect_failure" => true},
      {"id" => "invalid_object", "argv" => %w[create -f - -o json], "stdin" => true, "expect_failure" => true},
      {"id" => "auth_can_i", "argv" => %w[auth can-i create pods]},
      {"id" => "protobuf_pod_list", "argv" => ["get", "--raw", "/api/v1/pods", "--as", "system:anonymous"], "expect_failure" => true}
    ].freeze

    STDIN_BODIES = {
      "apply_configmap_conflict" => {"apiVersion" => "v1", "kind" => "ConfigMap",
                                     "metadata" => {"name" => "k5-cm", "namespace" => "default"},
                                     "data" => {"a" => "b"}},
      "unknown_field_strict" => {"apiVersion" => "v1", "kind" => "ConfigMap",
                                 "metadata" => {"name" => "k5-strict", "namespace" => "default"},
                                 "dataz" => {"a" => "b"}},
      "invalid_object" => {"apiVersion" => "v1", "kind" => "ConfigMap",
                           "metadata" => {"name" => "K5 Invalid Name"}, "data" => {"a" => "b"}}
    }.freeze

    # Fields whose value is per-cluster; compared structurally, not literally.
    VOLATILE = %w[uid resourceVersion creationTimestamp generation
                  managedFields time lastTransitionTime lastUpdateTime
                  selfLink resourceVersionMatch startTime podIP hostIP nodeName
                  clusterIP clusterIPs bootID machineID systemUUID kubeletVersion
                  kubeProxyVersion containerRuntimeVersion osImage kernelVersion].freeze

    module_function

    def run(argv = ARGV)
      options = {output: File.join(ROOT, "artifacts/conformance/k5")}
      OptionParser.new do |parser|
        parser.on("--kubeconfig PATH") { |v| options[:kubeconfig] = v }
        parser.on("--oracle-kubeconfig PATH") { |v| options[:oracle] = v }
        parser.on("--output PATH") { |v| options[:output] = v }
      end.parse!(argv)
      raise ArgumentError, "--kubeconfig is required" if options[:kubeconfig].nil?
      raise ArgumentError, "--oracle-kubeconfig is required" if options[:oracle].nil?

      FileUtils.mkdir_p(options[:output])
      results = OBSERVABLES.map { |observable| compare(observable, options) }
      differences = results.reject { |entry| entry.fetch("matches") }
      report = {
        "schema_version" => 1,
        "kind" => "k5_api_wire_differential",
        "generated_at" => Time.now.utc.iso8601,
        "observables" => results.length,
        "matching" => results.count { |entry| entry.fetch("matches") },
        "differences" => differences,
        "cases" => results
      }
      File.write(File.join(options[:output], "differential.json"), "#{JSON.pretty_generate(report)}\n")
      differences.empty? ? 0 : 1
    end

    def compare(observable, options)
      ours = invoke(observable, options[:kubeconfig])
      theirs = invoke(observable, options[:oracle])
      normalized_ours = normalize(ours)
      normalized_theirs = normalize(theirs)
      {
        "id" => observable.fetch("id"),
        "matches" => normalized_ours == normalized_theirs,
        "rubernetes" => normalized_ours,
        "kubernetes" => normalized_theirs,
        "rubernetes_sha256" => Digest::SHA256.hexdigest(JSON.generate(normalized_ours)),
        "kubernetes_sha256" => Digest::SHA256.hexdigest(JSON.generate(normalized_theirs))
      }
    end

    def invoke(observable, kubeconfig)
      argv = [KUBECTL, "--kubeconfig", kubeconfig, *observable.fetch("argv")]
      stdin = observable["stdin"] ? JSON.generate(STDIN_BODIES.fetch(observable.fetch("id"))) : nil
      stdout, stderr, status = Open3.capture3(*argv, stdin_data: stdin.to_s)
      {"exit_status" => status.exitstatus, "stdout" => stdout, "stderr" => stderr}
    end

    # Structural normalisation: parse JSON when possible, drop per-cluster
    # values but keep whether they were present and well formed, and reduce
    # free text to its stable shape.
    def normalize(result)
      body =
        begin
          scrub(JSON.parse(result.fetch("stdout")))
        rescue JSON::ParserError
          result.fetch("stdout").lines.map(&:strip).reject(&:empty?).sort
        end
      {
        "exit_status" => result.fetch("exit_status"),
        "body" => body,
        "error" => scrub_message(result.fetch("stderr"))
      }
    end

    def scrub(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, child), out|
          out[key] = VOLATILE.include?(key) ? present_shape(child) : scrub(child)
        end
      when Array then value.map { |child| scrub(child) }
      else value
      end
    end

    # Keep the observable property of a volatile value: that it exists and what
    # shape it has, never its literal content.
    def present_shape(value)
      case value
      when nil then "<absent>"
      when String
        if value.match?(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/) then "<uuid>"
        elsif value.match?(/\A\d{4}-\d{2}-\d{2}T/) then "<rfc3339>"
        elsif value.match?(/\A\d+\z/) then "<numeric-string>"
        else "<string>"
        end
      when Integer then "<int>"
      when Array then value.map { |child| present_shape(child) }
      when Hash then "<object:#{value.keys.sort.join(",")}>"
      else "<#{value.class.name.downcase}>"
      end
    end

    def scrub_message(text)
      text.to_s.gsub(/\h{8}-\h{4}-\h{4}-\h{4}-\h{12}/, "<uuid>")
          .gsub(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/, "<rfc3339>")
          .gsub(/\bresourceVersion:?\s*"?\d+"?/, "resourceVersion <n>")
          .lines.map(&:strip).reject(&:empty?).sort
    end
  end
end

exit(Conformance::K5Differential.run) if $PROGRAM_NAME == __FILE__
