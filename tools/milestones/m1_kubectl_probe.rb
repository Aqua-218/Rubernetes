#!/usr/bin/env ruby
# frozen_string_literal: true

# Run the pinned upstream kubectl against the Rubernetes HTTP transport. The
# executable is accepted only when its bytes match the architecture-specific
# Kubernetes v1.36.2 release digest.

require "tmpdir"
require "yaml"
require_relative "m1_gate"
require_relative "m1_probe_support"

KUBECTL_SHA256 = {
  "amd64" => "1e9045ec32bea85da43de85f0065358529ea7c7a152eca78154fba5b58c27d82",
  "arm64" => "c957eb8c4bea27a3bb35b269edd9082e27f027f7b76b20b5bf4afebc726c6d3e"
}.freeze

def kubectl_architecture
  case RbConfig::CONFIG.fetch("host_cpu")
  when "x86_64", "amd64" then "amd64"
  when "aarch64", "arm64" then "arm64"
  else
    raise M1ProbeSupport::ProbeError,
          "official kubectl digest is not pinned for #{RbConfig::CONFIG.fetch("host_cpu")}"
  end
end

def kubectl_operation(name, command, expected_exit: 0, &semantic_check)
  result = M1ProbeSupport.run_command(*command)
  exit_matched = result.fetch("exit_status") == expected_exit
  semantic_passed = exit_matched && semantic_check.call(result.fetch("stdout"), result.fetch("stderr"))
  {
    "operation" => name,
    "command" => result.fetch("command"),
    "stdout" => result.fetch("stdout"),
    "stderr" => result.fetch("stderr"),
    "exit_status" => result.fetch("exit_status"),
    "expected_exit_status" => expected_exit,
    "semantic_passed" => semantic_passed == true,
    "attempt_count" => 1,
    "passed" => exit_matched && semantic_passed == true
  }.tap do |record|
    record["error"] = result.fetch("error") if result.key?("error")
  end
end

M1ProbeSupport.run_probe("m1_kubectl_transcript") do |_current, input|
  architecture = kubectl_architecture
  binary = File.join(ROOT, "build/tools/kubectl-v1.36.2")
  raise M1ProbeSupport::ProbeError, "pinned kubectl is missing: #{binary}" unless File.file?(binary)
  raise M1ProbeSupport::ProbeError, "pinned kubectl is not executable: #{binary}" unless File.executable?(binary)

  expected_digest = KUBECTL_SHA256.fetch(architecture)
  actual_digest = Digest::SHA256.file(binary).hexdigest
  unless actual_digest == expected_digest
    raise M1ProbeSupport::ProbeError,
          "kubectl v1.36.2 SHA-256 mismatch for linux/#{architecture}: expected #{expected_digest}, got #{actual_digest}"
  end

  $LOAD_PATH.unshift(File.join(ROOT, "lib")) unless $LOAD_PATH.include?(File.join(ROOT, "lib"))
  require "rubernetes/transport"
  api_server, _store, _registry_document = M1ProbeSupport.build_api_server
  http_server = Rubernetes::Transport::HTTPServer.new(
    api_server,
    host: "127.0.0.1",
    port: 0,
    read_timeout: 5,
    write_timeout: 5,
    shutdown_timeout: 2
  )
  http_server.start
  operations = []

  begin
    Dir.mktmpdir("rubernetes-m1-kubectl-") do |directory|
      kubeconfig = File.join(directory, "kubeconfig.yaml")
      manifest = File.join(directory, "configmap.yaml")
      File.write(
        kubeconfig,
        YAML.dump(
          "apiVersion" => "v1",
          "kind" => "Config",
          "clusters" => [{"name" => "m1", "cluster" => {"server" => http_server.endpoint}}],
          "contexts" => [{"name" => "m1", "context" => {"cluster" => "m1", "user" => "m1"}}],
          "current-context" => "m1",
          "users" => [{"name" => "m1", "user" => {}}]
        )
      )
      File.write(
        manifest,
        YAML.dump(
          "apiVersion" => "v1",
          "kind" => "ConfigMap",
          "metadata" => {"name" => "m1-evidence", "namespace" => "default"},
          "data" => {"phase" => "apply"}
        )
      )
      base = [binary, "--kubeconfig", kubeconfig]

      operations << kubectl_operation(
        "get",
        base + ["get", "configmaps", "--namespace", "default", "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        %w[ConfigMapList List].include?(document["kind"]) && Array(document["items"]).empty?
      rescue JSON::ParserError
        false
      end

      invalid_manifest = File.join(directory, "invalid.yaml")
      File.write(
        invalid_manifest,
        YAML.dump(
          "apiVersion" => "v1",
          "kind" => "ConfigMap",
          "metadata" => {"name" => "m1-invalid", "namespace" => "default"},
          "dataz" => {"phase" => "apply"}
        )
      )
      namespace = "m1-evidence"

      operations << kubectl_operation(
        "create-namespace",
        base + ["create", "namespace", namespace, "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document["kind"] == "Namespace" && document.dig("metadata", "name") == namespace
      rescue JSON::ParserError
        false
      end

      # Typed clientset path: kubectl create deployment sends and receives
      # application/vnd.kubernetes.protobuf.
      operations << kubectl_operation(
        "create-deployment",
        base + ["create", "deployment", "m1-web", "--image", "registry.k8s.io/pause:3.10", "--replicas", "1",
                "--namespace", namespace, "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document["kind"] == "Deployment" && document.dig("spec", "replicas") == 1
      rescue JSON::ParserError
        false
      end

      operations << kubectl_operation(
        "scale",
        base + ["scale", "deployment", "m1-web", "--replicas", "2", "--namespace", namespace, "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document["kind"] == "Deployment" && document.dig("spec", "replicas") == 2
      rescue JSON::ParserError
        false
      end

      operations << kubectl_operation(
        "expose",
        base + ["expose", "deployment", "m1-web", "--port", "80", "--namespace", namespace, "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document["kind"] == "Service" && Array(document.dig("spec", "ports")).any? { |port| port["port"] == 80 }
      rescue JSON::ParserError
        false
      end

      # Strict client-side validation downloads /openapi/v2 as protobuf.
      operations << kubectl_operation(
        "apply",
        base + ["apply", "--validate=strict", "--filename", manifest, "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document["kind"] == "ConfigMap" && document.dig("data", "phase") == "apply"
      rescue JSON::ParserError
        false
      end

      operations << kubectl_operation(
        "apply-invalid",
        base + ["apply", "--validate=strict", "--filename", invalid_manifest, "--output", "json"],
        expected_exit: 1
      ) do |_stdout, stderr|
        stderr.include?("unknown field \"dataz\"")
      end

      operations << kubectl_operation(
        "patch",
        base + ["patch", "configmap", "m1-evidence", "--namespace", "default", "--type", "merge",
                "--patch", JSON.generate("data" => {"phase" => "patch"}), "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document.dig("data", "phase") == "patch"
      rescue JSON::ParserError
        false
      end

      operations << kubectl_operation(
        "label",
        base + ["label", "configmap", "m1-evidence", "--namespace", "default", "tier=evidence", "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        document.dig("metadata", "labels", "tier") == "evidence"
      rescue JSON::ParserError
        false
      end

      operations << kubectl_operation(
        "watch",
        base + ["get", "configmaps", "--namespace", "default", "--watch",
                "--output-watch-events=true", "--request-timeout", "2s", "--output", "json"]
      ) do |stdout, _stderr|
        document = JSON.parse(stdout)
        %w[ADDED MODIFIED].include?(document["type"]) &&
          document.dig("object", "metadata", "name") == "m1-evidence"
      rescue JSON::ParserError
        false
      end

      operations << kubectl_operation(
        "delete",
        base + ["delete", "configmap", "m1-evidence", "--namespace", "default", "--wait=false", "--output", "name"]
      ) { |stdout, _stderr| stdout.include?("configmap/m1-evidence") }
    end
  ensure
    http_server.stop(graceful: false)
  end

  failures = operations.count { |operation| !operation.fetch("passed") }
  names = operations.map { |operation| operation.fetch("operation") }
  structural_errors = []
  required_names = M1Gate::REQUIRED_OPERATIONS
  structural_errors << "kubectl transcript must contain each required operation once" unless names.sort == required_names.sort
  structural_errors << "kubectl apply must run strict client-side validation" unless operations.any? do |operation|
    operation["operation"] == "apply" && operation.fetch("command").include?("--validate=strict")
  end
  failure_count = failures + structural_errors.length

  {
    "kubectl_version" => "v1.36.2",
    "kubectl_platform" => "linux/#{architecture}",
    "kubectl_path" => binary.delete_prefix("#{ROOT}/"),
    "kubectl_sha256" => actual_digest,
    "expected_kubectl_sha256" => expected_digest,
    "operation_count" => operations.length,
    "operations" => operations,
    "failure_count" => failure_count,
    "errors" => structural_errors,
    "passed" => input.fetch("stable") && failure_count.zero?
  }
end
