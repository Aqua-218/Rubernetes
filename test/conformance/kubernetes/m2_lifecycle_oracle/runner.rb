#!/usr/bin/env ruby
# frozen_string_literal: true

# Privileged entrypoint for the M2 Kubernetes lifecycle oracle.
#
# The entrypoint is intentionally fail-closed. It does not select a CNI, use a
# host default network, or turn an arbitrary local runtime into an oracle. A
# repository CNI lock and immutable containerd/runc identities are prerequisites
# for invoking the privileged harness.
#
# Flow: request (stdin) -> CNI lock -> Kubernetes source lock -> privileged
# backend -> self-contained node image + runtime identities -> harness ->
# normalized response (stdout). Every identity the harness reports is checked
# against what this runner established independently.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "shellwords"

require_relative "../../../../tools/milestones/m2_kubernetes_lifecycle_oracle"

module M2KubernetesLifecycleOracleRunner
  module_function

  ROOT = M2KubernetesLifecycleOracle::ROOT
  CONTRACT = M2KubernetesLifecycleOracle.contract
  REQUIRED_CASES = M2KubernetesLifecycleOracle::REQUIRED_CASES
  HARNESS_PATH = File.join(__dir__, "harness.rb").freeze
  NODE_IMAGE_PATH = File.join(__dir__, "node_image.rb").freeze
  HARNESS_COMMAND_ENV = "RUBERNETES_M2_LIFECYCLE_HARNESS_COMMAND"

  def run
    request = read_request
    lock_status = M2KubernetesLifecycleOracle.cni_lock_status
    return [blocked(request, lock_status.fetch("errors").first), 2] unless lock_status.fetch("available")

    validate_kubernetes_lock!
    verify_privileged_isolated_backend!
    image = build_self_contained_image!(request)
    runtime = image.fetch("runtime")
    host_runtime = runtime_identities!
    if host_runtime.fetch("available")
      # Explicit host reuse is only honest when the host binaries are the very
      # bytes that run inside the oracle node.
      %w[containerd runc].each do |name|
        host = host_runtime.fetch("identities").fetch(name)
        unless host.fetch("binary_sha256") == runtime.fetch(name).fetch("binary_sha256")
          raise M2KubernetesLifecycleOracle::OracleError,
                "host #{name} #{host.fetch("path")} (#{host.fetch("binary_sha256")}) is not the oracle node runtime (#{runtime.fetch(name).fetch("binary_sha256")}); host reuse refused"
        end
      end
      runtime = host_runtime.fetch("identities")
    end
    harness_command, harness_identity = harness_command_identity
    harness_output, harness_stderr, harness_status = run_harness(harness_command, request, image, runtime)
    unless harness_status.success?
      detail = harness_stderr.to_s.strip
      detail = harness_failure_detail(harness_output) if detail.empty?
      raise M2KubernetesLifecycleOracle::OracleError,
            "privileged lifecycle harness failed: #{detail.empty? ? "exit status #{harness_status.exitstatus || 1}" : detail}"
    end
    harness = JSON.parse(harness_output, max_nesting: 512)
    response = normalize_harness(harness, request, runtime, lock_status.fetch("lock"), image, harness_identity)
    [response, response.fetch("passed") ? 0 : 1]
  rescue JSON::ParserError => error
    [failure("privileged lifecycle harness returned invalid JSON: #{error.message}"), 1]
  rescue M2KubernetesLifecycleOracle::OracleError, SystemCallError, ArgumentError, KeyError => error
    [failure(error.message), 1]
  end

  def harness_failure_detail(output)
    document = JSON.parse(output.to_s, max_nesting: 512)
    document.is_a?(Hash) ? Array(document["errors"]).join("; ") : ""
  rescue JSON::ParserError
    ""
  end

  def read_request
    request = JSON.parse($stdin.read, create_additions: false, max_nesting: 512)
    unless request.is_a?(Hash) && request["schema_version"] == 1 &&
           request["suite"] == "m2-kubernetes-lifecycle-oracle" &&
           request["kubernetes_version"] == M2KubernetesLifecycleOracle::KUBERNETES_VERSION &&
           request["source_commit"] == M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT
      raise M2KubernetesLifecycleOracle::OracleError, "lifecycle oracle request is not pinned to Kubernetes v1.36.2"
    end
    unless M2KubernetesLifecycleOracle.valid_digest?(request["request_seed_sha256"])
      raise M2KubernetesLifecycleOracle::OracleError, "lifecycle oracle request_seed_sha256 is required"
    end
    expected_seed = M2KubernetesLifecycleOracle.canonical_digest(request.reject { |key, _| key == "request_seed_sha256" })
    raise M2KubernetesLifecycleOracle::OracleError, "lifecycle oracle request seed digest does not match" unless expected_seed == request["request_seed_sha256"]
    fixture = M2KubernetesLifecycleOracle.fixture_document
    raise M2KubernetesLifecycleOracle::OracleError, "lifecycle oracle fixture digest does not match" unless request["fixture_sha256"] == M2KubernetesLifecycleOracle.canonical_digest(fixture.fetch("cases"))
    raise M2KubernetesLifecycleOracle::OracleError, "lifecycle oracle timeline digest does not match" unless request["timeline_sha256"] == M2KubernetesLifecycleOracle.canonical_digest(fixture.fetch("timeline"))
    request_cases = request["cases"]
    unless request_cases.is_a?(Hash) && request_cases.keys.map(&:to_s).sort == REQUIRED_CASES.sort
      raise M2KubernetesLifecycleOracle::OracleError, "lifecycle oracle request case inventory is incomplete"
    end
    request
  end

  def blocked(request, blocker)
    {
      "schema_version" => 1,
      "suite" => "m2-kubernetes-lifecycle-oracle",
      "executed" => false,
      "status" => "BLOCKED",
      "passed" => false,
      "blocker" => blocker,
      "kubernetes_version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "input_sha256" => request["input_sha256"],
      "input_file_count" => request["input_file_count"],
      "fixture_sha256" => request["fixture_sha256"],
      "timeline_sha256" => request["timeline_sha256"],
      "request_seed_sha256" => request["request_seed_sha256"],
      "comparison_count" => 0,
      "missing_comparison_count" => REQUIRED_CASES.length,
      "comparisons" => [],
      "errors" => [blocker]
    }
  end

  def validate_kubernetes_lock!
    lock = M2KubernetesLifecycleOracle.parse_json(M2KubernetesLifecycleOracle::KUBERNETES_LOCK_PATH)
    source = lock.is_a?(Hash) ? lock["source"] : nil
    unless source.is_a?(Hash) && source["tag"] == M2KubernetesLifecycleOracle::KUBERNETES_VERSION && source["commit"] == M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT
      raise M2KubernetesLifecycleOracle::OracleError, "Kubernetes lock does not identify v1.36.2 at #{M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT}"
    end
    source_env = CONTRACT.fetch("kubernetes").fetch("source_checkout_env")
    source_root = ENV.fetch(source_env, "").strip
    raise M2KubernetesLifecycleOracle::OracleError, "#{source_env} must point to the pinned Kubernetes source checkout" if source_root.empty? || !File.directory?(source_root)
    stdout, _stderr, status = Open3.capture3("git", "-C", source_root, "rev-parse", "HEAD")
    unless status.success? && stdout.strip == M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT
      raise M2KubernetesLifecycleOracle::OracleError, "Kubernetes source checkout is not #{M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT}"
    end
    tag_stdout, _tag_stderr, tag_status = Open3.capture3("git", "-C", source_root, "describe", "--tags", "--exact-match", "HEAD")
    unless tag_status.success? && tag_stdout.strip == M2KubernetesLifecycleOracle::KUBERNETES_VERSION
      raise M2KubernetesLifecycleOracle::OracleError, "Kubernetes source checkout is not tagged #{M2KubernetesLifecycleOracle::KUBERNETES_VERSION}"
    end
    dirty_stdout, _dirty_stderr, dirty_status = Open3.capture3("git", "-C", source_root, "status", "--porcelain", "--untracked-files=no")
    raise M2KubernetesLifecycleOracle::OracleError, "Kubernetes source checkout has tracked modifications" unless dirty_status.success? && dirty_stdout.strip.empty?
  end

  # Host runtime reuse is only attempted when both binary paths are set
  # explicitly. Nothing is ever inferred from PATH: the host runs an unrelated
  # containerd (k3s / Docker) that is not the oracle's runtime.
  def runtime_identities!
    runtime_contract = CONTRACT.fetch("runtime")
    paths = %w[containerd runc].to_h { |name| [name, ENV.fetch(runtime_contract.fetch("#{name}_path_env"), "").strip] }
    if paths.values.any?(&:empty?)
      return {"available" => false, "error" => "host runtime reuse not requested (#{paths.keys.map { |name| runtime_contract.fetch("#{name}_path_env") }.join(" and ")} are not both set)"}
    end
    runtime = {}
    paths.each do |name, path|
      command = Shellwords.split(ENV.fetch(runtime_contract.fetch("#{name}_command_env"), path))
      raise M2KubernetesLifecycleOracle::OracleError, "#{name} command is empty" if command.empty?
      stdout, stderr, status = Open3.capture3(*command, "--version", chdir: ROOT)
      raise M2KubernetesLifecycleOracle::OracleError, "#{name} version command failed: #{stderr.to_s.strip}" unless status.success?
      real_path = File.realpath(path)
      raise M2KubernetesLifecycleOracle::OracleError, "#{name} binary is not a regular file" unless File.file?(real_path)
      runtime[name] = {
        "path" => real_path,
        "version" => stdout.to_s.lines.first.to_s.strip,
        "binary_sha256" => Digest::SHA256.file(real_path).hexdigest,
        "identity_method" => "realpath+version+binary_sha256"
      }
    rescue Errno::ENOENT => error
      raise M2KubernetesLifecycleOracle::OracleError, "#{name} immutable identity is unavailable: #{error.message}"
    end
    {"available" => true, "identities" => runtime}
  end

  def self_contained_image_command
    env_name = CONTRACT.fetch("kubernetes").fetch("self_contained_image").fetch("build_command_env")
    configured = ENV.fetch(env_name, "").strip
    command = configured.empty? ? [RbConfig.ruby, NODE_IMAGE_PATH] : Shellwords.split(configured)
    raise M2KubernetesLifecycleOracle::OracleError, "#{env_name} is empty" if command.empty?
    command
  end

  def build_self_contained_image!(request)
    command = self_contained_image_command
    stdout, stderr, status = Open3.capture3(
      *command,
      stdin_data: JSON.generate({"kubernetes_version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
                                 "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
                                 "request" => request}),
      chdir: ROOT
    )
    unless status.success?
      raise M2KubernetesLifecycleOracle::OracleError, "self-contained lifecycle image build failed: #{stderr.to_s.strip.empty? ? "exit status #{status.exitstatus || 1}" : stderr.to_s.strip}"
    end
    document = JSON.parse(stdout, create_additions: false, max_nesting: 128)
    image = document.is_a?(Hash) ? document["image"] : nil
    runtime = document.is_a?(Hash) ? document["runtime"] : nil
    unless image.is_a?(String) && image.match?(/\A[^@]+@sha256:[0-9a-f]{64}\z/)
      raise M2KubernetesLifecycleOracle::OracleError, "self-contained lifecycle image identity must be digest-pinned"
    end
    unless document["source_commit"] == M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT
      raise M2KubernetesLifecycleOracle::OracleError, "self-contained lifecycle image was not built from the pinned Kubernetes source"
    end
    unless runtime.is_a?(Hash) && %w[containerd runc].all? do |name|
             identity = runtime[name]
             identity.is_a?(Hash) && identity["path"].is_a?(String) && !identity["path"].empty? &&
               identity["version"].is_a?(String) && !identity["version"].empty? &&
               M2KubernetesLifecycleOracle.valid_digest?(identity["binary_sha256"]) &&
               identity["identity_method"].is_a?(String) && !identity["identity_method"].empty?
           end
      raise M2KubernetesLifecycleOracle::OracleError, "self-contained lifecycle image must report immutable containerd and runc identities"
    end
    %w[containerd runc].each do |name|
      identity = runtime.fetch(name)
      real_path = File.realpath(identity.fetch("path"))
      actual = Digest::SHA256.file(real_path).hexdigest
      raise M2KubernetesLifecycleOracle::OracleError, "self-contained #{name} binary at #{real_path} hashes to #{actual}, not #{identity["binary_sha256"]}" unless actual == identity["binary_sha256"]
      runtime[name] = identity.merge("path" => real_path)
    end
    document.merge("image" => image, "runtime" => runtime, "command" => command)
  rescue JSON::ParserError => error
    raise M2KubernetesLifecycleOracle::OracleError, "self-contained lifecycle image builder returned invalid JSON: #{error.message}"
  rescue Errno::ENOENT, Errno::EACCES => error
    raise M2KubernetesLifecycleOracle::OracleError, "self-contained lifecycle image runtime binary is unavailable: #{error.message}"
  end

  def verify_privileged_isolated_backend!
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle oracle requires uid 0" unless Process.uid.zero?
    backend = ENV.fetch(CONTRACT.fetch("isolation").fetch("backend_env"), "docker")
    command = Shellwords.split(backend)
    raise M2KubernetesLifecycleOracle::OracleError, "lifecycle isolation backend is empty" if command.empty?
    _stdout, stderr, status = Open3.capture3(*command, "info", chdir: ROOT)
    raise M2KubernetesLifecycleOracle::OracleError, "lifecycle isolation backend is unavailable: #{stderr.to_s.strip}" unless status.success?
    true
  end

  # The built-in harness is the default; an external harness argv is allowed
  # only through the contract env and is recorded with its real file identity.
  def harness_command_identity
    configured = ENV.fetch(HARNESS_COMMAND_ENV, "").strip
    command = configured.empty? ? [RbConfig.ruby, HARNESS_PATH] : Shellwords.split(configured)
    raise M2KubernetesLifecycleOracle::OracleError, "#{HARNESS_COMMAND_ENV} is empty" if command.empty?
    script = command.find { |word| word.end_with?(".rb") && File.file?(File.expand_path(word, ROOT)) } || command.first
    path = File.expand_path(script, ROOT)
    identity = {
      "command" => command,
      "mode" => configured.empty? ? "built_in" : "external",
      "path" => File.file?(path) ? File.realpath(path) : path,
      "sha256" => File.file?(path) ? Digest::SHA256.file(path).hexdigest : nil
    }
    [command, identity]
  end

  def run_harness(command, request, image, runtime)
    input = {"request" => request, "node_image" => image.fetch("image"), "runtime" => runtime, "node_image_document" => image.reject { |key, _| key == "request" }}
    Open3.capture3(*command, stdin_data: JSON.generate(input), chdir: ROOT)
  end

  def normalize_harness(harness, request, runtime, cni, image, harness_identity)
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness output must be an object" unless harness.is_a?(Hash)
    unless harness["status"] == "PASS" && harness["passed"] == true && harness["errors"].is_a?(Array) && harness["errors"].empty?
      detail = Array(harness["errors"]).join("; ")
      raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness status, passed, and empty errors are required#{detail.empty? ? "" : ": #{detail}"}"
    end
    trace = harness["trace"]
    observations = harness["observations"] || harness["cases"]
    source = harness["source"]
    unless trace.is_a?(Array) && !trace.empty? && observations.is_a?(Hash) && source.is_a?(Hash)
      raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness must return source, observations, and a non-empty trace"
    end
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness must echo request_seed_sha256" unless harness["request_seed_sha256"] == request["request_seed_sha256"]
    REQUIRED_CASES.each do |name|
      observable = M2KubernetesLifecycleOracle.observable_from_entry(observations[name] || observations[name.to_sym])
      M2KubernetesLifecycleOracle::REQUIRED_OBSERVABLE_FIELDS.fetch(name).each do |field|
        unless observable.is_a?(Hash) && observable.key?(field)
          raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness case #{name} is missing observable field #{field}"
        end
      end
    end
    %w[kubelet_image apiserver_image etcd_image].each do |key|
      value = source[key]
      raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness source #{key} is required" unless value.is_a?(String) && value.match?(/\A[^@]+@sha256:[0-9a-f]{64}\z/)
    end
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness kubelet image #{source["kubelet_image"]} is not the built node image #{image.fetch("image")}" unless source["kubelet_image"] == image.fetch("image")
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness must prove network isolation" unless source["network_isolated"] == true
    expected_cni = cni.slice("plugin", "version", "source_commit", "image_reference", "image_digest", "config_sha256")
    actual_cni = harness["cni"] || source["cni"]
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness CNI identity is required" unless actual_cni == expected_cni
    harness_runtime = harness["runtime"] || source["runtime"]
    raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness runtime identity is required" unless harness_runtime.is_a?(Hash)
    %w[containerd runc].each do |name|
      reported = harness_runtime[name]
      unless reported.is_a?(Hash) && reported["in_node_sha256"] == runtime.fetch(name).fetch("binary_sha256") && reported["binary_sha256"] == runtime.fetch(name).fetch("binary_sha256")
        raise M2KubernetesLifecycleOracle::OracleError, "privileged lifecycle harness #{name} identity does not match the runner's #{name} identity"
      end
      runtime[name] = runtime.fetch(name).merge(reported.slice("in_node_path", "in_node_sha256", "in_node_version"))
    end
    runner = {
      "version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "runner_sha256" => Digest::SHA256.file(__FILE__).hexdigest,
      "command" => [RbConfig.ruby, __FILE__],
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "privileged Kubernetes kubelet lifecycle harness",
      "harness" => harness_identity,
      "node_image_builder" => {"command" => image["command"], "builder_sha256" => image["builder_sha256"], "node_image_lock_sha256" => image["node_image_lock_sha256"]},
      "process_id" => Process.pid
    }
    {
      "schema_version" => 1,
      "suite" => "m2-kubernetes-lifecycle-oracle",
      "executed" => true,
      "status" => "PASS",
      "passed" => true,
      "kubernetes_version" => M2KubernetesLifecycleOracle::KUBERNETES_VERSION,
      "source_commit" => M2KubernetesLifecycleOracle::KUBERNETES_SOURCE_COMMIT,
      "input_sha256" => request["input_sha256"],
      "input_file_count" => request["input_file_count"],
      "fixture_sha256" => request["fixture_sha256"],
      "timeline_sha256" => request["timeline_sha256"],
      "request_seed_sha256" => request["request_seed_sha256"],
      "source" => source.merge("runtime" => runtime, "cni" => actual_cni, "harness" => harness_identity, "node_image" => image.slice("image", "image_id", "images", "kind", "base_image", "node_image_lock_sha256")),
      "runtime" => runtime,
      "cni" => actual_cni,
      "trace" => trace,
      "observations" => observations,
      "observations_sha256" => M2KubernetesLifecycleOracle.canonical_digest(observations),
      "runner" => runner,
      "comparisons" => REQUIRED_CASES.map { |name| {"id" => name, "attempt_count" => 1} },
      "errors" => []
    }
  end

  def failure(message)
    {
      "schema_version" => 1,
      "suite" => "m2-kubernetes-lifecycle-oracle",
      "executed" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "errors" => [message]
    }
  end
end

response, status = M2KubernetesLifecycleOracleRunner.run
puts JSON.generate(response)
exit(status)
