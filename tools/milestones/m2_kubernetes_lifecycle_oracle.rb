#!/usr/bin/env ruby
# frozen_string_literal: true

# Orchestrate the independent Kubernetes v1.36.2 Pod lifecycle oracle.
#
# This file owns the boundary between production Rubernetes semantic
# observations and the privileged external runner. Native kernel-effect
# evidence is recorded separately by the lifecycle probe; this oracle never
# relabels in-process semantic checks as Native effects. It never supplies
# expected observations on behalf of Kubernetes. Missing supply-chain
# identities, an unavailable runner, malformed output, or a mismatched fixture
# all remain incomplete evidence.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "time"

require_relative "m2_gate"

module M2KubernetesLifecycleOracle
  ROOT = File.expand_path("../..", __dir__).freeze
  CONTRACT_PATH = File.join(ROOT, "test/conformance/kubernetes/m2_lifecycle_oracle/runner_contract.json").freeze
  FIXTURE_PATH = File.join(ROOT, "test/conformance/kubernetes/m2_lifecycle_oracle/fixtures/lifecycle.json").freeze
  KUBERNETES_LOCK_PATH = File.join(ROOT, "third_party/locks/kubernetes-v1.36.2.json").freeze
  CNI_LOCK_RELATIVE_PATH = "third_party/locks/m2-lifecycle-cni.json".freeze
  CNI_LOCK_PATH = File.join(ROOT, CNI_LOCK_RELATIVE_PATH).freeze
  RUNNER_PATH = File.join(ROOT, "test/conformance/kubernetes/m2_lifecycle_oracle/runner.rb").freeze
  RUNNER_LOCK_RELATIVE_PATH = "third_party/locks/m2-lifecycle-oracle-runner.json".freeze
  RUNNER_LOCK_PATH = File.join(ROOT, RUNNER_LOCK_RELATIVE_PATH).freeze
  KUBERNETES_VERSION = "v1.36.2".freeze
  KUBERNETES_SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467".freeze
  REQUIRED_CASES = %w[
    init_sidecar_app_order
    startup_liveness_readiness_thresholds
    restart_policy_and_backoff
    graceful_termination_oracle
  ].freeze
  REQUIRED_OBSERVABLE_FIELDS = {
    "init_sidecar_app_order" => %w[operations],
    "startup_liveness_readiness_thresholds" => %w[startup liveness readiness],
    "restart_policy_and_backoff" => %w[restartPolicy restartCount phase status],
    "graceful_termination_oracle" => %w[operations events]
  }.freeze
  ACTUAL_SOURCE = M2Gate::LIFECYCLE_SEMANTICS_ACTUAL_SOURCE
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/.freeze
  COMMIT_PATTERN = /\A[0-9a-f]{40}\z/.freeze
  DIGEST_PINNED_IMAGE_PATTERN = /\A[^@\s]+@sha256:[0-9a-f]{64}\z/.freeze
  CNI_LOCK_BLOCKER = M2Gate::LIFECYCLE_CNI_LOCK_BLOCKER

  class OracleError < StandardError; end

  module_function

  def canonical_value(value, excluded_keys = [])
    excluded = Array(excluded_keys).map(&:to_s)
    case value
    when Hash
      value.keys.map(&:to_s).reject { |key| excluded.include?(key) }.sort.each_with_object({}) do |key, result|
        source_key = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_value(value.fetch(source_key), [])
      end
    when Array
      value.map { |child| canonical_value(child, []) }
    else
      value
    end
  end

  def canonical_digest(value, excluded_keys: [])
    Digest::SHA256.hexdigest(JSON.generate(canonical_value(value, excluded_keys)))
  end

  def valid_digest?(value)
    value.is_a?(String) && SHA256_PATTERN.match?(value)
  end

  def valid_commit?(value)
    value.is_a?(String) && COMMIT_PATTERN.match?(value)
  end

  def digest_pinned_image?(value)
    value.is_a?(String) && DIGEST_PINNED_IMAGE_PATTERN.match?(value)
  end

  def parse_json(path)
    JSON.parse(File.binread(path), max_nesting: 512)
  rescue Errno::ENOENT => error
    raise OracleError, "JSON input is missing: #{path}: #{error.message}"
  rescue JSON::ParserError => error
    raise OracleError, "JSON input is invalid: #{path}: #{error.message}"
  end

  def contract(path = CONTRACT_PATH)
    document = parse_json(path)
    raise OracleError, "lifecycle oracle runner contract must be an object" unless document.is_a?(Hash)
    raise OracleError, "lifecycle oracle runner contract schema_version must be 1" unless document["schema_version"] == 1
    document
  end

  def fixture_document(path = FIXTURE_PATH)
    document = parse_json(path)
    unless document.is_a?(Hash) && document["schema_version"] == 1 &&
           document["kubernetes_version"] == KUBERNETES_VERSION &&
           document["source_commit"] == KUBERNETES_SOURCE_COMMIT
      raise OracleError, "lifecycle oracle fixture is not pinned to Kubernetes #{KUBERNETES_VERSION} at #{KUBERNETES_SOURCE_COMMIT}"
    end
    timeline = document["timeline"]
    cases = document["cases"]
    raise OracleError, "lifecycle oracle fixture timeline must be a non-empty array" unless timeline.is_a?(Array) && !timeline.empty?
    raise OracleError, "lifecycle oracle fixture cases must be an object" unless cases.is_a?(Hash)
    missing = REQUIRED_CASES - cases.keys.map(&:to_s)
    raise OracleError, "lifecycle oracle fixture is missing cases: #{missing.join(", ")}" unless missing.empty?
    validate_fixture_images!(cases)
    document
  end

  def fixture_cases(path = FIXTURE_PATH)
    fixture_document(path).fetch("cases")
  end

  def fixture_timeline(path = FIXTURE_PATH)
    fixture_document(path).fetch("timeline")
  end

  def validate_fixture_images!(cases)
    lock = parse_json(KUBERNETES_LOCK_PATH)
    busybox = lock.dig("runner_support_images", "busybox")
    expected_reference = busybox.is_a?(Hash) ? busybox["reference"].to_s : ""
    expected_digest = busybox.is_a?(Hash) ? busybox.dig("platforms", "linux/amd64").to_s.delete_prefix("sha256:") : ""
    raise OracleError, "Kubernetes lock does not provide an amd64 busybox image digest" unless expected_reference.match?(/\A[^:]+:[^:]+\z/) && valid_digest?(expected_digest)
    expected_image = expected_reference.sub(/:[^:]+\z/, "@sha256:#{expected_digest}")
    images = []
    walk = lambda do |value|
      case value
      when Hash
        images << value["image"] if value["image"].is_a?(String)
        value.each_value { |child| walk.call(child) }
      when Array
        value.each { |child| walk.call(child) }
      end
    end
    walk.call(cases)
    raise OracleError, "lifecycle oracle fixture must include at least one pinned workload image" if images.empty?
    invalid = images.uniq.reject { |image| image == expected_image }
    raise OracleError, "lifecycle oracle fixture image is not the locked amd64 busybox digest: #{invalid.join(", ")}" unless invalid.empty?
    true
  end

  def source_identity(input)
    hash = input.is_a?(Hash) ? input : {}
    sha256 = hash["sha256"] || hash[:sha256]
    file_count = hash["file_count"] || hash[:file_count]
    raise OracleError, "source input SHA-256 is required" unless valid_digest?(sha256)
    raise OracleError, "source input file count must be positive" unless file_count.is_a?(Integer) && file_count.positive?
    {"sha256" => sha256, "file_count" => file_count}
  end

  def request_document(input:, fixture_path: FIXTURE_PATH)
    source = source_identity(input)
    fixture = fixture_document(fixture_path)
    cases = fixture.fetch("cases")
    timeline = fixture.fetch("timeline")
    request = {
      "schema_version" => 1,
      "suite" => "m2-kubernetes-lifecycle-oracle",
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => KUBERNETES_SOURCE_COMMIT,
      "input_sha256" => source.fetch("sha256"),
      "input_file_count" => source.fetch("file_count"),
      "fixture_sha256" => canonical_digest(cases),
      "timeline_sha256" => canonical_digest(timeline),
      "cases" => REQUIRED_CASES.each_with_object({}) { |name, result| result[name] = cases.fetch(name) },
      "timeline" => timeline
    }
    request["request_seed_sha256"] = canonical_digest(request)
    request
  end

  def cni_lock_status(path = CNI_LOCK_PATH)
    relative_path = if File.expand_path(path) == CNI_LOCK_PATH
                      CNI_LOCK_RELATIVE_PATH
                    else
                      path.to_s
                    end
    unless File.file?(path) && !File.symlink?(path)
      return {
        "available" => false,
        "path" => relative_path,
        "errors" => [CNI_LOCK_BLOCKER]
      }
    end

    document = parse_json(path)
    required_fields = %w[plugin version source_commit image_reference image_digest config_sha256]
    unless document.is_a?(Hash)
      return {"available" => false, "path" => relative_path, "errors" => ["CNI lock #{relative_path} must be an object"]}
    end
    missing = required_fields.reject { |field| document[field].is_a?(String) && !document[field].empty? }
    errors = missing.map { |field| "CNI lock #{relative_path} is missing #{field}" }
    errors << "CNI lock #{relative_path} source_commit must be a 40-character commit" unless valid_commit?(document["source_commit"])
    errors << "CNI lock #{relative_path} image_digest must be a SHA-256 digest" unless valid_digest?(document["image_digest"])
    errors << "CNI lock #{relative_path} config_sha256 must be a SHA-256 digest" unless valid_digest?(document["config_sha256"])
    image_reference = document["image_reference"]
    unless digest_pinned_image?(image_reference)
      errors << "CNI lock #{relative_path} image_reference must be digest-pinned"
    else
      expected_digest = image_reference.split("@sha256:", 2).last
      errors << "CNI lock #{relative_path} image_reference digest must match image_digest" unless expected_digest == document["image_digest"]
    end
    if document.key?("lock_sha256")
      errors << "CNI lock #{relative_path} lock_sha256 must be a SHA-256 digest" unless valid_digest?(document["lock_sha256"])
      if valid_digest?(document["lock_sha256"])
        errors << "CNI lock #{relative_path} lock_sha256 does not match canonical content" unless
          document["lock_sha256"] == canonical_digest(document, excluded_keys: ["lock_sha256"])
      end
    end
    {
      "available" => errors.empty?,
      "path" => relative_path,
      "lock" => document,
      "errors" => errors
    }
  rescue OracleError => error
    {"available" => false, "path" => relative_path, "errors" => [error.message]}
  end

  def default_command(contract_document)
    command_env = contract_document.dig("isolation", "runner_command_env") || "RUBERNETES_M2_LIFECYCLE_ORACLE_COMMAND"
    configured = ENV[command_env].to_s.strip
    return Shellwords.split(configured) unless configured.empty?

    [RbConfig.ruby, RUNNER_PATH]
  end

  def built_in_command
    [RbConfig.ruby, RUNNER_PATH]
  end

  # Resolve the only runner command that is trusted by default. A configured
  # external command remains supported only when a repository lock binds its
  # exact argv and the real executable/runner bytes to immutable SHA-256
  # identities. The command output can never choose its own trust anchor.
  def runner_identity(command)
    words = Array(command).map(&:to_s)
    raise OracleError, "lifecycle oracle runner command is empty" if words.empty?

    if words == built_in_command
      runner_path = immutable_file_identity(RUNNER_PATH, "built-in lifecycle oracle runner")
      executable = immutable_file_identity(RbConfig.ruby, "Ruby executable")
      return runner_path.merge(
        "command" => words,
        "mode" => "built_in",
        "runner_path" => runner_path.fetch("path"),
        "runner_sha256" => runner_path.fetch("sha256"),
        "executable_path" => executable.fetch("path"),
        "executable_sha256" => executable.fetch("sha256")
      )
    end

    lock = runner_lock_document
    raise OracleError, "external lifecycle oracle command is not the built-in pinned runner and no immutable runner lock is present" unless lock
    validate_runner_lock!(lock, words)
    runner_path = immutable_file_identity(lock.fetch("runner_path"), "locked lifecycle oracle runner")
    executable_path = immutable_file_identity(lock.fetch("executable_path"), "locked lifecycle oracle executable")
    {
      "command" => words,
      "mode" => "locked_external",
      "path" => runner_path.fetch("path"),
      "sha256" => runner_path.fetch("sha256"),
      "runner_path" => runner_path.fetch("path"),
      "runner_sha256" => runner_path.fetch("sha256"),
      "executable_path" => executable_path.fetch("path"),
      "executable_sha256" => executable_path.fetch("sha256"),
      "lock_path" => RUNNER_LOCK_RELATIVE_PATH,
      "lock_sha256" => lock.fetch("lock_sha256")
    }
  end

  def immutable_file_identity(path, label)
    value = path.to_s
    raise OracleError, "#{label} path is required" if value.empty?
    raise OracleError, "#{label} path must not contain NUL" if value.include?("\0")
    expanded = File.expand_path(value, ROOT)
    raise OracleError, "#{label} path must not be a symlink" if File.symlink?(expanded)

    real_path = File.realpath(value, ROOT)
    raise OracleError, "#{label} is not a regular non-symlink file" unless File.file?(real_path) && !File.symlink?(real_path)

    {"path" => real_path, "sha256" => Digest::SHA256.file(real_path).hexdigest}
  rescue Errno::ENOENT, Errno::EACCES => error
    raise OracleError, "#{label} is unavailable: #{error.message}"
  end

  def runner_lock_document
    return nil unless File.file?(RUNNER_LOCK_PATH) && !File.symlink?(RUNNER_LOCK_PATH)

    document = parse_json(RUNNER_LOCK_PATH)
    raise OracleError, "lifecycle oracle runner lock must be an object" unless document.is_a?(Hash)
    document
  rescue Errno::ENOENT
    nil
  end

  def validate_runner_lock!(lock, command)
    raise OracleError, "lifecycle oracle runner lock schema_version must be 1" unless lock["schema_version"] == 1
    locked_command = lock["command"]
    raise OracleError, "lifecycle oracle runner lock command must be an exact argv" unless
      locked_command.is_a?(Array) && !locked_command.empty? && locked_command.all? { |part| part.is_a?(String) && !part.empty? }
    raise OracleError, "lifecycle oracle command does not match the immutable runner lock" unless command == locked_command
    %w[runner_path executable_path].each do |key|
      raise OracleError, "lifecycle oracle runner lock #{key} is required" unless lock[key].is_a?(String) && !lock[key].empty?
    end
    %w[runner_sha256 executable_sha256 lock_sha256].each do |key|
      raise OracleError, "lifecycle oracle runner lock #{key} must be a SHA-256 digest" unless valid_digest?(lock[key])
    end
    raise OracleError, "lifecycle oracle runner lock digest does not match canonical content" unless
      lock["lock_sha256"] == canonical_digest(lock, excluded_keys: ["lock_sha256"])

    runner = immutable_file_identity(lock.fetch("runner_path"), "locked lifecycle oracle runner")
    executable = immutable_file_identity(lock.fetch("executable_path"), "locked lifecycle oracle executable")
    raise OracleError, "lifecycle oracle runner lock runner SHA-256 does not match the real file" unless runner["sha256"] == lock["runner_sha256"]
    raise OracleError, "lifecycle oracle runner lock executable SHA-256 does not match the real file" unless executable["sha256"] == lock["executable_sha256"]
    command_runner = command.find do |part|
      begin
        File.realpath(part, ROOT) == runner["path"]
      rescue Errno::ENOENT, Errno::EACCES
        false
      end
    end
    raise OracleError, "lifecycle oracle runner lock does not bind the runner path into argv" unless command_runner
    true
  end

  def runner_digest
    return Digest::SHA256.file(RUNNER_PATH).hexdigest if File.file?(RUNNER_PATH) && !File.symlink?(RUNNER_PATH)

    Digest::SHA256.hexdigest("missing:#{RUNNER_PATH}")
  end

  def run(input:, actual_cases:, command: nil, cni_lock_path: CNI_LOCK_PATH, fixture_path: FIXTURE_PATH)
    request = nil
    contract_document = nil
    lock_status = {"available" => false, "errors" => []}
    command_words = []
    request = request_document(input: input, fixture_path: fixture_path)
    contract_document = contract
    lock_status = cni_lock_status(cni_lock_path)
    return blocked_report(request, lock_status, contract_document) unless lock_status.fetch("available")

    command_words = if command.nil? || (command.respond_to?(:empty?) && command.empty?)
                      default_command(contract_document)
                    elsif command.is_a?(Array)
                      command.map(&:to_s)
                    else
                      Shellwords.split(command.to_s)
                    end
    runner_identity = runner_identity(command_words)

    raw_output, stderr, status = Open3.capture3(*command_words, stdin_data: JSON.generate(request), chdir: ROOT)
    raw_trace_sha256 = Digest::SHA256.hexdigest(raw_output.to_s)
    unless status.success?
      detail = stderr.to_s.strip
      if detail.empty?
        # The runner reports its own refusal as a JSON document on stdout.
        runner_errors = begin
          Array(JSON.parse(raw_output.to_s, create_additions: false)["errors"]).map(&:to_s)
        rescue JSON::ParserError, TypeError
          []
        end
        detail = runner_errors.empty? ? "exit status #{status.exitstatus || 1}" : runner_errors.join("; ")
      end
      return failed_report(
        request,
        lock_status,
        contract_document,
        command_words,
        raw_trace_sha256,
        "external lifecycle oracle command failed: #{detail}"
      )
    end
    if raw_output.to_s.strip.empty?
      return failed_report(request, lock_status, contract_document, command_words, raw_trace_sha256,
                           "external lifecycle oracle command returned no JSON")
    end

    parsed = JSON.parse(raw_output, create_additions: false, max_nesting: 512)
    normalize_external_report(
      parsed,
      request: request,
      actual_cases: actual_cases,
      lock_status: lock_status,
      contract_document: contract_document,
      command: command_words,
      runner_identity: runner_identity,
      raw_trace_sha256: raw_trace_sha256
    )
  rescue JSON::ParserError => error
    return incomplete_without_request("external lifecycle oracle returned invalid JSON: #{error.message}") unless request.is_a?(Hash)

    failed_report(request, lock_status, contract_document, command_words, raw_trace_sha256,
                  "external lifecycle oracle returned invalid JSON: #{error.message}")
  rescue OracleError => error
    return incomplete_without_request(error.message) unless request.is_a?(Hash)

    failed_report(request, lock_status, contract_document, command_words, nil, error.message)
  rescue SystemCallError => error
    message = "external lifecycle oracle command could not be executed: #{error.message}"
    return incomplete_without_request(message) unless request.is_a?(Hash)

    failed_report(request, lock_status, contract_document, command_words, nil, message)
  rescue ArgumentError => error
    message = "external lifecycle oracle command is invalid: #{error.message}"
    return incomplete_without_request(message) unless request.is_a?(Hash)

    failed_report(request, lock_status, contract_document, command_words, nil, message)
  end

  def incomplete_without_request(message)
    {
      "schema_version" => 1,
      "executed" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "comparison_count" => 0,
      "missing_comparison_count" => REQUIRED_CASES.length,
      "comparisons" => [],
      "errors" => [message.to_s]
    }
  end

  def blocked_report(request, lock_status, contract_document)
    blocker = lock_status.fetch("errors").first || CNI_LOCK_BLOCKER
    provenance = base_provenance(
      request: request,
      runner_sha256: runner_digest,
      command: default_command(contract_document),
      source: {
        "version" => KUBERNETES_VERSION,
        "commit" => KUBERNETES_SOURCE_COMMIT,
        "tag" => KUBERNETES_VERSION,
        "kubelet_image" => nil,
        "apiserver_image" => nil,
        "etcd_image" => nil,
        "runtime" => {},
        "cni" => {},
        "network_isolated" => false,
        "lock_status" => "BLOCKED",
        "missing_lock_path" => lock_status["path"]
      },
      raw_trace_sha256: nil,
      canonical_trace_sha256: nil
    )
    {
      "schema_version" => 1,
      "executed" => false,
      "status" => "BLOCKED",
      "passed" => false,
      "blocker" => blocker,
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => KUBERNETES_SOURCE_COMMIT,
      "runner_sha256" => runner_digest,
      "request_seed_sha256" => request.fetch("request_seed_sha256"),
      "input_sha256" => request.fetch("input_sha256"),
      "input_file_count" => request.fetch("input_file_count"),
      "fixture_sha256" => request.fetch("fixture_sha256"),
      "timeline_sha256" => request.fetch("timeline_sha256"),
      "raw_trace_sha256" => nil,
      "canonical_trace_sha256" => nil,
      "comparison_count" => 0,
      "missing_comparison_count" => REQUIRED_CASES.length,
      "comparisons" => [],
      "provenance" => provenance,
      "errors" => [blocker]
    }
  end

  def failed_report(request, lock_status, contract_document, command, raw_trace_sha256, error)
    provenance = base_provenance(
      request: request,
      runner_sha256: runner_digest,
      command: command || default_command(contract_document),
      source: {
        "version" => KUBERNETES_VERSION,
        "commit" => KUBERNETES_SOURCE_COMMIT,
        "tag" => KUBERNETES_VERSION,
        "kubelet_image" => nil,
        "apiserver_image" => nil,
        "etcd_image" => nil,
        "runtime" => {},
        "cni" => lock_status["lock"] || {},
        "network_isolated" => false,
        "lock_status" => "INCOMPLETE"
      },
      raw_trace_sha256: raw_trace_sha256,
      canonical_trace_sha256: nil
    )
    {
      "schema_version" => 1,
      "executed" => false,
      "status" => "INCOMPLETE",
      "passed" => false,
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => KUBERNETES_SOURCE_COMMIT,
      "runner_sha256" => runner_digest,
      "request_seed_sha256" => request.fetch("request_seed_sha256"),
      "input_sha256" => request.fetch("input_sha256"),
      "input_file_count" => request.fetch("input_file_count"),
      "fixture_sha256" => request.fetch("fixture_sha256"),
      "timeline_sha256" => request.fetch("timeline_sha256"),
      "raw_trace_sha256" => raw_trace_sha256,
      "canonical_trace_sha256" => nil,
      "comparison_count" => 0,
      "missing_comparison_count" => REQUIRED_CASES.length,
      "comparisons" => [],
      "provenance" => provenance,
      "errors" => [error]
    }
  end

  def normalize_external_report(document, request:, actual_cases:, lock_status:, contract_document:, command:, raw_trace_sha256:, runner_identity: nil)
    raise OracleError, "external lifecycle oracle output must be an object" unless document.is_a?(Hash)
    errors = []
    external_status = document["status"]
    external_passed = document["passed"]
    external_errors = document["errors"]
    errors << "external lifecycle oracle status is required" unless external_status.is_a?(String)
    errors << "external lifecycle oracle status must be PASS" unless external_status == "PASS"
    errors << "external lifecycle oracle passed must be true" unless external_passed == true
    errors << "external lifecycle oracle errors must be an array" unless external_errors.is_a?(Array)
    if external_errors.is_a?(Array)
      errors << "external lifecycle oracle reported errors must be empty" unless external_errors.empty?
      errors.concat(external_errors.map { |error| "external lifecycle oracle reported error: #{error}" })
    end
    errors << "external lifecycle oracle output is not marked executed" unless document["executed"] == true
    errors << "external lifecycle oracle Kubernetes version is not pinned" unless document["kubernetes_version"] == KUBERNETES_VERSION
    errors << "external lifecycle oracle source commit is not pinned" unless document["source_commit"] == KUBERNETES_SOURCE_COMMIT
    if document["input_sha256"] && document["input_sha256"] != request["input_sha256"]
      errors << "external lifecycle oracle input SHA-256 does not match the Native input"
    end
    if document["fixture_sha256"] && document["fixture_sha256"] != request["fixture_sha256"]
      errors << "external lifecycle oracle fixture SHA-256 does not match the request"
    end
    if document["timeline_sha256"] && document["timeline_sha256"] != request["timeline_sha256"]
      errors << "external lifecycle oracle timeline SHA-256 does not match the request"
    end
    errors << "external lifecycle oracle must echo request_seed_sha256" unless document["request_seed_sha256"] == request["request_seed_sha256"]

    trace = document["trace"]
    errors << "external lifecycle oracle trace is required" unless trace.is_a?(Array) && !trace.empty?
    canonical_trace_sha256 = trace.is_a?(Array) ? canonical_digest(trace) : nil
    if document["canonical_trace_sha256"] && document["canonical_trace_sha256"] != canonical_trace_sha256
      errors << "external lifecycle oracle canonical trace SHA-256 does not match trace"
    end

    source = document["source"] || document.dig("provenance", "source")
    runtime = document["runtime"] || (source.is_a?(Hash) && source["runtime"])
    cni = document["cni"] || (source.is_a?(Hash) && source["cni"])
    validate_external_identity(source, runtime, cni, lock_status["lock"], errors)
    runner = document["runner"] || document["provenance"]
    runner_sha256 = runner.is_a?(Hash) ? runner["runner_sha256"] : nil
    errors << "external lifecycle oracle runner SHA-256 is missing" unless valid_digest?(runner_sha256)
    expected_runner = begin
      runner_identity || public_send(:runner_identity, command)
    rescue OracleError => error
      errors << error.message
      nil
    end
    if expected_runner
      errors << "external lifecycle oracle runner SHA-256 does not match the real pinned runner" unless
        runner_sha256 == expected_runner.fetch("runner_sha256")
      runner_command = runner.is_a?(Hash) ? runner["command"] : nil
      errors << "external lifecycle oracle runner command is not the pinned argv" unless runner_command == expected_runner.fetch("command")
    end

    external_cases = document["observations"] || document["cases"] || document["comparisons"]
    unless external_cases.is_a?(Hash)
      errors << "external lifecycle oracle observations are required"
      external_cases = {}
    end
    actual_cases = normalize_actual_cases(actual_cases)
    comparisons = REQUIRED_CASES.map do |name|
      entry = external_cases[name] || external_cases[name.to_sym]
      expected = observable_from_entry(entry)
      actual_entry = actual_cases[name]
      actual = actual_entry && actual_entry["observed"]
      actual_provenance = actual_entry && actual_entry["provenance"]
      expected_sha256 = expected.nil? ? nil : canonical_digest(expected)
      actual_sha256 = actual.nil? ? nil : canonical_digest(actual)
      passed = !expected.nil? && !actual.nil? && expected_sha256 == actual_sha256
      errors << "external lifecycle oracle case #{name} is missing" if expected.nil?
      errors << "Rubernetes lifecycle case #{name} is missing" if actual.nil?
      REQUIRED_OBSERVABLE_FIELDS.fetch(name).each do |field|
        errors << "external lifecycle oracle case #{name} is missing observable field #{field}" unless expected.is_a?(Hash) && expected.key?(field)
        errors << "Rubernetes lifecycle case #{name} is missing observable field #{field}" unless actual.is_a?(Hash) && actual.key?(field)
      end
      errors << "Rubernetes lifecycle case #{name} actual provenance is missing" unless actual_provenance.is_a?(Hash)
      validate_actual_provenance(name, actual_provenance, errors)
      actual_source = actual_provenance.is_a?(Hash) && actual_provenance["source"] == ACTUAL_SOURCE ? ACTUAL_SOURCE : nil
      {
        "id" => name,
        "attempt_count" => entry.is_a?(Hash) && entry.key?("attempt_count") ? entry["attempt_count"] : 1,
        "expected_source" => "kubernetes_external",
        "actual_source" => actual_source,
        "actual_provenance" => actual_provenance,
        "expected_observable" => expected,
        "actual_observable" => actual,
        "expected_sha256" => expected_sha256,
        "actual_sha256" => actual_sha256,
        "passed" => passed
      }
    end
    # Errors collected so far concern the external oracle itself (protocol,
    # identity, missing observations). Everything from here on concerns the
    # comparison with Rubernetes: an executed oracle with differences is a FAIL,
    # never an INCOMPLETE, so a real mismatch list is always reported.
    identity_errors = errors.dup
    comparisons.each do |comparison|
      errors << "external lifecycle oracle case #{comparison.fetch("id")} must run exactly once" unless comparison["attempt_count"] == 1
      errors << "external lifecycle oracle case #{comparison.fetch("id")} differs from Rubernetes production semantics" unless comparison["passed"] == true
    end

    provenance_source = source.is_a?(Hash) ? source.dup : {}
    provenance_source["version"] ||= KUBERNETES_VERSION
    provenance_source["commit"] ||= KUBERNETES_SOURCE_COMMIT
    provenance_source["tag"] ||= KUBERNETES_VERSION
    provenance_source["runtime"] ||= runtime
    provenance_source["cni"] ||= cni
    provenance_source["network_isolated"] = document["network_isolated"] if document.key?("network_isolated")
    provenance = base_provenance(
      request: request,
      runner_sha256: runner_sha256,
      command: command,
      source: provenance_source,
      raw_trace_sha256: raw_trace_sha256,
      canonical_trace_sha256: canonical_trace_sha256,
      runner_identity: expected_runner
    )
    external_provenance = document["provenance"]
    if external_provenance.is_a?(Hash) && external_provenance["provenance_sha256"]
      errors << "external lifecycle oracle provenance SHA-256 does not match canonical content" unless external_provenance["provenance_sha256"] == canonical_digest(external_provenance, excluded_keys: ["provenance_sha256"])
    end

    difference_count = comparisons.count { |comparison| comparison["passed"] != true }
    external_errors_only = identity_errors.reject { |error| error.start_with?("Rubernetes lifecycle case") }
    executed = external_errors_only.empty? && document["executed"] == true &&
               comparisons.none? { |comparison| comparison["expected_observable"].nil? }
    passed = executed && errors.empty? && difference_count.zero?
    {
      "schema_version" => 1,
      "executed" => executed,
      "status" => passed ? "PASS" : (executed ? "FAIL" : "INCOMPLETE"),
      "passed" => passed,
      "difference_count" => difference_count,
      "external_status" => external_status,
      "external_passed" => external_passed,
      "external_errors" => external_errors,
      "kubernetes_version" => KUBERNETES_VERSION,
      "source_commit" => KUBERNETES_SOURCE_COMMIT,
      "runner_sha256" => runner_sha256,
      "request_seed_sha256" => request.fetch("request_seed_sha256"),
      "input_sha256" => request.fetch("input_sha256"),
      "input_file_count" => request.fetch("input_file_count"),
      "fixture_sha256" => request.fetch("fixture_sha256"),
      "timeline_sha256" => request.fetch("timeline_sha256"),
      "raw_trace_sha256" => raw_trace_sha256,
      "canonical_trace_sha256" => canonical_trace_sha256,
      "comparison_count" => comparisons.length,
      "missing_comparison_count" => comparisons.count { |comparison| comparison["expected_observable"].nil? },
      "trace" => trace,
      "comparisons" => comparisons,
      "provenance" => provenance,
      "errors" => errors
    }
  end

  def normalize_actual_cases(actual_cases)
    if actual_cases.is_a?(Hash)
      return actual_cases.each_with_object({}) do |(name, value), result|
        result[name.to_s] = normalize_actual_case(value)
      end
    end
    Array(actual_cases).each_with_object({}) do |entry, result|
      next unless entry.is_a?(Hash)

      name = entry["name"] || entry[:name]
      result[name.to_s] = normalize_actual_case(entry) if name
    end
  end

  def normalize_actual_case(value)
    if value.is_a?(Hash) && (value.key?("observed") || value.key?(:observed))
      {
        "observed" => value["observed"] || value[:observed],
        "provenance" => value["actual_provenance"] || value[:actual_provenance]
      }
    else
      {"observed" => value, "provenance" => nil}
    end
  end

  def validate_actual_provenance(name, provenance, errors)
    return unless provenance.is_a?(Hash)

    expected = M2Gate::LIFECYCLE_SEMANTICS_PROVENANCE[name]
    errors << "Rubernetes lifecycle case #{name} actual source is not #{ACTUAL_SOURCE}" unless provenance["source"] == ACTUAL_SOURCE
    return unless expected

    expected.each do |key, value|
      errors << "Rubernetes lifecycle case #{name} actual provenance #{key} is not truthful" unless provenance[key] == value
    end
  end

  def observable_from_entry(entry)
    return nil unless entry.is_a?(Hash)

    entry["observable"] || entry["observed"] || entry["expected_observable"] || entry
  end

  def validate_external_identity(source, runtime, cni, cni_lock, errors)
    unless source.is_a?(Hash)
      errors << "external lifecycle oracle source identity is required"
      return
    end
    errors << "external lifecycle oracle source version is not pinned" unless source["version"] == KUBERNETES_VERSION
    errors << "external lifecycle oracle source commit is not pinned" unless source["commit"] == KUBERNETES_SOURCE_COMMIT
    errors << "external lifecycle oracle source tag is not pinned" unless source["tag"] == KUBERNETES_VERSION
    %w[kubelet_image apiserver_image etcd_image].each do |key|
      errors << "external lifecycle oracle #{key} identity must be digest-pinned" unless digest_pinned_image?(source[key])
    end
    errors << "external lifecycle oracle network isolation must be true" unless source["network_isolated"] == true
    unless runtime.is_a?(Hash)
      errors << "external lifecycle oracle runtime identity is required"
    else
      %w[containerd runc].each do |name|
        identity = runtime[name]
        unless identity.is_a?(Hash) && identity["version"].is_a?(String) && !identity["version"].empty? &&
               identity["path"].is_a?(String) && !identity["path"].empty? &&
               valid_digest?(identity["binary_sha256"]) && identity["identity_method"] == "realpath+version+binary_sha256"
          errors << "external lifecycle oracle #{name} path, version, and binary SHA-256 are required"
          next
        end
        begin
          real_path = File.realpath(identity.fetch("path"))
          errors << "external lifecycle oracle #{name} path must be the real executable path" unless
            real_path == identity.fetch("path") && File.file?(real_path) && !File.symlink?(identity.fetch("path"))
          errors << "external lifecycle oracle #{name} binary SHA-256 does not match the real file" unless
            valid_digest?(identity["binary_sha256"]) && Digest::SHA256.file(real_path).hexdigest == identity["binary_sha256"]
        rescue KeyError, Errno::ENOENT, Errno::EACCES, Errno::EINVAL => error
          errors << "external lifecycle oracle #{name} executable path could not be verified: #{error.message}"
        end
      end
    end
    unless cni.is_a?(Hash)
      errors << "external lifecycle oracle CNI identity is required"
    else
      %w[plugin version source_commit image_reference image_digest config_sha256].each do |key|
        errors << "external lifecycle oracle CNI #{key} is required" unless cni[key].is_a?(String) && !cni[key].empty?
      end
      errors << "external lifecycle oracle CNI source_commit must be a commit" unless valid_commit?(cni["source_commit"])
      errors << "external lifecycle oracle CNI image_digest must be a SHA-256 digest" unless valid_digest?(cni["image_digest"])
      errors << "external lifecycle oracle CNI config_sha256 must be a SHA-256 digest" unless valid_digest?(cni["config_sha256"])
      errors << "external lifecycle oracle CNI image_reference must be digest-pinned" unless digest_pinned_image?(cni["image_reference"])
      if digest_pinned_image?(cni["image_reference"])
        errors << "external lifecycle oracle CNI image_reference digest must match image_digest" unless
          cni["image_reference"].split("@sha256:", 2).last == cni["image_digest"]
      end
      if cni_lock.is_a?(Hash)
        locked_identity = cni_lock.slice("plugin", "version", "source_commit", "image_reference", "image_digest", "config_sha256")
        errors << "external lifecycle oracle CNI identity does not match the repository lock" unless cni.slice(*locked_identity.keys) == locked_identity
      else
        errors << "external lifecycle oracle CNI repository lock identity is required"
      end
    end
  end

  def base_provenance(request:, runner_sha256:, command:, source:, raw_trace_sha256:, canonical_trace_sha256:, runner_identity: nil)
    started_at = Time.now.utc.iso8601(6)
    provenance = {
      "kind" => M2Gate::KUBERNETES_SEMANTICS_ORACLE_KIND,
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "pinned Kubernetes v1.36.2 kubelet lifecycle runner in an isolated privileged environment",
      "source" => source,
      "runner_sha256" => runner_sha256,
      "request_seed_sha256" => request.fetch("request_seed_sha256"),
      "input_sha256" => request.fetch("input_sha256"),
      "fixture_sha256" => request.fetch("fixture_sha256"),
      "timeline_sha256" => request.fetch("timeline_sha256"),
      "raw_trace_sha256" => raw_trace_sha256,
      "canonical_trace_sha256" => canonical_trace_sha256,
      "command" => command,
      "process_id" => Process.pid,
      "started_at" => started_at,
      "finished_at" => Time.now.utc.iso8601(6)
    }
    if runner_identity.is_a?(Hash)
      provenance["runner_path"] = runner_identity["runner_path"] || runner_identity["path"]
      provenance["executable_path"] = runner_identity["executable_path"]
      provenance["executable_sha256"] = runner_identity["executable_sha256"]
      provenance["runner_lock_path"] = runner_identity["lock_path"] if runner_identity["lock_path"]
      provenance["runner_lock_sha256"] = runner_identity["lock_sha256"] if runner_identity["lock_sha256"]
    end
    provenance["provenance_sha256"] = canonical_digest(provenance, excluded_keys: ["provenance_sha256"])
    provenance
  end
end

if $PROGRAM_NAME == __FILE__
  # Standalone invocation runs the real external oracle. The Rubernetes side of
  # the comparison is never fabricated here: supply the production semantics
  # matrix (the `lifecycle_semantics_matrix` array of the lifecycle probe
  # report) through --actual PATH or RUBERNETES_M2_LIFECYCLE_ACTUAL_CASES;
  # without it every comparison is reported as missing its Rubernetes side and
  # the Kubernetes observables are still printed for inspection.
  input = {
    "sha256" => ENV.fetch("RUBERNETES_M2_INPUT_SHA256", Digest::SHA256.hexdigest("manual")),
    "file_count" => Integer(ENV.fetch("RUBERNETES_M2_INPUT_FILE_COUNT", "1"), 10)
  }
  actual_index = ARGV.index("--actual")
  actual_path = actual_index ? ARGV[actual_index + 1] : ENV["RUBERNETES_M2_LIFECYCLE_ACTUAL_CASES"]
  actual_cases = if actual_path.to_s.empty?
                   []
                 else
                   document = M2KubernetesLifecycleOracle.parse_json(actual_path)
                   document.is_a?(Hash) && document["lifecycle_semantics_matrix"].is_a?(Array) ? document["lifecycle_semantics_matrix"] : document
                 end
  report = M2KubernetesLifecycleOracle.run(input: input, actual_cases: actual_cases)
  puts JSON.pretty_generate(report)
  exit(report["passed"] == true ? 0 : 1)
end
