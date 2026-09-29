#!/usr/bin/env ruby
# frozen_string_literal: true

# External M3 scheduler oracle runner.  The Go program is compiled and run
# from a separately checked-out, pinned Kubernetes source tree; this adapter
# only transports JSON and records provenance/digests.

require "digest"
require "json"
require "open3"
require "rbconfig"
require "time"

module M3KubernetesSchedulerOracle
  VERSION = "v1.36.2".freeze
  SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467".freeze
  REQUIRED_CASE_IDS = %w[filter score tie_break preemption binding volume_binding].freeze
  PROJECT_ROOT = File.expand_path("../..", __dir__).freeze
  ORACLE_SOURCE = File.join(PROJECT_ROOT, "test", "conformance", "kubernetes", "m3_scheduler_oracle", "main.go").freeze

  module_function

  def run(input_bytes: STDIN.read, source_root: ENV["RUBERNETES_M3_KUBERNETES_SOURCE_ROOT"] || ENV["KUBERNETES_SOURCE_ROOT"], go: ENV.fetch("GO", "go"))
    source = verify_source!(source_root)
    request = JSON.parse(input_bytes, create_additions: false, max_nesting: 512)
    verify_request!(request)
    started_at = Time.now.utc.iso8601(6)
    # Kubernetes v1.36.2's checked-in vendor metadata is incompatible with
    # its go.mod replacements. Use the pinned module graph without mutating
    # the verified source checkout.
    command = [go, "run", "-mod=mod", ORACLE_SOURCE]
    environment = {"GOWORK" => "off"}
    stdout, stderr, status = Open3.capture3(environment, *command, stdin_data: input_bytes, chdir: source.fetch("root"))
    finished_at = Time.now.utc.iso8601(6)
    unless status.success?
      detail = stderr.to_s.strip
      detail = "exit status #{status.exitstatus || 1}" if detail.empty?
      raise "pinned Kubernetes scheduler oracle failed: #{detail}"
    end
    raise "pinned Kubernetes scheduler oracle returned no JSON" if stdout.to_s.strip.empty?

    response = JSON.parse(stdout, create_additions: false, max_nesting: 512)
    comparisons = normalize_comparisons(response.fetch("comparisons"))
    raw_input_sha256 = Digest::SHA256.hexdigest(input_bytes)
    canonical_input = canonical_json(request)
    raw_output_sha256 = Digest::SHA256.hexdigest(stdout)
    canonical_output = canonical_json(response)
    execution = {
      "argv" => command,
      "stdin" => input_bytes,
      "stdin_sha256" => raw_input_sha256,
      "stdout" => stdout,
      "stdout_sha256" => raw_output_sha256,
      "stderr" => stderr.to_s,
      "stderr_sha256" => Digest::SHA256.hexdigest(stderr.to_s),
      "exit_status" => status.exitstatus,
      "success" => status.success?
    }
    runner = {
      "mode" => "external",
      "self_comparison" => false,
      "implementation" => "Go direct Kubernetes scheduler framework/plugin APIs",
      "version" => VERSION,
      "source_commit" => SOURCE_COMMIT,
      "command" => command,
      "process_id" => Process.pid,
      "started_at" => started_at,
      "finished_at" => finished_at,
      "runner_sha256" => source.fetch("runner_sha256"),
      "source" => source,
      "image" => {
        "used" => false,
        "reference" => nil,
        "digest" => nil,
        "reason" => "direct source execution; no container image was used"
      }
    }
    runner["provenance_sha256"] = digest_without(runner, "provenance_sha256")
    {
      "executed" => true,
      "version" => VERSION,
      "source_commit" => SOURCE_COMMIT,
      "runner_sha256" => source.fetch("runner_sha256"),
      "runner" => runner,
      "execution" => execution,
      "input" => {
        "raw_sha256" => raw_input_sha256,
        "canonical_sha256" => Digest::SHA256.hexdigest(canonical_input),
        "bytes" => input_bytes.bytesize,
        "case_ids" => request.fetch("cases").keys.sort
      },
      "output" => {
        "raw_sha256" => raw_output_sha256,
        "canonical_sha256" => Digest::SHA256.hexdigest(canonical_output),
        "bytes" => stdout.bytesize
      },
      "comparisons" => comparisons
    }
  rescue JSON::ParserError => error
    raise "scheduler oracle JSON is invalid: #{error.message}"
  end

  def verify_source!(source_root)
    raise "KUBERNETES_SOURCE_ROOT is required for the external scheduler oracle" if source_root.to_s.strip.empty?

    root = File.expand_path(source_root)
    raise "Kubernetes source root is not a directory: #{root}" unless File.directory?(root)
    commit = command!(root, "git", "rev-parse", "HEAD").strip
    raise "Kubernetes source commit is #{commit}, expected #{SOURCE_COMMIT}" unless commit == SOURCE_COMMIT
    tag = command!(root, "git", "describe", "--tags", "--exact-match", "HEAD").strip
    raise "Kubernetes source tag is #{tag.inspect}, expected #{VERSION.inspect}" unless tag == VERSION
    status = command!(root, "git", "status", "--porcelain", "--untracked-files=all")
    raise "Kubernetes source tree is not clean" unless status.empty?
    tree = command!(root, "git", "rev-parse", "HEAD^{tree}").strip
    source_inventory = command!(root, "git", "ls-tree", "-r", "--full-tree", "--name-only", "HEAD")
    {
      "root" => root,
      "repository" => "https://github.com/kubernetes/kubernetes.git",
      "version" => VERSION,
      "tag" => VERSION,
      "commit" => SOURCE_COMMIT,
      "tree" => tree,
      "source_tree_sha256" => Digest::SHA256.hexdigest("#{SOURCE_COMMIT}\0#{tree}"),
      "source_inventory_sha256" => Digest::SHA256.hexdigest(source_inventory),
      "source_inventory_file_count" => source_inventory.lines.reject { |line| line.strip.empty? }.length,
      "tree_clean" => true,
      "runner_source" => ORACLE_SOURCE,
      "runner_sha256" => Digest::SHA256.file(ORACLE_SOURCE).hexdigest
    }
  end

  def verify_request!(request)
    raise "scheduler oracle request must be an object" unless request.is_a?(Hash)
    raise "scheduler oracle request version is not pinned" unless request["kubernetes_version"] == VERSION
    raise "scheduler oracle request source commit is not pinned" unless request["source_commit"] == SOURCE_COMMIT
    cases = request["cases"]
    raise "scheduler oracle request cases must be an object" unless cases.is_a?(Hash) && cases.length >= 6
    raise "scheduler oracle request case inventory is incomplete" unless cases.keys.map(&:to_s).sort == REQUIRED_CASE_IDS.sort
  end

  def normalize_comparisons(raw)
    raise "scheduler oracle comparisons must be an object" unless raw.is_a?(Hash)

    raw.sort_by { |id, _| id.to_s }.map do |id, observation|
      raise "scheduler oracle case #{id.inspect} is not an object" unless observation.is_a?(Hash)
      expected = observation["normalized_observable"]
      raise "scheduler oracle case #{id.inspect} has no normalized observable" unless expected.is_a?(Hash)

      {
        "id" => id.to_s,
        "expected_observable" => expected,
        "expected_sha256" => canonical_digest(expected),
        "oracle_observation" => observation
      }
    end
  end

  def canonical_digest(value)
    Digest::SHA256.hexdigest(canonical_json(value))
  end

  def canonical_json(value)
    JSON.generate(canonical_value(value))
  end

  def canonical_value(value)
    case value
    when Hash
      value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
        source_key = value.keys.find { |candidate| candidate.to_s == key }
        result[key] = canonical_value(value.fetch(source_key))
      end
    when Array
      value.map { |child| canonical_value(child) }
    else
      value
    end
  end

  def digest_without(value, excluded)
    canonical_digest(value.reject { |key, _| key.to_s == excluded.to_s })
  end

  def command!(directory, *command)
    stdout, stderr, status = Open3.capture3(*command, chdir: directory)
    return stdout if status.success?

    detail = stderr.to_s.strip
    detail = "exit status #{status.exitstatus || 1}" if detail.empty?
    raise "#{command.join(" ")} failed: #{detail}"
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    puts JSON.generate(M3KubernetesSchedulerOracle.run)
  rescue StandardError => error
    warn error.message
    exit 1
  end
end
