# frozen_string_literal: true

require "time"
require_relative "../conformance/archived_artifact"
require_relative "../conformance/k4_node_conformance"

module M8K4Evidence
  K4 = Conformance::Lanes::K4
  RRO = Conformance::K4RRO
  Lock = Conformance::Lock
  Artifact = Conformance::ArchivedArtifact
  Invalid = Artifact::Invalid
  Missing = Artifact::Missing
  ORIGINALS = %w[build.json node.json host.json result.json inventory-execution.json execution.json
                 inventory.json ginkgo.json coverage.json junit_01.xml].freeze

  module_function

  def verify(manifest, lane)
    directory = File.realpath(File.dirname(File.expand_path(manifest.fetch("_path"), Lock::ROOT)))
    complete = lane.values_at("status", "passed") == ["COMPLETE", true]
    return failure("not_complete", lane["reason"] || "the K4 lane did not complete") unless complete || lane.values_at("status", "passed") == ["FAILED", false]

    originals = {}
    read = lambda do |name, manifest_only: false|
      bytes = read_original(manifest, lane, directory, name, manifest_only: manifest_only)
      originals[name] = Digest::SHA256.hexdigest(bytes)
      bytes
    end
    recorded = JSON.parse(read.call("result.json", manifest_only: true))
    raise Invalid, "the K4 lane differs from the original lane result" unless recorded == lane

    build, node, host = %w[build.json node.json host.json].map { |name| JSON.parse(read.call(name)) }
    validate_run!(manifest, lane, build, node, host)
    inventory = JSON.parse(read.call("inventory-execution.json"))
    execution = JSON.parse(read.call("execution.json"))
    dry_run = K4.parse_suite(read.call(K4::INVENTORY), dry_run: true)
    actual = K4.parse_suite(read.call(K4::REPORT), dry_run: false)
    raise Invalid, "the original K4 inventory does not match a pinned Node Conformance selection" unless dry_run && K4.pinned_inventory?(dry_run)
    raise Invalid, "the original K4 execution is missing an unfiltered Node Conformance report" unless actual

    validate_invocations!(inventory, execution, lane, node, dry_run, actual)
    identity = K4.inventory_identity(dry_run)
    before, after = RRO::OBSERVATIONS.map { |name| JSON.parse(read.call(name)) if recorded?(lane, name) }
    support = RRO.observed_support(before, after, node: node, execution: execution)
    coverage = K4.compare(dry_run, actual, rro_supported: support)
    unless JSON.parse(read.call("coverage.json")) == coverage && lane["coverage"] == coverage
      raise Invalid, "K4 coverage differs from the original Ginkgo reports"
    end

    # Historical failed reports predate the inclusion of framework JUnit
    # in the lane artifact list. Their manifest can attest the diagnostic.
    junit = read.call(K4::FRAMEWORK_JUNIT, manifest_only: !complete && !recorded?(lane, K4::FRAMEWORK_JUNIT))
    raise Invalid, "the framework JUnit does not match the original Ginkgo report" unless Conformance::K4JUnit.matches?(junit, actual, framework: true)

    if recorded?(lane, K4::JUNIT) || execution.fetch("command").any? { |arg| arg.start_with?("--junit-report=") }
      junit = read.call(K4::JUNIT)
      raise Invalid, "the Ginkgo CLI JUnit does not match the original Ginkgo report" unless Conformance::K4JUnit.matches?(junit, actual, framework: false)
    end

    clean = execution["exit_status"] == 0 && K4.complete_coverage?(dry_run, actual, coverage)
    unless complete && clean
      status = complete ? "invalid_evidence" : "failed"
      detail = "the original run passed #{coverage.fetch("passed")} of #{identity.fetch("selected")} selected specs"
      detail += ", with #{coverage.fetch("expected_skips").length} expected RRO skips" if coverage.key?("expected_skips")
      return failure(status, detail).merge("coverage" => coverage, "inventory" => identity)
    end

    {"status" => "verified", "passed" => true, "run_id" => manifest.fetch("runId"), "source_commit" => Lock.source_commit,
     "inventory" => identity, "coverage" => coverage, "original_sha256" => originals}
  rescue Missing, Errno::ENOENT => error
    failure("missing_evidence", error.message)
  rescue Invalid, Conformance::K4Evidence::Error, SystemCallError, JSON::ParserError, ArgumentError, KeyError, TypeError, NoMethodError => error
    failure("invalid_evidence", error.message)
  end

  def failure(status, detail)
    {"status" => status, "passed" => false, "detail" => detail}
  end

  def recorded?(record, name)
    [name, "#{name}.gz"].any? { |variant| !Artifact.references(record, "k4/#{variant}").empty? }
  end

  def read_original(manifest, lane, directory, name, manifest_only:)
    reference = manifest_only ? manifest : lane
    variants = ["k4/#{name}", "k4/#{name}.gz"].reject { |variant| Artifact.references(reference, variant).empty? }
    raise Missing, "missing artifact reference: k4/#{name}" if variants.empty?
    raise Invalid, "conflicting storage formats for k4/#{name}" unless variants.one?

    path = Artifact.verify!(manifest, reference, directory, variants.first)
    return File.binread(path) unless path.end_with?(".gz")

    metadata = Artifact.references(reference, variants.first).first
    digest, size = metadata.values_at("uncompressed_sha256", "uncompressed_bytes")
    raise Invalid, "missing original byte identity for k4/#{name}.gz" unless K4::SHA256.match?(digest.to_s) && size.is_a?(Integer) && size.positive?

    bytes = Conformance::K4Evidence.read(path, sha256: digest, alternate: false)
    raise Invalid, "original size differs for k4/#{name}.gz" unless size == bytes.bytesize

    bytes
  end

  def validate_run!(manifest, lane, build, node, host)
    profile = manifest.fetch("profileDefinition")
    identity = manifest.fetch("rubernetesCommit")
    source = manifest.slice("rubernetesSourceStable", "rubernetesCommitAfter")
    expected = {"rubernetesSourceStable" => true, "rubernetesCommitAfter" => identity}
    unless manifest["schemaVersion"] == 1 && manifest["suite"] == "K0-K7-kubernetes-compatibility" &&
           manifest["runId"].is_a?(String) && !manifest["runId"].empty? &&
           /\A(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})\z/.match?(identity.to_s) &&
           (source.empty? || source == expected) &&
           manifest.values_at("sourceCommit", "inputsLock", "platform") ==
           [Lock.source_commit, Lock::KUBERNETES.delete_prefix("#{Lock::ROOT}/"), "linux/amd64"] &&
           profile.values_at("name", "os", "architecture") == [manifest.fetch("profile"), "linux", "amd64"] &&
           K4.valid_build_record?(build)
      raise Invalid, "K4 run does not match the pinned amd64 build and source"
    end

    info = node.dig("status", "nodeInfo")
    ready = Array(node.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Ready True] }
    unless ready && node["kind"] == "Node" && info.values_at("architecture", "operatingSystem") == %w[amd64 linux] &&
           host["hostname"].is_a?(String) && !host["hostname"].empty? &&
           host["kernel"].is_a?(String) && !host["kernel"].empty? && info["kernelVersion"] == host["kernel"]
      raise Invalid, "K4 execution does not bind its Ready amd64 Linux node and kernel"
    end

    run_start, run_end = times(manifest, "startedAt", "finishedAt")
    lane_start, lane_end = times(lane, "startedAt", "finishedAt")
    raise Invalid, "K4 lane timestamps fall outside the recorded run" unless run_start <= lane_start && lane_start < lane_end && lane_end <= run_end
  end

  def validate_invocations!(inventory, execution, lane, node, dry_run, actual)
    first = validate_command!(inventory, dry_run, node, dry_run: true)
    last = validate_command!(execution, actual, node, dry_run: false)
    raise Invalid, "K4 inventory and execution did not use the same stock runner and node" unless inventory["exit_status"] == 0 && first == last

    lane_start, lane_end = times(lane, "startedAt", "finishedAt")
    dry_start, dry_end = times(inventory, "started_at", "finished_at")
    run_start, run_end = times(execution, "started_at", "finished_at")
    return if lane_start <= dry_start && dry_end <= run_start && run_start <= run_end && run_end <= lane_end

    raise Invalid, "K4 inventory or execution timestamps fall outside the recorded lane"
  end

  def validate_command!(record, suite, node, dry_run:)
    command = record.fetch("command")
    duration = record["elapsed_seconds"]
    unless command.is_a?(Array) && command.all? { |arg| arg.is_a?(String) && !arg.empty? } &&
           record["timed_out"] == false && record["exit_status"].is_a?(Integer) &&
           duration.is_a?(Numeric) && duration.positive? && record.values_at("stdout", "stderr").all?(String)
      raise Invalid, "malformed stock K4 execution capture"
    end

    namespace = nil
    if command.take(3) == %w[ip netns exec]
      namespace = command[3]
      raise Invalid, "malformed K4 network namespace" unless /\A[A-Za-z0-9_.-]+\z/.match?(namespace.to_s)

      command = command.drop(4)
    end
    cli, *args = command
    ginkgo, positional, *extra = args.slice_after("--").to_a
    raise Invalid, "malformed stock K4 command" unless positional && extra.empty? && ginkgo.last == "--"

    binary = ginkgo[-2]
    flags = options(ginkgo[0...-2])
    node_flags = options(positional)
    directory = node_flags.fetch("--report-dir")
    report = File.join(directory, dry_run ? K4::INVENTORY : K4::REPORT)
    expected = {"--label-filter" => K4::LABEL, "--fail-on-empty" => nil, "--json-report" => report}
    if dry_run
      expected["--dry-run"] = nil
    else
      expected["--nodes"] = "8"
      expected["--junit-report"] = File.join(directory, K4::JUNIT) if flags.key?("--junit-report")
      expected["--timeout"] = K4::SUITE_TIMEOUT if flags.key?("--timeout")
    end
    unless cli && binary && File.basename(binary) == "e2e_node.test" && cli == K4.ginkgo_binary(binary) &&
           File.dirname(binary) == suite["SuitePath"] && flags == expected &&
           suite.dig("SuiteConfig", "ParallelTotal") == (dry_run ? 1 : 8)
      raise Invalid, "K4 command is not the stock Node Conformance invocation"
    end

    required = {"--conformance" => "true", "--start-services" => "false", "--prepull-images" => "false",
                "--bearer-token" => "[redacted]", "--node-name" => node.dig("metadata", "name")}
    paths = %w[--host --kubectl-path --report-dir]
    optional = %w[--dns-domain --container-runtime-endpoint]
    unless node_flags.except(*paths, *optional) == required && paths.all? { |flag| !node_flags[flag].to_s.empty? } &&
           node_flags.slice(*optional).values.all?(String) && File.basename(directory) == "k4" &&
           File.basename(node_flags.fetch("--kubectl-path")) == "kubectl-v1.36.2" && !required["--node-name"].to_s.empty?
      raise Invalid, "K4 command does not bind the recorded node and stock flags"
    end

    command_start, command_end = times(record, "started_at", "finished_at")
    suite_start, suite_end = times(suite, "StartTime", "EndTime")
    unless command_start.to_i <= suite_start.to_i && suite_start < suite_end && suite_end.to_i <= command_end.to_i &&
           (duration - (command_end - command_start)).abs < 2
      raise Invalid, "K4 Ginkgo report timestamps fall outside the captured command"
    end

    [namespace, cli, binary, node_flags]
  end

  def options(arguments)
    arguments.each_with_object({}) do |arg, result|
      name, value = arg.split("=", 2)
      raise Invalid, "unexpected or repeated K4 option" if !name.start_with?("--") || result.key?(name)

      result[name] = value
    end
  end

  def times(document, start, finish)
    document.values_at(start, finish).map { |value| Time.iso8601(value) }
  end

  def proof?(proof)
    return false unless proof.is_a?(Hash) && proof.values_at("status", "passed", "source_commit") == ["verified", true, Lock.source_commit] &&
                        proof["run_id"].is_a?(String) && !proof["run_id"].empty?

    inventory = proof["inventory"]
    coverage = proof["coverage"]
    originals = proof["original_sha256"]
    return false unless Lock.kubernetes.fetch("node_conformance").fetch("inventories").value?(inventory) &&
                        coverage.is_a?(Hash) && originals.is_a?(Hash)

    skips = coverage.fetch("expected_skips", [])
    return false unless skips == [] || [true, false].any? { |supported| skips == RRO.skip_records(supported) }

    required = skips.empty? ? ORIGINALS : ORIGINALS + RRO::OBSERVATIONS
    total = inventory.fetch("selected")
    coverage.values_at("complete", "selected", "passed", "missing_failed_or_skipped", "unexpected_executions") ==
      [true, total, total - skips.size, [], []] && required.all? { |name| K4::SHA256.match?(originals[name].to_s) }
  end

  def original_matches?(proof)
    path = File.expand_path(proof.fetch("manifest"), Lock::ROOT)
    manifest = JSON.parse(File.binread(path)).merge("_path" => path)
    lanes = Array(manifest["lanes"]).grep(Hash).select { |lane| lane["lane"] == "K4" }
    lanes.one? && verify(manifest, lanes.first) == proof.except("manifest", "recorded_status")
  rescue SystemCallError, JSON::ParserError, KeyError, TypeError, NoMethodError
    false
  end
end
