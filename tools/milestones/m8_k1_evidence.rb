# frozen_string_literal: true

require "json"
require "time"
require_relative "../conformance/archived_artifact"
require_relative "../conformance/k1_evidence"
require_relative "../conformance/k1_ginkgo_report"

module M8K1Evidence
  Lock = Conformance::Lock
  JUNIT = "k1/hydrophone/junit_01.xml"
  GINKGO = "k1/hydrophone/#{Conformance::K1GinkgoReport::ARCHIVE}".freeze
  SHA256 = /\A[0-9a-f]{64}\z/
  RELEASE_REVISION = /\A(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})\z/

  Invalid = Conformance::ArchivedArtifact::Invalid
  Missing = Conformance::ArchivedArtifact::Missing

  module_function

  def verify(manifest, lane, profile:, expected:)
    return failure("not_complete", lane["reason"] || "the K1 lane did not complete") unless lane["status"] == "COMPLETE" && lane["passed"] == true

    validate_provenance!(manifest, lane, profile)
    directory = File.realpath(File.dirname(File.expand_path(manifest.fetch("_path"), Lock::ROOT)))
    definition = Conformance::ArchivedArtifact.verify!(manifest, lane, directory, "k1/conformance-definition.yaml")
    stdout = Conformance::ArchivedArtifact.verify!(manifest, lane, directory, "k1/hydrophone.stdout.gz")
    junit = Conformance::ArchivedArtifact.verify!(manifest, lane, directory, JUNIT)
    ginkgo = Conformance::ArchivedArtifact.verify!(manifest, lane, directory, GINKGO)
    command = Conformance::ArchivedArtifact.verify!(manifest, lane, directory, "k1/hydrophone-command.json")

    validate_command!(JSON.parse(File.binread(command)), lane)
    codenames = definition_codenames(definition, expected)
    summary, joined, junit_cases = Zlib::GzipReader.open(stdout) do |log|
      Conformance::K1Evidence.junit(junit, codenames: codenames, stdout: log)
    end
    report = Conformance::K1GinkgoReport.join(ginkgo, junit_cases, expected: expected)
    unless [summary, joined, report] == lane.values_at("summary", "codenames", "ginkgo")
      raise Invalid, "K1 totals, codenames or Ginkgo join do not match the original reports"
    end
    unless Conformance::K1Evidence.complete?(summary, joined, expected: expected) && report["passed"] == true
      raise Invalid, "the original reports do not show one clean run of the full Conformance suite"
    end

    {"status" => "verified", "passed" => true}
  rescue Missing, Errno::ENOENT => error
    failure("missing_evidence", error.message)
  rescue Invalid, SystemCallError, JSON::ParserError, REXML::ParseException, Zlib::Error, Psych::Exception,
         ArgumentError, KeyError, TypeError, EOFError => error
    failure("invalid_evidence", error.message)
  end

  def failure(status, detail)
    {"status" => status, "detail" => detail, "passed" => false}
  end

  def validate_provenance!(manifest, lane, profile)
    source_check = manifest.slice("rubernetesSourceStable", "rubernetesCommitAfter")
    expected = {"rubernetesSourceStable" => true, "rubernetesCommitAfter" => manifest["rubernetesCommit"]}
    raise Invalid, "Rubernetes source changed during the recorded K1 run" if !source_check.empty? && source_check != expected

    unless manifest["sourceCommit"] == Lock.source_commit &&
           manifest["inputsLock"] == Lock::KUBERNETES.delete_prefix("#{Lock::ROOT}/") &&
           manifest["profileDefinition"] == profile && lane["profile"] == profile.fetch("name") &&
           manifest["platform"] == "#{profile.fetch("os")}/#{profile.fetch("architecture")}"
      raise Invalid, "K1 manifest does not match the pinned source and release profile"
    end

    run_start, run_finish = timestamps(manifest, "startedAt", "finishedAt")
    lane_start, lane_finish = timestamps(lane, "startedAt", "finishedAt")
    return if run_start <= lane_start && lane_start < lane_finish && lane_finish <= run_finish

    raise Invalid, "K1 lane timestamps fall outside the recorded run"
  end

  def validate_command!(record, lane)
    unless record.is_a?(Hash) && record["exit_status"] == 0 && record["timed_out"] == false &&
           record["stdout_artifact"] == "hydrophone.stdout.gz"
      raise Invalid, "K1 Hydrophone did not finish successfully"
    end

    command = record.fetch("command")
    raise Invalid, "K1 Hydrophone command is malformed" unless command.is_a?(Array) && command.all? { |argument| argument.is_a?(String) && !argument.empty? }

    command = command.drop(4) if command.take(3) == %w[ip netns exec]
    executable, *args = command
    options = hydrophone_options(args)
    expected = {
      "--conformance" => "true",
      "--conformance-image" => Lock.reference_by_digest(Lock.kubernetes.fetch("conformance_image")),
      "--busybox-image" => Lock.reference_by_digest(Lock.support_images.fetch("busybox")),
      "--parallel" => "1",
      "--extra-args" => Conformance::K1GinkgoReport::FLAG.split("=", 2).last
    }
    paths = %w[--kubeconfig --output-dir]
    valid_paths = options.values_at(*paths).all? { |path| path && !path.empty? && !path.start_with?("-") }
    unless executable && File.basename(executable) == "hydrophone" && valid_paths && options.except(*paths) == expected
      raise Invalid, "K1 command is not the pinned, unfiltered Hydrophone Conformance invocation"
    end

    command_start, command_finish = timestamps(record, "started_at", "finished_at")
    lane_start, lane_finish = timestamps(lane, "startedAt", "finishedAt")
    return if lane_start <= command_start && command_start < command_finish && command_finish <= lane_finish

    raise Invalid, "Hydrophone command timestamps fall outside its K1 lane"
  end

  def hydrophone_options(args)
    options = {}
    until args.empty?
      flag, value = args.shift.split("=", 2)
      raise Invalid, "K1 Hydrophone command contains a repeated flag or an unexpected argument" if !flag.start_with?("--") || options.key?(flag)

      options[flag] = value || (flag == "--conformance" ? "true" : args.shift)
    end
    options
  end

  def timestamps(record, start_key, finish_key)
    record.values_at(start_key, finish_key).map { |value| Time.iso8601(value) }
  end

  def definition_codenames(path, expected)
    definition = Lock.conformance_definition
    bytes = File.binread(path)
    unless Digest::SHA256.hexdigest(bytes) == definition.fetch("sha256") && expected == definition.fetch("test_count")
      raise Invalid, "K1 Conformance definition does not match the upstream pin"
    end

    entries = YAML.safe_load(bytes)
    codenames = entries.map { |entry| entry.fetch("codename") } if entries.is_a?(Array) && entries.all?(Hash)
    unless codenames&.length == expected && codenames.uniq.length == expected && codenames.all?(String)
      raise Invalid, "K1 Conformance definition must contain #{expected} unique codenames"
    end

    codenames
  end

  def fingerprints(lane)
    junit = Conformance::ArchivedArtifact.recorded_digests(lane, JUNIT)
    ginkgo = lane["ginkgo"]
    {"junit" => junit.first, "ginkgo" => ginkgo.is_a?(Hash) ? ginkgo["raw_sha256"] : nil}
      .select { |_format, digest| SHA256.match?(digest.to_s) }
  end
end
