# frozen_string_literal: true

require_relative "../conformance/archived_artifact"
require_relative "../conformance/k3_observations"
require_relative "m8_k3_replacements"

module M8K3Evidence
  Lanes = Conformance::Lanes
  K3 = Lanes::K3
  Lock = Conformance::Lock
  Archive = Conformance::ArchivedArtifact
  Build = Conformance::K3BuildReceipt
  Invalid = Archive::Invalid
  CASE = "k3_required_campaign"
  MANIFEST_PATH = %r{\A[a-zA-Z0-9_-][a-zA-Z0-9_.-]*/manifest\.json\z}
  CLASSIFICATIONS = %w[required platform-inapplicable provider-private implementation-internal].freeze
  FORBIDDEN_REASONS = ["LinuxOnly", "Disruptive", "Slow", "Serial", "Flaky", "Feature:",
                       "unimplemented", "not implemented", "fails", "timeout", "hard to set up"].freeze

  class Campaign
    def initialize(reference, ledger_bytes:, run_root: M8K3Evidence.run_root, binary: Lanes.tool_path("e2e.test"))
      @reference = reference
      @ledger_sha = Digest::SHA256.hexdigest(ledger_bytes)
      @ledger = JSON.parse(ledger_bytes)
      raise Invalid, "expected a K3 ledger object" unless @ledger.is_a?(Hash)

      @run_root = run_root
      @binary = binary
    end

    def verify
      read_manifest!
      selection = read("upstream-selection.json")
      chunks = validate_selection!(selection)
      contracts = validate_ledger!
      validate_provenance!(selection)
      chunks.each_with_index { |ids, index| verify_chunk!(ids, index, selection.fetch("binary_path")) }
      M8K3Replacements.new(contracts, method(:read), method(:artifact)).verify!
      {"passed" => true, "status" => "verified", "run_id" => @manifest.fetch("runId"),
       "required" => @required.length, "verified_required" => @required.length, "verified_replacements" => contracts.length,
       "ledger_sha256" => @ledger_sha, "classification_counts" => @ledger.fetch("counts")}
    rescue Invalid, ArgumentError, KeyError, TypeError, SystemCallError, JSON::ParserError, REXML::ParseException,
           Conformance::ReportArchive::Error => error
      {"passed" => false, "status" => "unverified", "detail" => error.message}
    end

    private

    def read_manifest!
      unless @reference.is_a?(Hash) && @reference["path"].is_a?(String) && MANIFEST_PATH.match?(@reference["path"]) &&
             /\A[0-9a-f]{64}\z/.match?(@reference["sha256"].to_s)
        raise Invalid, "K3 requires a hash-pinned campaign manifest"
      end

      path = File.join(File.realpath(@run_root), @reference.fetch("path"))
      @directory = File.dirname(path)
      raise Invalid, "K3 original campaign manifest is missing or outside its archive directory" unless File.file?(path) && File.realpath(path) == path

      bytes = File.binread(path)
      raise Invalid, "K3 original campaign manifest SHA-256 differs" unless Digest::SHA256.hexdigest(bytes) == @reference["sha256"]

      @manifest = JSON.parse(bytes)
      raise Invalid, "expected a K3 conformance runner manifest" unless @manifest.is_a?(Hash) && @manifest["suite"] == "K0-K7-kubernetes-compatibility"

      lanes = Array(@manifest["lanes"]).grep(Hash).select { |lane| lane["lane"] == "K3" }
      raise Invalid, "expected exactly one K3 lane in the original campaign" unless lanes.one?

      @lane = lanes.first
      return if @lane["status"] == "COMPLETE" && @lane["passed"] == true

      raise Invalid, "original K3 lane is #{@lane["status"]}: #{@lane["reason"] || "required coverage and replacements are incomplete"}"
    end

    def validate_selection!(selection)
      entries = @ledger.fetch("tests")
      raise Invalid, "K3 ledger must contain an array of entries" unless entries.is_a?(Array) && entries.all?(Hash)

      @required = entries.select { |entry| entry["classification"] == "required" }.map { |entry| entry.fetch("id") }
      chunks = selection["chunks"]
      unless chunks.is_a?(Array) && chunks.all? { |chunk| chunk.is_a?(Array) && !chunk.empty? && chunk.all?(String) }
        raise Invalid, "K3 original selection must record nonempty exact-ID chunks"
      end

      ids = chunks.flatten
      unless !@required.empty? && ids.length == @required.length && ids.sort == @required.sort
        raise Invalid, "K3 selected #{(ids & @required).length} of #{@required.length} required ledger IDs; " \
                       "#{ids.length - ids.uniq.length} duplicate and #{(ids - @required).uniq.length} unexpected"
      end
      unless selection["ledger_sha256"] == @ledger_sha && selection["kubernetes_tag"] == Lock.kubernetes.fetch("source").fetch("tag") &&
             selection["kubernetes_tag"] == @ledger.dig("source", "kubernetes_tag")
        raise Invalid, "K3 original selection is for a different ledger or upstream tag"
      end

      chunks
    end

    def validate_ledger!
      entries = @ledger.fetch("tests")
      counts = entries.map { |entry| entry.fetch("classification") }.tally
      unless entries.length == @ledger.dig("source", "spec_count") && entries.map { |entry| entry.fetch("id") }.uniq.length == entries.length &&
             counts == @ledger["counts"] && (counts.keys - CLASSIFICATIONS).empty?
        raise Invalid, "K3 ledger inventory and classification counts must agree for every unique test ID"
      end

      excluded = entries.reject { |entry| entry["classification"] == "required" }
      if excluded.any? { |entry| FORBIDDEN_REASONS.any? { |word| entry.fetch("reason").to_s.include?(word) } }
        raise Invalid, "K3 ledger contains a forbidden exclusion reason"
      end

      contracts = excluded.select { |entry| entry["external_contract"] == true }
      unlinked = contracts.count { |entry| !K3.linked_replacement?(entry) }
      raise Invalid, "K3 ledger has #{unlinked} unlinked external contracts" if unlinked.positive?

      contracts
    end

    def validate_provenance!(selection)
      profile = Lock.profiles.fetch("profiles").find { |entry| entry.fetch("name") == @manifest["profile"] }
      revision = @manifest["rubernetesCommit"]
      unless profile && @manifest["profileDefinition"] == profile && selection["profile"] == profile["name"] &&
             @manifest["platform"] == "#{profile.fetch("os")}/#{profile.fetch("architecture")}" &&
             @manifest["sourceCommit"] == Lock.source_commit &&
             @manifest["inputsLock"] == Lock::KUBERNETES.delete_prefix("#{Lock::ROOT}/") &&
             /\A(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})\z/.match?(revision.to_s) &&
             @manifest["rubernetesSourceStable"] == true && @manifest["rubernetesCommitAfter"] == revision &&
             @manifest["runId"].is_a?(String) && !@manifest["runId"].empty?
        raise Invalid, "K3 campaign provenance must match the pinned source, stable revision and Linux profile"
      end

      @lane_start, @lane_finish = times(@lane, "startedAt", "finishedAt")
      run_start, run_finish = times(@manifest, "startedAt", "finishedAt")
      valid_times = @lane_start.between?(run_start, @lane_finish) && @lane_finish <= run_finish
      raise Invalid, "K3 lane timestamps fall outside the recorded run" unless valid_times

      verify_binary_receipt!(selection)
    end

    def verify_binary_receipt!(selection)
      sha256 = selection["binary_sha256"]
      platform = @manifest.fetch("platform")
      if File.basename(selection.fetch("binary_path")) != File.basename(Build::TARGET) || !/\A[0-9a-f]{64}\z/.match?(sha256.to_s)
        raise Invalid, "K3 original selection does not identify the stock executable"
      end

      name = "k3/#{Build::ARTIFACT}"
      archived = [@manifest, @lane].any? { |record| !Archive.references(record, name).empty? }
      if archived
        bytes = File.binread(artifact(Build::ARTIFACT))
        return if Build.matches?(bytes, sha256: sha256, platform: platform)
      elsif Build.local(@binary, sha256: sha256, platform: platform, allow_legacy: true)
        return
      end

      raise Invalid, "K3 stock executable requires a matching build receipt for the pinned source and platform"
    end

    def verify_chunk!(ids, index, binary_path)
      basename = format("e2e-command-%03d", index)
      chunk_dir = format("chunk-%03d", index)
      record = read("#{basename}.json")
      started, finished = times(record, "started_at", "finished_at")
      if record["timed_out"] != false || record["exit_status"] != 0 ||
         !started.between?(@lane_start, finished) || finished > @lane_finish
        raise Invalid, "K3 #{basename} did not complete successfully during the lane"
      end

      report_dir = validate_command!(record, ids, chunk_dir, binary_path)
      %w[stdout stderr].each do |stream|
        name = "#{basename}.#{stream}.gz"
        raise Invalid, "K3 #{basename} does not name its original #{stream}" unless record["#{stream}_artifact"] == name

        artifact(name)
      end
      reports = Conformance::K3JUnit.paths(File.join(@directory, "k3", chunk_dir))
      raise Invalid, "K3 #{chunk_dir} must contain one original JUnit report" unless reports.one?

      filename = File.basename(reports.first)
      path = artifact("#{chunk_dir}/#{filename}", top_level_only: true)
      sha256 = Conformance::K3JUnit.recorded_digest(record["junit_report"], File.join(report_dir, filename))
      outcomes = Conformance::K3Observations.read_report(path, ids, sha256: sha256, require_clean_suite: true)
      missed = outcomes.reject { |_, outcome| outcome == "passed" }
      raise Invalid, "K3 #{chunk_dir} did not pass every selected ID in the original JUnit: #{missed}" unless missed.empty?
    end

    def validate_command!(record, ids, chunk_dir, binary_path)
      command = record.fetch("command")
      command = command.drop(4) if command.is_a?(Array) && command.take(3) == %w[ip netns exec] && /\A[A-Za-z0-9_.-]+\z/.match?(command[3].to_s)
      expected = [binary_path, "--provider=skeleton", "--kubeconfig", nil, "--kubectl-path", nil,
                  "--ginkgo.focus=#{K3.focus_pattern(ids)}", nil]
      unless command.is_a?(Array) && command.length == expected.length && command.all?(String) &&
             expected.each_with_index.all? { |argument, index| !argument || command[index] == argument } &&
             !command[3].empty? && File.basename(command[5]) == "kubectl-#{@ledger.dig("source", "kubernetes_tag")}" &&
             command[7].start_with?("--report-dir=") && command[7].end_with?("/k3/#{chunk_dir}")
        raise Invalid, "K3 #{chunk_dir} command differs from the exact pinned skeleton selection"
      end

      command[7].delete_prefix("--report-dir=")
    end

    def times(record, start, finish)
      [Time.iso8601(record.fetch(start)), Time.iso8601(record.fetch(finish))]
    end

    def read(name)
      result = JSON.parse(File.binread(artifact(name)))
      raise Invalid, "expected a JSON object in K3 #{name}" unless result.is_a?(Hash)

      result
    end

    def artifact(name, top_level_only: false, unique_format: false)
      return Archive.verify_format!(@manifest, @lane, @directory, "k3/#{name}") if unique_format

      Archive.verify!(@manifest, top_level_only ? @manifest : @lane, @directory, "k3/#{name}")
    end
  end

  module_function

  def run_root
    File.expand_path(ENV.fetch("RUBERNETES_M8_RUN_ROOT", "artifacts/conformance"), Lock::ROOT)
  end

  def reference(path)
    root = File.realpath(run_root)
    relative = File.expand_path(path, Lock::ROOT).delete_prefix("#{run_root}/")
    original = File.join(root, relative)
    unless MANIFEST_PATH.match?(relative) && File.realpath(original) == original
      raise Invalid, "K3 original campaign is outside the configured conformance archive root"
    end

    {"path" => relative, "sha256" => Digest::SHA256.file(original).hexdigest}
  end

  def verify(reference, ledger_bytes: File.binread(K3::LEDGER))
    Campaign.new(reference, ledger_bytes: ledger_bytes).verify
  rescue Invalid, SystemCallError, JSON::ParserError => error
    {"passed" => false, "status" => "unverified", "detail" => error.message}
  end
end
