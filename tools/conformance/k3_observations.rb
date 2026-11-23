# frozen_string_literal: true

require "digest"
require "optparse"
require "rexml/parsers/pullparser"
require "tempfile"
require_relative "lanes"

module Conformance
  # Searchable history of exact upstream executions. The same ID can be
  # observed in several fixtures or revisions. K3's live gate remains the
  # completeness check for the selected cluster profile.
  module K3Observations
    module_function

    def collect(roots)
      ledger_bytes = File.binread(Lanes::K3::LEDGER)
      ledger = JSON.parse(ledger_bytes)
      required = ledger.fetch("tests").select { |entry| entry["classification"] == "required" }
      tag = ledger.dig("source", "kubernetes_tag")
      binary = Lanes.tool_path("e2e.test")
      raise ArgumentError, "pinned e2e.test is missing" unless binary

      digest = Digest::SHA256.file(binary).hexdigest
      records = Hash.new { |observations, id| observations[id] = [] }
      rejected = []
      roots.map { |root| File.expand_path(root) }.uniq.sort.each do |root|
        observe_fixture(root, tag: tag, binary: binary, digest: digest, records: records, rejected: rejected)
      end
      summaries = required.map { |entry| summarize_spec(entry, records.fetch(entry.fetch("id"), [])) }
      {
        "kind" => "k3_observations",
        "kubernetes_tag" => tag,
        "binary_sha256" => digest,
        "current_ledger_sha256" => Digest::SHA256.hexdigest(ledger_bytes),
        "required" => required.size,
        "observed" => summaries.count { |summary| !summary.fetch("observations").empty? },
        "with_pass" => summaries.count { |summary| summary.fetch("observed_pass") },
        "by_source_file" => summarize_files(summaries),
        "specs" => summaries,
        "rejected_inputs" => rejected
      }
    end

    def observe_fixture(root, tag:, binary:, digest:, records:, rejected:)
      provenance = %w[upstream-selection.json family-results.json results.json]
        .map { |name| File.join(root, name) }.find { |path| File.file?(path) }
      return unless provenance

      fixture = JSON.parse(File.read(provenance))
      raise ArgumentError, "expected fixture provenance as an object" unless fixture.is_a?(Hash)
      return unless fixture["kubernetes_tag"] == tag && fixture["binary_sha256"] == digest

      if File.basename(provenance) == "upstream-selection.json"
        observe_lane(fixture, provenance: provenance, binary: binary, records: records, rejected: rejected)
        return
      end

      archives = diagnostic_archives(fixture)
      Dir.glob(File.join(root, "{,*/}selection.json")).each do |path|
        suite_directory = File.dirname(path)
        command_path = File.join(suite_directory, "command.json")
        next unless File.file?(command_path)

        ids = JSON.parse(File.read(path))
        command = JSON.parse(File.read(command_path))
        observe_execution(ids, command, binary: binary, provenance: provenance,
                                        selection: path, command_path: command_path, records: records,
                                        report: archives[File.basename(suite_directory)])
      rescue ArgumentError, JSON::ParserError, REXML::ParseException, K3JUnit::Error, SystemCallError => error
        rejected << {"path" => path, "detail" => error.message}
      end
    rescue ArgumentError, JSON::ParserError => error
      rejected << {"path" => provenance, "detail" => error.message}
    end

    def diagnostic_archives(fixture)
      rows = fixture["suite_results"]
      return {} unless rows.is_a?(Array)

      rows.each_with_object({}) do |row, archives|
        next unless row.is_a?(Hash) && row["archived_junit"]

        name = row["suite"]
        raise ArgumentError, "duplicate JUnit archive metadata for #{name.inspect}" if archives.key?(name)

        archives[name] = row["archived_junit"]
      end
    end

    def observe_lane(fixture, provenance:, binary:, records:, rejected:)
      chunks = fixture["chunks"]
      raise ArgumentError, "expected ordered selections from the pinned K3 binary" unless fixture["binary_path"] == binary && chunks.is_a?(Array)

      chunks.each_with_index do |ids, index|
        command_path = File.join(File.dirname(provenance), format("e2e-command-%03d.json", index))
        next unless File.file?(command_path)

        execution = JSON.parse(File.read(command_path))
        raise ArgumentError, "expected an execution record as an object" unless execution.is_a?(Hash)

        command = execution["command"]
        command = command.drop(4) if command.is_a?(Array) && command.take(3) == %w[ip netns exec]
        observe_execution(ids, command, binary: binary, provenance: provenance,
                                        selection: provenance, command_path: command_path, records: records, report: execution["junit_report"])
      rescue ArgumentError, JSON::ParserError, REXML::ParseException, K3JUnit::Error, SystemCallError => error
        rejected << {"path" => command_path, "detail" => error.message}
      end
    end

    def observe_execution(ids, command, binary:, provenance:, selection:, command_path:, records:, report: nil)
      unless ids.is_a?(Array) && !ids.empty? && ids.all?(String) && ids.uniq.length == ids.length &&
             command.is_a?(Array) && command.all?(String) && command.first == binary &&
             command.grep(/\A--provider(?:=|\z)/) == ["--provider=skeleton"] &&
             command.grep(/\A--ginkgo\.focus(?:=|\z)/) == ["--ginkgo.focus=#{Lanes::K3.focus_pattern(ids)}"]
        raise ArgumentError, "expected the exact pinned ledger selection and skeleton provider"
      end

      directory_argument = command.find { |argument| argument.start_with?("--report-dir=") }
      return unless directory_argument

      directory = File.expand_path(directory_argument.delete_prefix("--report-dir="))
      raise ArgumentError, "JUnit report directory is outside the fixture" unless directory.start_with?("#{File.dirname(provenance)}/")

      paths = K3JUnit.paths(directory)
      return if paths.empty? # The fixture can still be running.
      raise ArgumentError, "expected one raw Ginkgo JUnit report" unless paths.one?

      digest = K3JUnit.recorded_digest(report, paths.first)
      read_report(paths.first, ids, sha256: digest).each do |id, outcome|
        records[id] << {"outcome" => outcome, "junit" => paths.first, "selection" => selection,
                        "command" => command_path, "provenance" => provenance}
      end
    end

    def read_report(path, ids, sha256: nil, require_clean_suite: false)
      selected = ids.to_h { |id| [id, true] }
      outcomes = Hash.new { |results, id| results[id] = [] }
      suite = []
      scan_junit(path, sha256: sha256, succeeded: suite) do |attributes, markers|
        name = REXML::Text.unnormalize(attributes["name"].to_s)
        outcome = junit_outcome(attributes["status"], markers)
        unless name.start_with?("[It] ")
          raise ArgumentError, "JUnit hook did not pass: #{name}" if require_clean_suite && outcome != "passed"

          next
        end

        id = Lanes::K3.junit_spec_id(name)
        if selected.key?(id)
          outcomes[id] << outcome
        elsif outcome != "skipped"
          raise ArgumentError, "JUnit includes an unexpected execution of #{id.inspect}"
        end
      end
      raise ArgumentError, "original JUnit suite did not succeed" if require_clean_suite && suite != ["true"]

      ids.to_h do |id|
        values = outcomes.fetch(id, [])
        outcome = if values.one?
                    values.first
                  elsif values.empty?
                    "not_reported"
                  else
                    "duplicate"
                  end
        [id, outcome]
      end
    end

    # A focused Ginkgo report still has thousands of skipped rows. Pull just
    # the direct testcase attributes and outcome nodes to avoid building a DOM
    # for all those rows and the full diagnostic text of failures.
    def scan_junit(path, sha256: nil, succeeded: [])
      parents = []
      suites = 0
      attributes = nil
      markers = []
      K3JUnit.with_xml(path, sha256: sha256) do |file|
        parser = REXML::Parsers::PullParser.new(file)
        while parser.has_next?
          event = parser.pull
          if event.start_element?
            parents << event[0]
            case parents
            when %w[testsuite], %w[testsuites testsuite]
              suites += 1
            when %w[testsuite testcase], %w[testsuites testsuite testcase]
              attributes = event[1]
            when %w[testsuite properties property], %w[testsuites testsuite properties property]
              succeeded << event[1]["value"] if event[1]["name"] == "SuiteSucceeded"
            else
              markers << event[0] if attributes && parents[-2] == "testcase"
            end
          elsif event.end_element?
            next unless parents.pop == "testcase" && attributes

            yield attributes, markers
            attributes = nil
            markers = []
          end
        end
      end
      raise ArgumentError, "expected one complete Ginkgo suite" unless suites == 1 && parents.empty?
    end

    def junit_outcome(status, markers)
      return "failed" if markers.include?("failure") || markers.include?("error")
      return "skipped" if markers.include?("skipped") || %w[skipped pending].include?(status)

      status == "passed" ? "passed" : "failed"
    end

    def summarize_spec(entry, observations)
      {"id" => entry.fetch("id"), "source_file" => entry.fetch("file"),
       "observed_pass" => observations.any? { |observation| observation["outcome"] == "passed" }, "observations" => observations}
    end

    def summarize_files(specs)
      specs.group_by { |spec| spec.fetch("source_file") }.sort.to_h.transform_values do |rows|
        {"required" => rows.length, "with_pass" => rows.count { |row| row.fetch("observed_pass") }}
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  options = {output: nil}
  parser = OptionParser.new do |arguments|
    arguments.banner = "Usage: ruby tools/conformance/k3_observations.rb [--output PATH] FIXTURE..."
    arguments.on("--output PATH", "Write the index to PATH") { |path| options[:output] = path }
  end
  roots = parser.parse(ARGV)
  abort(parser.to_s) if roots.empty?

  evidence = JSON.pretty_generate(Conformance::K3Observations.collect(roots)) << "\n"
  if options[:output]
    path = File.expand_path(options[:output])
    Tempfile.create(".k3-observations", File.dirname(path)) do |file|
      file.write(evidence)
      file.close
      File.rename(file.path, path)
    end
  else
    puts(evidence)
  end
end
