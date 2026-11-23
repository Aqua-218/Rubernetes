# frozen_string_literal: true

require "rexml/document"
require "yaml"

require_relative "lock"

module Conformance
  # Adapts the pinned upstream Ginkgo JUnit representation to the K1 contract.
  module K1Evidence
    L = Lock
    FOCUS = "\\[Conformance\\]"

    module_function

    def definition(source_root)
      lock = L.conformance_definition
      path = File.join(source_root, lock.fetch("path"))
      bytes = File.binread(path)
      raise ArgumentError, "upstream conformance definition digest mismatch" unless Digest::SHA256.hexdigest(bytes) == lock.fetch("sha256")

      codenames = YAML.safe_load(bytes).map { |entry| entry.fetch("codename") }
      unless codenames.length == lock.fetch("test_count") && codenames.uniq.length == codenames.length
        raise ArgumentError, "upstream conformance definition must contain #{lock.fetch("test_count")} unique codenames"
      end

      [bytes, codenames]
    end

    def junit(path, codenames:, stdout:)
      document = REXML::Document.new(File.read(path))
      suites = REXML::XPath.match(document, "/testsuite | /testsuites/testsuite")
      raise ArgumentError, "Ginkgo JUnit must contain exactly one test suite" unless suites.length == 1

      suite = suites.first
      properties = suite.get_elements("properties/property").to_h { |property| [property.attributes["name"], property.attributes["value"]] }
      cases = suite.get_elements("testcase")
      raise ArgumentError, "JUnit testcase count does not match the suite" unless Integer(suite.attributes.fetch("tests").value, 10) == cases.length

      specs, hooks = cases.partition { |entry| entry.attributes["name"].to_s.start_with?("[It] ") }
      selected, unselected = specs.partition { |entry| entry.attributes["name"].include?("[Conformance]") }
      selected_codenames = selected.map { |entry| entry.attributes["name"].delete_prefix("[It] ") }
      outcomes = selected.map { |entry| outcome(entry) }.tally
      summary = {
        "selected" => selected.length, "passed" => outcomes.fetch("passed", 0), "failed" => outcomes.fetch("failed", 0),
        "skipped" => outcomes.fetch("skipped", 0),
        "flaked" => stdout.each_line.sum { |line| line.b.scan(/\[FLAKEY TEST - TOOK \d+ ATTEMPTS TO PASS\]/).length },
        "suite_passed" => properties["SuiteSucceeded"] == "true" && hooks.all? { |hook| outcome(hook) == "passed" },
        "setup_teardown_failures" => hooks.reject { |hook| outcome(hook) == "passed" }.map { |hook| hook.attributes["name"] },
        "unexpected_executions" => unselected.reject { |entry| outcome(entry) == "skipped" }.map { |entry| entry.attributes["name"] },
        "unselected" => unselected.length, "suite_hooks" => hooks.length,
        "execution_properties_match" => execution_properties_match?(properties)
      }
      joined = {
        "definition_available" => true, "definition_count" => codenames.length, "executed_count" => selected.length,
        "duplicate_codenames" => selected_codenames.tally.select { |_name, count| count > 1 }.keys,
        "unmatched_codenames" => codenames - selected_codenames, "unexpected_codenames" => selected_codenames - codenames
      }
      report = {"cases" => selected.zip(selected_codenames).map { |entry, codename| [codename, entry.attributes["status"]] },
                "random_seed" => properties["RandomSeed"]}
      [summary, joined, report]
    end

    def execution_properties_match?(properties)
      properties["FocusStrings"] == FOCUS && properties["SkipStrings"] == "" &&
        properties["FocusFiles"] == "" && properties["SkipFiles"] == "" &&
        properties["LabelFilter"] == "" && properties["SemVerFilter"] == "" &&
        properties["SuiteHasProgrammaticFocus"] == "false" && properties["DryRun"] == "false" &&
        properties["ParallelTotal"] == "1" && %w[0 1].include?(properties["FlakeAttempts"])
    end

    def complete?(summary, codenames, expected:)
      summary.fetch("selected") == expected && summary.fetch("passed") == expected &&
        summary.fetch("failed").zero? && summary.fetch("skipped").zero? && summary.fetch("flaked").zero? &&
        summary.fetch("suite_passed") && summary.fetch("execution_properties_match") &&
        summary.fetch("unexpected_executions").empty? && codenames.fetch("unexpected_codenames").empty? &&
        codenames.fetch("unmatched_codenames").empty? && codenames.fetch("duplicate_codenames").empty?
    end

    def outcome(entry)
      return "failed" if entry.elements["failure"] || entry.elements["error"]
      return "skipped" if entry.elements["skipped"] || %w[skipped pending].include?(entry.attributes["status"])

      entry.attributes["status"] == "passed" ? "passed" : "failed"
    end
  end
end
