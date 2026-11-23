# frozen_string_literal: true

require "rexml/document"

module Conformance
  # The framework's JUnit writer omits appended labels, while the Ginkgo CLI
  # preserves them. Both spellings include the upstream spec text and state.
  module K4JUnit
    OUTCOME_ELEMENTS = %w[skipped failure error].freeze
    OUTCOME_BY_STATE = {
      "skipped" => "skipped", "pending" => "skipped", "failed" => "failure",
      "timedout" => "failure", "interrupted" => "error", "panicked" => "error", "aborted" => "error"
    }.freeze

    module_function

    def matches?(bytes, suite, framework:)
      root = REXML::Document.new(bytes).root
      return false unless root&.name == "testsuites" && root.get_elements("testsuite").one?

      report = root.elements["testsuite"]
      return false unless report.attributes["name"] == suite.fetch("SuiteDescription")

      properties = report.get_elements("properties/property").map { |element| [element.attributes["name"], element.attributes["value"]] }
      expected_properties = {
        "SuiteSucceeded" => suite.fetch("SuiteSucceeded").to_s,
        "SuiteHasProgrammaticFocus" => "false", "LabelFilter" => "NodeConformance", "DryRun" => "false",
        "RandomSeed" => suite.fetch("SuiteConfig").fetch("RandomSeed").to_s
      }
      return false unless expected_properties.all? { |key, value| properties.select { |name, _value| name == key } == [[key, value]] }

      observed = report.get_elements("testcase").filter_map do |element|
        name = element.attributes["name"]
        next unless name&.start_with?("[It] ")

        [name, element.attributes["status"], element.elements.map(&:name).select { |tag| OUTCOME_ELEMENTS.include?(tag) }]
      end
      expected = suite.fetch("SpecReports").filter_map do |entry|
        next unless entry.fetch("LeafNodeType") == "It"

        state = entry.fetch("State")
        [case_name(entry, framework: framework), state, Array(OUTCOME_BY_STATE[state])]
      end
      !expected.empty? && observed.tally == expected.tally
    rescue REXML::ParseException
      false
    end

    def case_name(entry, framework:)
      text = [*Array(entry["ContainerHierarchyTexts"]), entry.fetch("LeafNodeText")].reject(&:empty?)
      name = ["[It]", *text]
      labels = [*Array(entry["ContainerHierarchyLabels"]), entry["LeafNodeLabels"]].flatten.compact.uniq
      name << "[#{labels.join(", ")}]" if !framework && !labels.empty?
      semver = [*Array(entry["ContainerHierarchySemVerConstraints"]), entry["LeafNodeSemVerConstraints"]].flatten.compact.uniq
      name << "[#{semver.join(", ")}]" unless semver.empty?
      components = {}
      Array(entry["ContainerHierarchyComponentSemVerConstraints"]).each do |scope|
        scope.each { |component, constraints| (components[component] ||= []).concat(constraints) }
      end
      # Ginkgo v2's JSON omits leaf component constraints that the original
      # JUnit includes. Kubernetes' label preserves the kubelet minimum.
      versions = Array(entry["LeafNodeLabels"]).filter_map { |label| label.delete_prefix("KubeletMinVersion:") if label.start_with?("KubeletMinVersion:") }
      (components["kubelet"] ||= []).concat(versions.map { |version| ">=#{version}" }) unless versions.empty?
      unless components.empty?
        constraints = components.sort.map { |component, versions| "#{component}: [#{versions.chunk_while { |a, b| a == b }.map(&:first).join(" ")}]" }
        name << "[#{constraints.join(", ")}]"
      end
      name.join(" ").strip
    end
  end
end
