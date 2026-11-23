# frozen_string_literal: true

require "json"
require "time"
require_relative "lock"

module Conformance
  # The pinned upstream Node Conformance suite exercises both sides of the
  # default runtime's RecursiveReadOnlyMounts capability on the same node.
  module K4RRO
    SOURCE_COMMIT = "24e2b02af5543d7910c2bb074c7264df5a8f0467"
    FILE = "k8s.io/kubernetes/test/e2e_node/mount_rro_linux_test.go"
    PREFIX = "[sig-node] Mount recursive read-only [LinuxOnly] [NodeConformance] Mount recursive read-only"
    BEFORE = "rro-node-before.json"
    AFTER = "rro-node-after.json"
    OBSERVATIONS = [BEFORE, AFTER].freeze
    SNAPSHOT_TIMEOUT = 30
    CASES = {
      true => {41 => ["should accept recursive read-only mounts", 45], 84 => ["should reject invalid recursive read-only mounts", 88]}.freeze,
      false => {130 => ["should accept non-recursive read-only mounts", 135], 171 => ["should reject recursive read-only mounts", 176]}.freeze
    }.freeze

    module_function

    def node_list_command(kubectl, endpoint, kubeconfig)
      [kubectl, "--kubeconfig=#{kubeconfig}", "--server=#{endpoint}", "get", "--raw", "/api/v1/nodes"]
    end

    def observed_support(before, after, node:, execution:)
      return unless before && after && before["command"] == after["command"]

      namespace, invocation = split_namespace(execution.fetch("command"))
      separator = invocation.index("--")
      return unless separator

      arguments = invocation.drop(separator + 1)
      kubectl = arguments.find { |arg| arg.start_with?("--kubectl-path=") }&.delete_prefix("--kubectl-path=")
      endpoint = arguments.find { |arg| arg.start_with?("--host=") }&.delete_prefix("--host=")
      return if kubectl.to_s.empty? || endpoint.to_s.empty?

      before_start, before_end, run_start, run_end, after_start, after_end = [before, execution, after].flat_map do |capture|
        capture.values_at("started_at", "finished_at").map { |value| Time.iso8601(value) }
      end
      return unless before_end.between?(before_start, run_start) && after_start.between?(run_end, after_end) && run_start <= run_end &&
                    run_start - before_end <= SNAPSHOT_TIMEOUT && after_start - run_end <= SNAPSHOT_TIMEOUT &&
                    before_end - before_start <= SNAPSHOT_TIMEOUT + 1 && after_end - after_start <= SNAPSHOT_TIMEOUT + 1

      first = read_support(before, node, namespace, kubectl, endpoint)
      last = read_support(after, node, namespace, kubectl, endpoint)
      first if first == last
    rescue ArgumentError, KeyError, TypeError
      nil
    end

    def split_namespace(command)
      command.take(3) == %w[ip netns exec] ? [command[3], command.drop(4)] : [nil, command]
    end

    def read_support(capture, target, namespace, kubectl, endpoint)
      observed_namespace, command = split_namespace(capture.fetch("command"))
      kubeconfig = command[1]&.delete_prefix("--kubeconfig=")
      return unless capture.values_at("exit_status", "timed_out", "timeout_seconds") == [0, false, SNAPSHOT_TIMEOUT] &&
                    namespace == observed_namespace && !kubeconfig.to_s.empty? && command == node_list_command(kubectl, endpoint, kubeconfig)

      document = JSON.parse(capture.fetch("stdout"))
      nodes = document["items"]
      return unless document.values_at("kind", "apiVersion") == %w[NodeList v1] && nodes.is_a?(Array) && nodes.one?

      node = nodes.first
      metadata = target.fetch("metadata")
      uid = metadata["uid"]
      ready = Array(node.dig("status", "conditions")).any? { |condition| condition.values_at("type", "status") == %w[Ready True] }
      return unless uid.is_a?(String) && !uid.empty? && ready && node.fetch("metadata").values_at("name", "uid") == metadata.values_at("name", "uid")

      defaults = Array(node.dig("status", "runtimeHandlers")).select { |handler| handler["name"] == "" }
      supported = defaults.first.dig("features", "recursiveReadOnlyMounts") if defaults.one?
      supported if CASES.key?(supported)
    rescue JSON::ParserError, NoMethodError
      nil
    end

    def expected_skips(support, selected, observations, suite:)
      conditional = skip_records(support)
      return [] if conditional.empty?

      reciprocal = CASES.fetch(support).keys.map { |line| identity(support, line) }
      return [] unless reciprocal.all? do |id|
        result = observations.fetch(id, [])
        selected.key?(id) && result.one? && single_attempt?(result.first, "passed") &&
        result.first["Failure"].nil? && executed_in_suite?(result.first, suite)
      end

      return [] unless conditional.all? do |record|
        id = record.fetch("id")
        result = observations.fetch(id, [])
        selected.key?(id) && result.one? && guarded_skip?(result.first, record) && executed_in_suite?(result.first, suite)
      end

      conditional
    end

    def skip_records(support)
      return [] unless Lock.source_commit == SOURCE_COMMIT && CASES.key?(support)

      CASES.fetch(!support).map do |line, (_name, guard)|
        reason = support ? "runtime supports recursive read-only mounts" : "runtime does not support recursive read-only mounts"
        {"id" => identity(!support, line), "reason" => reason, "guard" => {"file" => FILE, "line" => guard}, "runtime_supports_rro" => support}
      end
    end

    def identity(support, line)
      condition = support ? "supports" : "does not support"
      name = CASES.fetch(support).fetch(line).first
      {"name" => "#{PREFIX} when the runtime #{condition} recursive read-only mounts #{name}", "file" => FILE, "line" => line}
    end

    def guarded_skip?(spec, record)
      failure = spec["Failure"]
      single_attempt?(spec, "skipped") && failure.is_a?(Hash) &&
        failure.values_at("Message", "FailureNodeContext", "FailureNodeType") == [record["reason"], "leaf-node", "It"] &&
        failure.dig("Location", "FileName") == FILE && failure.dig("Location", "LineNumber") == record.dig("guard", "line") &&
        failure.dig("FailureNodeLocation", "FileName") == FILE && failure.dig("FailureNodeLocation", "LineNumber") == record.dig("id", "line")
    end

    def single_attempt?(spec, state)
      spec.values_at("State", "NumAttempts") == [state, 1] && Array(spec["AdditionalFailures"]).empty?
    end

    def executed_in_suite?(spec, suite)
      started, finished = spec.values_at("StartTime", "EndTime").map { |value| Time.iso8601(value) }
      suite_start, suite_finish = suite.values_at("StartTime", "EndTime").map { |value| Time.iso8601(value) }
      started >= suite_start && started < finished && finished <= suite_finish
    rescue ArgumentError, TypeError
      false
    end
  end
end
