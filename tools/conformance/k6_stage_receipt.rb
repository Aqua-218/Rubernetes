# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"

module Conformance
  # Persist stock outcomes before later observers and cleanup can fail. The
  # progress receipt deliberately excludes command output and object specs.
  class K6StageReceipt
    OUTCOME_FIELDS = %w[stage passed exit_status elapsed_seconds stdout_sha256 started_at finished_at skipped].freeze
    WORKLOAD_FIELDS = %w[replicas readyReplicas availableReplicas updatedReplicas numberReady desiredNumberScheduled numberAvailable].freeze
    LIMIT = 128

    def initialize(directory:, name:, namespace:, kubectl:, kubeconfig:)
      FileUtils.mkdir_p(directory)
      @path = File.join(directory, "#{name}.stages.jsonl")
      @name = name
      @command = [kubectl, "--kubeconfig", kubeconfig, "--request-timeout=8s", "-n", namespace]
      File.open(@path, File::WRONLY | File::CREAT | File::TRUNC | File::NOFOLLOW, 0o600, &:close)
    end

    def record(outcome)
      return unless outcome

      summary = outcome.slice(*OUTCOME_FIELDS).merge("project" => @name)
      failure = outcome["stderr"].to_s
      summary["failure"] = failure_reason(failure) unless failure.empty?
      append(summary)
      stage = outcome.fetch("stage")
      append({"project" => @name, "stage" => stage, "readiness" => readiness}) if %w[install ready].include?(stage) && !outcome.key?("skipped")
    end

    private

    def append(record)
      File.open(@path, File::WRONLY | File::APPEND | File::NOFOLLOW) do |file|
        file.puts(JSON.generate(record))
        file.fsync
      end
    end

    def failure_reason(output)
      return "deployment_progress_deadline" if output.match?(/Progress(?:\s+deadline\s+exceeded|DeadlineExceeded)/i)
      return "wait_timeout" if output.match?(/context deadline exceeded|timed out waiting|WaitTimeout/i)

      "command_failed"
    end

    def readiness
      output, _, status = Open3.capture3(*@command, "get", "deployment,statefulset,daemonset,pod", "-o", "json", binmode: true)
      return {"measured" => false, "exit_status" => status.exitstatus} unless status.success?

      items = JSON.parse(output.force_encoding(Encoding::UTF_8)).fetch("items")
      return {"measured" => false, "reason" => "invalid workload readiness snapshot"} unless items.is_a?(Array)

      {"measured" => true, "total" => items.length, "truncated" => items.length > LIMIT,
       "objects" => items.first(LIMIT).filter_map { |item| readiness_object(item) }}
    rescue JSON::ParserError, EncodingError, KeyError, SystemCallError
      {"measured" => false, "reason" => "cannot read workload readiness"}
    end

    def readiness_object(item)
      return unless item.is_a?(Hash) && item["metadata"].is_a?(Hash)

      status = item["status"] || {}
      conditions = Array(status["conditions"]).first(16).map { |state| state.slice("type", "status", "reason").select { |_key, value| compact_reason?(value) } }
      containers = (Array(status["containerStatuses"]) + Array(status["initContainerStatuses"])).first(32).map do |state|
        reason = state.dig("state", "waiting", "reason")
        state.slice("name", "ready").merge("waiting" => (reason if compact_reason?(reason))).compact
      end
      {"kind" => item.fetch("kind"), **item.fetch("metadata").slice("name", "uid"), **status.slice(*WORKLOAD_FIELDS, "phase"),
       "conditions" => conditions, "containers" => containers}
    end

    def compact_reason?(value)
      value.to_s.match?(/\A[A-Za-z][A-Za-z0-9]{0,63}\z/)
    end
  end
end
