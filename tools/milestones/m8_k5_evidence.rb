# frozen_string_literal: true

require "time"
require_relative "../conformance/archived_artifact"
require_relative "../conformance/k5_evidence"

module M8K5Evidence
  module_function

  def verify(manifest, lane, root:)
    return {"passed" => false, "detail" => lane["reason"] || "K5 lane did not complete"} unless lane.values_at("status", "passed") == ["COMPLETE", true]
    unless manifest["sourceCommit"] == Conformance::Lock.source_commit && manifest["rubernetesSourceStable"] == true &&
           manifest["rubernetesCommit"] && manifest["rubernetesCommit"] == manifest["rubernetesCommitAfter"]
      raise ArgumentError, "K5 requires a stable source revision and the pinned Kubernetes oracle"
    end

    directory = File.realpath(File.dirname(File.expand_path(manifest.fetch("_path"), root)))
    execution, report = %w[k5/k5-command.json k5/differential.json].map do |name|
      JSON.parse(File.binread(Conformance::ArchivedArtifact.verify!(manifest, lane, directory, name)))
    end
    unless execution.is_a?(Hash) && report.is_a?(Hash) && execution.values_at("exit_status", "timed_out") == [0, false] &&
           report["observables"] == lane["observables"] && lane["differences"] == 0
      raise ArgumentError, "K5 lane summary differs from its original run"
    end

    timestamps = [manifest["startedAt"], lane["startedAt"], execution["started_at"], report["generated_at"],
                  execution["finished_at"], lane["finishedAt"], manifest["finishedAt"]].map { |value| Time.iso8601(value) }
    raise ArgumentError, "K5 report falls outside the original run" unless timestamps.each_cons(2).all? { |before, after| before <= after }

    mode = cbor_enabled?(execution.fetch("command"))
    Conformance::K5Evidence.verify(report, cbor_enabled: mode)
  rescue Conformance::ArchivedArtifact::Invalid, JSON::ParserError, KeyError, ArgumentError, TypeError, SystemCallError => error
    {"passed" => false, "detail" => error.message}
  end

  def cbor_enabled?(command)
    raise ArgumentError, "malformed K5 command" unless command.is_a?(Array) && command.all? { |arg| arg.is_a?(String) && !arg.empty? }

    command = command.drop(4) if command.take(3) == %w[ip netns exec]
    _ruby, script, *args = command
    raise ArgumentError, "missing K5 differential runner" unless File.basename(script.to_s) == "k5_differential.rb"

    options = {}
    until args.empty?
      key, inline = args.shift.split("=", 2)
      raise ArgumentError, "duplicate K5 flag" if options.key?(key)

      if key == "--cbor-enabled" && inline.nil?
        options[key] = true
      elsif %w[--kubeconfig --oracle-kubeconfig --output].include?(key)
        path = inline || args.shift
        raise ArgumentError, "missing K5 path" if path.to_s.empty? || path.start_with?("-")

        options[key] = path
      else
        raise ArgumentError, "unexpected K5 flag"
      end
    end
    unless %w[--kubeconfig --oracle-kubeconfig --output].all? { |key| options.key?(key) } && options["--kubeconfig"] != options["--oracle-kubeconfig"]
      raise ArgumentError, "K5 command must identify its target, separate oracle and output"
    end

    options.fetch("--cbor-enabled", false)
  end
end
