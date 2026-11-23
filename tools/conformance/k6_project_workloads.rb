# frozen_string_literal: true

require "json"
require "open3"

module Conformance
  class K6ProjectWorkloads
    def initialize(kubectl:, kubeconfig:, namespace:)
      @command = [kubectl, "--kubeconfig", kubeconfig, "--namespace", namespace, "--request-timeout=30s"]
    end

    def scale(desired, exclusions: {}, targets: [])
      candidates = scale_candidates(targets)
      return {"passed" => false, "stderr" => "the installed chart has no scalable Deployment or StatefulSet"} if candidates.empty?

      retained = scale_exclusions(candidates, exclusions)
      scalable = candidates.reject { |item| exclusions.key?(target(item)) }
      evidence = scalable.map do |item|
        original = item.dig("spec", "replicas") || 1
        exercise_scale(item, original: original, desired: original == desired ? original + 1 : desired)
      end
      {"passed" => evidence.any? && (evidence + retained).all? { |item| item.fetch("passed") }, "workloads" => evidence,
       "upstream_scale_exclusions" => retained}
    rescue RuntimeError, JSON::ParserError => error
      {"passed" => false, "stderr" => error.message}
    end

    def restart
      candidates = %w[deployments statefulsets daemonsets].flat_map { |resource| list(resource) }
      return {"passed" => false, "stderr" => "the installed chart has no workload supporting rollout restart"} if candidates.empty?

      evidence = candidates.map do |item|
        name = target(item)
        checks = [command("rollout", "restart", name)]
        checks << rollout(item) if checks.last.fetch("passed")
        {"target" => name, "passed" => checks.all? { |check| check.fetch("passed") }, "checks" => checks}
      end
      {"passed" => evidence.all? { |item| item.fetch("passed") }, "workloads" => evidence}
    rescue RuntimeError, JSON::ParserError => error
      {"passed" => false, "stderr" => error.message}
    end

    private

    def scale_candidates(targets)
      if targets.empty?
        deployments = list("deployments")
        return deployments.empty? ? list("statefulsets") : deployments
      end

      workloads = %w[deployments statefulsets].flat_map { |resource| list(resource) }.to_h { |item| [target(item), item] }
      targets.map { |name| workloads.fetch(name) { raise "cannot verify declared scale target #{name}" } }
    end

    def scale_exclusions(candidates, exclusions)
      by_name = candidates.to_h { |item| [target(item), item] }
      exclusions.map do |name, contract|
        item = by_name[name] or raise "cannot verify declared scale exclusion #{name}"

        replicas = item.dig("spec", "replicas") || 1
        ready = item.dig("status", "readyReplicas").to_i
        expected = Integer(contract.fetch("replicas"))
        {"target" => name, "replicas" => replicas, "ready_replicas" => ready, "contract" => contract,
         "passed" => replicas == expected && ready == expected}
      end
    end

    def target(item)
      "#{item.fetch("kind").downcase}/#{item.dig("metadata", "name")}"
    end

    def rollout(item)
      grace = item.dig("spec", "template", "spec", "terminationGracePeriodSeconds").to_i
      progress_deadline = item.dig("spec", "progressDeadlineSeconds").to_i
      timeout = [120, grace + 60, progress_deadline].max
      command("rollout", "status", target(item), "--timeout=#{timeout}s")
    end

    def list(resource)
      out, error, status = Open3.capture3(*@command, "get", resource, "-o", "json", binmode: true)
      raise "cannot list #{resource}: #{error.force_encoding(Encoding::UTF_8).scrub.lines.last(5).join.strip}" unless status.success?

      JSON.parse(out.force_encoding(Encoding::UTF_8)).fetch("items")
    end

    def exercise_scale(item, original:, desired:)
      name = target(item)
      checks = [command("scale", name, "--replicas=#{desired}")]
      checks << rollout(item) if checks.last.fetch("passed")
      # The following Helm operation should start from the replica count the
      # chart installed. An independent scale manager may own this field.
      # Restoring the value avoids forcing an SSA ownership conflict on upgrade.
      checks << command("scale", name, "--replicas=#{original}")
      checks << rollout(item) if checks.last.fetch("passed")
      {"target" => name, "original" => original, "scaled" => desired,
       "passed" => checks.all? { |check| check.fetch("passed") }, "checks" => checks}
    end

    def command(*arguments)
      _out, error, status = Open3.capture3(*@command, *arguments, binmode: true)
      {"arguments" => arguments, "passed" => status.success?,
       "stderr" => status.success? ? nil : error.force_encoding(Encoding::UTF_8).scrub.lines.last(5).join.strip}
    end
  end
end
