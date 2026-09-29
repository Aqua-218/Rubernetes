#!/usr/bin/env ruby
# frozen_string_literal: true

# Project-owned M3 effect boundary control. It talks to the same HTTP API
# process as the worker processes; it never creates a local MemoryStore or a
# fake watch/effect target. The annotation is an idempotent effect marker, so a
# retry with the same effect ID is observed as one semantic side effect.

require "json"
require "digest"
require "time"

ROOT = File.expand_path("../../../..", __dir__).freeze
require File.join(ROOT, "lib", "rubernetes", "client")
require File.join(ROOT, "lib", "rubernetes", "controller", "effect_journal")

module M3EffectControl
  module_function

  def run
    request = JSON.parse($stdin.read, create_additions: false, max_nesting: 128)
    raise ArgumentError, "effect control request must be an object" unless request.is_a?(Hash)
    raise ArgumentError, "effect control request schema_version must be 1" unless request["schema_version"] == 1

    endpoint = ENV.fetch("RUBERNETES_M3_API_ENDPOINT")
    client = Rubernetes::Client::KubernetesClient.new(server: endpoint)
    target = normalize_target(request.fetch("target"))
    phase = request.fetch("phase").to_s
    component = request.fetch("component").to_s
    reconcile_key = request.fetch("reconcile_key").to_s
    effect_type = request.fetch("effect_type", "reconcile").to_s
    generation = request.dig("leader", "generation").to_s
    raise ArgumentError, "effect control leader generation is required" if generation.empty?
    journal = Rubernetes::Controller::EffectJournal.from_env(component: component, identity: request.dig("leader", "identity"))
    effect_key = journal&.effect_key(reconcile_key: reconcile_key, effect_type: effect_type) ||
                 [component, reconcile_key, effect_type].join("|")
    effect_id = journal&.effect_id(reconcile_key: reconcile_key, effect_type: effect_type, generation: generation) ||
                ["rubernetes", component, generation, effect_type, Digest::SHA256.hexdigest(reconcile_key)[0, 32]].join(":")
    lease = read_lease(client, request.fetch("lease"))
    old_leader = request.dig("leader", "identity").to_s
    actor_alive = process_generation_alive?(request.fetch("leader"))
    actor_is_holder = lease["holder_identity"] == old_leader

    observation = {
      "component" => component,
      "phase" => phase,
      "effect_id" => effect_id,
      "target" => target,
      "lease_holder" => lease["holder_identity"],
      "lease_resource_version" => lease["resource_version"],
      "old_leader" => old_leader,
      "generation" => generation,
      "effect_key" => effect_key,
      "reconcile_key" => reconcile_key,
      "effect_type" => effect_type,
      "actor_alive" => actor_alive,
      "observed_at" => Time.now.utc.iso8601(6)
    }

    if phase == "fence_check"
      passed = request.dig("leader", "observed_exit") == true &&
               !old_leader.empty? && lease["holder_identity"] != old_leader && !actor_alive
      observation["action"] = "observation_only"
      observation["stale_leader_rejected"] = passed
      return JSON.pretty_generate(result(
        request: request,
        effect_id: effect_id,
        effect_key: effect_key,
        reconcile_key: reconcile_key,
        effect_type: effect_type,
        generation: generation,
        passed: passed,
        stale: false,
        stale_rejected: passed,
        effect_attempt_ids: [effect_id],
        mutation_count: 0,
        observation: observation
      ))
    end

    # A request issued by a killed or fenced process is a successful safety
    # observation only when it produces no API mutation. The lease holder and
    # the kernel process generation are both checked; identity alone is not a
    # sufficient process identity after an in-place restart.
    unless actor_is_holder && actor_alive
      observation["action"] = "stale_rejected"
      observation["stale_leader_rejected"] = true
      return JSON.pretty_generate(result(
        request: request,
        effect_id: effect_id,
        effect_key: effect_key,
        reconcile_key: reconcile_key,
        effect_type: effect_type,
        generation: generation,
        passed: true,
        stale: false,
        stale_rejected: true,
        effect_attempt_ids: [effect_id],
        mutation_count: 0,
        observation: observation
      ))
    end

    before = client.get(target.fetch("kind"), target.fetch("name"), namespace: target["namespace"], api_version: target.fetch("api_version"))
    annotations = (before.dig("metadata", "annotations") || {}).dup
    marker_key = "rubernetes.io/m3-effect-key"
    marker_id_key = "rubernetes.io/m3-effect-id"
    applied = false
    unless annotations[marker_key].to_s == effect_key
      patch_body = {"metadata" => {"annotations" => annotations.merge(marker_key => effect_key, marker_id_key => effect_id)}}
      after_patch = client.patch(
        target.fetch("kind"),
        patch_body,
        type: :merge,
        namespace: target["namespace"],
        api_version: target.fetch("api_version"),
        name: target.fetch("name")
      )
      journal&.record(effect_type: effect_type, reconcile_key: reconcile_key, action: :patch,
                     object: patch_body, response: after_patch, generation: generation,
                     effect_id: effect_id, extra: {"phase" => phase, "target" => target})
      applied = true
    end

    # This is the retry boundary: replaying the same effect ID is a read-only
    # confirmation rather than a second mutation.
    after = client.get(target.fetch("kind"), target.fetch("name"), namespace: target["namespace"], api_version: target.fetch("api_version"))
    observed_key = after.dig("metadata", "annotations", marker_key).to_s
    observed_id = after.dig("metadata", "annotations", marker_id_key).to_s
    passed = observed_key == effect_key
    observation["action"] = applied ? "apply_once_then_idempotent_retry" : "idempotent_retry"
    observation["target_resource_version"] = after.dig("metadata", "resourceVersion")
    observation["observed_effect_id"] = observed_id
    observation["observed_effect_key"] = observed_key
    observation["mutation_count"] = applied ? 1 : 0

    JSON.pretty_generate(result(
      request: request,
      effect_id: effect_id,
      effect_key: effect_key,
      reconcile_key: reconcile_key,
      effect_type: effect_type,
      generation: generation,
      passed: passed,
      stale: !passed,
      stale_rejected: false,
      effect_attempt_ids: [effect_id],
      mutation_count: applied ? 1 : 0,
      observation: observation
    ))
  end

  def normalize_target(value)
    raise ArgumentError, "effect target must be an object" unless value.is_a?(Hash)

    target = {
      "kind" => value.fetch("kind").to_s,
      "api_version" => value.fetch("api_version").to_s,
      "namespace" => value["namespace"]&.to_s,
      "name" => value.fetch("name").to_s
    }
    raise ArgumentError, "effect target name must not be empty" if target["name"].empty?
    target
  end

  def read_lease(client, value)
    lease = value.is_a?(Hash) ? value : {}
    object = client.get(
      "leases",
      lease.fetch("name"),
      namespace: lease.fetch("namespace", "kube-system"),
      api_version: "coordination.k8s.io/v1"
    )
    {
      "holder_identity" => object.dig("spec", "holderIdentity").to_s,
      "resource_version" => object.dig("metadata", "resourceVersion").to_s
    }
  end

  def result(request:, effect_id:, effect_key:, reconcile_key:, effect_type:, generation:, passed:, stale:, stale_rejected:, effect_attempt_ids:, mutation_count:, observation:)
    attempts = Array(effect_attempt_ids).map(&:to_s).reject(&:empty?)
    mutations = Integer(mutation_count)
    {
      "schema_version" => 1,
      "scenario" => request["scenario"],
      "component" => request["component"],
      "phase" => request["phase"],
      "passed" => passed == true,
      "effect_ids" => [effect_id],
      "effect_key" => effect_key,
      "reconcile_key" => reconcile_key,
      "effect_type" => effect_type,
      "generation" => generation,
      "effect_attempt_ids" => attempts,
      "mutation_count" => mutations,
      "duplicate_side_effect_count" => attempts.length - attempts.uniq.length,
      "stale_side_effect_count" => stale == true ? 1 : 0,
      "double_side_effect_count" => [mutations - 1, 0].max,
      "stale_rejected" => stale_rejected == true,
      "observation" => observation
    }
  end

  def process_generation_alive?(record)
    pid = Integer(record.fetch("pid"))
    Process.kill(0, pid)
    text = File.read("/proc/#{pid}/stat")
    start_time = Integer(text.rpartition(") ").last.split(" ").fetch(19))
    expected = record.fetch("generation").to_s
    expected == [record.fetch("identity"), pid, start_time].join(":")
  rescue Errno::ESRCH, Errno::EPERM, Errno::ENOENT, Errno::EACCES, IndexError, ArgumentError
    false
  end
end

puts M3EffectControl.run if $PROGRAM_NAME == __FILE__
