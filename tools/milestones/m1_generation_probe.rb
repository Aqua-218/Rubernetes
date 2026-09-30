#!/usr/bin/env ruby
# frozen_string_literal: true

# Regenerate the schema tree twice and compare both runs with the checked-in tree.

require "tmpdir"
require_relative "m1_probe_support"

M1ProbeSupport.run_probe("m1_generation_diff") do |_current, input|
  corpus = File.join(ROOT, "schema/kubernetes/v1.36.2")
  generator = File.join(ROOT, "tools/schema/generate.rb")
  canonical = M1ProbeSupport.tree_snapshot(
    File.join(ROOT, "generated"),
    ignore_prefixes: ["platform", "README.md"]
  )
  corpus_snapshot = M1ProbeSupport.tree_snapshot(corpus)
  corpus_digest = M1ProbeSupport.tree_digest(corpus_snapshot)
  runs = []
  run_snapshots = []

  Dir.mktmpdir("rubernetes-m1-generation-") do |directory|
    2.times do |index|
      output = File.join(directory, "run-#{index + 1}")
      command = M1ProbeSupport.run_command(
        RbConfig.ruby,
        generator,
        "--corpus",
        corpus,
        "--output",
        output
      )
      snapshot = M1ProbeSupport.tree_snapshot(output)
      run_snapshots << snapshot
      run = {
        "id" => "run-#{index + 1}",
        "command" => command.fetch("command"),
        "exit_status" => command.fetch("exit_status"),
        "tree_sha256" => M1ProbeSupport.tree_digest(snapshot),
        "file_count" => snapshot.length,
        "stdout" => command.fetch("stdout"),
        "stderr" => command.fetch("stderr")
      }
      run["error"] = command.fetch("error") if command.key?("error")
      runs << run
    end
  end

  byte_differences = if run_snapshots.length == 2
                       M1ProbeSupport.tree_differences(run_snapshots.fetch(0), run_snapshots.fetch(1))
                     else
                       [{"path" => "generated", "kind" => "run-missing"}]
                     end
  check_command = M1ProbeSupport.run_command(
    RbConfig.ruby,
    generator,
    "--corpus",
    corpus,
    "--output",
    File.join(ROOT, "generated"),
    "--check"
  )
  canonical_differences = if run_snapshots.empty?
                            [{"path" => "generated", "kind" => "run-missing"}]
                          else
                            M1ProbeSupport.tree_differences(canonical, run_snapshots.fetch(0))
                          end
  run_digests = runs.map { |run| run.fetch("tree_sha256") }
  command_failures = runs.count { |run| run.fetch("exit_status") != 0 } + (check_command.fetch("exit_status").zero? ? 0 : 1)
  missing_count = canonical_differences.count { |entry| entry.fetch("kind") == "missing" }
  unexpected_count = canonical_differences.count { |entry| entry.fetch("kind") == "unexpected" }
  {
    "runs" => runs,
    "canonical_tree_sha256" => M1ProbeSupport.tree_digest(canonical),
    "corpus_input_sha256" => corpus_digest,
    "corpus_input_file_count" => corpus_snapshot.length,
    "canonical_check" => check_command,
    "byte_differences" => byte_differences,
    "canonical_differences" => canonical_differences,
    "byte_diff_count" => byte_differences.length,
    "tree_diff_count" => byte_differences.length,
    "canonical_diff_count" => canonical_differences.length,
    "canonical_tree_diff_count" => canonical_differences.length,
    "missing_count" => missing_count,
    "unexpected_count" => unexpected_count,
    "failure_count" => command_failures + byte_differences.length + canonical_differences.length,
    "passed" => input.fetch("stable") && command_failures.zero? && byte_differences.empty? &&
      run_digests.length == 2 && run_digests.uniq.length == 1 &&
      run_digests.all?(M1ProbeSupport.tree_digest(canonical))
  }
end
