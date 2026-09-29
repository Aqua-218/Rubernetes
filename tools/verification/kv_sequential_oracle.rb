#!/usr/bin/env ruby
# frozen_string_literal: true

# Differential check between the Ruby sequential KV model used by the
# linearizability checker and the Lean executable reference
# (verification/lean/KVSequential.lean).  Per D4 the Lean program is a test
# oracle; the Ruby model is only trusted after it matches on the corpus.

require "json"
require "open3"
require "digest"

require_relative "linearizability"

module KVSequentialOracle
  ROOT = File.expand_path("../..", __dir__)
  LEAN_SOURCE = File.join(ROOT, "verification/lean/KVSequential.lean")

  module_function

  def lean_executable
    candidates = [ENV["RUBERNETES_LEAN"], "/root/.elan/bin/lean", "lean"].compact
    candidates.find { |candidate| candidate.include?("/") ? File.executable?(candidate) : system("which #{candidate} >/dev/null 2>&1") }
  end

  def random_corpus(seed:, sequences:, length:)
    random = Random.new(seed)
    keys = %w[a b c]
    Array.new(sequences) do
      versions = {}
      Array.new(length) do
        key = keys.sample(random: random)
        case random.rand(5)
        when 0 then {"op" => "create", "key" => key, "value" => random.rand(100)}
        when 1 then {"op" => "update", "key" => key, "value" => random.rand(100), "expected_version" => random.rand < 0.5 ? (versions[key] || random.rand(1..6)) : nil}.compact
        when 2 then {"op" => "delete", "key" => key, "expected_version" => random.rand < 0.5 ? random.rand(1..6) : nil}.compact
        else {"op" => "read", "key" => key}
        end.tap { |op| versions[key] = (versions[key] || 0) + 1 }
      end
    end
  end

  def ruby_outputs(sequence)
    model = Linearizability::KVModel.new
    state = model.initial_state
    sequence.map do |op|
      state, output = model.step(state, op)
      output
    end
  end

  def lean_outputs(sequence, lean:)
    stdout, stderr, status = Open3.capture3(lean, "--run", LEAN_SOURCE, stdin_data: JSON.generate(sequence), chdir: File.dirname(LEAN_SOURCE))
    raise "lean oracle failed (#{status.exitstatus}): #{stderr}" unless status.success?

    JSON.parse(stdout)
  end

  def normalize(output)
    output.transform_values { |value| value.is_a?(Float) && value == value.floor ? value.to_i : value }.sort.to_h
  end

  def run(seed: 20_260_906, sequences: 40, length: 12)
    lean = lean_executable
    raise "lean executable is unavailable" unless lean

    corpus = random_corpus(seed: seed, sequences: sequences, length: length)
    mismatches = []
    corpus.each_with_index do |sequence, index|
      ruby = ruby_outputs(sequence).map { |output| normalize(output) }
      lean_result = lean_outputs(sequence, lean: lean).map { |output| normalize(output) }
      next if ruby == lean_result

      mismatches << {"sequence_index" => index, "operations" => sequence, "ruby" => ruby, "lean" => lean_result}
    end
    {
      "schema_version" => 1,
      "kind" => "kv_sequential_oracle_differential",
      "lean_source" => LEAN_SOURCE.delete_prefix("#{ROOT}/"),
      "lean_source_sha256" => Digest::SHA256.file(LEAN_SOURCE).hexdigest,
      "lean_executable" => lean,
      "lean_version" => `#{lean} --version`.strip,
      "seed" => seed,
      "sequences" => sequences,
      "operations_per_sequence" => length,
      "compared_operations" => sequences * length,
      "mismatches" => mismatches,
      "passed" => mismatches.empty?
    }
  end
end

if $PROGRAM_NAME == __FILE__
  report = KVSequentialOracle.run
  puts JSON.pretty_generate(report)
  exit(report["passed"] ? 0 : 1)
end
