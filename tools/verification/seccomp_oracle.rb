#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require_relative "lean_oracle"
require_relative "../../lib/rubernetes/platform/linux/security"

module SeccompOracle
  SOURCE = File.expand_path("../../verification/lean/Seccomp.lean", __dir__)
  LINUX = Rubernetes::Platform::Linux
  SEED = 20_260_918
  MAX_WORD = (1 << 64) - 1
  BOUNDARIES = [0, 1, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, MAX_WORD - 1, MAX_WORD].freeze
  ALLOW = 0x7fff_0000
  ERRNO = 0x0005_000b
  KILL = 0x8000_0000

  module_function

  def run(lean: LeanOracle.executable, seed: SEED)
    random = Random.new(seed)
    cases = %w[x86_64 aarch64].flat_map { |arch| corpus(arch, random) }
    reference = LeanOracle.run(SOURCE, cases.map(&:first), lean: lean)

    mismatches = cases.each_with_index.filter_map do |(input, bpf, profile), index|
      expected = reference.fetch(index)
      {"input" => input, "bpf" => bpf, "profile" => profile, "lean" => expected} unless bpf == expected && profile == expected
    end
    {"passed" => mismatches.empty?, "seed" => seed, "cases" => cases.length,
     "source_sha256" => Digest::SHA256.file(SOURCE).hexdigest, "mismatches" => mismatches}
  end

  def corpus(architecture, random)
    compiler = LINUX::SeccompCompiler.new(architecture: architecture)
    names = %w[read write getpid]
    syscalls = compiler.syscall_numbers.slice(*names)
    audit_arch = LINUX::Security::ARCHITECTURES.fetch(architecture)
    LINUX::Seccomp::OPERATORS.flat_map do |operator|
      operands = BOUNDARIES + Array.new(8) { random.rand(0..MAX_WORD) }
      operands.flat_map do |operand|
        index = random.rand(0..5)
        arguments = Array.new(6, 0)
        expected = operand & random.rand(0..MAX_WORD)
        condition = LINUX::Seccomp::Arg.from("index" => index, "op" => operator, "value" => operand, "valueTwo" => expected)
        rules = [
          LINUX::Seccomp::Rule.new(names: %w[read write], action: :allow, errno_ret: nil, args: [condition]),
          LINUX::Seccomp::Rule.new(names: %w[read], action: :errno, errno_ret: 11, args: []),
          LINUX::Seccomp::Rule.new(names: %w[getpid], action: :allow, errno_ret: nil, args: [])
        ]
        profile = LINUX::Seccomp::Profile.new(default_action: :kill, rules: rules)
        instructions = compiler.compile(profile: profile).instructions
        lowered = [
          {"numbers" => syscalls.values_at("read", "write"), "conditions" => [condition.to_h], "result" => ALLOW},
          {"numbers" => [syscalls.fetch("read")], "conditions" => [], "result" => ERRNO},
          {"numbers" => [syscalls.fetch("getpid")], "conditions" => [], "result" => ALLOW}
        ]
        names.product(BOUNDARIES + [operand, expected]).map do |name, actual|
          record_args = arguments.dup
          record_args[index] = actual
          number = syscalls.fetch(name)
          input = {"rules" => lowered, "fallback" => KILL, "nr" => number, "arguments" => record_args}
          record = {"nr" => number, "arch" => audit_arch, "args" => record_args}
          actual_bpf = LINUX::Seccomp::Interpreter.run(instructions, record)
          action, error = profile.evaluate(name, record_args)
          ruby_profile = {allow: ALLOW, errno: 0x0005_0000, kill: KILL}.fetch(action) | (error || 0)
          [input, actual_bpf, ruby_profile]
        end
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  report = SeccompOracle.run
  puts JSON.pretty_generate(report)
  exit(report.fetch("passed") ? 0 : 1)
end
