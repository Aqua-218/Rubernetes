#!/usr/bin/env ruby
# frozen_string_literal: true

# The device cgroup filter compiler (lib/rubernetes/platform/linux/
# device_cgroup.rb) against runc v1.4.3's own emulator + eBPF generator
# (test/conformance/runc/device_filter_oracle, an unmodified copy of
# github.com/opencontainers/cgroups@v0.0.6/devices): random OCI rule lists --
# wildcard resets, allow-list and deny-list modes, wildcard majors/minors,
# permission unions and removals, hole punching, unsorted input, values at
# the uint32 edge -- are compiled by both; the instruction streams (hex, jump
# offsets resolved) and the error messages are compared.
#
#   ruby tools/differential/device_filter_differential.rb [--cases N] [--seed N]

require "json"
require "open3"
require "tmpdir"
require_relative "../../lib/rubernetes/platform/linux/device_cgroup"

module DeviceFilterDifferential
  ROOT = File.expand_path("../..", __dir__)
  ORACLE = File.join(ROOT, "test/conformance/runc/device_filter_oracle")
  DeviceCgroup = Rubernetes::Platform::Linux::DeviceCgroup
  PERMISSIONS = %w[r w m rw rm wm rwm mrw wr].freeze
  MAJORS = [-1, 0, 1, 5, 8, 10, 136, 195, 259, 2**31 - 1, 2**31, 2**32 - 1].freeze
  MINORS = [-1, 0, 1, 2, 3, 5, 7, 8, 9, 200, 255, 2**32 - 1].freeze

  module_function

  def rule(random)
    case random.rand(10)
    when 0 then {"type" => "a", "major" => -1, "minor" => -1, "access" => "rwm", "allow" => random.rand < 0.5}
    else
      {"type" => random.rand < 0.7 ? "c" : "b", "major" => MAJORS.sample(random: random), "minor" => MINORS.sample(random: random),
       "access" => PERMISSIONS.sample(random: random), "allow" => random.rand < 0.75}
    end
  end

  def cases(random, count)
    fixed = [
      DeviceCgroup.rules_for.map(&:to_h),
      DeviceCgroup.rules_for(privileged: true).map(&:to_h),
      DeviceCgroup.rules_for(devices: [{"type" => "c", "major" => 195, "minor" => 0, "access" => "rw", "allow" => true},
                                       {"type" => "b", "major" => 259, "minor" => -1, "access" => "r", "allow" => true}]).map(&:to_h),
      # A device rule with empty permissions (a CRI Device without them).
      DeviceCgroup.rules_for(devices: [{"type" => "c", "major" => 4, "minor" => 1, "access" => "", "allow" => true}]).map(&:to_h)
    ]
    generated = Array.new(count) do
      prefix = random.rand < 0.8 ? [{"type" => "a", "major" => -1, "minor" => -1, "access" => "rwm", "allow" => random.rand < 0.3}] : []
      prefix + Array.new(random.rand(0..7)) { rule(random) }
    end
    (fixed + generated).each_with_index.map { |rules, index| {"name" => "case-#{index}", "rules" => rules} }
  end

  def run_port(test_case)
    instructions, license = DeviceCgroup.compile(test_case["rules"])
    {"name" => test_case["name"], "license" => license, "instructions" => instructions.map { |instruction| instruction.to_binary.unpack1("H*") }}
  rescue DeviceCgroup::Error => error
    {"name" => test_case["name"], "error" => error.message}
  end

  def run_oracle(cases)
    stdout, stderr, status = Open3.capture3("go", "run", ".", stdin_data: JSON.generate(cases), chdir: ORACLE)
    raise "oracle failed:\n#{stderr}" unless status.success?

    JSON.parse(stdout).to_h { |result| [result["name"], result] }
  end

  def compare(expected, actual)
    keys = %w[error license instructions]
    expected.slice(*keys) == actual.slice(*keys)
  end

  def main(argv)
    count = 400
    seed = Random.new_seed % 1_000_000
    argv.each_slice(2) do |flag, value|
      case flag
      when "--cases" then count = Integer(value)
      when "--seed" then seed = Integer(value)
      else raise ArgumentError, "unknown option #{flag}"
      end
    end
    random = Random.new(seed)
    cases = cases(random, count)
    oracle = run_oracle(cases)
    mismatches = cases.reject { |test_case| compare(oracle.fetch(test_case["name"]), run_port(test_case)) }
    puts "device filter differential: seed=#{seed} cases=#{cases.length} errors=#{oracle.values.count { |result| result["error"] }} mismatches=#{mismatches.length}"
    mismatches.first(5).each do |test_case|
      puts JSON.pretty_generate("rules" => test_case["rules"], "oracle" => oracle.fetch(test_case["name"]), "port" => run_port(test_case))
    end
    mismatches.empty? ? 0 : 1
  end
end

exit DeviceFilterDifferential.main(ARGV) if __FILE__ == $PROGRAM_NAME
