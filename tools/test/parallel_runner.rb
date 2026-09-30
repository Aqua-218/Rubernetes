#!/usr/bin/env ruby
# frozen_string_literal: true

# Developer fast lane for the full suite: every test file runs in its own
# process, N at a time, longest-first.  Files that share build/ or measure the
# source tree (the milestone gates and probes) run one at a time in a dedicated
# serial worker so they never see another file's artifacts.  The evidence path
# (`rake test`, one process, JUnit bound to the rake command) is unchanged.
#
#   ruby tools/test/parallel_runner.rb [--jobs N] [--pattern GLOB] [--verbose]
#
# Exit status is non-zero when any file fails, errors, exits abnormally or
# prints no Minitest summary.  RUBERNETES_M2_LEDGER_CYCLES defaults to 100 here
# (the release probe keeps 1000); set it explicitly to override.

require "etc"
require "fileutils"
require "open3"
require "optparse"
require "rbconfig"
require "shellwords"

module ParallelTestRunner
  ROOT = File.expand_path("../..", __dir__)
  LOAD_PATHS = %w[lib test build/ext/rubernetes_linux].freeze
  SUMMARY = /(\d+) runs, (\d+) assertions, (\d+) failures, (\d+) errors, (\d+) skips/
  # Serial group: gate/probe tests that hash the source tree, build the gem under
  # build/, or exercise host-global kernel state.  Ordered longest first.
  SERIAL = %w[
    test/unit/m1_gate_test.rb
    test/unit/m0_gate_test.rb
    test/integration/m1_probes_test.rb
    test/unit/m2_gate_test.rb
    test/unit/m1_kubernetes_validation_oracle_test.rb
    test/unit/m1_kubernetes_semantic_oracle_test.rb
    test/integration/m1_gem_contents_test.rb
    test/integration/executables_test.rb
    test/unit/m3_gate_test.rb
    test/unit/m4_gate_test.rb
    test/unit/m5_gate_test.rb
  ].freeze
  # Known long files go first so the tail of the run is short.
  HEAVY = %w[
    test/integration/m2_runtime_probe_test.rb
    test/integration/network_policy_native_kernel_test.rb
    test/unit/rubectl_client_test.rb
  ].freeze

  # Long files whose tests are independent (each builds its own fixture under a
  # temp dir) are split by test name into K processes.  Every test name in the
  # file lands in exactly one shard; the summary checks the file's total runs.
  SHARDS = {
    "test/unit/m1_gate_test.rb" => 6,
    "test/unit/m0_gate_test.rb" => 3
  }.freeze

  Result = Struct.new(:file, :seconds, :status, :runs, :assertions, :failures, :errors, :skips, :output, :label)
  Job = Struct.new(:file, :label, :name_filter)

  module_function

  def main(argv)
    options = {jobs: [Etc.nprocessors / 2, 4].max, pattern: "test/**/*_test.rb", verbose: false}
    OptionParser.new do |parser|
      parser.on("--jobs N", Integer) { |n| options[:jobs] = n }
      parser.on("--pattern GLOB") { |g| options[:pattern] = g }
      parser.on("--verbose") { options[:verbose] = true }
    end.parse!(argv)

    ENV["RUBERNETES_M2_LEDGER_CYCLES"] ||= "100"
    prebuild_fixture_gem
    files = Dir.chdir(ROOT) { Dir.glob(options[:pattern]).sort }
    raise "no test files match #{options[:pattern]}" if files.empty?

    # Phase 1: the tree-hashing gate/probe files (sharded or serial) together with
    # the long M2 probe, which only writes under build/ and /tmp.  Nothing else runs,
    # so a test that legitimately writes inside the tree for a moment (TLC drops its
    # states/ next to the spec under verification/tla) can never change the source
    # inventory while a gate test is hashing it.  Phase 2: everything else.
    serial = (SERIAL & files) - SHARDS.keys
    phase1 = (HEAVY & files) + (SHARDS.keys & files)
    phase2 = files - serial - phase1
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    results = []
    mutex = Mutex.new
    record = lambda do |result|
      mutex.synchronize do
        results << result
        report_line(result, options[:verbose])
      end
    end

    serial_worker = Thread.new do
      serial.each { |file| record.call(run_job(Job.new(file, file, nil))) }
    end
    run_pool(phase1.flat_map { |file| jobs_for(file) }, options[:jobs], record)
    serial_worker.join
    run_pool(phase2.flat_map { |file| jobs_for(file) }, options[:jobs], record)

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    summarize(results, files.length, elapsed)
  end

  FIXTURE_GEM = File.join(ROOT, "build/rubernetes-0.1.0.gem")

  # The M0/M1 gate tests need the fixture gem at exactly build/rubernetes-0.1.0.gem.
  # Building it once here (and telling the tests so) lets gate files and shards run
  # concurrently against one immutable file instead of racing `gem build`.
  def prebuild_fixture_gem
    FileUtils.mkdir_p(File.dirname(FIXTURE_GEM))
    output, status = Open3.capture2e("gem", "build", "rubernetes.gemspec", "--output", FIXTURE_GEM, chdir: ROOT)
    raise "fixture gem build failed: #{output}" unless status.success?

    ENV["RUBERNETES_TEST_FIXTURE_GEM_PREBUILT"] = "1"
  end

  def run_pool(jobs, size, record)
    queue = Queue.new
    jobs.each { |job| queue << job }
    queue.close
    Array.new(size) do
      Thread.new do
        while (job = queue.pop)
          record.call(run_job(job))
        end
      end
    end.each(&:join)
  end

  def jobs_for(file)
    shards = SHARDS[file]
    return [Job.new(file, file, nil)] unless shards

    names = File.read(File.join(ROOT, file)).scan(/^\s*def (test_\w+)/).flatten
    raise "#{file}: no test methods found for sharding" if names.empty?

    groups = Array.new([shards, names.length].min) { [] }
    names.each_with_index { |name, index| groups[index % groups.length] << name }
    groups.each_with_index.map do |group, index|
      Job.new(file, "#{file} [shard #{index + 1}/#{groups.length}]", "/\\A(?:#{group.map { |name| Regexp.escape(name) }.join("|")})\\z/")
    end
  end

  def run_job(job)
    command = [RbConfig.ruby, "-w", *LOAD_PATHS.map { |path| "-I#{path}" }, job.file]
    command += ["-n", job.name_filter] if job.name_filter
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output, status = Open3.capture2e({"RUBERNETES_JUNIT" => nil}, *command, chdir: ROOT)
    seconds = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
    match = output.scan(SUMMARY).last
    counts = match ? match.map(&:to_i) : [nil, nil, nil, nil, nil]
    Result.new(job.file, seconds, status, *counts, output, job.label)
  end

  def failed?(result)
    !result.status.success? || result.runs.nil? || result.failures.to_i.positive? || result.errors.to_i.positive?
  end

  def report_line(result, verbose)
    marker = failed?(result) ? "FAIL" : "ok  "
    line = format("%s %7.1fs %s", marker, result.seconds, result.label)
    if result.runs
      line += format("  (%d runs, %d failures, %d errors, %d skips)", result.runs, result.failures, result.errors,
                     result.skips)
    end
    line += "  (exit #{result.status.exitstatus.inspect}, no summary)" if result.runs.nil?
    $stdout.puts(line)
    $stdout.flush
    $stdout.puts(result.output) if verbose && failed?(result)
  end

  def summarize(results, expected_files, elapsed)
    failed = results.select { |result| failed?(result) }
    totals = %i[runs assertions failures errors skips].map { |key| results.sum { |result| result.public_send(key).to_i } }
    $stdout.puts
    $stdout.puts(format("%d files (%d expected), %d runs, %d assertions, %d failures, %d errors, %d skips in %.0fs wall",
                        results.map(&:file).uniq.length, expected_files, *totals, elapsed))
    slowest = results.sort_by { |result| -result.seconds }.first(5)
    $stdout.puts("slowest: " + slowest.map { |result| format("%s %.0fs", File.basename(result.file), result.seconds) }.join(", "))
    unless failed.empty?
      $stdout.puts
      failed.each do |result|
        $stdout.puts("==== #{result.label} (exit #{result.status.exitstatus.inspect})")
        $stdout.puts(result.output.lines.last(60).join)
      end
    end
    files_seen = results.map(&:file).uniq.length
    shard_errors = SHARDS.keys.filter_map do |file|
      parts = results.select { |result| result.file == file }
      next if parts.empty?

      declared = File.read(File.join(ROOT, file)).scan(/^\s*def (test_\w+)/).length
      ran = parts.sum { |result| result.runs.to_i }
      "#{file}: shards ran #{ran} tests, file declares #{declared}" unless ran == declared
    end
    shard_errors.each { |message| $stdout.puts("SHARD MISMATCH #{message}") }
    ok = failed.empty? && files_seen == expected_files && shard_errors.empty?
    $stdout.puts(ok ? "PARALLEL TEST RUN PASSED" : "PARALLEL TEST RUN FAILED")
    ok ? 0 : 1
  end
end

exit ParallelTestRunner.main(ARGV) if $PROGRAM_NAME == __FILE__
