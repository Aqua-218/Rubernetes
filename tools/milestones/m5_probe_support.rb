# frozen_string_literal: true

# Shared helpers for the M5 durable-HA probes.  Every probe emits one JSON
# report on stdout with the source input identity supplied by the evidence
# runner, a measurement level, and a `passed` verdict computed only from the
# recorded observations.

require "digest"
require "etc"
require "json"
require "rbconfig"
require "time"

module M5ProbeSupport
  ROOT = File.expand_path("../..", __dir__).freeze

  module_function

  def now
    Time.now.utc.iso8601(6)
  end

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def host
    uname = Etc.uname
    {"architecture" => RbConfig::CONFIG.fetch("host_cpu").sub("amd64", "x86_64"), "kernel" => uname.fetch(:release),
     "ruby" => RUBY_DESCRIPTION}
  end

  def source_files(paths)
    paths.map do |relative|
      path = File.join(ROOT, relative)
      {"path" => relative, "sha256" => Digest::SHA256.file(path).hexdigest, "bytes" => File.size(path)}
    end
  end

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(canonical(value)))
  end

  def canonical(value)
    case value
    when Hash then value.keys.map(&:to_s).sort.to_h do |key|
                     [key, canonical(value[value.keys.find do |k|
                       k.to_s == key
                     end])]
                   end
    when Array then value.map { |child| canonical(child) }
    when Symbol then value.to_s
    else value
    end
  end

  def report(kind:, measurement_level:, started_at:, cases:, extra: {})
    passed = cases.all? { |entry| entry["passed"] == true }
    {
      "schema_version" => 1,
      "milestone" => "M5",
      "kind" => kind,
      "input_sha256" => ENV.fetch("RUBERNETES_M5_INPUT_SHA256", nil),
      "input_file_count" => ENV.fetch("RUBERNETES_M5_INPUT_FILE_COUNT", nil) && Integer(ENV.fetch("RUBERNETES_M5_INPUT_FILE_COUNT", nil)),
      "input_stable" => true,
      "host" => host,
      "measurement_level" => measurement_level,
      "started_at" => started_at,
      "finished_at" => now,
      "case_count" => cases.length,
      "passed_count" => cases.count { |entry| entry["passed"] == true },
      "failed_count" => cases.count { |entry| entry["passed"] != true },
      "cases" => cases,
      "status" => passed ? "COMPLETE" : "INCOMPLETE",
      "passed" => passed,
      "available" => true
    }.merge(extra)
  end

  def emit(document)
    $stdout.write(JSON.pretty_generate(document) << "\n")
    $stdout.flush
    exit(document["passed"] ? 0 : 1)
  end
end
