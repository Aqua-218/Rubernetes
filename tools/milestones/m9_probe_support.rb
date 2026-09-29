# frozen_string_literal: true

# Shared helpers for the M9 release probes.  Each probe reads a report that a
# tools/release/* runner produced; nothing here re-derives a release criterion
# from anything but a recorded run.

require "digest"
require "json"
require "time"

require_relative "m5_probe_support"

module M9ProbeSupport
  ROOT = M5ProbeSupport::ROOT
  RELEASE_ROOT = ENV.fetch("RUBERNETES_M9_RELEASE_ROOT", File.join(ROOT, "artifacts/release"))

  module_function

  def now = M5ProbeSupport.now

  def report(kind:, measurement_level:, started_at:, cases:, extra: {})
    document = M5ProbeSupport.report(kind: kind, measurement_level: measurement_level,
                                     started_at: started_at, cases: cases, extra: extra)
    document.merge("milestone" => "M9",
                   "input_sha256" => ENV.fetch("RUBERNETES_M9_INPUT_SHA256", document["input_sha256"]),
                   "input_file_count" => ENV["RUBERNETES_M9_INPUT_FILE_COUNT"] ? Integer(ENV["RUBERNETES_M9_INPUT_FILE_COUNT"]) : document["input_file_count"])
  end

  def emit(document) = M5ProbeSupport.emit(document)

  # A release report that was never produced is missing, never a pass.
  def load(name)
    path = File.join(RELEASE_ROOT, name)
    return {"available" => false, "path" => path.delete_prefix("#{ROOT}/")} unless File.file?(path)

    JSON.parse(File.read(path)).merge(
      "available" => true,
      "path" => path.delete_prefix("#{ROOT}/"),
      "sha256" => Digest::SHA256.file(path).hexdigest
    )
  rescue JSON::ParserError => error
    {"available" => false, "path" => path.delete_prefix("#{ROOT}/"), "error" => error.message}
  end

  def digest_file(path) = Digest::SHA256.file(path).hexdigest
end
