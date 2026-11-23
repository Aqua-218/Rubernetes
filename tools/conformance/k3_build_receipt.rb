# frozen_string_literal: true

require "open3"
require_relative "lock"

module Conformance
  module K3BuildReceipt
    TARGET = "test/e2e/e2e.test"
    ARTIFACT = "e2e.test.build.json"
    KIND = "conformance_e2e_build"
    COMMAND = ["make", "WHAT=#{TARGET}"].freeze
    PLATFORM = "linux/amd64"

    module_function

    def matches?(bytes, sha256:, platform:)
      target = build_target(bytes, sha256)
      target && platform == PLATFORM && target["platform"] == platform &&
        target["source_commit"] == Lock.source_commit && target["source_clean"] == true && target["command"] == COMMAND
    end

    # An old build report has the commit and binary digest but omits the
    # binary platform. Read that from the matching executable without running it.
    def local(binary, sha256:, platform:, allow_legacy: false)
      return unless binary && File.executable?(binary) && Digest::SHA256.file(binary).hexdigest == sha256

      path = ENV.fetch("RUBERNETES_M8_K3_BUILD_RECEIPT", "#{binary}.build.json")
      bytes = File.binread(path)
      return bytes if matches?(bytes, sha256: sha256, platform: platform)
      return unless allow_legacy && legacy?(bytes, sha256) && go_platform(binary) == platform

      bytes
    rescue SystemCallError
      nil
    end

    def build_target(bytes, sha256)
      return unless /\A[0-9a-f]{64}\z/.match?(sha256.to_s)

      report = JSON.parse(bytes)
      return unless report.is_a?(Hash) && report["schema_version"] == 1 && report["kind"] == KIND &&
                    report["passed"] == true && report["commit"] == Lock.source_commit

      targets = report["targets"]
      return unless targets.is_a?(Array) && targets.one? && targets.first.is_a?(Hash)

      target = targets.first
      return target if target["target"] == File.basename(TARGET) && target["installed"] == true &&
                       target["exit_status"] == 0 && target["sha256"] == sha256

      nil
    rescue JSON::ParserError
      nil
    end

    def legacy?(bytes, sha256)
      target = build_target(bytes, sha256)
      target && (target.keys & %w[platform source_commit source_clean command]).empty?
    end

    def go_platform(binary)
      output, _error, status = Open3.capture3("go", "version", "-m", binary)
      return unless status.success?

      rows = output.lines.map { |line| line.strip.split("\t") }
      return unless rows.include?(["path", "k8s.io/kubernetes/test/e2e.test"])

      settings = rows.filter_map { |section, value| value.split("=", 2) if section == "build" && value&.include?("=") }.to_h
      "#{settings.fetch("GOOS")}/#{settings.fetch("GOARCH")}" if settings.key?("GOOS") && settings.key?("GOARCH")
    rescue Errno::ENOENT
      nil
    end
  end
end
