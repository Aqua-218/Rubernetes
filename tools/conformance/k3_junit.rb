# frozen_string_literal: true

require "digest"
require "rexml/parsers/pullparser"
require "stringio"

require_relative "report_archive"

module Conformance
  # Stores completed stock Ginkgo reports without changing the upstream XML.
  module K3JUnit
    REPORTS = "junit_*.xml{,.gz}"
    Error = ReportArchive::Error

    module_function

    def paths(directory)
      files = Dir.glob(File.join(directory, REPORTS))
      files.group_by { |path| path.delete_suffix(".gz") }.flat_map do |xml, variants|
        archive = "#{xml}.gz"
        if variants.length == 2 && equivalent?(xml, archive)
          [archive]
        else
          variants
        end
      end
    end

    def equivalent?(xml, archive)
      Digest::SHA256.file(xml).hexdigest == archived_xml_sha256(archive)
    rescue Errno::ENOENT
      # The archive is published before its XML sibling is unlinked.
      !File.exist?(xml) && File.file?(archive)
    rescue Error
      false
    end

    def with_xml(path, sha256: nil)
      open_report(path) do |io|
        next yield(io) unless sha256

        bytes = io.read
        raise Error, "JUnit XML checksum differs from the execution record" unless Digest::SHA256.hexdigest(bytes) == sha256

        yield StringIO.new(bytes)
      end
    end

    def read(path, sha256: nil)
      with_xml(path, sha256: sha256, &:read)
    end

    def recorded_digest(metadata, path)
      return unless metadata

      archive = metadata.is_a?(Hash) && metadata["path"]
      digest = metadata.is_a?(Hash) && metadata["xml_sha256"]
      if archive.is_a?(String) && File.expand_path(archive).delete_suffix(".gz") == File.expand_path(path).delete_suffix(".gz") &&
         digest.is_a?(String) && digest.match?(/\A[0-9a-f]{64}\z/)
        return digest
      end

      raise Error, "invalid JUnit report identity in the execution record"
    end

    def open_report(path, &)
      file = ReportArchive.open_report(path)
      if file.path.end_with?(".gz")
        ReportArchive.read_gzip(file, label: "JUnit gzip", &)
      else
        yield file
      end
    ensure
      file&.close
    end

    def archived_xml_sha256(path)
      File.open(path, "rb") do |file|
        ReportArchive.read_gzip(file, label: "JUnit gzip") { |reader| ReportArchive.stream_sha256(reader) }
      end
    end

    def complete_xml?(bytes)
      parser = REXML::Parsers::PullParser.new(bytes)
      depth = 0
      root = nil
      while parser.has_next?
        event = parser.pull
        if event.start_element?
          if depth.zero?
            return false if root || !%w[testsuite testsuites].include?(event[0])

            root = event[0]
          end
          depth += 1
        elsif event.end_element?
          depth -= 1
        end
      end
      !root.nil? && depth.zero?
    rescue REXML::ParseException
      false
    end

    # The caller has waited for the upstream process. A truncated XML remains
    # in its original file for diagnostics. A completed capture may be retried.
    def archive_completed(directory)
      reports = paths(directory)
      return unless reports.one?

      path = reports.first
      xml = path.delete_suffix(".gz")
      bytes = read(path)
      return unless complete_xml?(bytes)

      artifact = ReportArchive.retain(xml, bytes: bytes)
      return unless artifact.key?("uncompressed_sha256")

      {"path" => "#{xml}.gz", "sha256" => artifact.fetch("sha256"),
       "xml_sha256" => artifact.fetch("uncompressed_sha256"), "xml_bytes" => artifact.fetch("uncompressed_bytes")}
    rescue SystemCallError, Error, Zlib::Error
      # Compression is optional. Existing bytes stay readable when it fails.
      nil
    end
  end
end
