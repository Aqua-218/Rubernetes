# frozen_string_literal: true

require "rubygems/package"
require "tempfile"
require "zlib"

require_relative "k1_evidence"

module Conformance
  module K2Evidence
    module_function

    def read(archive, codenames:)
      documents = read_documents(archive)
      xml = documents["junit_01.xml"]
      log = documents["e2e.log"]
      return {"passed" => false, "reason" => "Sonobuoy archive lacks the e2e JUnit report or log"} if xml.to_s.empty? || log.to_s.empty?

      summary, joined = Tempfile.create(["sonobuoy", ".xml"]) do |file|
        file.binmode
        file.write(xml)
        file.flush
        K1Evidence.junit(file.path, codenames: codenames, stdout: log)
      end
      {"passed" => K1Evidence.complete?(summary, joined, expected: codenames.length),
       "summary" => summary, "codenames" => joined}
    rescue ArgumentError, Gem::Package::TarInvalidError, REXML::ParseException, Zlib::Error, EOFError => error
      {"passed" => false, "reason" => "invalid Sonobuoy archive: #{error.message}"}
    end

    def read_documents(archive)
      documents = {}
      Zlib::GzipReader.open(archive) do |gzip|
        Gem::Package::TarReader.new(gzip).each do |entry|
          next unless entry.file? && entry.full_name.delete_prefix("./").start_with?("plugins/e2e/")

          name = File.basename(entry.full_name)
          next unless %w[junit_01.xml e2e.log].include?(name)
          raise ArgumentError, "multiple e2e #{name} files" if documents.key?(name)

          documents[name] = entry.read
        end
      end
      documents
    end
  end
end
