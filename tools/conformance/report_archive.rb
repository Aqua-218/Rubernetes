# frozen_string_literal: true

require "digest"
require "stringio"
require "tempfile"
require "zlib"

require_relative "lock"

module Conformance
  module ReportArchive
    class Error < StandardError; end

    CHUNK_BYTES = 64 * 1024

    module_function

    # A logical report path can address either storage format. A checksum
    # supplied by a reader always identifies the original report bytes.
    def read(path, sha256: nil, alternate: true)
      file = open_report(path, alternate: alternate)
      bytes = file.path.end_with?(".gz") ? read_gzip(file, &:read) : file.read
      raise Error, "report checksum differs from the original" if sha256 && Digest::SHA256.hexdigest(bytes) != sha256

      bytes
    ensure
      file&.close
    end

    # The caller supplies the completed, validated original. A failed
    # compression or a conflicting archive leaves the raw report available.
    def retain(path, bytes:)
      archive = "#{path}.gz"
      digest = Digest::SHA256.hexdigest(bytes)
      source = File.lstat(path)
      return artifact_for(path) unless source.file?

      publish(archive, bytes, source.mode & 0o777)
      artifact = matching_artifact(archive, bytes, digest)
      return artifact if artifact && retire_original(path, source, digest)

      artifact_for(path)
    rescue SystemCallError, Error, Zlib::Error
      raw_or_archive(path, archive, bytes, digest)
    end

    def raw_or_archive(path, archive, bytes, digest)
      artifact_for(path)
    rescue Errno::ENOENT
      # A previous invocation or a concurrent writer may have removed the raw
      # file. Its archive is usable only after verifying the supplied original.
      matching_artifact(archive, bytes, digest) || raise(Error, "gzip report differs from the original")
    end

    def matching_artifact(path, bytes, digest)
      File.open(path, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) do |file|
        next unless file.stat.file? && gzip_matches?(file, bytes)

        file.rewind
        artifact_for(path, sha256: stream_sha256(file)).merge("uncompressed_sha256" => digest, "uncompressed_bytes" => bytes.bytesize)
      end
    end

    def retire_original(path, source, digest)
      File.open(File.dirname(path), &:fsync)
      File.open(path, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) do |file|
        current = file.stat
        return false unless same_file?(source, current) && stream_sha256(file) == digest

        named = File.lstat(path)
        return false unless same_file?(current, named) && current.mtime == named.mtime && current.ctime == named.ctime && current.size == named.size

        File.unlink(path)
      end
      true
    end

    def same_file?(left, right)
      right.file? && left.dev == right.dev && left.ino == right.ino
    end

    def artifact_for(path, sha256: Digest::SHA256.file(path).hexdigest)
      {"path" => path.delete_prefix("#{Lock::ROOT}/"), "sha256" => sha256}
    end

    def open_report(path, alternate: true)
      File.open(path, "rb")
    rescue Errno::ENOENT
      raise unless alternate

      sibling = path.end_with?(".gz") ? path.delete_suffix(".gz") : "#{path}.gz"
      File.open(sibling, "rb")
    end

    def read_gzip(file, label: "gzip")
      reader = Zlib::GzipReader.new(file, external_encoding: Encoding::BINARY)
      value = yield reader
      buffer = +"".b
      nil while reader.read(CHUNK_BYTES, buffer)
      raise Error, "unexpected data after the #{label} stream" unless reader.unused.to_s.empty? && file.eof?

      value
    rescue Zlib::Error => error
      raise Error, "invalid #{label} report: #{error.message}"
    ensure
      reader&.finish
    end

    def gzip_matches?(file, bytes)
      original = StringIO.new(bytes, "rb")
      read_gzip(file) do |reader|
        actual = +"".b
        expected = +"".b
        matches = true
        while reader.read(CHUNK_BYTES, actual)
          matches = original.read(CHUNK_BYTES, expected) == actual
          break unless matches
        end
        matches && original.eof?
      end
    end

    def stream_sha256(io)
      digest = Digest::SHA256.new
      buffer = +"".b
      digest.update(buffer) while io.read(CHUNK_BYTES, buffer)
      digest.hexdigest
    end

    def publish(archive, bytes, mode = nil)
      return if File.exist?(archive)

      Tempfile.create([".report-", ".pending"], File.dirname(archive), binmode: true) do |file|
        writer = Zlib::GzipWriter.new(file)
        writer.mtime = 0
        original = StringIO.new(bytes, "rb")
        buffer = +"".b
        writer.write(buffer) while original.read(CHUNK_BYTES, buffer)
        writer.finish
        file.chmod(mode) if mode
        file.fsync
        file.rewind
        raise Error, "gzip report did not round trip" unless gzip_matches?(file, bytes)

        File.link(file.path, archive)
      end
    rescue Errno::EEXIST
      # A parallel writer may already have published the same artifact.
    end
  end
end
