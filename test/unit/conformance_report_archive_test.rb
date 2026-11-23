# frozen_string_literal: true

require "tmpdir"

require_relative "../test_helper"
require_relative "../../tools/conformance/report_archive"

class ConformanceReportArchiveTest < Minitest::Test
  Archive = Conformance::ReportArchive
  ORIGINAL = ("行\u0000\n" * 40_000).freeze

  def test_retains_and_retries_with_the_original_already_removed
    with_report do |raw, gzip|
      artifact = Archive.retain(raw, bytes: ORIGINAL)

      assert_equal gzip, artifact.fetch("path")
      assert_equal Digest::SHA256.file(gzip).hexdigest, artifact.fetch("sha256")
      assert_equal Digest::SHA256.hexdigest(ORIGINAL), artifact.fetch("uncompressed_sha256")
      assert_equal ORIGINAL.bytesize, artifact.fetch("uncompressed_bytes")
      assert_equal ORIGINAL.b, Archive.read(gzip, sha256: artifact.fetch("uncompressed_sha256"))
      refute_path_exists raw
      assert_equal artifact, Archive.retain(raw, bytes: ORIGINAL)
    end
  end

  def test_concurrent_retention_returns_the_same_archive
    with_report do |raw, gzip|
      start = Queue.new
      writers = Array.new(4) do
        Thread.new do
          start.pop
          Archive.retain(raw, bytes: ORIGINAL.b)
        end
      end
      writers.size.times { start << true }
      results = writers.map(&:value)

      assert_equal 1, results.uniq.size
      assert_equal gzip, results.first.fetch("path")
      assert_equal ORIGINAL.b, Archive.read(gzip, sha256: results.first.fetch("uncompressed_sha256"))
      refute_path_exists raw
    end
  end

  def test_keeps_both_artifacts_when_the_archive_is_different_or_invalid
    with_report do |raw, gzip|
      packed = Zlib.gzip(ORIGINAL)
      alternatives = [Zlib.gzip("different"), Zlib.gzip(ORIGINAL + "extra"), packed.byteslice(0...-1), packed + "trailer", packed + Zlib.gzip("")]
      alternatives.each do |conflict|
        File.binwrite(gzip, conflict)

        assert_equal Archive.artifact_for(raw), Archive.retain(raw, bytes: ORIGINAL.b)
        assert_equal ORIGINAL.b, File.binread(raw)
        assert_equal conflict, File.binread(gzip)
      end
    end
  end

  def test_rejects_any_archive_that_cannot_replace_a_missing_original
    with_report do |raw, gzip|
      File.unlink(raw)
      packed = Zlib.gzip(ORIGINAL)
      [Zlib.gzip("different"), packed.byteslice(0...-1), packed + "trailer"].each do |conflict|
        File.binwrite(gzip, conflict)

        assert_raises(Archive::Error) { Archive.retain(raw, bytes: ORIGINAL.b) }
        assert_equal conflict, File.binread(gzip)
      end
    end
  end

  def test_keeps_raw_when_its_content_has_changed
    with_report do |raw, gzip|
      File.binwrite(raw, "new evidence")

      assert_equal Archive.artifact_for(raw), Archive.retain(raw, bytes: ORIGINAL.b)
      assert_equal "new evidence", File.binread(raw)
      assert_equal ORIGINAL.b, Archive.read(gzip, alternate: false)
    end
  end

  def test_gzip_checks_the_footer_and_trailing_bytes_after_a_partial_read
    with_report do |_raw, gzip|
      packed = Zlib.gzip(ORIGINAL)
      File.binwrite(gzip, packed)

      assert_equal ORIGINAL.b.byteslice(0, 7), File.open(gzip, "rb") { |file| Archive.read_gzip(file) { |reader| reader.read(7) } }
      [packed.byteslice(0...-1), packed + "trailer"].each do |conflict|
        File.binwrite(gzip, conflict)

        assert_raises(Archive::Error) do
          File.open(gzip, "rb") { |file| Archive.read_gzip(file) { |reader| reader.read(7) } }
        end
      end
    end
  end

  private

  def with_report
    Dir.mktmpdir do |folder|
      raw = File.join(folder, "ginkgo.json")
      File.binwrite(raw, ORIGINAL)
      yield raw, "#{raw}.gz"
    end
  end
end
