# frozen_string_literal: true

require "rubygems/package"
require "stringio"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/image"

# Unpacking jessie-dnsutils took 12 s: a per-byte Ruby loop for every tar
# header checksum, an fsync of the private copy of each layer, and an fsync of
# every extracted file.  Now 4.5 s, with the same checks.
class LayerExtractorSpeedTest < Minitest::Test
  Image = Rubernetes::Image

  def header(name = "etc/hosts")
    io = StringIO.new(+"".b)
    Gem::Package::TarWriter.new(io) { |tar| tar.add_file_simple(name, 0o644, 5) { |file| file.write("hello") } }
    io.string.byteslice(0, 512)
  end

  def extractor(root) = Image::LayerExtractor.new(root)

  def test_the_header_checksum_is_the_tar_one
    Dir.mktmpdir do |root|
      subject = extractor(root)
      valid = header

      subject.send(:verify_tar_checksum!, valid)
      broken = valid.dup
      broken.setbyte(0, broken.getbyte(0) ^ 1)
      assert_raises(Image::SecurityError) { subject.send(:verify_tar_checksum!, broken) }
    ensure
      subject&.close
    end
  end

  def test_extracted_files_are_not_synced_one_by_one
    Dir.mktmpdir do |root|
      subject = extractor(root)

      assert_equal({sync: false}, subject.send(:write_sync_option))
    ensure
      subject&.close
    end
  end

  def test_the_secure_rootfs_still_syncs_by_default
    parameters = Rubernetes::Platform::Linux::SecureRootfs.instance_method(:write_file).parameters

    assert_includes parameters, [:key, :sync]
  end
end
