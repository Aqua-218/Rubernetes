# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../../tools/milestones/m7_snapshot_probe"

class M7SnapshotProbeTest < Minitest::Test
  def test_snapshot_copy_preserves_bytes_and_holes_with_a_private_inode
    skip "requires Linux coreutils" unless RUBY_PLATFORM.include?("linux")

    Dir.mktmpdir("m7 snapshot copy") do |root|
      source = File.join(root, "original")
      destination = File.join(root, "mutable copy")
      Dir.mkdir(source)
      memory = File.join(source, "mem")
      File.open(memory, "wb") do |file|
        file.write("header")
        file.seek(16 * 1024 * 1024)
        file.write("footer")
      end
      File.chmod(0o640, memory)
      digest = Digest::SHA256.file(memory).hexdigest

      M7SnapshotProbe.copy_snapshot(source, destination)
      copied = File.join(destination, "mem")

      assert_equal File.size(memory), File.size(copied)
      assert_equal digest, Digest::SHA256.file(copied).hexdigest
      assert_equal 0o640, File.stat(copied).mode & 0o777
      assert_operator File.stat(copied).blocks * 512, :<, 1024 * 1024
      refute File.identical?(memory, copied)

      M7SnapshotProbe.flip_byte(copied, 1)

      assert_equal digest, Digest::SHA256.file(memory).hexdigest
      refute_equal digest, Digest::SHA256.file(copied).hexdigest
    end
  end
end
