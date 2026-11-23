# frozen_string_literal: true

require "digest"
require "tmpdir"

require_relative "../test_helper"
require "rubernetes/image"

class OCIStoreTest < Minitest::Test
  def test_put_verifies_digest_and_publishes_a_read_only_blob
    Dir.mktmpdir do |directory|
      store = Rubernetes::Image::ContentStore.new(directory)
      bytes = "immutable blob"
      digest = "sha256:#{Digest::SHA256.hexdigest(bytes)}"

      path = store.put(digest, bytes)

      assert_equal bytes, store.fetch(digest)
      assert_equal 0o444, File.stat(path).mode & 0o777
      refute(Dir.children(File.join(directory, "sha256")).any? { |name| name.end_with?(".tmp") })
    end
  end

  def test_rejects_digest_mismatch_without_leaving_a_temporary_blob
    Dir.mktmpdir do |directory|
      store = Rubernetes::Image::ContentStore.new(directory)
      digest = "sha256:#{"a" * 64}"

      assert_raises(Rubernetes::Image::DigestMismatch) { store.put(digest, "tampered") }
      assert_empty Dir.children(File.join(directory, "sha256"))
    end
  end

  def test_corrupt_existing_blob_fails_closed
    Dir.mktmpdir do |directory|
      store = Rubernetes::Image::ContentStore.new(directory)
      bytes = "valid"
      digest = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
      path = store.put(digest, bytes)
      File.chmod(0o600, path)
      File.binwrite(path, "corrupt")

      assert_raises(Rubernetes::Image::StoreError) { store.fetch(digest) }
      assert_raises(Rubernetes::Image::StoreError) { store.put(digest, bytes) }
    end
  end

  def test_competing_stages_keep_the_winners_verified_inode
    Dir.mktmpdir do |directory|
      store = Rubernetes::Image::ContentStore.new(directory)
      bytes = "concurrent content"
      digest = "sha256:#{Digest::SHA256.hexdigest(bytes)}"
      ready = Queue.new
      finish = Queue.new
      writer = Thread.new do
        store.write_blob(digest, size: bytes.bytesize) do |file|
          file.write(bytes)
          ready << true
          finish.pop
        end
      end
      ready.pop

      path = store.write_blob(digest, size: bytes.bytesize) { |file| file.write(bytes) }
      inode = File.stat(path).ino
      finish << true

      assert_equal path, writer.value
      assert_equal inode, File.stat(path).ino
      assert_equal [File.basename(path)], Dir.children(File.dirname(path))
      assert_equal bytes, store.fetch(digest)
    ensure
      finish << true if writer&.alive?
      writer&.join
    end
  end
end
