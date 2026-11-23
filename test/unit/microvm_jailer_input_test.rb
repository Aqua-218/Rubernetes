# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/runtime/microvm"

class MicroVMJailerInputTest < Minitest::Test
  def test_cross_filesystem_inputs_remain_sparse_and_independent
    skip "requires a writable /dev/shm" unless File.directory?("/dev/shm") && File.writable?("/dev/shm")

    Dir.mktmpdir do |root|
      skip "requires two filesystems" if File.stat(root).dev == File.stat("/dev/shm").dev

      Dir.mktmpdir("rbn-jail-input-", "/dev/shm") do |staging|
        source = File.join(staging, "workspace")
        File.open(source, "wb", 0o644) do |file|
          file.write("head")
          file.seek(8 * 1024 * 1024)
          file.write("tail")
        end
        File.chmod(0o644, source)
        digest = Digest::SHA256.file(source).hexdigest
        jailer = Rubernetes::Runtime::MicroVM::Jailer.new(artifacts: nil, chroot_base: root)
        [true, false].each do |writable|
          target = jailer.install_input(root, "drives/disk-#{writable}", source, Process.uid, Process.gid, writable: writable)

          assert_equal digest, Digest::SHA256.file(target).hexdigest
          assert_equal writable ? 0o600 : 0o644, File.stat(target).mode & 0o777
          assert_operator File.stat(target).blocks * 512, :<, File.size(source) / 2
          File.open(target, "r+b") { |file| file.write("jail") } if writable
          before = Digest::SHA256.file(target).hexdigest

          assert_raises(Errno::EEXIST) { jailer.install_input(root, "drives/disk-#{writable}", source, Process.uid, Process.gid, writable: writable) }
          assert_equal before, Digest::SHA256.file(target).hexdigest
        end

        assert_equal digest, Digest::SHA256.file(source).hexdigest
        assert_equal 0o644, File.stat(source).mode & 0o777
      end
    end
  end

  def test_local_readonly_input_shares_the_existing_inode_and_mode
    Dir.mktmpdir do |root|
      source = File.join(root, "kernel")
      File.write(source, "kernel")
      File.chmod(0o444, source)
      jailer = Rubernetes::Runtime::MicroVM::Jailer.new(artifacts: nil, chroot_base: root)
      target = jailer.install_input(root, "drives/kernel", source, Process.uid, Process.gid)

      assert File.identical?(source, target)
      assert_equal 0o444, File.stat(target).mode & 0o777
      assert_raises(Errno::EEXIST) { jailer.install_input(root, "drives/kernel", source, Process.uid, Process.gid) }
    end
  end
end
