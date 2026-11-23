# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

# A hostPath under a host symlink (/var/run -> /run) is the operator's own
# path and is followed as kubelet follows it; the descriptor walk still
# refuses symlinks, so the host prefix is resolved to its real path first.
# Cilium's /var/run/cilium hostPath was refused with ELOOP before.
class HostPathSymlinkTest < Minitest::Test
  Volume = Rubernetes::Volume

  def security(directory)
    root = File.realpath(directory)
    Volume::PathSecurity.new(root: root, adapter: Rubernetes::Platform::Linux::Openat2.new(root: root, strict: true), require_openat2: true)
  end

  def backend(directory, path, type)
    Volume::HostPathBackend.new(id: "vol-cilium-run", spec: {"path" => File.join(directory, path), "type" => type},
                                path_security: security(directory))
  end

  def test_directory_or_create_under_a_symlinked_prefix
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "run"))
      File.symlink("run", File.join(dir, "var-run"))
      real = File.realpath(dir)
      result = backend(dir, "var-run/cilium", "DirectoryOrCreate").provision

      assert_equal File.join(real, "run", "cilium"), result.fetch("source")
      assert File.directory?(File.join(dir, "run", "cilium"))
    end
  end

  def test_existing_directory_under_a_symlinked_prefix
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "run", "cilium"))
      File.symlink("run", File.join(dir, "var-run"))
      result = backend(dir, "var-run/cilium", "Directory").provision

      assert_equal File.join(File.realpath(dir), "run", "cilium"), result.fetch("source")
    end
  end

  def test_unset_type_creates_missing_source_directories
    Dir.mktmpdir do |dir|
      path = File.join(dir, "rook-ceph", "log")
      volume = backend(dir, "rook-ceph/log", "")

      assert_equal File.join(File.realpath(dir), "rook-ceph", "log"), volume.provision.fetch("source")
      assert File.directory?(path)
    ensure
      volume&.delete
    end
  end

  def test_unset_type_accepts_an_existing_file
    Dir.mktmpdir do |dir|
      path = File.join(dir, "config")
      File.write(path, "data")
      volume = backend(dir, "config", nil)

      assert_equal File.realpath(path), volume.provision.fetch("source")
      assert_equal "data", File.read(path)
      assert_raises(Volume::ValidationError) { backend(dir, "config", "Directory").provision }
    ensure
      volume&.delete
    end
  end

  def test_missing_directory_is_still_refused
    Dir.mktmpdir do |dir|
      File.symlink("run", File.join(dir, "var-run"))
      assert_raises(Volume::Error) { backend(dir, "var-run/cilium", "Directory").provision }
    end
  end

  def test_local_volume_requires_an_existing_source_and_recovers_when_it_appears
    Dir.mktmpdir do |dir|
      path = File.join(dir, "local", "data")
      volume = Volume::LocalBackend.new(id: "local", spec: {"path" => path}, path_security: security(dir))
      failure = assert_raises(Volume::LocalSourceNotFoundError) { volume.provision }

      assert_includes failure.message, path
      refute_path_exists File.dirname(path)

      FileUtils.mkdir_p(path)

      assert_equal File.realpath(path), volume.provision.fetch("source")
    ensure
      volume&.delete
    end
  end
end
