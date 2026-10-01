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

  def security
    Volume::PathSecurity.new(root: "/", adapter: Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true), require_openat2: true)
  end

  def backend(path, type)
    Volume::HostPathBackend.new(id: "vol-cilium-run", spec: {"path" => path, "type" => type}, path_security: security)
  end

  def test_directory_or_create_under_a_symlinked_prefix
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "run"))
      File.symlink("run", File.join(dir, "var-run"))
      real = File.realpath(dir)
      result = backend(File.join(dir, "var-run", "cilium"), "DirectoryOrCreate").provision

      assert_equal File.join(real, "run", "cilium"), result.fetch("source")
      assert File.directory?(File.join(dir, "run", "cilium"))
    end
  end

  def test_existing_directory_under_a_symlinked_prefix
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "run", "cilium"))
      File.symlink("run", File.join(dir, "var-run"))
      result = backend(File.join(dir, "var-run", "cilium"), "Directory").provision

      assert_equal File.join(File.realpath(dir), "run", "cilium"), result.fetch("source")
    end
  end

  def test_missing_directory_is_still_refused
    Dir.mktmpdir do |dir|
      File.symlink("run", File.join(dir, "var-run"))
      assert_raises(Volume::Error) { backend(File.join(dir, "var-run", "cilium"), "Directory").provision }
    end
  end
end
