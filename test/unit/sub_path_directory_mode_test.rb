# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

# kubelet_pods.go: a subPath directory that does not exist yet is created with
# the VOLUME directory's mode (hu.GetMode(volumePath), setgid included), so a
# non-root container can write to a subPath of a 0777 emptyDir.  We created it
# 0755 root-owned: Bitnami's /tmp and conf subPaths failed with EACCES.
class SubPathDirectoryModeTest < Minitest::Test
  PathSecurity = Rubernetes::Volume::PathSecurity

  def test_a_created_sub_path_takes_the_volume_directory_mode
    Dir.mktmpdir("subpath-mode") do |root|
      security = PathSecurity.new(root: "/", adapter: Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true), require_openat2: true)
      {"empty-dir" => 0o777, "group-dir" => 0o2775, "plain" => 0o755}.each do |name, mode|
        volume = File.join(root, name)
        Dir.mkdir(volume)
        File.chmod(mode, volume)
        handle = security.open_mount_point(volume)
        begin
          created = security.validate_sub_path!(handle, "app/tmp-dir", create: true)
          created.close if created.respond_to?(:close)
        ensure
          handle.close if handle.respond_to?(:close)
        end
        assert_equal mode, File.stat(File.join(volume, "app")).mode & 0o7777, "#{name}: first component"
        assert_equal mode, File.stat(File.join(volume, "app", "tmp-dir")).mode & 0o7777, "#{name}: leaf"
      end
    end
  end

  def test_an_explicit_mode_still_wins
    Dir.mktmpdir("subpath-mode") do |root|
      security = PathSecurity.new(root: "/", adapter: Rubernetes::Platform::Linux::Openat2.new(root: "/", strict: true), require_openat2: true)
      volume = File.join(root, "v")
      Dir.mkdir(volume)
      File.chmod(0o777, volume)
      handle = security.open_mount_point(volume)
      created = security.validate_sub_path!(handle, "conf", create: true, mode: 0o750)
      created.close if created.respond_to?(:close)
      handle.close if handle.respond_to?(:close)
      assert_equal 0o750, File.stat(File.join(volume, "conf")).mode & 0o7777
    end
  end
end
