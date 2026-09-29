# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/volume"
require "rubernetes/platform/linux/openat2"

# A subPath publish that failed before its bind (the file an init container
# writes did not exist yet) left an empty DIRECTORY target; the retry, once
# the file existed, failed with "CSI block target ... must be a regular file"
# for ever.  An empty, unmounted target of the wrong kind is replaced; a
# target with content or a mount on it is still a conflict.
class PathSecurityStaleTargetTest < Minitest::Test
  PathSecurity = Rubernetes::Volume::PathSecurity

  def setup
    skip "openat2 target leases need root" unless Process.uid.zero?
    @root = Dir.mktmpdir("stale-target")
    @security = PathSecurity.new(root: @root, adapter: Rubernetes::Platform::Linux::Openat2.new(root: @root, strict: true),
                                 require_openat2: true)
  end

  def teardown
    FileUtils.rm_rf(@root) if @root
  end

  def test_an_empty_directory_target_is_replaced_by_the_file_the_source_turned_out_to_be
    target = File.join(@root, "volume-subpaths", "app", "secrets", "0")
    FileUtils.mkdir_p(target)
    lease = @security.acquire_target!(target, directory: false, create: true)
    lease.close if lease.respond_to?(:close)
    assert File.file?(target), "the stale directory became a regular file"
  end

  def test_an_empty_file_target_is_replaced_by_a_directory
    target = File.join(@root, "volume-subpaths", "app", "data", "0")
    FileUtils.mkdir_p(File.dirname(target))
    File.write(target, "")
    lease = @security.acquire_target!(target, directory: true, create: true)
    lease.close if lease.respond_to?(:close)
    assert File.directory?(target)
  end

  def test_a_target_with_content_is_not_replaced
    target = File.join(@root, "volume-subpaths", "app", "secrets", "0")
    FileUtils.mkdir_p(target)
    File.write(File.join(target, "keep"), "x")
    error = assert_raises(Rubernetes::Volume::PathSecurityError) do
      @security.acquire_target!(target, directory: false, create: true)
    end
    assert_match(/must be a regular file/, error.message)
    assert File.exist?(File.join(target, "keep"))

    file = File.join(@root, "volume-subpaths", "app", "data", "0")
    FileUtils.mkdir_p(File.dirname(file))
    File.write(file, "content")
    assert_raises(Rubernetes::Volume::PathSecurityError) { @security.acquire_target!(file, directory: true, create: true) }
    assert_equal "content", File.read(file)
  end

  def test_a_mounted_empty_directory_is_not_replaced
    target = File.join(@root, "volume-subpaths", "app", "secrets", "0")
    FileUtils.mkdir_p(target)
    skip "tmpfs mount unavailable" unless system("mount", "-t", "tmpfs", "-o", "size=64k", "stale-target-test", target, err: File::NULL)
    begin
      assert_raises(Rubernetes::Volume::PathSecurityError) { @security.acquire_target!(target, directory: false, create: true) }
      assert File.directory?(target)
    ensure
      system("umount", target, err: File::NULL)
    end
  end

  def test_without_create_nothing_is_touched
    target = File.join(@root, "volume-subpaths", "app", "secrets", "0")
    FileUtils.mkdir_p(target)
    assert_raises(Rubernetes::Volume::PathSecurityError) { @security.acquire_target!(target, directory: false, create: false) }
    assert File.directory?(target)
  end
end
