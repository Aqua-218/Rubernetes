# frozen_string_literal: true

require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/platform/linux/native_adapters"

class NativeBindMountPermissionsTest < Minitest::Test
  def test_restrictive_umask_preserves_search_permissions_on_created_mount_parents
    Dir.mktmpdir do |root|
      run = File.join(root, "run")
      var = File.join(root, "var")
      FileUtils.mkdir(run, mode: 0o750)
      FileUtils.mkdir(var, mode: 0o755)
      File.symlink("/run", File.join(var, "run"))

      pid = fork do
        File.umask(0o077)
        security = Rubernetes::Platform::Linux::NativeAdapters::SecurityAdapter.new
        security.send(:bind_mount_target, root, "/var/run/secrets/kubernetes.io/serviceaccount", File.stat(run), 0)
        exit!(File.umask == 0o077)
      end
      _, status = Process.wait2(pid)

      assert_predicate status, :success?
      assert_equal 0o750, File.stat(run).mode & 0o777
      %w[secrets secrets/kubernetes.io secrets/kubernetes.io/serviceaccount].each do |relative|
        assert_equal 0o755, File.stat(File.join(run, relative)).mode & 0o777, relative
      end
    end
  end
end
