# frozen_string_literal: true

require_relative "../test_helper"
require "open3"
require "rbconfig"
require "tmpdir"

class NativeVolumeMountAdapterIntegrationTest < Minitest::Test
  KERNEL_SCRIPT = <<~'RUBY'
    require "fileutils"
    require "rubernetes/volume"

    root = ARGV.fetch(0)
    source = File.join(root, "source")
    stage = File.join(root, "stage")
    target = File.join(root, "target")
    FileUtils.mkdir_p(source)
    FileUtils.mkdir_p(stage)
    FileUtils.mkdir_p(target)

    adapter = Rubernetes::Volume::NativeMountAdapter.new
    stage_identity = nil
    target_identity = nil
    begin
      File.write(File.join(source, "before"), "source")
      stage_identity = adapter.ensure_tmpfs(stage, size_limit: "1Mi")
      raise "tmpfs readback did not identify the stage" unless stage_identity.fetch("filesystem") == "tmpfs"
      File.write(File.join(stage, "hello"), "native")

      target_identity = adapter.bind(source: stage, target: target, readonly: true)
      raise "bind readback did not identify the target" unless target_identity.fetch("target") == target
      raise "bind readback was not read-only" unless target_identity.fetch("readonly")
      raise "bind effect was not observable" unless File.read(File.join(target, "hello")) == "native"

      adapter.unmount(target: target, mount_id: target_identity.fetch("mountId"))
      adapter.unmount(target: stage, mount_id: stage_identity.fetch("mountId"))
      raise "target mount remained after umount2" if adapter.find_mount(target)
      raise "stage mount remained after umount2" if adapter.find_mount(stage)
    rescue Rubernetes::Platform::Linux::Error => error
      if [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::EOPNOTSUPP::Errno].include?(error.errno)
        warn "SKIP: kernel denied mount capability (errno #{error.errno})"
        exit 77
      end
      raise
    ensure
      begin
        adapter.unmount(target: target, mount_id: target_identity.fetch("mountId")) if target_identity && adapter.find_mount(target)
      rescue StandardError
        nil
      end
      begin
        adapter.unmount(target: stage, mount_id: stage_identity.fetch("mountId")) if stage_identity && adapter.find_mount(stage)
      rescue StandardError
        nil
      end
    end
  RUBY

  def test_native_mount_and_bind_effects_are_verified_inside_an_isolated_mount_namespace
    skip "native mount integration requires root" unless Process.uid.zero?

    Dir.mktmpdir("native-volume-mount") do |directory|
      output, error, status = Open3.capture3(
        "unshare", "--mount", "--propagation", "private", "--", RbConfig.ruby, "-Ilib", "-e", KERNEL_SCRIPT, directory
      )
      skip error.strip if status.exitstatus == 77 && error.start_with?("SKIP:")
      if !status.success? && error.match?(/Operation not permitted|Permission denied/i)
        skip "missing CAP_SYS_ADMIN for isolated mount namespace: #{error.strip}"
      end

      assert_predicate status, :success?, "isolated native mount script failed: #{error.empty? ? output : error}"
    end
  rescue Errno::ENOENT => error
    flunk "unshare is required for the isolated mount integration test: #{error.message}"
  end
end
