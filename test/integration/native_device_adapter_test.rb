# frozen_string_literal: true

require_relative "../test_helper"
require "fileutils"
require "rubernetes/volume"
require "tmpdir"

class NativeDeviceAdapterIntegrationTest < Minitest::Test
  Adapter = Rubernetes::Volume::NativeDeviceAdapter
  SIZE_BYTES = 1 << 20

  def test_sparse_loop_and_linear_device_mapper_lifecycle_when_kernel_capability_exists
    skip "native device integration requires Linux root" unless RUBY_PLATFORM.include?("linux") && Process.uid.zero?
    skip "loop-control device is unavailable" unless File.exist?(Adapter::LOOP_CONTROL_PATH)
    skip "device-mapper control device is unavailable" unless File.exist?(Adapter::MAPPER_CONTROL_PATH)
    skip "dm_mod kernel module is unavailable" unless File.exist?("/sys/module/dm_mod")

    Dir.mktmpdir("rubernetes-native-device") do |directory|
      backing_path = File.join(directory, "backing.img")
      File.open(backing_path, File::RDWR | File::CREAT | File::EXCL, 0o600) { |file| file.truncate(SIZE_BYTES) }
      adapter = Adapter.new
      loop_identity = nil
      dm_identity = nil
      begin
        loop_identity = adapter.create_loop(path: backing_path, volume_id: "integration", size_bytes: SIZE_BYTES)
        assert_match(%r{\A/dev/loop\d+\z}, loop_identity.fetch("id"))
        assert_equal SIZE_BYTES, loop_identity.fetch("sizeBytes")
        assert_equal loop_identity.fetch("id"),
                     adapter.create_loop(path: backing_path, volume_id: "integration", size_bytes: SIZE_BYTES).fetch("id")

        # dm-linear is built into dm_mod on distribution kernels (no separate
        # /sys/module/dm_linear); the create below reports a missing target
        # through the errno rescue rather than a pre-check.

        dm_identity = adapter.create_dm(device: loop_identity.fetch("id"), volume_id: "integration", size_bytes: SIZE_BYTES)
        assert_match(%r{\A/dev/mapper/}, dm_identity.fetch("id"))
        assert_equal SIZE_BYTES, dm_identity.fetch("sizeBytes")
        assert_equal dm_identity.fetch("id"),
                     adapter.create_dm(device: loop_identity.fetch("id"), volume_id: "integration", size_bytes: SIZE_BYTES).fetch("id")
      rescue Rubernetes::Platform::Linux::Error => error
        skip "kernel/device-mapper denied native lifecycle (errno #{error.errno}: #{error.message})" if
          [Errno::EACCES::Errno, Errno::EINVAL::Errno, Errno::ENODEV::Errno, Errno::ENOSYS::Errno,
           Errno::ENOTTY::Errno, Errno::EOPNOTSUPP::Errno, Errno::EPERM::Errno].include?(error.errno)
        raise
      ensure
        adapter.destroy_device(id: dm_identity.fetch("id")) if dm_identity
        adapter.destroy_device(id: loop_identity.fetch("id")) if loop_identity
        adapter.destroy_device(id: loop_identity.fetch("id")) if loop_identity
      end
    end
  rescue Rubernetes::Volume::NativeDeviceAdapter::Unsupported => error
    skip error.message
  end
end
