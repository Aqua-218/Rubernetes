# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/volume"

class NativeDeviceAdapterTest < Minitest::Test
  Adapter = Rubernetes::Volume::NativeDeviceAdapter
  Resolver = Adapter::FilesystemUuidResolver

  def test_kernel_struct_sizes_match_linux_uapi_layouts
    assert_equal 232, Adapter::LOOP_INFO64_SIZE
    assert_equal 304, Adapter::LOOP_CONFIGURE_SIZE
    assert_equal 312, Adapter::DM_IOCTL_SIZE
  end

  def test_filesystem_uuid_resolver_reads_ext4_uuid_without_fabricating_identity
    uuid = ["00112233445566778899aabbccddeeff"].pack("H*")
    superblock = ("\0" * 120).b
    superblock.setbyte(56, 0x53)
    superblock.setbyte(57, 0xef)
    superblock[104, 16] = uuid
    resolver = Resolver.new(reader: ->(_path, _offset, _length) { superblock })

    assert_equal "00112233-4455-6677-8899-aabbccddeeff",
                 resolver.call("filesystem" => "ext4", "source" => "/dev/loop-test")

    zero_uuid = superblock.dup
    zero_uuid[104, 16] = ("\0" * 16).b
    zero_resolver = Resolver.new(reader: ->(_path, _offset, _length) { zero_uuid })
    assert_nil zero_resolver.call("filesystem" => "ext4", "source" => "/dev/loop-test")
    assert_nil resolver.call("filesystem" => "tmpfs", "source" => "/dev/loop-test")
    assert_nil resolver.call("filesystem" => "ext4")
  end

  def test_filesystem_uuid_resolver_reads_xfs_uuid_and_rejects_short_reads
    uuid = ["ffeeddccbbaa99887766554433221100"].pack("H*")
    xfs_superblock = ("\0" * 48).b
    xfs_superblock[0, 4] = "XFSB".b
    xfs_superblock[32, 16] = uuid
    resolver = Resolver.new(reader: ->(_path, _offset, _length) { xfs_superblock })

    assert_equal "ffeeddcc-bbaa-9988-7766-554433221100",
                 resolver.call("filesystem" => "xfs", "source" => "/dev/mapper/test")

    short = Resolver.new(reader: ->(_path, _offset, _length) { "short" })
    assert_nil short.call("filesystem" => "xfs", "source" => "/dev/mapper/test")
  end

  def test_native_device_adapter_rejects_unbounded_and_unaligned_sizes_before_effects
    adapter = Adapter.new(max_size_bytes: 1 << 20)

    assert_raises(Rubernetes::Volume::CapacityError) do
      adapter.create_loop(path: "/tmp/rubernetes-device.img", volume_id: "v", size_bytes: (1 << 20) + 1)
    end
    assert_raises(Rubernetes::Volume::CapacityError) do
      adapter.create_dm(device: "/dev/loop0", volume_id: "v", size_bytes: 513)
    end
    assert_raises(Rubernetes::Volume::ValidationError) do
      adapter.create_loop(path: "/dev/loop0", volume_id: "v", size_bytes: 512)
    end
  end

  def test_native_mount_adapter_can_inject_the_superblock_uuid_resolver
    uuid = ["0123456789abcdef0123456789abcdef"].pack("H*")
    superblock = ("\0" * 120).b
    superblock.setbyte(56, 0x53)
    superblock.setbyte(57, 0xef)
    superblock[104, 16] = uuid
    resolver = Resolver.new(reader: ->(_path, _offset, _length) { superblock })
    mount = Object.new
    mount.define_singleton_method(:mount) { |_kwargs| true }
    mount.define_singleton_method(:unmount) { |_kwargs| true }
    mountinfo = "321 45 7:9 / /tmp/uuid-target rw - ext4 /dev/loop0 rw\n"
    adapter = Rubernetes::Volume::NativeMountAdapter.new(
      mount: mount,
      mountinfo_reader: -> { mountinfo },
      filesystem_uuid_resolver: resolver
    )

    raw = Rubernetes::Volume::NativeMountAdapter.parse_mountinfo(mountinfo).fetch(0)
    assert_nil raw.fetch("filesystemUuid")
    # Observations of block filesystems are decorated so reconciliation can
    # match the UUID-bearing identity registered at mount time.
    observed = adapter.list_mounts.fetch(0)
    assert_equal "01234567-89ab-cdef-0123-456789abcdef", observed.fetch("filesystemUuid")
    assert observed.fetch("filesystemUuidAvailable")
    mounted = adapter.send(:decorate_mount, raw, requested_source: "/dev/loop0", dispatch_source: "/dev/loop0",
                            requested_filesystem: "ext4", requested_options: {}, volume_id: "v", stage: true,
                            readonly: false, bind: false, mount_api: "mount")
    assert_equal "01234567-89ab-cdef-0123-456789abcdef", mounted.fetch("filesystemUuid")
    assert mounted.fetch("filesystemUuidAvailable")
    assert_equal "/dev/loop0", mounted.fetch("kernelSource")
    refute mounted.fetch("bind")
    bound = adapter.send(:decorate_mount, raw, requested_source: "/srv/data", dispatch_source: "/proc/self/fd/9",
                          requested_filesystem: nil, requested_options: {"bind" => true}, volume_id: "v", stage: false,
                          readonly: false, bind: true, mount_api: "open_tree")
    assert_nil bound.fetch("filesystemUuid"), "a bind never claims the underlying filesystem UUID"
    assert_equal "/srv/data", bound.fetch("source")
    assert_equal "/dev/loop0", bound.fetch("kernelSource")
    assert_equal "/dev/loop0", bound.fetch("sourceIdentity")
    assert bound.fetch("bind")
  end
end
