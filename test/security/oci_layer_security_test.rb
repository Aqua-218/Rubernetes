# frozen_string_literal: true

require "digest"
require "rubygems/package"
require "stringio"
require "tmpdir"
require "zlib"

require_relative "../test_helper"
require "rubernetes/image"

class OCILayerSecurityTest < Minitest::Test
  def test_digest_mismatch_is_rejected_before_rootfs_mutation
    layer = gzip_layer do |tar|
      tar.add_file_simple("safe", 0o644, 4) { |io| io.write("safe") }
    end
    Dir.mktmpdir do |directory|
      root = File.join(directory, "root")
      extractor = Rubernetes::Image::LayerExtractor.new(root)

      assert_raises(Rubernetes::Image::DigestMismatch) do
        extractor.extract(layer, digest: "sha256:#{"0" * 64}", media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
      end
      assert_empty Dir.children(root)
    end
  end

  def test_rejects_path_traversal_absolute_paths_and_escaping_links
    archives = [
      gzip_layer { |tar| tar.add_file_simple("../escape", 0o644, 1) { |io| io.write("x") } },
      gzip_layer { |tar| tar.add_file_simple("/absolute", 0o644, 1) { |io| io.write("x") } },
      gzip_layer { |tar| tar.add_symlink("inside/link", "../../escape", 0o777) }
    ]

    archives.each do |layer|
      Dir.mktmpdir do |directory|
        root = File.join(directory, "root")
        extractor = Rubernetes::Image::LayerExtractor.new(root)
        assert_raises(Rubernetes::Image::SecurityError) do
          extractor.extract(layer, digest: digest_for(layer), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
        end
        refute_path_exists File.join(directory, "escape")
      end
    end
  end

  # Docker and containerd both emit an entry for the layer's own root, and
  # a real busybox layer starts with one.  It names a directory that already
  # exists, so it is skipped; the same path claimed by anything else is still
  # an attack.
  def test_root_directory_entry_is_skipped_but_a_root_file_entry_is_rejected
    root_directory = tar_header("./", type: "5")
    payload = tar_header("bin/sh", type: "0")
    layer = gzip_bytes(root_directory + payload + ("\0" * 1024))

    Dir.mktmpdir do |directory|
      root = File.join(directory, "root")
      extractor = Rubernetes::Image::LayerExtractor.new(root)
      extractor.extract(layer, digest: digest_for(layer), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)

      assert_path_exists File.join(root, "bin/sh")
    end

    hostile = gzip_bytes(tar_header("./", type: "0") + ("\0" * 1024))
    Dir.mktmpdir do |directory|
      extractor = Rubernetes::Image::LayerExtractor.new(File.join(directory, "root"))
      assert_raises(Rubernetes::Image::SecurityError) do
        extractor.extract(hostile, digest: digest_for(hostile), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
      end
    end
  end

  # Device nodes, FIFOs and sockets in a layer are never materialised in the
  # rootfs (spec 5.8.5): the container's /dev is a nodev tmpfs the runtime
  # populates itself.  They are skipped and counted rather than failing the
  # whole layer -- bitnami/redis ships one and was unpullable.  A hardlink
  # that escapes the rootfs still rejects the layer.
  def test_device_fifo_and_socket_entries_are_skipped_and_hardlink_escapes_are_rejected
    device = tar_header("dev", type: "3")
    fifo = tar_header("fifo", type: "6")
    socket = tar_header("sock", type: "S")
    regular = tar_header("bin/sh", type: "0", size: 3) + "sh\n".b + ("\0" * 509)
    layer = gzip_bytes(device + fifo + socket + regular + ("\0" * 1024))

    Dir.mktmpdir do |directory|
      root = File.join(directory, "root")
      extractor = Rubernetes::Image::LayerExtractor.new(root)
      extractor.extract(layer, digest: digest_for(layer), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)

      assert_equal 3, extractor.skipped_special_files
      assert_equal %w[bin], Dir.children(root).sort
      assert_equal "sh\n", File.read(File.join(root, "bin/sh"))
    end

    hardlink = tar_header("hard", type: "1", linkname: "../../escape")
    hostile = gzip_bytes(hardlink + ("\0" * 1024))
    Dir.mktmpdir do |directory|
      extractor = Rubernetes::Image::LayerExtractor.new(File.join(directory, "root"))
      assert_raises(Rubernetes::Image::SecurityError) do
        extractor.extract(hostile, digest: digest_for(hostile), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
      end
    end
  end

  def test_enforces_entry_path_and_expansion_limits
    layer = gzip_layer { |tar| tar.add_file_simple("large", 0o644, 16) { |io| io.write("0123456789abcdef") } }
    Dir.mktmpdir do |directory|
      root = File.join(directory, "root")
      extractor = Rubernetes::Image::LayerExtractor.new(root, max_uncompressed_bytes: 8, max_entries: 1)

      assert_raises(Rubernetes::Image::LimitError) do
        extractor.extract(layer, digest: digest_for(layer), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
      end
      assert_empty Dir.children(root)
    end
  end

  def test_whiteouts_remove_only_entries_inside_the_current_rootfs
    base = gzip_layer do |tar|
      tar.mkdir("etc", 0o755)
      tar.add_file_simple("etc/config", 0o644, 3) { |io| io.write("old") }
    end
    whiteout = gzip_layer do |tar|
      tar.add_file_simple("etc/.wh.config", 0o644, 3) { |io| io.write("pad") }
    end

    Dir.mktmpdir do |directory|
      root = File.join(directory, "root")
      extractor = Rubernetes::Image::LayerExtractor.new(root)
      extractor.extract(base, digest: digest_for(base), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)
      extractor.extract(whiteout, digest: digest_for(whiteout), media_type: Rubernetes::Image::MediaTypes::OCI_IMAGE_LAYER_GZIP)

      refute_path_exists File.join(root, "etc", "config")
      refute_path_exists File.join(directory, "config")
    end
  end

  def test_descriptor_relative_mutations_survive_deterministic_parent_replacement
    operations = %i[write directory symlink hardlink remove clear]
    operations.each do |operation|
      Dir.mktmpdir("rubernetes-layer-race-") do |directory|
        root = File.join(directory, "root")
        outside = File.join(directory, "outside")
        FileUtils.mkdir_p([root, outside])
        parent = File.join(root, "parent")
        FileUtils.mkdir_p(parent)
        File.write(File.join(outside, "sentinel"), "keep")
        File.write(File.join(parent, "target"), "inside")
        File.write(File.join(parent, "remove"), "inside")

        replaced = false
        hook = lambda do |operation: nil, relative: nil, fd: nil|
          next unless relative == "parent" && !replaced

          replaced = true
          racer = Thread.new do
            File.rename(parent, File.join(root, "parent-held"))
            File.symlink(outside, parent)
          end
          racer.value
        end
        filesystem = Rubernetes::Platform::Linux::SecureRootfs.new(root: root, race_hook: hook)
        begin
          case operation
          when :write
            filesystem.write_file("parent/new", mode: 0o600) { |io| io.write("safe") }
          when :directory
            filesystem.create_directory("parent/new-directory", mode: 0o700)
          when :symlink
            filesystem.create_symlink("parent/link", "target", validation_path: "parent/target")
          when :hardlink
            filesystem.create_hardlink("parent/link", "parent/target")
          when :remove
            filesystem.remove("parent/remove")
          when :clear
            filesystem.clear_directory("parent")
          end
        ensure
          filesystem.close
        end

        assert replaced, "race hook did not run for #{operation}"
        assert_equal "keep", File.read(File.join(outside, "sentinel"))
        refute_path_exists File.join(outside, "new")
        refute_path_exists File.join(outside, "new-directory")
        refute_path_exists File.join(outside, "link")
        refute_path_exists File.join(outside, "remove")
        assert_path_exists File.join(root, "parent-held")
      end
    end
  end

  def test_secure_remove_rejects_target_identity_replacement
    %i[file directory].each do |kind|
      Dir.mktmpdir("rubernetes-remove-race-") do |directory|
        root = File.join(directory, "root")
        FileUtils.mkdir_p(root)
        victim = File.join(root, "victim")
        if kind == :directory
          FileUtils.mkdir_p(victim)
        else
          File.write(victim, "original")
        end

        hook_operation = kind == :directory ? :remove_before_rmdir : :remove_before_unlink
        hook = lambda do |operation:, **_arguments|
          next unless operation == hook_operation

          File.rename(victim, File.join(root, "victim-held"))
          kind == :directory ? FileUtils.mkdir_p(victim) : File.write(victim, "replacement")
        end
        filesystem = Rubernetes::Platform::Linux::SecureRootfs.new(root: root, race_hook: hook)
        assert_raises(Rubernetes::Platform::Linux::SecureRootfs::UnsafePath) do
          filesystem.remove("victim")
        end

        assert_path_exists victim, "replacement #{kind} was deleted"
        assert_path_exists File.join(root, "victim-held"), "original #{kind} identity was lost"
      ensure
        filesystem&.close
      end
    end
  end

  private

  def gzip_layer(&)
    tar_io = StringIO.new("".b)
    Gem::Package::TarWriter.new(tar_io, &)
    gzip_bytes(tar_io.string)
  end

  def gzip_bytes(bytes)
    output = StringIO.new("".b)
    gzip = Zlib::GzipWriter.new(output)
    gzip.write(bytes)
    gzip.close
    output.string
  end

  def digest_for(bytes)
    "sha256:#{Digest::SHA256.hexdigest(bytes)}"
  end

  def tar_header(name, type:, linkname: "", size: 0)
    header = "\0" * 512
    write_field(header, 0, 100, name)
    write_field(header, 100, 8, "0000644\0")
    write_field(header, 108, 8, "0000000\0")
    write_field(header, 116, 8, "0000000\0")
    write_field(header, 124, 12, format("%011o\0", size))
    write_field(header, 136, 12, "00000000000\0")
    write_field(header, 148, 8, "        ")
    write_field(header, 156, 1, type)
    write_field(header, 157, 100, linkname)
    write_field(header, 257, 6, "ustar\0")
    write_field(header, 263, 2, "00")
    checksum = header.bytes.sum
    write_field(header, 148, 8, format("%06o\0 ", checksum))
    header
  end

  def write_field(buffer, offset, length, value)
    bytes = value.to_s.b.byteslice(0, length)
    (0...length).each do |index|
      buffer.setbyte(offset + index, bytes.getbyte(index) || 0)
    end
  end
end
