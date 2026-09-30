# frozen_string_literal: true

# File capabilities travel in a layer tar as the PAX record
# SCHILY.xattr.security.capability.  Without applying it, an image whose
# non-root binary was `setcap cap_net_bind_service=+ep` (ingress-nginx) cannot
# bind port 80: bounding has the capability, permitted/effective do not.
require_relative "../test_helper"
require "rubernetes/image"
require "rubernetes/platform/linux/xattr"
require "digest"
require "stringio"
require "tmpdir"
require "zlib"

class LayerExtractorXattrTest < Minitest::Test
  Image = Rubernetes::Image
  Xattr = Rubernetes::Platform::Linux::Xattr
  # cap_net_bind_service=+ep, VFS_CAP_REVISION_2 little-endian, as setcap writes it.
  CAPABILITY = %w[01000002 00040000 00000000 00000000 00000000].map { |hex| [hex].pack("H*") }.join.b

  def test_security_capability_and_user_xattrs_are_applied_and_others_ignored
    skip "xattr on the temp filesystem requires root" unless Process.uid.zero?

    Dir.mktmpdir("xattr-layer") do |dir|
      root = File.join(dir, "rootfs")
      Dir.mkdir(root)
      layer = tar(
        pax_entry("bin/server", {"SCHILY.xattr.security.capability" => CAPABILITY, "SCHILY.xattr.user.note" => "hello",
                                 "SCHILY.xattr.trusted.overlay.opaque" => "y", "SCHILY.xattr.security.selinux" => "u:r:t:s0"}) +
        file_entry("bin/server", "#!/bin/sh\n", mode: "0000755", uid: 101, gid: 82) +
        dir_entry("etc/app", mode: "0000755", uid: 101, gid: 82) +
        pax_entry("etc/app/big-owner", {"uid" => "3000000", "gid" => "3000001"}) +
        file_entry("etc/app/big-owner", "y\n", mode: "0000644", uid: 0, gid: 0) +
        symlink_entry("etc/app/link", "big-owner", uid: 101, gid: 82) +
        file_entry("etc/plain", "x\n", mode: "0000644") +
        special_entry("var/run/redis.pipe", "6") +
        special_entry("dev/tty-copy", "3")
      )
      extractor = Image::LayerExtractor.new(root)
      extractor.extract(StringIO.new(layer), digest: "sha256:#{Digest::SHA256.hexdigest(layer)}",
                                             media_type: Image::MediaTypes::OCI_IMAGE_LAYER_GZIP, expected_size: layer.bytesize)

      File.open(File.join(root, "bin/server"), File::RDONLY) do |file|
        assert_equal CAPABILITY, Xattr.fget(file.fileno, "security.capability")
        assert_equal "hello".b, Xattr.fget(file.fileno, "user.note")
        assert_nil Xattr.fget(file.fileno, "user.absent")
        assert_nil Xattr.fget(file.fileno, "trusted.overlay.opaque") if Process.uid.zero?
      end

      File.open(File.join(root, "etc/plain"), File::RDONLY) do |file|
        assert_nil Xattr.fget(file.fileno, "security.capability")
      end
      assert_equal 2, extractor.ignored_xattrs, "trusted.* and security.selinux are counted, not applied"

      # Ownership from the tar header, PAX uid/gid records and symlink ownership.
      assert_equal([101, 82], File.stat(File.join(root, "bin/server")).then { |st| [st.uid, st.gid] })
      assert_equal([101, 82], File.stat(File.join(root, "etc/app")).then { |st| [st.uid, st.gid] })
      assert_equal([3_000_000, 3_000_001], File.stat(File.join(root, "etc/app/big-owner")).then { |st| [st.uid, st.gid] })
      assert_equal([101, 82], File.lstat(File.join(root, "etc/app/link")).then { |st| [st.uid, st.gid] })
      assert_equal([0, 0], File.stat(File.join(root, "etc/plain")).then { |st| [st.uid, st.gid] })
      assert_equal 0o755, File.stat(File.join(root, "bin/server")).mode & 0o7777

      # Device nodes and FIFOs in a layer (bitnami/redis ships one) are skipped,
      # not fatal: the whole image used to be unpullable.
      assert_equal 2, extractor.skipped_special_files
      refute_path_exists File.join(root, "var/run/redis.pipe")
      refute_path_exists File.join(root, "dev/tty-copy")
    end
  end

  private

  def tar(entries)
    io = StringIO.new("".b)
    gz = Zlib::GzipWriter.new(io)
    gz.write(entries + ("\0" * 1024).b)
    gz.close
    io.string
  end

  def pax_entry(name, records)
    payload = records.map do |key, value|
      body = " #{key}=#{value.b}\n".b
      # length field counts itself; iterate until stable (as GNU tar does)
      length = body.bytesize + 1
      length += 1 while (length.to_s.bytesize + body.bytesize) != length
      "#{length}#{body}".b
    end.join.b
    header("PaxHeaders/#{name}", "x", payload.bytesize, mode: "0000644") + padded(payload)
  end

  def file_entry(name, content, mode:, uid: 0, gid: 0)
    header(name, "0", content.bytesize, mode: mode, uid: uid, gid: gid) + padded(content.b)
  end

  def dir_entry(name, mode:, uid: 0, gid: 0)
    header("#{name}/", "5", 0, mode: mode, uid: uid, gid: gid)
  end

  def symlink_entry(name, target, uid: 0, gid: 0)
    header(name, "2", 0, mode: "0000777", uid: uid, gid: gid, linkname: target)
  end

  def special_entry(name, type)
    header(name, type, 0, mode: "0000644")
  end

  def padded(bytes)
    bytes + ("\0" * ((512 - (bytes.bytesize % 512)) % 512)).b
  end

  def header(name, type, size, mode:, uid: 0, gid: 0, linkname: "")
    h = ("\0" * 512).b
    put(h, 0, 100, name)
    put(h, 100, 8, "#{mode}\0")
    put(h, 108, 8, format("%07o\0", uid))
    put(h, 116, 8, format("%07o\0", gid))
    put(h, 157, 100, linkname)
    put(h, 124, 12, format("%011o\0", size))
    put(h, 136, 12, "00000000000\0")
    put(h, 148, 8, "        ")
    put(h, 156, 1, type)
    put(h, 257, 6, "ustar\0")
    put(h, 263, 2, "00")
    put(h, 148, 8, format("%06o\0 ", h.bytes.sum))
    h
  end

  def put(buffer, offset, length, value)
    bytes = value.to_s.b.byteslice(0, length)
    bytes.bytesize.times { |i| buffer.setbyte(offset + i, bytes.getbyte(i)) }
  end
end
