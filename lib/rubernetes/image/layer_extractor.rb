# frozen_string_literal: true

require "fileutils"
require "stringio"
require "tempfile"
require "zlib"

require_relative "digest"
require_relative "errors"
require_relative "media_types"
require_relative "../platform/linux/secure_rootfs"

module Rubernetes
  module Image
    # Bounded resource policy for a single OCI layer.
    class LayerLimits
      DEFAULT_MAX_COMPRESSED_BYTES = 20 * 1024 * 1024 * 1024
      DEFAULT_MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024 * 1024
      DEFAULT_MAX_ENTRIES = 1_000_000
      DEFAULT_MAX_PATH_BYTES = 4096
      DEFAULT_MAX_METADATA_BYTES = 1024 * 1024

      attr_reader :max_compressed_bytes, :max_uncompressed_bytes, :max_entries, :max_path_bytes, :max_metadata_bytes

      def initialize(
        max_compressed_bytes: DEFAULT_MAX_COMPRESSED_BYTES,
        max_uncompressed_bytes: DEFAULT_MAX_UNCOMPRESSED_BYTES,
        max_entries: DEFAULT_MAX_ENTRIES,
        max_path_bytes: DEFAULT_MAX_PATH_BYTES,
        max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES
      )
        @max_compressed_bytes = positive_integer(max_compressed_bytes, "compressed byte limit")
        @max_uncompressed_bytes = positive_integer(max_uncompressed_bytes, "uncompressed byte limit")
        @max_entries = positive_integer(max_entries, "entry limit")
        @max_path_bytes = positive_integer(max_path_bytes, "path length limit")
        @max_metadata_bytes = positive_integer(max_metadata_bytes, "metadata limit")
        freeze
      rescue ArgumentError, TypeError => error
        raise LayerError.new("invalid layer limits: #{error.message}", cause: error), cause: error
      end

      private

      def positive_integer(value, label)
        integer = Integer(value)
        raise ArgumentError, "#{label} must be positive" unless integer.positive?

        integer
      end
    end

    # Safe gzip/tar layer applier. Every archive is verified into a temporary
    # compressed file before any rootfs pathname is changed; this prevents a
    # digest failure from partially applying an untrusted stream.
    class LayerExtractor
      TAR_BLOCK_BYTES = 512
      MAX_READ_BYTES = 1024 * 1024
      REGULAR_FILE_TYPES = ["", "0", "\0"].freeze

      attr_reader :root, :limits

      # PAX xattrs seen but deliberately not applied (see entry_xattrs), and
      # device/FIFO/socket entries skipped (see apply_entry).
      attr_reader :ignored_xattrs, :skipped_special_files

      def initialize(root, limits: nil, max_compressed_bytes: nil, max_uncompressed_bytes: nil, max_entries: nil, max_path_bytes: nil, max_metadata_bytes: nil, filesystem: nil)
        @root = File.expand_path(root.to_s)
        raise LayerError, "layer extraction root must be a non-empty path" if root.to_s.empty?
        ensure_root_directory!(@root, create: true)
        @filesystem = filesystem || secure_filesystem(@root)
        @limits = limits || LayerLimits.new(
          max_compressed_bytes: max_compressed_bytes || LayerLimits::DEFAULT_MAX_COMPRESSED_BYTES,
          max_uncompressed_bytes: max_uncompressed_bytes || LayerLimits::DEFAULT_MAX_UNCOMPRESSED_BYTES,
          max_entries: max_entries || LayerLimits::DEFAULT_MAX_ENTRIES,
          max_path_bytes: max_path_bytes || LayerLimits::DEFAULT_MAX_PATH_BYTES,
          max_metadata_bytes: max_metadata_bytes || LayerLimits::DEFAULT_MAX_METADATA_BYTES
        )
      end

      # Closes the fixed root descriptor held by the default secure backend.
      # Callers that reuse an extractor for several layers should close it
      # after the final layer has been applied.
      def close
        @filesystem.close if @filesystem.respond_to?(:close)
        true
      end

      # Applies one compressed or uncompressed tar layer. `digest` is mandatory:
      # an OCI layer cannot be applied before its content address is verified.
      def extract(source, digest: nil, expected_digest: nil, media_type: nil, expected_size: nil)
        expected = digest || expected_digest
        raise DigestError, "layer digest is required before extraction" if expected.nil?
        expected_digest_object = Digest.parse(expected)
        temporary = Tempfile.new(["rubernetes-layer", ".blob"])
        temporary.binmode
        compressed_bytes = copy_and_verify_source(source, temporary, expected_digest_object, expected_size)
        # The verified copy is read back by this process and then deleted; it
        # never has to survive a crash, so it is not synced.
        temporary.flush
        temporary.rewind

        type = normalize_media_type(media_type, temporary)
        raise UnsupportedMediaType, "zstd layer decompression is unavailable in Ruby stdlib" if MediaTypes.zstd_layer?(type)
        gzip = if type.nil?
                 temporary.rewind
                 temporary.read(2) == "\x1f\x8b".b
               else
                 MediaTypes.gzip_layer?(type)
               end
        reader = gzip ? gzip_reader(temporary, type) : bounded_reader(temporary)
        parse_tar(reader)
        drain_trailing_archive(reader)
        compressed_bytes
      rescue Zlib::Error, IOError, EOFError => error
        raise LayerError.new("cannot read OCI layer: #{error.message}", cause: error), cause: error
      ensure
        begin
          reader.close if defined?(reader) && reader && reader.respond_to?(:close)
        rescue IOError
          # The primary extraction error is more useful than a close failure.
        end
        temporary.close! if defined?(temporary) && temporary
      end
      alias unpack extract
      alias apply extract
      alias extract_layer extract

      private

      def copy_and_verify_source(source, destination, expected, expected_size)
        input, close_input = open_source(source)
        digest = ::Digest::SHA256.new
        compressed_bytes = 0
        begin
          loop do
            chunk = input.read(MAX_READ_BYTES)
            break if chunk.nil? || chunk.empty?

            chunk = chunk.to_s.b
            compressed_bytes += chunk.bytesize
            raise LimitError, "compressed layer exceeds the configured byte limit" if compressed_bytes > limits.max_compressed_bytes
            digest.update(chunk)
            destination.write(chunk)
          end
        ensure
          input.close if close_input
        end
        if expected_size && compressed_bytes != Integer(expected_size)
          raise LayerError, "compressed layer size does not match the descriptor"
        end
        actual = digest.hexdigest
        unless secure_compare(actual, expected.hex)
          raise DigestMismatch, "layer digest mismatch: expected #{expected}, got sha256:#{actual}"
        end
        compressed_bytes
      rescue ArgumentError, TypeError => error
        raise LayerError.new("invalid compressed layer size: #{error.message}", cause: error), cause: error
      end

      def open_source(source)
        if source.is_a?(String) && !source.include?("\0") && File.file?(source) && !File.symlink?(source)
          [File.open(source, File::RDONLY | (File::Constants.const_defined?(:NOFOLLOW) ? File::Constants::NOFOLLOW : 0)), true]
        elsif source.respond_to?(:read)
          [source, false]
        elsif source.is_a?(String)
          [StringIO.new(source.b), true]
        else
          raise LayerError, "layer source must be a readable IO or regular file path"
        end
      rescue SystemCallError => error
        raise LayerError.new("cannot open OCI layer source: #{error.message}", cause: error), cause: error
      end

      def normalize_media_type(media_type, io)
        return nil if media_type.nil? || media_type.to_s.empty?
        type = media_type.to_s.split(";", 2).first.strip
        raise UnsupportedMediaType, "unsupported OCI layer media type: #{type}" unless MediaTypes.layer?(type)

        type
      end

      def gzip_reader(io, media_type)
        io.rewind
        Zlib::GzipReader.new(io)
      rescue Zlib::Error => error
        raise LayerError.new("layer is not a valid gzip stream: #{error.message}", cause: error), cause: error
      end

      def bounded_reader(io)
        io.rewind
        LimitedReader.new(io, limits.max_uncompressed_bytes)
      end

      def parse_tar_stream(io)
        state = {pax: {}, global_pax: {}, long_name: nil, long_link: nil, zero_blocks: 0}
        loop do
          header = read_exact(io, TAR_BLOCK_BYTES, allow_eof: true)
          raise LayerError, "truncated tar header" if header.nil?
          if header.bytes.all?(&:zero?)
            state[:zero_blocks] += 1
            break if state[:zero_blocks] >= 2
            next
          end
          raise LayerError, "tar data follows an incomplete end marker" if state[:zero_blocks].positive?
          verify_tar_checksum!(header)

          typeflag = header.byteslice(156, 1).to_s.b
          name = tar_field(header, 0, 100, "name")
          prefix = tar_field(header, 345, 155, "prefix")
          name = "#{prefix}/#{name}" unless prefix.empty?
          size = parse_tar_number(header.byteslice(124, 12), "size")
          raise LimitError, "tar metadata exceeds the configured limit" if size > limits.max_metadata_bytes && ["x", "g", "L", "K"].include?(typeflag)
          payload = nil

          case typeflag
          when "x", "g"
            payload = read_payload(io, size)
            parsed_pax = parse_pax(payload)
            if typeflag == "g"
              state[:global_pax] = state[:global_pax].merge(parsed_pax).freeze
            else
              state[:pax] = parsed_pax
            end
            discard_padding(io, size)
            next
          when "L"
            payload = read_payload(io, size)
            state[:long_name] = payload.delete_suffix("\0".b)
            discard_padding(io, size)
            next
          when "K"
            payload = read_payload(io, size)
            state[:long_link] = payload.delete_suffix("\0".b)
            discard_padding(io, size)
            next
          end

          pax = state[:global_pax].merge(state[:pax])
          effective_name = pax["path"] || state[:long_name] || name
          effective_link = pax["linkpath"] || state[:long_link] || tar_field(header, 157, 100, "linkname")
          effective_size = pax.key?("size") ? parse_pax_size(pax["size"]) : size
          apply_entry(typeflag, effective_name, effective_link, effective_size, header, xattrs: entry_xattrs(pax), pax: pax)
          discard_padding(io, effective_size)
          state[:pax] = {}
          state[:long_name] = nil
          state[:long_link] = nil
        end
        raise LayerError, "tar archive is missing its two-block end marker" unless state[:zero_blocks] >= 2
      end

      def apply_entry(typeflag, raw_name, raw_link, size, header, xattrs: nil, pax: {})
        increment_entry_count!
        raise LimitError, "tar file exceeds the configured uncompressed byte limit" if size > limits.max_uncompressed_bytes
        # A layer tar routinely carries an entry for its own root ("./" or
        # "."), which is a directory that already exists.  It names nothing to
        # create, so it is skipped rather than rejected -- but only as a
        # directory: any other type claiming the root is an attack.
        name = safe_entry_path(raw_name, allow_root: typeflag == "5")
        if name.nil?
          discard_entry_payload(size)
          return
        end

        mode = parse_tar_number(header.byteslice(100, 8), "mode") & 0o7777
        owner = entry_owner(header, pax)

        case typeflag
        when *REGULAR_FILE_TYPES
          write_regular_file(name, size, mode, xattrs: xattrs, owner: owner)
        when "5"
          create_directory(name, mode, owner: owner)
        when "2"
          create_symlink(name, raw_link, owner: owner)
        when "1"
          create_hardlink(name, raw_link)
        when "3", "4", "6", "S"
          # Character/block devices, FIFOs and sockets in an image layer
          # (bitnami/redis ships one) are not materialised: the container's
          # /dev is a nodev tmpfs the runtime populates itself, and nothing in
          # an image contract depends on a packaged FIFO or socket.  Rejecting
          # the whole layer made the image unpullable; containerd creates the
          # node, we skip it and count it.
          @skipped_special_files += 1
          discard_entry_payload(size)
        when "7", "M", "D", "s"
          raise SecurityError, "tar special file type is forbidden"
        else
          raise SecurityError, "unknown tar entry type is forbidden"
        end
      end

      # PAX "SCHILY.xattr.<name>" records carry the entry's extended attributes.
      # Applied: security.capability (file capabilities -- how a non-root image
      # binary binds a privileged port, e.g. ingress-nginx) and user.* attributes.
      # Not applied: trusted.* (needs CAP_SYS_ADMIN and can steer overlayfs),
      # system.* (ACLs are not part of the image contract here) and security.*
      # other than capability (SELinux/SMACK labels belong to the host policy).
      XATTR_PAX_PREFIX = "SCHILY.xattr."
      APPLIED_XATTRS = ->(name) { name == "security.capability" || name.start_with?("user.") }

      def entry_xattrs(pax)
        return nil if pax.empty?

        selected = nil
        pax.each do |key, value|
          next unless key.start_with?(XATTR_PAX_PREFIX)

          name = key.delete_prefix(XATTR_PAX_PREFIX)
          if APPLIED_XATTRS.call(name)
            (selected ||= {})[name] = value.to_s.b
          else
            @ignored_xattrs += 1
          end
        end
        selected
      end

      # Image directories such as ingress-nginx's /etc/ingress-controller are owned
      # by the non-root image user (uid 101); dropping ownership left them root's
      # and the controller could not write its certificates.  PAX uid/gid records
      # override the octal header fields (they carry values above 2^21).
      def entry_owner(header, pax)
        uid = pax.key?("uid") ? Integer(pax["uid"], 10) : parse_tar_number(header.byteslice(108, 8), "uid")
        gid = pax.key?("gid") ? Integer(pax["gid"], 10) : parse_tar_number(header.byteslice(116, 8), "gid")
        raise SecurityError, "tar entry owner is out of range" if uid.negative? || gid.negative? || uid > 0xFFFF_FFFE || gid > 0xFFFF_FFFE

        [uid, gid]
      rescue ArgumentError => error
        raise LayerError.new("tar entry owner is invalid: #{error.message}", cause: error), cause: error
      end

      def write_regular_file(name, size, mode, xattrs: nil, owner: nil)
        if whiteout?(name)
          apply_whiteout(name)
          skip_file_payload(size)
          return
        end
        @filesystem.write_file(name, mode: mode, xattrs: xattrs, owner: owner, **write_sync_option) do |file|
          remaining = size
          while remaining.positive?
            chunk = read_exact(@current_reader, [remaining, MAX_READ_BYTES].min)
            raise LayerError, "truncated tar file payload" if chunk.nil?
            file.write(chunk)
            @extracted_bytes += chunk.bytesize
            raise LimitError, "layer exceeds the configured uncompressed byte limit" if @extracted_bytes > limits.max_uncompressed_bytes
            remaining -= chunk.bytesize
          end
        end
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::Error => error
        raise_filesystem_error(error, "cannot create layer file #{name.inspect}")
      end

      def create_directory(name, mode, owner: nil)
        @filesystem.create_directory(name, mode: mode, owner: owner)
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::Error => error
        raise_filesystem_error(error, "cannot create layer directory #{name.inspect}")
      end

      def create_symlink(name, raw_link, owner: nil)
        link = safe_link_target(raw_link, name)
        @filesystem.create_symlink(name, raw_link.to_s.b.delete_suffix("\0".b), validation_path: link, owner: owner)
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::Error => error
        raise_filesystem_error(error, "cannot create layer symlink #{name.inspect}")
      end

      # A tar hardlink names its target as an archive path (relative to the
      # archive root), unlike a symlink whose target is relative to the link's
      # directory; resolving it against the link's directory would reject
      # every busybox applet link (`bin/sh -> bin/[`).
      def create_hardlink(name, raw_link)
        target_name = safe_entry_path(raw_link.to_s.b.delete_suffix("\0".b))
        @filesystem.create_hardlink(name, target_name)
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::UnsafePath => error
        raise SecurityError.new("hardlink target is unsafe: #{error.message}", cause: error), cause: error
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::Error => error
        raise SecurityError.new("hardlink target does not exist", cause: error), cause: error
      end

      def apply_whiteout(name)
        parent_name, marker = split_parent(name)
        if marker == ".wh..wh..opq"
          @filesystem.clear_directory(parent_name)
          return
        end
        target_name = marker.delete_prefix(".wh.")
        raise SecurityError, "whiteout target is invalid" if target_name.empty? || target_name == "." || target_name == ".." || target_name.include?("/")
        target = [parent_name, target_name].reject(&:empty?).join("/")
        @filesystem.remove(target)
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::Error => error
        raise SecurityError.new("cannot apply whiteout safely: #{error.message}", cause: error), cause: error
      end

      def split_parent(name)
        parts = name.split("/")
        [parts[0...-1].join("/"), parts.last]
      end

      def whiteout?(name)
        name.split("/").last.start_with?(".wh.")
      end

      def skip_file_payload(size)
        remaining = size
        while remaining.positive?
          chunk = read_exact(@current_reader, [remaining, MAX_READ_BYTES].min)
          raise LayerError, "truncated tar whiteout payload" if chunk.nil?
          remaining -= chunk.bytesize
        end
      end

      # Consumes and discards an entry's payload, for an entry that names
      # nothing this extractor has to create.
      def discard_entry_payload(size)
        remaining = size
        while remaining.positive?
          chunk = read_exact(@current_reader, [remaining, MAX_READ_BYTES].min)
          raise LayerError, "truncated tar file payload" if chunk.nil?

          remaining -= chunk.bytesize
        end
      end

      def safe_entry_path(raw, allow_root: false)
        bytes = raw.to_s.b
        raise SecurityError, "tar path contains NUL" if bytes.include?("\0")
        raise SecurityError, "tar path is absolute" if bytes.start_with?("/") || bytes.start_with?("\\") || bytes.match?(/\A[A-Za-z]:[\\\/]/)
        raise SecurityError, "tar path exceeds the configured length limit" if bytes.bytesize > limits.max_path_bytes
        components = bytes.split("/")
        raise SecurityError, "tar path is empty" if components.empty? || components.all?(&:empty?)
        normalized = []
        components.each do |component|
          next if component.empty? || component == "."
          raise SecurityError, "tar path contains a parent traversal component" if component == ".."
          normalized << component
        end
        if normalized.empty?
          return nil if allow_root

          raise SecurityError, "tar path resolves to the root"
        end
        result = normalized.join("/")
        raise SecurityError, "tar path exceeds the configured length limit" if result.bytesize > limits.max_path_bytes

        result
      end

      def safe_link_target(raw, link_name)
        bytes = raw.to_s.b.delete_suffix("\0".b)
        raise SecurityError, "tar link contains NUL" if bytes.include?("\0")
        raise SecurityError, "tar link is empty" if bytes.empty?
        # A Windows-style link is never valid in an OCI layer.
        raise SecurityError, "tar link is absolute" if bytes.start_with?("\\") || bytes.match?(/\A[A-Za-z]:[\\\/]/)

        # A POSIX absolute target is normal in real images ("/lib" -> "/usr/lib",
        # "/bin/sh" -> "/bin/dash") and is not an escape: it is resolved inside
        # the container, so it means "relative to the rootfs root".  Only the
        # base differs; the traversal check below is unchanged, so a target that
        # climbs above the rootfs is still rejected.
        absolute = bytes.start_with?("/")
        base = absolute ? [] : link_name.split("/")[0...-1]
        normalized = base.dup
        bytes.split("/").each do |component|
          next if component.empty? || component == "."
          if component == ".."
            raise SecurityError, "tar link escapes the rootfs" if normalized.empty?
            normalized.pop
          else
            normalized << component
          end
        end
        result = normalized.join("/")
        raise SecurityError, "tar link escapes the rootfs" if result.empty?
        raise SecurityError, "tar link exceeds the configured length limit" if bytes.bytesize > limits.max_path_bytes || result.bytesize > limits.max_path_bytes

        result
      end

      def ensure_root_directory!(path, create: false)
        FileUtils.mkdir_p(path, mode: 0o700) if create
      rescue SystemCallError => error
        raise LayerError.new("cannot prepare layer root: #{error.message}", cause: error), cause: error
      end

      def secure_filesystem(path)
        unless RUBY_PLATFORM.include?("linux")
          raise LayerError, "secure OCI layer extraction requires a Linux openat2 backend"
        end

        ::Rubernetes::Platform::Linux::SecureRootfs.new(root: path)
      rescue ::Rubernetes::Platform::Linux::SecureRootfs::Error, ::Rubernetes::Platform::Linux::Error => error
        raise LayerError.new("secure OCI layer extraction is unavailable: #{error.message}", cause: error), cause: error
      end

      def raise_filesystem_error(error, message)
        security_errno = [Errno::ELOOP::Errno, Errno::EXDEV::Errno, Errno::ENOTDIR::Errno, Errno::EISDIR::Errno, Errno::ENOENT::Errno]
        error_class = error.is_a?(::Rubernetes::Platform::Linux::SecureRootfs::UnsafePath) || security_errno.include?(error.errno) ? SecurityError : LayerError
        raise error_class.new("#{message}: #{error.message}", cause: error), cause: error
      end

      def increment_entry_count!
        @entry_count = (@entry_count || 0) + 1
        raise LimitError, "layer exceeds the configured entry limit" if @entry_count > limits.max_entries
        @extracted_bytes ||= 0
      end

      def parse_tar_number(field, label)
        bytes = field.to_s.b
        text = bytes.delete("\0 ").strip
        return 0 if text.empty?
        unless text.match?(/\A[0-7]+\z/)
          raise SecurityError, "tar #{label} field is not valid octal"
        end
        Integer(text, 8)
      rescue ArgumentError => error
        raise SecurityError.new("tar #{label} field is invalid: #{error.message}", cause: error), cause: error
      end

      def parse_pax(payload)
        values = {}
        offset = 0
        while offset < payload.bytesize
          separator = payload.index(" ", offset)
          raise SecurityError, "PAX record has no length separator" unless separator
          length_text = payload.byteslice(offset, separator - offset)
          length = Integer(length_text, 10)
          raise SecurityError, "PAX record length is invalid" if length <= 0 || offset + length > payload.bytesize
          record = payload.byteslice(offset, length)
          raise SecurityError, "PAX record does not match its declared length" unless record.end_with?("\n")
          body_offset = separator - offset + 1
          body = record.byteslice(body_offset, length - body_offset - 1)
          key, value = body.split("=", 2)
          raise SecurityError, "PAX record is invalid" if key.to_s.empty? || value.nil? || values.key?(key)
          values[key] = value
          offset += length
        end
        values
      rescue ArgumentError => error
        raise SecurityError.new("PAX record length is invalid: #{error.message}", cause: error), cause: error
      end

      def parse_pax_size(value)
        integer = Integer(value.to_s, 10)
        raise SecurityError, "PAX size must be non-negative" if integer.negative?

        integer
      rescue ArgumentError => error
        raise SecurityError.new("PAX size is invalid: #{error.message}", cause: error), cause: error
      end

      def tar_field(header, offset, length, label)
        field = header.byteslice(offset, length).to_s.b
        nul = field.index("\0")
        if nul && field.byteslice((nul + 1)..).to_s.bytes.any? { |byte| byte != 0 }
          raise SecurityError, "tar #{label} field contains data after NUL"
        end
        value = nul ? field.byteslice(0, nul) : field
        value.to_s.b.delete_suffix(" ".b)
      end

      def verify_tar_checksum!(header)
        expected_text = header.byteslice(148, 8).to_s.b.delete("\0 ").strip
        raise SecurityError, "tar checksum field is invalid" unless expected_text.match?(/\A[0-7]+\z/)
        expected = Integer(expected_text, 8)
        # Every byte of the header with the checksum field counted as eight
        # spaces.  String#sum adds the bytes in C; the per-byte Ruby loop it
        # replaces was a fifth of the CPU of unpacking an image.
        actual = header.sum(32) - header.byteslice(148, 8).sum(32) + (8 * 32)
        raise SecurityError, "tar header checksum mismatch" unless expected == actual
      rescue ArgumentError => error
        raise SecurityError.new("tar checksum is invalid: #{error.message}", cause: error), cause: error
      end

      def read_payload(io, size)
        raise LimitError, "tar metadata exceeds the configured uncompressed byte limit" if size > limits.max_metadata_bytes
        payload = read_exact(io, size)
        raise LayerError, "truncated tar metadata payload" if payload.nil? || payload.bytesize != size

        payload
      end

      def discard_padding(io, size)
        remaining = (TAR_BLOCK_BYTES - (size % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES
        return if remaining.zero?
        padding = read_exact(io, remaining)
        raise LayerError, "truncated tar padding" if padding.nil? || padding.bytesize != remaining
      end

      # The secure backend takes sync: false (see SecureRootfs#write_file); an
      # injected filesystem may not know the option.
      def write_sync_option
        @write_sync_option ||= begin
          parameters = @filesystem.respond_to?(:write_file) ? @filesystem.method(:write_file).parameters : []
          accepts = parameters.any? { |kind, name| (%i[key keyreq].include?(kind) && name == :sync) || kind == :keyrest }
          accepts ? {sync: false}.freeze : {}.freeze
        end
      end

      def read_exact(io, bytes, allow_eof: false)
        return "".b if bytes.zero?
        output = String.new(encoding: Encoding::BINARY)
        while output.bytesize < bytes
          chunk = io.read([bytes - output.bytesize, MAX_READ_BYTES].min)
          if chunk.nil? || chunk.empty?
            return nil if output.empty? && allow_eof
            break
          end
          @stream_bytes += chunk.bytesize
          raise LimitError, "layer exceeds the configured uncompressed byte limit" if @stream_bytes > limits.max_uncompressed_bytes
          output << chunk.to_s.b
        end
        output.bytesize == bytes ? output : nil
      end

      # Tar payload reads are routed through this accessor so every regular file
      # and whiteout consumes exactly the bytes declared by its header.
      def current_reader
        @current_reader
      end

      class LimitedReader
        def initialize(io, limit)
          @io = io
          @limit = limit
          @bytes = 0
        end

        def read(length = nil)
          chunk = length.nil? ? @io.read : @io.read(length)
          return chunk if chunk.nil? || chunk.empty?
          @bytes += chunk.bytesize
          raise LimitError, "layer exceeds the configured uncompressed byte limit" if @bytes > @limit

          chunk
        end

        def close
          @io.close
        end
      end

      def parse_tar(io)
        @current_reader = io
        @entry_count = 0
        @extracted_bytes = 0
        @ignored_xattrs = 0
        @skipped_special_files = 0
        @stream_bytes = 0
        parse_tar_stream(io)
      ensure
        @current_reader = nil
      end

      def drain_trailing_archive(io)
        while (chunk = io.read(MAX_READ_BYTES))
          next if chunk.empty?
          @stream_bytes += chunk.bytesize
          raise LimitError, "layer exceeds the configured uncompressed byte limit" if @stream_bytes > limits.max_uncompressed_bytes
          raise SecurityError, "tar archive contains non-zero data after its end marker" if chunk.to_s.b.bytes.any?(&:positive?)
        end
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
    end

    Layer = LayerExtractor
  end
end
