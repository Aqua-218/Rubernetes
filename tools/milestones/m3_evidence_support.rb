#!/usr/bin/env ruby
# frozen_string_literal: true

# Shared content-addressed evidence capture helpers for M3 and M4.

require "digest"
require "etc"
require "fileutils"
require "json"
require "open3"
require "rbconfig"
require "shellwords"
require "time"

module M34EvidenceSupport
  ROOT = File.expand_path("../..", __dir__).freeze
  SOURCE_EXCLUSIONS = %r{\A(?:\.git|artifacts|build|pkg|tmp|\.bundle)(?:/|\z)|\Aa11-generated\.[A-Za-z0-9]{6,}/|\Aapps/[^/]+/(?:log|tmp|storage)/}.freeze
  # External observers are allowed to hand the evidence runner a path to a
  # capture, but the path is only a transport pointer.  The pointer must
  # never become part of a milestone claim: the bytes are copied into the
  # immutable bundle and the report is rewritten to refer to that copy.
  # Keep this bound deliberately finite; a packet capture is evidence, not a
  # general-purpose file upload channel.
  MAX_EXTERNAL_ARTIFACT_BYTES = 256 * 1024 * 1024
  # Linux has no Ruby-level O_DIRECTORY constant.  M4 runs only on Linux and
  # uses this flag while walking the bundle by directory descriptor, so a
  # FIFO or symlink can never be opened as an intermediate component.
  O_DIRECTORY = 0x10_000
  O_NONBLOCK = 0x800

  module_function

  def source_identity(gate_module)
    paths = Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).select do |path|
      next false unless File.file?(path)

      !path.delete_prefix("#{ROOT}/").match?(SOURCE_EXCLUSIONS)
    end.sort
    entries = paths.map do |path|
      {
        "path" => path.delete_prefix("#{ROOT}/"),
        "sha256" => Digest::SHA256.file(path).hexdigest,
        "bytes" => File.size(path)
      }
    end
    {
      "sha256" => gate_module.canonical_inventory_digest(entries),
      "file_count" => entries.length,
      "entries" => entries
    }
  end

  def git_metadata_paths
    Dir.glob(File.join(ROOT, "**/*"), File::FNM_DOTMATCH).filter_map do |path|
      relative = path.delete_prefix("#{ROOT}/")
      relative if relative.split("/").include?(".git")
    end.uniq.sort
  end

  def now
    Time.now.utc.iso8601(6)
  end

  def command_words(value)
    value.is_a?(Array) ? value : Shellwords.split(value.to_s)
  rescue ArgumentError => error
    raise OptionParser::InvalidArgument, "invalid command: #{error.message}"
  end

  def command_record(name, command, started_at, finished_at, status, stdout: "", stderr: "", error: nil)
    record = {
      "name" => name,
      "command" => command,
      "started_at" => started_at,
      "finished_at" => finished_at,
      "exit_status" => status,
      "stdout" => stdout,
      "stderr" => stderr
    }
    record["error"] = error if error
    record
  end

  def copy_tree(source_path, destination_directory)
    FileUtils.mkdir_p(destination_directory)
    FileUtils.cp_r(File.join(source_path, "."), destination_directory, preserve: true)
  end

  def copy_report(source_path, destination_path)
    raise "report path does not exist: #{source_path}" unless File.file?(source_path)

    FileUtils.cp(source_path, destination_path)
  end

  # Safely materialize a file supplied by an external observation runner.
  #
  # The source is checked with lstat before and after opening, opened with
  # O_NOFOLLOW, and copied with an explicit byte bound.  The destination is
  # created exclusively so an attacker cannot replace it with a symlink
  # between validation and write.  This helper intentionally returns the
  # resulting byte count and digest; callers must record both in the report.
  def copy_external_artifact(source_path, destination_path, max_bytes: MAX_EXTERNAL_ARTIFACT_BYTES)
    raise ArgumentError, "external artifact source path is required" unless source_path.is_a?(String) && !source_path.empty?
    raise ArgumentError, "external artifact destination path is required" unless destination_path.is_a?(String) && !destination_path.empty?
    raise ArgumentError, "external artifact byte bound is invalid" unless max_bytes.is_a?(Integer) && max_bytes.positive?

    source = File.expand_path(source_path, ROOT)
    destination = File.expand_path(destination_path, ROOT)
    raise "external artifact source and destination must differ" if source == destination

    source_lstat = File.lstat(source)
    raise "external artifact source must be a regular non-symlink file" unless source_lstat.file? && !source_lstat.symlink?
    raise "external artifact exceeds #{max_bytes} bytes" if source_lstat.size <= 0 || source_lstat.size > max_bytes

    parent = File.dirname(destination)
    # The caller controls the destination directory. Validate every
    # filesystem component from the root so a temporary test/CI bundle outside
    # the source tree is still safe, while the materializer itself keeps the
    # final destination under its supplied bundle directory.
    ensure_no_symlink_path!(parent, File::SEPARATOR)
    raise "external artifact destination already exists" if File.exist?(destination) || File.symlink?(destination)

    bytes = 0
    begin
      File.open(source, File::RDONLY | File::BINARY | File::NOFOLLOW) do |input|
        opened = input.stat
        unless opened.file? && !opened.symlink? && opened.size == source_lstat.size &&
               opened.dev == source_lstat.dev && opened.ino == source_lstat.ino
          raise "external artifact source changed while opening"
        end

        File.open(destination, File::WRONLY | File::CREAT | File::EXCL | File::BINARY | File::NOFOLLOW, 0o600) do |output|
          while (chunk = input.read(1024 * 1024))
            bytes += chunk.bytesize
            raise "external artifact exceeds #{max_bytes} bytes" if bytes > max_bytes || bytes > source_lstat.size

            output.write(chunk)
          end
          output.flush
          output.fsync
        end
      end
      destination_lstat = File.lstat(destination)
      raise "external artifact destination is not a regular file" unless destination_lstat.file? && !destination_lstat.symlink?
      raise "external artifact size changed during copy" unless bytes == source_lstat.size && destination_lstat.size == bytes
      {"path" => destination, "bytes" => bytes, "sha256" => Digest::SHA256.file(destination).hexdigest}
    rescue StandardError
      File.unlink(destination) if File.exist?(destination) && !File.symlink?(destination)
      raise
    end
  rescue Errno::ENOENT, Errno::ELOOP, Errno::EACCES => error
    raise "external artifact could not be safely copied: #{error.message}"
  end

  # Reject symlink components, including a symlink parent that still resolves
  # inside the bundle. Evidence must be self-contained and regular-file
  # backed; merely being inside the lexical bundle directory is insufficient.
  def ensure_no_symlink_path!(path, root = ROOT)
    expanded_root = File.expand_path(root)
    expanded = File.expand_path(path)
    under_root = expanded_root == File::SEPARATOR ? expanded.start_with?(File::SEPARATOR) :
      (expanded == expanded_root || expanded.start_with?("#{expanded_root}/"))
    unless under_root
      raise "external artifact path escapes the evidence root"
    end

    relative = expanded_root == File::SEPARATOR ? expanded.delete_prefix(File::SEPARATOR) :
      expanded.delete_prefix("#{expanded_root}/")
    current = expanded_root
    relative.split("/").reject(&:empty?).each do |component|
      current = File.join(current, component)
      stat = File.lstat(current)
      raise "external artifact path contains a symlink" if stat.symlink?
    end
    true
  rescue Errno::ENOENT => error
    raise "external artifact path component is missing: #{error.message}"
  end

  # Read a bundle-relative regular file through a directory-descriptor walk.
  # Every component is opened relative to an already-open directory FD with
  # O_NOFOLLOW|O_DIRECTORY; the final file is opened with O_NOFOLLOW and all
  # stat/read/hash/parse consumers use the bytes from that same descriptor.
  # This closes the rename/symlink TOCTOU window left by checking a pathname
  # and opening it later.
  def read_bundle_file(root, relative_path, max_bytes: MAX_EXTERNAL_ARTIFACT_BYTES)
    raise ArgumentError, "bundle root is required" unless root.is_a?(String) && !root.empty?
    raise ArgumentError, "bundle-relative path is required" unless relative_path.is_a?(String) && !relative_path.empty?
    raise ArgumentError, "bundle-relative path is not normalized" if relative_path.start_with?("/") || relative_path.include?("\0") || relative_path.split("/").any? { |part| ["", ".", ".."].include?(part) }
    raise ArgumentError, "bundle file byte bound is invalid" unless max_bytes.is_a?(Integer) && max_bytes.positive?

    components = relative_path.split("/")
    root_path = File.expand_path(root)
    directory_flags = File::RDONLY | File::NOFOLLOW | O_DIRECTORY
    root_components = root_path.delete_prefix(File::SEPARATOR).split(File::SEPARATOR).reject(&:empty?)
    root_fd = File.open(File::SEPARATOR, directory_flags)
    directory_fds = [root_fd]
    current = root_fd
    (root_components + components[0...-1]).each do |component|
      child_path = "/proc/self/fd/#{current.fileno}/#{component}"
      child = File.open(child_path, directory_flags)
      unless child.stat.directory?
        child.close
        raise "bundle path component is not a directory: #{component}"
      end
      raise "bundle path crosses a filesystem boundary" unless child.stat.dev == current.stat.dev
      directory_fds << child
      current = child
    end
    raise "bundle root must be a directory" unless current.stat.directory?

    final_path = "/proc/self/fd/#{current.fileno}/#{components.fetch(-1)}"
    file = File.open(final_path, File::RDONLY | File::BINARY | File::NOFOLLOW | O_NONBLOCK)
    begin
      opened = file.stat
      unless opened.file? && !opened.symlink?
        raise "bundle file must be a regular non-symlink file"
      end
      raise "bundle file crosses a filesystem boundary" unless opened.dev == current.stat.dev
      raise "bundle file is empty" unless opened.size.positive?
      raise "bundle file exceeds #{max_bytes} bytes" if opened.size > max_bytes

      bytes = file.read.to_s.b
      after = file.stat
      unless after.dev == opened.dev && after.ino == opened.ino && after.size == opened.size && bytes.bytesize == opened.size
        raise "bundle file changed while reading"
      end
      {"bytes" => bytes, "bytesize" => opened.size, "dev" => opened.dev, "ino" => opened.ino}
    ensure
      file.close unless file.closed?
    end
  rescue Errno::ELOOP, Errno::ENOTDIR, Errno::ENOENT, Errno::EACCES, Errno::EISDIR, Errno::ENXIO => error
    raise "bundle file could not be securely opened: #{error.message}"
  ensure
    directory_fds&.reverse_each { |fd| fd.close unless fd.closed? }
  end

  # Parse every record/block in a capture. Looking only at four magic bytes is
  # insufficient evidence: a global header, a truncated record, or bytes after
  # the last complete record could otherwise claim an arbitrary packet count.
  def parse_packet_capture(path, max_bytes: MAX_EXTERNAL_ARTIFACT_BYTES)
    stat = File.lstat(path)
    unless stat.file? && !stat.symlink? && stat.size.positive? && stat.size <= max_bytes
      raise "packet capture must be a bounded regular non-symlink file"
    end
    bytes = File.open(path, File::RDONLY | File::BINARY | File::NOFOLLOW | O_NONBLOCK) do |io|
      opened = io.stat
      unless opened.file? && opened.dev == stat.dev && opened.ino == stat.ino && opened.size == stat.size
        raise "packet capture changed while opening"
      end
      value = io.read.to_s.b
      after = io.stat
      unless after.dev == opened.dev && after.ino == opened.ino && after.size == opened.size
        raise "packet capture changed while reading"
      end
      value
    end
    raise "packet capture changed while reading" unless bytes.bytesize == stat.size
    raise "packet capture is empty" if bytes.empty?

    parse_packet_capture_bytes(bytes)
  end

  def parse_packet_capture_bytes(bytes)
    value = bytes.to_s.b
    raise "packet capture is empty" if value.empty?

    if value.byteslice(0, 4) == [0x0a, 0x0d, 0x0d, 0x0a].pack("C4")
      parse_pcapng(value)
    else
      parse_pcap(value)
    end
  end

  def parse_pcap(bytes)
    magic = bytes.byteslice(0, 4)
    endian, timestamp_limit = case magic
                              when [0xd4, 0xc3, 0xb2, 0xa1].pack("C4") then [:little, 1_000_000]
                              when [0xa1, 0xb2, 0xc3, 0xd4].pack("C4") then [:big, 1_000_000]
                              when [0x4d, 0x3c, 0xb2, 0xa1].pack("C4") then [:little, 1_000_000_000]
                              when [0xa1, 0xb2, 0x3c, 0x4d].pack("C4") then [:big, 1_000_000_000]
                              else raise "packet capture has an unknown PCAP magic"
                              end
    raise "PCAP global header is truncated" if bytes.bytesize < 24

    uint16 = endian == :little ? "v" : "n"
    uint32 = endian == :little ? "V" : "N"
    major = bytes.byteslice(4, 2).unpack1(uint16)
    minor = bytes.byteslice(6, 2).unpack1(uint16)
    raise "unsupported PCAP version #{major}.#{minor}" unless major == 2 && minor == 4

    snaplen = bytes.byteslice(16, 4).unpack1(uint32)
    raise "PCAP snaplen must be positive" unless snaplen.positive?
    link_type = bytes.byteslice(20, 4).unpack1(uint32)
    link_minimum = packet_link_minimum(link_type)

    offset = 24
    packet_count = 0
    while offset < bytes.bytesize
      remaining = bytes.bytesize - offset
      raise "PCAP packet header is truncated or trailing bytes are present" if remaining < 16

      header = bytes.byteslice(offset, 16).unpack("#{uint32}4")
      _seconds, fraction, included_length, original_length = header
      raise "PCAP timestamp fraction is out of range" unless fraction < timestamp_limit
      raise "PCAP packet included length must be positive" unless included_length.positive?
      raise "PCAP packet original length must be positive" unless original_length.positive?
      raise "PCAP included length exceeds snaplen" if included_length > snaplen
      raise "PCAP included length exceeds original length" if included_length > original_length
      offset += 16
      raise "PCAP packet payload is truncated" if included_length > bytes.bytesize - offset

      payload = bytes.byteslice(offset, included_length)
      validate_packet_payload!(payload, link_type, link_minimum, "PCAP")
      offset += included_length
      packet_count += 1
    end
    raise "PCAP contains no packet records" unless packet_count.positive?
    raise "PCAP contains trailing bytes" unless offset == bytes.bytesize

    {"format" => "pcap", "packet_count" => packet_count, "bytes" => bytes.bytesize}
  end

  def parse_pcapng(bytes)
    offset = 0
    endian = nil
    packet_count = 0
    section_seen = false
    interfaces = []

    while offset < bytes.bytesize
      remaining = bytes.bytesize - offset
      raise "PCAPNG block header is truncated or trailing bytes are present" if remaining < 12

      type_bytes = bytes.byteslice(offset, 4)
      if type_bytes == [0x0a, 0x0d, 0x0d, 0x0a].pack("C4")
        byte_order_magic = bytes.byteslice(offset + 8, 4)
        endian = case byte_order_magic
                 when [0x4d, 0x3c, 0x2b, 0x1a].pack("C4") then :little
                 when [0x1a, 0x2b, 0x3c, 0x4d].pack("C4") then :big
                 else raise "PCAPNG section byte-order magic is invalid"
                 end
        total_length = unpack_u32(bytes.byteslice(offset + 4, 4), endian)
        validate_pcapng_block!(bytes, offset, total_length, endian, minimum: 28)
        major = unpack_u16(bytes.byteslice(offset + 12, 2), endian)
        minor = unpack_u16(bytes.byteslice(offset + 14, 2), endian)
        raise "unsupported PCAPNG version #{major}.#{minor}" unless major == 1 && minor == 0
        validate_pcapng_options!(bytes, offset + 24, total_length - 28, endian)
        section_seen = true
        interfaces = []
      else
        raise "PCAPNG data block precedes a section header" unless section_seen && endian

        block_type = unpack_u32(type_bytes, endian)
        total_length = unpack_u32(bytes.byteslice(offset + 4, 4), endian)
        validate_pcapng_block!(bytes, offset, total_length, endian, minimum: 12)
        case block_type
        when 0x00000001 # Interface Description Block
          raise "PCAPNG interface block is too short" if total_length < 20

          link_type = unpack_u16(bytes.byteslice(offset + 8, 2), endian)
          reserved = unpack_u16(bytes.byteslice(offset + 10, 2), endian)
          raise "PCAPNG interface reserved field is non-zero" unless reserved.zero?
          snaplen = unpack_u32(bytes.byteslice(offset + 12, 4), endian)
          raise "PCAPNG interface snaplen must be positive" unless snaplen.positive?
          validate_pcapng_options!(bytes, offset + 16, total_length - 20, endian)
          interfaces << {"link_type" => link_type, "snaplen" => snaplen,
                         "minimum" => packet_link_minimum(link_type)}
        when 0x00000006 # Enhanced Packet Block
          raise "PCAPNG enhanced packet block is too short" if total_length < 32

          interface_id = unpack_u32(bytes.byteslice(offset + 8, 4), endian)
          captured_length = unpack_u32(bytes.byteslice(offset + 20, 4), endian)
          original_length = unpack_u32(bytes.byteslice(offset + 24, 4), endian)
          interface = interfaces[interface_id]
          raise "PCAPNG enhanced packet references an unknown interface" unless interface
          snaplen = interface.fetch("snaplen")
          raise "PCAPNG enhanced packet captured length must be positive" unless captured_length.positive?
          raise "PCAPNG enhanced packet original length must be positive" unless original_length.positive?
          raise "PCAPNG captured length exceeds snaplen" if captured_length > snaplen
          raise "PCAPNG captured length exceeds original length" if captured_length > original_length
          minimum_length = 32 + padded_u32_length(captured_length)
          raise "PCAPNG enhanced packet payload is truncated" if total_length < minimum_length
          payload = bytes.byteslice(offset + 28, captured_length)
          validate_packet_payload!(payload, interface.fetch("link_type"), interface.fetch("minimum"), "PCAPNG enhanced")
          validate_pcapng_options!(bytes, offset + minimum_length - 4, total_length - minimum_length, endian)
          packet_count += 1
        when 0x00000003 # Simple Packet Block
          raise "PCAPNG simple packet block is too short" if total_length < 16
          raise "PCAPNG simple packet requires interface zero" if interfaces.empty?

          original_length = unpack_u32(bytes.byteslice(offset + 8, 4), endian)
          interface = interfaces.first
          raise "PCAPNG simple packet original length must be positive" unless original_length.positive?
          captured_length = [original_length, interface.fetch("snaplen")].min
          raise "PCAPNG simple packet captured length must be positive" unless captured_length.positive?
          expected_length = 16 + padded_u32_length(captured_length)
          raise "PCAPNG simple packet block length is inconsistent" unless total_length == expected_length
          payload = bytes.byteslice(offset + 12, captured_length)
          validate_packet_payload!(payload, interface.fetch("link_type"), interface.fetch("minimum"), "PCAPNG simple")
          packet_count += 1
        end
      end
      offset += total_length
    end
    raise "PCAPNG contains no section header" unless section_seen
    raise "PCAPNG contains no enhanced or simple packet blocks" unless packet_count.positive?
    raise "PCAPNG contains trailing bytes" unless offset == bytes.bytesize

    {"format" => "pcapng", "packet_count" => packet_count, "bytes" => bytes.bytesize}
  end

  def validate_pcapng_block!(bytes, offset, total_length, endian, minimum:)
    unless total_length.is_a?(Integer) && total_length >= minimum && (total_length % 4).zero?
      raise "PCAPNG block length is invalid"
    end
    raise "PCAPNG block is truncated" if total_length > bytes.bytesize - offset

    trailer = unpack_u32(bytes.byteslice(offset + total_length - 4, 4), endian)
    raise "PCAPNG block length trailer does not match" unless trailer == total_length
  end

  def validate_pcapng_options!(bytes, offset, length, endian)
    return if length.zero?
    raise "PCAPNG options area is not 32-bit aligned" unless (length % 4).zero?

    finish = offset + length
    cursor = offset
    end_seen = false
    while cursor < finish
      raise "PCAPNG option header is truncated" if finish - cursor < 4

      code = unpack_u16(bytes.byteslice(cursor, 2), endian)
      option_length = unpack_u16(bytes.byteslice(cursor + 2, 2), endian)
      cursor += 4
      padded = padded_u32_length(option_length)
      raise "PCAPNG option payload is truncated" if padded > finish - cursor

      cursor += padded
      if code.zero?
        raise "PCAPNG end-of-options length must be zero" unless option_length.zero?
        raise "PCAPNG bytes follow end-of-options" unless cursor == finish
        end_seen = true
      elsif end_seen
        raise "PCAPNG option follows end-of-options"
      end
    end
    raise "PCAPNG options area lacks an end-of-options marker" unless end_seen
  end

  def unpack_u16(bytes, endian)
    raise "packet capture integer is truncated" unless bytes&.bytesize == 2

    bytes.unpack1(endian == :little ? "v" : "n")
  end

  def unpack_u32(bytes, endian)
    raise "packet capture integer is truncated" unless bytes&.bytesize == 4

    bytes.unpack1(endian == :little ? "V" : "N")
  end

  # Keep the capture corpus honest: a record must carry a non-empty packet,
  # use a link type we can interpret, and contain at least that link's fixed
  # header.  Raw-IP captures get an additional version/header-length check.
  def packet_link_minimum(link_type)
    minima = {
      0 => 4,    # DLT_NULL
      1 => 14,   # DLT_EN10MB
      6 => 14,   # DLT_IEEE802
      9 => 2,    # DLT_PPP
      101 => 20, # DLT_RAW (IPv4 minimum; IPv6 is checked below)
      105 => 10, # DLT_IEEE802_11 control minimum
      108 => 4,  # DLT_LOOP
      113 => 16, # DLT_LINUX_SLL
      127 => 8,  # DLT_IEEE802_11_RADIO base header
      228 => 20, # DLT_IPV4
      229 => 40, # DLT_IPV6
      276 => 20 # DLT_LINUX_SLL2
    }
    minima.fetch(Integer(link_type)) { raise "unsupported packet link type #{link_type}" }
  end

  def validate_packet_payload!(payload, link_type, minimum, label)
    value = payload.to_s.b
    raise "#{label} packet payload is truncated" if value.bytesize < minimum

    case Integer(link_type)
    when 101
      version = value.getbyte(0) >> 4
      if version == 4
        header_length = (value.getbyte(0) & 0x0f) * 4
        raise "#{label} raw IPv4 header is invalid" if header_length < 20 || header_length > value.bytesize
      elsif version == 6
        raise "#{label} raw IPv6 packet is truncated" if value.bytesize < 40
      else
        raise "#{label} raw IP version is invalid"
      end
    when 228
      first = value.getbyte(0)
      raise "#{label} IPv4 link type has an invalid version" unless first && (first >> 4) == 4
      header_length = (first & 0x0f) * 4
      raise "#{label} IPv4 header is invalid" if header_length < 20 || header_length > value.bytesize
    when 229
      raise "#{label} IPv6 link type has an invalid version" unless (value.getbyte(0) >> 4) == 6
    when 127
      radiotap_length = value.byteslice(2, 2)&.unpack1("v")
      raise "#{label} radiotap header is invalid" unless radiotap_length && radiotap_length >= 8 && radiotap_length <= value.bytesize
    end
    true
  end

  def padded_u32_length(length)
    (Integer(length) + 3) & ~3
  end

  def packet_capture_format(path)
    parse_packet_capture(path).fetch("format")
  rescue StandardError
    nil
  end

  # Materialize a packet trace referenced by a report. Reports are produced
  # by an external process and may therefore contain an absolute temporary
  # path. That path is never accepted by the M4 gate; it is replaced by a
  # bundle-relative path and all content-addressed fields are recomputed.
  def materialize_packet_trace!(report_path, bundle_directory:, basename:, max_bytes: MAX_EXTERNAL_ARTIFACT_BYTES)
    document = json_document(report_path)
    packet = document.dig("kernel_observation", "packet_trace")
    return false unless packet.is_a?(Hash)

    source_path = packet["path"] || packet["capture_path"]
    return false unless source_path.is_a?(String) && !source_path.empty?

    format = packet["format"].to_s.downcase
    raise "packet trace format must be pcap or pcapng" unless %w[pcap pcapng].include?(format)
    destination = File.join(bundle_directory, "#{basename}.#{format}")
    copied = copy_external_artifact(source_path, destination, max_bytes: max_bytes)
    parsed = parse_packet_capture(copied.fetch("path"))
    actual_format = parsed.fetch("format")
    raise "packet trace bytes are not a valid #{format} capture" unless actual_format == format
    reported_packet_count = packet["packet_count"]
    unless reported_packet_count.is_a?(Integer) && reported_packet_count.positive? &&
           reported_packet_count == parsed.fetch("packet_count")
      raise "packet trace packet_count does not match parsed capture records"
    end

    relative = copied.fetch("path").delete_prefix("#{File.expand_path(bundle_directory)}/")
    packet["path"] = relative
    packet["capture_path"] = relative if packet.key?("capture_path")
    packet["artifact_path"] = relative
    packet["materialized"] = true
    packet["format"] = actual_format
    packet["bytes"] = copied.fetch("bytes")
    packet["size"] = copied.fetch("bytes")
    packet["sha256"] = copied.fetch("sha256")
    packet["parsed_packet_count"] = parsed.fetch("packet_count")
    packet["parser"] = "rubernetes-m4-packet-capture-v1"
    document["report_sha256"] = canonical_document_digest(document, excluded_keys: ["report_sha256"])
    write_json(report_path, document)
    copied.merge("report_path" => report_path, "report_sha256" => document.fetch("report_sha256"))
  end

  def canonical_document_digest(document, excluded_keys: [])
    # Keep this helper independent of M4Gate so evidence capture can be used
    # before the gate has loaded its full cumulative dependency chain.
    canonical = lambda do |value, excluded = []|
      case value
      when Hash
        keys = value.keys.map(&:to_s).reject { |key| excluded.map(&:to_s).include?(key) }.sort
        keys.each_with_object({}) do |key, output|
          original = value.keys.find { |candidate| candidate.to_s == key }
          output[key] = canonical.call(value.fetch(original), [])
        end
      when Array then value.map { |child| canonical.call(child, []) }
      else value
      end
    end
    Digest::SHA256.hexdigest(JSON.generate(canonical.call(document, excluded_keys)))
  end

  def run_command(name, command, destination_path, input, env_prefix:)
    started_at = now
    environment = {
      "#{env_prefix}_INPUT_SHA256" => input.fetch("sha256"),
      "#{env_prefix}_INPUT_FILE_COUNT" => input.fetch("file_count").to_s
    }
    stdout, stderr, status = Open3.capture3(environment, *command, chdir: ROOT)
    File.binwrite(destination_path, stdout)
    command_record(name, command, started_at, now, status.exitstatus || 1,
                   stdout: stdout, stderr: stderr)
  rescue SystemCallError => error
    command_record(name, command, started_at, now, 127,
                   error: "adapter command could not be executed: #{error.message}")
  end

  def run_gate(name, gate_path, manifest_path, relative_manifest)
    started_at = now
    stdout, stderr, status = Open3.capture3(RbConfig.ruby, gate_path, manifest_path, chdir: ROOT)
    result_path = File.join(File.dirname(manifest_path), "gate-result.json")
    File.binwrite(result_path, stdout)
    record = command_record(name, [RbConfig.ruby, gate_path.delete_prefix("#{ROOT}/"), relative_manifest],
                            started_at, now, status.exitstatus || 1, stdout: stdout, stderr: stderr)
    [record, result_path, status.success?]
  rescue SystemCallError => error
    result_path = File.join(File.dirname(manifest_path), "gate-result.json")
    File.binwrite(result_path, JSON.generate({"schema_version" => 1, "milestone" => name.sub(/_gate\z/, ""), "passed" => false, "errors" => [error.message]}))
    [command_record(name, [RbConfig.ruby, gate_path, manifest_path], started_at, now, 127,
                    error: "gate could not be executed: #{error.message}"), result_path, false]
  end

  def json_document(path)
    JSON.parse(File.binread(path), max_nesting: 512)
  end

  # Copy a complete prior bundle, rerun its gate, and return references for all
  # milestones carried by that bundle.  The copied subtree remains immutable
  # evidence; only its freshly generated gate-result.json is added.
  def copy_prior_bundle(source_manifest, destination, gate_path, gate_name, gate_module, commands)
    source_manifest = File.realpath(source_manifest)
    source_directory = File.dirname(source_manifest)
    copy_tree(source_directory, destination)
    basename = File.basename(source_manifest)
    copied_manifest = File.join(destination, basename)
    # The relative command path is informational; the gate receives an
    # absolute path so a bundle outside the project remains verifiable.
    command, gate_result_path, passed = run_gate(gate_name, gate_path, copied_manifest,
                                                 copied_manifest.delete_prefix("#{ROOT}/"))
    commands << command
    document = json_document(copied_manifest)
    references = {}
    references[gate_name.sub(/_gate\z/, "")] = {
      "manifest_path" => copied_manifest.delete_prefix("#{File.dirname(File.dirname(destination))}/").sub(%r{\A/}, ""),
      "manifest_sha256" => Digest::SHA256.file(copied_manifest).hexdigest,
      "gate_result_path" => gate_result_path.delete_prefix("#{File.dirname(File.dirname(destination))}/").sub(%r{\A/}, ""),
      "gate_result_sha256" => Digest::SHA256.file(gate_result_path).hexdigest,
      "input_sha256" => document["input_sha256"],
      "input_file_count" => document["input_file_count"],
      "gate_passed" => passed
    }
    prior = document["prior_milestones"]
    if prior.is_a?(Hash)
      prior.each do |milestone, reference|
        next unless reference.is_a?(Hash)

        references[milestone] = reference.merge(
          "manifest_path" => File.join(File.basename(destination), reference.fetch("manifest_path")),
          "gate_result_path" => File.join(File.basename(destination), reference.fetch("gate_result_path"))
        )
      end
    end
    [document, references]
  end

  def references_from_prior(document, prefix)
    references = {}
    prior = document["prior_milestones"]
    return references unless prior.is_a?(Hash)

    prior.each do |milestone, reference|
      next unless reference.is_a?(Hash)

      references[milestone] = reference.merge(
        "manifest_path" => File.join(prefix, reference.fetch("manifest_path")),
        "gate_result_path" => File.join(prefix, reference.fetch("gate_result_path"))
      )
    end
    references
  end

  def prefixed_reference(reference, prefix)
    return nil unless reference.is_a?(Hash)

    reference.merge(
      "manifest_path" => File.join(prefix, reference.fetch("manifest_path")),
      "gate_result_path" => File.join(prefix, reference.fetch("gate_result_path"))
    )
  end

  def artifact_entries(directory, excluded: ["manifest.json"])
    Dir.glob(File.join(directory, "**/*"), File::FNM_DOTMATCH).select do |path|
      File.file?(path) && !excluded.include?(path.delete_prefix("#{directory}/"))
    end.sort.map do |path|
      {"path" => path.delete_prefix("#{directory}/"),
       "sha256" => Digest::SHA256.file(path).hexdigest,
       "bytes" => File.size(path)}
    end
  end

  # An operator waiver of the M4 kernel release requirement is recorded in
  # the manifest, never inferred: it names the requirement, the reason, and
  # the host kernel so the gate and every reader see exactly what was relaxed.
  KERNEL_WAIVER_ENV = "RUBERNETES_M4_KERNEL_WAIVER_REASON".freeze
  KERNEL_WAIVER_REQUIREMENT = "linux>=6.12".freeze

  def kernel_waivers(environment = ENV)
    reason = environment[KERNEL_WAIVER_ENV].to_s.strip
    return [] if reason.empty?

    [{
      "requirement" => KERNEL_WAIVER_REQUIREMENT,
      "scope" => "m4-kernel-release",
      "reason" => reason,
      "host_kernel" => Etc.uname.fetch(:release),
      "waived_at" => now
    }]
  end

  def host_identity
    uname = Etc.uname
    {
      "architecture" => RbConfig::CONFIG.fetch("host_cpu").sub("amd64", "x86_64").sub("arm64", "aarch64"),
      "kernel" => uname.fetch(:release),
      "sysname" => uname.fetch(:sysname),
      "ruby" => RUBY_DESCRIPTION
    }
  end

  def write_json(path, value)
    File.write(path, JSON.pretty_generate(value) << "\n")
  end
end
