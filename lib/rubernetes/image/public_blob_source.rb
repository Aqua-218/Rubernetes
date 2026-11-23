# frozen_string_literal: true

require_relative "../platform/linux/openat2"
require_relative "digest"
require_relative "errors"
require_relative "reference"
require_relative "strict_json"

module Rubernetes
  module Image
    # An administrator-provisioned source of public OCI blobs. A file is
    # eligible only for an explicitly listed upstream platform manifest.
    # The puller still resolves that manifest and authorizes the blob online.
    class PublicBlobSource
      OpenAt = ::Rubernetes::Platform::Linux::Openat2
      SOURCE_LIST_LIMIT = 1024 * 1024

      def initialize(path, scratch: [])
        source = File.realpath(path)
        overlap = scratch.any? do |work|
          work = canonical_directory(File.expand_path(work))
          source == work || source.start_with?(File.join(work, "")) || work.start_with?(File.join(source, ""))
        end
        raise StoreError, "public blob source must be separate from writable scratch directories" if overlap

        @reader = OpenAt.new(root: source)
        document = open_regular("sources.json") { |input| input.read(SOURCE_LIST_LIMIT + 1) }
        entries = StrictJSON.parse(document, max_bytes: SOURCE_LIST_LIMIT)
        raise StoreError, "public blob source must list pinned manifests" unless entries.is_a?(Array)

        @references = entries.to_h do |entry|
          reference = Reference.parse(entry)
          raise StoreError, "public blob source references require a digest and no tag" unless reference.digest && reference.tag.nil?

          [reference.to_s, true]
        end.freeze
      rescue StandardError
        @reader&.close
        raise
      end

      def blob(reference, descriptor)
        return unless @references.key?(reference.to_s)

        digest = Digest.parse(descriptor.digest)
        open_regular("blobs/#{digest.algorithm}/#{digest.hex}", size: descriptor.size)
      rescue Rubernetes::Platform::Linux::Error => error
        raise unless error.errno == Errno::ENOENT::Errno

        nil
      end

      private

      def canonical_directory(path)
        File.realpath(path)
      rescue Errno::ENOENT
        File.join(canonical_directory(File.dirname(path)), File.basename(path))
      end

      def open_regular(path, size: nil)
        handle = @reader.open(path, flags: OpenAt::O_RDONLY | File::NONBLOCK | OpenAt::O_NOFOLLOW)
        input = IO.for_fd(handle.fd, "rb")
        stat = input.stat
        raise StoreError, "public blob source contains a non-regular file" unless stat.file?
        raise StoreError, "public blob source size differs from the upstream descriptor" if size && stat.size != size

        return yield input if block_given?

        transferred = true
        input
      ensure
        input&.close unless transferred
      end
    end
  end
end
