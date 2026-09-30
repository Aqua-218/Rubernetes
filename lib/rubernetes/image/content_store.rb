# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"
require "stringio"

require_relative "digest"
require_relative "errors"

module Rubernetes
  module Image
    # Filesystem content-addressable store for OCI blobs. A blob becomes visible
    # only after its contents, digest, and durable directory entry are complete.
    class ContentStore
      DEFAULT_MAX_BLOB_BYTES = 20 * 1024 * 1024 * 1024
      CHUNK_BYTES = 1024 * 1024

      attr_reader :root, :max_blob_bytes

      def initialize(root, max_blob_bytes: DEFAULT_MAX_BLOB_BYTES, fsync_directory: true)
        @root = File.expand_path(root.to_s)
        raise StoreError, "content store root must be a non-empty path" if root.to_s.empty?

        @max_blob_bytes = Integer(max_blob_bytes)
        raise StoreError, "content store blob limit must be positive" unless @max_blob_bytes.positive?

        @fsync_directory = !!fsync_directory
        FileUtils.mkdir_p(@root, mode: 0o700)
        ensure_directory!(@root)
      rescue ArgumentError, TypeError, SystemCallError => error
        raise StoreError.new("cannot initialize content store: #{error.message}", cause: error), cause: error
      end

      def path(digest)
        parsed = Digest.parse(digest)
        directory = File.join(root, parsed.algorithm)
        File.join(directory, parsed.hex)
      rescue DigestError => error
        raise error
      end

      def include?(digest, verify: false)
        blob_path = path(digest)
        return false unless File.file?(blob_path) && !File.symlink?(blob_path)
        return true unless verify

        verify_file!(blob_path, Digest.parse(digest))
        true
      rescue Errno::ENOENT
        false
      end
      alias exist? include?
      alias contains? include?

      def fetch(digest, verify: true)
        parsed = Digest.parse(digest)
        blob_path = path(parsed)
        raise StoreError, "content blob is not present: #{parsed}" unless File.file?(blob_path) && !File.symlink?(blob_path)

        verify_file!(blob_path, parsed) if verify
        File.binread(blob_path)
      rescue DigestError => error
        raise StoreError.new(error.message, cause: error), cause: error
      rescue SystemCallError => error
        raise StoreError.new("cannot read content blob #{digest}: #{error.message}", cause: error), cause: error
      end
      alias read fetch
      alias get_blob fetch

      # Stores a String or IO under its verified digest and returns the durable path.
      def put(digest, data = nil, io: nil, size: nil, media_type: nil)
        parsed = Digest.parse(digest)
        raise StoreError, "provide either blob data or an IO, not both" if !data.nil? && !io.nil?

        source = io || StringIO.new(data.to_s.b)
        store_stream(parsed, source, expected_size: size, media_type: media_type)
      rescue DigestError => error
        raise error
      rescue IOError, SystemCallError => error
        raise StoreError.new("cannot store content blob #{digest}: #{error.message}", cause: error), cause: error
      end

      def put_stream(digest, io, size: nil, media_type: nil)
        put(digest, io: io, size: size, media_type: media_type)
      end
      alias put_blob put

      def delete(digest)
        blob_path = path(digest)
        return false unless File.file?(blob_path) && !File.symlink?(blob_path)

        File.unlink(blob_path)
        fsync_directory(File.dirname(blob_path)) if @fsync_directory
        true
      rescue SystemCallError => error
        raise StoreError.new("cannot delete content blob #{digest}: #{error.message}", cause: error), cause: error
      end

      private

      def store_stream(parsed, source, expected_size:, media_type:)
        directory = File.join(root, parsed.algorithm)
        FileUtils.mkdir_p(directory, mode: 0o700)
        ensure_directory!(directory)
        destination = File.join(directory, parsed.hex)

        if File.file?(destination) && !File.symlink?(destination)
          verify_file!(destination, parsed)
          if expected_size && File.size(destination) != Integer(expected_size)
            raise StoreError, "existing content blob size does not match the descriptor"
          end

          return destination
        elsif File.exist?(destination) || File.symlink?(destination)
          raise StoreError, "content store destination is not a regular file"
        end

        temporary = File.join(directory, ".#{parsed.hex}.#{Process.pid}.#{SecureRandom.hex(12)}.tmp")
        bytes = 0
        digest = ::Digest::SHA256.new
        begin
          File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            loop do
              chunk = source.read(CHUNK_BYTES)
              break if chunk.nil? || chunk.empty?

              chunk = chunk.to_s.b
              bytes += chunk.bytesize
              raise LimitError, "content blob exceeds the configured byte limit" if bytes > max_blob_bytes

              digest.update(chunk)
              file.write(chunk)
            end
            raise StoreError, "content blob size does not match the descriptor" if expected_size && bytes != Integer(expected_size)

            actual = digest.hexdigest
            unless secure_compare(actual, parsed.hex)
              raise DigestMismatch, "content blob digest mismatch: expected #{parsed}, got sha256:#{actual}"
            end

            file.flush
            file.fsync
          end

          # A verified destination is never replaced. This protects against a
          # concurrent writer or an operator placing a corrupt file at a digest key.
          if File.exist?(destination)
            if File.file?(destination) && !File.symlink?(destination)
              verify_file!(destination, parsed)
              File.unlink(temporary)
              return destination
            end
            raise StoreError, "content store destination is not a regular file"
          end
          File.rename(temporary, destination)
          File.chmod(0o444, destination)
          fsync_directory(directory) if @fsync_directory
          destination
        rescue StandardError
          begin
            File.unlink(temporary) if File.exist?(temporary)
          rescue SystemCallError
            # Preserve the original storage failure; cleanup is best effort and
            # the uniquely named temporary file cannot become a valid blob key.
          end
          raise
        end
      rescue ArgumentError, TypeError => error
        raise StoreError.new("invalid content blob size: #{error.message}", cause: error), cause: error
      end

      def verify_file!(file_path, expected)
        digest = ::Digest::SHA256.new
        bytes = 0
        File.open(file_path, File::RDONLY | (File::Constants.const_defined?(:NOFOLLOW) ? File::Constants::NOFOLLOW : 0)) do |file|
          while (chunk = file.read(CHUNK_BYTES))
            bytes += chunk.bytesize
            raise LimitError, "content blob exceeds the configured byte limit" if bytes > max_blob_bytes

            digest.update(chunk)
          end
        end
        actual = digest.hexdigest
        return bytes if secure_compare(actual, expected.hex)

        raise StoreError, "content store blob is corrupt: expected #{expected}, got sha256:#{actual}"
      rescue SystemCallError => error
        raise StoreError.new("cannot verify content blob #{expected}: #{error.message}", cause: error), cause: error
      end

      def ensure_directory!(directory)
        stat = File.lstat(directory)
        raise StoreError, "content store path is not a directory: #{directory}" unless stat.directory? && !stat.symlink?
      rescue Errno::ENOENT => error
        raise StoreError.new("content store directory disappeared: #{directory}", cause: error), cause: error
      end

      def fsync_directory(directory)
        File.open(directory, File::RDONLY, &:fsync)
      rescue Errno::EINVAL, Errno::ENOTSUP, Errno::EOPNOTSUPP => error
        raise StoreError.new("filesystem cannot durably sync content store directory: #{directory}", cause: error), cause: error
      rescue SystemCallError => error
        raise StoreError.new("cannot sync content store directory: #{directory}: #{error.message}", cause: error), cause: error
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
    end

    ContentAddressableStore = ContentStore
    BlobStore = ContentStore
  end
end
