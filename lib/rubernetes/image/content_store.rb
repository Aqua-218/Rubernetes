# frozen_string_literal: true

require "digest"
require "fileutils"
require "securerandom"
require "stringio"

require_relative "../support/secure_compare"
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
        @downloads = {}
        @verified_sources = {}
        @downloads_mutex = Mutex.new
        FileUtils.mkdir_p(@root, mode: 0o700)
        ensure_directory!(@root)
      rescue ArgumentError, TypeError, SystemCallError => error
        raise StoreError.new("cannot initialize content store: #{error.message}", cause: error), cause: error
      end

      def path(digest)
        parsed = Digest.parse(digest)
        directory = File.join(root, parsed.algorithm)
        File.join(directory, parsed.hex)
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
        raise StoreError, "provide either blob data or an IO, not both" if !data.nil? && !io.nil?

        cached = verified_path(digest, size: size)
        return cached if cached

        source = io || StringIO.new(data.to_s.b)
        write_blob(digest, size: size) { |file| copy_source(source, file) }
      end

      def put_stream(digest, io, size: nil, media_type: nil)
        put(digest, io: io, size: size, media_type: media_type)
      end
      alias put_blob put

      # Only one pull stages a missing digest in this store at a time. Other
      # pulls verify the resulting entry and prove access with their own client.
      def synchronize_download(digest)
        key = Digest.parse(digest).to_s
        current = nil
        @downloads_mutex.synchronize do
          while (download = @downloads[key])
            download.wait(@downloads_mutex)
          end
          @downloads[key] = current = ConditionVariable.new
        end
        yield
      ensure
        @downloads_mutex.synchronize { @downloads.delete(key).broadcast } if current
      end

      def downloaded_from?(digest, source)
        @downloads_mutex.synchronize { @verified_sources[digest.to_s] == source }
      end

      def remember_download(digest, source)
        @downloads_mutex.synchronize { @verified_sources[digest.to_s] = source }
      end

      # Return a verified local blob, or nil when it is absent. Callers still
      # have to prove they may read the blob from the registry they requested.
      def verified_path(digest, size: nil)
        parsed = Digest.parse(digest)
        blob_path = path(parsed)
        directory = File.dirname(blob_path)
        return unless File.lstat(directory).directory?
        raise StoreError, "content store destination is not a regular file" unless File.lstat(blob_path).file?

        bytes = verify_file!(blob_path, parsed)
        raise StoreError, "existing content blob size does not match the descriptor" if size && bytes != Integer(size)

        blob_path
      rescue Errno::ENOENT
        nil
      rescue ArgumentError, TypeError => error
        raise StoreError.new("invalid content blob size: #{error.message}", cause: error), cause: error
      end

      # The writer owns only an unpublished file on this filesystem. Publish
      # it after the returned bytes pass the store's own size and digest checks.
      def write_blob(digest, size: nil)
        parsed = Digest.parse(digest)
        expected_size = Integer(size) if size
        raise LimitError, "content blob exceeds the configured byte limit" if expected_size && expected_size > max_blob_bytes

        destination = path(parsed)
        directory = File.dirname(destination)
        FileUtils.mkdir_p(directory, mode: 0o700)
        ensure_directory!(directory)
        temporary = File.join(directory, ".#{parsed.hex}.#{Process.pid}.#{SecureRandom.hex(12)}.tmp")
        created = false
        File.open(temporary, File::RDWR | File::CREAT | File::EXCL, 0o600) do |file|
          created = true
          file.binmode
          yield file
          verify_staging!(file, parsed, expected_size)
        end
        publish_blob(temporary, destination, parsed, expected_size)
        File.unlink(temporary)
        created = false
        if @fsync_directory
          fsync_directory(directory)
          fsync_directory(root)
        end
        destination
      rescue ArgumentError, TypeError => error
        raise StoreError.new("invalid content blob size: #{error.message}", cause: error), cause: error
      rescue IOError, SystemCallError => error
        raise StoreError.new("cannot store content blob #{digest}: #{error.message}", cause: error), cause: error
      ensure
        FileUtils.rm_f(temporary) if created
      end

      def delete(digest)
        blob_path = path(digest)
        return false unless File.file?(blob_path) && !File.symlink?(blob_path)

        File.unlink(blob_path)
        @downloads_mutex.synchronize { @verified_sources.delete(digest.to_s) }
        fsync_directory(File.dirname(blob_path)) if @fsync_directory
        true
      rescue SystemCallError => error
        raise StoreError.new("cannot delete content blob #{digest}: #{error.message}", cause: error), cause: error
      end

      private

      def copy_source(source, file)
        bytes = 0
        loop do
          chunk = source.read(CHUNK_BYTES)
          break if chunk.nil? || chunk.empty?

          chunk = chunk.to_s.b
          bytes += chunk.bytesize
          raise LimitError, "content blob exceeds the configured byte limit" if bytes > max_blob_bytes

          file.write(chunk)
        end
      end

      def verify_staging!(file, digest, expected_size)
        file.flush
        raise StoreError, "content blob size does not match the descriptor" if expected_size && file.stat.size != expected_size

        file.rewind
        digest.verify_io!(file, max_bytes: max_blob_bytes)
        file.chmod(0o444)
        file.fsync
      end

      def publish_blob(temporary, destination, digest, size)
        # A hard link creates the canonical name without replacing either a
        # concurrent writer's result or an unexpected file at that location.
        File.link(temporary, destination)
      rescue Errno::EEXIST
        return if verified_path(digest, size: size)

        File.link(temporary, destination)
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

      def secure_compare(left, right) = SecureCompare.call(left, right)
    end

    ContentAddressableStore = ContentStore
    BlobStore = ContentStore
  end
end
