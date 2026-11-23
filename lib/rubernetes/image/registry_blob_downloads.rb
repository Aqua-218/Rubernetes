# frozen_string_literal: true

require "tempfile"
require_relative "content_store"
require_relative "verified_download"

module Rubernetes
  module Image
    module RegistryBlobDownloads
      # Keep the local public source independent of in-process cache trust.
      # Require a fresh upstream authorization for this exact manifest blob.
      def public_blob_source_allowed?(reference)
        return false if @username || @password || @bearer_token || @allow_insecure || endpoint.scheme != "https"

        registry = normalize_reference(reference).registry
        registry = RegistryClient::DOCKER_HUB_ENDPOINT if RegistryClient::DOCKER_HUB_ALIASES.include?(registry)
        expected = URI("https://#{registry}")
        expected.host == endpoint.host && expected.port == endpoint.port && !public_blob_loopback?(endpoint.hostname)
      end

      def authorize_public_blob(reference, descriptor)
        return false unless public_blob_source_allowed?(reference) && descriptor.size <= @max_blob_bytes

        validate_blob_request!(descriptor.size, descriptor.media_type)
        authorized_cached_blob?(reference, descriptor)
      rescue RegistryError
        false # The ordinary verified GET can still succeed.
      end

      # Returns the verified blob, rewound. The caller owns the temporary file.
      def download_blob(ref_or_digest, digest = nil, expected_size: nil, media_type: nil, handoff: false)
        temporary = Tempfile.new(["rubernetes-blob", ".part"])
        temporary.binmode
        stream_verified_blob(ref_or_digest, digest, io: temporary, expected_size: expected_size, media_type: media_type)
        temporary.flush
        if handoff
          handoff = handoff_verified_download(temporary, ref_or_digest, digest, expected_size)
          transferred = true
          return handoff
        end

        temporary.rewind
        transferred = true
        temporary
      ensure
        temporary&.close! unless transferred
      end

      def handoff_verified_download(temporary, ref_or_digest, digest, expected_size)
        _reference, blob_digest = normalize_blob_arguments(ref_or_digest, digest)
        input = File.open(temporary.path, File::RDONLY | File::NOFOLLOW)
        raise RegistryError, "verified download changed before handoff" unless File.identical?(input, temporary)

        expected_bytes = expected_size && Integer(expected_size)
        raise RegistryError, "verified download size changed before handoff" if expected_bytes && input.stat.size != expected_bytes

        temporary.close!
        raise RegistryError, "verified download retained a named link" unless input.stat.nlink.zero?

        handoff = VerifiedDownload.send(:issue, input, digest: blob_digest, size: input.stat.size)
        transferred = true
        handoff
      ensure
        input&.close unless transferred
        temporary&.close! unless transferred
      end
      private :handoff_verified_download

      def store_blob(reference, descriptor, store:)
        return copy_download_to_store(reference, descriptor, store) unless instance_of?(RegistryClient) && store.instance_of?(ContentStore)

        options = {expected_size: descriptor.size, media_type: descriptor.media_type, max_bytes: [@max_blob_bytes, store.max_blob_bytes].min}
        validate_blob_request!(descriptor.size, descriptor.media_type)
        source = blob_source(reference)
        cached = store.synchronize_download(descriptor.digest) do
          existing = store.verified_path(descriptor.digest, size: descriptor.size)
          next existing if existing

          path = store.write_blob(descriptor.digest, size: descriptor.size) do |file|
            stream_verified_blob(reference, descriptor.digest, io: file, **options)
          end
          store.remember_download(descriptor.digest, source)
          return path
        end
        unless store.downloaded_from?(descriptor.digest, source) && authorized_cached_blob?(reference, descriptor)
          stream_verified_blob(reference, descriptor.digest, io: nil, **options)
          store.remember_download(descriptor.digest, source)
        end
        cached
      end

      def store_config(reference, descriptor, store:)
        limit = RegistryClient::DEFAULT_MAX_CONFIG_BYTES
        raise LimitError, "image config exceeds the configured byte limit" if descriptor.size > limit

        path = store_blob(reference, descriptor, store: store)
        bytes = File.binread(path, limit + 1).to_s.b
        raise LimitError, "image config exceeds the configured byte limit" if bytes.bytesize > limit
        raise StoreError, "content blob size does not match the descriptor" unless bytes.bytesize == descriptor.size

        descriptor.digest.verify_bytes!(bytes)
        [bytes, path]
      end

      private

      def public_blob_loopback?(host)
        host.casecmp?("localhost") || IPAddr.new(host).loopback?
      rescue IPAddr::InvalidAddressError
        false # Ordinary DNS names are not loopback literals.
      end

      # Registry, repository and credentials all participate in an access
      # proof. A new source must supply the bytes even if it claims the hash.
      def blob_source(reference)
        credentials = ::Digest::SHA256.digest(Marshal.dump([@username, @password, @bearer_token]))
        [endpoint.to_s, normalize_reference(reference).repository, credentials, @blob_cache_trust]
      end

      def copy_download_to_store(reference, descriptor, store)
        temporary = fetch_blob_to_temp(reference, descriptor)
        store.put(descriptor.digest, io: temporary, size: descriptor.size, media_type: descriptor.media_type)
      ensure
        temporary&.close!
      end

      # Renew proof from a source that already supplied these bytes. Use a
      # verified GET when the registry cannot confirm the descriptor via HEAD.
      def authorized_cached_blob?(reference, descriptor)
        image_reference = normalize_reference(reference)
        path = "/v2/#{image_reference.repository}/blobs/#{descriptor.digest}"
        response = request("HEAD", path, accept: descriptor.media_type || "application/octet-stream",
                                         scope: "repository:#{image_reference.repository}:pull", max_bytes: @max_manifest_bytes)
        return false unless response.status == 200 && response["docker-content-digest"] == descriptor.digest.to_s
        return false unless Integer(response["content-length"], 10, exception: false) == descriptor.size

        validate_response_media_type!(descriptor.media_type, response["content-type"])
        true
      rescue AuthenticationError
        false
      end

      def stream_verified_blob(ref_or_digest, digest, io:, expected_size:, media_type:, max_bytes: @max_blob_bytes)
        image_reference, blob_digest = normalize_blob_arguments(ref_or_digest, digest)
        validate_blob_request!(expected_size, media_type)
        raise LimitError, "registry blob exceeds the configured byte limit" if expected_size && Integer(expected_size) > max_bytes

        path = "/v2/#{image_reference.repository}/blobs/#{blob_digest}"
        digest_state = ::Digest::SHA256.new
        bytes = 0
        rewind = lambda do
          io&.truncate(0)
          io&.rewind
          digest_state.reset
          bytes = 0
        end
        response = stream_request(
          "GET", path,
          accept: media_type || "application/octet-stream",
          scope: "repository:#{image_reference.repository}:pull",
          max_bytes: max_bytes,
          on_retry: rewind
        ) do |chunk|
          chunk = chunk.to_s.b
          bytes += chunk.bytesize
          raise LimitError, "registry blob exceeds the configured byte limit" if bytes > max_bytes

          digest_state.update(chunk)
          io&.write(chunk)
        end
        ensure_success!(response, "GET #{path}")
        raise RegistryError, "registry blob size does not match the descriptor" if expected_size && bytes != Integer(expected_size)

        verify_stream_digest!(digest_state, blob_digest, response["docker-content-digest"])
        validate_response_media_type!(media_type, response["content-type"])
      rescue ArgumentError, TypeError => error
        raise RegistryError.new("invalid registry blob size: #{error.message}", cause: error), cause: error
      end
    end
  end
end
