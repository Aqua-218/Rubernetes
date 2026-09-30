# frozen_string_literal: true

require "digest"

module Rubernetes
  module Image
    # A validated OCI content digest. M2 intentionally accepts only SHA-256 because
    # runtime image pinning and the node specification require SHA-256 everywhere.
    class Digest
      SHA256_PATTERN = /\Asha256:([0-9a-f]{64})\z/

      attr_reader :algorithm, :hex

      def self.parse(value)
        return value if value.is_a?(self)

        text = value.to_s
        match = SHA256_PATTERN.match(text)
        raise DigestError, "image digest must be a lowercase sha256 digest" unless match

        new("sha256", match[1])
      end

      def self.from_bytes(bytes)
        new("sha256", ::Digest::SHA256.hexdigest(bytes.to_s.b))
      end

      def self.hexdigest(bytes)
        from_bytes(bytes).to_s
      end

      def self.valid?(value)
        parse(value)
        true
      rescue DigestError
        false
      end

      def initialize(algorithm, hex)
        @algorithm = algorithm.to_s
        @hex = hex.to_s
        raise DigestError, "unsupported or malformed image digest" unless @algorithm == "sha256" && @hex.match?(/\A[0-9a-f]{64}\z/)

        freeze
      end

      def to_s
        "#{algorithm}:#{hex}"
      end
      alias to_str to_s

      def ==(other)
        other = self.class.parse(other) unless other.is_a?(self.class)
        algorithm == other.algorithm && secure_compare(hex, other.hex)
      rescue DigestError
        false
      end
      alias eql? ==

      def hash
        [algorithm, hex].hash
      end

      def verify_bytes!(bytes)
        actual = ::Digest::SHA256.hexdigest(bytes.to_s.b)
        return true if secure_compare(actual, hex)

        raise DigestMismatch, "image digest mismatch: expected #{self}, got sha256:#{actual}"
      end

      def verify_io!(io, max_bytes: nil)
        digest = ::Digest::SHA256.new
        bytes = 0
        while (chunk = io.read(1024 * 1024))
          chunk = chunk.to_s.b
          bytes += chunk.bytesize
          raise LimitError, "content exceeds the configured byte limit" if max_bytes && bytes > Integer(max_bytes)

          digest.update(chunk)
        end
        actual = digest.hexdigest
        return bytes if secure_compare(actual, hex)

        raise DigestMismatch, "image digest mismatch: expected #{self}, got sha256:#{actual}"
      rescue TypeError, ArgumentError => error
        raise DigestError.new("cannot verify image digest stream: #{error.message}", cause: error), cause: error
      end

      private

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
    end
  end
end
