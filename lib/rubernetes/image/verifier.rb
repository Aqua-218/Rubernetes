# frozen_string_literal: true

require "digest"
require "json"

require_relative "digest"
require_relative "errors"

module Rubernetes
  module Image
    # Verifies the pinned image identity handed to the runtime before any
    # workspace effect (spec/node/runtime.md §5.8.5).  A resolved image is
    # accepted only when the raw manifest bytes hash to the pinned digest and
    # the sandbox-level aggregate digest is the canonical aggregate of those
    # per-image digests.  A digest string alone is never sufficient.
    class PinnedImageVerifier
      def verify(image:, digest:, bytes: nil)
        return Digest.parse(digest).verify_bytes!(bytes) && true if bytes

        input = image.respond_to?(:to_h) ? image.to_h : {}
        resolved = Array(input["resolved_images"] || input[:resolved_images])
        raise DigestMismatch, "no resolved images to verify" if resolved.empty?

        digests = resolved.map { |entry| verify_resolved_image(entry) }.uniq.sort
        aggregate = "sha256:#{::Digest::SHA256.hexdigest(JSON.generate(digests))}"
        expected = String(digest).downcase
        unless secure_compare(aggregate, expected)
          raise DigestMismatch, "aggregate image digest mismatch: expected #{expected}, got #{aggregate}"
        end

        true
      end

      private

      def verify_resolved_image(entry)
        value = entry.respond_to?(:to_h) ? entry.to_h.each_with_object({}) { |(key, child), result| result[String(key)] = child } : {}
        pinned = Digest.parse(value["digest"])
        raw = value["manifest_raw"]
        raise DigestMismatch, "resolved image #{pinned} carries no raw manifest bytes" unless raw.is_a?(String) && !raw.empty?

        pinned.verify_bytes!(raw.b)
        rootfs = value["rootfs"]
        if rootfs && !(File.directory?(rootfs) && !File.symlink?(rootfs))
          raise DigestMismatch, "resolved image #{pinned} rootfs is not a directory: #{rootfs}"
        end
        pinned.to_s
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
    end
  end
end
