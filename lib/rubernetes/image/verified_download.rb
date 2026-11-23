# frozen_string_literal: true

require_relative "digest"

module Rubernetes
  module Image
    # A read-only, anonymous descriptor whose bytes were verified by the
    # built-in registry transport before the named temporary file was
    # unlinked. The digest and size are part of the handoff, so an extractor
    # cannot accidentally apply the proof to another descriptor.
    class VerifiedDownload
      attr_reader :digest, :size

      def self.issue(io, digest:, size:)
        new(io, digest: digest, size: size)
      end
      private_class_method :new, :issue

      def initialize(io, digest:, size:)
        @io = io
        @digest = Digest.parse(digest).freeze
        @size = Integer(size)
        raise ArgumentError, "verified download size must be non-negative" if @size.negative?

        freeze
      end

      def read(length = nil, buffer = nil)
        @io.read(length, buffer)
      end

      def rewind
        @io.rewind
      end

      def stat
        @io.stat
      end

      def to_io
        @io
      end

      def close!
        return false if closed?

        @io.close
        true
      rescue IOError
        false
      end

      # Readers that wrap this handoff (a plain tar layer has no decompressor
      # in between) close what they were given.
      alias close close!

      def closed?
        @io.closed?
      end
    end
  end
end
