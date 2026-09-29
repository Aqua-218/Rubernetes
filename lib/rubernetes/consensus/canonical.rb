# frozen_string_literal: true

require "digest"
require "json"

module Rubernetes
  module Consensus
    # Canonical JSON encoding shared by the WAL, snapshot, transport and
    # request fingerprints.  Keys are sorted, strings are UTF-8, and parsing
    # rejects duplicate keys, oversized documents and deep nesting so a peer
    # or a corrupted file can never smuggle an ambiguous document in.
    module Canonical
      MAX_DEPTH = 256
      DEFAULT_MAX_BYTES = 16 * 1024 * 1024

      class StrictHash < Hash
        def []=(key, value)
          raise ProtocolError, "duplicate JSON object key #{key.inspect}" if key?(key)

          super
        end
      end

      module_function

      def normalize(value, depth = 0)
        raise ProtocolError, "document nesting exceeds #{MAX_DEPTH}" if depth > MAX_DEPTH

        case value
        when Hash
          # One pass, first key wins when two keys spell the same string --
          # the same result as looking each sorted name up again, without the
          # O(keys^2) lookup that made a 60 MB snapshot take 9 s to encode.
          output = {}
          value.each do |key, child|
            name = key.to_s
            next if output.key?(name)

            output[name] = normalize(child, depth + 1)
          end
          output.size > 1 ? output.sort_by { |name, _| name }.to_h : output
        when Array then value.map { |child| normalize(child, depth + 1) }
        when Symbol then value.to_s
        when String
          # A frozen, valid UTF-8 string cannot change under the encoder, so it
          # is used as is; everything the store hands out is one.  Copying
          # every string of a snapshot doubled its transient footprint.
          return value if value.frozen? && value.encoding == Encoding::UTF_8 && value.valid_encoding?

          copy = value.dup.force_encoding(Encoding::UTF_8)
          raise ProtocolError, "string is not valid UTF-8" unless copy.valid_encoding?

          copy
        when Integer, Float, TrueClass, FalseClass, NilClass then value
        when Time then value.utc.iso8601(6)
        else
          raise ProtocolError, "unsupported value #{value.class} in canonical document"
        end
      end

      def encode(value)
        JSON.generate(normalize(value))
      end

      def decode(bytes, max_bytes: DEFAULT_MAX_BYTES)
        raise ProtocolError, "document exceeds #{max_bytes} bytes" if bytes.bytesize > max_bytes

        JSON.parse(bytes, object_class: StrictHash, max_nesting: MAX_DEPTH)
      rescue JSON::ParserError => error
        raise ProtocolError, "invalid JSON document: #{error.message}"
      end

      def digest(value)
        Digest::SHA256.hexdigest(encode(value))
      end
    end
  end
end
