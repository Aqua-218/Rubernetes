# frozen_string_literal: true

require "base64"
require "time"

module Rubernetes
  module Schema
    class Codec
      # Small, dependency-free CBOR implementation for the primitive values used
      # by API objects and the guest-host protocol.  Canonical mode uses shortest
      # integer/length encodings, shortest exact IEEE-754 float width, and the
      # deterministic map-key ordering from RFC 8949.
      module CBOR
        Base64Bytes = Data.define(:bytes)
        TaggedValue = Data.define(:tag, :value)

        module_function

        def encode(value, canonical: true, max_bytes: Codec::DEFAULT_MAX_BYTES,
                   max_depth: Codec::DEFAULT_MAX_DEPTH, kubernetes: false)
          encoder = Encoder.new(canonical: canonical, max_depth: max_depth, kubernetes: kubernetes)
          output = encoder.encode(value)
          Codec.validate_output!(output, max_bytes)
        rescue Codec::Error
          raise
        rescue TypeError, ArgumentError, EncodingError => error
          raise Codec::EncodeError.new("cannot encode CBOR: #{error.message}"), cause: error
        end

        def decode(input, strict: true, max_bytes: Codec::DEFAULT_MAX_BYTES,
                   max_depth: Codec::DEFAULT_MAX_DEPTH, kubernetes: false)
          Codec.validate_body!(input, max_bytes)
          parser = Decoder.new(input, strict: strict, max_depth: max_depth, kubernetes: kubernetes)
          value = parser.read
          Codec.validate_depth!(value, max_depth)
          value
        rescue Codec::Error
          raise
        rescue TypeError, ArgumentError, EncodingError => error
          raise Codec::ParseError.new("invalid CBOR: #{error.message}"), cause: error
        end

        alias dump encode
        alias load decode
        alias canonical_encode encode
        alias canonical canonical_encode
        module_function :dump, :load, :canonical_encode, :canonical

        # Shortest-exact-width encoding and strict decoding use the same IEEE 754 rules.
        module FloatWidths
          private

          def half_exact?(value)
            return true if value.zero?

            half_to_float(half_bits(value)) == value
          end

          def single_exact?(value)
            [value].pack("g").unpack1("g") == value
          end

          def half_bits(value)
            bits = [value].pack("G").unpack1("Q>")
            sign = (bits >> 63) & 0x01
            exponent = (bits >> 52) & 0x7ff
            fraction = bits & ((1 << 52) - 1)
            sign_bits = sign << 15

            return sign_bits if exponent.zero? && fraction.zero?
            return sign_bits | 0x7c00 if exponent == 0x7ff

            unbiased = exponent - 1023
            half_exponent = unbiased + 15
            if half_exponent >= 31
              sign_bits | 0x7c00
            elsif half_exponent <= 0
              shifted = fraction | (1 << 52)
              shift = 1 - half_exponent
              rounded = round_shift(shifted, 52 - 10 + shift)
              sign_bits | rounded
            else
              rounded_fraction = round_shift(fraction, 52 - 10)
              if rounded_fraction == (1 << 10)
                half_exponent += 1
                rounded_fraction = 0
              end
              if half_exponent >= 31
                sign_bits | 0x7c00
              else
                sign_bits | (half_exponent << 10) | rounded_fraction
              end
            end
          end

          def round_shift(value, shift)
            return value if shift <= 0

            truncated = value >> shift
            remainder = value & ((1 << shift) - 1)
            halfway = 1 << (shift - 1)
            truncated += 1 if remainder > halfway || (remainder == halfway && truncated.odd?)
            truncated
          end

          def half_to_float(bits)
            sign = (bits >> 15) & 0x01
            exponent = (bits >> 10) & 0x1f
            fraction = bits & 0x3ff
            sign_value = sign.zero? ? 1.0 : -1.0
            if exponent.zero?
              return sign_value * 0.0 if fraction.zero?

              sign_value * (fraction.to_f / (1 << 10)) * (2.0**-14)
            elsif exponent == 0x1f
              sign_value * Float::INFINITY
            else
              sign_value * (1.0 + (fraction.to_f / (1 << 10))) * (2.0**(exponent - 15))
            end
          end
        end

        class Encoder
          include FloatWidths

          def initialize(canonical:, max_depth:, kubernetes: false)
            @canonical = canonical
            @max_depth = max_depth
            @kubernetes = kubernetes
            @stack = {}
          end

          def encode(value, depth: 0)
            raise Codec::LimitError, "codec nesting exceeds #{@max_depth} levels" if depth > @max_depth

            case value
            when NilClass then "\xf6".b
            when FalseClass then "\xf4".b
            when TrueClass then "\xf5".b
            when Integer then encode_integer(value)
            when Float then encode_float(value)
            when String then encode_string(value)
            when Base64Bytes
              "\xD6".b + header(2, value.bytes.bytesize) + value.bytes
            when TaggedValue
              header(6, value.tag) + encode(value.value, depth: depth + 1)
            when Symbol then encode_string(value.to_s)
            when Array then encode_array(value, depth: depth)
            when Hash then encode_map(value, depth: depth)
            else
              raise Codec::UnsupportedTypeError, "unsupported CBOR value #{value.class}" unless value.respond_to?(:to_h)

              hash = value.to_h
              raise Codec::UnsupportedTypeError, "to_h for #{value.class} must return a Hash" unless hash.is_a?(Hash)

              encode_map(hash, depth: depth)

            end
          end

          private

          def encode_integer(value)
            raise Codec::EncodeError, "Kubernetes CBOR integer exceeds int64" if @kubernetes && !value.between?(-(1 << 63), (1 << 63) - 1)

            if value >= 0
              header(0, value)
            else
              header(1, -1 - value)
            end
          end

          def encode_float(value)
            raise Codec::EncodeError, "CBOR does not support non-finite Float values" unless value.finite?

            if half_exact?(value)
              "\xf9".b + [half_bits(value)].pack("n")
            elsif single_exact?(value)
              "\xfa".b + [value].pack("g")
            else
              "\xfb".b + [value].pack("G")
            end
          end

          def encode_string(value)
            string = String(value)
            if @kubernetes || string.encoding == Encoding::BINARY
              header(2, string.bytesize) + string.b
            else
              string = string.dup.force_encoding(Encoding::UTF_8)
              raise Codec::EncodeError, "CBOR text strings must be valid UTF-8" unless string.valid_encoding?

              header(3, string.bytesize) + string.b
            end
          end

          def encode_array(value, depth:)
            with_cycle_guard(value) do
              header(4, value.length) + value.map { |child| encode(child, depth: depth + 1) }.join
            end
          end

          def encode_map(value, depth:)
            with_cycle_guard(value) do
              encoded_entries = value.map do |key, child|
                encoded_key = encode(key, depth: depth + 1)
                [encoded_key, encode(child, depth: depth + 1)]
              end
              duplicate = encoded_entries.group_by(&:first).find { |_encoded, entries| entries.length > 1 }
              raise Codec::DuplicateKeyError, "CBOR map contains duplicate encoded key" if duplicate

              if @kubernetes
                @canonical ? encoded_entries.sort_by!(&:first) : encoded_entries.shuffle!
              elsif @canonical
                encoded_entries.sort_by! { |encoded_key, _encoded_value| [encoded_key.bytesize, encoded_key] }
              end
              header(5, encoded_entries.length) + encoded_entries.map { |key, child| key + child }.join
            end
          end

          def with_cycle_guard(value)
            object_id = value.object_id
            raise Codec::UnsupportedTypeError, "cyclic CBOR value graph is not supported" if @stack.key?(object_id)

            @stack[object_id] = true
            yield
          ensure
            @stack.delete(object_id)
          end

          def header(major, value)
            raise Codec::EncodeError, "CBOR length/value must be non-negative" if value.negative?
            raise Codec::EncodeError, "CBOR value exceeds uint64" if value >= (1 << 64)

            prefix = major << 5
            case value
            when 0...24 then [prefix | value].pack("C")
            when 24...(1 << 8) then [prefix | 24, value].pack("CC")
            when (1 << 8)...(1 << 16) then [prefix | 25, value].pack("Cn")
            when (1 << 16)...(1 << 32) then [prefix | 26, value].pack("CN")
            else [prefix | 27, value].pack("CQ>")
            end
          end
        end

        class Decoder
          include FloatWidths

          def initialize(input, strict:, max_depth:, kubernetes: false)
            @input = input.b
            @strict = strict
            @max_depth = max_depth
            @kubernetes = kubernetes
            @offset = 0
          end

          def read
            value = read_item(0)
            raise Codec::ParseError, "trailing bytes after CBOR value" unless @offset == @input.bytesize

            value
          end

          private

          def read_item(depth)
            raise Codec::LimitError, "codec nesting exceeds #{@max_depth} levels" if depth > @max_depth

            initial = read_byte("CBOR initial byte")
            major = initial >> 5
            additional = initial & 0x1f
            return read_indefinite(major, depth) if @kubernetes && additional == 31

            case major
            when 0 then checked_integer(read_argument(additional))
            when 1 then -1 - checked_integer(read_argument(additional))
            when 2 then byte_string(read_bytes(read_argument(additional)))
            when 3 then read_text(read_argument(additional))
            when 4 then read_array(read_argument(additional), depth: depth)
            when 5 then read_map(read_argument(additional), depth: depth)
            when 6 then read_tag(additional, depth)
            when 7 then read_simple(additional)
            else raise Codec::ParseError, "invalid CBOR major type #{major}"
            end
          end

          def checked_integer(value)
            raise Codec::ParseError, "Kubernetes CBOR integer exceeds int64" if @kubernetes && value >= (1 << 63)

            value
          end

          def byte_string(bytes)
            return bytes unless @kubernetes

            bytes.force_encoding(Encoding::UTF_8).scrub
          end

          def read_tag(additional, depth)
            raise Codec::ParseError, "CBOR tags are not supported" unless @kubernetes

            tag = read_argument(additional)
            case tag
            when 2, 3
              raise Codec::ParseError, "CBOR bignums are not supported"
            when 21, 22, 23
              initial = read_byte("CBOR tagged byte string")
              raise Codec::ParseError, "CBOR expected encoding tags require byte strings" unless initial >> 5 == 2

              width = initial & 0x1f
              bytes = width == 31 ? read_string_chunks(2) : read_bytes(read_argument(width))
              case tag
              when 21 then Base64.urlsafe_encode64(bytes)
              when 22 then Base64.strict_encode64(bytes)
              when 23 then bytes.unpack1("H*")
              end
            when 0, 1
              value = read_item(depth + 1)
              timestamp = tag.zero? ? Time.iso8601(value) : Time.at(value).utc
              timestamp.iso8601(9).sub(/\.0+(?=Z|[+-])/, "").sub(/(\.\d*?[1-9])0+(?=Z|[+-])/, '\1')
            else
              read_item(depth + 1)
            end
          end

          def read_indefinite(major, depth)
            case major
            when 2 then byte_string(read_string_chunks(2))
            when 3 then read_string_chunks(3)
            when 4
              result = []
              result << read_item(depth + 1) until consume_break?
              result
            when 5 then read_map(nil, depth: depth)
            else raise Codec::ParseError, "invalid indefinite-length CBOR item"
            end
          end

          def read_string_chunks(major)
            output = major == 2 ? "".b : +""
            until consume_break?
              initial = read_byte("CBOR string chunk")
              width = initial & 0x1f
              raise Codec::ParseError, "invalid chunk in indefinite-length CBOR string" if initial >> 5 != major || width == 31

              length = read_argument(width)
              output << (major == 2 ? read_bytes(length) : read_text(length))
            end
            output
          end

          def consume_break?
            return false if @input.getbyte(@offset) != 0xff

            @offset += 1
            true
          end

          def read_argument(additional)
            case additional
            when 0..23 then additional
            when 24 then read_uint(1, minimum: 24)
            when 25 then read_uint(2, minimum: 1 << 8)
            when 26 then read_uint(4, minimum: 1 << 16)
            when 27 then read_uint(8, minimum: 1 << 32)
            when 31 then raise Codec::ParseError, "indefinite-length CBOR is not supported"
            else raise Codec::ParseError, "invalid CBOR additional information #{additional}"
            end
          end

          def read_uint(size, minimum: nil)
            bytes = read_bytes_raw(size, "CBOR length/value")
            value = case size
                    when 1 then bytes.unpack1("C")
                    when 2 then bytes.unpack1("n")
                    when 4 then bytes.unpack1("N")
                    when 8 then bytes.unpack1("Q>")
                    else raise Codec::ParseError, "invalid CBOR integer width #{size}"
                    end
            raise Codec::ParseError, "non-canonical CBOR integer/length encoding" if @strict && minimum && value < minimum

            value
          end

          def read_bytes(length)
            read_bytes_raw(length, "CBOR byte string").b
          end

          def read_text(length)
            value = read_bytes_raw(length, "CBOR text string").dup.force_encoding(Encoding::UTF_8)
            raise Codec::ParseError, "CBOR text string is not valid UTF-8" unless value.valid_encoding?

            value
          end

          def read_array(length, depth:)
            enforce_collection_length!(length)
            Array.new(length) { read_item(depth + 1) }
          end

          def read_map(length, depth:)
            enforce_collection_length!(length) if length
            result = {}
            previous_key = nil
            count = 0
            until length ? count == length : consume_break?
              count += 1
              key_start = @offset
              key = read_item(depth + 1)
              key_encoding = @input.byteslice(key_start, @offset - key_start).b
              raise Codec::ParseError, "CBOR map keys are not in canonical order" if @strict && previous_key && compare_keys(previous_key, key_encoding) >= 0

              previous_key = key_encoding
              raise Codec::ParseError, "CBOR map key is not hashable" unless key.hash
              raise Codec::ParseError, "Kubernetes CBOR map keys must be strings" if @kubernetes && !key.is_a?(String)
              raise Codec::DuplicateKeyError, "CBOR map contains duplicate key" if result.key?(key)

              result[key] = read_item(depth + 1)
            end
            result
          end

          def read_simple(additional)
            case additional
            when 20 then false
            when 21 then true
            when 22 then nil
            when 23 then raise Codec::ParseError, "CBOR undefined is not supported"
            when 24 then raise Codec::ParseError, "CBOR simple values are not supported"
            when 25 then read_float16
            when 26 then read_float32
            when 27 then read_float64
            else raise Codec::ParseError, "unsupported CBOR simple value #{additional}"
            end
          end

          def read_float16
            bits = read_bytes_raw(2, "CBOR float16").unpack1("n")
            value = half_to_float(bits)
            reject_nonfinite!(value)
            value
          end

          def read_float32
            value = read_bytes_raw(4, "CBOR float32").unpack1("g")
            reject_nonfinite!(value)
            raise Codec::ParseError, "non-canonical CBOR float width" if @strict && half_exact?(value)

            value
          end

          def read_float64
            value = read_bytes_raw(8, "CBOR float64").unpack1("G")
            reject_nonfinite!(value)
            raise Codec::ParseError, "non-canonical CBOR float width" if @strict && (half_exact?(value) || single_exact?(value))

            value
          end

          def compare_keys(left, right)
            [left.bytesize, left] <=> [right.bytesize, right]
          end

          def read_byte(label)
            byte = @input.getbyte(@offset)
            raise Codec::ParseError, "truncated #{label}" if byte.nil?

            @offset += 1
            byte
          end

          def read_bytes_raw(length, label)
            raise Codec::ParseError, "#{label} length is invalid" unless length.is_a?(Integer) && length >= 0
            raise Codec::LimitError, "#{label} exceeds input body" if length > @input.bytesize - @offset

            value = @input.byteslice(@offset, length)
            @offset += length
            value
          end

          def enforce_collection_length!(length)
            raise Codec::LimitError, "CBOR collection length exceeds input body" if length > @input.bytesize
          end

          def reject_nonfinite!(value)
            raise Codec::ParseError, "non-finite CBOR floats are not supported" unless value.finite?
          end
        end
      end

      CBORCodec = CBOR unless const_defined?(:CBORCodec, false)
      Cbor = CBOR unless const_defined?(:Cbor, false)
    end
  end
end
