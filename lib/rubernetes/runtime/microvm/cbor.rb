# frozen_string_literal: true

require_relative "errors"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Canonical CBOR (RFC 8949 §4.2 deterministic encoding) for the
      # guest-host protocol: definite lengths only, shortest integer
      # encodings, map keys sorted by their encoded bytes, and a decoder
      # that rejects indefinite lengths, duplicate keys, non-canonical
      # integer widths, unknown simple values, tags, and documents that
      # exceed the depth or size bound.  Only the types the protocol needs
      # are supported: unsigned/negative integers, byte strings, text
      # strings, arrays, maps, false, true, null and IEEE-754 doubles.
      module CBOR
        MAX_DEPTH = 64
        DEFAULT_MAX_BYTES = 1024 * 1024

        module_function

        def encode(value)
          buffer = String.new(encoding: Encoding::BINARY)
          write(value, buffer, 0)
          buffer
        end

        def decode(bytes, max_bytes: DEFAULT_MAX_BYTES)
          data = bytes.b
          raise FramingError, "CBOR document exceeds #{max_bytes} bytes" if data.bytesize > max_bytes

          decoder = Decoder.new(data)
          value = decoder.read(0)
          raise ProtocolError, "trailing bytes after CBOR document" unless decoder.finished?

          value
        end

        def write(value, buffer, depth)
          raise ProtocolError, "CBOR nesting exceeds #{MAX_DEPTH}" if depth > MAX_DEPTH

          case value
          when Integer
            if value >= 0
              write_head(0, value, buffer)
            else
              write_head(1, -1 - value, buffer)
            end
          when String
            if value.encoding == Encoding::BINARY
              write_head(2, value.bytesize, buffer)
              buffer << value
            else
              text = value.encode(Encoding::UTF_8)
              raise ProtocolError, "text string is not valid UTF-8" unless text.valid_encoding?

              write_head(3, text.bytesize, buffer)
              buffer << text.b
            end
          when Symbol
            write(value.to_s, buffer, depth)
          when Array
            write_head(4, value.length, buffer)
            value.each { |item| write(item, buffer, depth + 1) }
          when Hash
            entries = value.map do |key, item|
              key_bytes = String.new(encoding: Encoding::BINARY)
              write(key.is_a?(Symbol) ? key.to_s : key, key_bytes, depth + 1)
              [key_bytes, item]
            end
            raise ProtocolError, "duplicate map key" if entries.map(&:first).uniq.length != entries.length

            write_head(5, entries.length, buffer)
            entries.sort_by(&:first).each do |key_bytes, item|
              buffer << key_bytes
              write(item, buffer, depth + 1)
            end
          when false then buffer << 0xF4.chr
          when true then buffer << 0xF5.chr
          when nil then buffer << 0xF6.chr
          when Float
            buffer << 0xFB.chr << [value].pack("G")
          else
            raise ProtocolError, "unsupported CBOR value #{value.class}"
          end
        end

        def write_head(major, argument, buffer)
          raise ProtocolError, "CBOR integer out of range" if argument > 0xFFFF_FFFF_FFFF_FFFF

          base = major << 5
          if argument < 24
            buffer << (base | argument).chr
          elsif argument < 0x100
            buffer << (base | 24).chr << [argument].pack("C")
          elsif argument < 0x10000
            buffer << (base | 25).chr << [argument].pack("n")
          elsif argument < 0x1_0000_0000
            buffer << (base | 26).chr << [argument].pack("N")
          else
            buffer << (base | 27).chr << [argument].pack("Q>")
          end
        end

        class Decoder
          def initialize(data)
            @data = data
            @position = 0
          end

          def finished?
            @position == @data.bytesize
          end

          def read(depth)
            raise ProtocolError, "CBOR nesting exceeds #{MAX_DEPTH}" if depth > MAX_DEPTH

            initial = take(1).unpack1("C")
            major = initial >> 5
            additional = initial & 0x1F
            case major
            when 0 then argument(additional)
            when 1 then -1 - argument(additional)
            when 2 then take(argument(additional))
            when 3
              text = take(argument(additional)).force_encoding(Encoding::UTF_8)
              raise ProtocolError, "CBOR text string is not valid UTF-8" unless text.valid_encoding?

              text
            when 4
              Array.new(argument(additional)) { read(depth + 1) }
            when 5
              count = argument(additional)
              map = {}
              previous = nil
              count.times do
                start = @position
                key = read(depth + 1)
                encoded = @data.byteslice(start, @position - start)
                raise ProtocolError, "CBOR map keys are not in canonical order" if previous && (encoded <=> previous) <= 0

                previous = encoded
                map[key] = read(depth + 1)
              end
              map
            when 6 then raise ProtocolError, "CBOR tags are not part of the protocol"
            when 7
              case additional
              when 20 then false
              when 21 then true
              when 22 then nil
              when 27 then take(8).unpack1("G")
              else raise ProtocolError, "unsupported CBOR simple value #{additional}"
              end
            else
              raise ProtocolError, "unsupported CBOR major type #{major}"
            end
          end

          private

          def argument(additional)
            case additional
            when 0..23 then additional
            when 24 then canonical(take(1).unpack1("C"), 24)
            when 25 then canonical(take(2).unpack1("n"), 0x100)
            when 26 then canonical(take(4).unpack1("N"), 0x10000)
            when 27 then canonical(take(8).unpack1("Q>"), 0x1_0000_0000)
            else raise ProtocolError, "indefinite-length or reserved CBOR item"
            end
          end

          def canonical(value, minimum)
            raise ProtocolError, "non-canonical CBOR integer encoding" if value < minimum

            value
          end

          def take(length)
            raise FramingError, "CBOR document is truncated" if @position + length > @data.bytesize

            slice = @data.byteslice(@position, length)
            @position += length
            slice
          end
        end
      end
    end
  end
end
