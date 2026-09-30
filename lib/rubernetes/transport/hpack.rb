# frozen_string_literal: true

require_relative "hpack_tables"

module Rubernetes
  module Transport
    # HPACK (RFC 7541): the header compression HTTP/2 requires.  The decoder
    # is complete -- static and dynamic tables, table size updates, Huffman
    # strings.  The encoder only emits literals without indexing (indexed for
    # a static :status): always valid, and it keeps no per-connection state a
    # peer could grow.
    module HPACK
      class DecodingError < StandardError; end

      STATIC_TABLE = HPACKTables::STATIC_TABLE
      ENTRY_OVERHEAD = 32

      # Huffman decoding tree: nodes are [child0, child1]; a leaf is an Integer
      # symbol.
      HUFFMAN_TREE = begin
        root = [nil, nil]
        HPACKTables::HUFFMAN_CODES.each_with_index do |(code, length), symbol|
          node = root
          (length - 1).downto(0) do |shift|
            bit = (code >> shift) & 1
            if shift.zero?
              node[bit] = symbol
            else
              node[bit] ||= [nil, nil]
              node = node[bit]
            end
          end
        end
        root
      end

      module_function

      def huffman_decode(bytes)
        output = String.new(capacity: bytes.bytesize * 2, encoding: Encoding::BINARY)
        node = HUFFMAN_TREE
        depth = 0
        ones = true
        bytes.each_byte do |byte|
          7.downto(0) do |shift|
            bit = (byte >> shift) & 1
            ones &&= bit == 1
            depth += 1
            node = node[bit]
            raise DecodingError, "invalid Huffman code" if node.nil?
            next if node.is_a?(Array)

            raise DecodingError, "Huffman string contains EOS" if node == 256

            output << node.chr
            node = HUFFMAN_TREE
            depth = 0
            ones = true
          end
        end
        # Padding: fewer than 8 bits, all ones (the EOS prefix).
        raise DecodingError, "invalid Huffman padding" if depth > 7 || (depth.positive? && !ones)

        output
      end

      def decode_integer(bytes, offset, prefix_bits)
        raise DecodingError, "truncated integer" if offset >= bytes.bytesize

        mask = (1 << prefix_bits) - 1
        value = bytes.getbyte(offset) & mask
        offset += 1
        return [value, offset] if value < mask

        shift = 0
        loop do
          raise DecodingError, "truncated integer" if offset >= bytes.bytesize

          byte = bytes.getbyte(offset)
          offset += 1
          value += (byte & 0x7f) << shift
          shift += 7
          raise DecodingError, "integer overflow" if shift > 56
          break if byte.nobits?(0x80)
        end
        [value, offset]
      end

      def encode_integer(value, prefix_bits, first_byte_flags)
        mask = (1 << prefix_bits) - 1
        return [first_byte_flags | value].pack("C") if value < mask

        bytes = [first_byte_flags | mask]
        value -= mask
        while value >= 128
          bytes << ((value & 0x7f) | 0x80)
          value >>= 7
        end
        bytes << value
        bytes.pack("C*")
      end

      def decode_string(bytes, offset)
        raise DecodingError, "truncated string" if offset >= bytes.bytesize

        huffman = bytes.getbyte(offset).anybits?(0x80)
        length, offset = decode_integer(bytes, offset, 7)
        raise DecodingError, "truncated string" if offset + length > bytes.bytesize

        raw = bytes.byteslice(offset, length)
        [huffman ? huffman_decode(raw) : raw.b, offset + length]
      end

      def encode_string(value)
        value = value.to_s.b
        encode_integer(value.bytesize, 7, 0) + value
      end

      class Decoder
        attr_reader :max_table_size

        def initialize(max_table_size: 4096, max_header_list_bytes: 1 << 20)
          @entries = []
          @size = 0
          @max_table_size = max_table_size
          @protocol_max = max_table_size
          @max_header_list_bytes = max_header_list_bytes
        end

        # Decodes one complete header block into [[name, value], ...].
        def decode(block)
          block = block.b
          headers = []
          list_bytes = 0
          offset = 0
          first = true
          while offset < block.bytesize
            byte = block.getbyte(offset)
            if byte & 0x80 != 0
              index, offset = HPACK.decode_integer(block, offset, 7)
              name, value = lookup(index)
              headers << [name, value]
            elsif byte & 0xc0 == 0x40
              name, value, offset = literal(block, offset, 6)
              add(name, value)
              headers << [name, value]
            elsif byte & 0xe0 == 0x20
              raise DecodingError, "dynamic table size update after a header field" unless first

              size, offset = HPACK.decode_integer(block, offset, 5)
              raise DecodingError, "table size update above the allowed maximum" if size > @protocol_max

              @max_table_size = size
              evict
              next
            else
              name, value, offset = literal(block, offset, 4)
              headers << [name, value]
            end
            first = false
            list_bytes += name.bytesize + value.bytesize + ENTRY_OVERHEAD
            raise DecodingError, "header list too large" if list_bytes > @max_header_list_bytes
          end
          headers
        end

        private

        def literal(block, offset, prefix_bits)
          index, offset = HPACK.decode_integer(block, offset, prefix_bits)
          if index.zero?
            name, offset = HPACK.decode_string(block, offset)
          else
            name, = lookup(index)
          end
          value, offset = HPACK.decode_string(block, offset)
          [name, value, offset]
        end

        def lookup(index)
          raise DecodingError, "header index 0" if index.zero?
          return STATIC_TABLE.fetch(index - 1) if index <= STATIC_TABLE.length

          entry = @entries[index - STATIC_TABLE.length - 1]
          raise DecodingError, "header index #{index} out of range" if entry.nil?

          entry
        end

        def add(name, value)
          size = name.bytesize + value.bytesize + ENTRY_OVERHEAD
          if size > @max_table_size
            @entries.clear
            @size = 0
            return
          end
          @entries.unshift([name.freeze, value.freeze].freeze)
          @size += size
          evict
        end

        def evict
          while @size > @max_table_size && !@entries.empty?
            name, value = @entries.pop
            @size -= name.bytesize + value.bytesize + ENTRY_OVERHEAD
          end
        end
      end

      module Encoder
        module_function

        STATUS_INDEX = STATIC_TABLE.each_with_index.filter_map do |(name, value), index|
          [value, index + 1] if name == ":status"
        end.to_h.freeze

        # [[name, value], ...] -> header block.
        def encode(headers)
          block = +"".b
          headers.each do |name, value|
            name = name.to_s
            value = value.to_s
            if name == ":status" && (index = STATUS_INDEX[value])
              block << HPACK.encode_integer(index, 7, 0x80)
            else
              block << "\x00".b << HPACK.encode_string(name.downcase) << HPACK.encode_string(value)
            end
          end
          block
        end
      end
    end
  end
end
