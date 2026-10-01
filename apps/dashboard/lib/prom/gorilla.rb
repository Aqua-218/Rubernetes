# frozen_string_literal: true

module Prom
  # Gorilla / Prometheus XOR chunk compression for one series.
  #
  # Timestamps (ms) are stored as delta-of-delta with the Prometheus bucket
  # scheme (0 -> 1 bit, 14 bits for |dod| < 8192, 17 for < 65536, 20 for
  # < 524288, else 64 bits); values as XOR against the previous value with
  # leading/trailing-zero windows (tsdb/chunkenc/xor.go).  A chunk is a
  # byte string: 2-byte sample count, then the bit stream.  At ~1.4 bytes
  # per sample for scrape data this is what makes days of retention fit.
  module Gorilla
    class BitWriter
      def initialize
        @bytes = "".b
        @current = 0
        @filled = 0 # bits used in @current
      end

      def write_bit(bit)
        @current = (@current << 1) | (bit & 1)
        @filled += 1
        flush_byte if @filled == 8
        self
      end

      def write_bits(value, count)
        count.downto(1) { |i| write_bit((value >> (i - 1)) & 1) }
        self
      end

      # Two's complement of `value` in `count` bits.
      def write_signed(value, count)
        write_bits(value & ((1 << count) - 1), count)
      end

      def bytes
        return @bytes.dup if @filled.zero?

        @bytes.dup << ((@current << (8 - @filled)) & 0xFF).chr
      end

      private

      def flush_byte
        @bytes << (@current & 0xFF).chr
        @current = 0
        @filled = 0
      end
    end

    class BitReader
      def initialize(bytes, offset_bits = 0)
        @bytes = bytes
        @pos = offset_bits
        @limit = bytes.bytesize * 8
      end

      def read_bit
        raise EOFError, "chunk truncated" if @pos >= @limit

        byte = @bytes.getbyte(@pos >> 3)
        bit = (byte >> (7 - (@pos & 7))) & 1
        @pos += 1
        bit
      end

      def read_bits(count)
        value = 0
        count.times { value = (value << 1) | read_bit }
        value
      end

      def read_signed(count)
        value = read_bits(count)
        value >= (1 << (count - 1)) ? value - (1 << count) : value
      end
    end

    # Streaming encoder: append(timestamp_ms, float) then #bytes.
    class Encoder
      attr_reader :count, :min_time, :max_time

      def initialize
        @writer = BitWriter.new
        @count = 0
        @min_time = nil
        @max_time = nil
        @t = nil
        @t_delta = nil
        @v = nil
        @leading = 0xFF
        @trailing = 0
      end

      def append(timestamp, value)
        timestamp = Integer(timestamp)
        value = Float(value)
        if @count.zero?
          write_varint(timestamp)
          @writer.write_bits(float_bits(value), 64)
          @min_time = timestamp
        elsif @count == 1
          delta = timestamp - @t
          raise ArgumentError, "timestamps must not decrease" if delta.negative?

          write_uvarint(delta)
          @t_delta = delta
          write_xor(value)
        else
          delta = timestamp - @t
          raise ArgumentError, "timestamps must not decrease" if delta.negative?

          dod = delta - @t_delta
          @t_delta = delta
          write_dod(dod)
          write_xor(value)
        end
        @t = timestamp
        @v = value
        @max_time = timestamp
        @count += 1
        self
      end

      def bytes
        [@count].pack("n") + @writer.bytes
      end

      private

      def write_dod(dod)
        if dod.zero?
          @writer.write_bit(0)
        elsif dod.abs < 8192
          @writer.write_bits(0b10, 2).write_signed(dod, 14)
        elsif dod.abs < 65_536
          @writer.write_bits(0b110, 3).write_signed(dod, 17)
        elsif dod.abs < 524_288
          @writer.write_bits(0b1110, 4).write_signed(dod, 20)
        else
          @writer.write_bits(0b1111, 4).write_signed(dod, 64)
        end
      end

      def write_xor(value)
        xor = float_bits(value) ^ float_bits(@v)
        if xor.zero?
          @writer.write_bit(0)
          return
        end
        @writer.write_bit(1)
        leading = leading_zeros(xor)
        trailing = trailing_zeros(xor)
        leading = 31 if leading >= 32
        if @leading != 0xFF && leading >= @leading && trailing >= @trailing
          @writer.write_bit(0)
          @writer.write_bits(xor >> @trailing, 64 - @leading - @trailing)
        else
          @leading = leading
          @trailing = trailing
          @writer.write_bit(1)
          @writer.write_bits(leading, 5)
          sigbits = 64 - leading - trailing
          # 64 significant bits are written as 0 in a 6-bit field.
          @writer.write_bits(sigbits & 0x3F, 6)
          @writer.write_bits(xor >> trailing, sigbits)
        end
      end

      def write_varint(value)
        write_uvarint((value << 1) ^ (value >> 63))
      end

      def write_uvarint(value)
        loop do
          byte = value & 0x7F
          value >>= 7
          if value.zero?
            @writer.write_bits(byte, 8)
            break
          end
          @writer.write_bits(byte | 0x80, 8)
        end
      end

      def float_bits(value)
        [value].pack("G").unpack1("Q>")
      end

      def leading_zeros(value)
        64 - value.bit_length
      end

      def trailing_zeros(value)
        return 64 if value.zero?

        count = 0
        count += 1 while (value >> count).nobits?(1)
        count
      end
    end

    module_function

    # Decode a chunk into [[timestamp_ms, value], ...].
    def decode(bytes)
      count = bytes.unpack1("n")
      return [] if count.nil? || count.zero?

      reader = BitReader.new(bytes.byteslice(2..) || "".b)
      samples = []
      t = read_varint(reader)
      v = bits_float(reader.read_bits(64))
      samples << [t, v]
      return samples if count == 1

      t_delta = read_uvarint(reader)
      t += t_delta
      leading = 0
      trailing = 0
      v_bits = float_bits(v)
      v_bits, leading, trailing = read_xor(reader, v_bits, leading, trailing)
      samples << [t, bits_float(v_bits)]
      (count - 2).times do
        dod = if reader.read_bit.zero?
                0
              elsif reader.read_bit.zero? # rubocop:disable Lint/DuplicateElsifCondition -- each read_bit consumes the next bit
                reader.read_signed(14)
              elsif reader.read_bit.zero? # rubocop:disable Lint/DuplicateElsifCondition -- each read_bit consumes the next bit
                reader.read_signed(17)
              elsif reader.read_bit.zero? # rubocop:disable Lint/DuplicateElsifCondition -- each read_bit consumes the next bit
                reader.read_signed(20)
              else
                reader.read_signed(64)
              end
        t_delta += dod
        t += t_delta
        v_bits, leading, trailing = read_xor(reader, v_bits, leading, trailing)
        samples << [t, bits_float(v_bits)]
      end
      samples
    end

    def read_xor(reader, previous, leading, trailing)
      return [previous, leading, trailing] if reader.read_bit.zero?

      if reader.read_bit == 1
        leading = reader.read_bits(5)
        sigbits = reader.read_bits(6)
        sigbits = 64 if sigbits.zero?
        trailing = 64 - leading - sigbits
      end
      sigbits = 64 - leading - trailing
      value = reader.read_bits(sigbits)
      [previous ^ (value << trailing), leading, trailing]
    end

    def read_uvarint(reader)
      value = 0
      shift = 0
      loop do
        byte = reader.read_bits(8)
        value |= (byte & 0x7F) << shift
        break if byte.nobits?(0x80)

        shift += 7
      end
      value
    end

    def read_varint(reader)
      raw = read_uvarint(reader)
      (raw >> 1) ^ -(raw & 1)
    end

    def float_bits(value)
      [value].pack("G").unpack1("Q>")
    end

    def bits_float(bits)
      [bits].pack("Q>").unpack1("G")
    end
  end
end
