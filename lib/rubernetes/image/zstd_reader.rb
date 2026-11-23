# frozen_string_literal: true

require "fiddle/import"

require_relative "errors"

module Rubernetes
  module Image
    # Presents a zstd stream as a sized-read IO for the tar parser. The native
    # decoder caps the frame window at 128 MiB by default, and the parser
    # enforces the total uncompressed layer limit across all frames.
    class ZstdReader
      CHUNK_BYTES = 128 * 1024

      module Native
        extend Fiddle::Importer

        dlload "libzstd.so.1"

        Input = struct(["const void *src", "size_t size", "size_t pos"])
        Output = struct(["void *dst", "size_t size", "size_t pos"])

        extern "void *ZSTD_createDStream()"
        extern "size_t ZSTD_freeDStream(void *)"
        extern "size_t ZSTD_initDStream(void *)"
        extern "size_t ZSTD_decompressStream(void *, void *, void *)"
        extern "unsigned int ZSTD_isError(size_t)"
        extern "const char *ZSTD_getErrorName(size_t)"
      end
      private_constant :Native

      def initialize(io)
        @io = io
        @input = Native::Input.malloc(Fiddle::RUBY_FREE)
        @input_bytes = Fiddle::Pointer.malloc(CHUNK_BYTES, Fiddle::RUBY_FREE)
        @input.src = @input_bytes
        @input.size = @input.pos = 0
        @output = Native::Output.malloc(Fiddle::RUBY_FREE)
        @output_bytes = Fiddle::Pointer.malloc(CHUNK_BYTES, Fiddle::RUBY_FREE)
        @output.dst = @output_bytes
        @output.size = CHUNK_BYTES
        @output.pos = @output_offset = 0
        @source_eof = false
        @frame_complete = false

        @stream = Native.ZSTD_createDStream
        raise LayerError, "cannot allocate zstd layer decoder" if @stream.null?

        check_result(Native.ZSTD_initDStream(@stream))
      rescue LayerError
        close
        raise
      end

      def read(length)
        return "".b if length.zero?

        refill_output if @output_offset == @output.pos
        available = @output.pos - @output_offset
        return nil if available.zero?

        size = [available, length].min
        bytes = @output_bytes[@output_offset, size]
        @output_offset += size
        bytes
      end

      def close
        return unless @stream

        Native.ZSTD_freeDStream(@stream)
        @stream = nil
      end

      private

      def refill_output
        @output.pos = @output_offset = 0
        loop do
          refill_input if !@source_eof && @input.pos == @input.size
          return if @source_eof && @frame_complete

          remaining = check_result(Native.ZSTD_decompressStream(@stream, @output, @input))
          @frame_complete = remaining.zero?
          return if @output.pos.positive?

          raise LayerError, "truncated zstd layer stream" if @source_eof && !@frame_complete
        end
      end

      def refill_input
        bytes = @io.read(CHUNK_BYTES)
        @input.size = bytes&.bytesize || 0
        @input.pos = 0
        @source_eof = @input.size.zero?
        @input_bytes[0, @input.size] = bytes unless @source_eof
      end

      def check_result(result)
        return result if Native.ZSTD_isError(result).zero?

        raise LayerError, "cannot decompress zstd layer: #{Native.ZSTD_getErrorName(result)}"
      end
    end
  end
end
