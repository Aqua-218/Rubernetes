# frozen_string_literal: true

require "stringio"
require_relative "../prom/native_histogram"

module Tsdb
  # A zero sample count distinguishes histogram chunks from legacy Gorilla
  # chunks. Each native sample uses the same payload in chunks and the WAL.
  class HistogramChunk
    MAGIC = "\x00\x00H".b.freeze
    HEADER = "cCG4N2"
    HEADER_SIZE = 42
    BUCKET_SIZE = 12

    attr_reader :min_time, :max_time, :count

    def initialize
      @bytes = MAGIC.dup
      @count = 0
    end

    def append(timestamp, value)
      @bytes << [timestamp].pack("q>") << self.class.encode(value)
      @min_time ||= timestamp
      @max_time = timestamp
      @count += 1
    end

    def bytes = @bytes.dup

    def self.encode(value)
      header = [value.schema, value.gauge ? 1 : 0, value.count, value.sum, value.zero_threshold, value.zero_count,
                value.negative.size, value.positive.size].pack(HEADER)
      [value.negative, value.positive].each do |side|
        side.each { |index, count| header << [index, count].pack("l>G") }
      end
      header << [value.custom_bounds.length, *value.custom_bounds].pack("NG*") if value.custom?
      header
    end

    def self.read(io)
      header = io.read(HEADER_SIZE)
      return nil unless header&.bytesize == HEADER_SIZE

      schema, gauge, count, sum, threshold, zero, negative_size, positive_size = header.unpack(HEADER)
      negative = read_side(io, negative_size)
      positive = read_side(io, positive_size) if negative
      return nil unless negative && positive

      bounds = schema == Prom::NativeHistogram::CUSTOM_SCHEMA ? read_bounds(io) : Prom::NativeHistogram::EMPTY_BOUNDS
      return nil unless bounds

      Prom::NativeHistogram.new(schema: schema, gauge: gauge == 1, count: count, sum: sum, zero_threshold: threshold,
                                zero_count: zero, negative: negative, positive: positive, custom_bounds: bounds)
    end

    def self.read_side(io, size)
      buckets = {}
      size.times do
        record = io.read(BUCKET_SIZE)
        return nil unless record&.bytesize == BUCKET_SIZE

        index, count = record.unpack("l>G")
        buckets[index] = count
      end
      buckets
    end

    def self.read_bounds(io)
      size = io.read(4)&.unpack1("N")
      return nil if size.nil? || size > (io.size - io.pos) / 8

      io.read(size * 8).unpack("G*")
    end

    def self.decode(bytes)
      return Prom::Gorilla.decode(bytes) unless bytes.start_with?(MAGIC)

      io = StringIO.new(bytes)
      io.pos = MAGIC.bytesize
      points = []
      until io.eof?
        timestamp = io.read(8)&.unpack1("q>")
        value = timestamp && read(io)
        raise IOError, "truncated native histogram chunk" unless value

        points << [timestamp, value]
      end
      points
    end
  end
end
