# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        class NamespaceConnector
          # Kubernetes port-forward assigns two channels to each requested
          # port: 2*n carries data and 2*n+1 carries errors.
          class PortForwardMultiplexer
            def initialize(streams)
              @streams = Array(streams).freeze
              @readers = @streams.flat_map.with_index do |stream, index|
                [[stream.fetch(:stdout), index * 2], [stream.fetch(:stderr), (index * 2) + 1]]
              end.reject { |reader, _channel| reader.nil? }
              @buffer = "".b
              @closed = false
            end

            attr_reader :streams

            def status
              @streams.map { |stream| stream.fetch(:status) }.freeze
            end

            def write(value)
              bytes = String(value).b
              raise EffectError, "port-forward channel frame is empty" if bytes.empty?

              channel = bytes.getbyte(0)
              raise EffectError, "port-forward data channel must be even" unless channel.even?

              stream = @streams.fetch(channel / 2) { raise EffectError, "unknown port-forward channel #{channel}" }
              payload = bytes.byteslice(1, bytes.bytesize - 1) || "".b
              stream.fetch(:stdin).write(payload) unless payload.empty?
              bytes.bytesize
            end

            def read(length = nil)
              requested = length && Integer(length)
              return consume(requested) unless @buffer.empty?

              loop do
                return nil if @readers.empty?

                ready = IO.select(@readers.map(&:first), nil, nil)&.first || []
                ready.each do |reader|
                  pair = @readers.find { |candidate, _channel| candidate.equal?(reader) }
                  next unless pair

                  chunk = reader.read_nonblock(16 * 1024)
                  @buffer << pair.fetch(1).chr.b << chunk.b
                  return consume(requested)
                rescue IOError
                  @readers.delete(pair)
                rescue IO::WaitReadable
                  next
                end
              end
            end

            def close_write
              @streams.each do |stream|
                input = stream.fetch(:stdin)
                input.close unless input.closed?
              rescue IOError
                nil
              end
              self
            end

            def close
              return self if @closed

              @closed = true
              @streams.each do |stream|
                %i[stdin stdout stderr].filter_map { |key| stream[key] }.each do |io|
                  io.close unless io.closed?
                rescue IOError
                  nil
                end
              end
              self
            end

            def closed? = @closed

            private

            def consume(length)
              size = length ? [length, @buffer.bytesize].min : @buffer.bytesize
              value = @buffer.byteslice(0, size)
              @buffer = @buffer.byteslice(size, @buffer.bytesize - size) || "".b
              value
            end
          end
        end
      end
    end
  end
end
