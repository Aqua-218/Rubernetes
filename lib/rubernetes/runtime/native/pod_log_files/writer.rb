# frozen_string_literal: true

module Rubernetes
  module Runtime
    class Native
      class PodLogFiles
        class Writer
          Tee = Data.define(:raw, :writer, :stream, :combined) do
            def append(bytes)
              return combined.append_stream(raw, bytes) { write(bytes) } if combined

              write(bytes)
            end

            private

            def write(bytes)
              written = raw.append(bytes)
              writer&.append(stream, bytes)
              written
            end
          end

          def initialize(rotator, clock)
            @rotator = rotator
            @clock = clock
          end

          def append(stream, bytes)
            prefix = "#{@clock.call.utc.iso8601(9)} #{stream} ".b
            limit = @rotator.max_bytes - prefix.bytesize - 3
            return unless limit.positive?

            bytes.each_line do |line|
              full = line.end_with?("\n")
              payload = line.delete_suffix("\n")
              offset = 0
              loop do
                fragment = payload.byteslice(offset, limit)
                offset += fragment.bytesize
                final = offset == payload.bytesize
                record = prefix + (full && final ? "F " : "P ") + fragment + "\n"
                @rotator.rotate! if @rotator.bytesize + record.bytesize > @rotator.max_bytes
                @rotator.append(record)
                break if final
              end
            end
          rescue SystemCallError => error
            warn "could not write native Pod log: #{error.message}"
          end
        end
      end
    end
  end
end
