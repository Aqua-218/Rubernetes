# frozen_string_literal: true

module Rubernetes
  module Platform
    module Linux
      module NativeAdapters
        class ProcessGateAdapter
          # The write side of a pty session.  Closing a terminal's input has
          # no pipe-like EOF: the equivalent the workload understands is an
          # end-of-transmission character, which is what a client's stdin
          # close turns into (the master itself stays open for reading).
          class PtyInput
            EOT = "\x04".b

            def initialize(master)
              @master = master
              @closed = false
            end

            def write(value)
              raise IOError, "pty input is closed" if @closed

              @master.write(value)
              @master.flush
              value.to_s.bytesize
            end

            def write_nonblock(value, exception: true)
              @master.write_nonblock(value, exception: exception)
            end

            def close_write
              return self if @closed

              @closed = true
              begin
                @master.write(EOT)
                @master.flush
              rescue IOError, SystemCallError
                nil
              end
              self
            end

            alias close close_write

            def closed?
              @closed
            end

            def to_io
              @master
            end
          end
        end
      end
    end
  end
end
