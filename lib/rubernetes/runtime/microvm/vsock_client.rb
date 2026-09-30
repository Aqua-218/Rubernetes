# frozen_string_literal: true

require "socket"

require_relative "errors"
require_relative "framing"

module Rubernetes
  module Runtime
    class MicroVM < Runtime
      # Host side of a vsock connection through Firecracker's Unix-socket
      # backend: the host connects to the VM's UDS and sends
      # "CONNECT <port>"; the VMM answers "OK <host-port>" once the guest
      # accepted.  Caller identity is the connection itself: the socket
      # path is unique per VM instance and recorded in the identity ledger.
      module VsockClient
        module_function

        def connect(uds_path, port, timeout: 5.0)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          begin
            socket = UNIXSocket.new(uds_path)
          rescue Errno::ENOENT, Errno::ECONNREFUSED => error
            if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
              raise VsockError,
                    "vsock backend #{uds_path} is unavailable: #{error.message}"
            end

            sleep 0.005
            retry
          end
          socket.write("CONNECT #{Integer(port)}\n")
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          unless remaining.positive? && socket.wait_readable(remaining)
            raise VsockError,
                  "guest did not accept vsock port #{port} within #{timeout}s"
          end

          line = socket.gets
          raise VsockError, "vsock connect to port #{port} rejected: #{line.inspect}" unless line.to_s.start_with?("OK ")

          socket
        rescue VsockError
          socket&.close
          raise
        rescue SystemCallError, IOError => error
          socket&.close
          raise VsockError, "vsock connect to #{uds_path}:#{port} failed: #{error.class}: #{error.message}"
        end

        # Two-phase connect for restores: send CONNECT while the VM is
        # paused, read the guest's OK after the resume.
        def preconnect(uds_path, port)
          socket = UNIXSocket.new(uds_path)
          socket.write("CONNECT #{Integer(port)}\n")
          socket
        rescue SystemCallError, IOError => error
          socket&.close
          raise VsockError, "vsock preconnect to #{uds_path}:#{port} failed: #{error.class}: #{error.message}"
        end

        def complete(socket, port, timeout: 10.0)
          raise VsockError, "guest did not accept vsock port #{port} within #{timeout}s" unless socket.wait_readable(timeout)

          line = socket.gets
          raise VsockError, "vsock connect to port #{port} rejected: #{line.inspect}" unless line.to_s.start_with?("OK ")

          socket
        rescue VsockError
          socket.close unless socket.closed?
          raise
        end

        # Retries the CONNECT handshake until the guest listener is up (used
        # right after boot/restore).
        def channel(uds_path, port, timeout: 10.0, request_timeout: Framing::RESPONSE_TIMEOUT)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          begin
            Channel.new(connect(uds_path, port, timeout: [deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0.1].max),
                        timeout: request_timeout)
          rescue VsockError
            raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

            sleep 0.005
            retry
          end
        end

        # Host listener for guest-initiated connections to +port+: Firecracker
        # connects to "<uds_path>_<port>" on the host side.
        def listener(uds_path, port)
          path = "#{uds_path}_#{Integer(port)}"
          File.delete(path) if File.socket?(path)
          UNIXServer.new(path)
        end
      end
    end
  end
end
