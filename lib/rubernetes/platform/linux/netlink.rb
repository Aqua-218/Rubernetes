# frozen_string_literal: true

require "socket"
require_relative "error"

module Rubernetes
  module Platform
    module Linux
      class Netlink
        Message = Data.define(:type, :flags, :sequence, :payload)
        Ack = Data.define(:sequence, :messages)

        NETLINK_ROUTE = 0
        NLM_F_REQUEST = 0x01
        NLM_F_ACK = 0x04
        NLMSG_ERROR = 0x02
        NLMSG_DONE = 0x03
        RTM_NEWLINK = 16
        RTM_GETLINK = 18
        HEADER_SIZE = 16

        def get_link(index:, sequence: 1, timeout: 2.0, resource_id: "netlink:link:#{index}")
          socket = Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, NETLINK_ROUTE)
          socket.bind([Socket::AF_NETLINK, 0, 0, 0].pack("S!S!L2"))
          request = encode_get_link(index: Integer(index), sequence: Integer(sequence))
          socket.send(request, 0)
          receive_ack(socket, sequence: Integer(sequence), timeout: timeout, resource_id: resource_id)
        rescue SystemCallError => error
          raise Linux::Error.wrap(error, operation: "netlink", resource_id: resource_id), cause: error
        ensure
          socket&.close
        end

        private

        def encode_get_link(index:, sequence:)
          body = [Socket::AF_UNSPEC, 0, 0, index, 0, 0].pack("CCSlLL")
          [HEADER_SIZE + body.bytesize, RTM_GETLINK, NLM_F_REQUEST | NLM_F_ACK, sequence, 0].pack("LSSLL") + body
        end

        def receive_ack(socket, sequence:, timeout:, resource_id:)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
          messages = []
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            if remaining <= 0 || socket.wait_readable(remaining).nil?
              raise Linux::Error.new(errno: Errno::ETIMEDOUT::Errno, operation: "netlink_ack", resource_id: resource_id)
            end

            buffer = socket.recv(65_536)
            parse_messages(buffer).each do |message|
              next unless message.sequence == sequence

              if message.type == NLMSG_ERROR
                kernel_error = message.payload.unpack1("l")
                if kernel_error.negative?
                  raise Linux::Error.new(
                    errno: -kernel_error,
                    operation: "netlink_ack",
                    resource_id: resource_id
                  )
                end
                return Ack.new(sequence: sequence, messages: messages.freeze)
              end
              messages << message
              return Ack.new(sequence: sequence, messages: messages.freeze) if message.type == NLMSG_DONE
            end
          end
        end

        def parse_messages(buffer)
          messages = []
          offset = 0
          while offset + HEADER_SIZE <= buffer.bytesize
            length, type, flags, sequence, = buffer.byteslice(offset, HEADER_SIZE).unpack("LSSLL")
            break if length < HEADER_SIZE || offset + length > buffer.bytesize

            payload = buffer.byteslice(offset + HEADER_SIZE, length - HEADER_SIZE)
            messages << Message.new(type: type, flags: flags, sequence: sequence, payload: payload.freeze)
            offset += (length + 3) & ~3
          end
          messages
        end
      end
    end
  end
end
