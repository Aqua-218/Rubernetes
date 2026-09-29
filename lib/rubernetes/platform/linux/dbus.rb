# frozen_string_literal: true

require "socket"

module Rubernetes
  module Platform
    module Linux
      # A minimal D-Bus client (the wire protocol of the D-Bus specification,
      # little-endian) for what the kubelet asks of systemd: reading a
      # logind property, taking a shutdown inhibitor lock (a file descriptor
      # passed with SCM_RIGHTS), subscribing to PrepareForShutdown and
      # reloading logind.  Only the types those messages use are marshalled
      # and every type is unmarshalled.
      module DBus
        SYSTEM_BUS = "/run/dbus/system_bus_socket"
        # godbus SystemBus: DBUS_SYSTEM_BUS_ADDRESS overrides the default.
        SYSTEM_BUS_ADDRESS_ENV = "DBUS_SYSTEM_BUS_ADDRESS"

        class Error < StandardError; end

        # A D-Bus error reply.
        class RemoteError < Error
          attr_reader :name

          def initialize(name, message)
            super("#{name}: #{message}")
            @name = name
          end
        end

        METHOD_CALL = 1
        METHOD_RETURN = 2
        ERROR = 3
        SIGNAL = 4
        NO_REPLY_EXPECTED = 0x1

        FIELD_PATH = 1
        FIELD_INTERFACE = 2
        FIELD_MEMBER = 3
        FIELD_ERROR_NAME = 4
        FIELD_REPLY_SERIAL = 5
        FIELD_DESTINATION = 6
        FIELD_SENDER = 7
        FIELD_SIGNATURE = 8
        FIELD_UNIX_FDS = 9
        FIELD_TYPES = {FIELD_PATH => "o", FIELD_INTERFACE => "s", FIELD_MEMBER => "s", FIELD_ERROR_NAME => "s",
                       FIELD_REPLY_SERIAL => "u", FIELD_DESTINATION => "s", FIELD_SENDER => "s", FIELD_SIGNATURE => "g",
                       FIELD_UNIX_FDS => "u"}.freeze

        # A value with an explicit D-Bus type (a variant's content, an fd
        # index): [signature, value].
        Typed = Struct.new(:signature, :value)
        # A received unix fd: its index in the message and the IO.
        UnixFD = Struct.new(:index, :io)

        Message = Struct.new(:type, :flags, :serial, :fields, :body, :fds, keyword_init: true) do
          def path = fields[FIELD_PATH]
          def interface = fields[FIELD_INTERFACE]
          def member = fields[FIELD_MEMBER]
          def error_name = fields[FIELD_ERROR_NAME]
          def reply_serial = fields[FIELD_REPLY_SERIAL]
          def signature = fields[FIELD_SIGNATURE].to_s
        end

        # RequestName flags / replies.
        NAME_FLAG_DO_NOT_QUEUE = 0x4
        NAME_PRIMARY_OWNER = 1

        module_function

        # The socket of the first usable "unix:" entry of a D-Bus server
        # address list ("unix:path=/x;unix:abstract=y").
        def connect_address(address)
          errors = []
          address.to_s.split(";").each do |entry|
            transport, _, parameters = entry.partition(":")
            next unless transport == "unix"

            options = parameters.split(",").to_h do |pair|
              key, _, value = pair.partition("=")
              [key, value.gsub(/%([0-9A-Fa-f]{2})/) { Regexp.last_match(1).hex.chr }]
            end
            begin
              return UNIXSocket.new(options["path"]) if options["path"]
              return UNIXSocket.new("\0#{options["abstract"]}") if options["abstract"]
            rescue SystemCallError => error
              errors << error.message
            end
          end
          raise Error, "no usable unix transport in D-Bus address #{address.inspect}#{errors.empty? ? "" : ": #{errors.join("; ")}"}"
        end

        # Splits a signature into its complete types.
        def split_signature(signature)
          types = []
          index = 0
          while index < signature.length
            finish = complete_type_end(signature, index)
            types << signature[index...finish]
            index = finish
          end
          types
        end

        def complete_type_end(signature, index)
          case signature[index]
          when "a" then complete_type_end(signature, index + 1)
          when "(" then container_end(signature, index, "(", ")")
          when "{" then container_end(signature, index, "{", "}")
          when nil then raise Error, "incomplete signature #{signature.dump}"
          else index + 1
          end
        end

        def container_end(signature, index, open, close)
          depth = 0
          (index...signature.length).each do |position|
            depth += 1 if signature[position] == open
            depth -= 1 if signature[position] == close
            return position + 1 if depth.zero?
          end
          raise Error, "unbalanced signature #{signature.dump}"
        end

        def alignment(type)
          case type[0]
          when "y", "g", "v" then 1
          when "n", "q" then 2
          when "b", "i", "u", "s", "o", "a", "h" then 4
          when "x", "t", "d", "(", "{" then 8
          else raise Error, "unknown type #{type.dump}"
          end
        end

        # Marshalling into a binary String; +offset+ is the position of the
        # buffer's start in the message (alignment is message-relative).
        class Writer
          attr_reader :buffer

          def initialize(offset = 0)
            @buffer = String.new(encoding: Encoding::BINARY)
            @offset = offset
          end

          def pad(bytes)
            @buffer << ("\0" * ((bytes - ((@offset + @buffer.bytesize) % bytes)) % bytes))
          end

          def write(type, value)
            pad(DBus.alignment(type))
            case type[0]
            when "y" then @buffer << [value].pack("C")
            when "b" then @buffer << [value ? 1 : 0].pack("L<")
            when "n" then @buffer << [value].pack("s<")
            when "q" then @buffer << [value].pack("S<")
            when "i" then @buffer << [value].pack("l<")
            when "u", "h" then @buffer << [value].pack("L<")
            when "x" then @buffer << [value].pack("q<")
            when "t" then @buffer << [value].pack("Q<")
            when "d" then @buffer << [value].pack("E")
            when "s", "o"
              text = value.to_s.b
              @buffer << [text.bytesize].pack("L<") << text << "\0"
            when "g"
              text = value.to_s.b
              @buffer << [text.bytesize].pack("C") << text << "\0"
            when "v"
              write("g", value.signature)
              write(value.signature, value.value)
            when "a"
              element = type[1..]
              length_at = @buffer.bytesize
              @buffer << [0].pack("L<")
              pad(DBus.alignment(element))
              start = @buffer.bytesize
              entries = element.start_with?("{") ? value.to_a : Array(value)
              entries.each { |entry| write(element, entry) }
              @buffer[length_at, 4] = [@buffer.bytesize - start].pack("L<")
            when "(", "{"
              DBus.split_signature(type[1...-1]).zip(Array(value)).each { |member, entry| write(member, entry) }
            else
              raise Error, "cannot marshal #{type.dump}"
            end
            self
          end
        end

        class Reader
          def initialize(data, offset = 0, fds: [])
            @data = data
            @position = offset
            @fds = fds
          end

          attr_reader :position

          def align(bytes) = @position += (bytes - (@position % bytes)) % bytes

          def take(count)
            raise Error, "truncated message" if @position + count > @data.bytesize

            chunk = @data.byteslice(@position, count)
            @position += count
            chunk
          end

          def read(type)
            align(DBus.alignment(type))
            case type[0]
            when "y" then take(1).unpack1("C")
            when "b" then take(4).unpack1("L<") != 0
            when "n" then take(2).unpack1("s<")
            when "q" then take(2).unpack1("S<")
            when "i" then take(4).unpack1("l<")
            when "u" then take(4).unpack1("L<")
            when "h"
              index = take(4).unpack1("L<")
              UnixFD.new(index, @fds[index])
            when "x" then take(8).unpack1("q<")
            when "t" then take(8).unpack1("Q<")
            when "d" then take(8).unpack1("E")
            when "s", "o"
              length = take(4).unpack1("L<")
              text = take(length).force_encoding(Encoding::UTF_8)
              take(1)
              text
            when "g"
              length = take(1).unpack1("C")
              text = take(length)
              take(1)
              text
            when "v"
              signature = read("g")
              Typed.new(signature, read(signature))
            when "a"
              length = take(4).unpack1("L<")
              element = type[1..]
              align(DBus.alignment(element))
              finish = @position + length
              values = []
              values << read(element) while @position < finish
              element.start_with?("{") ? values.to_h : values
            when "(", "{"
              DBus.split_signature(type[1...-1]).map { |member| read(member) }
            else
              raise Error, "cannot unmarshal #{type.dump}"
            end
          end
        end

        # A complete message as bytes.
        def encode(type:, serial:, fields:, body_signature: "", body: [], flags: 0)
          body_writer = Writer.new(0)
          split_signature(body_signature).zip(body).each { |member, value| body_writer.write(member, value) }
          fields = fields.merge(FIELD_SIGNATURE => body_signature) unless body_signature.empty?
          header = Writer.new(0)
          header.write("y", "l".ord).write("y", type).write("y", flags).write("y", 1)
          header.write("u", body_writer.buffer.bytesize).write("u", serial)
          header.write("a(yv)", fields.sort.map { |code, value| [code, Typed.new(FIELD_TYPES.fetch(code), value)] })
          header.pad(8)
          header.buffer + body_writer.buffer
        end

        # Parses one message from +data+ (starting at 0): [message, bytes
        # used], or nil when the data is not complete yet.
        def decode(data, fds: [])
          return nil if data.bytesize < 16
          raise Error, "big-endian messages are not supported" unless data.getbyte(0) == "l".ord

          body_length, _serial, fields_length = data.byteslice(4, 12).unpack("L<L<L<")
          header_end = 16 + fields_length
          header_end += (8 - (header_end % 8)) % 8
          total = header_end + body_length
          return nil if data.bytesize < total

          reader = Reader.new(data, 0, fds: fds)
          _endian, type, flags, _version = Array.new(4) { reader.read("y") }
          reader.read("u")
          serial = reader.read("u")
          fields = reader.read("a(yv)").to_h { |code, typed| [code, typed.value] }
          body_reader = Reader.new(data.byteslice(header_end, body_length), 0, fds: fds)
          body = split_signature(fields[FIELD_SIGNATURE].to_s).map { |member| body_reader.read(member) }
          [Message.new(type: type, flags: flags, serial: serial, fields: fields, body: body, fds: fds), total]
        end

        # A connection to a bus: authenticated, with unix fd passing.
        class Connection
          attr_reader :unique_name

          def self.system(path = nil)
            return new(UNIXSocket.new(path)) if path

            address = ENV.fetch(SYSTEM_BUS_ADDRESS_ENV, "").strip
            new(address.empty? ? UNIXSocket.new(SYSTEM_BUS) : DBus.connect_address(address))
          end

          def initialize(socket, uid: Process.uid)
            @socket = socket
            @serial = 0
            @buffer = String.new(encoding: Encoding::BINARY)
            @pending_fds = []
            @signals = []
            @method_calls = []
            @mutex = Mutex.new
            authenticate(uid)
            @unique_name = call(destination: "org.freedesktop.DBus", path: "/org/freedesktop/DBus", interface: "org.freedesktop.DBus",
                                member: "Hello").first
          end

          def close
            @socket.close unless @socket.closed?
          end
          def closed? = @socket.closed?

          # A method call; returns the reply body, raises RemoteError.
          def call(destination:, path:, interface:, member:, signature: "", args: [], timeout: 25.0)
            serial = send_message(METHOD_CALL, {FIELD_PATH => path, FIELD_INTERFACE => interface, FIELD_MEMBER => member,
                                                FIELD_DESTINATION => destination}, signature, args)
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            loop do
              message = next_message(deadline)
              raise Error, "D-Bus call #{interface}.#{member} timed out" if message.nil?

              case message.type
              when SIGNAL
                @signals << message
              when METHOD_CALL
                @method_calls << message
              when METHOD_RETURN
                return message.body if message.reply_serial == serial
              when ERROR
                raise RemoteError.new(message.error_name, message.body.first.to_s) if message.reply_serial == serial
              end
            end
          end

          # The next signal (queued ones first), or nil after +timeout+.
          def next_signal(timeout: nil)
            return @signals.shift unless @signals.empty?

            deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            loop do
              message = next_message(deadline)
              return nil if message.nil?
              return message if message.type == SIGNAL
            end
          end

          # The next method call addressed to this connection (queued ones
          # first), or nil after +timeout+ -- the service side, for tests
          # that play logind on a private bus.
          def next_method_call(timeout: nil)
            return @method_calls.shift unless @method_calls.empty?

            deadline = timeout && Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            loop do
              message = next_message(deadline)
              return nil if message.nil?

              @signals << message if message.type == SIGNAL
              return message if message.type == METHOD_CALL
            end
          end

          # RequestName (DO_NOT_QUEUE); true when this connection owns +name+.
          def request_name(name)
            call(destination: "org.freedesktop.DBus", path: "/org/freedesktop/DBus", interface: "org.freedesktop.DBus",
                 member: "RequestName", signature: "su", args: [name, NAME_FLAG_DO_NOT_QUEUE]).first == NAME_PRIMARY_OWNER
          end

          # A method return for +call+; +fds+ (IOs) travel with SCM_RIGHTS
          # and the body refers to them by index ("h").
          def reply(call, signature: "", body: [], fds: [])
            fields = {FIELD_REPLY_SERIAL => call.serial}
            fields[FIELD_DESTINATION] = call.fields[FIELD_SENDER] if call.fields[FIELD_SENDER]
            fields[FIELD_UNIX_FDS] = fds.length unless fds.empty?
            send_message(METHOD_RETURN, fields, signature, body, fds: fds)
          end

          def reply_error(call, name, text)
            fields = {FIELD_REPLY_SERIAL => call.serial, FIELD_ERROR_NAME => name}
            fields[FIELD_DESTINATION] = call.fields[FIELD_SENDER] if call.fields[FIELD_SENDER]
            send_message(ERROR, fields, "s", [text])
          end

          def emit_signal(path:, interface:, member:, signature: "", body: [])
            send_message(SIGNAL, {FIELD_PATH => path, FIELD_INTERFACE => interface, FIELD_MEMBER => member}, signature, body)
          end

          def add_match(rule)
            call(destination: "org.freedesktop.DBus", path: "/org/freedesktop/DBus", interface: "org.freedesktop.DBus",
                 member: "AddMatch", signature: "s", args: [rule])
          end

          def get_property(destination:, path:, interface:, name:)
            call(destination: destination, path: path, interface: "org.freedesktop.DBus.Properties", member: "Get",
                 signature: "ss", args: [interface, name]).first.value
          end

          private

          def authenticate(uid)
            @socket.write("\0")
            @socket.write("AUTH EXTERNAL #{uid.to_s.unpack1("H*")}\r\n")
            line = read_line
            raise Error, "D-Bus authentication failed: #{line}" unless line.start_with?("OK ")

            @socket.write("NEGOTIATE_UNIX_FD\r\n")
            line = read_line
            raise Error, "the bus does not pass unix fds: #{line}" unless line.start_with?("AGREE_UNIX_FD")

            @socket.write("BEGIN\r\n")
          end

          def read_line
            line = +""
            line << @socket.readpartial(1) until line.end_with?("\r\n")
            line.chomp
          end

          def send_message(type, fields, signature, args, fds: [])
            @mutex.synchronize do
              @serial += 1
              bytes = DBus.encode(type: type, serial: @serial, fields: fields, body_signature: signature, body: args)
              if fds.empty?
                @socket.write(bytes)
              else
                @socket.sendmsg(bytes, 0, nil, Socket::AncillaryData.unix_rights(*fds))
              end
              @serial
            end
          end

          def next_message(deadline)
            loop do
              fds_needed = 0
              if (decoded = peek_message)
                message, used, fds_needed = decoded
                if @pending_fds.length >= fds_needed
                  @buffer = @buffer.byteslice(used..) || String.new(encoding: Encoding::BINARY)
                  fds = @pending_fds.shift(fds_needed)
                  message.fds = fds
                  # Resolve the fd indexes the body refers to.
                  message.body = message.body.map { |value| value.is_a?(UnixFD) ? UnixFD.new(value.index, fds[value.index]) : value }
                  return message
                end
              end
              remaining = deadline && (deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC))
              return nil if remaining && remaining <= 0
              return nil unless @socket.wait_readable(remaining)

              data, _address, _flags, *controls = @socket.recvmsg(65_536, 0, 4096, scm_rights: true)
              raise Error, "the bus closed the connection" if data.nil? || (data.empty? && controls.empty?)

              @buffer << data.b
              controls.each { |control| @pending_fds.concat(control.unix_rights) if control.cmsg_is?(:SOCKET, :RIGHTS) }
            end
          end

          def peek_message
            decoded = DBus.decode(@buffer)
            return nil unless decoded

            message, used = decoded
            [message, used, message.fields[FIELD_UNIX_FDS].to_i]
          end
        end
      end
    end
  end
end
