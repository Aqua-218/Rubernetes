# frozen_string_literal: true

require "ipaddr"
require "digest"
require "socket"
require "fiddle"

require_relative "errors"
require_relative "support"

module Rubernetes
  module Network
    # Ruby netlink encoder/decoder.  The adapter boundary is deliberate: unit
    # tests and unprivileged controllers can inject a recording adapter, while
    # the default adapter opens AF_NETLINK/NETLINK_ROUTE and checks every ACK.
    class Netlink
      # A network namespace operation may never reopen a caller supplied
      # pathname.  The runtime proves the holder generation with pidfd and
      # /proc start time, then this lease opens the namespace once and keeps
      # that exact file description alive for the complete transaction.
      class NamespaceLease
        REQUIRED_FIELDS = %w[handle path inode pid pidfd start_time].freeze

        def self.open(context)
          new(context).tap(&:open!)
        end

        def initialize(context)
          value = context.respond_to?(:to_h) ? context.to_h : context
          @context = Support.canonical(value || {})
          @io = nil
        end

        def open!
          missing = REQUIRED_FIELDS.select { |field| Support.fetch(@context, field, default: nil).nil? }
          raise OwnershipError, "network namespace holder is missing #{missing.join(", ")}" unless missing.empty?

          @handle = Support.identifier(Support.fetch(@context, "handle"), "network namespace handle")
          @pid = Support.integer(Support.fetch(@context, "pid"), "network namespace holder PID", min: 1)
          @pidfd = Support.integer(Support.fetch(@context, "pidfd"), "network namespace holder pidfd", min: 0)
          @start_time = Support.integer(Support.fetch(@context, "start_time"), "network namespace holder start time", min: 1)
          @inode = Support.integer(Support.fetch(@context, "inode"), "network namespace inode", min: 1)
          @path = Support.string(Support.fetch(@context, "path"), "network namespace path")
          expected_path = "/proc/#{@pid}/ns/net"
          raise OwnershipError, "network namespace path does not match its holder PID" unless @path == expected_path

          verify_holder!
          @io = File.open(@path, File::RDONLY)
          raise OwnershipError, "network namespace inode changed while opening lease" unless @io.stat.ino == @inode

          # Recheck the generation and pidfd after open.  If exit/PID reuse
          # raced the open, the lease is not allowed to escape to netlink.
          verify_holder!
          self
        rescue StandardError
          close
          raise
        end

        attr_reader :handle, :path, :inode, :pid, :pidfd, :start_time

        def fileno
          raise OwnershipError, "network namespace lease is closed" unless @io && !@io.closed?

          @io.fileno
        end

        def closed?
          @io.nil? || @io.closed?
        end

        def close
          @io&.close unless @io&.closed?
          true
        end

        def to_h
          {"handle" => @handle, "path" => @path, "inode" => @inode,
           "pid" => @pid, "pidfd" => @pidfd, "start_time" => @start_time,
           "namespace_fd" => fileno}.freeze
        end

        private

        def verify_holder!
          current_start = proc_start_time(@pid)
          raise OwnershipError, "network namespace holder PID generation changed" unless current_start == @start_time

          fd_target = File.readlink("/proc/self/fd/#{@pidfd}")
          raise OwnershipError, "network namespace holder descriptor is not a pidfd" unless fd_target == "anon_inode:[pidfd]"

          fdinfo = File.read("/proc/self/fdinfo/#{@pidfd}")
          pid_line = fdinfo.each_line.find { |line| line.start_with?("Pid:") }
          fd_pid = pid_line && Integer(pid_line.split(":", 2).last.strip)
          raise OwnershipError, "network namespace pidfd belongs to a different holder" unless fd_pid == @pid

          pidfd_io = IO.for_fd(@pidfd, autoclose: false)
          raise OwnershipError, "network namespace holder pidfd is no longer alive" unless pidfd_io.wait_readable(0).nil?

          current_inode = File.stat(@path).ino
          raise OwnershipError, "network namespace path inode changed" unless current_inode == @inode
        rescue IOError, SystemCallError => error
          raise OwnershipError, "network namespace holder is unavailable: #{error.message}"
        end

        def proc_start_time(pid)
          stat = File.binread("/proc/#{pid}/stat")
          suffix = stat.rpartition(") ").last
          raise OwnershipError, "network namespace holder stat is malformed" if suffix.empty?

          Integer(suffix.split.fetch(19))
        rescue ArgumentError, IndexError => error
          raise OwnershipError, "network namespace holder stat is malformed: #{error.message}"
        end
      end

      Message = Struct.new(:type, :flags, :sequence, :payload, keyword_init: true) do
        def to_h
          {"type" => type, "flags" => flags, "sequence" => sequence, "payload" => payload}
        end
      end

      Ack = Struct.new(:sequence, :messages, :request, keyword_init: true) do
        def success?
          true
        end

        def to_h
          {"sequence" => sequence, "messages" => messages.map { |message| message.respond_to?(:to_h) ? message.to_h : message },
           "request" => request}
        end
      end

      NlmsgError = Struct.new(:errno, :message, :sequence, keyword_init: true)

      # Values in this module mirror the Linux UAPI headers listed in the
      # comments below.  Netlink uses host-endian fixed-width fields on the
      # supported little-endian Linux targets; the explicit little-endian pack
      # directives below make the layout independent of Ruby's native packing.
      AF_UNSPEC = 0
      AF_INET = 2
      AF_NETLINK = 16
      AF_BRIDGE = 7
      AF_INET6 = 10
      CLONE_NEWNET = 0x4000_0000
      IFF_UP = 0x1
      IFF_CHANGE_UP = IFF_UP

      NETLINK_ROUTE = 0
      NLM_F_REQUEST = 0x01
      NLM_F_MULTI = 0x02
      NLM_F_ACK = 0x04
      NLM_F_ECHO = 0x08
      NLM_F_REPLACE = 0x100
      NLM_F_EXCL = 0x200
      NLM_F_CREATE = 0x400
      NLM_F_APPEND = 0x800
      NLM_F_ROOT = 0x100
      NLM_F_MATCH = 0x200
      NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH
      NLMSG_NOOP = 0x01
      NLMSG_ERROR = 0x02
      NLMSG_DONE = 0x03
      RTM_NEWLINK = 16
      RTM_DELLINK = 17
      RTM_GETLINK = 18
      RTM_SETLINK = 19
      RTM_NEWADDR = 20
      RTM_DELADDR = 21
      RTM_GETADDR = 22
      RTM_NEWROUTE = 24
      RTM_DELROUTE = 25
      RTM_GETROUTE = 26
      RTM_NEWNEIGH = 28
      RTM_DELNEIGH = 29
      RTM_GETNEIGH = 30
      HEADER_SIZE = 16
      MAX_MESSAGE_BYTES = 65_536
      IFNAMSIZ = 16

      # <linux/if_link.h>: top-level link attributes.
      IFLA_ADDRESS = 1
      IFLA_IFNAME = 3
      IFLA_MTU = 4
      IFLA_MASTER = 10
      IFLA_LINKINFO = 18
      IFLA_NET_NS_FD = 28
      IFLA_NEW_IFINDEX = 37
      IFLA_INFO_KIND = 1
      IFLA_INFO_DATA = 2
      IFLA_BR_STP_STATE = 5
      VETH_INFO_PEER = 1 # <linux/veth.h>

      # <linux/if_link.h>: IFLA_INFO_DATA attributes for a VXLAN link.
      # VXLAN_PORT is stored in network byte order by the kernel UAPI.
      IFLA_VXLAN_ID = 1
      IFLA_VXLAN_GROUP = 2
      IFLA_VXLAN_LINK = 3
      IFLA_VXLAN_LOCAL = 4
      IFLA_VXLAN_TTL = 5
      IFLA_VXLAN_TOS = 6
      IFLA_VXLAN_LEARNING = 7
      IFLA_VXLAN_AGEING = 8
      IFLA_VXLAN_LIMIT = 9
      IFLA_VXLAN_PORT_RANGE = 10
      IFLA_VXLAN_PROXY = 11
      IFLA_VXLAN_RSC = 12
      IFLA_VXLAN_L2MISS = 13
      IFLA_VXLAN_L3MISS = 14
      IFLA_VXLAN_PORT = 15
      IFLA_VXLAN_GROUP6 = 16
      IFLA_VXLAN_LOCAL6 = 17
      IFLA_VXLAN_UDP_CSUM = 18
      IFLA_VXLAN_UDP_ZERO_CSUM6_TX = 19
      IFLA_VXLAN_UDP_ZERO_CSUM6_RX = 20
      IFLA_VXLAN_REMCSUM_TX = 21
      IFLA_VXLAN_REMCSUM_RX = 22
      IFLA_VXLAN_GBP = 23
      IFLA_VXLAN_REMCSUM_NOPARTIAL = 24
      IFLA_VXLAN_COLLECT_METADATA = 25

      # <linux/if_addr.h>: address attributes.
      IFA_ADDRESS = 1
      IFA_LOCAL = 2
      IFA_LABEL = 3
      IFA_BROADCAST = 4
      IFA_ANYCAST = 5
      IFA_FLAGS = 8
      IFA_RT_PRIORITY = 9
      IFA_F_DADFAILED = 0x08
      IFA_F_TENTATIVE = 0x40

      # <linux/rtnetlink.h>: route message and route attributes.
      RTPROT_STATIC = 4
      RTN_UNICAST = 1
      RT_SCOPE_UNIVERSE = 0
      RT_SCOPE_LINK = 253
      RT_TABLE_MAIN = 254
      RTA_DST = 1
      RTA_OIF = 4
      RTA_GATEWAY = 5
      RTA_PRIORITY = 6
      RTA_TABLE = 15

      # <linux/neighbour.h>: neighbour attributes/state.
      NDA_DST = 1
      NDA_LLADDR = 2
      NUD_PERMANENT = 0x80
      RTN_UNSPEC = 0

      # The public API historically called bridge FDB operations fdb_*.
      # Keep those names and expose the native rtnetlink terminology too.
      NTF_SELF = 0x02

      module TLV
        module_function

        def align(length)
          (Integer(length) + 3) & ~3
        end

        def encode(type, value, nested: false)
          attribute_type = Integer(type)
          attribute_type |= 0x8000 if nested
          body = encode_value(value)
          length = 4 + body.bytesize
          [length, attribute_type].pack("S<S<") + body + ("\0" * (align(length) - length))
        rescue ArgumentError, TypeError => error
          raise ValidationError, "invalid netlink attribute #{type.inspect}: #{error.message}"
        end

        def encode_many(attributes)
          Array(attributes).map do |attribute|
            if attribute.is_a?(Hash)
              type = Support.fetch(attribute, "type")
              value = Support.fetch(attribute, "value")
              encode(type, value, nested: Support.bool(Support.fetch(attribute, "nested", default: false)))
            else
              type, value = Array(attribute)
              encode(type, value)
            end
          end.join
        end

        def decode(buffer)
          bytes = String(buffer).b
          attributes = []
          offset = 0
          while offset + 4 <= bytes.bytesize
            length, type = bytes.byteslice(offset, 4).unpack("S<S<")
            break if length < 4 || offset + length > bytes.bytesize

            body = bytes.byteslice(offset + 4, length - 4)
            attributes << {"type" => type & 0x3fff, "nested" => type.anybits?(0x8000), "value" => body}
            offset += align(length)
          end
          raise NetlinkError, "netlink attribute stream is truncated" unless offset == bytes.bytesize

          attributes.freeze
        end

        def encode_value(value)
          case value
          when String then value.b
          when Integer then [value].pack("L<")
          when IPAddr then value.hton
          when Array then encode_many(value)
          else
            raise TypeError, "unsupported attribute value #{value.class}" unless value.respond_to?(:to_str)

            value.to_str.b

          end
        end
        private_class_method :encode_value
      end

      # Default production adapter.  It does not expose policy methods; it
      # only transmits already-encoded requests and decodes kernel messages.
      class SocketAdapter
        def initialize(socket_factory: nil, timeout: 2.0)
          @socket_factory = socket_factory || method(:open_socket)
          @timeout = Float(timeout)
          raise ValidationError, "netlink timeout must be positive" unless @timeout.positive?
        end

        def request(type:, flags:, sequence:, payload: "", attributes: [])
          socket = @socket_factory.call
          socket.bind([AF_NETLINK, 0, 0, 0].pack("S<S<L<L<")) if socket.respond_to?(:bind)
          body = String(payload).b << TLV.encode_many(attributes)
          message = [HEADER_SIZE + body.bytesize, Integer(type), Integer(flags), Integer(sequence), 0].pack("L<S<S<L<L<") + body
          sent = socket.send(message, 0)
          raise NetlinkError, "netlink request was short-written" unless sent == message.bytesize

          receive(socket, sequence: Integer(sequence))
        rescue SystemCallError => error
          raise NetlinkError.new("netlink request failed: #{error.message}", errno: error.respond_to?(:errno) ? error.errno : nil,
                                                                             operation: "netlink")
        ensure
          socket&.close
        end

        private

        def open_socket
          Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, Netlink::NETLINK_ROUTE)
        end

        def receive(socket, sequence:)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
          messages = []
          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            if remaining <= 0 || socket.wait_readable(remaining).nil?
              raise NetlinkError.new("netlink ACK timed out", errno: Errno::ETIMEDOUT::Errno,
                                                              operation: "netlink_ack", sequence: sequence)
            end
            parse_messages(socket.recv(MAX_MESSAGE_BYTES)).each do |message|
              next unless message.sequence == sequence

              if message.type == NLMSG_ERROR
                code = message.payload.bytesize >= 4 ? message.payload.unpack1("l<") : -Errno::EPROTO::Errno
                unless code.zero?
                  errno = code.abs
                  raise NetlinkError.new("kernel rejected netlink request with errno #{errno}", errno: errno,
                                                                                                operation: "netlink_ack", sequence: sequence)
                end
                messages << message
                return Ack.new(sequence: sequence, messages: messages.freeze, request: nil).freeze
              end
              messages << message
              return Ack.new(sequence: sequence, messages: messages.freeze, request: nil).freeze if message.type == NLMSG_DONE
            end
          end
        end

        def parse_messages(buffer)
          bytes = String(buffer).b
          messages = []
          offset = 0
          while offset + HEADER_SIZE <= bytes.bytesize
            length, type, flags, sequence, = bytes.byteslice(offset, HEADER_SIZE).unpack("L<S<S<L<L<")
            raise NetlinkError, "netlink message has invalid length" if length < HEADER_SIZE || offset + length > bytes.bytesize

            messages << Message.new(type: type, flags: flags, sequence: sequence,
                                    payload: bytes.byteslice(offset + HEADER_SIZE, length - HEADER_SIZE).freeze)
            offset += TLV.align(length)
          end
          raise NetlinkError, "netlink message stream is truncated" unless offset == bytes.bytesize

          messages
        end
      end

      def initialize(adapter: nil, sequence: 0, timeout: 2.0)
        @adapter = adapter || SocketAdapter.new(timeout: timeout)
        @mutex = Mutex.new
        @sequence = Integer(sequence)
      end

      attr_reader :adapter

      def next_sequence
        @mutex.synchronize do
          @sequence = (@sequence + 1) & 0xffff_ffff
          @sequence = 1 if @sequence.zero?
          @sequence
        end
      end

      def request(type:, payload: "", attributes: [], flags: NLM_F_REQUEST | NLM_F_ACK,
                  sequence: nil, operation: nil)
        sequence ||= next_sequence
        sequence = Support.integer(sequence, "netlink sequence", min: 1, max: 0xffff_ffff)
        request = {"type" => Integer(type), "flags" => Integer(flags), "sequence" => Integer(sequence),
                   "payload" => String(payload).b, "attributes" => normalize_attributes(attributes),
                   "operation" => operation && String(operation)}
        encoded_size = HEADER_SIZE + request.fetch("payload").bytesize + TLV.encode_many(request.fetch("attributes")).bytesize
        raise ValidationError, "netlink message exceeds #{MAX_MESSAGE_BYTES} bytes" if encoded_size > MAX_MESSAGE_BYTES

        response = dispatch(request)
        validate_response!(response, request)
        normalize_ack(response, request)
      end

      # Issue a rtnetlink dump and return the kernel data messages.  Unlike a
      # mutation this request terminates with NLMSG_DONE rather than a
      # mutation ACK; every sequence and NLMSG_ERROR is still validated.
      def dump(type:, payload: "", attributes: [], flags: NLM_F_REQUEST | NLM_F_DUMP,
               namespace: nil, namespace_fd: nil, operation: nil)
        namespace_target = namespace_fd || namespace
        validate_namespace_target!(namespace_target)
        if kernel_adapter? && namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            dump(type: type, payload: payload, attributes: attributes, flags: flags, operation: operation)
          end
        end

        sequence = next_sequence
        request = {"type" => Integer(type), "flags" => Integer(flags), "sequence" => sequence,
                   "payload" => String(payload).b, "attributes" => normalize_attributes(attributes),
                   "operation" => operation && String(operation)}
        encoded_size = HEADER_SIZE + request.fetch("payload").bytesize + TLV.encode_many(request.fetch("attributes")).bytesize
        raise ValidationError, "netlink dump message exceeds #{MAX_MESSAGE_BYTES} bytes" if encoded_size > MAX_MESSAGE_BYTES

        response = dispatch(request)
        messages = response.is_a?(Ack) ? response.messages : Array(response).map { |entry| normalize_message(entry, request) }
        raise NetlinkError.new("netlink dump returned no response", operation: operation, sequence: sequence) if messages.empty?

        messages.each { |message| validate_message!(message.to_h, request) if message.type == NLMSG_ERROR }
        unless messages.any? { |message| message.type == NLMSG_DONE }
          raise NetlinkError.new("netlink dump did not terminate with NLMSG_DONE", operation: operation, sequence: sequence)
        end

        messages.reject { |message| [NLMSG_DONE, NLMSG_NOOP, NLMSG_ERROR].include?(message.type) }.freeze
      end

      def link_dump(namespace: nil, namespace_fd: nil, operation: "link_dump")
        dump(type: RTM_GETLINK, payload: ifinfomsg(index: 0), namespace: namespace,
             namespace_fd: namespace_fd, operation: operation)
      end

      # One link by name (RTM_GETLINK with IFLA_IFNAME, not a dump): the
      # kernel answers with that link's RTM_NEWLINK, or ENODEV.  Proving that
      # a Pod's veth exists used to dump and parse every link on the node --
      # one per Pod -- after each of an attach's link operations.
      def link_get(name:, operation: "link_get")
        response = request(type: RTM_GETLINK, payload: ifinfomsg(index: 0),
                           attributes: [attribute(IFLA_IFNAME, c_string(name))], operation: operation)
        Array(response.messages).select { |message| message.type == RTM_NEWLINK }.freeze
      rescue NetlinkError => error
        return [].freeze if [Errno::ENODEV::Errno, Errno::ENOENT::Errno].include?(error.errno)

        raise
      end

      def address_dump(namespace: nil, namespace_fd: nil, operation: "address_dump")
        dump(type: RTM_GETADDR, payload: [AF_UNSPEC, 0, 0, 0, 0].pack("CCCCL<"), namespace: namespace,
             namespace_fd: namespace_fd, operation: operation)
      end

      def route_dump(namespace: nil, namespace_fd: nil, operation: "route_dump")
        dump(type: RTM_GETROUTE, payload: rtmsg(family: AF_UNSPEC, prefix: 0, table: 0, protocol: 0,
                                                scope: 0, type: 0), namespace: namespace,
             namespace_fd: namespace_fd, operation: operation)
      end

      def neighbor_dump(namespace: nil, namespace_fd: nil, operation: "neighbor_dump")
        # AF_BRIDGE is required for the kernel to return bridge/VXLAN FDB
        # entries. An AF_UNSPEC dump is valid but commonly returns no FDB
        # records, which would make an ownership observer falsely report a
        # missing resource.
        dump(type: RTM_GETNEIGH, payload: [AF_BRIDGE, 0, 0, 0, 0, 0, 0].pack("CCS<l<S<CC"), namespace: namespace,
             namespace_fd: namespace_fd, operation: operation)
      end

      def link_add(name:, kind:, mtu: nil, index: nil, master: nil, up: true, peer: nil, namespace: nil,
                   namespace_fd: nil, operation: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        unless kernel_adapter?
          return legacy_link_add(name: name, kind: kind, mtu: mtu, index: index, master: master, up: up,
                                 peer: peer, namespace: namespace, namespace_fd: namespace_fd,
                                 operation: operation, attributes: attributes)
        end

        namespace_target = namespace_fd || namespace
        name = interface_name(name)
        kind = Support.string(kind, "link kind").downcase
        flags = Support.bool(up, default: true) ? IFF_UP : 0
        payload = ifinfomsg(index: 0, flags: flags, change: IFF_CHANGE_UP)
        link_attributes = [attribute(IFLA_IFNAME, c_string(name))]
        link_attributes << attribute(IFLA_MTU, uint32(mtu, "MTU")) if mtu
        link_attributes << attribute(IFLA_MASTER, link_index(master, "master")) if master
        link_attributes << attribute(IFLA_NEW_IFINDEX, uint32(index, "link index")) if index
        if namespace_target && !(kind == "veth" && peer)
          link_attributes << attribute(IFLA_NET_NS_FD,
                                       uint32(namespace_fd_value(namespace_target),
                                              "network namespace FD"))
        end
        link_attributes << link_info_attributes(kind, peer: peer, namespace: namespace, namespace_fd: namespace_fd,
                                                      attributes: attributes)
        request(type: RTM_NEWLINK, payload: payload,
                flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                attributes: link_attributes, operation: operation)
      end

      def link_delete(name: nil, index: nil, namespace: nil, namespace_fd: nil, operation: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        return legacy_link_delete(name: name, index: index, operation: operation, attributes: attributes) unless kernel_adapter?

        namespace_target = namespace_fd || namespace
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            link_delete(name: name, index: index, operation: operation, **attributes)
          end
        end

        link_index = link_index(name || index, "link")
        request(type: RTM_DELLINK, payload: ifinfomsg(index: link_index), operation: operation)
      end

      # Return the state needed to safely undo a link mutation.  The lookup is
      # intentionally performed in the requested namespace, so the ifindex
      # and sysfs identity cannot accidentally refer to the host namespace.
      def link_state(name: nil, index: nil, namespace: nil, namespace_fd: nil)
        raise ValidationError, "link name or positive link index is required" unless name || index

        namespace_target = namespace_fd || namespace
        validate_namespace_target!(namespace_target)
        if kernel_adapter? && namespace_target
          return with_network_namespace(namespace_target) do
            link_state(name: name, index: index)
          end
        end

        # Sysfs is not reliably network-namespace aware (notably in a
        # container whose /sys mount belongs to the host). Use rtnetlink's
        # in-namespace dump for the authoritative ifindex, flags, MTU, MAC,
        # and master state whenever the production socket is available.
        return link_state_from_dump(name: name, index: index) if kernel_adapter?

        selected_name = name && interface_name(name)
        selected_index = index && Support.integer(index, "link index", min: 1)
        selected_name = Socket.getifaddrs.find { |entry| entry.ifindex == selected_index }&.name if selected_name.nil?
        selected_name = interface_name(selected_name)
        selected_index ||= link_index(selected_name, "link")
        sysfs = File.join("/sys/class/net", selected_name)
        address_path = File.join(sysfs, "address")
        mtu_path = File.join(sysfs, "mtu")
        address = File.file?(address_path) ? File.read(address_path).strip.downcase : nil
        mtu = File.file?(mtu_path) ? Integer(File.read(mtu_path).strip) : nil
        flags = Socket.getifaddrs.find { |entry| entry.name == selected_name }&.flags || 0
        master_path = File.join(sysfs, "master")
        master = File.symlink?(master_path) ? File.basename(File.realpath(master_path)) : nil
        kind = "bridge" if File.directory?(File.join(sysfs, "bridge"))
        {
          "name" => selected_name,
          "index" => selected_index,
          "up" => flags.anybits?(IFF_UP),
          "mtu" => mtu,
          "master" => master,
          "kind" => kind,
          "mac" => address,
          "netns_inode" => File.stat(THREAD_NAMESPACE_PATH).ino
        }.compact.freeze
      rescue SocketError, SystemCallError => error
        raise NetlinkError.new("failed to observe link state: #{error.message}",
                               errno: error.respond_to?(:errno) ? error.errno : Errno::ENODEV::Errno,
                               operation: "link_state")
      end

      def link_set(name: nil, index: nil, mtu: nil, up: nil, master: nil, namespace: nil, namespace_fd: nil,
                   operation: nil, move_namespace: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        validate_namespace_target!(move_namespace)
        unless kernel_adapter?
          return legacy_link_set(name: name, index: index, mtu: mtu, up: up, master: master, namespace: namespace,
                                 namespace_fd: namespace_fd, operation: operation, attributes: attributes)
        end

        namespace_target = namespace_fd || namespace
        if namespace_target && move_namespace.nil?
          begin
            return with_network_namespace(namespace_target, operation: operation) do
              link_set(name: name, index: index, mtu: mtu, up: up, master: master, operation: operation, **attributes)
            end
          rescue NetlinkError => error
            # A veth peer may still be in the caller namespace when the
            # caller asks us to move it.  The target-scoped lookup correctly
            # fails with ENODEV in that case; retry the RTM_SETLINK against
            # the source namespace while retaining IFLA_NET_NS_FD.  Any
            # permission/protocol error remains fail-closed.
            raise unless [Errno::ENODEV::Errno, Errno::ENOENT::Errno].include?(error.errno)

            move_namespace = namespace_target
          end
        end

        link_index = link_index(name || index, "link")
        flags = if up.nil?
                  0
                else
                  (Support.bool(up) ? IFF_UP : 0)
                end
        change = up.nil? ? 0 : IFF_CHANGE_UP
        payload = ifinfomsg(index: link_index, flags: flags, change: change)
        link_attributes = []
        link_attributes << attribute(IFLA_MTU, uint32(mtu, "MTU")) if mtu
        clear_master = Support.bool(Support.fetch(attributes, "clear_master", default: false))
        if master || clear_master
          link_attributes << attribute(IFLA_MASTER,
                                       master ? link_index(master, "master") : uint32(0, "master index"))
        end
        namespace_value = move_namespace || namespace_fd || namespace
        link_attributes << attribute(IFLA_NET_NS_FD, uint32(namespace_fd_value(namespace_value), "network namespace FD")) if namespace_value
        link_attributes.concat(encode_link_extra_attributes(attributes))
        request(type: RTM_SETLINK, payload: payload, attributes: link_attributes, operation: operation)
      end

      def address_add(address:, prefix: nil, index: nil, name: nil, namespace: nil, namespace_fd: nil, operation: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        unless kernel_adapter?
          return legacy_address_request(RTM_NEWADDR, address: address, prefix: prefix, index: index, name: name,
                                                     operation: operation, attributes: attributes,
                                                     flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
        end

        namespace_target = namespace_fd || namespace
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            address_add(address: address, prefix: prefix, index: index, name: name, operation: operation, **attributes)
          end
        end

        address_request(RTM_NEWADDR, address: address, prefix: prefix, index: index, name: name,
                                     operation: operation, attributes: attributes,
                                     flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
      end

      def address_delete(address:, prefix: nil, index: nil, name: nil, namespace: nil, namespace_fd: nil, operation: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        unless kernel_adapter?
          return legacy_address_request(RTM_DELADDR, address: address, prefix: prefix, index: index, name: name,
                                                     operation: operation, attributes: attributes, flags: NLM_F_REQUEST | NLM_F_ACK)
        end

        namespace_target = namespace_fd || namespace
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            address_delete(address: address, prefix: prefix, index: index, name: name, operation: operation, **attributes)
          end
        end

        address_request(RTM_DELADDR, address: address, prefix: prefix, index: index, name: name,
                                     operation: operation, attributes: attributes, flags: NLM_F_REQUEST | NLM_F_ACK)
      end

      def route_add(destination:, via: nil, dev: nil, table: 254, metric: nil, family: nil, namespace: nil, namespace_fd: nil,
                    operation: nil, **attributes)
        namespace_target = namespace_fd || namespace
        validate_namespace_target!(namespace_target)
        if kernel_adapter? && namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            route_add(destination: destination, via: via, dev: dev, table: table, metric: metric, family: family,
                      operation: operation, **attributes)
          end
        end
        route_request(RTM_NEWROUTE, destination: destination, via: via, dev: dev, table: table, metric: metric,
                                    family: family, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                                    operation: operation, attributes: attributes)
      end

      def route_delete(destination:, via: nil, dev: nil, table: 254, metric: nil, family: nil, namespace: nil, namespace_fd: nil,
                       operation: nil, **attributes)
        namespace_target = namespace_fd || namespace
        validate_namespace_target!(namespace_target)
        if kernel_adapter? && namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            route_delete(destination: destination, via: via, dev: dev, table: table, metric: metric, family: family,
                         operation: operation, **attributes)
          end
        end
        route_request(RTM_DELROUTE, destination: destination, via: via, dev: dev, table: table, metric: metric,
                                    family: family, flags: NLM_F_REQUEST | NLM_F_ACK, operation: operation, attributes: attributes)
      end

      def fdb_add(mac:, destination:, dev:, namespace: nil, namespace_fd: nil, operation: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        unless kernel_adapter?
          return legacy_fdb_request(RTM_NEWNEIGH, mac: mac, destination: destination, dev: dev,
                                                  operation: operation, attributes: attributes,
                                                  flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
        end

        namespace_target = namespace_fd || namespace
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            fdb_add(mac: mac, destination: destination, dev: dev, operation: operation, **attributes)
          end
        end

        neighbor_request(RTM_NEWNEIGH, destination: destination, lladdr: mac, dev: dev, family: AF_BRIDGE,
                                       state: NUD_PERMANENT, ndm_flags: NTF_SELF, operation: operation,
                                       flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, attributes: attributes)
      end

      def fdb_delete(mac:, destination:, dev:, namespace: nil, namespace_fd: nil, operation: nil, **attributes)
        validate_namespace_target!(namespace_fd || namespace)
        unless kernel_adapter?
          return legacy_fdb_request(RTM_DELNEIGH, mac: mac, destination: destination, dev: dev,
                                                  operation: operation, attributes: attributes,
                                                  flags: NLM_F_REQUEST | NLM_F_ACK)
        end

        namespace_target = namespace_fd || namespace
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            fdb_delete(mac: mac, destination: destination, dev: dev, operation: operation, **attributes)
          end
        end

        neighbor_request(RTM_DELNEIGH, destination: destination, lladdr: mac, dev: dev, family: AF_BRIDGE,
                                       state: 0, ndm_flags: NTF_SELF, operation: operation, flags: NLM_F_REQUEST | NLM_F_ACK,
                                       attributes: attributes)
      end

      # Native neighbour terminology is useful to callers that are not
      # managing bridge FDB entries.  The older fdb_* methods above remain the
      # compatibility surface used by the topology planner.
      def neighbor_add(destination:, dev:, lladdr: nil, mac: nil, family: nil, state: NUD_PERMANENT, flags: 0,
                       namespace: nil, namespace_fd: nil, operation: nil, **attributes)
        lladdr ||= mac
        raise ValidationError, "neighbour link-layer address is required" unless lladdr

        namespace_target = namespace_fd || namespace
        validate_namespace_target!(namespace_target)
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            neighbor_add(destination: destination, dev: dev, lladdr: lladdr, family: family, state: state,
                         flags: flags, operation: operation, **attributes)
          end
        end

        neighbor_request(RTM_NEWNEIGH, destination: destination, lladdr: lladdr, dev: dev, family: family,
                                       state: state, ndm_flags: flags, operation: operation,
                                       flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, attributes: attributes)
      end

      def neighbor_delete(destination:, dev:, lladdr: nil, mac: nil, family: nil, namespace: nil, namespace_fd: nil,
                          operation: nil, **attributes)
        lladdr ||= mac
        namespace_target = namespace_fd || namespace
        validate_namespace_target!(namespace_target)
        if namespace_target
          return with_network_namespace(namespace_target, operation: operation) do
            neighbor_delete(destination: destination, dev: dev, lladdr: lladdr, family: family,
                            operation: operation, **attributes)
          end
        end

        neighbor_request(RTM_DELNEIGH, destination: destination, lladdr: lladdr, dev: dev, family: family,
                                       state: 0, ndm_flags: 0, operation: operation, flags: NLM_F_REQUEST | NLM_F_ACK,
                                       attributes: attributes)
      end

      # Public read-only namespace boundary used by NativeObserver.  Mutating
      # callers should use the operation-specific namespace arguments above.
      def with_namespace(target, operation: "namespace_scope", &block)
        raise ArgumentError, "namespace scope requires a block" unless block

        with_network_namespace(target, operation: operation, &block)
      end

      private

      # Execute a request in the target network namespace without changing
      # the namespace of the process.  setns(2) with CLONE_NEWNET acts on the
      # calling native thread only; MRI runs each Ruby thread on its own
      # native thread and never migrates a running block between them, so the
      # switch is invisible to every other thread.  The block opens its own
      # rtnetlink socket, which therefore belongs to the target namespace,
      # and the thread re-enters the host namespace before returning.
      #
      # This used to fork a child per call.  Forking a worker agent that had
      # grown to several GB copied its page tables (tens of milliseconds) and
      # stalled every other thread on the mm lock while it did; a Pod attach
      # needed about seven such forks and network readiness took seconds.
      # The fork remains only for M:N threading (RUBY_MN_THREADS=1), where a
      # Ruby thread may move between native threads.
      NAMESPACE_TAINT_KEY = :rubernetes_netns_tainted
      THREAD_NAMESPACE_PATH = "/proc/thread-self/ns/net"

      def with_network_namespace(target, operation: nil, &)
        return yield unless kernel_adapter?
        return with_network_namespace_forked(target, operation: operation, &) if self.class.fork_for_namespaces?

        if Thread.current[NAMESPACE_TAINT_KEY]
          raise NetlinkError.new("thread did not return to the host network namespace earlier; refusing #{operation || "netlink"} on it",
                                 errno: Errno::EIO::Errno, operation: operation)
        end

        namespace_fd, close_namespace_fd = open_namespace_target(target)
        host_namespace = File.open(THREAD_NAMESPACE_PATH, File::RDONLY)
        enter_namespace(namespace_fd, operation)
        begin
          yield
        ensure
          begin
            enter_namespace(host_namespace.fileno, "#{operation || "netlink"}:restore")
          rescue StandardError => error
            # The thread is stuck in a Pod namespace: never run host netlink
            # on it again.  Restoring fails only on a broken kernel or lost
            # privileges, so this is a hard error, not a retry.
            Thread.current[NAMESPACE_TAINT_KEY] = true
            raise NetlinkError.new("failed to return to the host network namespace: #{error.message}",
                                   errno: error.respond_to?(:errno) ? error.errno : Errno::EIO::Errno, operation: operation)
          end
        end
      ensure
        host_namespace&.close
        close_namespace_fd&.close unless close_namespace_fd&.closed?
      end

      def self.fork_for_namespaces?
        return @fork_for_namespaces unless @fork_for_namespaces.nil?

        @fork_for_namespaces = ENV["RUBY_MN_THREADS"] == "1"
      end

      class << self
        attr_writer :fork_for_namespaces
      end

      def enter_namespace(namespace_fd, operation)
        result = setns_function.call(namespace_fd, CLONE_NEWNET)
        return unless result == -1

        errno = Fiddle.last_error.to_i
        raise NetlinkError.new("setns(CLONE_NEWNET) failed", errno: errno.zero? ? Errno::EPERM::Errno : errno,
                                                             operation: operation)
      end

      # Fork-based variant: the child enters the namespace, runs the block,
      # and returns only the marshalled result.
      def with_network_namespace_forked(target, operation: nil)
        namespace_fd, close_namespace_fd = open_namespace_target(target)
        reader, writer = IO.pipe
        child_pid = fork do
          reader.close
          payload = nil
          begin
            enter_namespace(namespace_fd, operation)
            payload = {"ok" => true, "value" => yield}
          rescue Exception => error # rubocop:disable Lint/RescueException
            payload = {"ok" => false, "error" => serialize_namespace_error(error)}
          ensure
            begin
              writer.write(Marshal.dump(payload)) if payload
              writer.flush
            rescue StandardError
              nil
            ensure
              writer.close unless writer.closed?
            end
            exit!(payload && payload["ok"] == true ? 0 : 1)
          end
        end
        writer.close
        encoded = reader.read
        reader.close
        _pid, status = Process.wait2(child_pid)
        result = encoded && !encoded.empty? ? Marshal.load(encoded) : nil # rubocop:disable Security/MarshalLoad
        unless status.success? && result.is_a?(Hash) && result["ok"] == true
          raise_namespace_error(result && result["error"], operation: operation, status: status)
        end

        result.fetch("value")
      ensure
        reader&.close unless reader&.closed?
        writer&.close unless writer&.closed?
        close_namespace_fd&.close unless close_namespace_fd&.closed?
      end

      def setns_function
        @setns_function ||= Fiddle::Function.new(
          Fiddle::Handle::DEFAULT["setns"], [Fiddle::TYPE_INT, Fiddle::TYPE_INT], Fiddle::TYPE_INT
        )
      rescue Fiddle::DLError => error
        raise NetlinkError.new("setns(2) is unavailable: #{error.message}", errno: Errno::ENOSYS::Errno,
                                                                            operation: "setns")
      end

      def open_namespace_target(target)
        return [Support.integer(target, "network namespace FD", min: 0), nil] if target.is_a?(Integer)
        return [Support.integer(target.fileno, "network namespace FD", min: 0), nil] if target.respond_to?(:fileno)

        raise ValidationError, "network namespace must be a verified open FD lease"
      end

      def serialize_namespace_error(error)
        {"class" => error.class.name, "message" => error.message,
         "errno" => error.respond_to?(:errno) ? error.errno : nil,
         "operation" => error.respond_to?(:operation) ? error.operation : nil,
         "sequence" => error.respond_to?(:sequence) ? error.sequence : nil}
      end

      def raise_namespace_error(details, operation:, status:)
        details ||= {"message" => "namespace netlink worker exited with #{status.inspect}"}
        message = details["message"] || "namespace netlink worker failed"
        errno = details["errno"]
        error_operation = details["operation"] || operation
        error_sequence = details["sequence"]
        raise NetlinkError.new(message, errno: errno, operation: error_operation, sequence: error_sequence)
      end

      def dispatch(request)
        if @adapter.respond_to?(:request)
          @adapter.request(**request.reject { |key, _| key == "operation" }.transform_keys(&:to_sym))
        elsif @adapter.respond_to?(:call)
          @adapter.call(request)
        else
          raise NetlinkError, "netlink adapter must respond to request or call"
        end
      rescue NetlinkError
        raise
      rescue StandardError => error
        raise NetlinkError.new("netlink adapter failed: #{error.message}", operation: request.fetch("operation"),
                                                                           sequence: request.fetch("sequence"))
      end

      def validate_response!(response, request)
        if response.nil?
          raise NetlinkError.new("netlink adapter returned no response", operation: request.fetch("operation"),
                                                                         sequence: request.fetch("sequence"))
        end

        if response.is_a?(Ack)
          unless response.sequence == request.fetch("sequence")
            raise NetlinkError.new("netlink ACK sequence mismatch", operation: request.fetch("operation"),
                                                                    sequence: request.fetch("sequence"))
          end

          messages = Array(response.messages)
          if messages.empty?
            raise NetlinkError.new("netlink adapter returned no ACK message", operation: request.fetch("operation"),
                                                                              sequence: request.fetch("sequence"))
          end

          acknowledged = false
          messages.each do |message|
            acknowledged ||= [NLMSG_ERROR, NLMSG_DONE].include?(message.type)
            validate_message!(message.to_h, request)
          end
          unless acknowledged
            raise NetlinkError.new("netlink response did not contain an ACK", operation: request.fetch("operation"),
                                                                              sequence: request.fetch("sequence"))
          end

          return
        end
        values = response.is_a?(Array) ? response : [response]
        if values.empty?
          raise NetlinkError.new("netlink adapter returned an empty response", operation: request.fetch("operation"),
                                                                               sequence: request.fetch("sequence"))
        end

        acknowledged = false
        values.each do |entry|
          hash = entry.respond_to?(:to_h) ? entry.to_h : entry
          unless hash.is_a?(Hash)
            raise NetlinkError.new("netlink adapter returned a non-object response", operation: request.fetch("operation"),
                                                                                     sequence: request.fetch("sequence"))
          end

          type_value = Support.fetch(hash, "type", default: nil)
          type_number = begin
            Integer(type_value)
          rescue ArgumentError, TypeError
            nil
          end
          acknowledged ||= [NLMSG_ERROR, NLMSG_DONE].include?(type_number)
          acknowledged ||= hash.key?("error") || hash.key?(:error) || hash.key?("errno") || hash.key?(:errno)
          validate_message!(hash, request)
        end
        return if acknowledged

        raise NetlinkError.new("netlink response did not contain an ACK", operation: request.fetch("operation"),
                                                                          sequence: request.fetch("sequence"))
      end

      def validate_message!(hash, request)
        type_value = Support.fetch(hash, "type", default: nil)
        type = type_value.nil? ? nil : Integer(type_value)
        response_sequence = Support.fetch(hash, "sequence", default: nil)
        if response_sequence.nil?
          raise NetlinkError.new("netlink response has no sequence", operation: request.fetch("operation"),
                                                                     sequence: request.fetch("sequence"))
        end
        if Integer(response_sequence) != request.fetch("sequence")
          raise NetlinkError.new("netlink response sequence mismatch", operation: request.fetch("operation"),
                                                                       sequence: request.fetch("sequence"))
        end

        error_code = Support.fetch(hash, "error", "errno", default: nil)
        if error_code.nil? && type == NLMSG_ERROR
          payload = Support.fetch(hash, "payload", default: "")
          error_code = String(payload).bytesize >= 4 ? String(payload).unpack1("l<") : -Errno::EPROTO::Errno
        end
        return unless type == NLMSG_ERROR || !error_code.nil?

        code = Integer(error_code || 0)
        return if code.zero?

        raise NetlinkError.new("kernel rejected #{request.fetch("operation", "netlink")} with errno #{code.abs}",
                               errno: code.abs, operation: request.fetch("operation"), sequence: request.fetch("sequence"))
      rescue ArgumentError, TypeError => error
        raise NetlinkError.new("invalid netlink response: #{error.message}", operation: request.fetch("operation"),
                                                                             sequence: request.fetch("sequence"))
      end

      def normalize_ack(response, request)
        return response if response.is_a?(Ack)

        messages = Array(response).map do |entry|
          if entry.is_a?(Message)
            entry
          else
            hash = entry.respond_to?(:to_h) ? entry.to_h : entry
            Message.new(type: Support.fetch(hash, "type", default: NLMSG_DONE),
                        flags: Support.fetch(hash, "flags", default: 0),
                        sequence: Support.fetch(hash, "sequence", default: request.fetch("sequence")),
                        payload: String(Support.fetch(hash, "payload", default: "")).b.freeze).freeze
          end
        end
        Ack.new(sequence: request.fetch("sequence"), messages: messages.freeze, request: request).freeze
      end

      def normalize_message(entry, request)
        return entry if entry.is_a?(Message)

        hash = entry.respond_to?(:to_h) ? entry.to_h : entry
        Message.new(type: Support.fetch(hash, "type", default: NLMSG_DONE),
                    flags: Support.fetch(hash, "flags", default: 0),
                    sequence: Support.fetch(hash, "sequence", default: request.fetch("sequence")),
                    payload: String(Support.fetch(hash, "payload", default: "")).b.freeze).freeze
      end

      def normalize_attributes(attributes)
        Array(attributes).map do |attribute|
          if attribute.is_a?(Hash)
            {"type" => attribute_id(Support.fetch(attribute, "type")),
             "value" => attribute_value(Support.fetch(attribute, "value")),
             "nested" => Support.bool(Support.fetch(attribute, "nested", default: false))}
          else
            key, value = Array(attribute)
            {"type" => attribute_id(key), "value" => attribute_value(value), "nested" => false}
          end
        end.freeze
      end

      def kernel_adapter?
        @adapter.is_a?(SocketAdapter)
      end

      def attribute(type, value, nested: false)
        {"type" => Integer(type), "value" => value, "nested" => nested}
      end

      def c_string(value)
        String(value).b << "\0"
      end

      def uint8(value, name)
        [Support.integer(value, name, min: 0, max: 0xff)].pack("C")
      end

      def uint16(value, name)
        [Support.integer(value, name, min: 0, max: 0xffff)].pack("S<")
      end

      def uint16_be(value, name)
        [Support.integer(value, name, min: 0, max: 0xffff)].pack("S>")
      end

      def uint32(value, name)
        [Support.integer(value, name, min: 0, max: 0xffff_ffff)].pack("L<")
      end

      # Linux UAPI: struct ifinfomsg (16 bytes).
      def ifinfomsg(index:, flags: 0, change: 0)
        [AF_UNSPEC, 0, 0, Support.integer(index, "link index", min: 0),
         Support.integer(flags, "link flags", min: 0, max: 0xffff_ffff),
         Support.integer(change, "link change mask", min: 0, max: 0xffff_ffff)].pack("CCS<l<L<L<")
      end

      def ifaddrmsg(family:, prefix:, index:, flags: 0, scope: 0)
        [family, Support.integer(prefix, "address prefix", min: 0, max: 128),
         Support.integer(flags, "address flags", min: 0, max: 0xff),
         Support.integer(scope, "address scope", min: 0, max: 0xff),
         Support.integer(index, "link index", min: 1, max: 0xffff_ffff)].pack("CCCCL<")
      end

      def rtmsg(family:, prefix:, table:, protocol:, scope:, type:, flags: 0)
        [family, Support.integer(prefix, "route prefix", min: 0, max: 128), 0, 0,
         Support.integer(table, "route table", min: 0, max: 0xff),
         Support.integer(protocol, "route protocol", min: 0, max: 0xff),
         Support.integer(scope, "route scope", min: 0, max: 0xff),
         Support.integer(type, "route type", min: 0, max: 0xff),
         Support.integer(flags, "route flags", min: 0, max: 0xffff_ffff)].pack("CCCCCCCCL<")
      end

      # Linux UAPI: struct ndmsg (12 bytes).
      def ndmsg(family:, index:, state:, flags: 0, type: RTN_UNICAST)
        [family, 0, 0, Support.integer(index, "link index", min: 1, max: 0xffff_ffff),
         Support.integer(state, "neighbour state", min: 0, max: 0xffff),
         Support.integer(flags, "neighbour flags", min: 0, max: 0xff),
         Support.integer(type, "neighbour type", min: 0, max: 0xff)].pack("CCS<l<S<CC")
      end

      def link_info_attributes(kind, peer:, namespace:, namespace_fd:, attributes:)
        info = [attribute(IFLA_INFO_KIND, c_string(kind))]
        data = []
        if kind == "veth"
          peer_name = peer_name_from(peer)
          raise ValidationError, "veth link requires a peer interface name" unless peer_name

          peer_attrs = [attribute(IFLA_IFNAME, c_string(peer_name))]
          peer_namespace = namespace_fd || namespace
          peer_attrs << attribute(IFLA_NET_NS_FD, uint32(namespace_fd_value(peer_namespace), "network namespace FD")) if peer_namespace
          data << attribute(VETH_INFO_PEER, ifinfomsg(index: 0) + TLV.encode_many(peer_attrs), nested: true)
        elsif kind == "bridge"
          stp = Support.fetch(attributes, "stp", "stp_state", default: nil)
          data << attribute(IFLA_BR_STP_STATE, uint32(Support.bool(stp) ? 1 : 0, "bridge STP state")) unless stp.nil?
        elsif kind == "vxlan"
          vni = Support.fetch(attributes, "vni", "id", default: nil)
          raise ValidationError, "VXLAN link requires a VNI" if vni.nil?

          data << attribute(IFLA_VXLAN_ID, uint32(Support.integer(vni, "VXLAN VNI", min: 1, max: 16_777_215), "VXLAN VNI"))
          device = Support.fetch(attributes, "dev", "underlay", "underlay_dev", default: nil)
          data << attribute(IFLA_VXLAN_LINK, uint32(link_index(device, "VXLAN underlay device"), "VXLAN underlay device index")) if device
          local = Support.fetch(attributes, "local", "local_vtep", "vtep", "vtep_ip", default: nil)
          if local
            local_ip = Support.ip(local, name: "VXLAN local VTEP")
            data << attribute(local_ip.ipv4? ? IFLA_VXLAN_LOCAL : IFLA_VXLAN_LOCAL6, local_ip.hton)
          end
          group = Support.fetch(attributes, "group", "multicast_group", default: nil)
          if group
            group_ip = Support.ip(group, name: "VXLAN multicast group")
            data << attribute(group_ip.ipv4? ? IFLA_VXLAN_GROUP : IFLA_VXLAN_GROUP6, group_ip.hton)
          end
          ttl = Support.fetch(attributes, "ttl", default: nil)
          data << attribute(IFLA_VXLAN_TTL, uint8(ttl, "VXLAN TTL")) if ttl
          tos = Support.fetch(attributes, "tos", default: nil)
          data << attribute(IFLA_VXLAN_TOS, uint8(tos, "VXLAN TOS")) if tos
          learning = Support.fetch(attributes, "learning", default: nil)
          data << attribute(IFLA_VXLAN_LEARNING, uint8(Support.bool(learning) ? 1 : 0, "VXLAN learning")) unless learning.nil?
          proxy = Support.fetch(attributes, "proxy", default: nil)
          data << attribute(IFLA_VXLAN_PROXY, uint8(Support.bool(proxy) ? 1 : 0, "VXLAN proxy")) unless proxy.nil?
          dstport = Support.fetch(attributes, "dstport", "destination_port", "port", default: nil)
          data << attribute(IFLA_VXLAN_PORT, uint16_be(dstport, "VXLAN UDP destination port")) if dstport
          udp_csum = Support.fetch(attributes, "udp_csum", default: nil)
          data << attribute(IFLA_VXLAN_UDP_CSUM, uint8(Support.bool(udp_csum) ? 1 : 0, "VXLAN UDP checksum")) unless udp_csum.nil?
          udp_zero_tx = Support.fetch(attributes, "udp_zero_csum6_tx", default: nil)
          unless udp_zero_tx.nil?
            data << attribute(IFLA_VXLAN_UDP_ZERO_CSUM6_TX,
                              uint8(Support.bool(udp_zero_tx) ? 1 : 0, "VXLAN IPv6 TX checksum"))
          end
          udp_zero_rx = Support.fetch(attributes, "udp_zero_csum6_rx", default: nil)
          unless udp_zero_rx.nil?
            data << attribute(IFLA_VXLAN_UDP_ZERO_CSUM6_RX,
                              uint8(Support.bool(udp_zero_rx) ? 1 : 0, "VXLAN IPv6 RX checksum"))
          end
          collect_metadata = Support.fetch(attributes, "collect_metadata", default: nil)
          unless collect_metadata.nil?
            data << attribute(IFLA_VXLAN_COLLECT_METADATA,
                              uint8(Support.bool(collect_metadata) ? 1 : 0, "VXLAN collect metadata"))
          end
        end
        info << attribute(IFLA_INFO_DATA, TLV.encode_many(data), nested: true) unless data.empty?
        attribute(IFLA_LINKINFO, TLV.encode_many(info), nested: true)
      end

      def encode_link_extra_attributes(attributes)
        values = []
        values << attribute(IFLA_ADDRESS, mac_binary(Support.fetch(attributes, "address", "mac"))) if Support.fetch(attributes, "address",
                                                                                                                    "mac", default: nil)
        values << attribute(2, mac_binary(Support.fetch(attributes, "broadcast"))) if Support.fetch(attributes, "broadcast", default: nil)
        values << attribute(13, uint32(Support.fetch(attributes, "txqlen"), "TX queue length")) if Support.fetch(attributes, "txqlen",
                                                                                                                 default: nil)
        values
      end

      def link_state_from_dump(name:, index:)
        selected_name = name && interface_name(name)
        selected_index = index && Support.integer(index, "link index", min: 1)
        entries = link_dump.filter_map do |message|
          payload = message.payload
          next if payload.bytesize < 16

          _family, _pad, _type, entry_index, flags, _change = payload.byteslice(0, 16).unpack("CCS<l<L<L<")
          attributes = TLV.decode(payload.byteslice(16..))
          entry_name = attributes_string(attributes, IFLA_IFNAME)
          next if entry_name.nil? || entry_name.empty?

          link_info_value = attributes.find { |entry| entry.fetch("type") == IFLA_LINKINFO }&.fetch("value")
          link_info = link_info_value ? TLV.decode(link_info_value) : []
          kind = attributes_string(link_info, IFLA_INFO_KIND)

          {
            "name" => entry_name,
            "index" => entry_index,
            "flags" => flags,
            "up" => flags.anybits?(IFF_UP),
            "mtu" => attributes_uint32(attributes, IFLA_MTU),
            "master_index" => attributes_uint32(attributes, IFLA_MASTER),
            "kind" => kind,
            "mac" => attributes_binary_mac(attributes, IFLA_ADDRESS)
          }.compact
        end
        selected = entries.find do |entry|
          (selected_name && entry["name"] == selected_name) ||
            (selected_index && entry["index"] == selected_index)
        end
        unless selected
          raise NetlinkError.new("interface #{selected_name || selected_index.inspect} was not found while observing link state",
                                 errno: Errno::ENODEV::Errno, operation: "link_state")
        end

        masters = entries.to_h { |entry| [entry.fetch("index"), entry.fetch("name")] }
        {
          "name" => selected.fetch("name"),
          "index" => selected.fetch("index"),
          "up" => selected.fetch("up"),
          "mtu" => selected["mtu"],
          "master" => selected["master_index"] && masters[selected["master_index"]],
          "kind" => selected["kind"],
          "mac" => selected["mac"],
          "netns_inode" => File.stat(THREAD_NAMESPACE_PATH).ino
        }.compact.freeze
      rescue NetlinkError
        raise
      rescue SystemCallError, SocketError, ArgumentError => error
        raise NetlinkError.new("failed to observe link state from rtnetlink: #{error.message}",
                               errno: error.respond_to?(:errno) ? error.errno : Errno::ENODEV::Errno,
                               operation: "link_state")
      end

      def attributes_string(attributes, type)
        value = attributes.find { |entry| entry.fetch("type") == type }&.fetch("value")
        value&.delete_suffix("\0")
      end

      def attributes_binary_mac(attributes, type)
        value = attributes.find { |entry| entry.fetch("type") == type }&.fetch("value")
        return nil unless value && value.bytesize >= 6

        value.byteslice(0, 6).unpack1("H12").scan(/../).join(":")
      end

      def attributes_uint32(attributes, type)
        value = attributes.find { |entry| entry.fetch("type") == type }&.fetch("value")
        value && value.bytesize >= 4 ? value.unpack1("L<") : nil
      end

      def link_index(value, name)
        return Support.integer(value, "#{name} index", min: 1) if value.is_a?(Integer)

        interface = interface_name(value)
        candidate = Socket.getifaddrs.find { |entry| entry.name == interface && entry.ifindex }
        return candidate.ifindex if candidate

        raise NetlinkError.new("interface #{interface.inspect} was not found while resolving #{name} index",
                               errno: Errno::ENODEV::Errno, operation: "resolve_interface")
      rescue SocketError, SystemCallError => error
        raise NetlinkError.new("failed to resolve interface #{interface.inspect}: #{error.message}",
                               errno: error.respond_to?(:errno) ? error.errno : Errno::ENODEV::Errno,
                               operation: "resolve_interface")
      end

      def namespace_fd_value(value)
        return Support.integer(value, "network namespace FD", min: 0) if value.is_a?(Integer)
        return Support.integer(value.fileno, "network namespace FD", min: 0) if value.respond_to?(:fileno)

        raise ValidationError, "network namespace must be a verified open FD lease"
      end

      def validate_namespace_target!(target)
        return nil if target.nil?
        return true if target.is_a?(Integer) || target.respond_to?(:fileno)

        raise ValidationError, "network namespace paths cannot be reopened; pass a verified open FD lease"
      end

      def address_request(type, address:, prefix:, index:, name:, operation:, attributes:, flags:)
        ip, inferred_prefix = parse_address(address, prefix)
        target_index = index ? Support.integer(index, "link index", min: 1) : link_index(name, "address")
        family_number = ip.ipv4? ? AF_INET : AF_INET6
        ifa_flags = Support.fetch(attributes, "ifa_flags", "flags", default: 0)
        scope = Support.fetch(attributes, "scope", default: ip.link_local? ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE)
        payload = ifaddrmsg(family: family_number, prefix: inferred_prefix, flags: ifa_flags, scope: scope, index: target_index)
        encoded = [attribute(IFA_ADDRESS, ip.hton), attribute(IFA_LOCAL, ip.hton)]
        label = Support.fetch(attributes, "label", default: nil)
        encoded << attribute(IFA_LABEL, c_string(interface_name(label))) if label
        if Support.fetch(
          attributes, "broadcast", default: nil
        )
          encoded << attribute(IFA_BROADCAST,
                               Support.ip(Support.fetch(attributes, "broadcast"), name: "address broadcast").hton)
        end
        encoded << attribute(IFA_ANYCAST, Support.ip(Support.fetch(attributes, "anycast"), name: "address anycast").hton) if Support.fetch(
          attributes, "anycast", default: nil
        )
        encoded << attribute(IFA_FLAGS, uint32(ifa_flags, "address flags")) if Support.fetch(attributes, "ifa_flags", default: nil)
        priority = Support.fetch(attributes, "priority", "ifa_rt_priority", default: nil)
        encoded << attribute(IFA_RT_PRIORITY, uint32(priority, "address priority")) if priority
        request(type: type, payload: payload, flags: flags, attributes: encoded, operation: operation)
      end

      def route_request(type, destination:, via:, dev:, table:, metric:, family:, flags:, operation:, attributes:)
        network, prefix = Support.cidr(destination, name: "route destination")
        family ||= network.ipv4? ? "ipv4" : "ipv6"
        normalized_family = Support.family(family)
        raise ValidationError, "route family does not match destination" if (normalized_family == "ipv4") != network.ipv4?

        gateway = via && Support.ip(via, name: "route gateway")
        raise ValidationError, "route gateway family does not match destination" if gateway && gateway.ipv4? != network.ipv4?

        unless kernel_adapter?
          interface_name(dev) if dev
          legacy_payload = {"destination" => network.to_s, "prefix" => prefix, "via" => via, "dev" => dev,
                            "table" => Support.integer(table, "route table", min: 0, max: 0xffff_ffff), "metric" => metric,
                            "family" => normalized_family}.merge(attributes).compact
          return request(type: type, flags: flags,
                         attributes: legacy_payload.map { |key, value| {"type" => attribute_id(key), "value" => attribute_value(value)} },
                         operation: operation)
        end

        table_value = Support.integer(table, "route table", min: 0, max: 0xffff_ffff)
        protocol = Support.fetch(attributes, "protocol", default: RTPROT_STATIC)
        scope = Support.fetch(attributes, "scope", default: gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK)
        route_type = Support.fetch(attributes, "route_type", "type", default: RTN_UNICAST)
        route_flags = Support.fetch(attributes, "route_flags", "rtm_flags", default: 0)
        family_number = network.ipv4? ? AF_INET : AF_INET6
        # RTM_*MSG carries only the legacy u8 table field.  The full table
        # number is carried by RTA_TABLE when it does not fit in that field.
        payload = rtmsg(family: family_number, prefix: prefix, table: [table_value, 0xff].min, protocol: protocol,
                        scope: scope, type: route_type, flags: route_flags)
        encoded = []
        encoded << attribute(RTA_DST, network.hton) if prefix.positive?
        encoded << attribute(RTA_GATEWAY, gateway.hton) if gateway
        encoded << attribute(RTA_OIF, uint32(link_index(dev, "route device"), "route device index")) if dev
        encoded << attribute(RTA_PRIORITY, uint32(metric, "route metric")) if metric
        encoded << attribute(RTA_TABLE, uint32(table_value, "route table")) if table_value > 0xff
        prefsrc = Support.fetch(attributes, "prefsrc", "preferred_source", default: nil)
        encoded << attribute(8, Support.ip(prefsrc, name: "route preferred source").hton) if prefsrc
        request(type: type, payload: payload, flags: flags, attributes: encoded, operation: operation)
      end

      def neighbor_request(type, destination:, lladdr:, dev:, family:, state:, operation:, flags:, attributes:, ndm_flags: 0)
        unless kernel_adapter?
          return legacy_fdb_request(type, mac: lladdr, destination: destination, dev: dev,
                                          operation: operation, attributes: attributes, flags: flags)
        end

        ip = Support.ip(destination, name: "neighbour destination")
        family_number = family_number(family, ip)
        index = link_index(dev, "neighbour device")
        state_value = neighbour_state(state)
        payload = ndmsg(family: family_number, index: index, state: state_value, flags: ndm_flags)
        encoded = [attribute(NDA_DST, ip.hton)]
        encoded << attribute(NDA_LLADDR, mac_binary(lladdr)) if lladdr
        vlan = Support.fetch(attributes, "vlan", default: nil)
        encoded << attribute(5, uint16(vlan, "neighbour VLAN")) if vlan
        request(type: type, payload: payload, flags: flags, attributes: encoded, operation: operation)
      end

      def family_number(family, ip)
        return AF_BRIDGE if family.to_s.downcase == "bridge" || family == AF_BRIDGE
        return family if [AF_INET, AF_INET6].include?(family)
        return AF_INET if family.nil? && ip.ipv4?
        return AF_INET6 if family.nil?

        Support.family(family) == "ipv4" ? AF_INET : AF_INET6
      end

      def neighbour_state(value)
        return value if value.is_a?(Integer)

        {permanent: NUD_PERMANENT, reachable: 0x02, stale: 0x04, noarp: 0x40, none: 0}.fetch(value.to_sym) do
          raise ValidationError, "unsupported neighbour state #{value.inspect}"
        end
      rescue NoMethodError
        raise ValidationError, "unsupported neighbour state #{value.inspect}"
      end

      def peer_name_from(peer)
        return nil if peer.nil?
        return interface_name(peer) unless peer.is_a?(Hash)

        interface_name(Support.fetch(peer, "name", "ifname"))
      end

      def mac_binary(value)
        text = mac_address(value)
        [text.delete(":")].pack("H12")
      end

      def legacy_link_add(name:, kind:, mtu:, index:, master:, up:, peer:, namespace:, namespace_fd:, operation:, attributes:)
        interface_name(name)
        link_attributes = {"ifname" => name, "kind" => Support.string(kind, "link kind"), "mtu" => mtu,
                           "index" => index, "master" => master, "up" => up, "peer" => peer,
                           "namespace" => namespace, "namespace_fd" => namespace_fd}.merge(attributes).compact
        request(type: RTM_NEWLINK, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
                attributes: link_attributes.map { |key, value| {"type" => attribute_id(key), "value" => attribute_value(value)} },
                operation: operation)
      end

      def legacy_link_delete(name:, index:, operation:, attributes:)
        validate_link_reference!(name, index)
        payload = {"ifname" => name, "index" => index}.merge(attributes).compact
        request(type: RTM_DELLINK, attributes: payload.map do |key, value|
          {"type" => attribute_id(key), "value" => attribute_value(value)}
        end, operation: operation)
      end

      def legacy_link_set(name:, index:, mtu:, up:, master:, namespace:, namespace_fd:, operation:, attributes:)
        validate_link_reference!(name, index)
        payload = {"ifname" => name, "index" => index, "mtu" => mtu, "up" => up, "master" => master,
                   "namespace" => namespace, "namespace_fd" => namespace_fd}.merge(attributes).compact
        request(type: RTM_SETLINK, attributes: payload.map do |key, value|
          {"type" => attribute_id(key), "value" => attribute_value(value)}
        end, operation: operation)
      end

      def legacy_address_request(type, address:, prefix:, index:, name:, operation:, attributes:, flags:)
        validate_link_reference!(name, index)
        ip, inferred_prefix = parse_address(address, prefix)
        payload = {"address" => ip.to_s, "prefix" => inferred_prefix, "index" => index, "name" => name}.merge(attributes).compact
        request(type: type, flags: flags,
                attributes: payload.map do |key, value|
                  {"type" => attribute_id(key), "value" => attribute_value(value)}
                end, operation: operation)
      end

      def legacy_fdb_request(type, mac:, destination:, dev:, operation:, attributes:, flags:)
        mac = mac_address(mac)
        Support.ip(destination, name: "FDB destination")
        interface_name(dev)
        request(type: type, flags: flags,
                attributes: {"mac" => mac, "destination" => destination, "dev" => dev}.merge(attributes).map do |key, value|
                  {"type" => attribute_id(key), "value" => attribute_value(value)}
                end, operation: operation)
      end

      def parse_address(address, prefix)
        value = String(address)
        if value.include?("/")
          address_text, inferred_text = value.split("/", 2)
          ip = Support.ip(address_text, name: "address")
          inferred = Support.integer(inferred_text, "address prefix", min: 0, max: ip.ipv4? ? 32 : 128)
          [ip, if prefix.nil?
                 inferred
               else
                 Support.integer(prefix, "prefix", min: 0, max: ip.ipv4? ? 32 : 128)
               end]
        else
          ip = Support.ip(value, name: "address")
          raise ValidationError, "address prefix is required" if prefix.nil?

          [ip, Support.integer(prefix, "prefix", min: 0, max: ip.ipv4? ? 32 : 128)]
        end
      end

      def interface_name(value)
        name = Support.string(value, "interface name")
        raise ValidationError, "interface name exceeds IFNAMSIZ-1" if name.bytesize >= IFNAMSIZ

        name
      end

      def validate_link_reference!(name, index)
        return interface_name(name) if name
        return Support.integer(index, "link index", min: 1) if index

        raise ValidationError, "link name or positive link index is required"
      end

      def mac_address(value)
        text = Support.string(value, "MAC address")
        raise ValidationError, "invalid MAC address" unless text.match?(/\A[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\z/)

        text.downcase
      end

      def attribute_id(key)
        return Integer(key) if key.is_a?(Integer)

        # The numeric values are only required by the production encoder.  A
        # stable private range keeps injected adapters deterministic for named
        # attributes without pretending to be a complete rtnetlink header.
        {
          "ifname" => 3, "mtu" => 4, "index" => 3, "master" => 10,
          "address" => 1, "prefix" => 2, "name" => 3, "namespace" => 7,
          "destination" => 1, "via" => 5, "dev" => 4, "table" => 15,
          "metric" => 6, "family" => 7, "kind" => 18, "mac" => 1
        }.fetch(key.to_s, 0x4000 + (Digest::SHA256.hexdigest(key.to_s)[0, 4].to_i(16) % 0x3fff))
      end

      def attribute_value(value)
        case value
        when Integer then value
        when TrueClass then 1
        when FalseClass then 0
        when IPAddr then value
        else String(value)
        end
      end
    end

    NetlinkEncoder = Netlink::TLV
  end
end
