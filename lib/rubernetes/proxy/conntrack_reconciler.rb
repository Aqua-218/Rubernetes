# frozen_string_literal: true

require "socket"
require "ipaddr"

module Rubernetes
  module Proxy
    class ConntrackNetlinkError < StandardError
      attr_reader :errno

      def initialize(message, errno: nil)
        super(message)
        @errno = errno
      end
    end

    # One kernel conntrack flow: the original tuple (client -> Service VIP or
    # NodePort) and the reply tuple (endpoint -> client, after DNAT).
    ConntrackFlow = Struct.new(:family, :protocol, :orig_src, :orig_sport, :orig_dst, :orig_dport,
                               :reply_src, :reply_sport, :reply_dst, :reply_dport, :id, :zone, keyword_init: true)

    # pkg/proxy/conntrack's netlink handle: ctnetlink (NFNL_SUBSYS_CTNETLINK
    # over NETLINK_NETFILTER) dump and per-flow delete, the calls
    # vishvananda/netlink's ConntrackTableList / ConntrackDeleteFilters make.
    class ConntrackNetlink
      AF_NETLINK = 16
      AF_INET = 2
      AF_INET6 = 10
      NETLINK_NETFILTER = 12
      NLM_F_REQUEST = 0x01
      NLM_F_ACK = 0x04
      NLM_F_DUMP = 0x300
      NLMSG_ERROR = 2
      NLMSG_DONE = 3
      NFNL_SUBSYS_CTNETLINK = 1
      IPCTNL_MSG_CT_GET = 1
      IPCTNL_MSG_CT_DELETE = 2
      NFNETLINK_V0 = 0
      NLA_F_NESTED = 0x8000
      NLA_TYPE_MASK = 0x3fff
      NETLINK_HEADER_SIZE = 16
      NFGENMSG_SIZE = 4
      MAX_MESSAGE_BYTES = 1_048_576
      IPPROTO_UDP = 17

      CTA_TUPLE_ORIG = 1
      CTA_TUPLE_REPLY = 2
      CTA_ID = 12
      CTA_ZONE = 18
      CTA_TUPLE_IP = 1
      CTA_TUPLE_PROTO = 2
      CTA_IP_V4_SRC = 1
      CTA_IP_V4_DST = 2
      CTA_IP_V6_SRC = 3
      CTA_IP_V6_DST = 4
      CTA_PROTO_NUM = 1
      CTA_PROTO_SRC_PORT = 2
      CTA_PROTO_DST_PORT = 3

      FAMILY_CODES = {"IPv4" => AF_INET, "IPv6" => AF_INET6}.freeze
      # proxy/util: EINTR on a dump means a partial result; retried a few times.
      MAX_ATTEMPTS_EINTR = 5

      Message = Struct.new(:type, :flags, :sequence, :payload, keyword_init: true)

      def initialize(socket_factory: nil, timeout: 5.0)
        @socket_factory = socket_factory || method(:open_socket)
        @timeout = Float(timeout)
        @sequence = 0
        @mutex = Mutex.new
      end

      # All conntrack entries of one IP family ("IPv4" / "IPv6").
      def list(family)
        code = family_code(family)
        attempts = 0
        begin
          attempts += 1
          with_socket do |socket|
            sequence = next_sequence
            request = netlink_message(message_type(IPCTNL_MSG_CT_GET), NLM_F_REQUEST | NLM_F_DUMP, sequence, nfgen(code))
            socket.send(request, 0)
            receive_dump(socket, sequence: sequence).filter_map { |message| decode_flow(message.payload, family) }
          end
        rescue ConntrackNetlinkError => error
          retry if error.errno == Errno::EINTR::Errno && attempts < MAX_ATTEMPTS_EINTR
          raise
        end
      end

      # Delete the given flows; returns how many the kernel removed (a flow
      # that already expired answers ENOENT and is not counted).
      def delete(family, flows)
        flows = Array(flows)
        return 0 if flows.empty?

        code = family_code(family)
        deleted = 0
        with_socket do |socket|
          flows.each_slice(64) do |batch|
            sequences = {}
            batch.each do |flow|
              sequence = next_sequence
              sequences[sequence] = flow
              socket.send(netlink_message(message_type(IPCTNL_MSG_CT_DELETE), NLM_F_REQUEST | NLM_F_ACK, sequence,
                                          nfgen(code) + flow_attributes(flow)), 0)
            end
            deleted += receive_acknowledgements(socket, sequences.keys)
          end
        end
        deleted
      end

      # -- wire format (also used by tests to build kernel-shaped dumps) --

      def encode_flow_message(flow, sequence: 1)
        netlink_message(message_type(IPCTNL_MSG_CT_GET), 0, sequence, nfgen(family_code(flow.family)) + flow_attributes(flow, id: true))
      end

      def done_message(sequence: 1)
        netlink_message(NLMSG_DONE, 0, sequence, [0].pack("l<"))
      end

      def error_message(errno, sequence:)
        netlink_message(NLMSG_ERROR, 0, sequence, [-Integer(errno)].pack("l<") + ("\0" * NETLINK_HEADER_SIZE))
      end

      def decode_flow(payload, family)
        attrs = decode_attributes(payload.byteslice(NFGENMSG_SIZE..).to_s)
        orig = decode_tuple(value(attrs, CTA_TUPLE_ORIG))
        reply = decode_tuple(value(attrs, CTA_TUPLE_REPLY))
        return nil unless orig && reply

        id = value(attrs, CTA_ID)
        zone = value(attrs, CTA_ZONE)
        ConntrackFlow.new(family: family, protocol: orig[:protocol],
                          orig_src: orig[:src], orig_sport: orig[:sport], orig_dst: orig[:dst], orig_dport: orig[:dport],
                          reply_src: reply[:src], reply_sport: reply[:sport], reply_dst: reply[:dst], reply_dport: reply[:dport],
                          id: id && id.bytesize >= 4 ? id.unpack1("L>") : nil,
                          zone: zone && zone.bytesize >= 2 ? zone.unpack1("S>") : 0)
      rescue ConntrackNetlinkError
        nil
      end

      private

      def family_code(family)
        FAMILY_CODES.fetch(family.to_s) { raise ArgumentError, "unknown IP family #{family.inspect}" }
      end

      def message_type(type) = (NFNL_SUBSYS_CTNETLINK << 8) | type

      def nfgen(family_code) = [family_code, NFNETLINK_V0, 0].pack("CCn")

      def flow_attributes(flow, id: false)
        v6 = flow.family.to_s == "IPv6"
        body = attribute(CTA_TUPLE_ORIG,
                         tuple_attributes(flow.orig_src, flow.orig_sport, flow.orig_dst, flow.orig_dport, flow.protocol, v6), nested: true) +
               attribute(CTA_TUPLE_REPLY,
                         tuple_attributes(flow.reply_src, flow.reply_sport, flow.reply_dst, flow.reply_dport, flow.protocol, v6), nested: true)
        body += attribute(CTA_ZONE, [flow.zone].pack("S>")) if flow.zone && !flow.zone.zero?
        body += attribute(CTA_ID, [flow.id].pack("L>")) if id && flow.id
        body
      end

      def tuple_attributes(src, sport, dst, dport, protocol, v6)
        ip = attribute(v6 ? CTA_IP_V6_SRC : CTA_IP_V4_SRC, IPAddr.new(src.to_s).hton) +
             attribute(v6 ? CTA_IP_V6_DST : CTA_IP_V4_DST, IPAddr.new(dst.to_s).hton)
        proto = attribute(CTA_PROTO_NUM, [Integer(protocol)].pack("C")) +
                attribute(CTA_PROTO_SRC_PORT, [Integer(sport)].pack("n")) +
                attribute(CTA_PROTO_DST_PORT, [Integer(dport)].pack("n"))
        attribute(CTA_TUPLE_IP, ip, nested: true) + attribute(CTA_TUPLE_PROTO, proto, nested: true)
      end

      def decode_tuple(bytes)
        return nil if bytes.nil?

        attrs = decode_attributes(bytes)
        ip = decode_attributes(value(attrs, CTA_TUPLE_IP).to_s)
        proto = decode_attributes(value(attrs, CTA_TUPLE_PROTO).to_s)
        src = value(ip, CTA_IP_V4_SRC) || value(ip, CTA_IP_V6_SRC)
        dst = value(ip, CTA_IP_V4_DST) || value(ip, CTA_IP_V6_DST)
        return nil unless src && dst

        number = value(proto, CTA_PROTO_NUM)
        sport = value(proto, CTA_PROTO_SRC_PORT)
        dport = value(proto, CTA_PROTO_DST_PORT)
        {src: address(src), dst: address(dst), protocol: number ? number.unpack1("C") : nil,
         sport: sport ? sport.unpack1("n") : 0, dport: dport ? dport.unpack1("n") : 0}
      end

      def address(bytes)
        IPAddr.new_ntoh(bytes).to_s
      rescue IPAddr::Error, ArgumentError
        nil
      end

      def with_socket
        socket = @socket_factory.call
        socket.bind([AF_NETLINK, 0, 0, 0].pack("S<S<L<L<")) if socket.respond_to?(:bind)
        yield socket
      rescue ConntrackNetlinkError
        raise
      rescue SystemCallError => error
        raise ConntrackNetlinkError.new("conntrack netlink I/O failed: #{error.message}", errno: error.errno)
      ensure
        socket&.close if socket.respond_to?(:close)
      end

      def receive_dump(socket, sequence:)
        entries = []
        deadline = monotonic_now + @timeout
        loop do
          messages = parse_messages(receive_bytes(socket, deadline: deadline))
          done = false
          messages.each do |message|
            next unless message.sequence == sequence

            case message.type
            when NLMSG_ERROR then check_error!(message)
            when NLMSG_DONE then done = true
            when message_type(IPCTNL_MSG_CT_GET), message_type(0) then entries << message
            end
          end
          return entries if done
        end
      end

      def receive_acknowledgements(socket, sequences)
        pending = sequences.to_h { |sequence| [sequence, true] }
        deleted = 0
        deadline = monotonic_now + @timeout
        until pending.empty?
          parse_messages(receive_bytes(socket, deadline: deadline)).each do |message|
            next unless pending.delete(message.sequence) && message.type == NLMSG_ERROR

            code = message.payload.bytesize >= 4 ? message.payload.unpack1("l<") : nil
            if code.nil?
              raise ConntrackNetlinkError, "kernel returned a malformed conntrack delete reply"
            elsif code.zero?
              deleted += 1
            elsif code.abs != Errno::ENOENT::Errno
              raise ConntrackNetlinkError.new("kernel rejected conntrack delete: errno #{code.abs}", errno: code.abs)
            end
          end
        end
        deleted
      end

      def check_error!(message)
        code = message.payload.bytesize >= 4 ? message.payload.unpack1("l<") : nil
        raise ConntrackNetlinkError, "kernel returned a malformed conntrack dump error" if code.nil?
        return if code.zero?

        raise ConntrackNetlinkError.new("kernel rejected conntrack dump: errno #{code.abs}", errno: code.abs)
      end

      def receive_bytes(socket, deadline:)
        remaining = deadline - monotonic_now
        raise ConntrackNetlinkError.new("conntrack dump timed out", errno: Errno::ETIMEDOUT::Errno) if remaining <= 0
        raise ConntrackNetlinkError.new("conntrack dump timed out", errno: Errno::ETIMEDOUT::Errno) unless IO.select([socket], nil, nil,
                                                                                                                     remaining)

        socket.recv(MAX_MESSAGE_BYTES)
      rescue SystemCallError => error
        raise ConntrackNetlinkError.new("conntrack receive failed: #{error.message}", errno: error.errno)
      end

      def parse_messages(bytes)
        buffer = String(bytes).b
        offset = 0
        messages = []
        while offset + NETLINK_HEADER_SIZE <= buffer.bytesize
          length, type, flags, sequence, _pid = buffer.byteslice(offset, NETLINK_HEADER_SIZE).unpack("L<S<S<L<L<")
          if length < NETLINK_HEADER_SIZE || offset + length > buffer.bytesize
            raise ConntrackNetlinkError,
                  "conntrack netlink message has invalid length #{length}"
          end

          messages << Message.new(type: type, flags: flags, sequence: sequence,
                                  payload: buffer.byteslice(offset + NETLINK_HEADER_SIZE, length - NETLINK_HEADER_SIZE).to_s)
          offset += align(length)
        end
        messages
      end

      def netlink_message(type, flags, sequence, payload)
        payload = String(payload).b
        length = NETLINK_HEADER_SIZE + payload.bytesize
        [length, type, flags, sequence, 0].pack("L<S<S<L<L<") + payload + ("\0" * (align(length) - length))
      end

      def attribute(type, body, nested: false)
        body = String(body).b
        length = 4 + body.bytesize
        [length, type | (nested ? NLA_F_NESTED : 0)].pack("S<S<") + body + ("\0" * (align(length) - length))
      end

      def decode_attributes(bytes)
        buffer = String(bytes).b
        offset = 0
        values = []
        while offset + 4 <= buffer.bytesize
          length, type = buffer.byteslice(offset, 4).unpack("S<S<")
          raise ConntrackNetlinkError, "conntrack attribute has invalid length #{length}" if length < 4 || offset + length > buffer.bytesize

          values << [type & NLA_TYPE_MASK, buffer.byteslice(offset + 4, length - 4).to_s]
          offset += align(length)
        end
        values
      end

      def value(attrs, type)
        entry = attrs.reverse_each.find { |candidate| candidate[0] == type }
        entry && entry[1]
      end

      def align(length) = (length + 3) & ~3

      def open_socket = Socket.new(Socket::AF_NETLINK, Socket::SOCK_RAW, NETLINK_NETFILTER)

      def monotonic_now = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      def next_sequence
        @mutex.synchronize do
          @sequence = (@sequence + 1) & 0xffff_ffff
          @sequence = 1 if @sequence.zero?
          @sequence
        end
      end
    end

    # pkg/proxy/conntrack.CleanStaleEntries: after every rules sync, UDP
    # conntrack flows that point a Service IP:port / NodePort at an endpoint
    # that is no longer serving are deleted (otherwise a client keeps hitting
    # the dead backend until the entry times out).  Per IP family, timed in
    # kubeproxy_conntrack_reconciler_sync_duration_seconds and counted in
    # kubeproxy_conntrack_reconciler_deleted_entries_total.
    class ConntrackReconciler
      SERVICE_KINDS = %w[ClusterIP ExternalIP LoadBalancer].freeze

      attr_reader :last_error

      def initialize(families: ["IPv4"], netlink: nil, metrics: nil, logger: nil,
                     clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @families = Array(families).map(&:to_s).uniq
        @netlink = netlink || ConntrackNetlink.new
        @metrics = metrics
        @logger = logger
        @clock = clock
        @last_error = nil
        @disabled = false
      end

      def disabled? = @disabled

      # +rules+: the compiled Rule set that was just published.
      def reconcile(rules)
        return {} if @disabled

        @families.to_h { |family| [family, reconcile_family(family, rules)] }
      end

      def reconcile_family(family, rules)
        started = @clock.call
        deleted = 0
        begin
          entries = @netlink.list(family)
          stale = self.class.stale_flows(family, rules, entries)
          deleted = @netlink.delete(family, stale) unless stale.empty?
          @last_error = nil
        rescue ConntrackNetlinkError, ArgumentError => error
          @last_error = error
          # Not root / no nf_conntrack: the reconciler is switched off rather
          # than logging on every sync.
          @disabled = true if [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::EPROTONOSUPPORT::Errno,
                               Errno::EAFNOSUPPORT::Errno, Errno::ENOENT::Errno].include?(error.errno)
          if @logger.respond_to?(:warn)
            @logger&.warn("proxy.conntrack_reconcile_failed", family: family, error: error.message,
                                                              disabled: @disabled)
          end
        end
        seconds = @clock.call - started
        @metrics.conntrack_reconciled(family, seconds, deleted) if @metrics.respond_to?(:conntrack_reconciled)
        deleted
      end

      # The upstream filter: for each UDP Service front end
      # (VIP:port and *:nodePort) with at least one serving endpoint, a flow
      # whose original destination is that front end and whose reply source
      # is not one of those endpoints is stale.
      def self.stale_flows(family, rules, flows)
        vip_endpoints = {}
        node_port_endpoints = {}
        Array(rules).each do |rule|
          next unless rule.protocol.to_s == "UDP"
          next if rule.respond_to?(:health_check) && rule.health_check

          serving = serving_endpoints(rule, family)
          next if serving.empty?

          if SERVICE_KINDS.include?(rule.kind.to_s) && rule.virtual_ip
            next unless ModelSupport.ip_family(rule.virtual_ip) == family

            (vip_endpoints[[canonical(rule.virtual_ip), rule.port]] ||= Set.new).merge(serving)
          elsif rule.kind.to_s == "NodePort" && rule.node_port
            (node_port_endpoints[rule.node_port] ||= Set.new).merge(serving)
          end
        end
        return [] if vip_endpoints.empty? && node_port_endpoints.empty?

        Array(flows).select do |flow|
          next false unless flow.protocol == ConntrackNetlink::IPPROTO_UDP

          reply = [canonical(flow.reply_src), flow.reply_sport]
          endpoints = vip_endpoints[[canonical(flow.orig_dst), flow.orig_dport]]
          next true if endpoints && !endpoints.include?(reply)

          endpoints = node_port_endpoints[flow.orig_dport]
          endpoints && !endpoints.include?(reply)
        end
      end

      def self.serving_endpoints(rule, family)
        Array(rule.backends).filter_map do |backend|
          next unless backend.respond_to?(:serving?) && backend.serving?
          next unless backend.respond_to?(:address) && backend.respond_to?(:port)
          next unless (backend.respond_to?(:family) ? backend.family.to_s : ModelSupport.ip_family(backend.address)) == family

          [canonical(backend.address), Integer(backend.port)]
        end.to_set
      end

      def self.canonical(ip)
        IPAddr.new(ip.to_s).to_s
      rescue IPAddr::Error, ArgumentError
        ip.to_s
      end
    end
  end
end
