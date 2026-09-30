# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

class NetlinkTest < Minitest::Test
  Netlink = Rubernetes::Network::Netlink

  class CaptureSocket
    attr_reader :message

    def initialize
      @reader, @writer = IO.pipe
    end

    def bind(_address)
      true
    end

    def send(message, _flags)
      @message = message.dup
      sequence = message.byteslice(8, 4).unpack1("L<")
      ack = [Netlink::HEADER_SIZE + 4, Netlink::NLMSG_ERROR, 0, sequence, 0].pack("L<S<S<L<L<") + [0].pack("l<")
      @writer.write(ack)
      @writer.flush
      message.bytesize
    end

    def recv(_size)
      @reader.read_nonblock(65_536)
    end

    # IO#wait_readable, as the production socket path now waits (fiber-scheduler safe).
    def wait_readable(timeout = nil)
      IO.select([@reader], nil, nil, timeout) ? self : nil
    end

    def to_io
      @reader
    end

    def close
      @reader.close unless @reader.closed?
      @writer.close unless @writer.closed?
    end
  end

  class RecordingAdapter
    attr_reader :requests

    def initialize
      @requests = []
    end

    def request(**request)
      @requests << request
      [{type: Netlink::NLMSG_ERROR, error: 0, sequence: request.fetch(:sequence)}]
    end
  end

  def test_veth_encoder_uses_ifinfomsg_and_nested_peer_attributes
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }), sequence: 0)

    netlink.link_add(name: "rk-veth0", kind: "veth", peer: "rk-peer0", up: false)

    header, payload = split_message(socket.message)

    assert_equal Netlink::RTM_NEWLINK, header.fetch(:type)
    assert_equal Netlink::NLM_F_REQUEST | Netlink::NLM_F_ACK | Netlink::NLM_F_CREATE | Netlink::NLM_F_EXCL, header.fetch(:flags)
    family, pad, arphrd, index, flags, change = payload.byteslice(0, 16).unpack("CCS<l<L<L<")

    assert_equal [0, 0, 0, 0, 0, 1], [family, pad, arphrd, index, flags, change]

    attributes = Netlink::TLV.decode(payload.byteslice(16, payload.bytesize - 16))

    assert_equal([Netlink::IFLA_IFNAME, Netlink::IFLA_LINKINFO], attributes.map { |entry| entry.fetch("type") })
    assert_equal "rk-veth0\0", attributes.fetch(0).fetch("value")

    link_info = Netlink::TLV.decode(attributes.fetch(1).fetch("value"))

    assert_equal([Netlink::IFLA_INFO_KIND, Netlink::IFLA_INFO_DATA], link_info.map { |entry| entry.fetch("type") })
    assert_equal "veth\0", link_info.fetch(0).fetch("value")

    info_data = Netlink::TLV.decode(link_info.fetch(1).fetch("value"))

    assert_equal([Netlink::VETH_INFO_PEER], info_data.map { |entry| entry.fetch("type") })
    peer_payload = info_data.fetch(0).fetch("value")
    peer_attributes = Netlink::TLV.decode(peer_payload.byteslice(16, peer_payload.bytesize - 16))

    assert_equal [[0, 0, 0, 0, 0, 0], "rk-peer0\0"],
                 [peer_payload.byteslice(0, 16).unpack("CCS<l<L<L<"), peer_attributes.fetch(0).fetch("value")]
  ensure
    socket&.close
  end

  def test_address_encoder_uses_ifaddrmsg_and_binary_ip_attributes
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }), sequence: 10)

    netlink.address_add(address: "198.18.1.7/24", name: "lo")

    header, payload = split_message(socket.message)

    assert_equal Netlink::RTM_NEWADDR, header.fetch(:type)
    family, prefix, flags, scope, index = payload.byteslice(0, 8).unpack("CCCCL<")

    assert_equal [Netlink::AF_INET, 24, 0, 0, 1], [family, prefix, flags, scope, index]
    attributes = Netlink::TLV.decode(payload.byteslice(8, payload.bytesize - 8))

    assert_equal([Netlink::IFA_ADDRESS, Netlink::IFA_LOCAL], attributes.map { |entry| entry.fetch("type") })
    assert_equal(["\xC6\x12\x01\x07".b, "\xC6\x12\x01\x07".b], attributes.map { |entry| entry.fetch("value") })
  ensure
    socket&.close
  end

  def test_address_encoder_rejects_an_address_without_any_prefix
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }))

    error = assert_raises(Rubernetes::Network::ValidationError) do
      netlink.address_add(address: "198.18.1.7", name: "lo")
    end

    assert_match(/prefix is required/, error.message)
  ensure
    socket&.close
  end

  def test_route_encoder_uses_rtmsg_ifindex_and_binary_gateway
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }), sequence: 20)

    netlink.route_add(destination: "198.18.2.0/24", via: "198.18.1.1", dev: "lo", metric: 42)

    header, payload = split_message(socket.message)

    assert_equal Netlink::RTM_NEWROUTE, header.fetch(:type)
    family, prefix, src_len, tos, table, protocol, scope, type, route_flags = payload.byteslice(0, 12).unpack("CCCCCCCCL<")

    assert_equal [Netlink::AF_INET, 24, 0, 0, Netlink::RT_TABLE_MAIN, Netlink::RTPROT_STATIC,
                  Netlink::RT_SCOPE_UNIVERSE, Netlink::RTN_UNICAST, 0],
                 [family, prefix, src_len, tos, table, protocol, scope, type, route_flags]
    attributes = Netlink::TLV.decode(payload.byteslice(12, payload.bytesize - 12))

    assert_equal([Netlink::RTA_DST, Netlink::RTA_GATEWAY, Netlink::RTA_OIF, Netlink::RTA_PRIORITY], attributes.map do |entry|
      entry.fetch("type")
    end)
    assert_equal "\xC6\x12\x02\x00".b, attributes.fetch(0).fetch("value")
    assert_equal "\xC6\x12\x01\x01".b, attributes.fetch(1).fetch("value")
    assert_equal [1].pack("L<"), attributes.fetch(2).fetch("value")
    assert_equal [42].pack("L<"), attributes.fetch(3).fetch("value")
  ensure
    socket&.close
  end

  def test_route_encoder_uses_rta_table_for_tables_above_legacy_header_range
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }), sequence: 21)

    netlink.route_add(destination: "198.18.2.0/24", dev: "lo", table: 1000)

    _header, payload = split_message(socket.message)
    _family, _prefix, _src_len, _tos, table, = payload.byteslice(0, 12).unpack("CCCCCCCCL<")

    assert_equal 0xff, table
    attributes = Netlink::TLV.decode(payload.byteslice(12, payload.bytesize - 12))

    assert_equal([Netlink::RTA_DST, Netlink::RTA_OIF, Netlink::RTA_TABLE], attributes.map { |entry| entry.fetch("type") })
    assert_equal [1000].pack("L<"), attributes.fetch(2).fetch("value")
  ensure
    socket&.close
  end

  def test_neighbor_encoder_uses_ndmsg_and_binary_link_layer_address
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }), sequence: 30)

    netlink.neighbor_add(destination: "198.18.1.9", lladdr: "02:00:00:00:00:09", dev: "lo")

    header, payload = split_message(socket.message)

    assert_equal Netlink::RTM_NEWNEIGH, header.fetch(:type)
    family, pad1, pad2, index, state, flags, type = payload.byteslice(0, 12).unpack("CCS<l<S<CC")

    assert_equal [Netlink::AF_INET, 0, 0, 1, Netlink::NUD_PERMANENT, 0, Netlink::RTN_UNICAST],
                 [family, pad1, pad2, index, state, flags, type]
    attributes = Netlink::TLV.decode(payload.byteslice(12, payload.bytesize - 12))

    assert_equal([Netlink::NDA_DST, Netlink::NDA_LLADDR], attributes.map { |entry| entry.fetch("type") })
    assert_equal "\xC6\x12\x01\x09".b, attributes.fetch(0).fetch("value")
    assert_equal "\x02\x00\x00\x00\x00\x09".b, attributes.fetch(1).fetch("value")
  ensure
    socket&.close
  end

  def test_vxlan_encoder_uses_nested_uapi_attributes_and_network_order_port
    socket = CaptureSocket.new
    netlink = Netlink.new(adapter: Netlink::SocketAdapter.new(socket_factory: -> { socket }), sequence: 40)

    netlink.link_add(name: "rk-vxlan0", kind: "vxlan", vni: 4096, dstport: 4789,
                     learning: false, dev: "lo", local: "198.18.1.10", mtu: 1450)

    _header, payload = split_message(socket.message)
    attributes = Netlink::TLV.decode(payload.byteslice(16, payload.bytesize - 16))
    link_info = Netlink::TLV.decode(attributes.find { |entry| entry.fetch("type") == Netlink::IFLA_LINKINFO }.fetch("value"))
    data = Netlink::TLV.decode(link_info.find { |entry| entry.fetch("type") == Netlink::IFLA_INFO_DATA }.fetch("value"))
    values = data.to_h { |entry| [entry.fetch("type"), entry.fetch("value")] }

    assert_equal [4096].pack("L<"), values.fetch(Netlink::IFLA_VXLAN_ID)
    assert_equal [4789].pack("S>"), values.fetch(Netlink::IFLA_VXLAN_PORT)
    assert_equal [0].pack("C"), values.fetch(Netlink::IFLA_VXLAN_LEARNING)
    assert_equal [1].pack("L<"), values.fetch(Netlink::IFLA_VXLAN_LINK)
    assert_equal "\xC6\x12\x01\x0A".b, values.fetch(Netlink::IFLA_VXLAN_LOCAL)
  ensure
    socket&.close
  end

  def test_fake_adapter_can_continue_using_unresolved_interface_names
    adapter = RecordingAdapter.new
    netlink = Netlink.new(adapter: adapter)

    netlink.link_set(name: "fake-interface", up: true)

    request = adapter.requests.fetch(0)

    assert_equal Netlink::RTM_SETLINK, request.fetch(:type)
    assert_includes request.fetch(:attributes).map { |entry| entry.fetch("type") }, Netlink::IFLA_IFNAME
  end

  def test_namespace_lease_binds_holder_generation_pidfd_and_inode_to_one_open_fd
    pidfd = Rubernetes::Platform::Linux::Pidfd.new.open(pid: Process.pid)
    context = namespace_context(pidfd)

    lease = Netlink::NamespaceLease.open(context)

    assert_equal context.fetch("inode"), File.stat("/proc/self/fd/#{lease.fileno}").ino
    assert_equal context.fetch("pid"), lease.pid
    refute_predicate lease, :closed?
  ensure
    lease&.close
    IO.for_fd(pidfd).close if pidfd
  end

  def test_namespace_lease_rejects_pid_reuse_path_replacement_and_inode_replacement
    pidfd = Rubernetes::Platform::Linux::Pidfd.new.open(pid: Process.pid)
    context = namespace_context(pidfd)

    assert_raises(Rubernetes::Network::OwnershipError) do
      Netlink::NamespaceLease.open(context.merge("start_time" => context.fetch("start_time") + 1))
    end
    assert_raises(Rubernetes::Network::OwnershipError) do
      Netlink::NamespaceLease.open(context.merge("path" => "/proc/self/ns/net"))
    end
    assert_raises(Rubernetes::Network::OwnershipError) do
      Netlink::NamespaceLease.open(context.merge("inode" => context.fetch("inode") + 1))
    end
  ensure
    IO.for_fd(pidfd).close if pidfd
  end

  def test_netlink_rejects_raw_namespace_paths_before_adapter_dispatch
    adapter = RecordingAdapter.new
    netlink = Netlink.new(adapter: adapter)

    error = assert_raises(Rubernetes::Network::ValidationError) do
      netlink.link_add(name: "veth0", kind: "veth", peer: "eth0", namespace_fd: "/proc/1/ns/net")
    end

    assert_match(/cannot be reopened/, error.message)
    assert_empty adapter.requests
  end

  private

  def namespace_context(pidfd)
    pid = Process.pid
    stat = File.binread("/proc/#{pid}/stat").rpartition(") ").last.split
    {"handle" => "namespace:test", "path" => "/proc/#{pid}/ns/net",
     "inode" => File.stat("/proc/#{pid}/ns/net").ino, "pid" => pid,
     "pidfd" => pidfd, "start_time" => Integer(stat.fetch(19))}
  end

  def split_message(message)
    length, type, flags, sequence, pid = message.byteslice(0, Netlink::HEADER_SIZE).unpack("L<S<S<L<L<")

    assert_equal message.bytesize, length
    assert_operator sequence, :>, 0
    assert_equal 0, pid
    [{type: type, flags: flags}, message.byteslice(Netlink::HEADER_SIZE, length - Netlink::HEADER_SIZE)]
  end
end
