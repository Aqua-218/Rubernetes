# frozen_string_literal: true

require_relative "../test_helper"
require_relative "../support/network_test_fakes"

# A reused Pod address must not inherit the host's neighbour entry for the
# previous holder: the entry is dropped when the address is taken and again
# when it is given up.
class NetworkNeighbourFlushTest < Minitest::Test
  class NeighbourNetlink
    attr_reader :deleted

    def initialize = @deleted = []

    def neighbor_delete(destination:, dev:, operation: nil, **_options)
      @deleted << [destination, dev]
      raise Rubernetes::Network::NetlinkError.new("no such entry", errno: Errno::ENOENT::Errno) if @deleted.length.odd?

      true
    end
  end

  def test_the_neighbour_entry_is_flushed_on_attach_and_release
    adapter = NetworkTestFakes::RecordingAdapter.new
    netlink = NeighbourNetlink.new
    ipam = Rubernetes::Network::IPAM.new(ipv4_cidr: "10.244.0.0/16", ipv4_node_prefix: 24)
    network = Rubernetes::Network::Interface.new(ipam: ipam, adapter: adapter, netlink: netlink)

    result = network.add({"sandbox_id" => "sandbox-a", "pod_uid" => "pod-a"}, "node" => "node-a", "families" => ["ipv4"])
    ip = result.fetch("ip")
    assert_equal [[ip, Rubernetes::Network::Topology::DEFAULT_BRIDGE]], netlink.deleted.uniq, "flushed once on attach (a missing entry is not an error)"

    network.delete("sandbox-a", stopped: true)
    assert_equal 2, netlink.deleted.length, "flushed again on release"
    assert_equal ip, netlink.deleted.last.first
  end
end
