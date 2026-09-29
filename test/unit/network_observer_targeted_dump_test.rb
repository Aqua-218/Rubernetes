# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

# A readback is a poll loop: the interface re-reads the kernel every 20 ms
# until it agrees that the operation landed, and a Pod attach does six of
# them.  The observer answered every one of those polls by dumping the link,
# address, route AND neighbour tables, so confirming that a veth exists paid
# for three dumps that cannot contain the answer.  Measured on a conformance
# node, network attach was the single most expensive phase of a Pod start
# (median 3.2 s, p95 5.3 s) while a Pod start was otherwise ~2 s.
class NetworkObserverTargetedDumpTest < Minitest::Test
  Observer = Rubernetes::Network::NativeObserver

  class CountingNetlink
    attr_reader :calls

    def initialize = @calls = Hash.new(0)

    def link_dump = tally(:link)
    def address_dump = tally(:address)
    def route_dump = tally(:route)
    def neighbor_dump = tally(:neighbour)

    private

    def tally(kind)
      @calls[kind] += 1
      []
    end
  end

  def observer
    @netlink = CountingNetlink.new
    Observer.new(netlink: @netlink)
  end

  def test_a_link_readback_reads_only_the_link_table
    subject = observer

    subject.resources(kinds: ["link"])

    assert_equal({link: 1}, @netlink.calls.to_h)
  end

  def test_an_address_readback_reads_links_and_addresses_only
    subject = observer

    subject.resources(kinds: ["address"])

    assert_equal({link: 1, address: 1}, @netlink.calls.to_h)
  end

  def test_a_route_readback_reads_links_and_routes_only
    subject = observer

    subject.resources(kinds: ["route"])

    assert_equal({link: 1, route: 1}, @netlink.calls.to_h)
  end

  # Recovery compares every durable claim against the kernel, so an unscoped
  # read must still see everything.
  def test_an_unscoped_read_still_dumps_every_table
    subject = observer

    subject.resources

    assert_equal({link: 1, address: 1, route: 1, neighbour: 1}, @netlink.calls.to_h)
  end

  def test_every_handled_action_names_the_table_that_can_prove_it
    expected = {
      "link_add" => %w[link], "link_set" => %w[link], "link_delete" => %w[link],
      "address_add" => %w[address], "address_delete" => %w[address],
      "route_add" => %w[route], "route_delete" => %w[route],
      "fdb_add" => %w[neighbour], "fdb_delete" => %w[neighbour]
    }

    assert_equal expected, Observer::ACTION_KINDS.to_h
  end
end

# A proof about one named link asks the kernel for that link only; the node
# carries one veth per Pod, and every link operation's readback used to dump
# and parse all of them.
class NetworkObserverNamedLinkTest < Minitest::Test
  Observer = Rubernetes::Network::NativeObserver

  class Netlink
    attr_reader :calls

    def initialize(fail_get: false)
      @calls = []
      @fail_get = fail_get
    end

    def link_get(name:)
      @calls << [:get, name]
      raise Rubernetes::Network::NetlinkError, "unsupported" if @fail_get

      []
    end

    def link_dump
      @calls << [:dump]
      []
    end
  end

  def test_a_named_link_readback_uses_a_single_get
    netlink = Netlink.new
    Observer.new(netlink: netlink).resources(kinds: ["link"], link_name: "veth1234")
    assert_equal [[:get, "veth1234"]], netlink.calls
  end

  def test_a_link_add_proof_by_name_does_not_dump
    netlink = Netlink.new
    Observer.new(netlink: netlink).resources_for({"action" => "link_set", "parameters" => {"name" => "veth1234", "up" => true}})
    assert_equal [[:get, "veth1234"]], netlink.calls
  end

  def test_a_failed_get_falls_back_to_the_dump
    netlink = Netlink.new(fail_get: true)
    Observer.new(netlink: netlink).resources(kinds: ["link"], link_name: "veth1234")
    assert_equal [[:get, "veth1234"], [:dump]], netlink.calls
  end

  def test_other_kinds_still_dump_links
    netlink = Netlink.new
    netlink.define_singleton_method(:address_dump) { [] }
    Observer.new(netlink: netlink).resources(kinds: ["address"], link_name: "veth1234")
    assert_equal [[:dump]], netlink.calls, "an address proof needs every link to resolve interfaces"
  end
end
