# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

# The nftables graph has one rule per endpoint and every rule re-evaluates the
# selector, so the selector must answer the same for every rule of a
# connection -- `numgen random` does not, and left almost a third of packets
# matching no rule at all.  It must also not answer the same for every
# connection from a client unless the Service asked for ClientIP affinity:
# hashing the source address alone made every Service sticky, and
# "[sig-network] Services should be able to switch session affinity" failed
# with "Affinity shouldn't hold but did".  Address . source port is constant
# within a connection and differs between connections.
class ProxyEndpointSelectionTest < Minitest::Test
  Adapter = Rubernetes::Proxy::NftablesNetlinkAdapter

  def adapter = Adapter.allocate

  def hash_length(expressions)
    blob = expressions.map(&:to_s).join
    # NFTA_HASH_LEN is attribute 3; its u32 value is the byte count hashed.
    blob.bytesize
  end

  def test_the_port_is_loaded_right_after_the_address_for_ipv4
    ipv4 = adapter.send(:source_port_expression, Adapter::NFPROTO_IPV4)
    ipv6 = adapter.send(:source_port_expression, Adapter::NFPROTO_IPV6)

    refute_equal(ipv4.map(&:to_s).join, ipv6.map(&:to_s).join,
                 "IPv6 addresses fill NFT_REG_2, so the port goes one register later")
  end

  def test_including_the_port_widens_the_hashed_key
    without = adapter.send(:source_hash_expression, Adapter::NFPROTO_IPV4, 3, nil)
    with = adapter.send(:source_hash_expression, Adapter::NFPROTO_IPV4, 3, nil, include_port: true)

    refute_equal(without.map(&:to_s).join, with.map(&:to_s).join)
  end

  # The selector stays a deterministic hash in both modes; never numgen.
  def test_selection_is_never_a_random_number_generator
    [false, true].each do |include_port|
      blob = adapter.send(:source_hash_expression, Adapter::NFPROTO_IPV4, 3, nil, include_port: include_port)
        .map(&:to_s).join

      assert_includes(blob, "hash")
      refute_includes(blob, "numgen")
    end
  end
end
