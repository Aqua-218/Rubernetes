# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network/dns"

# Static hosts on the node DNS (CoreDNS hosts plugin): exact names and
# `*.suffix` wildcards answered authoritatively, A/AAAA by family, and
# never forwarded upstream.
class DNSStaticHostsTest < Minitest::Test
  DNS = Rubernetes::Network::DNS

  def resolver
    DNS::Resolver.new(domain: "cluster.local", cluster_ip: "10.240.0.1",
                      hosts: {"gitlab.dev.provn-vm.jp" => "10.240.0.1",
                              "*.dev.provn-vm.jp" => ["10.240.0.1", "fd00::1"]})
  end

  def test_exact_and_wildcard_names_are_answered_locally
    dns = resolver

    assert dns.authoritative?("gitlab.dev.provn-vm.jp")
    assert dns.authoritative?("registry.dev.provn-vm.jp.")
    refute dns.authoritative?("dev.provn-vm.jp"), "the wildcard does not cover the apex"
    refute dns.authoritative?("example.com")

    exact = dns.resolve("gitlab.dev.provn-vm.jp", type: "A")

    assert_equal ["10.240.0.1"], exact.records.map(&:data)
    assert_equal "NOERROR", exact.rcode

    wildcard_a = dns.resolve("registry.dev.provn-vm.jp", type: "A")

    assert_equal ["10.240.0.1"], wildcard_a.records.map(&:data)
    wildcard_aaaa = dns.resolve("kas.dev.provn-vm.jp", type: "AAAA")

    assert_equal ["fd00::1"], wildcard_aaaa.records.map(&:data)
    # NODATA, not NXDOMAIN: the name exists, it has no record of that type.
    nodata = dns.resolve("gitlab.dev.provn-vm.jp", type: "AAAA")

    assert_empty nodata.records
    assert_equal "NOERROR", nodata.rcode
  end

  def test_invalid_entries_are_rejected
    assert_raises(Rubernetes::Network::ValidationError) { DNS::Resolver.new(hosts: {"x.example" => []}) }
    assert_raises(Rubernetes::Network::ValidationError) { DNS::Resolver.new(hosts: {"x.example" => "not-an-ip"}) }
  end
end
