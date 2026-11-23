# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

class DNS64Test < Minitest::Test
  DNS = Rubernetes::Network::DNS
  Wire = DNS::Wire
  PREFIX = "64:ff9b:1::/96"
  NAME = "example.test"
  TARGET = "ipv4.example.test"

  def setup
    @questions = []
    @replies = {}
    upstream = lambda do |packet:, **options|
      query = Wire.decode(packet)
      question = query.questions.first
      @questions << [question.name, question.type, query.cd, query.edns.flags, options[:tcp]]
      Wire.encode(Wire::Message.new(id: query.id, qr: true, ra: true,
                                    questions: [question], **@replies.fetch(question.type, {})))
    end
    @resolver = DNS::Resolver.new(upstreams: ["192.0.2.53"], upstream_adapter: upstream)
    @server = DNS::Server.new(resolver: @resolver, nat64_prefix: PREFIX)
  end

  def test_synthesizes_only_addresses_for_the_queried_name_and_bounds_ttl
    @replies[Wire::TYPE_AAAA] = {
      authority: [record(NAME, Wire::TYPE_SOA, {
                           "mname" => "ns.test", "rname" => "admin.test", "serial" => 1, "refresh" => 1,
                           "retry" => 1, "expire" => 1, "minimum" => 20
                         }, ttl: 30)]
    }
    @replies[Wire::TYPE_A] = {
      answers: [record("unrelated.test", Wire::TYPE_A, "192.0.2.1"),
                record(NAME, Wire::TYPE_CNAME, TARGET),
                record(TARGET, Wire::TYPE_A, "192.0.2.33", ttl: 60)],
      additional: [record(TARGET, Wire::TYPE_A, "192.0.2.4")]
    }
    reply = ask(transport: :tcp)

    assert_equal [[NAME, Wire::TYPE_AAAA, false, 0, true], [NAME, Wire::TYPE_A, false, 0, true]], @questions
    assert_equal([[NAME, Wire::TYPE_CNAME, TARGET], [TARGET, Wire::TYPE_AAAA, "64:ff9b:1::c000:221"]],
                 reply.answers.map { |rr| [rr.name, rr.type, rr.rdata] })
    assert_equal Wire::TYPE_AAAA, reply.questions.first.type
    assert_equal 20, reply.answers.last.ttl
    assert_empty reply.authority
    assert_empty reply.additional
  end

  def test_keeps_ipv6_answers_nxdomain_and_dnssec_requests
    @replies[Wire::TYPE_AAAA] = {answers: [record(NAME, Wire::TYPE_AAAA, "2001:db8::1")]}

    assert_equal "2001:db8::1", ask.answers.first.rdata

    @replies[Wire::TYPE_AAAA] = {rcode: Wire::RCODE_NXDOMAIN}

    assert_equal Wire::RCODE_NXDOMAIN, ask.rcode

    @replies.clear

    assert_empty ask(dnssec: true).answers
    assert_empty ask(cd: true).answers
    assert_equal [[NAME, Wire::TYPE_AAAA, false, 0, false], [NAME, Wire::TYPE_AAAA, false, 0, false],
                  [NAME, Wire::TYPE_AAAA, false, Wire::EDNS_FLAG_DO, false], [NAME, Wire::TYPE_AAAA, true, 0, false]], @questions
  end

  def test_default_dns_leaves_external_nodata_unsynthesized
    @server = DNS::Server.new(resolver: @resolver)

    assert_empty ask.answers
    assert_equal [[NAME, Wire::TYPE_AAAA, false, 0, false]], @questions
  end

  def test_preserves_a_dname_chain_when_synthesizing
    name = "www.example.test"
    target = "www.other.test"
    @replies[Wire::TYPE_A] = {
      answers: [record(NAME, Wire::TYPE_DNAME, "other.test"),
                record(name, Wire::TYPE_CNAME, target),
                record(target, Wire::TYPE_A, "192.0.2.33")]
    }

    assert_equal([[Wire::TYPE_DNAME, "other.test"], [Wire::TYPE_CNAME, target], [Wire::TYPE_AAAA, "64:ff9b:1::c000:221"]],
                 ask(name: name).answers.map { |rr| [rr.type, rr.rdata] })
  end

  def test_keeps_a_and_internal_service_records
    @replies[Wire::TYPE_A] = {answers: [record(NAME, Wire::TYPE_A, "192.0.2.33")]}

    assert_equal "192.0.2.33", ask(type: Wire::TYPE_A).answers.first.rdata

    name = "ipv6.apps.svc.cluster.local"
    @resolver.add_service("metadata" => {"name" => "ipv6", "namespace" => "apps"},
                          "spec" => {"clusterIP" => "fd00::53", "clusterIPs" => ["fd00::53"]})

    assert_equal "fd00::53", ask(name: name).answers.first.rdata
    assert_equal [[NAME, Wire::TYPE_A, false, 0, false]], @questions
  end

  def test_synthesizes_the_external_target_for_externalname_services
    name = "alias.apps.svc.cluster.local"
    @resolver.add_service("metadata" => {"name" => "alias", "namespace" => "apps"},
                          "spec" => {"type" => "ExternalName", "externalName" => NAME})
    @replies[Wire::TYPE_A] = {answers: [record(NAME, Wire::TYPE_A, "192.0.2.33", ttl: 1200)]}
    reply = ask(name: name)

    assert_equal [NAME, "64:ff9b:1::c000:221"], reply.answers.map(&:rdata)
    assert_equal 600, reply.answers.last.ttl
    assert_equal [[NAME, Wire::TYPE_AAAA, false, 0, false], [NAME, Wire::TYPE_A, false, 0, false]], @questions
  end

  def test_embeds_in_each_rfc6052_prefix_and_rejects_misaligned_or_nonunicast_prefixes
    prefixes = {
      "2001:db8::/32" => "2001:db8:c000:221::",
      "2001:db8:100::/40" => "2001:db8:1c0:2:21::",
      "2001:db8:122::/48" => "2001:db8:122:c000:2:2100::",
      "2001:db8:122:300::/56" => "2001:db8:122:3c0:0:221::",
      "2001:db8:122:344::/64" => "2001:db8:122:344:c0:2:2100:0",
      "2001:db8:122:344::/96" => "2001:db8:122:344::c000:221"
    }

    prefixes.each do |prefix, address|
      assert_equal IPAddr.new(address), IPAddr.new(Rubernetes::Network::Nat64Prefix.new(prefix).embed("192.0.2.33")), prefix
    end
    %w[10.0.0.0/8 ::/96 fe80::/96 ff00::/96 fd00::1/96 fd00::/80 fd00::100:0:0:0/96 64:ff9b::/64].each do |invalid|
      assert_raises(ArgumentError, invalid) { Rubernetes::Network::Nat64Prefix.new(invalid) }
    end
    well_known = Rubernetes::Network::Nat64Prefix.new("64:ff9b::/96")

    assert_equal "64:ff9b::808:808", well_known.embed("8.8.8.8")
    assert_nil well_known.embed("10.0.0.1")
  end

  private

  def record(name, type, data, ttl: 60)
    Wire::Record.new(name: name, type: type, klass: Wire::CLASS_IN, ttl: ttl, rdata: data)
  end

  def ask(name: NAME, type: Wire::TYPE_AAAA, transport: :udp, cd: false, dnssec: false)
    query = Wire::Message.new(id: 12, rd: true, cd: cd,
                              questions: [Wire::Question.new(name: name, type: type, klass: Wire::CLASS_IN)])
    query.edns = Wire::EDNS.new(udp_payload: Wire::EDNS_UDP_PAYLOAD, extended_rcode: 0, version: 0, flags: Wire::EDNS_FLAG_DO, options: []) if dnssec
    Wire.decode(@server.respond(Wire.encode(query), client: ["fd00::42", 45_678], transport: transport))
  end
end
