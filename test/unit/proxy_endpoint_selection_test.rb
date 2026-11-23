# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class ProxyEndpointSelectionTest < Minitest::Test
  Adapter = Rubernetes::Proxy::NftablesNetlinkAdapter

  def setup
    @adapter = Adapter.new(transport: Object.new)
  end

  def expression(bytes)
    attrs = @adapter.send(:decode_attributes, bytes)
    name = @adapter.send(:string_value, attrs, Adapter::NFTA_EXPR_NAME)
    data = @adapter.send(:nested_value, attrs, Adapter::NFTA_EXPR_DATA)
    [name, @adapter.send(:decode_attributes, data)]
  end

  def field(data, type)
    @adapter.send(:uint32_value, data, type)
  end

  def test_the_flow_hash_covers_the_address_and_source_port_in_both_families
    [[Adapter::NFPROTO_IPV4, 8, Adapter::NFT_REG32_05], [Adapter::NFPROTO_IPV6, 20, Adapter::NFT_REG32_08]].each do |family, length, register|
      name, port = expression(@adapter.send(:source_port_expression, family).first)

      assert_equal "payload", name
      assert_equal register, field(port, Adapter::NFTA_PAYLOAD_DREG)
      assert_equal 0, field(port, Adapter::NFTA_PAYLOAD_OFFSET)
      assert_equal 2, field(port, Adapter::NFTA_PAYLOAD_LEN)
      name, hash = expression(@adapter.send(:source_hash_expression, family, 3).first)

      assert_equal "hash", name
      assert_equal length, field(hash, Adapter::NFTA_HASH_LEN)
      assert_equal 3, field(hash, Adapter::NFTA_HASH_MODULUS)
    end
  end

  def test_all_affinity_lookups_precede_selection_and_both_refresh_the_map
    proxy = Rubernetes::Proxy
    spec = {"clusterIP" => "192.0.2.10", "sessionAffinity" => "ClientIP", "ports" => [{"port" => 80, "targetPort" => 8080}]}
    service = {"metadata" => {"name" => "sticky"}, "spec" => spec}
    endpoints = %w[192.0.2.11 192.0.2.12].map { |address| proxy::Endpoint.new(address: address, port: 8080) }
    rules = proxy::RuleCompiler.new.compile(service, endpoints: endpoints).rules
    selectors = @adapter.send(:desired_objects, rules).fetch("rules").filter_map do |rule|
      attrs = @adapter.send(:decode_attributes, rule.dig("message", :attributes))
      list = @adapter.send(:nested_value, attrs, Adapter::NFTA_RULE_EXPRESSIONS)
      expressions = @adapter.send(:decode_attributes, list).to_h { |entry| expression(entry.fetch("value")) }
      next unless expressions.key?("dynset")

      update = expressions.fetch("dynset")

      assert_equal Adapter::NFT_DYNSET_OP_UPDATE, field(update, Adapter::NFTA_DYNSET_OP)
      assert_equal 2, field(update, Adapter::NFTA_DYNSET_SREG_KEY)
      assert_equal 1, field(update, Adapter::NFTA_DYNSET_SREG_DATA)
      expressions.keys & %w[lookup hash]
    end

    assert_equal [%w[lookup], %w[lookup], %w[hash], %w[hash]], selectors
  end
end
