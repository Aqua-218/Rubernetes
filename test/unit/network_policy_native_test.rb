# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/network"

class NetworkPolicyNativeTest < Minitest::Test
  PACKET_MATRIX = Rubernetes::Network::NftablesPolicyAdapter::POLICY_PACKET_CASES.to_h { |key| [key, true] }.freeze

  def test_compiler_keeps_selector_union_named_ports_and_family_specific_ipblocks
    pods = [
      {"namespace" => "apps", "name" => "frontend", "labels" => {"app" => "frontend"},
       "ips" => ["10.0.0.10", "fd00::10"], "ports" => [{"name" => "web", "port" => 8080}]},
      {"namespace" => "apps", "name" => "backend", "labels" => {"app" => "backend"},
       "ips" => ["10.0.0.20", "fd00::20"]},
      {"namespace" => "trusted", "name" => "backend", "labels" => {"app" => "backend"},
       "ips" => ["10.0.0.30", "fd00::30"], "ports" => [{"name" => "web", "port" => 8081}]}
    ]
    engine = Rubernetes::Network::PolicyEngine.new(
      pod_index: pods,
      namespace_labels: {"apps" => {"team" => "apps"}, "trusted" => {"team" => "trusted"}}
    )
    policy = {
      "metadata" => {"name" => "frontend-policy", "namespace" => "apps"},
      "spec" => {
        "podSelector" => {"matchLabels" => {"app" => "frontend"}},
        "policyTypes" => %w[Ingress Egress],
        "ingress" => [{
          "from" => [
            {"podSelector" => {"matchLabels" => {"app" => "backend"}}},
            {"ipBlock" => {"cidr" => "10.0.0.0/24", "except" => ["10.0.0.0/26"]}},
            {"ipBlock" => {"cidr" => "2001:db8::/120", "except" => ["2001:db8::/124"]}}
          ],
          "ports" => [{"protocol" => "TCP", "port" => "web"}]
        }],
        "egress" => [{
          "to" => [{"namespaceSelector" => {"matchLabels" => {"team" => "trusted"}},
                    "podSelector" => {"matchLabels" => {"app" => "backend"}}}],
          "ports" => [{"protocol" => "UDP", "port" => 80, "endPort" => 90}]
        }]
      }
    }

    kernel = engine.apply([policy], revision: 1).entries.fetch("kernel")
    rules = kernel.fetch("rules")

    assert_equal true, kernel.fetch("pod_index_present")
    assert_equal 4, kernel.fetch("targets").length
    assert(rules.any? { |rule| rule.values_at("direction", "family", "protocol", "port") == ["ingress", "ipv4", "TCP", 8080] })
    assert(rules.any? { |rule| rule.values_at("direction", "family", "protocol", "port", "end_port") == ["egress", "ipv4", "UDP", 80, 90] })
    assert(rules.any? { |rule| rule.fetch("family") == "ipv6" && rule.dig("peer", "cidr") == "2001:db8::10/124" })
    refute(rules.any? { |rule| rule.fetch("family") == "ipv4" && rule.dig("peer", "cidr").to_s.include?("2001:") })
    refute(rules.any? { |rule| rule.dig("peer", "cidr") == "10.0.0.0/26" })
  end

  def test_egress_named_port_without_to_resolves_every_destination_pod
    pods = [
      {"namespace" => "apps", "name" => "client", "labels" => {"app" => "client"},
       "ips" => ["10.0.0.10"]},
      {"namespace" => "apps", "name" => "web-a", "labels" => {"app" => "web"},
       "ips" => ["10.0.0.20"], "ports" => [{"name" => "web", "port" => 8080}]},
      {"namespace" => "other", "name" => "web-b", "labels" => {"app" => "web"},
       "ips" => ["10.0.0.30"], "ports" => [{"name" => "web", "port" => 8081}]}
    ]
    engine = Rubernetes::Network::PolicyEngine.new(pod_index: pods)
    policy = {
      "metadata" => {"name" => "client-egress", "namespace" => "apps"},
      "spec" => {
        "podSelector" => {"matchLabels" => {"app" => "client"}},
        "policyTypes" => ["Egress"],
        # No `to` means every destination pod. Named ports must be resolved
        # against each destination pod rather than against the wildcard peer.
        "egress" => [{"ports" => [{"protocol" => "TCP", "port" => "web"}]}]
      }
    }

    rules = engine.apply([policy], revision: 1).entries.dig("kernel", "rules")

    assert_equal [8080, 8081], rules.map { |rule| rule.fetch("port") }.uniq.sort
    assert(rules.all? { |rule| rule.dig("peer", "kind") == "all" })
    assert(rules.all? { |rule| rule.fetch("direction") == "egress" })
  end

  def test_cross_family_peers_are_not_compiled_and_omitted_peers_cover_both_families
    pods = [{"namespace" => "apps", "name" => "server", "labels" => {"app" => "server"},
             "ips" => ["10.0.0.10", "2001:db8::10"]}]
    engine = Rubernetes::Network::PolicyEngine.new(pod_index: pods)
    cross_family = {
      "metadata" => {"name" => "v6-only", "namespace" => "apps"},
      "spec" => {
        "podSelector" => {"matchLabels" => {"app" => "server"}},
        "policyTypes" => ["Ingress"],
        "ingress" => [{"from" => [{"ipBlock" => {"cidr" => "2001:db8::/64"}}],
                       "ports" => [{"protocol" => "TCP", "port" => 443}]}]
      }
    }
    cross_family_rules = engine.apply([cross_family], revision: 1).entries.dig("kernel", "rules")

    assert(cross_family_rules.all? { |rule| rule.fetch("family") == "ipv6" })
    assert(cross_family_rules.all? { |rule| rule.dig("peer", "cidr") == "2001:db8::/64" })

    omitted_peer = {
      "metadata" => {"name" => "all-families", "namespace" => "apps"},
      "spec" => {
        "podSelector" => {"matchLabels" => {"app" => "server"}},
        "policyTypes" => ["Ingress"],
        "ingress" => [{"ports" => [{"protocol" => "TCP", "port" => 443}]}]
      }
    }
    omitted_rules = engine.apply([omitted_peer], revision: 2).entries.dig("kernel", "rules")

    assert_equal %w[ipv4 ipv6], omitted_rules.map { |rule| rule.fetch("family") }.uniq.sort
    assert(omitted_rules.all? { |rule| rule.dig("peer", "kind") == "all" })
  end

  def test_nft_target_peer_and_partial_cidr_rules_start_with_nfproto_guard
    adapter = Rubernetes::Network::NftablesPolicyAdapter.new(table_name: "rkpol_guard_unit")
    names = lambda do |expressions|
      expressions.map do |item|
        length = item.byteslice(0, 2).unpack1("v")
        item.byteslice(4, length - 4).delete_suffix("\0")
      end
    end

    target = {"direction" => "ingress", "ip" => "10.0.0.10", "family" => "ipv4"}

    assert_equal %w[meta cmp payload cmp], names.call(adapter.send(:target_match_expressions, target))

    rule = {"direction" => "ingress", "target" => "10.0.0.10", "family" => "ipv4",
            "peer" => {"kind" => "cidr", "cidr" => "10.0.0.0/24"},
            "protocol" => nil, "port" => nil, "end_port" => nil}
    policy_names = names.call(adapter.send(:policy_match_expressions, rule))

    assert_equal 2, policy_names.count("meta"), policy_names.inspect
    assert_equal(2, policy_names.each_index.count { |index| policy_names[index, 2] == %w[meta cmp] })

    cidr_names = names.call(adapter.send(:cidr_expressions, adapter.class::NFPROTO_IPV6,
                                         IPAddr.new("2001:db8::"), 64, :source))

    assert_equal %w[meta cmp], cidr_names.first(2)
    refute(cidr_names.any? { |name| name.is_a?(Array) })
  end

  def test_nft_policy_markers_are_scoped_to_one_adapter_instance
    first = Rubernetes::Network::NftablesPolicyAdapter.new(
      table_name: "rkpol_instance_unit", instance_identity: "node-a/agent-1"
    )
    second = Rubernetes::Network::NftablesPolicyAdapter.new(
      table_name: "rkpol_instance_unit", instance_identity: "node-a/agent-2"
    )
    marker = first.send(:policy_marker, "rule", "allow:test")

    refute_equal marker, second.send(:policy_marker, "rule", "allow:test")
    assert first.send(:marker_owned?, marker)
    refute second.send(:marker_owned?, marker)
  end

  def test_nft_policy_readback_decodes_and_compares_rule_expressions
    adapter = Rubernetes::Network::NftablesPolicyAdapter.new(
      table_name: "rkpol_expression_unit", instance_identity: "node-a/agent-1"
    )
    expressions = adapter.send(:target_match_expressions,
                               "direction" => "ingress", "ip" => "10.0.0.10", "family" => "ipv4")
    expressions << adapter.send(:drop_expression)
    marker = adapter.send(:policy_marker, "rule", "drop:test")
    message = adapter.send(:new_rule_message, chain_name: "forward", marker: marker, expressions: expressions)
    decoded = adapter.send(:decoded_rule_expressions_from_attributes, message.fetch(:attributes))

    assert_equal(%w[meta cmp payload cmp immediate], decoded.map { |entry| entry.fetch("name") })
    refute(decoded.any? { |entry| entry.fetch("data").nil? })
  end

  def test_pod_selector_peer_defaults_to_policy_namespace
    engine = Rubernetes::Network::PolicyEngine.new(
      pod_index: [
        {"namespace" => "apps", "name" => "front", "labels" => {"app" => "front"}, "ips" => ["10.0.0.10"]},
        {"namespace" => "apps", "name" => "back", "labels" => {"app" => "back"}, "ips" => ["10.0.0.20"]},
        {"namespace" => "other", "name" => "back", "labels" => {"app" => "back"}, "ips" => ["10.0.0.30"]}
      ]
    )
    policy = {"metadata" => {"name" => "front", "namespace" => "apps"},
              "spec" => {"podSelector" => {"matchLabels" => {"app" => "front"}},
                         "policyTypes" => ["Ingress"],
                         "ingress" => [{"from" => [{"podSelector" => {"matchLabels" => {"app" => "back"}}}]}]}}
    engine.apply([policy], revision: 1)

    destination = {"namespace" => "apps", "labels" => {"app" => "front"}, "ip" => "10.0.0.10"}

    assert engine.allowed?(source: {"namespace" => "apps", "labels" => {"app" => "back"}, "ip" => "10.0.0.20"},
                           destination: destination, direction: "Ingress")
    refute engine.allowed?(source: {"namespace" => "other", "labels" => {"app" => "back"}, "ip" => "10.0.0.30"},
                           destination: destination, direction: "Ingress")
  end

  def test_empty_namespace_selector_selects_namespaces_even_without_namespace_label_cache
    engine = Rubernetes::Network::PolicyEngine.new(
      pod_index: [
        {"namespace" => "apps", "name" => "front", "labels" => {"app" => "front"}, "ips" => ["10.0.0.10"]},
        {"namespace" => "other", "name" => "back", "labels" => {"app" => "back"}, "ips" => ["10.0.0.30"]}
      ]
    )
    policy = {"metadata" => {"name" => "front", "namespace" => "apps"},
              "spec" => {"podSelector" => {"matchLabels" => {"app" => "front"}},
                         "policyTypes" => ["Ingress"],
                         "ingress" => [{"from" => [{"namespaceSelector" => {}}]}]}}
    kernel = engine.apply([policy], revision: 1).entries.fetch("kernel")

    assert_includes kernel.fetch("rules").map { |rule| rule.dig("peer", "ip") }, "10.0.0.30"
  end

  def test_native_adapters_reject_snapshots_without_concrete_pod_index
    snapshot = {"revision" => 1, "entries" => {"kernel" => {"targets" => [], "rules" => [], "pod_index_present" => false}}}
    nft = Rubernetes::Network::NftablesPolicyAdapter.new(table_name: "rkpol_unit_native")
    ebpf = Rubernetes::Network::EBPFPolicyAdapter.new

    assert_raises(Rubernetes::Network::PolicyError) { nft.atomic_swap(snapshot) }
    assert_raises(Rubernetes::Network::PolicyError) { ebpf.atomic_swap(snapshot) }
    refute_predicate nft, :production_capable?
    refute_predicate ebpf, :production_capable?
  end

  def test_packet_matrix_is_the_only_production_capability_gate
    nft = Rubernetes::Network::NftablesPolicyAdapter.new(table_name: "rkpol_unit_matrix")
    ebpf = Rubernetes::Network::EBPFPolicyAdapter.new

    refute_predicate nft, :production_capable?
    refute_predicate ebpf, :production_capable?
    assert nft.verify_packet_matrix!(matrix: PACKET_MATRIX)
    assert ebpf.verify_packet_matrix!(matrix: PACKET_MATRIX)
    assert_predicate nft, :production_capable?
    assert_predicate ebpf, :production_capable?
  end

  def test_ebpf_target_drop_is_emitted_even_when_allow_rule_set_is_empty
    target = {"direction" => "ingress", "target" => "10.0.0.10", "family" => "ipv4"}
    without_target = Rubernetes::Network::EBPFPolicyProgram.new(map_fds: {"flows" => 9}, rules: [], targets: []).build
    with_target = Rubernetes::Network::EBPFPolicyProgram.new(map_fds: {"flows" => 9}, rules: [], targets: [target]).build

    assert_operator with_target.length, :>, without_target.length
  end

  def test_ebpf_reverse_conntrack_key_swaps_each_network_order_port_byte
    # NetworkPolicy reverse-flow matching must exchange source/destination
    # port bytes for every parsed IP family and L4 protocol.
    program_class = Rubernetes::Network::EBPFPolicyProgram
    assembler = program_class::Assembler
    instructions = program_class.new(map_fds: {"flows" => 9}, rules: [], targets: []).build
    load_code = assembler::BPF_LDX | assembler::BPF_B | assembler::BPF_MEM
    store_code = assembler::BPF_STX | assembler::BPF_B | assembler::BPF_MEM
    expected = [
      [program_class::STACK_PORTS + 2, program_class::STACK_REVERSE_KEY + 2],
      [program_class::STACK_PORTS + 3, program_class::STACK_REVERSE_KEY + 3],
      [program_class::STACK_PORTS, program_class::STACK_REVERSE_KEY + 4],
      [program_class::STACK_PORTS + 1, program_class::STACK_REVERSE_KEY + 5]
    ]

    observed = instructions.each_cons(2).filter_map do |load, store|
      next unless load.code == load_code && store.code == store_code
      next unless load.destination == 2 && load.source == 10
      next unless store.destination == 10 && store.source == 2

      [load.offset, store.offset]
    end

    assert_equal(expected, observed.select { |source, destination| expected.include?([source, destination]) })
  end

  def test_ebpf_failed_swap_reattaches_the_complete_previous_filter_set
    adapter = Rubernetes::Network::EBPFPolicyAdapter.new(interfaces: [7])
    calls = []
    adapter.define_singleton_method(:attach_policy_filter) do |ifindex, direction, program, replace: false|
      calls << [ifindex, direction, program, replace]
      {ifindex: ifindex, direction: direction, parent: direction, handle: 1, priority: 100}
    end
    adapter.define_singleton_method(:verify_policy_kernel_state) do |ifindex|
      calls << [:verify, ifindex]
      {"verified" => true}
    end
    old_program = Object.new
    old_maps = {"flows" => Object.new}.freeze
    old_links = [
      {ifindex: 7, direction: :ingress},
      {ifindex: 7, direction: :egress}
    ].freeze

    restored = adapter.send(
      :restore_previous_policy_state,
      program: old_program, maps: old_maps, links: old_links, attached: true, interfaces: [7]
    )

    assert_equal true, restored
    assert_equal [[7, :ingress, old_program, true], [7, :egress, old_program, true]], calls.first(2)
    assert_equal [:verify, 7], calls.last
    assert_same old_program, adapter.instance_variable_get(:@program)
    assert_same old_maps, adapter.instance_variable_get(:@maps)
    assert_equal(old_links.map { |link| link.values_at(:ifindex, :direction) },
                 adapter.instance_variable_get(:@links).map { |link| link.values_at(:ifindex, :direction) })
  end

  def test_ebpf_failed_swap_refuses_partial_previous_filter_inventory
    adapter = Rubernetes::Network::EBPFPolicyAdapter.new(interfaces: [7])
    adapter.define_singleton_method(:attach_policy_filter) { raise "must not attach a partial old policy" }

    restored = adapter.send(
      :restore_previous_policy_state,
      program: Object.new, maps: {}, links: [{ifindex: 7, direction: :ingress}],
      attached: true, interfaces: [7]
    )

    assert_equal false, restored
  end
end
