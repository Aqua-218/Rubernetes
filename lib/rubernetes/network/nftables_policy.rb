# frozen_string_literal: true

# Native NetworkPolicy enforcement through the nf_tables netlink ABI. This
# adapter deliberately shares only the wire-level transaction primitives with
# the Service adapter; policy compilation remains owned by network/policy.rb.

require "digest"
require "ipaddr"
require "json"

require_relative "policy"
require_relative "../proxy/nftables_netlink"

module Rubernetes
  module Network
    # Direct kernel NetworkPolicy adapter. A policy revision is accepted only
    # after one nfnetlink batch and a complete owned-object readback succeed.
    class NftablesPolicyAdapter < Rubernetes::Proxy::NftablesNetlinkAdapter
      NftablesNetlinkError = Rubernetes::Proxy::NftablesNetlinkError
      NF_INET_FORWARD = 2
      NFPROTO_IPV4 = 2
      NFPROTO_IPV6 = 10
      NFT_DROP = 0
      NFT_META_NFPROTO = 15
      NFT_META_L4PROTO = 16
      NFT_PAYLOAD_NETWORK_HEADER = 1
      NFT_PAYLOAD_TRANSPORT_HEADER = 2
      NFT_CMP_LTE = 3
      NFT_CMP_GTE = 5
      NFT_CT_STATE = 0
      NFT_CT_ESTABLISHED = 2
      NFT_CT_RELATED = 4
      NFTA_CHAIN_HOOK_NUM = 1
      NFTA_CHAIN_HOOK_PRIORITY = 2

      POLICY_PACKET_CASES = %w[
        default_deny_ingress default_deny_egress selector_ingress selector_egress
        namespace_selector additive_union ipblock_except_ipv4 ipblock_except_ipv6
        named_port named_port_egress_all end_port tcp udp sctp dual_stack established atomic_readback
        multi_interface_readback
      ].freeze

      POLICY_FEATURE_MATRIX = {
        ingress_isolation: true,
        egress_isolation: true,
        namespace_selector: true,
        pod_selector: true,
        ip_block_except: true,
        named_ports: true,
        end_port: true,
        tcp: true,
        udp: true,
        sctp: true,
        ipv4: true,
        ipv6: true,
        additive_union: true,
        established_related: true,
        atomic_batch: true,
        owned_readback: true,
        multi_interface_readback: true
      }.freeze
      POLICY_MARKER_KINDS = %w[policy-table policy-chain policy-rule].freeze

      attr_reader :last_snapshot, :last_readback, :last_transaction, :packet_matrix,
                  :policy_feature_matrix, :instance_identity

      def initialize(table_name: "rubernetes_policy", timeout: 2.0, socket_factory: nil, transport: nil,
                     instance_identity: nil)
        @instance_identity = String(instance_identity || "#{Socket.gethostname}/#{table_name}")
        raise ArgumentError, "nftables policy instance identity is invalid" if @instance_identity.empty? || @instance_identity.include?("\0")

        super(table_name: table_name, timeout: timeout, socket_factory: socket_factory, transport: transport)
        @packet_matrix = nil
        @policy_feature_matrix = POLICY_FEATURE_MATRIX.dup.freeze
        @policy_mutex = Mutex.new
        @last_snapshot = nil
        @last_readback = nil
        @last_transaction = nil
      end

      def production_capable?
        !@packet_matrix.nil? && POLICY_FEATURE_MATRIX.values.all? &&
          POLICY_PACKET_CASES.all? { |key| @packet_matrix.fetch(key, false) == true }
      end

      def test_adapter?
        false
      end

      def production_capability_error
        return "nftables NetworkPolicy adapter is production-capable" if production_capable?

        missing = POLICY_PACKET_CASES.reject { |key| @packet_matrix.is_a?(Hash) && @packet_matrix[key] == true }
        "nftables NetworkPolicy adapter is not production-capable: packet matrix is incomplete (#{missing.join(", ")})"
      end

      # The packet matrix must come from isolated pod netns/veth traffic. A
      # model evaluator or a CNI oracle response cannot mark this adapter.
      def verify_packet_matrix!(matrix:)
        values = matrix.respond_to?(:transform_keys) ? matrix.transform_keys(&:to_s) : {}
        missing = POLICY_PACKET_CASES.reject { |key| values[key] == true }
        raise PolicyError, "NetworkPolicy packet matrix is incomplete: #{missing.join(", ")}" unless missing.empty?

        @packet_matrix = values.freeze
        true
      end

      # Apply a complete PolicyEngine snapshot as one atomic nfnetlink batch.
      # No command-line nft invocation is used, and failed readback leaves the
      # adapter's previous accepted revision visible to its caller.
      def atomic_swap(snapshot)
        normalized = normalize_policy_snapshot(snapshot)
        desired = desired_policy_objects(normalized)
        @policy_mutex.synchronize do
          current = read_kernel_ruleset
          ensure_owned_table!(current) if current["table"]
          ensure_owned_objects!(current)
          previous_desired = @last_snapshot && desired_policy_objects(@last_snapshot)
          messages = policy_lifecycle_messages(current, desired)
          transaction = send_transaction(messages)
          actual = read_kernel_ruleset
          unless verify_policy_readback(actual, desired)
            difference = policy_readback_difference(actual, desired)
            restore_previous_ruleset!(actual, previous_desired)
            raise NftablesNetlinkError,
                  "NetworkPolicy transaction completed without matching kernel readback (#{difference}); " \
                  "the prior ruleset was restored and verified"
          end

          @last_snapshot = normalized.freeze
          @last_transaction = transaction.freeze
          @last_readback = actual.merge("verified" => true).freeze
          true
        end
      rescue Rubernetes::Proxy::NftablesNetlinkError => error
        raise PolicyRevisionError, "native nftables NetworkPolicy revision was rejected: #{error.message}"
      rescue PolicyError
        raise
      rescue StandardError => error
        raise PolicyRevisionError, "native nftables NetworkPolicy revision was rejected: #{error.message}"
      end

      alias swap atomic_swap
      alias replace atomic_swap

      def readback(snapshot: @last_snapshot)
        normalized = snapshot && normalize_policy_snapshot(snapshot)
        desired = normalized && desired_policy_objects(normalized)
        actual = @policy_mutex.synchronize { read_kernel_ruleset }
        verified = desired ? verify_policy_readback(actual, desired) : owned_readback?(actual)
        result = actual.merge("verified" => verified).freeze
        @last_readback = result
        result
      end

      def detach
        @policy_mutex.synchronize do
          actual = read_kernel_ruleset
          return true unless actual["table"]

          ensure_owned_table!(actual)
          ensure_owned_objects!(actual)
          messages = actual.fetch("rules").map { |entry| delete_rule_message(entry) }
          messages.concat(actual.fetch("chains").reverse_each.map { |entry| delete_chain_message(entry) })
          messages << {type: NFT_MSG_DELTABLE, flags: NLM_F_REQUEST | NLM_F_ACK,
                       family: NFPROTO_INET,
                       attributes: [attribute(NFTA_TABLE_NAME, cstring(@table_name))].join}
          transaction = send_transaction(messages)
          remaining = read_kernel_ruleset
          raise NftablesNetlinkError, "NetworkPolicy detach readback still contains #{@table_name.inspect}" if remaining["table"]

          @last_snapshot = nil
          @last_transaction = transaction.freeze
          @last_readback = remaining.merge("verified" => true).freeze
          true
        end
      rescue Rubernetes::Proxy::NftablesNetlinkError => error
        raise PolicyRevisionError, "native nftables NetworkPolicy detach was rejected: #{error.message}"
      end

      private

      def normalize_policy_snapshot(snapshot)
        value = snapshot.respond_to?(:to_h) ? snapshot.to_h : snapshot
        raise PolicyError, "native NetworkPolicy adapter requires a snapshot object" unless value.is_a?(Hash)

        entries = value["entries"] || value[:entries] || value
        raise PolicyError, "native NetworkPolicy adapter requires compiled kernel entries" unless entries.is_a?(Hash)

        revision = Integer(value["revision"] || value[:revision] || entries["revision"] || entries[:revision])
        kernel = entries["kernel"] || entries[:kernel]
        raise PolicyError, "native NetworkPolicy snapshot has no kernel compilation" unless kernel.is_a?(Hash)
        raise PolicyError, "native NetworkPolicy snapshot has no concrete pod index" unless kernel["pod_index_present"] == true

        {"revision" => revision, "kernel" => stringify_hash(kernel)}.freeze
      rescue ArgumentError, TypeError
        raise PolicyError, "native NetworkPolicy snapshot revision is invalid"
      end

      def stringify_hash(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, child), result| result[key.to_s] = stringify_hash(child) }
        when Array
          value.map { |child| stringify_hash(child) }
        else
          value
        end
      end

      def desired_policy_objects(snapshot)
        kernel = snapshot.fetch("kernel")
        targets = Array(kernel.fetch("targets")).map { |entry| normalize_target(entry) }
        rules = Array(kernel.fetch("rules")).map { |entry| normalize_kernel_rule(entry) }
        chain_marker = policy_marker("chain", "policy:forward")
        chain = {"name" => "forward", "marker" => chain_marker, "base" => true,
                 "message" => new_policy_chain_message(name: "forward", marker: chain_marker)}
        rule_objects = []
        rule_objects.concat(conntrack_rule_objects)
        rules.each_with_index do |rule, index|
          rule_objects << policy_allow_rule_object(rule, index)
        end
        targets.each_with_index do |target, index|
          rule_objects << policy_drop_rule_object(target, index)
        end
        {"table" => {"name" => @table_name, "marker" => policy_marker("table", @table_name),
                     "message" => new_table_message},
         "chains" => [chain], "sets" => [], "set_elements" => [], "rules" => rule_objects}.freeze
      end

      def normalize_target(value)
        hash = stringify_hash(value)
        address = IPAddr.new(hash.fetch("ip"))
        direction = hash.fetch("direction").to_s
        raise PolicyError, "compiled NetworkPolicy target direction is invalid" unless PolicyEngine::DIRECTIONS.include?(direction)

        family = normalize_family(hash.fetch("family"), address, name: "compiled NetworkPolicy target")
        {"direction" => direction, "ip" => address.to_s, "family" => family}
      rescue KeyError, IPAddr::InvalidAddressError => error
        raise PolicyError, "invalid compiled NetworkPolicy target: #{error.message}"
      end

      def normalize_kernel_rule(value)
        hash = stringify_hash(value)
        address = IPAddr.new(hash.fetch("target"))
        direction = hash.fetch("direction").to_s
        raise PolicyError, "compiled NetworkPolicy rule direction is invalid" unless PolicyEngine::DIRECTIONS.include?(direction)

        family = normalize_family(hash.fetch("family"), address, name: "compiled NetworkPolicy rule target")
        peer = hash.fetch("peer")
        peer = stringify_hash(peer)
        if peer["kind"] == "cidr"
          network, prefix = Support.cidr(peer.fetch("cidr"), name: "compiled policy cidr")
          raise PolicyError, "compiled NetworkPolicy rule peer family does not match target" unless normalize_family(family, network,
                                                                                                                     name: "compiled policy peer") == family

          peer["cidr"] = "#{network}/#{prefix}"
        elsif peer["kind"] == "pod"
          peer_address = IPAddr.new(peer.fetch("ip"))
          peer_family = normalize_family(peer.fetch("family"), peer_address, name: "compiled policy pod peer")
          raise PolicyError, "compiled NetworkPolicy rule peer family does not match target" unless peer_family == family

          peer["ip"] = peer_address.to_s
          peer["family"] = peer_family
        elsif peer["kind"] != "all"
          raise PolicyError, "compiled NetworkPolicy peer kind is unsupported"
        end
        protocol = hash["protocol"]&.to_s
        raise PolicyError, "compiled NetworkPolicy protocol is invalid" unless protocol.nil? || PolicyEngine::PROTOCOLS.include?(protocol)

        port = normalize_policy_port(hash["port"], name: "compiled NetworkPolicy port")
        end_port = normalize_policy_port(hash["end_port"], name: "compiled NetworkPolicy endPort")
        raise PolicyError, "compiled NetworkPolicy endPort requires a port" if end_port && port.nil?
        raise PolicyError, "compiled NetworkPolicy endPort must be >= port" if end_port && end_port < port
        raise PolicyError, "compiled NetworkPolicy port requires a protocol" if port && protocol.nil?

        {"direction" => direction, "target" => address.to_s,
         "family" => family, "peer" => peer,
         "protocol" => protocol, "port" => port, "end_port" => end_port}
      rescue KeyError, IPAddr::InvalidAddressError, ValidationError => error
        raise PolicyError, "invalid compiled NetworkPolicy rule: #{error.message}"
      end

      def normalize_family(value, address, name:)
        family = value.to_s
        raise PolicyError, "#{name} family is invalid" unless %w[ipv4 ipv6].include?(family)

        expected = address.ipv4? ? "ipv4" : "ipv6"
        raise PolicyError, "#{name} family does not match address" unless family == expected

        family
      end

      def normalize_policy_port(value, name:)
        return nil if value.nil?

        Support.integer(value, name, min: 1, max: 65_535)
      end

      def conntrack_rule_objects
        [NFT_CT_ESTABLISHED, NFT_CT_RELATED].map do |state|
          state_name = state == NFT_CT_ESTABLISHED ? "established" : "related"
          # Include the verdict contract in the marker so a table installed by
          # an older adapter revision (which only matched ct state) is
          # replaced instead of being accepted as an equivalent readback.
          marker_value = policy_marker("rule", "ct:#{state_name}:accept:v1")
          {"chain" => "forward", "marker" => marker_value,
           "message" => new_rule_message(chain_name: "forward", marker: marker_value,
                                         expressions: conntrack_state_expressions(state) + [accept_expression])}
        end
      end

      def policy_allow_rule_object(rule, index)
        identity = "allow:#{rule.fetch("direction")}:#{rule.fetch("target")}:#{index}:#{Digest::SHA256.hexdigest(JSON.generate(rule))[0,
                                                                                                                                      16]}"
        marker_value = policy_marker("rule", identity)
        {"chain" => "forward", "marker" => marker_value,
         "message" => new_rule_message(chain_name: "forward", marker: marker_value,
                                       expressions: policy_match_expressions(rule) + [accept_expression])}
      end

      def policy_drop_rule_object(target, index)
        identity = "drop:#{target.fetch("direction")}:#{target.fetch("ip")}:#{index}"
        marker_value = policy_marker("rule", identity)
        {"chain" => "forward", "marker" => marker_value,
         "message" => new_rule_message(chain_name: "forward", marker: marker_value,
                                       expressions: target_match_expressions(target) + [drop_expression])}
      end

      def new_policy_chain_message(name:, marker:)
        hook = attributes(attribute(NFTA_CHAIN_HOOK_NUM, u32(NF_INET_FORWARD)),
                          attribute(NFTA_CHAIN_HOOK_PRIORITY, u32(-150)))
        values = [attribute(NFTA_CHAIN_TABLE, cstring(@table_name)), attribute(NFTA_CHAIN_NAME, cstring(name)),
                  attribute(NFTA_CHAIN_USERDATA, marker), attribute(NFTA_CHAIN_HOOK, hook, nested: true),
                  attribute(NFTA_CHAIN_POLICY, u32(NFT_ACCEPT)), attribute(NFTA_CHAIN_TYPE, cstring("filter"))]
        {type: NFT_MSG_NEWCHAIN, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
         family: NFPROTO_INET, attributes: attributes(*values)}
      end

      def new_table_message
        {type: NFT_MSG_NEWTABLE, flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
         family: NFPROTO_INET,
         attributes: attributes(attribute(NFTA_TABLE_NAME, cstring(@table_name)),
                                attribute(NFTA_TABLE_FLAGS, u32(0)),
                                attribute(NFTA_TABLE_USERDATA, policy_marker("table", @table_name)))}
      end

      def policy_lifecycle_messages(current, desired)
        messages = []
        desired_rule_markers = desired.fetch("rules").map { |entry| entry.fetch("marker") }
        current.fetch("rules").each do |entry|
          messages << delete_rule_message(entry) unless desired_rule_markers.include?(entry.fetch("marker"))
        end
        desired_chain_markers = desired.fetch("chains").map { |entry| entry.fetch("marker") }
        current.fetch("chains").reverse_each do |entry|
          messages << delete_chain_message(entry) unless desired_chain_markers.include?(entry.fetch("marker"))
        end
        messages << desired.fetch("table").fetch("message") unless current["table"]
        current_chain_markers = current.fetch("chains").map { |entry| entry.fetch("marker") }
        desired.fetch("chains").each do |entry|
          messages << entry.fetch("message") unless current_chain_markers.include?(entry.fetch("marker"))
        end
        current_rule_markers = current.fetch("rules").map { |entry| entry.fetch("marker") }
        desired.fetch("rules").each do |entry|
          messages << entry.fetch("message") unless current_rule_markers.include?(entry.fetch("marker"))
        end
        messages
      end

      def restore_previous_ruleset!(actual, previous_desired)
        ensure_owned_table!(actual) if actual["table"]
        ensure_owned_objects!(actual)
        messages = if previous_desired
                     policy_lifecycle_messages(actual, previous_desired)
                   else
                     remove_policy_ruleset_messages(actual)
                   end
        send_transaction(messages) unless messages.empty?
        restored = read_kernel_ruleset
        verified = previous_desired ? verify_policy_readback(restored, previous_desired) : !restored["table"]
        raise NftablesNetlinkError, "NetworkPolicy prior ruleset restoration did not match kernel readback" unless verified

        true
      rescue NftablesNetlinkError
        raise
      rescue StandardError => error
        raise NftablesNetlinkError, "NetworkPolicy prior ruleset restoration failed: #{error.message}"
      end

      def remove_policy_ruleset_messages(actual)
        return [] unless actual["table"]

        messages = actual.fetch("rules").map { |entry| delete_rule_message(entry) }
        messages.concat(actual.fetch("chains").reverse_each.map { |entry| delete_chain_message(entry) })
        messages << {type: NFT_MSG_DELTABLE, flags: NLM_F_REQUEST | NLM_F_ACK,
                     family: NFPROTO_INET,
                     attributes: [attribute(NFTA_TABLE_NAME, cstring(@table_name))].join}
        messages
      end

      def verify_policy_readback(actual, desired)
        return false unless actual["table"] && actual.dig("table", "name") == @table_name
        return false unless actual.dig("table", "marker") == desired.dig("table", "marker")

        actual_chain_markers = actual.fetch("chains").map { |entry| entry.fetch("marker") }.sort
        desired_chain_markers = desired.fetch("chains").map { |entry| entry.fetch("marker") }.sort
        actual_rules = actual.fetch("rules").map do |entry|
          [entry.fetch("chain"), entry.fetch("marker"), expression_digest(entry.fetch("expressions"))]
        end.sort_by { |entry| [entry.fetch(0), entry.fetch(1)] }
        desired_rules = desired.fetch("rules").map do |entry|
          expressions = decoded_rule_expressions_from_attributes(entry.fetch("message").fetch(:attributes))
          [entry.fetch("chain"), entry.fetch("marker"), expression_digest(expressions)]
        end.sort_by { |entry| [entry.fetch(0), entry.fetch(1)] }
        actual_chain_markers == desired_chain_markers && actual_rules == desired_rules &&
          actual.fetch("sets").empty? && actual.fetch("set_elements").empty?
      rescue KeyError, TypeError
        false
      end

      def policy_readback_difference(actual, desired)
        actual_rules = actual.fetch("rules", []).to_h do |entry|
          [entry["marker"], expression_digest(entry.fetch("expressions", []))]
        end
        desired_rules = desired.fetch("rules", []).to_h do |entry|
          expressions = decoded_rule_expressions_from_attributes(entry.fetch("message").fetch(:attributes))
          [entry["marker"], expression_digest(expressions)]
        end
        missing = desired_rules.keys - actual_rules.keys
        extra = actual_rules.keys - desired_rules.keys
        changed = (actual_rules.keys & desired_rules.keys).reject { |marker| actual_rules[marker] == desired_rules[marker] }
        first = changed.first
        detail = if first
                   actual_entry = actual.fetch("rules").find { |entry| entry["marker"] == first }
                   desired_entry = desired.fetch("rules").find { |entry| entry["marker"] == first }
                   wanted = decoded_rule_expressions_from_attributes(desired_entry.fetch("message").fetch(:attributes))
                   ", first_actual=#{JSON.generate(actual_entry.fetch("expressions"))}, first_desired=#{JSON.generate(wanted)}"
                 else
                   ""
                 end
        "missing=#{missing.length}, extra=#{extra.length}, changed=#{changed.length}, " \
          "actual_chains=#{actual.fetch("chains", []).length}, desired_chains=#{desired.fetch("chains", []).length}#{detail}"
      rescue StandardError => error
        "difference-unavailable=#{error.class}:#{error.message}"
      end

      def owned_readback?(actual)
        return true unless actual["table"]

        actual.dig("table", "marker") == policy_marker("table", @table_name) &&
          actual.fetch("chains").all? { |entry| marker_owned?(entry["marker"]) } &&
          actual.fetch("rules").all? { |entry| marker_owned?(entry["marker"]) } &&
          actual.fetch("sets").empty? && actual.fetch("set_elements").empty?
      rescue KeyError, TypeError
        false
      end

      def policy_marker(kind, identity, semantic = "")
        MAGIC + "policy-#{kind}\0" + Digest::SHA256.digest(@instance_identity) +
          Digest::SHA256.digest(identity.to_s) + Digest::SHA256.digest(semantic.to_s)
      end

      def marker_owned?(value)
        bytes = String(value).b
        kind = marker_kind(bytes)
        return false unless POLICY_MARKER_KINDS.include?(kind)

        prefix = MAGIC.bytesize + kind.bytesize + 1
        bytes.bytesize == prefix + 96 &&
          bytes.byteslice(prefix, 32) == Digest::SHA256.digest(@instance_identity)
      rescue TypeError
        false
      end

      def decode_readback_entry(payload, type)
        decoded = super
        return decoded unless type == NFT_MSG_GETRULE

        attrs = decode_attributes(payload.byteslice(NFGENMSG_SIZE..).to_s)
        decoded.merge("expressions" => decoded_rule_expressions(nested_value(attrs, NFTA_RULE_EXPRESSIONS)))
      end

      def decoded_rule_expressions_from_attributes(attributes)
        attrs = decode_attributes(attributes)
        decoded_rule_expressions(nested_value(attrs, NFTA_RULE_EXPRESSIONS))
      end

      def decoded_rule_expressions(bytes)
        decode_attributes(bytes).filter_map do |list_entry|
          next unless list_entry.fetch("type") == NFTA_LIST_ELEM

          expression_attributes = decode_attributes(list_entry.fetch("value"))
          name = string_value(expression_attributes, NFTA_EXPR_NAME)
          data = nested_value(expression_attributes, NFTA_EXPR_DATA)
          next if name.to_s.empty?

          {"name" => name, "data" => canonical_expression_data(name, decode_expression_data(data))}
        end
      end

      # nf_tables materializes the omitted default boolean bitwise operation
      # (NFTA_BITWISE_OP=0) on readback on some kernels. Canonicalize both the
      # submitted and returned form so strict verification compares semantics
      # without weakening any operand, register, mask, or xor check.
      def canonical_expression_data(name, data)
        return data unless name == "bitwise"
        return data if data.any? { |entry| entry.fetch("type") == NFTA_BITWISE_OP }

        (data + [{"type" => NFTA_BITWISE_OP, "value" => u32(0).unpack1("H*")}])
          .sort_by { |entry| [entry.fetch("type"), JSON.generate(entry)] }
      end

      def decode_expression_data(bytes)
        decode_attributes(bytes).map do |entry|
          result = {"type" => entry.fetch("type")}
          nested = canonical_nested_expression_data(entry)
          if nested
            result["nested"] = nested
          else
            result["value"] = entry.fetch("value").unpack1("H*")
          end
          result
        end.sort_by { |entry| [entry.fetch("type"), JSON.generate(entry)] }
      end

      # nf_tables readback is semantic, not a byte-for-byte echo. Linux may
      # clear NLA_F_NESTED on expression data containers and may reorder
      # attributes whose order has no meaning. Decode a value as a child TLV
      # stream when it is structurally complete, then sort by attribute type.
      # Scalar register/address bytes fail the strict TLV decoder and remain
      # canonical hex values.
      def canonical_nested_expression_data(entry)
        value = entry.fetch("value")
        return decode_expression_data(value) if entry.fetch("nested")

        children = decode_attributes(value)
        return nil if children.empty?

        decode_expression_data(value)
      rescue NftablesNetlinkError
        nil
      end

      def expression_digest(value)
        Digest::SHA256.hexdigest(JSON.generate(value))
      end

      def ensure_owned_table!(actual)
        table = actual["table"]
        return unless table
        return if table.is_a?(Hash) && table["marker"] == policy_marker("table", @table_name)

        raise NftablesNetlinkError,
              "refusing to modify nftables table #{@table_name.inspect} without an owned NetworkPolicy userdata marker"
      end

      def policy_match_expressions(rule)
        expressions = target_match_expressions("direction" => rule.fetch("direction"), "ip" => rule.fetch("target"),
                                               "family" => rule.fetch("family"))
        peer = rule.fetch("peer")
        expressions.concat(address_peer_expressions(peer, direction: rule.fetch("direction"))) unless peer.fetch("kind") == "all"
        protocol = rule["protocol"]
        expressions.concat(protocol_port_expressions(protocol, rule["port"], rule["end_port"])) if protocol
        expressions
      end

      def target_match_expressions(target)
        family = target.fetch("family") == "ipv6" ? NFPROTO_IPV6 : NFPROTO_IPV4
        address = IPAddr.new(target.fetch("ip"))
        address_expressions(family, address, target.fetch("direction") == "ingress" ? :destination : :source)
      end

      def address_peer_expressions(peer, direction:)
        position = direction == "ingress" ? :source : :destination
        if peer.fetch("kind") == "pod"
          address = IPAddr.new(peer.fetch("ip"))
          address_expressions(address.ipv6? ? NFPROTO_IPV6 : NFPROTO_IPV4, address, position)
        else
          network, prefix = Support.cidr(peer.fetch("cidr"), name: "compiled policy cidr")
          cidr_expressions(network.ipv6? ? NFPROTO_IPV6 : NFPROTO_IPV4, network, prefix, position)
        end
      end

      def address_expressions(family, address, position)
        offset = if family == NFPROTO_IPV6
                   position == :source ? 8 : 24
                 else
                   position == :source ? 12 : 16
                 end
        nfproto_expression(family) +
          [expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(2)),
                                            attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_NETWORK_HEADER)),
                                            attribute(NFTA_PAYLOAD_OFFSET, u32(offset)),
                                            attribute(NFTA_PAYLOAD_LEN, u32(family == NFPROTO_IPV6 ? 16 : 4)))),
           compare_expression(2, address.hton)]
      end

      def cidr_expressions(family, network, prefix, position)
        length = family == NFPROTO_IPV6 ? 16 : 4
        offset = if family == NFPROTO_IPV6
                   position == :source ? 8 : 24
                 else
                   position == :source ? 12 : 16
                 end
        return address_expressions(family, network, position) if Integer(prefix) == (length * 8)

        remaining = Integer(prefix)
        network_bytes = network.hton
        # `nfproto_expression` is already the two-expression guard (meta
        # load + compare).  Do not wrap it in another array: doing so emits a
        # nested Ruby array as an nft expression and bypasses the family guard
        # for partial CIDRs at serialization time.
        expressions = nfproto_expression(family).dup
        (length / 4).times do |chunk|
          chunk_prefix = [[remaining, 0].max, 32].min
          break if chunk_prefix.zero?

          chunk_bytes = network_bytes.byteslice(chunk * 4, 4)
          payload_offset = offset + (chunk * 4)
          expressions << expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(2)),
                                                          attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_NETWORK_HEADER)),
                                                          attribute(NFTA_PAYLOAD_OFFSET, u32(payload_offset)),
                                                          attribute(NFTA_PAYLOAD_LEN, u32(4))))
          if chunk_prefix == 32
            expressions << compare_expression(2, chunk_bytes)
          else
            mask = cidr_mask_bytes(4, chunk_prefix)
            expressions << expression("bitwise", attributes(attribute(NFTA_BITWISE_SREG, u32(2)),
                                                            attribute(NFTA_BITWISE_DREG, u32(2)),
                                                            attribute(NFTA_BITWISE_LEN, u32(4)),
                                                            attribute(NFTA_BITWISE_MASK, attribute(NFTA_DATA_VALUE, mask), nested: true),
                                                            attribute(NFTA_BITWISE_XOR, attribute(NFTA_DATA_VALUE, "\0".b * 4),
                                                                      nested: true)))
            expressions << compare_expression(2, chunk_bytes.bytes.zip(mask.bytes).map { |value, mask_byte|
              value & mask_byte
            }.pack("C*"))
          end
          remaining -= chunk_prefix
        end
        expressions
      end

      def nfproto_expression(family)
        [expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                       attribute(NFTA_META_KEY, u32(NFT_META_NFPROTO)))),
         compare_expression(1, family == NFPROTO_IPV6 ? NFPROTO_IPV6 : NFPROTO_IPV4)]
      end

      def cidr_mask_bytes(length, prefix)
        bits = Integer(prefix)
        Array.new(length) do |index|
          remaining = bits - (index * 8)
          if remaining >= 8
            0xff
          elsif remaining.positive?
            (0xff << (8 - remaining)) & 0xff
          else
            0
          end
        end.pack("C*")
      end

      def protocol_port_expressions(protocol, port, end_port)
        expressions = [expression("meta", attributes(attribute(NFTA_META_DREG, u32(1)),
                                                     attribute(NFTA_META_KEY, u32(NFT_META_L4PROTO)))),
                       compare_expression(1, {"TCP" => 6, "UDP" => 17, "SCTP" => 132}.fetch(protocol))]
        return expressions if port.nil?

        expressions << expression("payload", attributes(attribute(NFTA_PAYLOAD_DREG, u32(1)),
                                                        attribute(NFTA_PAYLOAD_BASE, u32(NFT_PAYLOAD_TRANSPORT_HEADER)),
                                                        attribute(NFTA_PAYLOAD_OFFSET, u32(2)),
                                                        attribute(NFTA_PAYLOAD_LEN, u32(2))))
        if end_port
          expressions << policy_compare_expression(1, NFT_CMP_GTE, [Integer(port)].pack("n"))
          expressions << policy_compare_expression(1, NFT_CMP_LTE, [Integer(end_port)].pack("n"))
        else
          expressions << compare_expression(1, [Integer(port)].pack("n"))
        end
        expressions
      end

      def conntrack_state_expressions(state)
        [expression("ct", attributes(attribute(NFTA_CT_DREG, u32(1)), attribute(NFTA_CT_KEY, u32(NFT_CT_STATE)))),
         compare_expression(1, data_u32(state))]
      end

      def policy_compare_expression(register, operation, value)
        data = value.is_a?(Integer) ? data_u32(value) : value
        expression("cmp", attributes(attribute(NFTA_CMP_SREG, u32(register)),
                                     attribute(NFTA_CMP_OP, u32(operation)),
                                     attribute(NFTA_CMP_DATA, attribute(NFTA_DATA_VALUE, data), nested: true)))
      end

      def accept_expression
        verdict = attributes(attribute(NFTA_VERDICT_CODE, u32(NFT_ACCEPT)))
        expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(0)),
                                           attribute(NFTA_IMMEDIATE_DATA,
                                                     attribute(NFTA_DATA_VERDICT, verdict, nested: true), nested: true)))
      end

      def drop_expression
        verdict = attributes(attribute(NFTA_VERDICT_CODE, u32(NFT_DROP)))
        expression("immediate", attributes(attribute(NFTA_IMMEDIATE_DREG, u32(0)),
                                           attribute(NFTA_IMMEDIATE_DATA,
                                                     attribute(NFTA_DATA_VERDICT, verdict, nested: true), nested: true)))
      end
    end

    LinuxNftablesPolicyAdapter = NftablesPolicyAdapter unless const_defined?(:LinuxNftablesPolicyAdapter, false)
    NFtablesPolicyAdapter = NftablesPolicyAdapter unless const_defined?(:NFtablesPolicyAdapter, false)
  end
end
