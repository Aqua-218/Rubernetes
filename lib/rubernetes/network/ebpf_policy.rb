# frozen_string_literal: true

# Native TC/eBPF NetworkPolicy enforcement. The program parser is deliberately
# separate from the Service program: a policy revision is compiled into a
# bounded verifier-visible rule sequence and a fresh flow map, then attached
# with rtnetlink replacement semantics.

require "digest"
require "ipaddr"
require "json"

require_relative "policy"
require_relative "nftables_policy"
require_relative "../proxy/ebpf_program"
require_relative "../proxy/ebpf"

module Rubernetes
  module Network
    class EBPFPolicyProgram < Rubernetes::Proxy::EBPFProgram::ServiceDatapath
      Assembler = Rubernetes::Proxy::EBPFProgram::Assembler
      HELPER_MAP_LOOKUP = 1
      HELPER_MAP_UPDATE = 2
      NFPROTO_IPV4 = 4
      NFPROTO_IPV6 = 6
      FLOW_VALUE_SIZE = 8
      FLOW_KEY_SIZE = 40
      # The eight-byte flow value is written with one BPF_DW store, which the
      # verifier requires to be 8-byte aligned; the parser scratch slot is
      # not.  The affinity-value slot is unused by the policy program and
      # aligned, so it carries the flow value instead.
      FLOW_VALUE_STACK = STACK_AFFINITY_VALUE

      def initialize(map_fds:, rules:, targets: [], fail_closed: false)
        super(map_fds: map_fds)
        @rules = Array(rules).map { |entry| stringify_hash(entry) }.freeze
        @targets = Array(targets).map { |entry| stringify_hash(entry) }.freeze
        @fail_closed = fail_closed == true
      end

      def build
        assembler = Rubernetes::Proxy::EBPFProgram::Assembler.new(map_fds: @map_fds)
        build_policy_program(assembler)
        assembler.to_instructions
      end

      private

      def stringify_hash(value)
        case value
        when Hash then value.each_with_object({}) { |(key, child), result| result[key.to_s] = stringify_hash(child) }
        when Array then value.map { |child| stringify_hash(child) }
        else value
        end
      end

      def build_policy_program(a)
        # Keep the skb and data pointers in callee-saved registers while the
        # parser and map helpers operate on the packet.
        a.mov_reg(8, 1)
        a.mov_reg(6, 1)
        a.load_mem(Assembler::BPF_W, 2, 1, 76)
        a.load_mem(Assembler::BPF_W, 7, 1, 80)
        a.load_mem(Assembler::BPF_W, 4, 1, 0)
        a.store_mem(Assembler::BPF_W, 10, STACK_META + 8, source: 4)
        check_data_end(a, 6, 7, 14, :drop)
        a.load_mem(Assembler::BPF_H, 2, 6, 12)
        a.mov_imm(9, 14)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_8021Q, label: :parse_vlan_one)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_8021AD, label: :parse_vlan_one)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_9100, label: :parse_vlan_one)
        a.ja(:parse_l3)

        a.label(:parse_vlan_one)
        check_data_end(a, 6, 7, 18, :drop)
        a.load_mem(Assembler::BPF_H, 2, 6, 16)
        a.mov_imm(9, 18)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_8021Q, label: :parse_vlan_two)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_8021AD, label: :parse_vlan_two)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_9100, label: :parse_vlan_two)
        a.ja(:parse_l3)

        a.label(:parse_vlan_two)
        check_data_end(a, 6, 7, 22, :drop)
        a.load_mem(Assembler::BPF_H, 2, 6, 20)
        a.mov_imm(9, 22)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_8021Q, label: :drop)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_8021AD, label: :drop)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_9100, label: :drop)

        a.label(:parse_l3)
        a.store_mem(Assembler::BPF_W, 10, STACK_META + 4, source: 9)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_IP, label: :parse_ipv4)
        a.jump(Assembler::BPF_JEQ, destination: 2, immediate: ETH_P_IPV6, label: :parse_ipv6)
        a.ja(:pass)

        parse_ipv4(a)
        parse_ipv6(a)
        a.label(:packet_fields_ready)
        @fail_closed ? a.ja(:drop) : policy_lookup(a)

        a.label(:pass)
        return_action(a, TC_ACT_OK)
        a.label(:drop)
        return_action(a, TC_ACT_SHOT)
      end

      def policy_lookup(a)
        zero_stack(a, STACK_CONNTRACK_KEY, FLOW_KEY_SIZE)
        zero_stack(a, STACK_REVERSE_KEY, FLOW_KEY_SIZE)
        zero_stack(a, FLOW_VALUE_STACK, FLOW_VALUE_SIZE)
        set_flow_header(a, STACK_CONNTRACK_KEY)
        copy_stack(a, STACK_SRC_IP, STACK_CONNTRACK_KEY + 8, 16)
        copy_stack(a, STACK_DST_IP, STACK_CONNTRACK_KEY + 24, 16)
        copy_stack(a, STACK_PORTS, STACK_CONNTRACK_KEY + 2, 4)
        map_lookup(a, "flows", STACK_CONNTRACK_KEY, 0)
        a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: :pass)

        set_flow_header(a, STACK_REVERSE_KEY)
        copy_stack(a, STACK_DST_IP, STACK_REVERSE_KEY + 8, 16)
        copy_stack(a, STACK_SRC_IP, STACK_REVERSE_KEY + 24, 16)
        copy_reverse_ports(a)
        map_lookup(a, "flows", STACK_REVERSE_KEY, 0)
        a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: :pass)

        @rules.each_with_index do |rule, index|
          next_label = "policy_rule_next_#{index}".to_sym
          emit_rule_match(a, rule, next_label)
          a.ja(:new_flow_allowed)
          a.label(next_label)
        end
        targets = (@targets + @rules.filter_map do |rule|
          next unless rule["target"]

          {"direction" => rule["direction"], "target" => rule["target"], "family" => rule["family"]}
        end).uniq { |entry| entry.values_at("direction", "target", "family") }
        targets.each_with_index do |target, index|
          next_label = "policy_target_next_#{index}".to_sym
          emit_target_match(a, target, next_label)
          a.ja(:drop)
          a.label(next_label)
        end
        # A revision without any allow rule (pure default-deny) has no path
        # into the flow-commit block.  The verifier rejects a program with
        # unreachable instructions, so the block is emitted only when a rule
        # can jump to it; the pass-through above is then the final exit.
        return a.ja(:pass) if @rules.empty?

        a.ja(:pass)
        a.label(:new_flow_allowed)
        map_update(a, "flows", STACK_CONNTRACK_KEY, FLOW_VALUE_STACK, :drop)
        map_update(a, "flows", STACK_REVERSE_KEY, FLOW_VALUE_STACK, :drop)
        a.ja(:pass)
      end

      def set_flow_header(a, offset)
        a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 12)
        a.store_mem(Assembler::BPF_B, 10, offset, source: 2)
        a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
        a.store_mem(Assembler::BPF_B, 10, offset + 1, source: 2)
      end

      def copy_reverse_ports(a)
        # STACK_PORTS contains the source and destination ports as raw
        # network-order bytes. The reverse flow key must mirror the packet
        # tuple byte-for-byte so TCP, UDP, and SCTP replies match on both IP
        # families without relying on host-endian BPF_H conversions.
        copy_port_bytes(a, STACK_PORTS + 2, STACK_REVERSE_KEY + 2)
        copy_port_bytes(a, STACK_PORTS, STACK_REVERSE_KEY + 4)
      end

      def copy_port_bytes(a, source_offset, destination_offset)
        2.times do |index|
          a.load_mem(Assembler::BPF_B, 2, 10, source_offset + index)
          a.store_mem(Assembler::BPF_B, 10, destination_offset + index, source: 2)
        end
      end

      def emit_rule_match(a, rule, failure_label)
        family = rule.fetch("family") == "ipv6" ? NFPROTO_IPV6 : NFPROTO_IPV4
        emit_address_match(a, rule.fetch("target"), family,
                           rule.fetch("direction") == "ingress" ? STACK_DST_IP : STACK_SRC_IP, failure_label)
        peer = rule.fetch("peer")
        unless peer.fetch("kind") == "all"
          if peer.fetch("kind") == "pod"
            peer_family = peer.fetch("family") == "ipv6" ? NFPROTO_IPV6 : NFPROTO_IPV4
            emit_address_match(a, peer.fetch("ip"), peer_family,
                               rule.fetch("direction") == "ingress" ? STACK_SRC_IP : STACK_DST_IP, failure_label)
          else
            network, prefix = Support.cidr(peer.fetch("cidr"), name: "compiled policy cidr")
            emit_cidr_match(a, network, prefix,
                            rule.fetch("direction") == "ingress" ? STACK_SRC_IP : STACK_DST_IP, failure_label)
          end
        end
        if (protocol = rule["protocol"])
          protocol_number = {"TCP" => 6, "UDP" => 17, "SCTP" => 132}.fetch(protocol)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: protocol_number, label: failure_label)
          unless rule["port"].nil?
            a.load_mem(Assembler::BPF_H, 2, 10, STACK_PORTS + 2)
            a.endian(2, 16)
            if rule["end_port"]
              a.jump(Assembler::BPF_JLT, destination: 2, immediate: Integer(rule.fetch("port")), label: failure_label)
              a.jump(Assembler::BPF_JGT, destination: 2, immediate: Integer(rule.fetch("end_port")), label: failure_label)
            else
              a.jump(Assembler::BPF_JNE, destination: 2, immediate: Integer(rule.fetch("port")), label: failure_label)
            end
          end
        end
      end

      def emit_target_match(a, target, failure_label)
        family = target.fetch("family") == "ipv6" ? NFPROTO_IPV6 : NFPROTO_IPV4
        # Selected-pod targets from the policy engine carry "ip"; rule
        # targets carry "target".  Both name the protected pod address.
        emit_address_match(a, target["target"] || target.fetch("ip"), family,
                           target.fetch("direction") == "ingress" ? STACK_DST_IP : STACK_SRC_IP, failure_label)
      end

      def emit_address_match(a, address, family, stack_offset, failure_label)
        ip = IPAddr.new(address)
        emit_family_guard(a, family, failure_label)
        bytes = ip.hton
        base_offset = family == NFPROTO_IPV6 ? stack_offset : stack_offset + 12
        chunks = family == NFPROTO_IPV6 ? 4 : 1
        chunks.times do |index|
          value = bytes.byteslice(index * 4, 4).unpack1("L<")
          a.load_mem(Assembler::BPF_W, 2, 10, base_offset + (index * 4))
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: value, label: failure_label)
        end
      end

      def emit_cidr_match(a, network, prefix, stack_offset, failure_label)
        family = network.ipv6? ? NFPROTO_IPV6 : NFPROTO_IPV4
        emit_family_guard(a, family, failure_label)
        bytes = network.hton
        base_offset = family == NFPROTO_IPV6 ? stack_offset : stack_offset + 12
        chunks = family == NFPROTO_IPV6 ? 4 : 1
        bits_remaining = Integer(prefix)
        chunks.times do |index|
          mask = if bits_remaining >= 32
                   0xffff_ffff
                 elsif bits_remaining.positive?
                   ((0xffff_ffff << (32 - bits_remaining)) & 0xffff_ffff)
                 else
                   0
                 end
          value = bytes.byteslice(index * 4, 4).unpack1("L<") & mask
          a.load_mem(Assembler::BPF_W, 2, 10, base_offset + (index * 4))
          a.alu_imm(Assembler::BPF_AND, 2, mask)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: value, label: failure_label)
          bits_remaining -= 32
        end
      end

      def emit_family_guard(a, family, failure_label)
        # IPv4 addresses occupy the low 32 bits of the normalized 128-bit
        # stack slot. Without this guard an IPv6 address with the same low
        # word can satisfy an IPv4 target or CIDR comparison.
        a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 12)
        a.jump(Assembler::BPF_JNE, destination: 2, immediate: family, label: failure_label)
      end
    end

    # Linux TC adapter for concrete NetworkPolicy rules. It creates a fresh
    # flow map and verifier-accepted program for every revision, then replaces
    # owned filters through rtnetlink before closing the old program/map.
    class EBPFPolicyAdapter < Rubernetes::Proxy::LinuxEBPFAdapter
      POLICY_PACKET_CASES = NftablesPolicyAdapter::POLICY_PACKET_CASES
      POLICY_FEATURE_MATRIX = NftablesPolicyAdapter::POLICY_FEATURE_MATRIX
      FLOW_LAYOUT = {
        "flows" => {"type" => "lru_hash", "key_size" => EBPFPolicyProgram::FLOW_KEY_SIZE,
                     "value_size" => EBPFPolicyProgram::FLOW_VALUE_SIZE, "max_entries" => 1_000_000},
        # LinuxEBPFAdapter validates every concrete layout against the shared
        # proxy ABI. The policy program does not use this map, but retaining
        # its declaration lets the policy adapter share the same verifier
        # boundary while owning only the flow map at runtime.
        "sctp_crc32c" => {"type" => "array", "key_size" => 4, "value_size" => 4, "max_entries" => 256}
      }.freeze

      attr_reader :last_snapshot, :last_readback, :packet_matrix, :policy_feature_matrix

      def initialize(bpf: BPF.new, netlink: TCNetlink.new, interfaces: nil, interface: nil, ifindex: nil,
                     program_name: "rkpolicy_tc")
        super(bpf: bpf, netlink: netlink, interface: interface, ifindex: ifindex,
              complete_semantics: false, program_name: program_name, map_layout: FLOW_LAYOUT)
        @interfaces = Array(interfaces || interface || ifindex).freeze
        @last_snapshot = nil
        @last_readback = nil
        @packet_matrix = nil
        @policy_feature_matrix = POLICY_FEATURE_MATRIX.dup.freeze
        @policy_program_name = normalize_policy_program_name(program_name)
      end

      def production_capable?
        !@packet_matrix.nil? && POLICY_FEATURE_MATRIX.values.all? &&
          POLICY_PACKET_CASES.all? { |key| @packet_matrix.fetch(key, false) == true }
      end

      def test_adapter?
        false
      end

      def production_capability_error
        return "eBPF NetworkPolicy adapter is production-capable" if production_capable?

        missing = POLICY_PACKET_CASES.reject { |key| @packet_matrix.is_a?(Hash) && @packet_matrix[key] == true }
        "eBPF NetworkPolicy adapter is not production-capable: packet matrix is incomplete (#{missing.join(", ")})"
      end

      def verify_packet_matrix!(matrix:)
        # Only isolated pod netns/veth packet evidence may populate this gate;
        # model output or an unlocked/external CNI oracle is never sufficient.
        values = matrix.respond_to?(:transform_keys) ? matrix.transform_keys(&:to_s) : {}
        missing = POLICY_PACKET_CASES.reject { |key| values[key] == true }
        raise PolicyError, "NetworkPolicy packet matrix is incomplete: #{missing.join(", ")}" unless missing.empty?

        @packet_matrix = values.freeze
        true
      end

      def atomic_swap(snapshot)
        normalized = normalize_policy_snapshot(snapshot)
        kernel = normalized.fetch("kernel")
        interfaces = resolve_policy_ifindices(kernel: kernel)
        rules = kernel.fetch("rules")
        targets = kernel.fetch("targets")
        map_layout = send(:normalize_map_layout, FLOW_LAYOUT)
        @mutex.synchronize do
          old_program = @program
          old_maps = @maps
          old_links = @links
          old_attached = @attached
          new_maps = {}
          new_program = nil
          new_links = []
          begin
            new_maps["flows"] = send(:create_map, "flows", map_layout.fetch("flows"), ifindex: interfaces.first)
            instructions = EBPFPolicyProgram.new(map_fds: {"flows" => new_maps.fetch("flows").fd},
                                                  rules: rules, targets: targets).build
            new_program = @bpf.load(instructions: instructions, program_type: BPF::BPF_PROG_TYPE_SCHED_CLS, log_size: BPF::MAX_LOG_SIZE,
                                    expected_attach_type: 0, ifindex: 0, name: @policy_program_name,
                                    map_fds: [new_maps.fetch("flows").fd], resource_id: "network:policy:ebpf:program")
            interfaces.each do |target_ifindex|
              send(:ensure_clsact, target_ifindex)
              %i[ingress egress].each do |direction|
                old_link = @links.find { |link| link.fetch(:ifindex) == target_ifindex && link.fetch(:direction) == direction }
                new_links << attach_policy_filter(target_ifindex, direction, new_program, replace: !old_link.nil?)
              end
            end
            @maps = new_maps.freeze
            @program = new_program
            @links = new_links.freeze
            readbacks = interfaces.to_h { |target_ifindex| [target_ifindex, verify_policy_kernel_state(target_ifindex)] }
            readback = readbacks.fetch(interfaces.first).merge("interfaces" => readbacks).freeze
            @attached = true
            old_program&.close
            old_maps.each_value { |map| map.close rescue nil }
            @last_snapshot = normalized.freeze
            @last_readback = readback.merge("verified" => true, "revision" => normalized.fetch("revision")).freeze
            true
          rescue StandardError => primary_error
            rollback_interfaces = (interfaces + Array(old_links).filter_map { |link| link[:ifindex] }).uniq
            restored = restore_previous_policy_state(
              program: old_program, maps: old_maps, links: old_links,
              attached: old_attached, interfaces: rollback_interfaces
            )
            if restored
              new_program&.close rescue nil
              new_maps.each_value { |map| map.close rescue nil }
              raise primary_error
            end

            begin
              install_fail_closed_policy!(rollback_interfaces, stale_programs: [old_program, new_program],
                                          stale_maps: [old_maps, new_maps])
            rescue StandardError => fail_closed_error
              raise PolicyError,
                    "eBPF NetworkPolicy swap readback failed and neither the prior filter nor fail-closed filter could be verified: " \
                    "#{primary_error.message}; fail-closed error: #{fail_closed_error.message}"
            end
            raise PolicyError,
                  "eBPF NetworkPolicy swap readback failed; a verified fail-closed filter is active: #{primary_error.message}"
          end
        end
      rescue Rubernetes::Platform::Linux::Error => error
        raise PolicyRevisionError, "native eBPF NetworkPolicy revision was rejected: #{error.message}"
      rescue PolicyError
        raise
      rescue StandardError => error
        raise PolicyRevisionError, "native eBPF NetworkPolicy revision was rejected: #{error.message}"
      end

      alias swap atomic_swap
      alias replace atomic_swap

      def readback(snapshot: @last_snapshot)
        normalized = snapshot && normalize_policy_snapshot(snapshot)
        return {"verified" => false, "reason" => "eBPF NetworkPolicy is unattached"}.freeze unless normalized && @attached

        result = @mutex.synchronize do
          interfaces = @links.map { |link| link.fetch(:ifindex) }.uniq
          readbacks = interfaces.to_h { |ifindex| [ifindex, verify_policy_kernel_state(ifindex)] }
          readbacks.fetch(interfaces.first).merge("interfaces" => readbacks).freeze
        end
        result = result.merge("verified" => true, "revision" => normalized.fetch("revision")).freeze
        @last_readback = result
        result
      rescue StandardError => error
        {"verified" => false, "reason" => error.message}.freeze
      end

      def detach(**options)
        result = super(**options)
        @last_snapshot = nil
        @last_readback = nil
        result
      end

      private

      def normalize_policy_snapshot(snapshot)
        value = snapshot.respond_to?(:to_h) ? snapshot.to_h : snapshot
        raise PolicyError, "native NetworkPolicy adapter requires a snapshot object" unless value.is_a?(Hash)

        entries = value["entries"] || value[:entries] || value
        revision = Integer(value["revision"] || value[:revision] || entries["revision"] || entries[:revision])
        kernel = entries["kernel"] || entries[:kernel]
        raise PolicyError, "native NetworkPolicy snapshot has no kernel compilation" unless kernel.is_a?(Hash)
        raise PolicyError, "native NetworkPolicy snapshot has no concrete pod index" unless kernel["pod_index_present"] == true
        kernel = stringify_hash(kernel)
        validate_kernel_entries!(kernel)
        {"revision" => revision, "kernel" => kernel}.freeze
      rescue ArgumentError, TypeError
        raise PolicyError, "native NetworkPolicy snapshot revision is invalid"
      end

      def validate_kernel_entries!(kernel)
        targets = kernel["targets"]
        rules = kernel["rules"]
        raise PolicyError, "native NetworkPolicy kernel targets must be an array" unless targets.is_a?(Array)
        raise PolicyError, "native NetworkPolicy kernel rules must be an array" unless rules.is_a?(Array)
        targets.each { |target| validate_kernel_target!(target) }
        rules.each { |rule| validate_kernel_rule!(rule) }
        true
      end

      def validate_kernel_target!(target)
        hash = target.is_a?(Hash) ? target : {}
        address = IPAddr.new(hash.fetch("ip"))
        family = hash.fetch("family").to_s
        direction = hash.fetch("direction").to_s
        raise PolicyError, "native NetworkPolicy target direction is invalid" unless PolicyEngine::DIRECTIONS.include?(direction)
        validate_kernel_family!(family, address, "target")
      rescue KeyError, IPAddr::InvalidAddressError => error
        raise PolicyError, "invalid native NetworkPolicy target: #{error.message}"
      end

      def validate_kernel_rule!(rule)
        hash = rule.is_a?(Hash) ? rule : {}
        address = IPAddr.new(hash.fetch("target"))
        family = hash.fetch("family").to_s
        direction = hash.fetch("direction").to_s
        raise PolicyError, "native NetworkPolicy rule direction is invalid" unless PolicyEngine::DIRECTIONS.include?(direction)
        validate_kernel_family!(family, address, "rule target")
        peer = hash.fetch("peer")
        peer = peer.is_a?(Hash) ? peer : {}
        case peer.fetch("kind")
        when "all"
          nil
        when "pod"
          peer_address = IPAddr.new(peer.fetch("ip"))
          validate_kernel_family!(peer.fetch("family").to_s, peer_address, "pod peer")
          raise PolicyError, "native NetworkPolicy peer family does not match target" unless peer.fetch("family").to_s == family
        when "cidr"
          network, = Support.cidr(peer.fetch("cidr"), name: "compiled policy cidr")
          validate_kernel_family!(family, network, "cidr peer")
        else
          raise PolicyError, "native NetworkPolicy peer kind is unsupported"
        end
        protocol = hash["protocol"]
        raise PolicyError, "native NetworkPolicy protocol is invalid" unless protocol.nil? || PolicyEngine::PROTOCOLS.include?(protocol.to_s)
        port = hash["port"]
        end_port = hash["end_port"]
        if port || end_port
          raise PolicyError, "native NetworkPolicy port requires a protocol" if protocol.nil?
          port = Support.integer(port, "compiled NetworkPolicy port", min: 1, max: 65_535)
          end_port = Support.integer(end_port, "compiled NetworkPolicy endPort", min: 1, max: 65_535) if end_port
          raise PolicyError, "native NetworkPolicy endPort must be >= port" if end_port && end_port < port
        end
      rescue KeyError, IPAddr::InvalidAddressError, ValidationError => error
        raise PolicyError, "invalid native NetworkPolicy rule: #{error.message}"
      end

      def validate_kernel_family!(family, address, name)
        raise PolicyError, "native NetworkPolicy #{name} family is invalid" unless %w[ipv4 ipv6].include?(family)
        expected = address.ipv4? ? "ipv4" : "ipv6"
        raise PolicyError, "native NetworkPolicy #{name} family does not match address" unless family == expected
      end

      def stringify_hash(value)
        case value
        when Hash then value.each_with_object({}) { |(key, child), result| result[key.to_s] = stringify_hash(child) }
        when Array then value.map { |child| stringify_hash(child) }
        else value
        end
      end

      def resolve_policy_ifindices(kernel: nil)
        candidates = @interfaces
        if candidates.empty? && kernel
          candidates = Array(kernel["pods"]).filter_map { |pod| pod["interface"] }
        end
        raise PolicyError, "eBPF NetworkPolicy requires at least one pod veth interface" if candidates.empty?

        candidates.map do |entry|
          if entry.is_a?(Integer) || entry.to_s.match?(/\A\d+\z/)
            value = Integer(entry)
            raise PolicyError, "eBPF NetworkPolicy interface index must be positive" unless value.positive?

            value
          else
            send(:resolve_ifindex, interface: entry, ifindex: nil)
          end
        end.uniq.freeze
      end

      def attach_policy_filter(ifindex, direction, program, replace: false)
        parent = direction == :ingress ? TC_PARENT_INGRESS : TC_PARENT_EGRESS
        handle = DEFAULT_HANDLE + (direction == :ingress ? 11 : 12)
        info = (ETH_P_ALL << 16) | DEFAULT_PRIORITY
        options = [
          TCNetlink.attribute(TCA_BPF_FD, [program.fd].pack("L<")),
          TCNetlink.attribute(TCA_BPF_NAME, "#{@policy_program_name}\0"),
          TCNetlink.attribute(TCA_BPF_FLAGS, [TCA_BPF_FLAG_ACT_DIRECT].pack("L<"))
        ].join
        attributes = [TCNetlink.attribute(TCA_KIND, "bpf\0"), TCNetlink.attribute(TCA_OPTIONS, options, nested: true)]
        flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | (replace ? NLM_F_REPLACE : NLM_F_EXCL)
        @netlink.request(type: RTM_NEWTFILTER, flags: flags,
                         payload: send(:tcmsg, ifindex: ifindex, handle: handle, parent: parent, info: info),
                         attributes: attributes, resource_id: "network:policy:ebpf:#{ifindex}:#{direction}")
        {ifindex: ifindex, direction: direction, parent: parent, handle: handle, priority: DEFAULT_PRIORITY}.freeze
      end

      def restore_previous_policy_state(program:, maps:, links:, attached:, interfaces:)
        return false unless attached && program && !Array(links).empty?

        expected_links = Array(interfaces).flat_map do |ifindex|
          %i[ingress egress].map { |direction| [ifindex, direction] }
        end.sort
        actual_links = Array(links).map { |link| [link.fetch(:ifindex), link.fetch(:direction)] }.uniq.sort
        # A partial old link inventory cannot prove that replacement did not
        # leave a new direction installed.  Refuse restoration and let the
        # fail-closed path replace both directions on every affected device.
        return false unless actual_links == expected_links

        restored_links = Array(links).map do |link|
          attach_policy_filter(link.fetch(:ifindex), link.fetch(:direction), program, replace: true)
        end
        @program = program
        @maps = maps
        @links = restored_links.freeze
        @attached = true
        interfaces.each { |ifindex| verify_policy_kernel_state(ifindex) }
        true
      rescue StandardError
        false
      end

      def install_fail_closed_policy!(interfaces, stale_programs:, stale_maps:)
        map_layout = send(:normalize_map_layout, FLOW_LAYOUT)
        emergency_maps = {}
        emergency_program = nil
        emergency_links = []
        begin
          emergency_maps["flows"] = send(:create_map, "flows", map_layout.fetch("flows"), ifindex: interfaces.first)
          instructions = EBPFPolicyProgram.new(map_fds: {"flows" => emergency_maps.fetch("flows").fd},
                                                rules: [], targets: [], fail_closed: true).build
          emergency_program = @bpf.load(
            instructions: instructions,
            program_type: BPF::BPF_PROG_TYPE_SCHED_CLS,
            expected_attach_type: 0,
            ifindex: 0,
            name: @policy_program_name,
            map_fds: [emergency_maps.fetch("flows").fd],
            resource_id: "network:policy:ebpf:fail-closed-program"
          )
          interfaces.each do |target_ifindex|
            send(:ensure_clsact, target_ifindex)
            %i[ingress egress].each do |direction|
              emergency_links << attach_policy_filter(target_ifindex, direction, emergency_program, replace: true)
            end
          end
          @program = emergency_program
          @maps = emergency_maps.freeze
          @links = emergency_links.freeze
          @attached = true
          readbacks = interfaces.to_h { |ifindex| [ifindex, verify_policy_kernel_state(ifindex)] }
          @last_snapshot = nil
          @last_readback = {"verified" => true, "fail_closed" => true, "interfaces" => readbacks}.freeze
          Array(stale_programs).compact.uniq.each { |program| program.close rescue nil }
          Array(stale_maps).compact.each do |collection|
            collection.each_value { |map| map.close rescue nil }
          end
          true
        rescue StandardError
          emergency_program&.close rescue nil
          emergency_maps.each_value { |map| map.close rescue nil }
          raise
        end
      end

      def normalize_policy_program_name(value)
        name = String(value)
        raise PolicyError, "eBPF NetworkPolicy program name must not be empty" if name.empty?
        raise PolicyError, "eBPF NetworkPolicy program name exceeds 15 bytes" if name.bytesize > 15

        name
      end

      def verify_policy_kernel_state(ifindex)
        raise RuntimeError, "program is not loaded" unless @program

        program_info = @bpf.program_info(@program, resource_id: "network:policy:ebpf:program:readback")
        map_info = @maps.each_with_object({}) do |(name, map), result|
          result[name] = @bpf.map_info(map, resource_id: "network:policy:ebpf:map:#{name}:readback")
        end
        filter_info = send(:read_filters, ifindex)
        expected_ids = @links.select { |link| link.fetch(:ifindex) == ifindex }
                           .map { |link| [link.fetch(:direction), link.fetch(:handle)] }
        actual_ids = filter_info.filter_map do |entry|
          next unless entry[:program_id] == @program.id

          [entry[:direction], entry[:handle]]
        end
        unless actual_ids.uniq.sort == expected_ids.uniq.sort
          raise RuntimeError, "TC policy filter readback did not contain the loaded program identity"
        end
        {program: program_info, maps: map_info.freeze, filters: filter_info.freeze}.freeze
      end
    end

    LinuxEBPFPolicyAdapter = EBPFPolicyAdapter unless const_defined?(:LinuxEBPFPolicyAdapter, false)
    EBPFNetworkPolicyAdapter = EBPFPolicyAdapter unless const_defined?(:EBPFNetworkPolicyAdapter, false)
  end
end
