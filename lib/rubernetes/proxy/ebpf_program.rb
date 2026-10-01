# frozen_string_literal: true

# Verifier-safe instruction generation for the Linux TC Service datapath.
#
# The program deliberately uses only helpers available to SCHED_CLS programs:
# direct packet reads for the fixed Ethernet/IP fields, skb load/store helpers
# for variable headers, and hash-map helpers for the compiled Service state.
# Keeping this assembler independent from the syscall adapter makes the wire
# format and the instruction stream testable without a privileged kernel.
require_relative "../platform/linux/bpf"

module Rubernetes
  module Proxy
    class EBPFProgram
      class Assembler
        BPF_LD = 0x00
        BPF_LDX = 0x01
        BPF_ST = 0x02
        BPF_STX = 0x03
        BPF_ALU = 0x04
        BPF_JMP = 0x05
        BPF_ALU64 = 0x07
        BPF_W = 0x00
        BPF_H = 0x08
        BPF_B = 0x10
        BPF_DW = 0x18
        BPF_IMM = 0x00
        BPF_MEM = 0x60
        BPF_K = 0x00
        BPF_X = 0x08
        BPF_ADD = 0x00
        BPF_SUB = 0x10
        BPF_MUL = 0x20
        BPF_DIV = 0x30
        BPF_OR = 0x40
        BPF_AND = 0x50
        BPF_LSH = 0x60
        BPF_RSH = 0x70
        BPF_XOR = 0xa0
        BPF_MOD = 0x90
        BPF_MOV = 0xb0
        BPF_END = 0xd0
        BPF_JA = 0x00
        BPF_JEQ = 0x10
        BPF_JGT = 0x20
        BPF_JGE = 0x30
        BPF_JSET = 0x40
        BPF_JNE = 0x50
        BPF_JLT = 0xa0
        BPF_JLE = 0xb0
        BPF_CALL = 0x80
        BPF_EXIT = 0x90
        BPF_PSEUDO_MAP_FD = 1
        # A ldimm64 with BPF_PSEUDO_FUNC is rewritten by the kernel to a
        # verifier-trusted pointer to a static BPF subprogram. Its immediate
        # is relative to the second instruction of the ldimm64 pair.
        BPF_PSEUDO_FUNC = 4
        BPF_TO_BE = 0x08

        Fixup = Data.define(:index, :label)

        def initialize(map_fds: {})
          @map_fds = map_fds.transform_keys(&:to_s)
          @instructions = []
          @labels = {}
          @fixups = []
          @function_fixups = []
        end

        def emit(code, destination: 0, source: 0, offset: 0, immediate: 0)
          @instructions << Rubernetes::Platform::Linux::BPF::Instruction.new(
            code: Integer(code), destination: Integer(destination), source: Integer(source),
            offset: Integer(offset), immediate: Integer(immediate)
          )
          @instructions.length - 1
        end

        def label(name)
          key = name.to_sym
          raise ArgumentError, "duplicate eBPF label #{name.inspect}" if @labels.key?(key)

          @labels[key] = @instructions.length
          self
        end

        def mov_imm(destination, immediate)
          emit(BPF_ALU64 | BPF_MOV | BPF_K, destination: destination, immediate: immediate)
        end

        def mov_reg(destination, source)
          emit(BPF_ALU64 | BPF_MOV | BPF_X, destination: destination, source: source)
        end

        def alu_imm(operation, destination, immediate)
          emit(BPF_ALU64 | operation | BPF_K, destination: destination, immediate: immediate)
        end

        # 32-bit ALU class: results wrap at 32 bits and zero the upper half,
        # which is exactly the arithmetic the Jenkins hash needs.
        def alu32_imm(operation, destination, immediate)
          emit(BPF_ALU | operation | BPF_K, destination: destination, immediate: immediate)
        end

        def alu32_reg(operation, destination, source)
          emit(BPF_ALU | operation | BPF_X, destination: destination, source: source)
        end

        def mov32_imm(destination, immediate)
          emit(BPF_ALU | BPF_MOV | BPF_K, destination: destination, immediate: immediate)
        end

        def alu_reg(operation, destination, source)
          emit(BPF_ALU64 | operation | BPF_X, destination: destination, source: source)
        end

        def endian(destination, bits = 16)
          emit(BPF_ALU | BPF_END | BPF_TO_BE, destination: destination, immediate: bits)
        end

        def load_mem(size, destination, base, offset)
          emit(BPF_LDX | size | BPF_MEM, destination: destination, source: base, offset: offset)
        end

        def store_mem(size, base, offset, source: nil, immediate: nil)
          if source
            emit(BPF_STX | size | BPF_MEM, destination: base, source: source, offset: offset)
          elsif immediate
            emit(BPF_ST | size | BPF_MEM, destination: base, offset: offset, immediate: immediate)
          else
            raise ArgumentError, "an eBPF store requires source or immediate"
          end
        end

        def jump(operation, label:, destination: 0, source: nil, immediate: 0)
          code = BPF_JMP | operation | (source.nil? ? BPF_K : BPF_X)
          index = emit(code, destination: destination, source: source || 0, immediate: immediate)
          @fixups << Fixup.new(index: index, label: label.to_sym)
          self
        end

        def ja(label)
          jump(BPF_JA, label: label)
        end

        def call(helper)
          emit(BPF_JMP | BPF_CALL, immediate: helper)
        end

        def map_load(destination, name)
          fd = @map_fds.fetch(name.to_s) do
            raise ArgumentError, "map fd for #{name.inspect} is required to compile the TC program"
          end
          emit(BPF_LD | BPF_DW | BPF_IMM, destination: destination, source: BPF_PSEUDO_MAP_FD, immediate: fd)
          # A 64-bit immediate occupies two eBPF instructions. The high word
          # is zero because a map descriptor is a positive 32-bit integer.
          emit(0)
        end

        # Emit a function-pointer relocation for a helper such as bpf_loop.
        # Keeping the target as a label until the complete program is
        # assembled avoids hand-maintained instruction offsets.
        def function_load(destination, label)
          index = emit(BPF_LD | BPF_DW | BPF_IMM, destination: destination,
                                                  source: BPF_PSEUDO_FUNC, immediate: 0)
          emit(0)
          @function_fixups << Fixup.new(index: index, label: label.to_sym)
          self
        end

        def to_instructions
          resolved = @instructions.dup
          @fixups.each do |fixup|
            target = @labels.fetch(fixup.label) { raise ArgumentError, "unknown eBPF label #{fixup.label.inspect}" }
            offset = target - fixup.index - 1
            raise ArgumentError, "eBPF branch offset is out of range" unless offset.between?(-32_768, 32_767)

            instruction = resolved.fetch(fixup.index)
            resolved[fixup.index] = instruction.with(offset: offset)
          end
          @function_fixups.each do |fixup|
            target = @labels.fetch(fixup.label) { raise ArgumentError, "unknown eBPF function label #{fixup.label.inspect}" }
            raise ArgumentError, "eBPF function relocation target must be an instruction" unless target.between?(0, resolved.length - 1)

            instruction = resolved.fetch(fixup.index)
            # BPF_PSEUDO_FUNC uses a pc-relative instruction offset measured
            # from the second instruction of the ldimm64 pair, not an
            # absolute program index.
            resolved[fixup.index] = instruction.with(immediate: target - fixup.index - 1)
          end
          unreachable = unreachable_instructions(resolved)
          # The kernel verifier (check_cfg) rejects a program containing an
          # instruction no path can reach.  Failing here names the emitter
          # bug directly instead of surfacing "unreachable insn N" at load.
          raise ArgumentError, "eBPF emitter produced unreachable instructions at #{unreachable.first(8).join(", ")}" unless unreachable.empty?

          resolved.freeze
        end

        # Mirror the verifier's control-flow reachability walk: entry is
        # instruction 0, ldimm64 occupies two slots, BPF_JA/conditional
        # branches add their target, BPF_EXIT stops, and a BPF_PSEUDO_FUNC
        # relocation makes its static subprogram reachable.
        def unreachable_instructions(instructions)
          reachable = Array.new(instructions.length, false)
          work = [0]
          instructions.each_with_index do |instruction, index|
            next unless instruction.code == (BPF_LD | BPF_DW | BPF_IMM) && instruction.source == BPF_PSEUDO_FUNC

            work << (index + 1 + instruction.immediate)
          end
          until work.empty?
            index = work.pop
            next if index.negative? || index >= instructions.length || reachable[index]

            reachable[index] = true
            instruction = instructions[index]
            if instruction.code == (BPF_LD | BPF_DW | BPF_IMM)
              reachable[index + 1] = true if index + 1 < instructions.length
              work << (index + 2)
              next
            end
            klass = instruction.code & 0x07
            operation = instruction.code & 0xf0
            if [BPF_JMP, 0x06].include?(klass)
              next if operation == BPF_EXIT

              if operation == BPF_JA
                work << (index + 1 + instruction.offset)
                next
              end
              work << (index + 1 + instruction.offset) unless operation == BPF_CALL
            end
            work << (index + 1)
          end
          reachable.each_index.reject { |index| reachable[index] }
        end
      end

      # The ABI is intentionally compact so the program can run with the map
      # sizes already used by the kernel adapter and by older readback tests.
      # All multi-byte scalar fields are host-endian; IP bytes stay in network
      # order because that is also how they occur in an skb.
      module WireFormat
        SERVICE_TOKEN_SIZE = 8
        SERVICE_VALUE_SIZE = 64
        BACKEND_KEY_SIZE = 16
        BACKEND_VALUE_SIZE = 96
        CONNTRACK_KEY_SIZE = 40
        CONNTRACK_VALUE_SIZE = 48
        AFFINITY_KEY_SIZE = 24
        AFFINITY_VALUE_SIZE = 16
        SOURCE_RANGE_KEY_SIZE = 28
        SOURCE_RANGE_VALUE_SIZE = 4
        SNAT_KEY_SIZE = CONNTRACK_KEY_SIZE
        SNAT_VALUE_SIZE = 16
        # bpf_loop permits the callback to walk the complete skb, including
        # non-linear data, without an instruction-count-dependent unroll. The
        # helper itself bounds nr_loops to 1 << 23; an skb length is far below
        # that limit on Linux.
        SCTP_CRC32C_MAX_BYTES = (1 << 23) - 1
        SCTP_CRC32C_LOOP_CONTRACT = {
          "helper" => "bpf_loop",
          "helper_id" => 181,
          "minimum_kernel" => "6.12",
          "callback" => "static_subprogram",
          "callback_context" => "packet_offset_and_crc32c_state",
          "bounded_by" => "skb_data_end_minus_transport_offset",
          "current_loader_support" => true,
          "relocation" => "BPF_PSEUDO_FUNC"
        }.freeze

        SERVICE_KIND = {
          "ClusterIP" => 1,
          "NodePort" => 2,
          "ExternalIP" => 3,
          "LoadBalancer" => 4,
          "HealthCheckNodePort" => 5
        }.freeze

        # Service value offsets.
        SERVICE_TOKEN = 0
        SERVICE_KIND_OFFSET = 8
        SERVICE_AFFINITY_OFFSET = 9
        SERVICE_PORT_OFFSET = 12
        SERVICE_NODE_PORT_OFFSET = 14
        SERVICE_IPV4_COUNT_OFFSET = 16
        SERVICE_IPV6_COUNT_OFFSET = 20
        SERVICE_AFFINITY_TIMEOUT_OFFSET = 24
        SERVICE_VIRTUAL_IP_OFFSET = 28
        SERVICE_NODE_ADDRESS_OFFSET = 44
        SERVICE_FLAGS_OFFSET = 60

        SERVICE_FLAG_MASQUERADE = 0x01
        SERVICE_FLAG_HAIRPIN = 0x02
        SERVICE_FLAG_HEALTH_CHECK = 0x04
        SERVICE_FLAG_SOURCE_RANGES = 0x08

        # Backend value offsets.
        BACKEND_ADDRESS_OFFSET = 0
        BACKEND_PORT_OFFSET = 16
        BACKEND_PROTOCOL_OFFSET = 18
        BACKEND_FAMILY_OFFSET = 19

        # Conntrack value offsets.
        CONNTRACK_BACKEND_ADDRESS_OFFSET = 0
        CONNTRACK_VIRTUAL_IP_OFFSET = 16
        CONNTRACK_BACKEND_PORT_OFFSET = 32
        CONNTRACK_SERVICE_PORT_OFFSET = 34
        CONNTRACK_PROTOCOL_OFFSET = 36
        CONNTRACK_FAMILY_OFFSET = 37
        CONNTRACK_DIRECTION_OFFSET = 38

        # The backend key stores the eight-byte Service token and a slot. The
        # high bit of the slot selects IPv6 so NodePort can share one Rule
        # while retaining separate IPv4/IPv6 backend sets.
        BACKEND_TOKEN_OFFSET = 0
        BACKEND_SLOT_OFFSET = 8
        IPV6_SLOT_BIT = 0x8000_0000
      end

      # Hostile-vector oracle used by local tests and evidence runners. It
      # deliberately applies the same IP-payload bound as the generated TC
      # program, making a padded Ethernet frame a regression test rather than
      # an implicit part of the CRC input.
      module SCTPCRC32C
        POLY = 0x82f63b78
        MAX_BYTES = WireFormat::SCTP_CRC32C_MAX_BYTES

        module_function

        def table
          @table ||= Array.new(256) do |index|
            value = index
            8.times { value = (value >> 1) ^ (value.anybits?(1) ? POLY : 0) }
            value & 0xffff_ffff
          end.freeze
        end

        def crc32c(bytes)
          bytes = String(bytes).b
          raise ArgumentError, "SCTP CRC input exceeds bpf_loop bound" if bytes.bytesize > MAX_BYTES

          crc = 0xffff_ffff
          bytes.each_byte { |byte| crc = (crc >> 8) ^ table[(crc ^ byte) & 0xff] }
          crc ^ 0xffff_ffff
        end

        def sctp_crc32c(frame, family:, l3_offset:, transport_offset:)
          bytes = String(frame).b
          payload_start, packet_end = ip_payload_bounds(bytes, family: family, l3_offset: l3_offset,
                                                               transport_offset: transport_offset)
          unless transport_offset == payload_start && transport_offset + 12 <= packet_end
            raise ArgumentError,
                  "SCTP transport offset is outside the IP payload"
          end

          payload = bytes.byteslice(transport_offset, packet_end - transport_offset).dup
          payload[8, 4] = "\0" * 4
          crc32c(payload)
        end

        def ip_payload_bounds(frame, family:, l3_offset:, transport_offset: nil)
          bytes = String(frame).b
          l3 = Integer(l3_offset)
          if Integer(family) == 4
            raise ArgumentError, "truncated IPv4 header" if l3.negative? || l3 + 20 > bytes.bytesize

            version_ihl = bytes.getbyte(l3)
            ihl = (version_ihl & 0x0f) * 4
            total = bytes.byteslice(l3 + 2, 2).unpack1("n")
            if (version_ihl & 0xf0) != 0x40 || ihl < 20 || total < ihl || l3 + total > bytes.bytesize
              raise ArgumentError,
                    "malformed IPv4 length"
            end
            raise ArgumentError, "IPv4 packet is not SCTP" unless bytes.getbyte(l3 + 9) == ServiceDatapath::IPPROTO_SCTP

            fragment_bits = bytes.byteslice(l3 + 6, 2).unpack1("n") & 0x3fff
            raise ArgumentError, "fragmented IPv4 SCTP packet is unsupported" unless fragment_bits.zero?

            payload_start = l3 + ihl
            if transport_offset && Integer(transport_offset) != payload_start
              raise ArgumentError,
                    "SCTP transport does not follow the IPv4 header"
            end

            [payload_start, l3 + total]
          elsif Integer(family) == 6
            raise ArgumentError, "truncated IPv6 header" if l3.negative? || l3 + 40 > bytes.bytesize

            payload_length = bytes.byteslice(l3 + 4, 2).unpack1("n")
            raise ArgumentError, "IPv6 jumbograms are unsupported by the bounded TC parser" if payload_length.zero?

            packet_end = l3 + 40 + payload_length
            raise ArgumentError, "malformed IPv6 length" if packet_end > bytes.bytesize

            cursor = l3 + 40
            next_header = bytes.getbyte(l3 + 6)
            extension_count = 0
            while ipv6_extension_header?(next_header)
              extension_count += 1
              if extension_count > ServiceDatapath::MAX_IPV6_EXTENSION_HEADERS
                raise ArgumentError, "IPv6 extension header chain exceeds parser bound"
              end
              raise ArgumentError, "truncated IPv6 extension header" if cursor + 2 > packet_end

              current_header = next_header
              next_header = bytes.getbyte(cursor)
              length_unit = bytes.getbyte(cursor + 1)
              header_length = if current_header == ServiceDatapath::IPPROTO_AH
                                (length_unit + 2) * 4
                              else
                                (length_unit + 1) * 8
                              end
              raise ArgumentError, "malformed IPv6 extension length" if header_length < 8 || cursor + header_length > packet_end

              cursor += header_length
            end
            raise ArgumentError, "IPv6 packet is not SCTP" unless next_header == ServiceDatapath::IPPROTO_SCTP
            if transport_offset && Integer(transport_offset) != cursor
              raise ArgumentError,
                    "SCTP transport does not follow the IPv6 extension chain"
            end

            [cursor, packet_end]
          else
            raise ArgumentError, "unsupported IP family #{family.inspect}"
          end
        end

        def ipv6_extension_header?(next_header)
          [ServiceDatapath::IPPROTO_HOPOPT, ServiceDatapath::IPPROTO_ROUTING,
           ServiceDatapath::IPPROTO_DEST, ServiceDatapath::IPPROTO_AH,
           ServiceDatapath::IPPROTO_MH, ServiceDatapath::IPPROTO_HIP,
           ServiceDatapath::IPPROTO_SHIM6].include?(next_header)
        end
      end

      class ServiceDatapath
        include WireFormat

        HELPER_MAP_LOOKUP = 1
        HELPER_MAP_UPDATE = 2
        HELPER_KTIME_GET_NS = 5
        HELPER_SKB_STORE_BYTES = 9
        HELPER_L3_CSUM_REPLACE = 10
        HELPER_L4_CSUM_REPLACE = 11
        HELPER_SKB_LOAD_BYTES = 26
        HELPER_BPF_LOOP = 181
        BPF_F_RECOMPUTE_CSUM = 1
        BPF_F_PSEUDO_HDR = 1 << 4
        TC_ACT_OK = 0
        TC_ACT_SHOT = 2

        ETH_P_IP = 0x0008
        ETH_P_IPV6 = 0xdd86
        ETH_P_8021Q = 0x0081
        ETH_P_8021AD = 0xa888
        ETH_P_9100 = 0x0091
        IPPROTO_TCP = 6
        IPPROTO_UDP = 17
        IPPROTO_SCTP = 132
        IPPROTO_HOPOPT = 0
        IPPROTO_ROUTING = 43
        IPPROTO_FRAGMENT = 44
        IPPROTO_ESP = 50
        IPPROTO_AH = 51
        IPPROTO_DEST = 60
        IPPROTO_MH = 135
        IPPROTO_HIP = 139
        IPPROTO_SHIM6 = 140
        MAX_IPV6_EXTENSION_HEADERS = 8

        # Stack offsets are all below -1 and leave enough room for the largest
        # key/value while staying within the 512-byte eBPF stack limit.
        STACK_SRC_IP = -160
        STACK_DST_IP = -176
        STACK_SERVICE_KEY = -216
        STACK_CONNTRACK_KEY = -256
        STACK_REVERSE_KEY = -296
        STACK_BACKEND_KEY = -312
        STACK_AFFINITY_KEY = -336
        STACK_PORTS = -340
        STACK_AFFINITY_VALUE = -360
        STACK_CONNTRACK_VALUE = -408
        # Keep the rewrite scratch area disjoint from STACK_META (-448..-417).
        # The previous -432 base overlapped metadata (including backend count),
        # so the subsequent DNAT/SNAT assembly could corrupt selection state.
        STACK_REWRITE = -480
        STACK_META = -448
        STACK_SCRATCH = -460
        # Absolute packet offset immediately after the IPv4/IPv6 payload.
        # SCTP CRC must stop here, not at skb->len, because Ethernet padding
        # and unrelated tail bytes are outside the IP packet.
        STACK_PACKET_END = STACK_META + 24
        # Source-range checks run before any rewrite is assembled, so this
        # 28-byte key safely reuses the rewrite area and keeps callback stack
        # accounting below the kernel's combined 512-byte limit.
        STACK_SOURCE_RANGE_KEY = STACK_REWRITE
        CALLBACK_SCRATCH = -8

        FEATURE_MATRIX = {
          ipv4: true,
          ipv6: true,
          tcp: true,
          udp: true,
          sctp_ports: true,
          service_kinds: %w[ClusterIP NodePort ExternalIP LoadBalancer].freeze,
          deterministic_backend_selection: true,
          conntrack: true,
          client_ip_affinity: true,
          dnat: true,
          reverse_snat: true,
          checksum_recompute: true,
          sctp_crc32c: true,
          ipv6_extension_headers: true,
          ipv4_fragment_reassembly: false,
          fragment_drop: true,
          vlan_encapsulation: true,
          forward_masquerade: true,
          topology_hints: true,
          load_balancer_source_ranges: true,
          # HealthCheckNodePort is answered by the node-local responder; TC
          # deliberately returns the packet to the local stack.
          health_check_node_port: true
        }.freeze

        def initialize(map_fds:)
          @map_fds = map_fds.transform_keys(&:to_s).freeze
          @rewrite_sequence = 0
          @connection_sequence = 0
        end

        def features
          FEATURE_MATRIX
        end

        def sctp_crc32c_loop_contract
          SCTP_CRC32C_LOOP_CONTRACT
        end

        def build
          assembler = Assembler.new(map_fds: @map_fds)
          build_program(assembler)
          assembler.to_instructions
        end

        private

        def build_program(a)
          a.mov_reg(8, 1) # Preserve the skb context across helper calls.
          a.mov_reg(6, 1) # r6 is data until the Service map lookup.
          a.load_mem(Assembler::BPF_W, 6, 1, 76)
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
          common_lookup(a)

          a.label(:pass)
          return_action(a, TC_ACT_OK)
          a.label(:drop)
          return_action(a, TC_ACT_SHOT)
          build_sctp_crc_callback(a) if @map_fds.key?("sctp_crc32c")
        end

        def parse_ipv4(a)
          a.label(:parse_ipv4)
          load_packet_field(a, 9, 0, STACK_SCRATCH, 1, :drop)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_SCRATCH)
          a.mov_reg(3, 2)
          a.alu_imm(Assembler::BPF_AND, 3, 0xf0)
          a.jump(Assembler::BPF_JNE, destination: 3, immediate: 0x40, label: :drop)
          a.mov_reg(3, 2)
          a.alu_imm(Assembler::BPF_AND, 3, 0x0f)
          a.jump(Assembler::BPF_JLT, destination: 3, immediate: 5, label: :drop)
          a.alu_imm(Assembler::BPF_LSH, 3, 2)
          a.mov_reg(4, 9)
          a.alu_reg(Assembler::BPF_ADD, 4, 3)
          a.store_mem(Assembler::BPF_W, 10, STACK_META, source: 4)
          a.mov_reg(9, 4)
          # bpf_skb_load_bytes is a helper call and clobbers R1-R5.  The IHL
          # byte count in R3 is needed again for the total_length comparison,
          # so park it in the scratch slot that the two-byte load leaves free.
          a.store_mem(Assembler::BPF_W, 10, STACK_SCRATCH + 8, source: 3)
          # IPv4 total_length includes the IPv4 header and payload.  Bind the
          # packet end before parsing transport fields so L4/CRC reads cannot
          # consume Ethernet padding or bytes from a following skb segment.
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 2, STACK_SCRATCH, 2, :drop)
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_SCRATCH)
          a.endian(2, 16)
          a.load_mem(Assembler::BPF_W, 3, 10, STACK_SCRATCH + 8)
          a.jump(Assembler::BPF_JLT, destination: 2, source: 3, label: :drop)
          # Use the original L3 offset and host-order length for the absolute
          # wire end; this excludes Ethernet padding from the SCTP walk.
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          a.load_mem(Assembler::BPF_H, 5, 10, STACK_SCRATCH)
          a.endian(5, 16)
          a.alu_reg(Assembler::BPF_ADD, 4, 5)
          a.store_mem(Assembler::BPF_W, 10, STACK_PACKET_END, source: 4)
          a.load_mem(Assembler::BPF_W, 5, 10, STACK_META + 8)
          a.jump(Assembler::BPF_JGT, destination: 4, source: 5, label: :drop)
          check_transport_bounds(a, 9, :drop)
          check_transport_packet_bounds(a, 9, :drop)
          # Any fragment can hide the transport header or require reassembly.
          # TC has no reassembly primitive, so fail closed before service lookup.
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 6, STACK_SCRATCH, 2, :drop)
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_SCRATCH)
          a.endian(2, 16)
          a.alu_imm(Assembler::BPF_AND, 2, 0x3fff)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: 0, label: :drop)
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 9, STACK_SCRATCH, 1, :drop)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_SCRATCH)
          set_meta(a, family: 4, protocol_register: 2)
          load_transport_ports(a, 9, :drop)
          zero_stack(a, STACK_SRC_IP, 16)
          zero_stack(a, STACK_DST_IP, 16)
          a.store_mem(Assembler::BPF_H, 10, STACK_SRC_IP + 8, immediate: 0)
          a.store_mem(Assembler::BPF_H, 10, STACK_SRC_IP + 10, immediate: 0xffff)
          a.store_mem(Assembler::BPF_H, 10, STACK_DST_IP + 8, immediate: 0)
          a.store_mem(Assembler::BPF_H, 10, STACK_DST_IP + 10, immediate: 0xffff)
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 12, STACK_SCRATCH, 4, :drop)
          copy_stack(a, STACK_SCRATCH, STACK_SRC_IP + 12, 4)
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 16, STACK_SCRATCH, 4, :drop)
          copy_stack(a, STACK_SCRATCH, STACK_DST_IP + 12, 4)
          a.ja(:packet_fields_ready)
        end

        def parse_ipv6(a)
          a.label(:parse_ipv6)
          load_packet_field(a, 9, 0, STACK_SCRATCH, 1, :drop)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_SCRATCH)
          a.mov_reg(3, 2)
          a.alu_imm(Assembler::BPF_AND, 3, 0xf0)
          a.jump(Assembler::BPF_JNE, destination: 3, immediate: 0x60, label: :drop)
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 6, STACK_SCRATCH, 1, :drop)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_SCRATCH)
          set_meta(a, family: 6, protocol_register: 2)
          a.load_mem(Assembler::BPF_W, 9, 10, STACK_META + 4)
          a.alu_imm(Assembler::BPF_ADD, 9, 40)
          # IPv6 payload_length covers extension headers and the transport
          # payload. A zero length is a jumbogram that this TC parser cannot
          # safely bound without a Jumbo Payload option, so reject it.
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 4, STACK_SCRATCH, 2, :drop)
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_SCRATCH)
          a.endian(2, 16)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: :drop)
          a.mov_reg(4, 9)
          a.alu_reg(Assembler::BPF_ADD, 4, 2)
          a.store_mem(Assembler::BPF_W, 10, STACK_PACKET_END, source: 4)
          a.load_mem(Assembler::BPF_W, 5, 10, STACK_META + 8)
          a.jump(Assembler::BPF_JGT, destination: 4, source: 5, label: :drop)
          parse_ipv6_extensions(a)
          a.label(:ipv6_transport_ready)
          check_transport_bounds(a, 9, :drop)
          check_transport_packet_bounds(a, 9, :drop)
          load_transport_ports(a, 9, :drop)
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 8, STACK_SRC_IP, 16, :drop)
          a.load_mem(Assembler::BPF_W, 4, 10, STACK_META + 4)
          load_packet_field(a, 4, 24, STACK_DST_IP, 16, :drop)
          a.ja(:packet_fields_ready)
        end

        def parse_ipv6_extensions(a)
          stages = (0...MAX_IPV6_EXTENSION_HEADERS).map { |index| :"ipv6_extension_#{index}" }
          a.ja(stages.first)

          stages.each_with_index do |stage, index|
            next_stage = stages[index + 1] || :drop
            extension_label = :"ipv6_parse_extension_#{index}"
            a.label(stage)
            a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
            [IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP].each do |protocol|
              a.jump(Assembler::BPF_JEQ, destination: 2, immediate: protocol, label: :ipv6_transport_ready)
            end
            [IPPROTO_HOPOPT, IPPROTO_ROUTING, IPPROTO_DEST, IPPROTO_MH, IPPROTO_HIP, IPPROTO_SHIM6].each do |protocol|
              a.jump(Assembler::BPF_JEQ, destination: 2, immediate: protocol, label: extension_label)
            end
            # Fragment and ESP headers cannot be safely interpreted at TC.
            # Rejecting them avoids routing a non-first fragment as a new flow.
            a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_FRAGMENT, label: :drop)
            a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_ESP, label: :drop)
            # Any other upper-layer protocol (ICMPv6 neighbour discovery, echo,
            # MLD, ...) is not Service traffic: let the stack handle it.
            a.jump(Assembler::BPF_JNE, destination: 2, immediate: IPPROTO_AH, label: :pass)

            a.label(extension_label)
            a.load_mem(Assembler::BPF_B, 4, 10, STACK_META + 13)
            # skb_load_bytes clobbers R1-R5; retain the current header type so
            # AH's four-byte length unit can be selected after the helper.
            a.store_mem(Assembler::BPF_B, 10, STACK_SCRATCH + 2, source: 4)
            skb_load_from_register(a, 9, STACK_SCRATCH, 2, :drop)
            a.load_mem(Assembler::BPF_B, 2, 10, STACK_SCRATCH)
            a.load_mem(Assembler::BPF_B, 3, 10, STACK_SCRATCH + 1)
            a.store_mem(Assembler::BPF_B, 10, STACK_META + 13, source: 2)
            a.load_mem(Assembler::BPF_B, 4, 10, STACK_SCRATCH + 2)
            # AH carries a four-byte length unit; every other supported
            # extension uses eight-byte length units.
            a.jump(Assembler::BPF_JEQ, destination: 4, immediate: IPPROTO_AH, label: :"ipv6_ah_length_#{index}")
            a.alu_imm(Assembler::BPF_ADD, 3, 1)
            a.alu_imm(Assembler::BPF_LSH, 3, 3)
            a.ja(:"ipv6_extension_length_ready_#{index}")
            a.label(:"ipv6_ah_length_#{index}")
            a.alu_imm(Assembler::BPF_ADD, 3, 2)
            a.alu_imm(Assembler::BPF_LSH, 3, 2)
            a.label(:"ipv6_extension_length_ready_#{index}")
            a.mov_reg(4, 9)
            a.alu_reg(Assembler::BPF_ADD, 4, 3)
            a.mov_reg(2, 6)
            a.alu_reg(Assembler::BPF_ADD, 2, 4)
            a.jump(Assembler::BPF_JGT, destination: 2, source: 7, label: :drop)
            a.load_mem(Assembler::BPF_W, 2, 10, STACK_PACKET_END)
            a.jump(Assembler::BPF_JGT, destination: 4, source: 2, label: :drop)
            a.mov_reg(9, 4)
            a.ja(next_stage)
          end
        end

        def common_lookup(a)
          a.label(:packet_fields_ready)
          zero_stack(a, STACK_SERVICE_KEY, 40)
          zero_stack(a, STACK_CONNTRACK_KEY, 40)
          zero_stack(a, STACK_REVERSE_KEY, 40)
          zero_stack(a, STACK_BACKEND_KEY, 16)
          zero_stack(a, STACK_AFFINITY_KEY, 24)
          set_key_header(a, STACK_SERVICE_KEY)
          set_conntrack_header(a, STACK_CONNTRACK_KEY)
          copy_stack(a, STACK_DST_IP, STACK_SERVICE_KEY + 8, 16)
          copy_stack(a, STACK_SRC_IP, STACK_CONNTRACK_KEY + 8, 16)
          copy_stack(a, STACK_DST_IP, STACK_CONNTRACK_KEY + 24, 16)
          map_lookup(a, "conntrack", STACK_CONNTRACK_KEY, 1)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: :lookup_service)
          a.mov_reg(9, 0)
          handle_existing_connection(a)

          a.label(:lookup_service)
          map_lookup(a, "service_rules", STACK_SERVICE_KEY, 1)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: :service_found)
          # A NodePort is represented by a zero VIP and the destination port
          # duplicated in the node_port key field. This second lookup keeps
          # ClusterIP/ExternalIP exact matching independent from NodePort.
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_PORTS + 2)
          a.endian(2, 16)
          a.store_mem(Assembler::BPF_H, 10, STACK_SERVICE_KEY + 4, source: 2)
          zero_stack_range(a, STACK_SERVICE_KEY + 8, 16)
          map_lookup(a, "service_rules", STACK_SERVICE_KEY, 1)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: :pass)

          a.label(:service_found)
          a.mov_reg(6, 0) # r6 now owns the Service value pointer.
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_KIND_OFFSET)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: SERVICE_KIND.fetch("HealthCheckNodePort"), label: :health_check_service)
          if @map_fds.key?("source_ranges")
            a.jump(Assembler::BPF_JEQ, destination: 2, immediate: SERVICE_KIND.fetch("LoadBalancer"), label: :check_lb_source_ranges)
          end
          a.ja(:service_policy_ready)

          if @map_fds.key?("source_ranges")
            a.label(:check_lb_source_ranges)
            enforce_load_balancer_source_ranges(a)
          end

          a.label(:service_policy_ready)
          a.load_mem(Assembler::BPF_W, 2, 6, SERVICE_IPV4_COUNT_OFFSET)
          a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JEQ, destination: 3, immediate: 6, label: :service_count_ipv6)
          a.mov_reg(4, 2)
          a.ja(:service_count_ready)
          a.label(:service_count_ipv6)
          a.load_mem(Assembler::BPF_W, 4, 6, SERVICE_IPV6_COUNT_OFFSET)
          a.label(:service_count_ready)
          a.jump(Assembler::BPF_JEQ, destination: 4, immediate: 0, label: :drop)
          a.store_mem(Assembler::BPF_W, 10, STACK_META + 20, source: 4)
          select_backend(a)

          a.label(:health_check_service)
          # HealthCheckNodePort is owned by the node health responder. TC must
          # leave the packet local so that responder can return 200 or 503;
          # forwarding it to an endpoint would report application health and
          # violate Kubernetes' node-local health contract.
          return_action(a, TC_ACT_OK)
        end

        def enforce_load_balancer_source_ranges(a)
          # The LPM key prefixes the source address with the Service token. A
          # full-width lookup therefore selects the longest configured CIDR
          # for this Service without iterating an unbounded range list.
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_FLAGS_OFFSET)
          a.alu_imm(Assembler::BPF_AND, 2, WireFormat::SERVICE_FLAG_SOURCE_RANGES)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: :service_policy_ready)
          zero_stack(a, STACK_SOURCE_RANGE_KEY, WireFormat::SOURCE_RANGE_KEY_SIZE)
          a.store_mem(Assembler::BPF_W, 10, STACK_SOURCE_RANGE_KEY, immediate: 192)
          copy_map_to_stack(a, 6, SERVICE_TOKEN, STACK_SOURCE_RANGE_KEY + 4, 8)
          copy_stack(a, STACK_SRC_IP, STACK_SOURCE_RANGE_KEY + 12, 16)
          map_lookup(a, "source_ranges", STACK_SOURCE_RANGE_KEY, 1)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: :drop)
          a.ja(:service_policy_ready)
        end

        def select_backend(a)
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_AFFINITY_OFFSET)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: :hash_backend)
          copy_map_to_stack(a, 6, SERVICE_TOKEN, STACK_AFFINITY_KEY, 8)
          copy_stack(a, STACK_SRC_IP, STACK_AFFINITY_KEY + 8, 16)
          map_lookup(a, "client_ip_affinity", STACK_AFFINITY_KEY, 4)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: :hash_backend)
          # bpf_ktime_get_ns clobbers R1-R5; keep the affinity value pointer in
          # callee-saved R9 while asking for the current time.
          a.mov_reg(9, 0)
          a.call(HELPER_KTIME_GET_NS)
          a.alu_imm(Assembler::BPF_DIV, 0, 1_000_000_000)
          a.mov_reg(4, 9)
          a.load_mem(Assembler::BPF_W, 2, 4, 12)
          a.jump(Assembler::BPF_JGE, destination: 0, source: 2, label: :hash_backend)
          copy_map_to_stack(a, 4, 0, STACK_BACKEND_KEY, 8)
          a.load_mem(Assembler::BPF_W, 2, 4, 8)
          a.store_mem(Assembler::BPF_W, 10, STACK_BACKEND_KEY + 8, source: 2)
          zero_stack_range(a, STACK_BACKEND_KEY + 12, 4)
          map_lookup(a, "backends", STACK_BACKEND_KEY, 4)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: :hash_backend)
          a.mov_reg(9, 0)
          a.ja(:new_backend_from_affinity)

          a.label(:hash_backend)
          hash_packet(a)
          a.load_mem(Assembler::BPF_W, 3, 10, STACK_META + 20)
          a.alu_reg(Assembler::BPF_MOD, 2, 3)
          a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JEQ, destination: 3, immediate: 6, label: :hash_ipv6_slot)
          a.ja(:hash_slot_ready)
          a.label(:hash_ipv6_slot)
          a.alu_imm(Assembler::BPF_OR, 2, IPV6_SLOT_BIT)
          a.label(:hash_slot_ready)
          # copy_map_to_stack uses R2 as its scratch register. Preserve the
          # selected slot before copying the Service token, otherwise the
          # token's low word is written as the backend slot.
          a.mov_reg(4, 2)
          copy_map_to_stack(a, 6, SERVICE_TOKEN, STACK_BACKEND_KEY, 8)
          a.store_mem(Assembler::BPF_W, 10, STACK_BACKEND_KEY + 8, source: 4)
          zero_stack_range(a, STACK_BACKEND_KEY + 12, 4)
          map_lookup(a, "backends", STACK_BACKEND_KEY, 4)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: :drop)
          a.mov_reg(9, 0)

          a.label(:new_backend_from_hash)
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_AFFINITY_OFFSET)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: :new_connection)
          zero_stack(a, STACK_AFFINITY_VALUE, 16)
          copy_stack(a, STACK_BACKEND_KEY, STACK_AFFINITY_VALUE, 12)
          a.call(HELPER_KTIME_GET_NS)
          a.alu_imm(Assembler::BPF_DIV, 0, 1_000_000_000)
          a.load_mem(Assembler::BPF_W, 2, 6, SERVICE_AFFINITY_TIMEOUT_OFFSET)
          a.alu_reg(Assembler::BPF_ADD, 0, 2)
          a.store_mem(Assembler::BPF_W, 10, STACK_AFFINITY_VALUE + 12, source: 0)
          map_update(a, "client_ip_affinity", STACK_AFFINITY_KEY, STACK_AFFINITY_VALUE, :drop)

          a.label(:new_connection)
          prepare_snat(a)
          build_connection_state(a)
          rewrite_forward_snat(a, :drop)
          rewrite_from_backend(a, :destination, :drop)
          return_action(a, TC_ACT_OK)

          a.label(:new_backend_from_affinity)
          prepare_snat(a)
          build_connection_state(a)
          rewrite_forward_snat(a, :drop)
          rewrite_from_backend(a, :destination, :drop)
          return_action(a, TC_ACT_OK)
        end

        def handle_existing_connection(a)
          # The entry's direction byte selects the path; the address
          # comparisons below still make an accidental hash collision fail
          # closed (forward: VIP in the destination, reverse: backend in the
          # source).
          a.load_mem(Assembler::BPF_B, 2, 9, CONNTRACK_DIRECTION_OFFSET)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: 0, label: :existing_reverse)
          compare_map_value_to_stack(a, 9, CONNTRACK_VIRTUAL_IP_OFFSET, STACK_DST_IP, :drop)
          a.load_mem(Assembler::BPF_B, 2, 9, CONNTRACK_FAMILY_OFFSET)
          a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JNE, destination: 2, source: 3, label: :drop)
          rewrite_from_conntrack(a, :destination, :drop)
          rewrite_existing_forward_source(a, :drop) if @map_fds.key?("snat")
          return_action(a, TC_ACT_OK)

          a.label(:existing_reverse)
          compare_map_value_to_stack(a, 9, CONNTRACK_BACKEND_ADDRESS_OFFSET, STACK_SRC_IP, :drop)
          a.load_mem(Assembler::BPF_B, 2, 9, CONNTRACK_FAMILY_OFFSET)
          a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JNE, destination: 2, source: 3, label: :drop)
          rewrite_from_conntrack(a, :source, :drop)
          rewrite_existing_reverse_destination(a, :drop) if @map_fds.key?("snat")
          return_action(a, TC_ACT_OK)
        end

        def build_connection_state(a)
          sequence = @connection_sequence
          @connection_sequence += 1
          nodeport_label = :"connection_nodeport_vip_#{sequence}"
          vip_ready_label = :"connection_vip_ready_#{sequence}"
          reverse_source_label = :"connection_reverse_source_#{sequence}"
          reverse_address_ready_label = :"connection_reverse_address_ready_#{sequence}"
          snat_ready_label = :"connection_snat_ready_#{sequence}"
          zero_stack(a, STACK_CONNTRACK_VALUE, 48)
          copy_map_to_stack(a, 9, BACKEND_ADDRESS_OFFSET, STACK_CONNTRACK_VALUE, 16)
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_KIND_OFFSET)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: SERVICE_KIND.fetch("NodePort"), label: nodeport_label)
          copy_map_to_stack(a, 6, SERVICE_VIRTUAL_IP_OFFSET, STACK_CONNTRACK_VALUE + 16, 16)
          a.ja(vip_ready_label)
          a.label(nodeport_label)
          copy_stack(a, STACK_DST_IP, STACK_CONNTRACK_VALUE + 16, 16)
          a.label(vip_ready_label)
          copy_map_to_stack(a, 9, BACKEND_PORT_OFFSET, STACK_CONNTRACK_VALUE + 32, 2)
          service_port_nodeport_label = :"connection_service_port_nodeport_#{sequence}"
          service_port_ready_label = :"connection_service_port_ready_#{sequence}"
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_KIND_OFFSET)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: SERVICE_KIND.fetch("NodePort"),
                                     label: service_port_nodeport_label)
          copy_map_to_stack(a, 6, SERVICE_PORT_OFFSET, STACK_CONNTRACK_VALUE + 34, 2)
          a.ja(service_port_ready_label)
          a.label(service_port_nodeport_label)
          # A NodePort flow must restore the externally visible node port on
          # the reverse packet.  The ClusterIP service port is the backend's
          # internal destination and is not the port the client addressed.
          copy_map_to_stack(a, 6, SERVICE_NODE_PORT_OFFSET, STACK_CONNTRACK_VALUE + 34, 2)
          a.label(service_port_ready_label)
          copy_map_to_stack(a, 9, BACKEND_PROTOCOL_OFFSET, STACK_CONNTRACK_VALUE + 36, 1)
          copy_map_to_stack(a, 9, BACKEND_FAMILY_OFFSET, STACK_CONNTRACK_VALUE + 37, 1)
          map_update(a, "conntrack", STACK_CONNTRACK_KEY, STACK_CONNTRACK_VALUE, :drop)

          zero_stack(a, STACK_REVERSE_KEY, 40)
          copy_stack_header(a, STACK_REVERSE_KEY)
          a.load_mem(Assembler::BPF_H, 2, 9, BACKEND_PORT_OFFSET)
          a.endian(2, 16)
          a.store_mem(Assembler::BPF_H, 10, STACK_REVERSE_KEY + 2, source: 2)
          # STACK_PORTS contains the packet's network-order bytes.  Build the
          # host-order key representation byte-by-byte so this does not rely
          # on BPF_END behavior for helper-loaded packet memory.
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_PORTS)
          a.store_mem(Assembler::BPF_B, 10, STACK_REVERSE_KEY + 5, source: 2)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_PORTS + 1)
          a.store_mem(Assembler::BPF_B, 10, STACK_REVERSE_KEY + 4, source: 2)
          copy_map_to_stack(a, 9, BACKEND_ADDRESS_OFFSET, STACK_REVERSE_KEY + 8, 16)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 16)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: reverse_source_label)
          copy_map_to_stack(a, 6, SERVICE_NODE_ADDRESS_OFFSET, STACK_REVERSE_KEY + 24, 16)
          a.ja(reverse_address_ready_label)
          a.label(reverse_source_label)
          copy_stack(a, STACK_SRC_IP, STACK_REVERSE_KEY + 24, 16)
          a.label(reverse_address_ready_label)
          if @map_fds.key?("snat")
            # Store both directions: forward packets need the chosen node
            # address as source, while reverse packets need the original pod
            # address as destination.
            a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 16)
            a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: snat_ready_label)
            map_update(a, "snat", STACK_CONNTRACK_KEY, STACK_REVERSE_KEY + 24, :drop)
            map_update(a, "snat", STACK_REVERSE_KEY, STACK_SRC_IP, :drop)
            a.label(snat_ready_label)
          end
          # The reverse entry carries an explicit direction: a NodePort flow
          # stores the node address as its virtual IP, so a reply packet
          # (destination = node address) would otherwise be classified as a
          # new forward packet and rewritten in the wrong direction.
          a.store_mem(Assembler::BPF_B, 10, STACK_CONNTRACK_VALUE + CONNTRACK_DIRECTION_OFFSET, immediate: 1)
          map_update(a, "conntrack", STACK_REVERSE_KEY, STACK_CONNTRACK_VALUE, :drop)
        end

        def prepare_snat(a)
          sequence = @connection_sequence
          snat_label = :"snat_connection_#{sequence}"
          no_snat_label = :"no_snat_connection_#{sequence}"
          snat_state_ready_label = :"snat_state_ready_#{sequence}"
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_FLAGS_OFFSET)
          a.alu_imm(Assembler::BPF_AND, 2, WireFormat::SERVICE_FLAG_MASQUERADE)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: 0, label: snat_label)
          a.load_mem(Assembler::BPF_B, 2, 6, SERVICE_FLAGS_OFFSET)
          a.alu_imm(Assembler::BPF_AND, 2, WireFormat::SERVICE_FLAG_HAIRPIN)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: no_snat_label)
          compare_map_value_to_stack(a, 9, BACKEND_ADDRESS_OFFSET, STACK_SRC_IP, no_snat_label)
          a.ja(snat_label)

          a.label(snat_label)
          a.store_mem(Assembler::BPF_B, 10, STACK_META + 16, immediate: 1)
          a.ja(snat_state_ready_label)
          a.label(no_snat_label)
          a.store_mem(Assembler::BPF_B, 10, STACK_META + 16, immediate: 0)
          a.label(snat_state_ready_label)
        end

        def rewrite_forward_snat(a, failure_label)
          sequence = @rewrite_sequence
          skip_label = :"skip_forward_snat_#{sequence}"
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 16)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: skip_label)
          # Every masqueraded flow (NodePort included) leaves with the node's
          # backend-facing address: kube-proxy parity, and the address the
          # reverse conntrack entry below expects replies to arrive at.
          copy_map_to_stack(a, 6, SERVICE_NODE_ADDRESS_OFFSET, STACK_REWRITE, 16)
          copy_stack(a, STACK_PORTS, STACK_REWRITE + 16, 2)
          store_rewrite(a, :source, STACK_REWRITE, STACK_REWRITE + 16, failure_label)
          a.label(skip_label)
        end

        def rewrite_existing_forward_source(a, failure_label)
          lookup_label = :"existing_forward_snat_#{@rewrite_sequence}"
          map_lookup(a, "snat", STACK_CONNTRACK_KEY, 1)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: lookup_label)
          copy_map_to_stack(a, 0, 0, STACK_REWRITE, 16)
          copy_stack(a, STACK_PORTS, STACK_REWRITE + 16, 2)
          store_rewrite(a, :source, STACK_REWRITE, STACK_REWRITE + 16, failure_label)
          a.label(lookup_label)
        end

        def rewrite_existing_reverse_destination(a, failure_label)
          lookup_label = :"existing_reverse_snat_#{@rewrite_sequence}"
          map_lookup(a, "snat", STACK_CONNTRACK_KEY, 1)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: lookup_label)
          copy_map_to_stack(a, 0, 0, STACK_REWRITE, 16)
          # A reverse packet already carries the original client source port
          # as its destination port; only the destination address is rewritten.
          store_address_rewrite(a, :destination, STACK_REWRITE, failure_label)
          a.label(lookup_label)
        end

        def rewrite_from_backend(a, direction, failure_label)
          a.load_mem(Assembler::BPF_B, 2, 9, BACKEND_FAMILY_OFFSET)
          a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JNE, destination: 2, source: 3, label: failure_label)
          copy_map_to_stack(a, 9, BACKEND_ADDRESS_OFFSET, STACK_REWRITE, 16)
          copy_map_to_stack(a, 9, BACKEND_PORT_OFFSET, STACK_REWRITE + 16, 2)
          store_rewrite(a, direction, STACK_REWRITE, STACK_REWRITE + 16, failure_label)
        end

        def rewrite_from_conntrack(a, direction, failure_label)
          address_offset = direction == :destination ? CONNTRACK_BACKEND_ADDRESS_OFFSET : CONNTRACK_VIRTUAL_IP_OFFSET
          port_offset = direction == :destination ? CONNTRACK_BACKEND_PORT_OFFSET : CONNTRACK_SERVICE_PORT_OFFSET
          copy_map_to_stack(a, 9, address_offset, STACK_REWRITE, 16)
          copy_map_to_stack(a, 9, port_offset, STACK_REWRITE + 16, 2)
          store_rewrite(a, direction, STACK_REWRITE, STACK_REWRITE + 16, failure_label)
        end

        def store_rewrite(a, direction, address_stack, port_stack, failure_label)
          sequence = @rewrite_sequence
          @rewrite_sequence += 1
          store_address_rewrite(a, direction, address_stack, failure_label, sequence: sequence,
                                                                            update_transport_checksum: false)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
          # The transport offset points at the source port. Destination
          # rewrites must advance by two bytes; using the base offset here
          # silently rewrote the source port and left the Service port intact.
          a.alu_imm(Assembler::BPF_ADD, 2, direction == :destination ? 2 : 0)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, port_stack)
          a.mov_imm(4, 2)
          a.mov_imm(5, 0)
          a.call(HELPER_SKB_STORE_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
          update_port_checksum(a, direction == :destination ? STACK_PORTS + 2 : STACK_PORTS,
                               port_stack, failure_label, sequence: sequence)
          if @map_fds.key?("sctp_crc32c")
            update_sctp_crc32c(a, port_stack, direction, failure_label)
          else
            reject_sctp_without_crc(a, failure_label)
          end
        end

        def store_address_rewrite(a, direction, address_stack, failure_label, sequence: nil,
                                  update_transport_checksum: true)
          sequence ||= @rewrite_sequence
          @rewrite_sequence += 1 if sequence == @rewrite_sequence
          ipv4_label = :"rewrite_address_ipv4_#{sequence}"
          address_done_label = :"rewrite_address_done_#{sequence}"
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 4, label: ipv4_label)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: 6, label: failure_label)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META + 4)
          a.alu_imm(Assembler::BPF_ADD, 2, direction == :destination ? 24 : 8)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, address_stack)
          a.mov_imm(4, 16)
          a.mov_imm(5, 0)
          a.call(HELPER_SKB_STORE_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
          update_address_checksums(a, direction, address_stack, failure_label, family: 6, sequence: sequence)
          a.ja(address_done_label)
          a.label(ipv4_label)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META + 4)
          a.alu_imm(Assembler::BPF_ADD, 2, direction == :destination ? 16 : 12)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, address_stack + 12)
          a.mov_imm(4, 4)
          a.mov_imm(5, 0)
          a.call(HELPER_SKB_STORE_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
          update_address_checksums(a, direction, address_stack, failure_label, family: 4, sequence: sequence)
          a.label(address_done_label)
          return unless update_transport_checksum

          if @map_fds.key?("sctp_crc32c")
            update_sctp_crc32c(a, nil, direction, failure_label)
          else
            reject_sctp_without_crc(a, failure_label)
          end
        end

        def reject_sctp_without_crc(a, failure_label)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_SCTP, label: failure_label)
        end

        # skb_store_bytes() does not update checksums when passed a zero flags
        # argument.  Keep checksum repair explicit so the same path works for
        # both locally delivered packets and packets routed to a veth peer.
        # The old address/port values remain in the parser stacks, while the
        # replacement values are in the rewrite stack.
        def update_address_checksums(a, direction, address_stack, failure_label, family:, sequence:)
          done_label = :"address_checksum_done_#{sequence}_#{family}"
          tcp_label = :"address_checksum_tcp_#{sequence}_#{family}"
          udp_label = :"address_checksum_udp_#{sequence}_#{family}"
          old_stack = direction == :destination ? STACK_DST_IP : STACK_SRC_IP

          replace_ipv4_header_checksum(a, old_stack, address_stack, failure_label) if family == 4

          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_TCP, label: tcp_label)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_UDP, label: udp_label)
          # SCTP is handled by the optional CRC32c path below.  For an
          # unsupported transport, leave the checksum untouched and let the
          # normal service/protocol key decide whether the flow is eligible.
          a.ja(done_label)

          a.label(tcp_label)
          replace_transport_address_checksum(a, old_stack, address_stack, failure_label,
                                             family: family, checksum_offset: 16)
          a.ja(done_label)

          a.label(udp_label)
          replace_transport_address_checksum(a, old_stack, address_stack, failure_label,
                                             family: family, checksum_offset: 6)
          a.ja(done_label)

          a.label(done_label)
        end

        def replace_ipv4_header_checksum(a, old_stack, new_stack, failure_label)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META + 4)
          a.alu_imm(Assembler::BPF_ADD, 2, 10)
          a.load_mem(Assembler::BPF_W, 3, 10, old_stack + 12)
          a.load_mem(Assembler::BPF_W, 4, 10, new_stack + 12)
          a.mov_imm(5, 4)
          a.call(HELPER_L3_CSUM_REPLACE)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
        end

        def replace_transport_address_checksum(a, old_stack, new_stack, failure_label, family:, checksum_offset:)
          chunks = family == 4 ? [12] : [0, 4, 8, 12]
          chunks.each do |offset|
            a.mov_reg(1, 8)
            a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
            a.alu_imm(Assembler::BPF_ADD, 2, checksum_offset)
            a.load_mem(Assembler::BPF_W, 3, 10, old_stack + offset)
            a.load_mem(Assembler::BPF_W, 4, 10, new_stack + offset)
            a.mov_imm(5, BPF_F_PSEUDO_HDR | 4)
            a.call(HELPER_L4_CSUM_REPLACE)
            a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
          end
        end

        def update_port_checksum(a, old_port_stack, new_port_stack, failure_label, sequence:)
          done_label = :"port_checksum_done_#{sequence}"
          tcp_label = :"port_checksum_tcp_#{sequence}"
          udp_label = :"port_checksum_udp_#{sequence}"
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_TCP, label: tcp_label)
          a.jump(Assembler::BPF_JEQ, destination: 2, immediate: IPPROTO_UDP, label: udp_label)
          a.ja(done_label)

          a.label(tcp_label)
          replace_transport_port_checksum(a, old_port_stack, new_port_stack, failure_label, checksum_offset: 16)
          a.ja(done_label)

          a.label(udp_label)
          replace_transport_port_checksum(a, old_port_stack, new_port_stack, failure_label, checksum_offset: 6)
          a.ja(done_label)

          a.label(done_label)
        end

        def replace_transport_port_checksum(a, old_port_stack, new_port_stack, failure_label, checksum_offset:)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
          a.alu_imm(Assembler::BPF_ADD, 2, checksum_offset)
          a.load_mem(Assembler::BPF_H, 3, 10, old_port_stack)
          a.load_mem(Assembler::BPF_H, 4, 10, new_port_stack)
          a.mov_imm(5, 2)
          a.call(HELPER_L4_CSUM_REPLACE)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
        end

        def update_sctp_crc32c(a, _port_stack, _direction, failure_label)
          done_label = :"sctp_crc_done_#{@rewrite_sequence}"
          local_failure_label = :"sctp_crc_failure_#{@rewrite_sequence}"
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: IPPROTO_SCTP, label: done_label)
          # The callback walks exactly the IP payload from the SCTP header to
          # packet_end. skb->len is deliberately not used: Ethernet minimum
          # frame padding must never participate in the CRC32c.
          a.load_mem(Assembler::BPF_W, 5, 10, STACK_PACKET_END)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
          a.jump(Assembler::BPF_JGT, destination: 2, source: 5, label: local_failure_label)
          a.alu_reg(Assembler::BPF_SUB, 5, 2)
          a.jump(Assembler::BPF_JLT, destination: 5, immediate: 12, label: local_failure_label)
          a.jump(Assembler::BPF_JGT, destination: 5, immediate: WireFormat::SCTP_CRC32C_MAX_BYTES,
                                     label: local_failure_label)

          # skb_store_bytes() is a helper call and therefore clobbers R1-R5.
          # Preserve the validated loop count before zeroing the wire checksum.
          a.store_mem(Assembler::BPF_W, 10, STACK_SCRATCH + 4, source: 5)

          # SCTP CRC is defined with the checksum field zeroed.
          zero_stack(a, STACK_SCRATCH, 4)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
          a.alu_imm(Assembler::BPF_ADD, 2, 8)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, STACK_SCRATCH)
          a.mov_imm(4, 4)
          a.mov_imm(5, 0)
          a.call(HELPER_SKB_STORE_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: local_failure_label)

          # bpf_loop requires a stack callback context. Place the skb context
          # pointer in a dedicated spill slot; the verifier preserves its
          # PTR_TO_CTX type when the callback loads that exact slot. The
          # remaining slots hold the transport offset, running CRC, and error.
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
          a.store_mem(Assembler::BPF_W, 10, STACK_REWRITE + 8, source: 2)
          a.mov_reg(2, 8)
          a.store_mem(Assembler::BPF_DW, 10, STACK_REWRITE, source: 2)
          a.store_mem(Assembler::BPF_W, 10, STACK_REWRITE + 12, immediate: 0xffff_ffff)
          a.store_mem(Assembler::BPF_W, 10, STACK_REWRITE + 16, immediate: 0)
          a.load_mem(Assembler::BPF_W, 5, 10, STACK_SCRATCH + 4)
          a.mov_reg(1, 5)
          a.function_load(2, :sctp_crc_callback)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, STACK_REWRITE)
          a.mov_imm(4, 0)
          a.call(HELPER_BPF_LOOP)
          # bpf_loop returns the number of iterations performed, not zero on
          # success. A full packet walk must therefore return the requested
          # count; a callback error or helper failure returns a smaller/error
          # value and is rejected here.
          a.load_mem(Assembler::BPF_W, 1, 10, STACK_SCRATCH + 4)
          a.jump(Assembler::BPF_JNE, destination: 0, source: 1, label: local_failure_label)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_REWRITE + 16)
          a.jump(Assembler::BPF_JNE, destination: 2, immediate: 0, label: local_failure_label)

          a.load_mem(Assembler::BPF_W, 4, 10, STACK_REWRITE + 12)
          a.alu_imm(Assembler::BPF_XOR, 4, 0xffff_ffff)
          a.endian(4, 32)
          a.store_mem(Assembler::BPF_W, 10, STACK_SCRATCH, source: 4)
          a.mov_reg(1, 8)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_META)
          a.alu_imm(Assembler::BPF_ADD, 2, 8)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, STACK_SCRATCH)
          a.mov_imm(4, 4)
          a.mov_imm(5, 0)
          a.call(HELPER_SKB_STORE_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: local_failure_label)
          a.ja(done_label)

          a.label(local_failure_label)
          a.ja(failure_label)
          a.label(done_label)
        end

        # Static callback for bpf_loop. It uses the SCTP CRC32c table map so
        # the callback stays bounded and verifier-friendly while still
        # covering every byte in an skb of any normal Linux packet size.
        def build_sctp_crc_callback(a)
          callback_error = :sctp_crc_callback_error
          a.label(:sctp_crc_callback)
          # bpf_loop gives index in R1 and a pointer to STACK_META in R2.
          # The first context slot is a verifier-tracked PTR_TO_CTX; the
          # remaining slots carry packet offset and CRC state across calls.
          a.mov_reg(6, 2)
          a.mov_reg(7, 1)
          a.load_mem(Assembler::BPF_DW, 1, 6, 0)
          a.load_mem(Assembler::BPF_W, 2, 6, 8)
          a.alu_reg(Assembler::BPF_ADD, 2, 7)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, CALLBACK_SCRATCH)
          a.mov_imm(4, 1)
          a.call(HELPER_SKB_LOAD_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: callback_error)

          a.load_mem(Assembler::BPF_W, 8, 6, 12)
          a.load_mem(Assembler::BPF_B, 3, 10, CALLBACK_SCRATCH)
          a.mov_reg(2, 8)
          a.alu_reg(Assembler::BPF_XOR, 2, 3)
          a.alu_imm(Assembler::BPF_AND, 2, 0xff)
          a.store_mem(Assembler::BPF_W, 10, CALLBACK_SCRATCH, source: 2)
          map_lookup(a, "sctp_crc32c", CALLBACK_SCRATCH, 0)
          a.jump(Assembler::BPF_JEQ, destination: 0, immediate: 0, label: callback_error)
          a.load_mem(Assembler::BPF_W, 3, 0, 0)
          a.alu_imm(Assembler::BPF_RSH, 8, 8)
          a.alu_reg(Assembler::BPF_XOR, 8, 3)
          a.store_mem(Assembler::BPF_W, 6, 12, source: 8)
          a.mov_imm(0, 0)
          a.emit(Assembler::BPF_JMP | Assembler::BPF_EXIT)

          a.label(callback_error)
          a.store_mem(Assembler::BPF_W, 6, 16, immediate: 1)
          a.mov_imm(0, 1)
          a.emit(Assembler::BPF_JMP | Assembler::BPF_EXIT)
        end

        # Backend selection contract: Jenkins one-at-a-time over the source
        # address bytes, seed zero, then modulo the sorted backend list. The
        # nftables hash expression and the Ruby model implement this exact
        # byte contract; destination/port changes do not silently select a
        # different backend implementation.
        def hash_packet(a)
          ipv6_label = :hash_packet_ipv6
          done_label = :hash_packet_done
          a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
          a.jump(Assembler::BPF_JEQ, destination: 3, immediate: 6, label: ipv6_label)
          jenkins_hash_bytes(a, STACK_SRC_IP + 12, 4, done_label)
          a.ja(done_label)
          a.label(ipv6_label)
          jenkins_hash_bytes(a, STACK_SRC_IP, 16, done_label)
          a.label(done_label)
        end

        JHASH_INITVAL = 0xdeadbeef
        MASK32 = 0xffff_ffff

        # Linux jhash() (lookup3) over `length` bytes at a stack offset; the
        # result (c) is left in r2.  This is the function nftables applies
        # for NFT_HASH_JENKINS, so both datapaths pick the same backend for a
        # flow.  Registers: r2 = a, r3 = b, r4 = c, r5/r0 = scratch.
        def jenkins_hash_bytes(a, base, length, _done_label)
          raise ArgumentError, "jhash length must be 4 or 16" unless [4, 16].include?(length)

          initial = (JHASH_INITVAL + length) & MASK32
          a.mov32_imm(2, initial)
          a.mov32_imm(3, initial)
          a.mov32_imm(4, initial)
          offset = 0
          if length > 12
            jhash_add_word(a, 2, base + offset)
            jhash_add_word(a, 3, base + offset + 4)
            jhash_add_word(a, 4, base + offset + 8)
            jhash_mix(a)
            offset += 12
          end
          jhash_add_word(a, 2, base + offset)
          jhash_final(a)
          a.mov_reg(2, 4)
        end

        def jhash_add_word(a, register, stack_offset)
          a.load_mem(Assembler::BPF_W, 5, 10, stack_offset)
          a.alu32_reg(Assembler::BPF_ADD, register, 5)
        end

        # r5 = rol32(source, bits) using r0 as scratch.
        def jhash_rol32(a, source, bits)
          a.mov_reg(5, source)
          a.alu32_imm(Assembler::BPF_LSH, 5, bits)
          a.mov_reg(0, source)
          a.alu32_imm(Assembler::BPF_RSH, 0, 32 - bits)
          a.alu32_reg(Assembler::BPF_OR, 5, 0)
        end

        # x -= y; x ^= rol32(y, bits); y += z
        def jhash_mix_step(a, x, y, z, bits)
          a.alu32_reg(Assembler::BPF_SUB, x, y)
          jhash_rol32(a, y, bits)
          a.alu32_reg(Assembler::BPF_XOR, x, 5)
          a.alu32_reg(Assembler::BPF_ADD, y, z)
        end

        def jhash_mix(a)
          jhash_mix_step(a, 2, 4, 3, 4)
          jhash_mix_step(a, 3, 2, 4, 6)
          jhash_mix_step(a, 4, 3, 2, 8)
          jhash_mix_step(a, 2, 4, 3, 16)
          jhash_mix_step(a, 3, 2, 4, 19)
          jhash_mix_step(a, 4, 3, 2, 4)
        end

        # x ^= y; x -= rol32(y, bits)
        def jhash_final_step(a, x, y, bits)
          a.alu32_reg(Assembler::BPF_XOR, x, y)
          jhash_rol32(a, y, bits)
          a.alu32_reg(Assembler::BPF_SUB, x, 5)
        end

        def jhash_final(a)
          jhash_final_step(a, 4, 3, 14)
          jhash_final_step(a, 2, 4, 11)
          jhash_final_step(a, 3, 2, 25)
          jhash_final_step(a, 4, 3, 16)
          jhash_final_step(a, 2, 4, 4)
          jhash_final_step(a, 3, 2, 14)
          jhash_final_step(a, 4, 3, 24)
        end

        def set_key_header(a, key_offset)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 12)
          a.store_mem(Assembler::BPF_B, 10, key_offset, source: 2)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.store_mem(Assembler::BPF_B, 10, key_offset + 1, source: 2)
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_PORTS + 2)
          a.endian(2, 16)
          a.store_mem(Assembler::BPF_H, 10, key_offset + 2, source: 2)
        end

        def set_conntrack_header(a, key_offset)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 12)
          a.store_mem(Assembler::BPF_B, 10, key_offset, source: 2)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.store_mem(Assembler::BPF_B, 10, key_offset + 1, source: 2)
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_PORTS)
          a.endian(2, 16)
          a.store_mem(Assembler::BPF_H, 10, key_offset + 2, source: 2)
          a.load_mem(Assembler::BPF_H, 2, 10, STACK_PORTS + 2)
          a.endian(2, 16)
          a.store_mem(Assembler::BPF_H, 10, key_offset + 4, source: 2)
        end

        def copy_stack_header(a, key_offset)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 12)
          a.store_mem(Assembler::BPF_B, 10, key_offset, source: 2)
          a.load_mem(Assembler::BPF_B, 2, 10, STACK_META + 13)
          a.store_mem(Assembler::BPF_B, 10, key_offset + 1, source: 2)
        end

        def set_meta(a, family:, protocol_register:)
          a.store_mem(Assembler::BPF_B, 10, STACK_META + 12, immediate: family)
          set_meta_protocol(a, protocol_register)
        end

        def set_meta_protocol(a, register)
          a.store_mem(Assembler::BPF_B, 10, STACK_META + 13, source: register)
        end

        def load_transport_ports(a, transport_register, failure_label)
          a.store_mem(Assembler::BPF_W, 10, STACK_META, source: transport_register)
          skb_load_from_register(a, transport_register, STACK_PORTS, 4, failure_label)
        end

        def check_transport_bounds(a, transport_register, failure_label)
          a.mov_reg(3, 6)
          a.alu_reg(Assembler::BPF_ADD, 3, transport_register)
          a.alu_imm(Assembler::BPF_ADD, 3, 4)
          a.jump(Assembler::BPF_JGT, destination: 3, source: 7, label: failure_label)
        end

        def check_transport_packet_bounds(a, transport_register, failure_label)
          a.load_mem(Assembler::BPF_W, 2, 10, STACK_PACKET_END)
          a.mov_reg(3, transport_register)
          a.alu_imm(Assembler::BPF_ADD, 3, 4)
          a.jump(Assembler::BPF_JGT, destination: 3, source: 2, label: failure_label)
        end

        def check_data_end(a, data_register, end_register, bytes, failure_label)
          a.mov_reg(2, data_register)
          a.alu_imm(Assembler::BPF_ADD, 2, bytes)
          a.jump(Assembler::BPF_JGT, destination: 2, source: end_register, label: failure_label)
        end

        def skb_load(a, offset, stack_offset, length, failure_label)
          a.mov_reg(1, 8)
          a.mov_imm(2, offset)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, stack_offset)
          a.mov_imm(4, length)
          a.call(HELPER_SKB_LOAD_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
        end

        def load_packet_field(a, base_register, relative_offset, stack_offset, length, failure_label)
          a.mov_reg(2, base_register)
          a.alu_imm(Assembler::BPF_ADD, 2, Integer(relative_offset))
          skb_load_from_register(a, 2, stack_offset, length, failure_label)
        end

        def skb_load_from_register(a, offset_register, stack_offset, length, failure_label)
          a.mov_reg(1, 8)
          a.mov_reg(2, offset_register)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, stack_offset)
          a.mov_imm(4, length)
          a.call(HELPER_SKB_LOAD_BYTES)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
        end

        def map_lookup(a, name, key_offset, result_register)
          a.map_load(1, name)
          a.mov_reg(2, 10)
          a.alu_imm(Assembler::BPF_ADD, 2, key_offset)
          a.call(HELPER_MAP_LOOKUP)
          a.mov_reg(result_register, 0) unless result_register == 0
        end

        def map_update(a, name, key_offset, value_offset, failure_label)
          a.map_load(1, name)
          a.mov_reg(2, 10)
          a.alu_imm(Assembler::BPF_ADD, 2, key_offset)
          a.mov_reg(3, 10)
          a.alu_imm(Assembler::BPF_ADD, 3, value_offset)
          a.mov_imm(4, 0)
          a.call(HELPER_MAP_UPDATE)
          a.jump(Assembler::BPF_JNE, destination: 0, immediate: 0, label: failure_label)
        end

        def copy_map_to_stack(a, map_register, map_offset, stack_offset, length)
          copy_memory(a, source_base: map_register, source_offset: map_offset,
                         destination_base: 10, destination_offset: stack_offset, length: length)
        end

        def copy_stack(a, source_offset, destination_offset, length)
          copy_memory(a, source_base: 10, source_offset: source_offset,
                         destination_base: 10, destination_offset: destination_offset, length: length)
        end

        def copy_memory(a, source_base:, source_offset:, destination_base:, destination_offset:, length:)
          remaining = Integer(length)
          cursor = 0
          while remaining >= 8
            break unless ((Integer(source_offset) + cursor) % 8).zero? &&
                         ((Integer(destination_offset) + cursor) % 8).zero?

            a.load_mem(Assembler::BPF_DW, 2, source_base, source_offset + cursor)
            a.store_mem(Assembler::BPF_DW, destination_base, destination_offset + cursor, source: 2)
            cursor += 8
            remaining -= 8
          end
          while remaining >= 4
            break unless ((Integer(source_offset) + cursor) % 4).zero? &&
                         ((Integer(destination_offset) + cursor) % 4).zero?

            a.load_mem(Assembler::BPF_W, 2, source_base, source_offset + cursor)
            a.store_mem(Assembler::BPF_W, destination_base, destination_offset + cursor, source: 2)
            cursor += 4
            remaining -= 4
          end
          while remaining >= 2
            break unless ((Integer(source_offset) + cursor) % 2).zero? &&
                         ((Integer(destination_offset) + cursor) % 2).zero?

            a.load_mem(Assembler::BPF_H, 2, source_base, source_offset + cursor)
            a.store_mem(Assembler::BPF_H, destination_base, destination_offset + cursor, source: 2)
            cursor += 2
            remaining -= 2
          end
          while remaining.positive?
            a.load_mem(Assembler::BPF_B, 2, source_base, source_offset + cursor)
            a.store_mem(Assembler::BPF_B, destination_base, destination_offset + cursor, source: 2)
            cursor += 1
            remaining -= 1
          end
        end

        def zero_stack(a, offset, length)
          zero_stack_range(a, offset, length)
        end

        def zero_stack_range(a, offset, length)
          remaining = Integer(length)
          cursor = 0
          while remaining >= 8
            a.store_mem(Assembler::BPF_DW, 10, offset + cursor, immediate: 0)
            cursor += 8
            remaining -= 8
          end
          if remaining >= 4
            a.store_mem(Assembler::BPF_W, 10, offset + cursor, immediate: 0)
            cursor += 4
            remaining -= 4
          end
          if remaining >= 2
            a.store_mem(Assembler::BPF_H, 10, offset + cursor, immediate: 0)
            cursor += 2
            remaining -= 2
          end
          a.store_mem(Assembler::BPF_B, 10, offset + cursor, immediate: 0) if remaining == 1
        end

        def compare_map_value_to_stack(a, map_register, map_offset, stack_offset, failure_label)
          [0, 8].each do |offset|
            a.load_mem(Assembler::BPF_DW, 2, map_register, map_offset + offset)
            a.load_mem(Assembler::BPF_DW, 3, 10, stack_offset + offset)
            a.jump(Assembler::BPF_JNE, destination: 2, source: 3, label: failure_label)
          end
        end

        def return_action(a, action)
          a.mov_imm(0, action)
          a.emit(Assembler::BPF_JMP | Assembler::BPF_EXIT)
        end
      end
    end
  end
end
