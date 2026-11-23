# frozen_string_literal: true

module Rubernetes
  module Proxy
    class EBPFProgram
      class ServiceDatapath
        module BackendHash
          private

          # Affinity handles repeated clients separately. A fresh connection
          # uses the source port so a client can move when its mapping expires.
          def hash_packet(a)
            ipv6_label = :hash_packet_ipv6
            done_label = :hash_packet_done
            a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
            a.jump(Assembler::BPF_JEQ, destination: 3, immediate: 6, label: ipv6_label)
            hash_source(a, STACK_SRC_IP + 12, 4)
            a.ja(done_label)
            a.label(ipv6_label)
            hash_source(a, STACK_SRC_IP, 16)
            a.label(done_label)
          end

          def hash_source(a, address, length)
            address_only = :"hash_address_#{length}"
            done = :"hash_source_done_#{length}"
            unless @kernel_reassembly
              a.load_mem(Assembler::BPF_B, 2, 6, WireFormat::SERVICE_AFFINITY_OFFSET)
              a.jump(Assembler::BPF_JEQ, destination: 2, immediate: 0, label: address_only)
            end
            copy_stack(a, address, STACK_REWRITE, length)
            a.store_mem(Assembler::BPF_W, 10, STACK_REWRITE + length, immediate: 0)
            a.load_mem(Assembler::BPF_H, 2, 10, STACK_PORTS)
            a.store_mem(Assembler::BPF_H, 10, STACK_REWRITE + length, source: 2)
            jenkins_hash_bytes(a, STACK_REWRITE, length + 4)
            return if @kernel_reassembly

            a.ja(done)
            a.label(address_only)
            jenkins_hash_bytes(a, address, length)
            a.label(done)
          end

          def hash_backend_slot(a)
            hash_packet(a)
            a.load_mem(Assembler::BPF_W, 3, 10, STACK_META + 20)
            a.load_mem(Assembler::BPF_B, 4, 6, WireFormat::SERVICE_AFFINITY_OFFSET)
            a.jump(Assembler::BPF_JEQ, destination: 4, immediate: 0, label: :plain_hash_slot)
            # nftables applies reciprocal_scale to the 32-bit Jenkins result.
            a.alu_reg(Assembler::BPF_MUL, 2, 3)
            a.alu_imm(Assembler::BPF_RSH, 2, 32)
            a.ja(:hash_slot_family)
            a.label(:plain_hash_slot)
            a.alu_reg(Assembler::BPF_MOD, 2, 3)
            a.label(:hash_slot_family)
            a.load_mem(Assembler::BPF_B, 3, 10, STACK_META + 12)
            a.jump(Assembler::BPF_JNE, destination: 3, immediate: 6, label: :hash_slot_ready)
            a.alu_imm(Assembler::BPF_OR, 2, WireFormat::IPV6_SLOT_BIT)
            a.label(:hash_slot_ready)
          end

          JHASH_INITVAL = 0xdeadbeef
          MASK32 = 0xffff_ffff

          # Linux jhash() (lookup3) over `length` bytes at a stack offset; the
          # result (c) is left in r2. This is the hash nftables applies for
          # NFT_HASH_JENKINS. Registers: r2 = a, r3 = b, r4 = c, r5/r0 = scratch.
          def jenkins_hash_bytes(a, base, length)
            raise ArgumentError, "unsupported jhash key length" unless [4, 8, 16, 20].include?(length)

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
            jhash_add_word(a, 3, base + offset + 4) if length - offset == 8
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
        end
      end
    end
  end
end
