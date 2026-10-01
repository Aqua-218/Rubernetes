# frozen_string_literal: true

require "fiddle"
require "digest"
require "json"
require_relative "abi_manifest"
require_relative "error"
require_relative "syscall"

module Rubernetes
  module Platform
    module Linux
      class BPF
        class VerifierError < Linux::Error
          def verifier_log
            details.fetch(:verifier_log)
          end
        end

        Instruction = Data.define(:code, :destination, :source, :offset, :immediate) do
          def to_binary
            registers = (Integer(source) << 4) | Integer(destination)
            [Integer(code), registers, Integer(offset), Integer(immediate)].pack("CCs<l<")
          end
        end
        class Program
          # helper_ids/calls are decoded from the kernel's translated stream;
          # requested_* retains the stable UAPI IDs submitted by this loader.
          attr_reader :fd, :verifier_log, :id, :type, :name, :ifindex, :tag,
                      :helper_ids, :requested_helper_ids, :translated_helper_calls, :requested_helper_calls,
                      :xlated_instructions, :verified_insns,
                      :func_info, :load_evidence, :load_evidence_sha256

          def initialize(fd:, verifier_log:, id: nil, type: nil, name: nil, ifindex: nil, tag: nil,
                         helper_ids: [], requested_helper_ids: [], translated_helper_calls: [],
                         requested_helper_calls: [], xlated_instructions: [], verified_insns: nil,
                         func_info: "", load_evidence: nil, load_evidence_sha256: nil)
            @fd = Integer(fd)
            @verifier_log = String(verifier_log).freeze
            @id = id.nil? ? nil : Integer(id)
            @type = type.nil? ? nil : Integer(type)
            @name = name&.to_s&.freeze
            @ifindex = ifindex.nil? ? nil : Integer(ifindex)
            @tag = tag&.dup&.freeze
            @helper_ids = Array(helper_ids).map { |helper| Integer(helper) }.uniq.sort.freeze
            @requested_helper_ids = Array(requested_helper_ids).map { |helper| Integer(helper) }.uniq.sort.freeze
            @translated_helper_calls = Array(translated_helper_calls).map { |helper| Integer(helper) }.freeze
            @requested_helper_calls = Array(requested_helper_calls).map { |helper| Integer(helper) }.freeze
            @xlated_instructions = Array(xlated_instructions).freeze
            @verified_insns = verified_insns.nil? ? nil : Integer(verified_insns)
            @func_info = String(func_info).b.freeze
            @load_evidence = load_evidence.nil? ? nil : immutable_value(load_evidence)
            @load_evidence_sha256 = load_evidence_sha256&.to_s&.freeze
            freeze
          end

          def close
            IO.for_fd(fd).close
          end

          def to_h
            {fd: fd, verifier_log: verifier_log, id: id, type: type, name: name, ifindex: ifindex, tag: tag,
             helper_ids: helper_ids, requested_helper_ids: requested_helper_ids,
             translated_helper_calls: translated_helper_calls, requested_helper_calls: requested_helper_calls,
             xlated_program_sha256: xlated_program_sha256,
             verified_insns: verified_insns, func_info_sha256: Digest::SHA256.hexdigest(func_info),
             load_evidence: load_evidence, load_evidence_sha256: load_evidence_sha256}
          end

          def verifier_log_sha256
            Digest::SHA256.hexdigest(verifier_log)
          end

          def xlated_program_sha256
            Digest::SHA256.hexdigest(xlated_instructions.map(&:to_binary).join)
          end

          alias verifier_evidence load_evidence

          alias load_evidence_digest load_evidence_sha256

          private

          def immutable_value(value)
            case value
            when Hash
              value.each_with_object({}) do |(key, child), result|
                result[key.to_s.freeze] = immutable_value(child)
              end.freeze
            when Array
              value.map { |child| immutable_value(child) }.freeze
            when String
              value.dup.freeze
            else
              value
            end
          end

          public

          def ==(other)
            other.is_a?(self.class) && to_h == other.to_h
          end

          alias eql? ==

          def hash
            to_h.hash
          end

          def with(**changes)
            self.class.new(
              fd: fd, verifier_log: verifier_log, id: id, type: type, name: name, ifindex: ifindex, tag: tag,
              helper_ids: helper_ids, requested_helper_ids: requested_helper_ids,
              translated_helper_calls: translated_helper_calls, requested_helper_calls: requested_helper_calls,
              xlated_instructions: xlated_instructions, verified_insns: verified_insns,
              func_info: func_info, load_evidence: load_evidence, load_evidence_sha256: load_evidence_sha256,
              **changes
            )
          end
        end

        class Map
          attr_reader :fd, :id, :type, :key_size, :value_size, :max_entries, :flags, :name, :ifindex

          def initialize(fd:, id:, type:, key_size:, value_size:, max_entries:, flags:, name:, ifindex: 0)
            @fd = Integer(fd)
            @id = Integer(id)
            @type = Integer(type)
            @key_size = Integer(key_size)
            @value_size = Integer(value_size)
            @max_entries = Integer(max_entries)
            @flags = Integer(flags)
            @name = String(name).freeze
            @ifindex = Integer(ifindex)
            freeze
          end

          def close
            IO.for_fd(fd).close
          end

          def to_h
            {fd: fd, id: id, type: type, key_size: key_size, value_size: value_size,
             max_entries: max_entries, flags: flags, name: name, ifindex: ifindex}
          end

          def ==(other)
            other.is_a?(self.class) && to_h == other.to_h
          end

          alias eql? ==

          def hash
            to_h.hash
          end
        end

        BPF_MAP_CREATE = 0
        BPF_MAP_LOOKUP_ELEM = 1
        BPF_MAP_UPDATE_ELEM = 2
        BPF_MAP_DELETE_ELEM = 3
        BPF_PROG_LOAD = 5
        BPF_PROG_ATTACH = 8
        BPF_PROG_DETACH = 9
        BPF_PROG_GET_FD_BY_ID = 13
        BPF_BTF_LOAD = 18
        BPF_OBJ_GET_INFO_BY_FD = 15
        BPF_PROG_QUERY = 16
        BPF_PROG_TYPE_UNSPEC = 0
        BPF_PROG_TYPE_SOCKET_FILTER = 1
        BPF_PROG_TYPE_SCHED_CLS = 3
        BPF_PROG_TYPE_SCHED_ACT = 4
        BPF_PROG_TYPE_CGROUP_DEVICE = 15
        # enum bpf_attach_type
        BPF_CGROUP_DEVICE = 6
        BPF_F_ALLOW_OVERRIDE = 1
        BPF_F_ALLOW_MULTI = 2
        BPF_F_REPLACE = 4
        BPF_MAP_TYPE_HASH = 1
        BPF_MAP_TYPE_ARRAY = 2
        BPF_MAP_TYPE_LRU_HASH = 9
        BPF_MAP_TYPE_LPM_TRIE = 11
        BPF_ANY = 0
        BPF_NOEXIST = 1
        BPF_EXIST = 2
        BPF_OBJ_NAME_LEN = 16
        BPF_F_NO_PREALLOC = 1
        BPF_ALU64 = 0x07
        BPF_MOV = 0xb0
        BPF_K = 0x00
        BPF_JMP = 0x05
        BPF_EXIT = 0x90
        BPF_LD = 0x00
        BPF_DW = 0x18
        BPF_IMM = 0x00
        BPF_PSEUDO_FUNC = 4
        MAX_LOG_SIZE = 1_048_576
        MAX_INSTRUCTIONS = 1_000_000
        MAX_XLATED_PROGRAM_BYTES = MAX_INSTRUCTIONS * 8
        MAX_FUNC_INFO_BYTES = MAX_INSTRUCTIONS * 16
        BPF_PROG_INFO_SIZE = 256
        BPF_PROG_INFO_XLATED_PROG_LEN = 20
        BPF_PROG_INFO_XLATED_PROG_INSNS = 32
        BPF_PROG_INFO_FUNC_INFO_REC_SIZE = 132
        BPF_PROG_INFO_FUNC_INFO = 136
        BPF_PROG_INFO_NR_FUNC_INFO = 144

        def initialize(manifest: ABIManifest.load, syscall: Syscall)
          @manifest = manifest
          @syscall = syscall
        end

        def load(instructions:, program_type: BPF_PROG_TYPE_SOCKET_FILTER, license: "GPL", log_size: 65_536,
                 resource_id: "bpf:program", expected_attach_type: 0, ifindex: 0, name: nil, map_fds: [],
                 function_relocations: {})
          raise ArgumentError, "instructions must not be empty" if instructions.empty?
          raise ArgumentError, "too many BPF instructions" if instructions.length > MAX_INSTRUCTIONS
          raise ArgumentError, "log_size must be between 1 and #{MAX_LOG_SIZE}" unless log_size.positive? && log_size <= MAX_LOG_SIZE

          relocated_instructions = relocate_function_references(instructions, function_relocations)
          requested_helper_ids = helper_ids_from_instructions(relocated_instructions)
          requested_helper_calls = helper_call_values(relocated_instructions)
          function_targets = pseudo_function_targets(relocated_instructions)
          btf_fd = nil
          nil
          func_info_blob = nil
          if function_targets.any?
            btf_blob = build_function_btf
            btf_fd = load_btf(btf_blob, resource_id: resource_id)
            func_info_blob = function_info_blob(function_targets)
          end
          instruction_bytes = relocated_instructions.map(&:to_binary).join
          instruction_pointer = Fiddle::Pointer[instruction_bytes]
          license_string = "#{license}\0"
          license_pointer = Fiddle::Pointer[license_string]
          log_pointer = Fiddle::Pointer.malloc(log_size, Fiddle::RUBY_FREE)
          log_pointer[0, log_size] = "\0" * log_size
          attribute_size = @manifest.structure("bpf_attr").fetch("size")
          attributes = "\0" * attribute_size
          attributes[0, 4] = [Integer(program_type)].pack("L")
          attributes[4, 4] = [relocated_instructions.length].pack("L")
          attributes[8, 8] = [instruction_pointer.to_i].pack("Q")
          attributes[16, 8] = [license_pointer.to_i].pack("Q")
          attributes[24, 4] = [1].pack("L<")
          attributes[28, 4] = [log_size].pack("L")
          attributes[32, 8] = [log_pointer.to_i].pack("Q")
          attributes[40, 4] = [0].pack("L<")
          attributes[44, 4] = [0].pack("L<")
          attributes[48, BPF_OBJ_NAME_LEN] = encode_name(name || "rubernetes_bpf")
          attributes[64, 4] = [Integer(ifindex)].pack("L<")
          attributes[68, 4] = [Integer(expected_attach_type)].pack("L<")
          if btf_fd
            # bpf_func_info records use instruction indices in the kernel
            # load ABI. The BTF object supplies the type IDs for the entry
            # function and each static callback.
            func_info_pointer = Fiddle::Pointer[func_info_blob]
            attributes[72, 4] = [Integer(btf_fd)].pack("L<")
            attributes[76, 4] = [8].pack("L<")
            attributes[80, 8] = [func_info_pointer.to_i].pack("Q")
            attributes[88, 4] = [func_info_blob.bytesize / 8].pack("L<")
          end
          if Array(map_fds).any?
            fd_array = Array(map_fds).map { |fd| Integer(fd) }.pack("L<*")
            fd_array_pointer = Fiddle::Pointer[fd_array]
            attributes[120, 8] = [fd_array_pointer.to_i].pack("Q")
          end
          attribute_pointer = Fiddle::Pointer[attributes]

          result = syscall_call(BPF_PROG_LOAD, attribute_pointer, attribute_size)
          verifier_log = log_pointer.to_s(log_size).split("\0", 2).first.freeze
          if result.value == -1
            raise VerifierError.new(
              errno: result.errno,
              operation: "bpf(BPF_PROG_LOAD)",
              resource_id: resource_id,
              details: {verifier_log: verifier_log}
            )
          end

          fd = Integer(result.value)
          begin
            info = program_info(fd, resource_id: resource_id)
            load_evidence = build_load_evidence(instruction_bytes, verifier_log, info,
                                                instruction_count: relocated_instructions.length,
                                                requested_helper_ids: requested_helper_ids,
                                                requested_helper_calls: requested_helper_calls)
            Program.new(fd: fd, verifier_log: verifier_log, id: info.fetch(:id), type: info.fetch(:type),
                        name: info.fetch(:name), ifindex: info.fetch(:ifindex), tag: info.fetch(:tag),
                        helper_ids: info.fetch(:helper_ids), requested_helper_ids: requested_helper_ids,
                        translated_helper_calls: info.fetch(:helper_calls), requested_helper_calls: requested_helper_calls,
                        xlated_instructions: info.fetch(:xlated_instructions),
                        verified_insns: info[:verified_insns], func_info: info.fetch(:func_info_bytes),
                        load_evidence: load_evidence.fetch(:document),
                        load_evidence_sha256: load_evidence.fetch(:sha256))
          rescue StandardError
            IO.for_fd(fd).close
            raise
          end
        ensure
          IO.for_fd(btf_fd).close if btf_fd && btf_fd >= 0
        end

        # Create a map directly through bpf(2). The returned descriptor remains
        # owned by the caller and must stay open while a loaded program uses it.
        def map_create(type:, key_size:, value_size:, max_entries:, map_flags: 0, name: nil, ifindex: 0,
                       resource_id: "bpf:map")
          normalized_name = normalize_name(name || "rubernetes_map")
          attributes = zeroed_attributes
          attributes[0, 4] = [Integer(type)].pack("L<")
          attributes[4, 4] = [Integer(key_size)].pack("L<")
          attributes[8, 4] = [Integer(value_size)].pack("L<")
          attributes[12, 4] = [Integer(max_entries)].pack("L<")
          attributes[16, 4] = [Integer(map_flags)].pack("L<")
          attributes[28, BPF_OBJ_NAME_LEN] = encode_name(normalized_name)
          attributes[44, 4] = [Integer(ifindex)].pack("L<")
          fd = syscall_result!(BPF_MAP_CREATE, Fiddle::Pointer[attributes], attributes.bytesize,
                               operation: "bpf(BPF_MAP_CREATE)", resource_id: resource_id)
          begin
            info = map_info(fd, resource_id: resource_id)
            expected = {type: Integer(type), key_size: Integer(key_size), value_size: Integer(value_size),
                        max_entries: Integer(max_entries), flags: Integer(map_flags), name: normalized_name,
                        ifindex: Integer(ifindex)}
            unless expected.all? { |key, value| info.fetch(key) == value }
              raise Linux::Error.new(
                errno: Errno::EPROTO::Errno,
                operation: "bpf(BPF_MAP_CREATE)",
                resource_id: resource_id,
                details: {expected: expected, actual: info}
              )
            end
            Map.new(fd: fd, id: info.fetch(:id), type: info.fetch(:type), key_size: info.fetch(:key_size),
                    value_size: info.fetch(:value_size), max_entries: info.fetch(:max_entries),
                    flags: info.fetch(:flags), name: info.fetch(:name), ifindex: info.fetch(:ifindex))
          rescue StandardError
            IO.for_fd(fd).close
            raise
          end
        end

        def map_update(map:, key:, value:, flags: BPF_ANY, resource_id: "bpf:map:update")
          map_fd, key_size, value_size = map_details(map)
          key_bytes = exact_bytes(key, key_size, "map key")
          value_bytes = exact_bytes(value, value_size, "map value")
          key_pointer = Fiddle::Pointer[key_bytes]
          value_pointer = Fiddle::Pointer[value_bytes]
          attributes = zeroed_attributes
          attributes[0, 4] = [map_fd].pack("L<")
          attributes[8, 8] = [key_pointer.to_i].pack("Q")
          attributes[16, 8] = [value_pointer.to_i].pack("Q")
          attributes[24, 8] = [Integer(flags)].pack("Q")
          syscall_result!(BPF_MAP_UPDATE_ELEM, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_MAP_UPDATE_ELEM)", resource_id: resource_id)
          true
        end

        def map_lookup(map:, key:, resource_id: "bpf:map:lookup")
          map_fd, key_size, value_size = map_details(map)
          key_bytes = exact_bytes(key, key_size, "map key")
          key_pointer = Fiddle::Pointer[key_bytes]
          value_pointer = Fiddle::Pointer.malloc(value_size, Fiddle::RUBY_FREE)
          value_pointer[0, value_size] = "\0" * value_size
          attributes = zeroed_attributes
          attributes[0, 4] = [map_fd].pack("L<")
          attributes[8, 8] = [key_pointer.to_i].pack("Q")
          attributes[16, 8] = [value_pointer.to_i].pack("Q")
          syscall_result!(BPF_MAP_LOOKUP_ELEM, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_MAP_LOOKUP_ELEM)", resource_id: resource_id)
          value_pointer.to_s(value_size).b
        end

        def map_delete(map:, key:, resource_id: "bpf:map:delete")
          map_fd, key_size, = map_details(map)
          key_bytes = exact_bytes(key, key_size, "map key")
          key_pointer = Fiddle::Pointer[key_bytes]
          attributes = zeroed_attributes
          attributes[0, 4] = [map_fd].pack("L<")
          attributes[8, 8] = [key_pointer.to_i].pack("Q")
          syscall_result!(BPF_MAP_DELETE_ELEM, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_MAP_DELETE_ELEM)", resource_id: resource_id)
          true
        end

        def map_info(map, resource_id: "bpf:map:info")
          info = object_info(map_fd(map), resource_id: resource_id)
          parse_map_info(info)
        end

        def program_info(program, resource_id: "bpf:program:info")
          fd = program_fd(program)
          initial = parse_program_info(object_info(fd, resource_id: resource_id))
          xlated_length = bounded_info_length(initial.fetch(:xlated_prog_len), MAX_XLATED_PROGRAM_BYTES,
                                              "translated BPF program", resource_id: resource_id)
          func_info_length = bounded_info_length(
            initial.fetch(:func_info_rec_size) * initial.fetch(:nr_func_info), MAX_FUNC_INFO_BYTES, "BPF function info",
            resource_id: resource_id
          )
          if xlated_length.zero? && func_info_length.zero?
            return initial.merge(xlated_prog_bytes: "".b.freeze, func_info_bytes: "".b.freeze,
                                 xlated_instructions: [].freeze, helper_ids: [].freeze, helper_calls: [].freeze).freeze
          end

          xlated_bytes = "\0".b * xlated_length
          func_info_bytes = "\0".b * func_info_length
          xlated_pointer = xlated_length.zero? ? nil : Fiddle::Pointer[xlated_bytes]
          func_info_pointer = func_info_length.zero? ? nil : Fiddle::Pointer[func_info_bytes]
          refreshed = parse_program_info(object_info(fd, resource_id: resource_id) do |buffer|
            if xlated_pointer
              buffer[BPF_PROG_INFO_XLATED_PROG_INSNS, 8] = [xlated_pointer.to_i].pack("Q")
              buffer[BPF_PROG_INFO_XLATED_PROG_LEN, 4] = [xlated_length].pack("L<")
            end
            if func_info_pointer
              buffer[BPF_PROG_INFO_FUNC_INFO, 8] = [func_info_pointer.to_i].pack("Q")
              buffer[BPF_PROG_INFO_FUNC_INFO_REC_SIZE, 4] = [initial.fetch(:func_info_rec_size)].pack("L<")
              buffer[BPF_PROG_INFO_NR_FUNC_INFO, 4] = [initial.fetch(:nr_func_info)].pack("L<")
            end
          end)
          actual_xlated_length = bounded_info_length(refreshed.fetch(:xlated_prog_len), MAX_XLATED_PROGRAM_BYTES,
                                                     "translated BPF program", resource_id: resource_id)
          actual_func_info_length = bounded_info_length(
            refreshed.fetch(:func_info_rec_size) * refreshed.fetch(:nr_func_info), MAX_FUNC_INFO_BYTES, "BPF function info",
            resource_id: resource_id
          )
          if actual_xlated_length > xlated_bytes.bytesize || actual_func_info_length > func_info_bytes.bytesize
            raise Linux::Error.new(errno: Errno::EOVERFLOW::Errno, operation: "bpf(BPF_OBJ_GET_INFO_BY_FD)",
                                   resource_id: resource_id,
                                   details: {translated_program_bytes: actual_xlated_length,
                                             function_info_bytes: actual_func_info_length})
          end
          xlated_bytes = xlated_bytes.byteslice(0, actual_xlated_length).to_s.b.freeze
          func_info_bytes = func_info_bytes.byteslice(0, actual_func_info_length).to_s.b.freeze
          instructions = parse_instruction_stream(xlated_bytes, resource_id: resource_id)
          refreshed.merge(xlated_prog_bytes: xlated_bytes, func_info_bytes: func_info_bytes,
                          xlated_instructions: instructions,
                          helper_ids: helper_ids_from_instructions(instructions),
                          helper_calls: helper_call_values(instructions)).freeze
        end

        def probe(resource_id: "bpf:m0-probe")
          load(
            instructions: [
              Instruction.new(code: BPF_ALU64 | BPF_MOV | BPF_K, destination: 0, source: 0, offset: 0, immediate: 0),
              Instruction.new(code: BPF_JMP | BPF_EXIT, destination: 0, source: 0, offset: 0, immediate: 0)
            ],
            resource_id: resource_id
          )
        end

        # Probe helper availability by asking the kernel to load the caller's
        # verifier-safe program and then checking the translated instruction
        # readback. A kernel release string is not evidence that a helper was
        # accepted for this program type and privilege context.
        def helper_capability_probe(instructions:, helper_id:, program_type: BPF_PROG_TYPE_SOCKET_FILTER,
                                    resource_id: "bpf:helper-probe", **)
          program = load(instructions: instructions, program_type: program_type, resource_id: resource_id, **)
          observed = if program.respond_to?(:translated_helper_calls)
                       Array(program.translated_helper_calls)
                     else
                       Array(program.helper_ids)
                     end
          requested = if program.respond_to?(:requested_helper_calls)
                        Array(program.requested_helper_calls)
                      elsif program.respond_to?(:requested_helper_ids)
                        Array(program.requested_helper_ids)
                      else
                        []
                      end
          return true if requested.include?(Integer(helper_id)) && observed.length == requested.length && !observed.empty?

          raise Linux::Error.new(errno: Errno::EPROTO::Errno, operation: "bpf(BPF_PROG_LOAD)",
                                 resource_id: resource_id,
                                 details: {required_helper_id: Integer(helper_id), requested_helper_ids: requested,
                                           translated_helper_ids: observed})
        ensure
          program&.close
        end

        private

        def pseudo_function_targets(instructions)
          Array(instructions).each_with_index.filter_map do |instruction, index|
            next unless instruction.code == (BPF_LD | BPF_DW | BPF_IMM) && instruction.source == BPF_PSEUDO_FUNC

            (index + 1 + Integer(instruction.immediate))
          end.uniq.sort.freeze
        end

        # Build the smallest valid BTF graph needed by BPF_PSEUDO_FUNC:
        # int(void *) for the entry function and long(__u32, void *) for the
        # bpf_loop callback. The verifier uses the latter to validate the
        # callback ABI; no source/debug metadata is required.
        def build_function_btf
          strings = "\0ctx\0int\0__u32\0unsigned int\0long\0index\0rubernetes_program\0rubernetes_sctp_crc_callback\0".b
          offsets = {}
          cursor = 0
          strings.split("\0", -1).each do |value|
            offsets[value] = cursor unless offsets.key?(value)
            cursor += value.bytesize + 1
          end
          kind_info = lambda { |kind, vlen = 0, kind_flag = false|
            (Integer(kind) << 24) | (kind_flag ? (1 << 31) : 0) | Integer(vlen)
          }
          types = []
          # Match clang/libbpf's compact ordering: PTR id 1, entry proto 2,
          # int id 3, entry FUNC id 4, __u32 typedef id 5, unsigned int id 6,
          # callback proto id 7, long id 8, callback FUNC id 9.
          types << [0, kind_info.call(2), 0].pack("L<*")
          types << [0, kind_info.call(13, 1), 3,
                    offsets.fetch("ctx"), 1].pack("L<*")
          types << [offsets.fetch("int"), kind_info.call(1), 4, (1 << 24) | 32].pack("L<*")
          types << [offsets.fetch("rubernetes_program"), kind_info.call(12, 1), 2].pack("L<*")
          types << [offsets.fetch("__u32"), kind_info.call(8), 6].pack("L<*")
          types << [offsets.fetch("unsigned int"), kind_info.call(1), 4, 32].pack("L<*")
          types << [0, kind_info.call(13, 2), 8,
                    offsets.fetch("index"), 5, offsets.fetch("ctx"), 1].pack("L<*")
          types << [offsets.fetch("long"), kind_info.call(1), 8, (1 << 24) | 64].pack("L<*")
          types << [offsets.fetch("rubernetes_sctp_crc_callback"), kind_info.call(12), 7].pack("L<*")
          type_blob = types.join.b
          header = [0xeb9f, 1, 0, 24, 0, type_blob.bytesize, type_blob.bytesize, strings.bytesize].pack("S<CCL<4L<")
          (header + type_blob + strings).b.freeze
        end

        def function_info_blob(targets)
          # The kernel's BPF_PROG_LOAD func_info ABI uses instruction indices
          # for these records (despite the byte-offset wording on older UAPI
          # comments). The entry program starts at zero; every pseudo function
          # target is the static callback and shares callback type 9.
          records = [[0, 4]] + Array(targets).map { |target| [Integer(target), 9] }
          records.uniq.sort_by(&:first).map { |offset, type_id| [offset, type_id].pack("L<2") }.join.b.freeze
        end

        def load_btf(blob, resource_id: "bpf:btf")
          btf_pointer = Fiddle::Pointer[blob]
          attributes = zeroed_attributes
          attributes[0, 8] = [btf_pointer.to_i].pack("Q")
          attributes[16, 4] = [blob.bytesize].pack("L<")
          result = syscall_call(BPF_BTF_LOAD, Fiddle::Pointer[attributes], attributes.bytesize)
          return Integer(result.value) unless result.value == -1

          raise VerifierError.new(errno: result.errno, operation: "bpf(BPF_BTF_LOAD)", resource_id: resource_id,
                                  details: {verifier_log: "BTF metadata load failed"})
        end

        # Validate and, when requested, resolve the ldimm64 function-pointer
        # relocations used by helpers such as bpf_loop. The kernel performs
        # the final BPF_PSEUDO_FUNC rewrite during BPF_PROG_LOAD; the loader's
        # responsibility is to bind symbolic instruction offsets to a real,
        # in-range static subprogram and reject malformed pairs early.
        def relocate_function_references(instructions, relocations)
          resolved = Array(instructions).dup
          Array(relocations).each do |entry|
            index, target = if entry.is_a?(Array)
                              [entry.fetch(0), entry.fetch(1)]
                            else
                              [entry[0], entry[1]]
                            end
            index = Integer(index)
            target = Integer(target)
            instruction = resolved.fetch(index)
            unless instruction.code == (BPF_LD | BPF_DW | BPF_IMM) && instruction.source == BPF_PSEUDO_FUNC
              raise ArgumentError, "BPF function relocation #{index} does not reference a BPF_PSEUDO_FUNC ldimm64"
            end

            resolved[index] = instruction.with(immediate: target - index - 1)
          end

          resolved.each_with_index do |instruction, index|
            next unless instruction.code == (BPF_LD | BPF_DW | BPF_IMM) && instruction.source == BPF_PSEUDO_FUNC

            raise ArgumentError, "BPF_PSEUDO_FUNC relocation is missing its ldimm64 high word" unless resolved[index + 1]&.code == 0

            target = index + 1 + Integer(instruction.immediate)
            raise ArgumentError, "BPF_PSEUDO_FUNC target #{target} is outside the program" unless target.between?(0, resolved.length - 1)
          end
          resolved.freeze
        rescue IndexError, TypeError, ArgumentError => error
          raise ArgumentError, "invalid BPF_PSEUDO_FUNC relocation: #{error.message}"
        end

        public

        # BPF_PROG_ATTACH: attach `program` to `target_fd` (a cgroup directory
        # for the cgroup attach types).  `replace` names the program an
        # attach with BPF_F_REPLACE swaps out atomically.
        def prog_attach(target_fd:, program:, attach_type:, flags: 0, replace: nil,
                        resource_id: "bpf:program:attach")
          attributes = zeroed_attributes
          attributes[0, 4] = [Integer(target_fd)].pack("L<")
          attributes[4, 4] = [program_fd(program)].pack("L<")
          attributes[8, 4] = [Integer(attach_type)].pack("L<")
          attributes[12, 4] = [Integer(flags)].pack("L<")
          attributes[16, 4] = [program_fd(replace)].pack("L<") if replace
          syscall_result!(BPF_PROG_ATTACH, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_PROG_ATTACH)", resource_id: resource_id)
          true
        end

        def prog_detach(target_fd:, program:, attach_type:, resource_id: "bpf:program:detach")
          attributes = zeroed_attributes
          attributes[0, 4] = [Integer(target_fd)].pack("L<")
          attributes[4, 4] = [program_fd(program)].pack("L<")
          attributes[8, 4] = [Integer(attach_type)].pack("L<")
          syscall_result!(BPF_PROG_DETACH, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_PROG_DETACH)", resource_id: resource_id)
          true
        end

        # BPF_PROG_QUERY: ids of the programs attached to `target_fd` for
        # `attach_type`, in attach order.  The kernel reports ENOSPC with the
        # real count when the buffer is too small; retry with that size.
        def prog_query(target_fd:, attach_type:, resource_id: "bpf:program:query")
          capacity = 64
          10.times do
            ids = Fiddle::Pointer.malloc(capacity * 4, Fiddle::RUBY_FREE)
            ids[0, capacity * 4] = "\0" * (capacity * 4)
            attributes = zeroed_attributes
            attributes[0, 4] = [Integer(target_fd)].pack("L<")
            attributes[4, 4] = [Integer(attach_type)].pack("L<")
            attributes[16, 8] = [ids.to_i].pack("Q<")
            attributes[24, 4] = [capacity].pack("L<")
            pointer = Fiddle::Pointer[attributes]
            result = syscall_call(BPF_PROG_QUERY, pointer, attributes.bytesize)
            count = pointer[24, 4].unpack1("L<")
            if result.value == -1
              if result.errno == Errno::ENOSPC::Errno && count > capacity
                capacity = count
                next
              end
              raise Linux::Error.new(errno: result.errno, operation: "bpf(BPF_PROG_QUERY)", resource_id: resource_id)
            end
            return ids[0, count * 4].unpack("L<*").freeze
          end
          raise Linux::Error.new(errno: Errno::ENOSPC::Errno, operation: "bpf(BPF_PROG_QUERY)", resource_id: resource_id)
        end

        # BPF_PROG_GET_FD_BY_ID: a new descriptor for an already-loaded
        # program.  The caller owns (and must close) it.
        def prog_get_fd_by_id(id, resource_id: "bpf:program:get_fd_by_id")
          attributes = zeroed_attributes
          attributes[0, 4] = [Integer(id)].pack("L<")
          syscall_result!(BPF_PROG_GET_FD_BY_ID, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_PROG_GET_FD_BY_ID)", resource_id: resource_id)
        end

        # A load evidence digest is intentionally calculated over canonical
        # kernel readback fields.  Hashing only the requested instruction
        # stream would let a caller claim that a different translated program
        # or verifier result was accepted by the kernel.
        def self.evidence_digest(document)
          Digest::SHA256.hexdigest(JSON.generate(canonicalize_evidence(document)))
        end

        private

        def syscall_call(command, pointer, size)
          @syscall.call(@manifest.syscall("bpf"), command, pointer, size)
        end

        def syscall_result!(command, pointer, size, operation:, resource_id:)
          result = syscall_call(command, pointer, size)
          return Integer(result.value) unless result.value == -1

          raise Linux::Error.new(errno: result.errno, operation: operation, resource_id: resource_id)
        end

        # A load evidence digest is intentionally calculated over canonical
        # kernel readback fields.  Hashing only the requested instruction
        # stream would let a caller claim that a different translated program
        # or verifier result was accepted by the kernel.
        def self.evidence_digest(document)
          Digest::SHA256.hexdigest(JSON.generate(canonicalize_evidence(document)))
        end

        def self.canonicalize_evidence(value)
          case value
          when Hash
            value.each_with_object({}) do |(key, child), result|
              result[key.to_s] = canonicalize_evidence(child)
            end.sort.to_h
          when Array
            value.map { |child| canonicalize_evidence(child) }
          else
            value
          end
        end

        private_class_method :canonicalize_evidence

        def build_load_evidence(instruction_bytes, verifier_log, info, instruction_count:, requested_helper_ids:,
                                requested_helper_calls:)
          document = {
            "schema" => 1,
            "instruction_count" => Integer(instruction_count),
            "instruction_sha256" => Digest::SHA256.hexdigest(String(instruction_bytes).b),
            "verifier_log_sha256" => Digest::SHA256.hexdigest(String(verifier_log).b),
            "xlated_instruction_count" => info.fetch(:xlated_prog_bytes).bytesize / 8,
            "xlated_instruction_sha256" => Digest::SHA256.hexdigest(info.fetch(:xlated_prog_bytes)),
            "helper_ids" => info.fetch(:helper_ids),
            "requested_helper_ids" => Array(requested_helper_ids).map(&:to_i).uniq.sort,
            "translated_helper_calls" => info.fetch(:helper_calls),
            "requested_helper_calls" => Array(requested_helper_calls).map(&:to_i),
            "verified_insns" => info.fetch(:verified_insns),
            "func_info_rec_size" => info.fetch(:func_info_rec_size),
            "func_info_count" => info.fetch(:nr_func_info),
            "func_info_sha256" => Digest::SHA256.hexdigest(info.fetch(:func_info_bytes)),
            "program_id" => info.fetch(:id),
            "program_tag" => info.fetch(:tag)
          }.freeze
          {document: document, sha256: self.class.evidence_digest(document)}.freeze
        end

        def bounded_info_length(value, maximum, label, resource_id: "bpf:program:info")
          length = Integer(value)
          if length.negative? || length > maximum
            raise Linux::Error.new(errno: Errno::EPROTO::Errno, operation: "bpf(BPF_OBJ_GET_INFO_BY_FD)",
                                   resource_id: resource_id,
                                   details: {label => length, maximum: maximum})
          end

          length
        end

        def parse_instruction_stream(bytes, resource_id: "bpf:program:info")
          buffer = String(bytes).b
          unless (buffer.bytesize % 8).zero?
            raise Linux::Error.new(errno: Errno::EPROTO::Errno, operation: "bpf(BPF_OBJ_GET_INFO_BY_FD)",
                                   resource_id: resource_id,
                                   details: {translated_program_bytes: buffer.bytesize})
          end

          Array.new(buffer.bytesize / 8) do |index|
            code, registers, offset, immediate = buffer.byteslice(index * 8, 8).unpack("CCs<l<")
            Instruction.new(code: code, destination: registers & 0x0f, source: (registers >> 4) & 0x0f,
                            offset: offset, immediate: immediate)
          end.freeze
        end

        def helper_ids_from_instructions(instructions)
          # The requested stream uses stable UAPI helper IDs. The translated
          # stream may contain a kernel helper address or BTF ID instead; both
          # are preserved as returned rather than rewritten into a fabricated
          # stable ID.
          Array(instructions).filter_map do |instruction|
            next unless instruction.code == (BPF_JMP | 0x80) && instruction.source.zero?

            Integer(instruction.immediate)
          end.uniq.sort.freeze
        end

        def helper_call_values(instructions)
          Array(instructions).filter_map do |instruction|
            next unless instruction.code == (BPF_JMP | 0x80) && instruction.source.zero?

            Integer(instruction.immediate)
          end.freeze
        end

        def zeroed_attributes
          "\0" * @manifest.structure("bpf_attr").fetch("size")
        end

        def normalize_name(value)
          name = String(value)
          raise ArgumentError, "BPF object name must not be empty" if name.empty?
          raise ArgumentError, "BPF object name exceeds #{BPF_OBJ_NAME_LEN - 1} bytes" if name.bytesize >= BPF_OBJ_NAME_LEN

          name
        end

        def encode_name(value)
          normalized = normalize_name(value)
          normalized.b.ljust(BPF_OBJ_NAME_LEN, "\0")
        end

        def exact_bytes(value, expected_size, label)
          bytes = String(value).b
          raise ArgumentError, "#{label} must be exactly #{expected_size} bytes" unless bytes.bytesize == expected_size

          bytes
        end

        def map_details(map)
          unless map.respond_to?(:fd) && map.respond_to?(:key_size) && map.respond_to?(:value_size)
            raise ArgumentError, "map must expose fd, key_size, and value_size"
          end

          [Integer(map.fd), Integer(map.key_size), Integer(map.value_size)]
        end

        def map_fd(map)
          return Integer(map.fd) if map.respond_to?(:fd)

          Integer(map)
        end

        def program_fd(program)
          return Integer(program.fd) if program.respond_to?(:fd)

          Integer(program)
        end

        def object_info(fd, resource_id:, info_size: BPF_PROG_INFO_SIZE, &configure)
          info_pointer = Fiddle::Pointer.malloc(info_size, Fiddle::RUBY_FREE)
          info_pointer[0, info_size] = "\0" * info_size
          configure&.call(info_pointer)
          attributes = zeroed_attributes
          attributes[0, 4] = [Integer(fd)].pack("L<")
          attributes[4, 4] = [info_size].pack("L<")
          attributes[8, 8] = [info_pointer.to_i].pack("Q")
          syscall_result!(BPF_OBJ_GET_INFO_BY_FD, Fiddle::Pointer[attributes], attributes.bytesize,
                          operation: "bpf(BPF_OBJ_GET_INFO_BY_FD)", resource_id: resource_id)
          info_pointer.to_s(info_size).b
        end

        def parse_map_info(bytes)
          {
            type: bytes.byteslice(0, 4).unpack1("L<"), id: bytes.byteslice(4, 4).unpack1("L<"),
            key_size: bytes.byteslice(8, 4).unpack1("L<"), value_size: bytes.byteslice(12, 4).unpack1("L<"),
            max_entries: bytes.byteslice(16, 4).unpack1("L<"), flags: bytes.byteslice(20, 4).unpack1("L<"),
            name: bytes.byteslice(24, BPF_OBJ_NAME_LEN).to_s.split("\0", 2).first,
            ifindex: bytes.byteslice(40, 4).unpack1("L<")
          }.freeze
        end

        def parse_program_info(bytes)
          {
            type: bytes.byteslice(0, 4).unpack1("L<"), id: bytes.byteslice(4, 4).unpack1("L<"),
            tag: bytes.byteslice(8, 8).unpack1("H*"),
            xlated_prog_len: bytes.byteslice(BPF_PROG_INFO_XLATED_PROG_LEN, 4).unpack1("L<"),
            name: bytes.byteslice(64, BPF_OBJ_NAME_LEN).to_s.split("\0", 2).first,
            ifindex: bytes.byteslice(80, 4).unpack1("L<"),
            func_info_rec_size: bytes.byteslice(BPF_PROG_INFO_FUNC_INFO_REC_SIZE, 4).unpack1("L<"),
            nr_func_info: bytes.byteslice(BPF_PROG_INFO_NR_FUNC_INFO, 4).unpack1("L<"),
            verified_insns: bytes.byteslice(216, 4).unpack1("L<")
          }.freeze
        end
      end
    end
  end
end
