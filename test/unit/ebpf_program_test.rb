# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class EBPFProgramTest < Minitest::Test
  MAP_FDS = {
    "service_rules" => 11,
    "backends" => 12,
    "conntrack" => 13,
    "client_ip_affinity" => 14,
    "sctp_crc32c" => 15
  }.freeze

  FakeMap = Data.define(:fd)

  class RecordingBPF
    attr_reader :updates, :deletes

    def initialize
      @updates = []
      @deletes = []
    end

    def map_update(**arguments)
      @updates << arguments
      true
    end

    def map_delete(**arguments)
      @deletes << arguments
      true
    end
  end

  def test_service_datapath_contains_real_parser_map_and_rewrite_helpers
    instructions = Rubernetes::Proxy::EBPFProgram::ServiceDatapath.new(map_fds: MAP_FDS).build
    codes = instructions.map(&:code)
    immediates = instructions.map(&:immediate)

    assert_operator instructions.length, :>, 200
    assert_includes immediates, 11
    assert_includes immediates, 12
    assert_includes immediates, 13
    assert_includes immediates, 14
    assert_includes codes, 0x85 # bpf_map_lookup_elem / helper call
    assert_includes codes, 0x95 # exit
    assert(instructions.any? { |instruction| instruction.immediate == 9 })
    assert(instructions.any? { |instruction| instruction.immediate == 26 })
  end

  def test_feature_matrix_exposes_sctp_crc32c_loop_contract
    features = Rubernetes::Proxy::EBPFProgram::ServiceDatapath::FEATURE_MATRIX
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(kernel_release: "6.11.99-generic")

    assert_equal true, features.fetch(:sctp_crc32c)
    assert_equal true, features.fetch(:ipv6_extension_headers)
    assert_equal true, features.fetch(:vlan_encapsulation)
    assert_equal true, features.fetch(:forward_masquerade)
    assert_equal true, features.fetch(:topology_hints)
    assert_equal true, features.fetch(:load_balancer_source_ranges)
    assert_equal true, features.fetch(:health_check_node_port)
    contract = Rubernetes::Proxy::EBPFProgram::ServiceDatapath.new(map_fds: MAP_FDS).sctp_crc32c_loop_contract

    assert_equal "bpf_loop", contract.fetch("helper")
    assert_equal "BPF_PSEUDO_FUNC", contract.fetch("relocation")
    refute_predicate adapter, :sctp_crc32c_kernel_supported?
    assert_match(/Linux >= 6\.12/, adapter.production_capability_error)
    refute_predicate adapter, :production_capable?
  end

  def test_sctp_kernel_capability_boundary_is_explicit
    unsupported = Rubernetes::Proxy::LinuxEBPFAdapter.new(kernel_release: "6.11.99-generic")
    supported = Rubernetes::Proxy::LinuxEBPFAdapter.new(kernel_release: "6.12.0-generic")

    refute_predicate unsupported, :sctp_crc32c_kernel_supported?
    assert_match(/Linux >= 6\.12/, unsupported.production_capability_error)
    assert_raises(RuntimeError) { unsupported.attach(ifindex: 1) }
    assert_predicate supported, :sctp_crc32c_kernel_supported?
    assert_predicate supported, :service_semantics_complete?
    refute_match(/unsupported on kernel/, supported.production_capability_error)
  end

  def test_sctp_crc32c_program_has_static_callback_relocation_and_full_loop_bound
    instructions = Rubernetes::Proxy::EBPFProgram::ServiceDatapath.new(map_fds: MAP_FDS).build
    function_relocations = instructions.each_with_index.filter_map do |instruction, index|
      next unless instruction.code == 0x18 && instruction.source == Rubernetes::Proxy::EBPFProgram::Assembler::BPF_PSEUDO_FUNC

      [index, instruction.immediate]
    end

    refute_empty function_relocations
    function_relocations.each do |index, target|
      assert_operator index + 1 + target, :>, index
      assert_equal 0, instructions.fetch(index + 1).code
    end
    assert_includes instructions.map(&:immediate), Rubernetes::Proxy::EBPFProgram::ServiceDatapath::HELPER_BPF_LOOP
    assert_includes instructions.map(&:immediate), Rubernetes::Proxy::EBPFProgram::WireFormat::SCTP_CRC32C_MAX_BYTES
  end

  def test_sctp_crc32c_table_matches_the_standard_reference_vector
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new
    table = 256.times.map { |index| adapter.send(:sctp_crc32c_table_value, index) }
    crc = 0xffff_ffff
    "123456789".bytes.each { |byte| crc = (crc >> 8) ^ table[(crc ^ byte) & 0xff] }

    assert_equal 0xe306_9283, crc ^ 0xffff_ffff
  end

  def test_sctp_crc32c_hostile_padded_frame_uses_ipv4_total_length_only
    crc = Rubernetes::Proxy::EBPFProgram::SCTPCRC32C
    ethernet = "\0" * 14
    ipv4 = [0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 132, 0, 0,
            10, 0, 0, 1, 10, 0, 0, 2].pack("C*")
    sctp = [9899, 9899, 0, 0].pack("n n N N")
    frame = (ethernet + ipv4 + sctp).ljust(60, "\0")
    padded = frame.dup
    padded.setbyte(59, 0xff)

    expected = crc.crc32c(sctp)

    assert_equal 60, frame.bytesize
    assert_equal expected, crc.sctp_crc32c(frame, family: 4, l3_offset: 14, transport_offset: 34)
    assert_equal expected, crc.sctp_crc32c(padded, family: 4, l3_offset: 14, transport_offset: 34)

    malformed = frame.dup
    malformed.setbyte(16, 0)
    malformed.setbyte(17, 47)
    assert_raises(ArgumentError) { crc.sctp_crc32c(malformed, family: 4, l3_offset: 14, transport_offset: 34) }
  end

  def test_sctp_crc32c_hostile_ipv6_extension_chain_excludes_padding_and_rejects_bad_length
    crc = Rubernetes::Proxy::EBPFProgram::SCTPCRC32C
    ipv6 = [0x60, 0, 0, 0, 0, 20, 0, 132] + ([0] * 32)
    extension = [132, 0].pack("C*") + ("\0" * 6)
    sctp = [9899, 9899, 0, 0].pack("n n N N")
    frame = ("\0" * 14).b + ipv6.pack("C*") + extension + sctp + ("\0" * 8)
    padded = frame.dup
    padded.setbyte(-1, 0xff)

    expected = crc.crc32c(sctp)

    assert_equal expected, crc.sctp_crc32c(frame, family: 6, l3_offset: 14, transport_offset: 62)
    assert_equal expected, crc.sctp_crc32c(padded, family: 6, l3_offset: 14, transport_offset: 62)

    malformed = frame.dup
    malformed.setbyte(14 + 40 + 1, 1)
    assert_raises(ArgumentError) { crc.sctp_crc32c(malformed, family: 6, l3_offset: 14, transport_offset: 62) }
  end

  def test_kernel_release_override_is_non_production_and_actual_release_is_exposed
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(kernel_release: "6.12.0-test")

    assert_equal Etc.uname.fetch(:release), adapter.actual_kernel_release
    assert_equal "6.12.0-test", adapter.kernel_release_override
    assert_equal Etc.uname.fetch(:release), adapter.kernel_release
    refute_predicate adapter, :production_release_attested?
    refute_predicate adapter, :production_capable?
  end

  def test_deterministic_hash_vector_matches_kernel_contract
    key = ["TCP", "10.0.0.8", 40_000, "10.96.0.40", 80]
    selector = Rubernetes::Proxy::DeterministicHash.new
    # Linux jhash (lookup3) of the source address 10.0.0.8 with seed 0.
    assert_equal 854_035_748, selector.packet_hash(key)
    assert_equal "10.1.0.1", selector.select(key, %w[10.1.0.1 10.1.0.2])
  end

  def test_native_bpf_loader_validates_and_applies_pseudo_function_relocations
    loader = Rubernetes::Platform::Linux::BPF.allocate
    instruction = Rubernetes::Platform::Linux::BPF::Instruction.new(
      code: 0x18, destination: 2, source: Rubernetes::Platform::Linux::BPF::BPF_PSEUDO_FUNC,
      offset: 0, immediate: 0
    )
    high = Rubernetes::Platform::Linux::BPF::Instruction.new(code: 0, destination: 0, source: 0, offset: 0, immediate: 0)
    exit_instruction = Rubernetes::Platform::Linux::BPF::Instruction.new(code: 0x95, destination: 0, source: 0, offset: 0, immediate: 0)

    relocated = loader.send(:relocate_function_references, [instruction, high, exit_instruction], {0 => 2})

    assert_equal 1, relocated.fetch(0).immediate
    assert_raises(ArgumentError) do
      loader.send(:relocate_function_references, [instruction, high, exit_instruction], {0 => 99})
    end
  end

  def test_native_bpf_loader_emits_btf_and_function_info_for_static_callbacks
    loader = Rubernetes::Platform::Linux::BPF.allocate
    btf = loader.send(:build_function_btf)
    func_info = loader.send(:function_info_blob, [11])

    assert_equal 0xeb9f, btf.unpack1("S<")
    assert_equal [[0, 4], [11, 9]], func_info.unpack("L<*").each_slice(2).to_a
  end

  def test_native_bpf_readback_extracts_helper_ids_from_translated_instructions
    loader = Rubernetes::Platform::Linux::BPF.allocate
    instructions = [
      Rubernetes::Platform::Linux::BPF::Instruction.new(code: 0x85, destination: 0, source: 0, offset: 0, immediate: 5),
      Rubernetes::Platform::Linux::BPF::Instruction.new(code: 0x85, destination: 0, source: 0, offset: 0, immediate: 181),
      Rubernetes::Platform::Linux::BPF::Instruction.new(code: 0x95, destination: 0, source: 0, offset: 0, immediate: 0)
    ]
    translated = loader.send(:parse_instruction_stream, instructions.map(&:to_binary).join)

    assert_equal [5, 181], loader.send(:helper_ids_from_instructions, translated)
    assert_equal instructions, translated
  end

  def test_load_evidence_digest_is_content_bound_and_key_order_independent
    bpf = Rubernetes::Platform::Linux::BPF
    evidence = {"verifier_log_sha256" => "a" * 64, "helper_ids" => [181], "program_id" => 9}
    reordered = {"program_id" => 9, "helper_ids" => [181], "verifier_log_sha256" => "a" * 64}

    assert_equal bpf.evidence_digest(evidence), bpf.evidence_digest(reordered)
    refute_equal bpf.evidence_digest(evidence), bpf.evidence_digest(evidence.merge("helper_ids" => [5]))
    refute_equal bpf.evidence_digest(evidence), bpf.evidence_digest(evidence.merge("verifier_log_sha256" => "b" * 64))
  end

  def test_program_exposes_kernel_helper_and_verifier_load_evidence
    bpf = Rubernetes::Platform::Linux::BPF
    instruction = bpf::Instruction.new(code: 0x85, destination: 0, source: 0, offset: 0, immediate: 181)
    evidence = {"schema" => 1, "helper_ids" => [181], "program_id" => 17}
    digest = bpf.evidence_digest(evidence)
    program = bpf::Program.new(fd: 17, verifier_log: "processed 1 insns\n", id: 17, type: 3,
                               name: "test", ifindex: 0, tag: "0123456789abcdef", helper_ids: [181],
                               xlated_instructions: [instruction], verified_insns: 1, load_evidence: evidence,
                               load_evidence_sha256: digest)

    assert_equal [181], program.helper_ids
    assert_equal Digest::SHA256.hexdigest("processed 1 insns\n"), program.verifier_log_sha256
    assert_equal digest, program.load_evidence_digest
    assert_equal Digest::SHA256.hexdigest(instruction.to_binary), program.xlated_program_sha256
  end

  def test_kernel_identity_uses_attested_helpers_instead_of_a_static_helper_list
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new
    program = Rubernetes::Platform::Linux::BPF::Program.new(
      fd: 17, verifier_log: "processed 1 insns\n", id: 17, type: 3, name: "test", ifindex: 0,
      tag: "0123456789abcdef", helper_ids: [181], xlated_instructions: [], verified_insns: 1
    )
    adapter.instance_variable_set(:@program, program)
    adapter.instance_variable_set(:@maps, {}.freeze)
    adapter.instance_variable_set(:@links, [].freeze)
    adapter.instance_variable_set(:@verifier_attested, true)
    adapter.instance_variable_set(:@helper_attested, true)
    adapter.instance_variable_set(:@helper_live_readback_attested, true)
    adapter.instance_variable_set(:@helper_attestation, {"source" => "kernel_program_info", "helperIds" => [181]}.freeze)
    adapter.instance_variable_set(:@tc_attach_attested, true)
    adapter.instance_variable_set(:@actual_kernel_release, "6.12.0-test")

    identity = adapter.kernel_identity

    assert_equal [181], identity.fetch("helperIds")
    assert_equal [181], identity.fetch("program").fetch("helperIds")
  end

  def test_external_helper_attestation_rejects_ids_that_differ_from_program
    program = helper_attestation_program(helper_ids: [999])
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(bpf: unavailable_program_info_bpf)

    external = external_helper_attestation(program, helper_ids: [181])

    assert_nil adapter.send(:helper_attestation_for, program, external)
    refute adapter.instance_variable_get(:@helper_live_readback_attested)
  end

  def test_kernel_identity_does_not_publish_mismatched_external_helper_ids
    program = helper_attestation_program(helper_ids: [999])
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new
    adapter.instance_variable_set(:@program, program)
    adapter.instance_variable_set(:@maps, {}.freeze)
    adapter.instance_variable_set(:@links, [].freeze)
    adapter.instance_variable_set(:@verifier_attested, true)
    adapter.instance_variable_set(:@helper_attested, true)
    adapter.instance_variable_set(:@helper_attestation, {"source" => "external_probe", "helperIds" => [181]}.freeze)
    adapter.instance_variable_set(:@tc_attach_attested, true)

    assert_nil adapter.kernel_identity
  end

  def test_live_program_info_readback_takes_precedence_over_external_helper_ids
    program = helper_attestation_program(helper_ids: [181])
    bpf = readback_program_info_bpf(program, helper_ids: [181])
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(bpf: bpf)

    external = external_helper_attestation(program, helper_ids: [999])
    attestation = adapter.send(:helper_attestation_for, program, external)

    assert_equal "kernel_program_info", attestation.fetch("source")
    assert_equal [181], attestation.fetch("helperIds")
    assert adapter.instance_variable_get(:@helper_live_readback_attested)
  end

  def test_live_helper_mismatch_rejects_external_report_even_when_external_matches_readback
    program = helper_attestation_program(helper_ids: [999])
    bpf = readback_program_info_bpf(program, helper_ids: [181])
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(bpf: bpf)

    external = external_helper_attestation(program, helper_ids: [181])

    assert_nil adapter.send(:helper_attestation_for, program, external)
    refute adapter.instance_variable_get(:@helper_live_readback_attested)
  end

  def test_external_helper_fallback_is_explicitly_nonproduction
    program = helper_attestation_program(helper_ids: [181])
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(bpf: unavailable_program_info_bpf)

    external = external_helper_attestation(program, helper_ids: [181])
    attestation = adapter.send(:helper_attestation_for, program, external)

    assert_equal "external_probe", attestation.fetch("source")
    refute adapter.instance_variable_get(:@helper_live_readback_attested)
    assert_match(/live_helper_readback/, adapter.production_capability_error)
  end

  def test_service_and_backend_wire_records_have_kernel_declared_sizes
    endpoint = Rubernetes::Proxy::Endpoint.new(address: "10.0.0.2", port: 8080, protocol: "TCP")
    rule = Rubernetes::Proxy::Rule.new(service_key: "default/web", service_type: "ClusterIP", kind: "ClusterIP",
                                       virtual_ip: "10.96.0.10", port: 80, protocol: "TCP", backends: [endpoint])
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new
    service_key, service_value = adapter.send(:encode_service_rule_for_family, rule, 4)
    backend_key, backend_value = adapter.send(:encode_backend, endpoint,
                                              token: adapter.send(:service_token, rule), index: 0, family: 4)

    assert_equal 40, service_key.bytesize
    assert_equal 64, service_value.bytesize
    assert_equal 16, backend_key.bytesize
    assert_equal 96, backend_value.bytesize
    assert_equal 4, service_key.getbyte(0)
    assert_equal 6, service_key.getbyte(1)
    assert_equal 1, service_value.getbyte(8)
    assert_equal 6, backend_value.getbyte(18)
    assert_equal 4, backend_value.getbyte(19)
  end

  def test_ruleset_sync_keeps_old_backend_slots_for_conntrack_and_affinity
    service = {
      "metadata" => {"name" => "web", "namespace" => "default"},
      "spec" => {
        "type" => "NodePort", "clusterIP" => "10.96.0.10",
        "clusterIPs" => ["10.96.0.10", "fd00::10"], "ipFamilies" => %w[IPv4 IPv6],
        "ports" => [{"port" => 80, "targetPort" => 8080, "nodePort" => 30_080}]
      }
    }
    endpoints = [
      Rubernetes::Proxy::Endpoint.new(address: "10.1.0.1", port: 8080, protocol: "TCP"),
      Rubernetes::Proxy::Endpoint.new(address: "fd00::1", port: 8080, protocol: "TCP")
    ]
    rules = Rubernetes::Proxy::RuleCompiler.new.compile(service, endpoints: endpoints).rules
    bpf = RecordingBPF.new
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new(bpf: bpf)
    maps = MAP_FDS.keys.to_h { |name| [name, FakeMap.new(1)] }

    adapter.send(:sync_maps, maps, rules)
    adapter.instance_variable_set(:@service_keys, adapter.send(:current_service_keys, rules).freeze)
    adapter.send(:sync_maps, maps, [])

    assert_equal(4, bpf.updates.count { |call| call.fetch(:value).bytesize == 64 })
    assert_equal(4, bpf.updates.count { |call| call.fetch(:value).bytesize == 96 })
    assert_equal 4, bpf.deletes.length
    assert_empty bpf.deletes.map { |call| call.fetch(:resource_id) }.grep(/backend/)
  end

  def test_service_datapath_emits_vlan_fragment_and_ipv6_extension_guards
    instructions = Rubernetes::Proxy::EBPFProgram::ServiceDatapath.new(map_fds: MAP_FDS).build
    immediates = instructions.map(&:immediate)

    assert_includes immediates, Rubernetes::Proxy::EBPFProgram::ServiceDatapath::ETH_P_8021Q
    assert_includes immediates, Rubernetes::Proxy::EBPFProgram::ServiceDatapath::IPPROTO_FRAGMENT
    assert_includes immediates, Rubernetes::Proxy::EBPFProgram::ServiceDatapath::IPPROTO_ROUTING
    assert_operator instructions.count { |instruction| instruction.immediate == 26 }, :>=, 2
  end

  def test_lb_source_range_and_snat_state_are_encoded_in_kernel_maps
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "public"},
      "spec" => {"type" => "LoadBalancer", "clusterIP" => "10.96.0.40",
                 "loadBalancerIP" => "192.0.2.40", "loadBalancerSourceRanges" => ["198.51.100.0/24"],
                 "ports" => [{"port" => 80, "targetPort" => 8080}]}
    )
    endpoint = Rubernetes::Proxy::Endpoint.new(address: "10.1.0.40", port: 8080, protocol: "TCP")
    rule = Rubernetes::Proxy::RuleCompiler.new(node_addresses: ["192.0.2.1"]).compile(service, endpoints: [endpoint]).rules.find do |entry|
      entry.kind == "LoadBalancer"
    end
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new
    _key, value = adapter.send(:encode_service_rule_for_family, rule, 4)
    range_key, range_value = adapter.send(:encode_source_range, rule, "198.51.100.0/24")

    assert_equal 11, value.getbyte(60) # masquerade + hairpin + source ranges
    assert_equal 16, value.byteslice(44, 16).bytesize
    assert_equal 28, range_key.bytesize
    assert_equal [1].pack("L<"), range_value
    ipv6_range_key, = adapter.send(:encode_source_range, rule, "2001:db8:40::/64")

    assert_equal [128].pack("L<"), ipv6_range_key.byteslice(0, 4)
    unrestricted = Rubernetes::Proxy::Rule.new(
      service_key: rule.service_key, service_type: rule.service_type, kind: rule.kind,
      virtual_ip: rule.virtual_ip, port: rule.port, protocol: rule.protocol, node_port: rule.node_port,
      health_check: rule.health_check, backends: rule.backends,
      external_traffic_policy: rule.external_traffic_policy, internal_traffic_policy: rule.internal_traffic_policy,
      session_affinity: rule.session_affinity, session_affinity_timeout_seconds: rule.session_affinity_timeout_seconds,
      metadata: rule.metadata.merge("loadBalancerSourceRanges" => [])
    )
    _unrestricted_key, unrestricted_value = adapter.send(:encode_service_rule_for_family, unrestricted, 4)

    assert_equal 3, unrestricted_value.getbyte(60)

    bpf = RecordingBPF.new
    maps = (MAP_FDS.keys + %w[source_ranges snat]).to_h { |name| [name, FakeMap.new(1)] }
    adapter_with_recorder = Rubernetes::Proxy::LinuxEBPFAdapter.new(bpf: bpf)
    adapter_with_recorder.send(:sync_maps, maps, [rule])

    assert_equal(1, bpf.updates.count { |call| call.fetch(:resource_id).to_s.include?("source_range:update") })
  end

  def test_topology_hints_select_only_endpoints_advertising_the_local_zone
    service = Rubernetes::Proxy::Service.new(
      "metadata" => {"name" => "zonal"},
      "spec" => {"clusterIP" => "10.96.0.41", "ports" => [{"port" => 80}]}
    )
    zonal = Rubernetes::Proxy::Endpoint.new(address: "10.1.0.41", port: 80, protocol: "TCP",
                                            hints: {"forZones" => [{"name" => "zone-a"}]})
    remote = Rubernetes::Proxy::Endpoint.new(address: "10.1.0.42", port: 80, protocol: "TCP",
                                             hints: {"forZones" => [{"name" => "zone-b"}]})
    rule = Rubernetes::Proxy::RuleCompiler.new(node_zone: "zone-a").compile(service, endpoints: [zonal, remote]).rules.first
    adapter = Rubernetes::Proxy::LinuxEBPFAdapter.new

    assert_equal ["10.1.0.41"], adapter.send(:backend_candidates, rule).map(&:address)
  end

  private

  def helper_attestation_program(helper_ids:)
    bpf = Rubernetes::Platform::Linux::BPF
    helper = Rubernetes::Proxy::EBPFProgram::ServiceDatapath::HELPER_BPF_LOOP
    evidence = {
      "schema" => 1, "program_id" => 17, "program_tag" => "0123456789abcdef",
      "helper_ids" => helper_ids, "requested_helper_ids" => [helper],
      "translated_helper_calls" => [helper], "requested_helper_calls" => [helper]
    }
    bpf::Program.new(
      fd: 17, verifier_log: "processed 1 insns\n", id: 17, type: 3, name: "test", ifindex: 0,
      tag: "0123456789abcdef", helper_ids: helper_ids, requested_helper_ids: [helper],
      translated_helper_calls: [helper], requested_helper_calls: [helper], xlated_instructions: [],
      verified_insns: 1, load_evidence: evidence, load_evidence_sha256: bpf.evidence_digest(evidence)
    )
  end

  def external_helper_attestation(program, helper_ids:)
    document = {
      "source" => "external_probe", "helperIds" => helper_ids,
      "requestedHelperIds" => program.requested_helper_ids,
      "requestedHelperCalls" => program.requested_helper_calls,
      "translatedHelperCalls" => program.translated_helper_calls,
      "programId" => program.id, "programTag" => program.tag,
      "loadEvidenceSha256" => program.load_evidence_sha256
    }
    document.merge("attestationSha256" => Rubernetes::Platform::Linux::BPF.evidence_digest(document))
  end

  def unavailable_program_info_bpf
    bpf = Object.new
    bpf.define_singleton_method(:program_info) do |_program, resource_id:|
      raise IOError, "#{resource_id} unavailable"
    end
    bpf
  end

  def readback_program_info_bpf(program, helper_ids:)
    info = {id: program.id, tag: program.tag, helper_ids: helper_ids}
    bpf = Object.new
    bpf.define_singleton_method(:program_info) do |_program, resource_id:|
      info
    end
    bpf
  end
end
