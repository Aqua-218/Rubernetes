# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class ProxyEBPFAffinityTest < Minitest::Test
  Proxy = Rubernetes::Proxy
  Linux = Rubernetes::Platform::Linux
  BPF = Linux::BPF
  Wire = Proxy::EBPFProgram::WireFormat
  SERVICE_PORT = 80
  TTL_NS = 2_000_000_000
  BPF_PROG_TEST_RUN = 10

  def test_ipv4_and_ipv6_client_ip_affinity_on_the_tc_datapath
    families = [["192.0.2.10", "198.51.100.10", %w[203.0.113.1 203.0.113.2 203.0.113.3]],
                ["2001:db8:1::a", "2001:db8:2::a", %w[2001:db8:3::1 2001:db8:3::2 2001:db8:3::3]]]
    [false, true].product(families).each do |reassemble, (source, vip, endpoints)|
      verify_affinity(reassemble, source, vip, endpoints)
    end
  rescue Linux::BPF::VerifierError => error
    raise "#{error.message}\n#{error.verifier_log}"
  rescue Linux::Error => error
    skip error.message if [Errno::EPERM::Errno, Errno::EACCES::Errno, Errno::ENOSYS::Errno].include?(error.errno)

    raise
  end

  private

  def verify_affinity(reassemble, source, vip, endpoints)
    bpf = BPF.new
    adapter = Proxy::LinuxEBPFAdapter.new(bpf: bpf)
    maps = make_maps(bpf)
    program = load_program(bpf, maps, reassemble)
    first_endpoint, second_endpoint, replacement = endpoints
    rule = service_rule(vip, [first_endpoint, second_endpoint])
    adapter.send(:sync_maps, maps, [rule])
    affinity_key = adapter.send(:service_token, rule) + adapter.send(:packed_ip, source)
    affinity = maps.fetch("client_ip_affinity")
    first_port, replacement_port, other_port, next_port = ports_for(source)
    first_flow = tcp_packet(source, vip, first_port)
    before = monotonic_ns

    assert_equal first_endpoint, run_packet(bpf, program, first_flow)
    initial = read_affinity(bpf, affinity, affinity_key)

    assert_operator initial.unpack1("Q<"), :>=, before + TTL_NS
    assert_operator initial.unpack1("Q<"), :<=, monotonic_ns + TTL_NS
    assert_equal first_endpoint, run_packet(bpf, program, tcp_packet(source, vip, other_port))
    refreshed = read_affinity(bpf, affinity, affinity_key)

    assert_operator refreshed.unpack1("Q<"), :>, initial.unpack1("Q<")

    refreshed[0, 8] = [1].pack("Q<")
    bpf.map_update(map: affinity, key: affinity_key, value: refreshed)

    assert_equal first_endpoint, run_packet(bpf, program, first_flow), "the established connection keeps its endpoint"
    assert_equal 1, read_affinity(bpf, affinity, affinity_key).unpack1("Q<")
    assert_equal second_endpoint, run_packet(bpf, program, tcp_packet(source, vip, next_port)), "a fresh flow can move after inactivity"
    old_affinity = read_affinity(bpf, affinity, affinity_key)
    adapter.send(:sync_maps, maps, [service_rule(vip, [first_endpoint, replacement])])

    assert_equal first_endpoint, run_packet(bpf, program, tcp_packet(source, vip, replacement_port)), "a reused slot is a miss"

    # The old second slot remains in the map for established flows after a
    # ruleset update. A new connection can only choose the current first slot.
    bpf.map_update(map: affinity, key: affinity_key, value: old_affinity)
    adapter.send(:sync_maps, maps, [service_rule(vip, endpoints.first(1))])

    assert_equal first_endpoint, run_packet(bpf, program, tcp_packet(source, vip, next_port + 1000))
  ensure
    program&.close
    maps&.each_value(&:close)
  end

  def service_rule(vip, endpoints)
    Proxy::Rule.new(service_key: "default/echo", service_type: "ClusterIP", kind: "ClusterIP", virtual_ip: vip, port: SERVICE_PORT,
                    protocol: "TCP", session_affinity: "ClientIP", session_affinity_timeout_seconds: 2,
                    backends: endpoints.map { |address| Proxy::Endpoint.new(address: address, port: 8080, protocol: "TCP") })
  end

  def make_maps(bpf)
    {"service_rules" => [BPF::BPF_MAP_TYPE_HASH, 40, Wire::SERVICE_VALUE_SIZE],
     "backends" => [BPF::BPF_MAP_TYPE_HASH, Wire::BACKEND_KEY_SIZE, Wire::BACKEND_VALUE_SIZE],
     "conntrack" => [BPF::BPF_MAP_TYPE_LRU_HASH, Wire::CONNTRACK_KEY_SIZE, Wire::CONNTRACK_VALUE_SIZE],
     "client_ip_affinity" => [BPF::BPF_MAP_TYPE_LRU_HASH, Wire::AFFINITY_KEY_SIZE, Wire::AFFINITY_VALUE_SIZE]}.transform_values do |type, key, value|
      bpf.map_create(type: type, key_size: key, value_size: value, max_entries: 16)
    end
  end

  def load_program(bpf, maps, reassemble)
    emitter = Proxy::EBPFProgram::ServiceDatapath.new(map_fds: maps.transform_values(&:fd), kernel_reassembly: reassemble)
    bpf.load(instructions: emitter.build, program_type: BPF::BPF_PROG_TYPE_SCHED_CLS, log_size: BPF::MAX_LOG_SIZE)
  end

  def read_affinity(bpf, map, key)
    bpf.map_lookup(map: map, key: key)
  end

  def ports_for(source)
    buckets = (20_000..20_020).group_by do |port|
      raw = IPAddr.new(source).hton + [port].pack("nxx")
      Proxy::DeterministicHash.jenkins_hash(raw) >> 31
    end
    buckets.fetch(0).first(2) + buckets.fetch(1).first(2)
  end

  def tcp_packet(source, destination, port)
    addresses = IPAddr.new(source).hton + IPAddr.new(destination).hton
    ipv6 = addresses.bytesize == 32
    tcp = [port, SERVICE_PORT, 1, 0, 0x5002, 4096, 0, 0].pack("nnNNnnnn")
    ip = ipv6 ? [0x6000_0000, tcp.bytesize, 6, 64].pack("NnCC") : [0x45, 0, 20 + tcp.bytesize, 1, 0, 64, 6, 0].pack("CCnnnCCn")
    ip += addresses
    ip[10, 2] = [checksum(ip)].pack("n") unless ipv6
    pseudo = addresses + (ipv6 ? [tcp.bytesize, 6].pack("NN") : [0, 6, tcp.bytesize].pack("CCn"))
    tcp[16, 2] = [checksum(pseudo + tcp)].pack("n")
    ("\0" * 12).b + [ipv6 ? 0x86dd : 0x0800].pack("n") + ip + tcp
  end

  def checksum(data)
    sum = data.unpack("n*").sum
    sum = (sum >> 16) + (sum & 0xffff) while sum > 0xffff
    (~sum) & 0xffff
  end

  def run_packet(bpf, program, packet)
    output = "\0".b * packet.bytesize
    input_pointer = Fiddle::Pointer[packet]
    output_pointer = Fiddle::Pointer[output]
    attributes = [program.fd, 0, packet.bytesize, output.bytesize, input_pointer.to_i, output_pointer.to_i, 1, 0].pack("L<4Q<2L<2")
    bpf.send(:syscall_result!, BPF_PROG_TEST_RUN, Fiddle::Pointer[attributes], attributes.bytesize,
             operation: "bpf(BPF_PROG_TEST_RUN)", resource_id: "test:proxy:affinity")

    assert_equal 0, attributes.byteslice(4, 4).unpack1("L<"), "the TC program forwarded the packet"
    ipv6 = packet.getbyte(14) >> 4 == 6
    IPAddr.new_ntoh(output.byteslice(ipv6 ? 38 : 30, ipv6 ? 16 : 4)).to_s
  end

  def monotonic_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
end
