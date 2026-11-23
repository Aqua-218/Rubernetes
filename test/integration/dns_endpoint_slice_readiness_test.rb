# frozen_string_literal: true

require "io/wait"

require_relative "../test_helper"
require "rubernetes/network/dns"

class DNSEndpointSliceReadinessTest < Minitest::Test
  DNS = Rubernetes::Network::DNS
  Wire = DNS::Wire
  SERVICE = "database.apps.svc.cluster.local"
  SRV = "_sql._tcp.#{SERVICE}".freeze

  def setup
    @resolver = DNS::Resolver.new
    @server = DNS::Server.new(resolver: @resolver, port: 0, tcp: false).start
    @socket = UDPSocket.new
    @socket.connect("127.0.0.1", @server.port)
    add_service(publish_not_ready: false)
  end

  def teardown
    @socket&.close
    @server&.stop
  end

  def test_restart_while_the_previous_udp_listener_is_sending
    old = @server.udp_sockets.fetch(0)
    sending = Queue.new
    closed = Queue.new
    release = Queue.new
    old.singleton_class.prepend(Module.new do
      define_method(:send) do |*args|
        sending << true
        release.pop
        super(*args)
      end
      define_method(:close) { super().tap { closed << true } }
    end)
    question = Wire::Question.new(name: SERVICE, type: Wire::TYPE_A, klass: Wire::CLASS_IN)
    @socket.send(Wire.encode(Wire::Message.new(id: 42, questions: [question])), 0)

    assert sending.pop(timeout: 5), "the original listener must reach the send"
    stopping = Thread.new { @server.stop }

    assert closed.pop(timeout: 5), "stop must close the original listener"
    @server.start
    replacement = @server.udp_sockets.fetch(0)
    release << true

    assert stopping.value
    assert_equal [replacement], @server.udp_sockets
    assert_equal 42, ask(SERVICE, Wire::TYPE_A).id
  ensure
    release&.close
  end

  def test_slice_ready_controls_address_hostname_and_srv_answers
    primary = [
      endpoint("192.0.2.1", "ready", {"ready" => true, "serving" => false, "terminating" => true}),
      endpoint("192.0.2.2", "not-ready", {"ready" => false, "serving" => true}),
      endpoint("192.0.2.3", "unknown", {"serving" => false, "terminating" => true})
    ]
    secondary = [
      endpoint("2001:db8::1", "ipv6-ready", {"ready" => true, "serving" => false}),
      endpoint("2001:db8::2", "ipv6-not-ready", {"ready" => false, "serving" => true})
    ]
    add_slice("primary", ["sql", 5432], primary)
    add_slice("secondary", ["sql", 6432], secondary)
    add_slice("metrics", ["metrics", 9090], [primary.first, endpoint("192.0.2.4", "metrics", {"ready" => true})])
    pod = {"kind" => "Pod", "metadata" => {"name" => "pod", "namespace" => "apps"},
           "spec" => {"hostname" => "not-ready", "subdomain" => "database"}, "status" => {"podIP" => "192.0.2.2"}}
    @resolver.watch("type" => "ADDED", "object" => pod)

    assert_equal %w[192.0.2.1 192.0.2.3 192.0.2.4], ask(SERVICE, Wire::TYPE_A).answers.map(&:rdata).sort
    assert_equal ["2001:db8::1"], ask(SERVICE, Wire::TYPE_AAAA).answers.map(&:rdata)
    assert_equal ["192.0.2.1"], ask("ready.#{SERVICE}", Wire::TYPE_A).answers.map(&:rdata)
    assert_equal ["2001:db8::1"], ask("ipv6-ready.#{SERVICE}", Wire::TYPE_AAAA).answers.map(&:rdata)
    assert_equal [["ipv6-ready.#{SERVICE}", 6432], ["ready.#{SERVICE}", 5432], ["unknown.#{SERVICE}", 5432]], srv_targets(SRV)
    assert_equal [["metrics.#{SERVICE}", 9090], ["ready.#{SERVICE}", 9090]], srv_targets("_metrics._tcp.#{SERVICE}")

    add_service(publish_not_ready: true)

    assert_equal Wire::RCODE_NXDOMAIN, ask("not-ready.#{SERVICE}", Wire::TYPE_A).rcode
    assert_equal Wire::RCODE_NXDOMAIN, ask("ipv6-not-ready.#{SERVICE}", Wire::TYPE_AAAA).rcode
    assert_equal %w[192.0.2.1 192.0.2.3 192.0.2.4], ask(SERVICE, Wire::TYPE_A).answers.map(&:rdata).sort
    assert_equal [["ipv6-ready.#{SERVICE}", 6432], ["ready.#{SERVICE}", 5432], ["unknown.#{SERVICE}", 5432]], srv_targets(SRV)
  end

  def test_explicit_ready_update_replaces_authoritative_negative_result
    add_service(publish_not_ready: true)
    add_slice("primary", ["sql", 5432], [endpoint("192.0.2.1", "database", {"ready" => false, "serving" => true})])

    assert_equal Wire::RCODE_NXDOMAIN, ask(SERVICE, Wire::TYPE_A).rcode
    assert_equal Wire::RCODE_NXDOMAIN, ask(SRV, Wire::TYPE_SRV).rcode
    add_slice("primary", ["sql", 5432], [endpoint("192.0.2.1", "database", {"ready" => true, "serving" => false, "terminating" => true})])

    assert_equal ["192.0.2.1"], ask(SERVICE, Wire::TYPE_A).answers.map(&:rdata)
    assert_equal Wire::RCODE_NOERROR, ask(SERVICE, Wire::TYPE_AAAA).rcode
    assert_equal [["database.#{SERVICE}", 5432]], srv_targets(SRV)
  end

  def test_flattened_direct_endpoints_keep_legacy_availability_and_service_ports
    @resolver.add_endpoints("metadata" => {"name" => "legacy", "namespace" => "apps"}, "service_name" => "database",
                            "endpoints" => [{"ip" => "192.0.2.6", "hostname" => "legacy", "ready" => false, "serving" => true}])

    assert_equal ["192.0.2.6"], ask(SERVICE, Wire::TYPE_A).answers.map(&:rdata)
    assert_equal [["legacy.#{SERVICE}", 80]], srv_targets(SRV)
  end

  private

  def endpoint(ip, hostname, conditions)
    {"addresses" => [ip], "hostname" => hostname, "conditions" => conditions}
  end

  def add_service(publish_not_ready:)
    service = {"kind" => "Service", "metadata" => {"name" => "database", "namespace" => "apps"},
               "spec" => {"clusterIP" => "None", "publishNotReadyAddresses" => publish_not_ready, "ports" => [{"name" => "sql", "port" => 80}]}}
    @resolver.watch("type" => "MODIFIED", "object" => service)
  end

  def add_slice(name, port, endpoints)
    slice = {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
             "metadata" => {"name" => name, "namespace" => "apps", "labels" => {"kubernetes.io/service-name" => "database"}},
             "addressType" => endpoints.first.fetch("addresses").first.include?(":") ? "IPv6" : "IPv4",
             "ports" => [{"name" => port[0], "port" => port[1], "protocol" => "TCP"}],
             "endpoints" => endpoints}
    @resolver.watch("type" => "MODIFIED", "object" => slice)
  end

  def ask(name, type)
    question = Wire::Question.new(name: name, type: type, klass: Wire::CLASS_IN)
    @socket.send(Wire.encode(Wire::Message.new(id: 42, questions: [question])), 0)
    raise "DNS response timed out for #{name}" unless @socket.wait_readable(3)

    Wire.decode(@socket.recv(4096))
  end

  def srv_targets(name)
    ask(name, Wire::TYPE_SRV).answers.map { |answer| answer.rdata.values_at("target", "port") }.sort
  end
end
