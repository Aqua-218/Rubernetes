# frozen_string_literal: true

require_relative "../test_helper"
require "socket"
require "rubernetes/node"
require "rubernetes/platform/linux/native_adapters"

# probe/http formatURL, probe/tcp and probe/grpc use net.JoinHostPort: an
# IPv6 Pod IP is bracketed in the probe URL, the gRPC target, the Host
# header and the TCP dial (which also needs an AF_INET6 socket).  Every
# httpGet probe on an IPv6 Pod failed because URI() rejected the bare
# address.
class ProbeIPv6HostsTest < Minitest::Test
  Helpers = Rubernetes::Node::Helpers
  Connector = Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector

  class HTTP
    attr_reader :uris

    def initialize = @uris = []

    def get(uri, headers:, timeout:, **)
      @uris << uri.to_s
      {"status" => 200}
    end
  end

  def test_join_host_port_brackets_ipv6_only
    assert_equal "10.0.0.5:8080", Helpers.join_host_port("10.0.0.5", 8080)
    assert_equal "[fd00::2]:8080", Helpers.join_host_port("fd00::2", 8080)
    assert_equal "[fe80::1%eth0]:80", Helpers.join_host_port("fe80::1%eth0", 80)
    assert_equal "[fd00::2]:8080", Helpers.join_host_port("[fd00::2]", 8080), "already bracketed"
    assert_equal "example.com:443", Helpers.join_host_port("example.com", 443)
    assert_equal Helpers.join_host_port("fd00::2", 1), Connector.host_port("fd00::2", 1)
  end

  def test_http_probe_url_is_formatted_like_upstream
    http = HTTP.new
    manager = Rubernetes::Node::ProbeManager.new(runtime: Object.new, http_client: http)
    assert manager.check("c", {"httpGet" => {"host" => "fd00::2", "port" => 8080, "path" => "/healthz"}}).success?
    assert manager.check("c", {"httpGet" => {"host" => "10.0.0.5", "port" => 8080, "path" => "healthz"}}).success?
    # The Pod IP comes from the context when the probe names no host.
    assert manager.check("c", {"httpGet" => {"port" => 8081}}, context: {"host" => "fd00::9"}).success?
    assert_equal ["http://[fd00::2]:8080/healthz", "http://10.0.0.5:8080/healthz", "http://[fd00::9]:8081/"], http.uris
  end

  def test_tcp_connect_uses_the_address_family_of_the_host
    server = begin
      TCPServer.new("::1", 0)
    rescue SystemCallError
      skip "no IPv6 loopback"
    end
    port = server.addr[1]
    assert_equal true, Connector.blocking_tcp_connect("::1", port, 1.0).fetch("connected")
    assert_equal true, Connector.blocking_tcp_connect("[::1]", port, 1.0).fetch("connected")
    server.close
    v4 = TCPServer.new("127.0.0.1", 0)
    assert_equal true, Connector.blocking_tcp_connect("127.0.0.1", v4.addr[1], 1.0).fetch("connected")
    v4.close
    refute Connector.blocking_tcp_connect("::1", port, 0.5).fetch("connected"), "closed port"
  end

  def test_http_get_sends_a_bracketed_host_header_over_ipv6
    server = begin
      TCPServer.new("::1", 0)
    rescue SystemCallError
      skip "no IPv6 loopback"
    end
    port = server.addr[1]
    seen = nil
    thread = Thread.new do
      # The connector first checks connectivity (a connection that sends
      # nothing), then sends the request on a second one.
      loop do
        client = server.accept
        data = IO.select([client], nil, nil, 1.0) ? (client.read_nonblock(4096, exception: false) rescue nil) : nil
        if data.is_a?(String) && data.start_with?("GET")
          seen = data
          client.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
          client.close
          break
        end
        client.close
      end
    end
    result = Connector.blocking_http_get("::1", port, "/healthz", {}, 2.0)
    thread.join
    server.close
    assert_equal 200, result.fetch("status")
    assert_match(/^GET \/healthz HTTP\/1.1\r\nHost: \[::1\]:#{port}\r\n/, seen)
  end
end
