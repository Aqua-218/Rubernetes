# frozen_string_literal: true

require "tmpdir"
require "socket"
require "yaml"
require "timeout"
require_relative "../test_helper"
require "rubernetes/security"
require "rubernetes/observability/metrics"

# --egress-selector-config-file: cluster / controlplane traffic through an
# HTTP CONNECT proxy over TCP or a Unix socket, with the dial metrics.
class EgressSelectorTest < Minitest::Test
  Egress = Rubernetes::Security::Egress

  # A tiny origin: answers every HTTP/1.1 request with a fixed body.
  def start_origin
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        client = server.accept
        Thread.new(client) do |io|
          request_line = io.gets
          loop do
            line = io.gets
            break if line.nil? || line.strip.empty?
          end
          body = "origin saw #{request_line.to_s.split.first(2).join(" ")}"
          io.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
          io.close
        end
      end
    rescue IOError, Errno::EBADF
      nil
    end
    [server, thread]
  end

  # A CONNECT proxy that tunnels to whatever the client asked for, refusing
  # a port of 1 with 403.
  def start_proxy(listener)
    seen = []
    thread = Thread.new do
      loop do
        client = listener.accept
        Thread.new(client) do |io|
          request_line = io.gets
          loop do
            line = io.gets
            break if line.nil? || line.strip.empty?
          end
          target = request_line.to_s.split[1].to_s
          seen << target
          host, port = target.rpartition(":").values_at(0, 2)
          if port.to_i == 1
            io.write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            io.close
            next
          end
          upstream = TCPSocket.new(host.delete_prefix("[").delete_suffix("]"), port.to_i)
          io.write("HTTP/1.1 200 Connection Established\r\n\r\n")
          # Half-closes travel through: the origin's close reaches the client as EOF.
          pump = Thread.new do
            loop { io.write(upstream.readpartial(65_536)) }
          rescue StandardError
            nil
          ensure
            begin
              io.shutdown(Socket::SHUT_WR)
            rescue StandardError
              nil
            end
          end
          begin
            loop { upstream.write(io.readpartial(65_536)) }
          rescue StandardError
            nil
          end
          begin
            upstream.shutdown(Socket::SHUT_WR)
          rescue StandardError
            nil
          end
          pump.join(2)
          begin
            upstream.close
          rescue StandardError
            nil
          end
          begin
            io.close
          rescue StandardError
            nil
          end
        end
      end
    rescue IOError, Errno::EBADF
      nil
    end
    [thread, seen]
  end

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    Egress.metrics = @metrics
    Egress.selector = nil
  end

  def teardown
    Egress.metrics = nil
    Egress.selector = nil
  end

  def test_http_connect_over_a_unix_socket_and_over_tcp
    Timeout.timeout(60) { run_http_connect_scenario }
  end

  def run_http_connect_scenario
    Dir.mktmpdir do |dir|
      origin, origin_thread = start_origin
      origin_port = origin.addr[1]
      uds_path = File.join(dir, "proxy.sock")
      uds_listener = UNIXServer.new(uds_path)
      uds_thread, uds_seen = start_proxy(uds_listener)
      tcp_listener = TCPServer.new("127.0.0.1", 0)
      tcp_thread, tcp_seen = start_proxy(tcp_listener)

      uds = Egress::Dialer.new(protocol: "HTTPConnect", transport: "uds", uds_name: uds_path)
      socket = uds.dial("127.0.0.1", origin_port)
      socket.write("GET /via-uds HTTP/1.1\r\nHost: x\r\n\r\n")

      assert_match(%r{origin saw GET /via-uds}, socket.read)
      socket.close

      assert_equal ["127.0.0.1:#{origin_port}"], uds_seen

      selector = Egress::Selector.from_h({"apiVersion" => "apiserver.k8s.io/v1beta1", "kind" => "EgressSelectorConfiguration",
                                          "egressSelections" => [{"name" => "cluster",
                                                                  "connection" => {"proxyProtocol" => "HTTPConnect",
                                                                                   "transport" => {"uds" => {"udsName" => uds_path}}}},
                                                                 {"name" => "controlplane",
                                                                  "connection" => {"proxyProtocol" => "Direct"}}]})
      Egress.selector = selector

      assert_nil Egress.dialer("controlplane")
      assert_nil Egress.dialer("etcd")
      http = Egress.http(URI("http://127.0.0.1:#{origin_port}/x"), "cluster")

      assert_kind_of Egress::ProxiedHTTP, http
      response = http.start { |connection| connection.get("/through-selector") }

      assert_equal "200", response.code
      assert_match(%r{origin saw GET /through-selector}, response.body)
      assert_kind_of Net::HTTP, Egress.http(URI("http://127.0.0.1:#{origin_port}/x"), "controlplane")
      refute_kind_of Egress::ProxiedHTTP, Egress.http(URI("http://127.0.0.1:#{origin_port}/x"), "controlplane")
      raw = Egress.tcp_socket("127.0.0.1", origin_port, "cluster")

      assert_equal Socket::AF_UNIX, raw.local_address.afamily, "the tunnel is the proxy connection"
      raw.close

      # TCP (without TLS to the proxy) exercised through the dialer directly.
      tcp = Egress::Dialer.new(protocol: "HTTPConnect", transport: "tcp", proxy_address: "127.0.0.1:#{tcp_listener.addr[1]}")
      socket = tcp.dial("127.0.0.1", origin_port)
      socket.write("GET /via-tcp HTTP/1.1\r\nHost: x\r\n\r\n")

      assert_match(%r{origin saw GET /via-tcp}, socket.read)
      socket.close

      assert_equal ["127.0.0.1:#{origin_port}"], tcp_seen

      # Failure stages: the proxy refusing (proxy) and no proxy at all (connect).
      error = assert_raises(Egress::DialError) { uds.dial("127.0.0.1", 1) }
      assert_match(/code 403/, error.message)
      gone = Egress::Dialer.new(protocol: "HTTPConnect", transport: "uds", uds_name: File.join(dir, "missing.sock"))
      assert_raises(Egress::DialError) { gone.dial("127.0.0.1", origin_port) }

      text = @metrics.render_own

      assert_match(/apiserver_egress_dialer_dial_start_total\{protocol="http-connect",transport="uds"\} 5/, text)
      assert_match(/apiserver_egress_dialer_dial_start_total\{protocol="http-connect",transport="tcp"\} 1/, text)
      assert_match(/apiserver_egress_dialer_dial_duration_seconds_count\{protocol="http-connect",transport="uds"\} 3/, text)
      assert_match(/apiserver_egress_dialer_dial_failure_count\{protocol="http-connect",stage="proxy",transport="uds"\} 1/, text)
      assert_match(/apiserver_egress_dialer_dial_failure_count\{protocol="http-connect",stage="connect",transport="uds"\} 1/, text)
    ensure
      [origin, uds_listener, tcp_listener].compact.each do |listener|
        listener.close
      rescue StandardError
        nil
      end
      [origin_thread, uds_thread, tcp_thread].compact.each(&:kill)
    end
  end

  def test_configuration_validation
    invalid = lambda do |document, pattern|
      error = assert_raises(Egress::Error) { Egress::Selector.from_h(document) }
      assert_match(pattern, error.message, error.message)
    end
    base = {"apiVersion" => "apiserver.k8s.io/v1beta1", "kind" => "EgressSelectorConfiguration"}
    invalid.call(base.merge("kind" => "Other", "egressSelections" => []), /kind must be EgressSelectorConfiguration/)
    invalid.call(base.merge("egressSelections" => [{"name" => "kubelet", "connection" => {"proxyProtocol" => "Direct"}}]),
                 /unrecognized service name/)
    invalid.call(base.merge("egressSelections" => [{"name" => "cluster", "connection" => {"proxyProtocol" => "Direct"}},
                                                   {"name" => "cluster",
                                                    "connection" => {"proxyProtocol" => "Direct"}}]), /Duplicate value/)
    invalid.call(base.merge("egressSelections" => [{"name" => "cluster", "connection" => {"proxyProtocol" => "Magic"}}]),
                 /unrecognized service connection protocol/)
    invalid.call(base.merge("egressSelections" => [{"name" => "cluster", "connection" => {"proxyProtocol" => "HTTPConnect"}}]),
                 /Either a TCP or UDS transport/)
    invalid.call(
      base.merge("egressSelections" => [{"name" => "cluster",
                                         "connection" => {"proxyProtocol" => "HTTPConnect",
                                                          "transport" => {"tcp" => {"url" => "https://proxy:8131"}}}}]), /tlsConfig: Required value/
    )
    invalid.call(
      base.merge("egressSelections" => [{"name" => "cluster",
                                         "connection" => {"proxyProtocol" => "GRPC",
                                                          "transport" => {"uds" => {"udsName" => "/run/k.sock"}}}}]), /GRPC.*not supported/
    )
    direct = Egress::Selector.from_h(base.merge("egressSelections" => [{"name" => "cluster",
                                                                        "connection" => {"proxyProtocol" => "Direct"}}]))

    assert_nil direct.dialer("cluster")
    Dir.mktmpdir do |dir|
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=client")
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
      cert.sign(key, "SHA256")
      File.write(File.join(dir, "c.crt"), cert.to_pem)
      File.write(File.join(dir, "c.key"), key.to_pem)
      File.write(File.join(dir, "ca.crt"), cert.to_pem)
      selector = Egress::Selector.from_h(base.merge("egressSelections" => [{"name" => "cluster", "connection" => {"proxyProtocol" => "HTTPConnect",
                                                                                                                  "transport" => {"tcp" => {"url" => "https://proxy.example:8131",
                                                                                                                                            "tlsConfig" => {
                                                                                                                                              "caBundle" => File.join(dir,
                                                                                                                                                                      "ca.crt"), "clientCert" => File.join(dir, "c.crt"), "clientKey" => File.join(dir, "c.key"), "tlsServerName" => "proxy"
                                                                                                                                            }}}}}]))
      dialer = selector.dialer("cluster")

      assert_equal "proxy.example:8131", dialer.proxy_address
      assert_equal "tcp", dialer.transport
      assert_equal "http-connect", dialer.metric_protocol
    end
  end
end
