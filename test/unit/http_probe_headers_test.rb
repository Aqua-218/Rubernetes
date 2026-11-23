# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/probe_connectors"
require "rubernetes/platform/linux/native_adapters"

class HTTPProbeHeadersTest < Minitest::Test
  Connector = Rubernetes::Platform::Linux::NativeAdapters::NamespaceConnector

  def test_connectors_send_one_virtual_host_and_preserve_repeated_header_lines
    fields = {"host" => "catalog.example.test", "X-Group" => %w[primary fallback], "User-Agent" => "", "Accept" => ""}
    requests = [
      capture { |port| Connector.blocking_http_get("127.0.0.1", port, "/ready", fields, 2) },
      capture { |port| Rubernetes::Node::ProbeConnectors::HTTP.new.get("http://127.0.0.1:#{port}/ready", headers: fields, timeout: 2) }
    ]
    requests.each do |lines|
      assert_equal ["host: catalog.example.test"], lines.grep(/\Ahost:/)
      assert_equal ["x-group: primary", "x-group: fallback"], lines.grep(/\Ax-group:/)
      assert_empty lines.grep(/\A(user-agent|accept|accept-encoding):/)
    end
  end

  private

  def capture
    server = TCPServer.new("127.0.0.1", 0)
    listener = Thread.new do
      peer = server.accept
      headers = []
      peer.each_line do |line|
        break if line == "\r\n"

        headers << line.chomp.downcase
      end
      peer.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      headers
    ensure
      peer&.close
    end
    response = yield server.addr[1]

    assert_equal 200, response.fetch("status")
    listener.value
  ensure
    server&.close
    listener&.join(2)
  end
end
