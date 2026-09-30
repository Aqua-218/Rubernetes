# frozen_string_literal: true

require_relative "../test_helper"
require "socket"
require "rubernetes/api"

# The pods/services/nodes proxy formats an IPv6 target as "[addr]" for the
# URL (format_proxy_host), and URI#host keeps those brackets, which
# getaddrinfo cannot resolve: every proxy request to an IPv6 Pod answered 500
# on the linux-amd64-ipv6-native profile ("[sig-network] Proxy version v1 A
# set of valid responses are returned for both pod and service Proxy").  The
# socket must be opened on URI#hostname, the bare address.
class APIProxyIPv6TargetTest < Minitest::Test
  def server = Rubernetes::API::Server.allocate

  def test_an_ipv6_proxy_target_is_dialled_at_the_bare_address
    listener = TCPServer.new("::1", 0)
    port = listener.addr[1]
    uri = URI("http://#{server.send(:format_proxy_host, "::1")}:#{port}/healthz")

    assert_equal "[::1]", uri.host, "URI keeps the brackets the proxy URL needs"

    socket = server.send(:open_proxy_socket, uri)
    accepted = listener.accept

    assert_equal "::1", accepted.remote_address.ip_address
  ensure
    socket&.close
    accepted&.close
    listener&.close
  end

  def test_an_ipv4_proxy_target_still_dials
    listener = TCPServer.new("127.0.0.1", 0)
    uri = URI("http://#{server.send(:format_proxy_host, "127.0.0.1")}:#{listener.addr[1]}/")
    socket = server.send(:open_proxy_socket, uri)
    accepted = listener.accept

    assert_equal "127.0.0.1", accepted.remote_address.ip_address
  ensure
    socket&.close
    accepted&.close
    listener&.close
  end
end
