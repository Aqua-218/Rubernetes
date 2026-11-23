# frozen_string_literal: true

require "timeout"
require_relative "../test_helper"
require "rubernetes/api"

class APIWatchWebSocketTest < Minitest::Test
  PATH = "/api/v1/namespaces/default/configmaps"
  HEADERS = {"Connection" => "Upgrade", "Upgrade" => "websocket", "Sec-WebSocket-Version" => "13",
             "Sec-WebSocket-Key" => "dGhlIHNhbXBsZSBub25jZQ==", "Origin" => "https://api.example.test"}.freeze

  def setup
    @server = Rubernetes::API::Server.new
  end

  def test_matches_upstream_watch_handshake
    missing = HEADERS.reject { |key| key == "Origin" }

    assert_equal(403, watch(headers: missing).status)
    assert_equal(400, watch(headers: HEADERS.merge("Sec-WebSocket-Protocol" => "one, two")).status)
    response = watch(headers: HEADERS.merge("Sec-WebSocket-Protocol" => "one"))

    assert_equal(101, response.status)
    assert_equal("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", response.header("sec-websocket-accept"))
    assert_equal("one", response.header("sec-websocket-protocol"))
    http_watch = watch(headers: {})

    assert_equal(200, http_watch.status)
  ensure
    response&.upgrade&.close
    http_watch&.body&.close
  end

  def test_sends_live_json_event_and_releases_idle_watch_on_peer_close
    response = watch
    server_socket, client_socket = Socket.pair(:UNIX, :STREAM)
    worker = Thread.new { response.upgrade.call(server_socket, nil) }
    client = Rubernetes::Transport::WebSocket::Connection.new(client_socket, client: true)
    created = @server.call(method: "POST", path: PATH, body: {"metadata" => {"name" => "live"}})

    assert_equal(201, created.status)
    message = Timeout.timeout(3) { client.read_message }

    assert_predicate(message, :text?)
    event = JSON.parse(message.payload)

    assert_equal("ADDED", event.fetch("type"))
    assert_equal("live", event.dig("object", "metadata", "name"))
    client.close

    assert(worker.join(3), "watch worker should exit on client close without waiting for another event")
  ensure
    worker&.kill
    response&.upgrade&.close
    server_socket&.close
    client_socket&.close
  end

  private

  def watch(headers: HEADERS)
    @server.call(method: "GET", path: PATH, headers: headers, query: {"watch" => "true"})
  end
end
