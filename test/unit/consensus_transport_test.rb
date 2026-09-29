# frozen_string_literal: true

require "stringio"
require_relative "../test_helper"
require "rubernetes/consensus"

class ConsensusTransportTest < Minitest::Test
  C = Rubernetes::Consensus
  Framing = C::Transport::Framing

  def test_frame_round_trip
    frame = Framing.encode(1, "payload")
    io = StringIO.new(frame + Framing.encode(1, ""))
    assert_equal [1, "payload"], Framing.read(io)
    assert_equal [1, ""], Framing.read(io)
    assert_nil Framing.read(io)
  end

  # A CRD description with non-ASCII text made the JSON payload UTF-8 while the
  # header is BINARY; String#+ raised Encoding::CompatibilityError inside the
  # leader's inbound thread and every forwarded read then timed out.
  def test_non_ascii_payload_is_framed_as_bytes
    payload = "{\"description\":\"brackets — e.g [2001:db8::1] — 日本語\"}"
    frame = Framing.encode(1, payload)
    assert_equal Encoding::BINARY, frame.encoding
    assert_equal 5 + payload.bytesize, frame.bytesize
    type, read_back = Framing.read(StringIO.new(frame))
    assert_equal 1, type
    assert_equal payload.b, read_back
    assert_equal payload, read_back.force_encoding(Encoding::UTF_8)
  end

  # A defect raised while handling one message is logged and the connection
  # keeps serving; before, the inbound thread died and took the leader with it.
  def test_a_handler_error_does_not_end_the_inbound_connection
    ca, ca_key = C::Identity.generate_ca("c1")
    a = C::Identity.issue_node(ca, ca_key, cluster_id: "c1", node_id: "a")
    b = C::Identity.issue_node(ca, ca_key, cluster_id: "c1", node_id: "b")
    received = Queue.new
    logged = Queue.new
    logger = Object.new
    logger.define_singleton_method(:error) { |event, **fields| logged << [event, fields] }
    %i[warn info debug].each { |level| logger.define_singleton_method(level) { |*_args, **_fields| nil } }
    server = C::Transport::Endpoint.new(node_id: "b", cluster_id: "c1", bundle: b, logger: logger)
    server.on_message do |message, _identity|
      raise Encoding::CompatibilityError, "injected handler defect" if message.request_id == "boom"

      received << message
    end
    server.start
    begin
      client = C::Transport::Endpoint.new(node_id: "a", cluster_id: "c1", bundle: a, peers: {"b" => server.address}).start
      client.send(C::Messages::TimeoutNow.new(cluster_id: "c1", from: "a", to: "b", term: 1, request_id: "boom"))
      client.send(C::Messages::TimeoutNow.new(cluster_id: "c1", from: "a", to: "b", term: 1, request_id: "after"))
      assert_equal "after", received.pop.request_id
      event, fields = logged.pop
      assert_equal "consensus.transport.handler_error", event
      assert_match(/Encoding::CompatibilityError: injected handler defect/, fields.fetch(:error))
      assert_equal 1, server.stats.fetch(:handler_errors)
      client.stop
    ensure
      server.stop
    end
  end

  def test_length_is_checked_before_allocation
    io = StringIO.new([C::Transport::MAX_FRAME_BYTES + 1, 1].pack("NC"))
    assert_raises(C::FrameTooLarge) { Framing.read(io) }
    assert_raises(C::FrameTooLarge) { Framing.encode(1, "x" * (C::Transport::MAX_FRAME_BYTES + 1)) }
    truncated = StringIO.new([10, 1].pack("NC") + "abc")
    assert_raises(C::ProtocolError) { Framing.read(truncated) }
  end

  def test_peer_identity_is_taken_from_the_verified_certificate
    ca, ca_key = C::Identity.generate_ca("cluster-a")
    bundle = C::Identity.issue_node(ca, ca_key, cluster_id: "cluster-a", node_id: "node-1")
    assert_equal({cluster_id: "cluster-a", node_id: "node-1"}, C::Identity.peer_identity(bundle.certificate))
    assert_raises(C::PeerIdentityMismatch) { C::Identity.peer_identity(ca) }
    assert_raises(ArgumentError) { C::Identity.issue_node(ca, ca_key, cluster_id: "bad id", node_id: "n") }
  end

  def test_endpoint_rejects_foreign_cluster_and_spoofed_sender
    ca, ca_key = C::Identity.generate_ca("c1")
    other_ca, other_key = C::Identity.generate_ca("c2")
    a = C::Identity.issue_node(ca, ca_key, cluster_id: "c1", node_id: "a")
    b = C::Identity.issue_node(ca, ca_key, cluster_id: "c1", node_id: "b")
    foreign = C::Identity.issue_node(other_ca, other_key, cluster_id: "c2", node_id: "a")
    received = Queue.new
    server = C::Transport::Endpoint.new(node_id: "b", cluster_id: "c1", bundle: b)
    server.on_message { |message, identity| received << [message, identity] }
    server.start
    begin
      client = C::Transport::Endpoint.new(node_id: "a", cluster_id: "c1", bundle: a, peers: {"b" => server.address}).start
      client.send(C::Messages::TimeoutNow.new(cluster_id: "c1", from: "a", to: "b", term: 1, request_id: "r1"))
      message, identity = received.pop
      assert_equal "a", message.from
      assert_equal({cluster_id: "c1", node_id: "a"}, identity)
      # A message whose payload claims a different sender than the certificate is rejected.
      assert_raises(C::ProtocolError) { client.send(C::Messages::TimeoutNow.new(cluster_id: "c1", from: "z", to: "b", term: 1, request_id: "r2")) }
      client.stop

      intruder = C::Transport::Endpoint.new(node_id: "a", cluster_id: "c2", bundle: foreign, peers: {"b" => server.address}).start
      intruder.send(C::Messages::TimeoutNow.new(cluster_id: "c2", from: "a", to: "b", term: 1, request_id: "r3"))
      sleep 0.3
      assert received.empty?, "foreign cluster message must not be delivered"
      intruder.stop
    ensure
      server.stop
    end
  end
end
