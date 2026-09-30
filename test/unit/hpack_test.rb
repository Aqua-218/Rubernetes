# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/transport/hpack"

# HPACK against the RFC 7541 appendix C examples: integers, literal and
# Huffman strings, and the dynamic table across a connection's requests.
class HPACKTest < Minitest::Test
  HPACK = Rubernetes::Transport::HPACK

  def hex(text) = [text.delete(" \n")].pack("H*")

  def test_integer_examples
    assert_equal "\x0a".b, HPACK.encode_integer(10, 5, 0)
    assert_equal "\x1f\x9a\x0a".b, HPACK.encode_integer(1337, 5, 0)
    assert_equal [1337, 3], HPACK.decode_integer("\x1f\x9a\x0a".b, 0, 5)
    assert_equal [42, 1], HPACK.decode_integer("\x2a".b, 0, 8)
  end

  def test_requests_without_huffman_share_the_dynamic_table
    decoder = HPACK::Decoder.new
    first = decoder.decode(hex("828684410f7777772e6578616d706c652e636f6d"))

    assert_equal [[":method", "GET"], [":scheme", "http"], [":path", "/"], [":authority", "www.example.com"]], first
    second = decoder.decode(hex("828684be58086e6f2d6361636865"))

    assert_equal %w[cache-control no-cache], second.last
    third = decoder.decode(hex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"))

    assert_equal [[":method", "GET"], [":scheme", "https"], [":path", "/index.html"],
                  [":authority", "www.example.com"], ["custom-key", "custom-value"]], third
  end

  def test_requests_with_huffman
    decoder = HPACK::Decoder.new
    decoder.decode(hex("828684418cf1e3c2e5f23a6ba0ab90f4ff"))
    decoder.decode(hex("828684be5886a8eb10649cbf"))
    third = decoder.decode(hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"))

    assert_equal %w[custom-key custom-value], third.last
  end

  def test_responses_evict_from_a_small_table
    decoder = HPACK::Decoder.new(max_table_size: 256)
    decoder.decode(hex(<<~HEX))
      4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d
    HEX
    second = decoder.decode(hex("4803333037c1c0bf"))

    assert_equal [":status", "307"], second.first
    assert_equal ["location", "https://www.example.com"], second.last
  end

  def test_invalid_input_is_rejected
    assert_raises(HPACK::DecodingError) { HPACK::Decoder.new.decode("\x80".b) }
    assert_raises(HPACK::DecodingError) { HPACK::Decoder.new.decode("\xff\x7f".b) }
    # Huffman padding longer than 7 bits.
    assert_raises(HPACK::DecodingError) { HPACK.huffman_decode("\xff\xff".b) }
    # A table size update above the protocol maximum.
    assert_raises(HPACK::DecodingError) { HPACK::Decoder.new.decode(HPACK.encode_integer(8192, 5, 0x20)) }
  end

  def test_encoder_output_decodes
    fields = [[":status", "200"], [":status", "418"], ["content-type", "application/json"], ["x-long", "v" * 300]]

    assert_equal fields, HPACK::Decoder.new.decode(HPACK::Encoder.encode(fields))
  end
end
