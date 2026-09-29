# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

# Pure-Ruby protobuf encoding costs ~1.8 ms for a Pod, and a stored object is
# encoded again and again (its write's response, every GET, each protobuf
# watcher's event).  An object frozen all the way down is encoded once.
class ProtobufEncodeCacheTest < Minitest::Test
  Codec = Rubernetes::Schema::Codec::KubernetesProtobuf

  def pod(name)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => "ns"},
     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}}
  end

  def test_a_deep_frozen_object_is_encoded_once
    codec = Codec.new
    stored = Rubernetes::Schema::DeepFreeze.call(pod("a"))
    first = codec.encode(stored)

    assert_same first, codec.encode(stored)
    assert first.frozen?
    assert_equal codec.encode(JSON.parse(JSON.generate(stored))), first
  end

  def test_a_store_frozen_object_is_cached_too
    stored = Rubernetes::Storage::MemoryStoreSupport.deep_freeze(pod("b"))
    codec = Codec.new
    assert_same codec.encode(stored), codec.encode(stored)
  end

  # A mutable (or only shallowly frozen) object may change between calls.
  def test_mutable_objects_are_encoded_every_time
    codec = Codec.new
    object = pod("c")
    first = codec.encode(object)
    object["metadata"]["name"] = "changed"
    second = codec.encode(object)

    refute_equal first, second
    shallow = pod("d").freeze
    refute_same codec.encode(shallow), codec.encode(shallow)
  end

  def test_field_keys_and_small_varints_are_shared_and_frozen
    wire = Rubernetes::Schema::Codec::Protobuf
    key = wire.encode_key(1, 2)
    assert_equal "\x0a".b, key
    assert key.frozen?
    assert_same key, wire.encode_key(1, 2)
    assert_equal "\x96\x01".b, wire.encode_varint(150)
    assert_equal "\x7f".b, wire.encode_varint(127)
    assert_equal [150, 2], wire.read_varint("\x96\x01".b, offset: 0, max_bits: 64, strict: true)
    assert_equal [5, 1], wire.read_varint("\x05".b, offset: 0, max_bits: 64, strict: true)
  end
end

