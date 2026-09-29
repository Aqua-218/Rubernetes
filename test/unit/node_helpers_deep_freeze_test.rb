# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# Helpers.immutable re-froze every cached Pod on every sync, walking the whole
# object each time.  A value already frozen all the way down is returned as is.
class NodeHelpersDeepFreezeTest < Minitest::Test
  Helpers = Rubernetes::Node::Helpers

  class CountingHash < Hash
    attr_reader :walks

    def each(...)
      @walks = (@walks || 0) + 1
      super
    end
  end

  def test_a_deeply_frozen_value_is_not_walked_again
    value = CountingHash.new
    value["spec"] = {"containers" => [{"name" => "c"}]}
    Helpers.deep_freeze(value)
    walks = value.walks
    Helpers.deep_freeze(value)

    assert_equal walks, value.walks
    assert Helpers.deep_frozen?(value)
    assert value.dig("spec", "containers", 0, "name").frozen?
  end

  def test_a_merely_frozen_value_is_still_frozen_all_the_way_down
    inner = {"name" => +"c"}
    value = {"containers" => [inner]}.freeze
    Helpers.deep_freeze(value)

    assert inner.frozen?
    assert inner["name"].frozen?
  end
end

# A value Helpers.immutable already produced is returned as it is; anything
# else is copied (string keys) and frozen as before.
class NodeHelpersImmutableTest < Minitest::Test
  Helpers = Rubernetes::Node::Helpers

  def test_an_immutable_value_is_not_rebuilt
    source = {metadata: {name: "p"}, "spec" => {"containers" => [{"name" => "c"}]}}
    first = Helpers.immutable(source)

    assert_equal({"metadata" => {"name" => "p"}, "spec" => {"containers" => [{"name" => "c"}]}}, first)
    assert first.frozen?
    refute_same source, first
    assert_same first, Helpers.immutable(first)
    assert Helpers.immutable?(first)
    refute Helpers.immutable?(source)
  end
end
