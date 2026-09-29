# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/watch"

# The sorted list is computed once per mutation, not once per reader.
class IndexerSortedListMemoTest < Minitest::Test
  def object(name, ns = "ns")
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name, "namespace" => ns, "resourceVersion" => "1"}}
  end

  def test_the_list_is_reused_until_a_mutation
    indexer = Rubernetes::Watch::Indexer.new
    indexer.upsert(object("b"))
    indexer.upsert(object("a"))

    first = indexer.list
    assert_same first, indexer.list, "no mutation, same array"
    assert_equal %w[a b], first.map { |o| o.dig("metadata", "name") }
    assert first.frozen?

    indexer.upsert(object("c"))
    second = indexer.list
    refute_same first, second
    assert_equal %w[a b c], second.map { |o| o.dig("metadata", "name") }

    indexer.delete("ns/a")
    assert_equal %w[b c], indexer.list.map { |o| o.dig("metadata", "name") }
    indexer.replace_all([object("z")])
    assert_equal %w[z], indexer.list.map { |o| o.dig("metadata", "name") }
    indexer.clear
    assert_empty indexer.list
  end
end
