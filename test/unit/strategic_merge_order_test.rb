# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# Merged list order follows strategicpatch.normalizeElementOrder: patch items
# in patch order, server-only items slotted in by their live order.
class StrategicMergeOrderTest < Minitest::Test
  Patch = Rubernetes::API::Patch

  def names(object) = object.dig("spec", "containers").map { |container| container["name"] }

  def merge(containers, patch_containers, extra = {})
    Patch.apply_strategic_merge({"spec" => {"containers" => containers}},
                                {"spec" => {"containers" => patch_containers}.merge(extra)})
  end

  def test_a_new_patch_item_precedes_server_only_items
    merged = merge([{"name" => "agnhost", "image" => "a"}], [{"name" => "test-rs", "image" => "pause"}])

    assert_equal %w[test-rs agnhost], names(merged)
    assert_equal "pause", merged.dig("spec", "containers", 0, "image")
  end

  def test_existing_items_keep_their_live_order_around_patch_items
    live = %w[a b c d].map { |name| {"name" => name} }
    # server-only [a b d] merge into patch [c x] by live order; x is unknown
    # to the server, so it is taken before d.
    assert_equal %w[a b c x d], names(merge(live, [{"name" => "c"}, {"name" => "x"}]))
  end

  def test_set_element_order_and_delete
    live = %w[a b c].map { |name| {"name" => name} }
    merged = merge(live, [{"name" => "b", "$patch" => "delete"}],
                   "$setElementOrder/containers" => [{"name" => "c"}, {"name" => "a"}])

    assert_equal %w[c a], names(merged)
    refute merged["spec"].key?("$setElementOrder/containers")
  end
end
