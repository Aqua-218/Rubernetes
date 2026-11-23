# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap/control_plane_services"

# The response to a controller's own write goes straight into the informer
# cache.  Removing the last finalizer of a PersistentVolumeClaim under
# deletion answers with the claim; when that answer was processed after the
# claim's DELETED event, the claim was back in the cache for good and its
# volume stayed Bound to a claim that no longer existed.
class InformerWriteThroughUpdateTest < Minitest::Test
  Informer = Struct.new(:indexer)

  def claim(version, **metadata)
    {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
     "metadata" => {"name" => "data", "namespace" => "shop", "resourceVersion" => version}.merge(metadata.transform_keys(&:to_s))}
  end

  def setup
    @indexer = Rubernetes::Watch::Indexer.new
    @cache = Rubernetes::Bootstrap::InformerCache.new(Informer.new(@indexer))
  end

  def cached = @cache.list.map { |object| object.dig("metadata", "resourceVersion") }

  def test_a_response_brings_the_entry_it_is_about_up_to_date
    @indexer.add(claim("5"))
    @cache.update(claim("6"))

    assert_equal ["6"], cached
  end

  def test_a_response_that_arrives_after_the_deletion_does_not_bring_the_object_back
    @indexer.add(claim("5"))
    @indexer.delete(claim("5"))
    @cache.update(claim("6"))

    assert_empty cached
  end

  def test_a_response_older_than_what_the_watch_already_delivered_is_ignored
    @indexer.add(claim("9"))
    @cache.update(claim("6"))

    assert_equal ["9"], cached
  end

  # The API server deletes the object in the very request that answers.
  def test_the_response_to_removing_the_last_finalizer_removes_the_entry
    @indexer.add(claim("5", deletionTimestamp: "2026-11-11T16:21:07Z", finalizers: ["kubernetes.io/pvc-protection"]))
    @cache.update(claim("6", deletionTimestamp: "2026-11-11T16:21:07Z", finalizers: []))

    assert_empty cached
  end

  def test_an_object_under_deletion_that_still_has_a_finalizer_or_a_grace_period_stays
    @indexer.add(claim("5"))
    @cache.update(claim("6", deletionTimestamp: "2026-11-11T16:21:07Z", finalizers: ["example.com/hold"]))

    assert_equal ["6"], cached

    @cache.update(claim("7", deletionTimestamp: "2026-11-11T16:21:07Z", deletionGracePeriodSeconds: 30))

    assert_equal ["7"], cached
  end

  def test_namespace_status_write_preserves_the_object_while_its_spec_finalizer_remains
    namespace = {"apiVersion" => "v1", "kind" => "Namespace",
                 "metadata" => {"name" => "shop", "resourceVersion" => "5"},
                 "spec" => {"finalizers" => ["kubernetes"]}}
    @indexer.add(namespace)
    terminating = namespace.merge("metadata" => namespace.fetch("metadata").merge(
      "resourceVersion" => "6", "deletionTimestamp" => "2026-11-11T16:21:07Z"
    ))
    @cache.update(terminating)

    assert_equal ["6"], cached

    @cache.update(terminating.merge("metadata" => terminating.fetch("metadata").merge("resourceVersion" => "7"),
                                    "spec" => {"finalizers" => []}))

    assert_empty cached
  end

  # A created object is not in the cache yet; that is what `add` is for.
  def test_a_created_object_is_still_written_through
    @cache.add(claim("5"))

    assert_equal ["5"], cached
  end
end
