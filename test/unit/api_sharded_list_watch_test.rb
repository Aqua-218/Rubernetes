# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class APIShardedListWatchTest < Minitest::Test
  API = Rubernetes::API
  PATH = "/api/v1/namespaces/team/configmaps"
  ALL = "shardRange(object.metadata.uid, '0x0000000000000000', '0x10000000000000000')"
  LOWER = "shardRange(object.metadata.uid, '0x0000000000000000', '0x8000000000000000')"
  UPPER = "shardRange(object.metadata.uid, '0x8000000000000000', '0x10000000000000000')"

  # Membership below was observed with kube-apiserver v1.36.2 using these UIDs.
  LOWER_UID = "9705ff52-287c-445c-9f5d-94001c2820e7"
  UPPER_UID = "ccc59b24-ac11-4954-b7f8-149b8a382e58"

  def test_disabled_gate_ignores_even_an_invalid_selector
    setup_server(API::MemoryStore.new, enabled: false)

    assert_equal 201, create("a", UPPER_UID).status

    list = request("GET", PATH, "shardSelector" => "unsupported()")

    assert_equal 200, list.status
    assert_equal ["a"], item_names(list)
    refute list.body.fetch("metadata").key?("shardInfo")
  end

  def test_list_partitions_uid_ranges_and_intersects_other_selectors
    each_store do
      assert_equal 201, create("a", UPPER_UID, "role" => "blue").status
      assert_equal 201, create("b", LOWER_UID, "role" => "green").status
      assert_equal 201, create("c", LOWER_UID, "role" => "blue").status
      assert_equal 201, create("outside", LOWER_UID, path: PATH.sub("/team/", "/team-extra/")).status

      lower = request("GET", PATH, "shardSelector" => LOWER)

      assert_equal %w[b c], item_names(lower)
      assert_equal({"selector" => LOWER}, lower.body.dig("metadata", "shardInfo"))
      assert_equal ["a"], item_names(request("GET", PATH, "shardSelector" => UPPER))
      union = request("GET", PATH, "shardSelector" => "(#{LOWER})||#{UPPER.tr("'", '"')}")

      assert_equal %w[a b c], item_names(union)
      assert_equal "#{LOWER} || #{UPPER}", union.body.dig("metadata", "shardInfo", "selector")
      intersected = request("GET", PATH, "shardSelector" => LOWER, "labelSelector" => "role=blue", "fieldSelector" => "metadata.name=c")

      assert_equal ["c"], item_names(intersected)
    end
  end

  def test_range_bounds_use_the_hash_of_the_namespace_and_are_half_open
    each_store do
      assert_equal 201, create("one", UPPER_UID, path: PATH.sub("/team/", "/default/")).status
      assert_equal 201, create("two", LOWER_UID, path: PATH.sub("/team/", "/other/")).status
      # Go hash/fnv New64a("default") is 0xebada5168620c5fe.
      lower = "shardRange(object.metadata.namespace, '0xebada5168620c5fe', '0xebada5168620c5ff')"
      upper = "shardRange(object.metadata.namespace, '0x0000000000000000', '0xebada5168620c5fe')"

      assert_equal ["one"], item_names(request("GET", "/api/v1/configmaps", "shardSelector" => lower))
      refute_includes item_names(request("GET", "/api/v1/configmaps", "shardSelector" => upper)), "one"
    end
  end

  def test_paginated_list_preserves_its_snapshot_and_reports_upstream_remaining_count
    each_store do
      create("a", UPPER_UID)
      create("b", LOWER_UID)
      create("c", LOWER_UID)
      create("d", UPPER_UID)
      options = {"shardSelector" => LOWER, "limit" => "1"}
      first = request("GET", PATH, options)

      assert_equal ["b"], item_names(first)
      assert_equal 3, first.body.dig("metadata", "remainingItemCount")
      assert_equal %w[b c], item_names(request("GET", PATH, options.merge("resourceVersion" => "0")))
      filtered = request("GET", PATH, options.merge("labelSelector" => "role!=missing"))

      refute filtered.body.fetch("metadata").key?("remainingItemCount")

      create("bb", LOWER_UID)
      request("DELETE", "#{PATH}/c")
      create("c", UPPER_UID)
      second = request("GET", PATH, options.merge("continue" => first.body.dig("metadata", "continue")))

      assert_equal ["c"], item_names(second)
      assert_equal first.body.dig("metadata", "resourceVersion"), second.body.dig("metadata", "resourceVersion")
      assert_equal 1, second.body.dig("metadata", "remainingItemCount")

      final = request("GET", PATH, options.merge("continue" => second.body.dig("metadata", "continue")))

      assert_empty item_names(final)
      refute final.body.fetch("metadata").key?("continue")
      assert_equal LOWER, final.body.dig("metadata", "shardInfo", "selector")
    end
  end

  def test_initial_events_and_live_events_apply_the_shard_and_preserve_bookmarks
    each_store do
      create("a", UPPER_UID)
      create("b", LOWER_UID)
      response = request("GET", PATH, "watch" => "true", "shardSelector" => LOWER, "sendInitialEvents" => "true",
                                      "resourceVersionMatch" => "NotOlderThan", "allowWatchBookmarks" => "true")

      assert_equal 200, response.status
      watch = response.body
      labels = '{group="",resource="configmaps"}'

      assert_includes @server.metrics.render, "apiserver_watch_shards_total#{labels} 1\n"
      create("c", UPPER_UID)
      create("d", LOWER_UID)
      request("DELETE", "#{PATH}/b")

      initial = watch.next(timeout: 0)

      assert_equal %w[ADDED b], [initial.type, initial.object.dig("metadata", "name")]
      bookmark = watch.next(timeout: 0)

      assert_equal "BOOKMARK", bookmark.type
      assert_equal "true", bookmark.object.dig("metadata", "annotations", "k8s.io/initial-events-end")
      added = watch.next(timeout: 0)

      assert_equal %w[ADDED d], [added.type, added.object.dig("metadata", "name")]
      deleted = watch.next(timeout: 0)

      assert_equal %w[DELETED b], [deleted.type, deleted.object.dig("metadata", "name")]
      assert_nil watch.next(timeout: 0)
      assert_includes @server.metrics.render, "apiserver_watch_filtered_events_total#{labels} 1\n"
      watch.close

      assert_includes @server.metrics.render, "apiserver_watch_shards_total#{labels} 0\n"
    ensure
      watch&.close
    end
  end

  def test_unknown_and_malformed_selectors_return_the_pinned_status_on_list_and_watch
    setup_server(API::MemoryStore.new)
    selectors = {
      " " => "empty shard selector is not allowed; omit the parameter for unfiltered lists",
      "aaa()" => 'unsupported function "aaa"; only shardRange() and || are allowed',
      "true" => "unexpected expression kind 5; expected shardRange() call or || operator",
      LOWER.sub("0x0000000000000000", "0x0") => 'hexStart must be a 0x-prefixed 16-digit hex value, got "0x0" ' \
                                                '(did you mean "0x0000000000000000"?)',
      LOWER.sub("0x0000000000000000", "0x8000000000000000") => "shard range start 0x8000000000000000 must be less than " \
                                                               "end 0x8000000000000000",
      "#{LOWER} || #{UPPER.sub(".uid", ".namespace")}" => "all shard ranges must use the same field, " \
                                                          'got "object.metadata.uid" and "object.metadata.namespace"'
    }
    selectors.each do |expression, message|
      %w[true false].each do |watch|
        response = request("GET", PATH, "shardSelector" => expression, "watch" => watch)

        assert_equal 500, response.status
        assert_equal "invalid shard selector: #{message}", response.body.fetch("message")
        refute response.body.key?("reason")
      end
    end
  end

  def test_builtin_protobuf_lists_preserve_metadata_while_partial_metadata_lists_omit_it
    setup_server(API::MemoryStore.new)
    create("a", LOWER_UID)
    protobuf = request("GET", PATH, {"shardSelector" => LOWER}, accept: "application/vnd.kubernetes.protobuf")

    assert_equal 200, protobuf.status
    body = Rubernetes::Schema::Codec::KubernetesProtobuf.new.decode(protobuf.body)

    assert_equal LOWER, body.dig("metadata", "shardInfo", "selector")

    partial = request("GET", PATH, {"shardSelector" => LOWER}, accept: "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")

    assert_equal ["a"], item_names(partial)
    refute partial.body.fetch("metadata").key?("shardInfo")
  end

  def test_delete_collection_uses_shard_and_limit_and_returns_the_selected_list
    each_store do
      create("a", UPPER_UID)
      create("b", LOWER_UID)
      create("c", LOWER_UID)

      deleted = request("DELETE", PATH, "shardSelector" => LOWER, "limit" => "1")

      assert_equal 200, deleted.status
      assert_equal "ConfigMapList", deleted.body.fetch("kind")
      assert_equal ["b"], item_names(deleted)
      assert_equal LOWER, deleted.body.dig("metadata", "shardInfo", "selector")
      assert_equal %w[a c], item_names(request("GET", PATH))
    end
  end

  private

  def each_store
    [API::MemoryStore.new, Rubernetes::Storage::MemoryStore.new].each do |store|
      setup_server(store)
      yield
    end
  end

  def setup_server(store, enabled: true)
    @server = API::Server.new(store: store, feature_gates: {"ShardedListAndWatch" => enabled}, uid_generator: -> { @next_uid })
  end

  def request(method, path, query = {}, body: nil, accept: nil, **parameters)
    path = "#{path}?#{URI.encode_www_form(query.merge(parameters))}" unless query.empty? && parameters.empty?
    headers = accept ? {"accept" => accept} : {}
    @server.call(API::Request.new(method: method, path: path, body: body, headers: headers))
  end

  def create(name, uid, labels = {}, path: PATH, **label_keywords)
    @next_uid = uid
    request("POST", path, body: {"metadata" => {"name" => name, "labels" => labels.merge(label_keywords)}})
  end

  def item_names(response)
    assert_equal 200, response.status, response.body.inspect
    response.body.fetch("items").map { |item| item.dig("metadata", "name") }
  end
end
