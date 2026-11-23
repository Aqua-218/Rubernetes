# frozen_string_literal: true

require "base64"
require "net/http"
require "tmpdir"
require "zlib"

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/consensus"
require "rubernetes/transport/http_server"

class APIServerCBORTest < Minitest::Test
  API = Rubernetes::API
  CBOR = Rubernetes::Schema::Codec::KubernetesCBOR
  Consensus = Rubernetes::Consensus
  CONFIG_MAPS = "/api/v1/namespaces/default/configmaps"
  WIDGETS = "/apis/example.test/v1/widgets"

  def setup
    @servers = []
  end

  def teardown
    @servers.reverse_each(&:stop)
  end

  def test_disabled_gate_rejects_cbor_writes_and_negotiation_without_mutating
    http, _api = serve(enabled: false)
    document = config_map("disabled")

    assert_equal "415", request(http, "POST", CONFIG_MAPS, body: CBOR.encode(document), media_type: CBOR::CONTENT_TYPE).code
    assert_equal "415", request(http, "PATCH", "#{CONFIG_MAPS}/disabled?fieldManager=test",
                                body: CBOR.encode(document), media_type: CBOR::APPLY_CONTENT_TYPE).code
    assert_equal "406", request(http, "POST", CONFIG_MAPS, body: JSON.generate(document), media_type: "application/json",
                                                           accept: CBOR::CONTENT_TYPE).code
    assert_equal "404", request(http, "GET", "#{CONFIG_MAPS}/disabled").code
    assert_equal "406", request(http, "GET", CONFIG_MAPS, accept: CBOR::CONTENT_TYPE).code
    assert_equal "200", request(http, "GET", CONFIG_MAPS, accept: "application/cbor, application/json;q=0.9").code
    assert_equal "406", request(http, "GET", "/api/v1", accept: CBOR::CONTENT_TYPE).code
  end

  def test_builtin_resource_read_reports_route_error_for_unadvertised_accept
    [false, true].each do |enabled|
      http, _api = serve(enabled: enabled)
      created = request(http, "POST", CONFIG_MAPS, body: JSON.generate(config_map("media")), media_type: "application/json")

      assert_equal "201", created.code
      available = %w[application/json application/yaml application/vnd.kubernetes.protobuf]
      available << CBOR::CONTENT_TYPE if enabled
      rejected = ["not-a-media-type", "application/x-unsupported", "application/*"]
      rejected << CBOR::CONTENT_TYPE unless enabled
      rejected.each do |accept|
        response = request(http, "GET", "#{CONFIG_MAPS}/media", accept: accept)
        status = JSON.parse(response.body)

        assert_equal "406", response.code, accept
        assert_equal "application/json", response["content-type"]
        assert_equal ["Status", "NotAcceptable", 406, {}], status.values_at("kind", "reason", "code", "details")
        assert_equal "406: Not Acceptable\n\nAvailable representations: #{available.join(", ")}", status.fetch("message")
      end
    end
  end

  def test_tagged_objects_list_metadata_apply_and_invalid_input
    http, _api = serve
    document = config_map("cbor")
    create = request(http, "POST", CONFIG_MAPS, body: CBOR.encode(document), media_type: CBOR::CONTENT_TYPE, accept: CBOR::CONTENT_TYPE)

    assert_equal "201", create.code
    assert_equal CBOR::CONTENT_TYPE, create["content-type"]
    assert create.body.start_with?(CBOR::PREFIX)
    created = CBOR.decode(create.body)

    assert_equal document["data"], created["data"]

    path = "#{CONFIG_MAPS}/cbor"
    annotated = created.merge("metadata" => created["metadata"].merge("annotations" => {"test" => "updated"}))
    update = request(http, "PUT", path, body: CBOR.encode(annotated), media_type: CBOR::CONTENT_TYPE, accept: CBOR::CONTENT_TYPE)

    assert_equal "200", update.code
    assert_equal "updated", CBOR.decode(update.body).dig("metadata", "annotations", "test")

    document["data"]["greeting"] = "再適用"
    # Kubernetes accepts CBOR request bodies without the self-described tag.
    patch = CBOR.encode(document).delete_prefix(CBOR::PREFIX)
    applied = request(http, "PATCH", "#{path}?fieldManager=test&force=true", body: patch, media_type: CBOR::APPLY_CONTENT_TYPE,
                                                                             accept: CBOR::CONTENT_TYPE)

    assert_equal "200", applied.code
    assert_equal "再適用", CBOR.decode(applied.body).dig("data", "greeting")
    assert_includes CBOR.decode(applied.body).dig("metadata", "managedFields").map { |entry| entry["operation"] }, "Apply"

    list = request(http, "GET", CONFIG_MAPS, accept: CBOR::CONTENT_TYPE)

    assert_equal(%w[cbor], CBOR.decode(list.body).fetch("items").map { |entry| entry.dig("metadata", "name") })
    discovery = request(http, "GET", "/api/v1", accept: CBOR::CONTENT_TYPE)

    assert_equal "APIResourceList", CBOR.decode(discovery.body)["kind"]
    assert_equal "406", request(http, "GET", "/apis", accept: CBOR::CONTENT_TYPE).code
    statusz = request(http, "GET", "/statusz", accept: "application/cbor;g=config.k8s.io;v=v1beta1;as=Statusz")

    assert_equal "Statusz", CBOR.decode(statusz.body)["kind"]
    partial = "application/cbor;g=meta.k8s.io;v=v1;as=PartialObjectMetadata"
    get = request(http, "GET", path, accept: partial)

    assert_equal partial, get["content-type"]
    assert_equal "PartialObjectMetadata", CBOR.decode(get.body)["kind"]
    refute CBOR.decode(get.body).key?("data")

    duplicate = "\xa2\x44kind\x49ConfigMap\x64kind\x49ConfigMap".b
    [duplicate, CBOR.encode(document) + "\xf6".b, "\xa1".b].each do |invalid|
      failed = request(http, "POST", CONFIG_MAPS, body: invalid, media_type: CBOR::CONTENT_TYPE, accept: CBOR::CONTENT_TYPE)

      assert_equal "400", failed.code
      assert_equal "BadRequest", CBOR.decode(failed.body)["reason"]
    end
    failed = request(http, "DELETE", path, body: "\xa1".b, media_type: CBOR::CONTENT_TYPE)

    assert_equal "400", failed.code
    assert_equal "200", request(http, "GET", path).code
    deleted = request(http, "DELETE", path, body: CBOR.encode({"kind" => "DeleteOptions", "apiVersion" => "v1"}),
                                            media_type: CBOR::CONTENT_TYPE, accept: CBOR::CONTENT_TYPE)

    assert_equal "200", deleted.code
  end

  def test_watch_serves_a_cbor_sequence_and_closes_the_store_watch
    store = Rubernetes::Storage::MemoryStore.new
    http, _api = serve(store: store)
    2.times do |index|
      create = request(http, "POST", CONFIG_MAPS, body: JSON.generate(config_map("watched-#{index}")), media_type: "application/json")

      assert_equal "201", create.code
    end
    path = "#{CONFIG_MAPS}?watch=true&resourceVersion=0"

    assert_equal "406", request(http, "GET", path, accept: CBOR::WATCH_CONTENT_TYPE).code
    assert_equal 0, store.watcher_count

    items = []
    connection = Net::HTTP.new("127.0.0.1", http.port, nil)
    connection.read_timeout = 3
    catch(:watched) do
      connection.request(Net::HTTP::Get.new(path, {"Accept" => CBOR::CONTENT_TYPE})) do |response|
        assert_equal "200", response.code
        assert_equal CBOR::WATCH_CONTENT_TYPE, response["content-type"]
        response.read_body do |frame|
          assert frame.start_with?(CBOR::PREFIX)
          assert_equal 2, frame.scan(CBOR::PREFIX).length
          items << CBOR.decode(frame)
          throw :watched if items.size == 2
        end
      end
    end

    assert_equal(%w[ADDED ADDED], items.map { |event| event.fetch("type") })
    assert_equal(%w[watched-0 watched-1], items.map { |event| event.dig("object", "metadata", "name") })
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
    sleep 0.01 while store.watcher_count.positive? && Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

    assert_equal 0, store.watcher_count
  end

  def test_custom_resource_writes_recover_from_tagged_raft_log_and_snapshot_with_gate_disabled
    Dir.mktmpdir do |directory|
      ca, ca_key = Consensus::Identity.generate_ca("test")
      bundle = Consensus::Identity.issue_node(ca, ca_key, cluster_id: "test", node_id: "a")
      raft = start_raft(directory, bundle)
      plain_http, _api = serve(enabled: false, store: Consensus::RaftStore.new(raft))
      write_widget(plain_http, "plain")
      plain_http.stop

      cbor_http, _api = serve(store: Consensus::RaftStore.new(raft, cbor_storage: true))
      write_widget(cbor_http, "binary")
      patch = request(cbor_http, "PATCH", "#{WIDGETS}/binary", body: '{"spec":{"count":14}}', media_type: "application/merge-patch+json",
                                                               accept: CBOR::CONTENT_TYPE)

      assert_equal "200", patch.code
      assert_equal 14, CBOR.decode(patch.body).dig("spec", "count")
      builtin = request(cbor_http, "POST", CONFIG_MAPS, body: CBOR.encode(config_map("builtin")),
                                                        media_type: CBOR::CONTENT_TYPE, accept: CBOR::CONTENT_TYPE)

      assert_equal "201", builtin.code
      cbor_http.stop
      raft.stop

      # Recover both formats by replaying the real on-disk log.
      raft = start_raft(directory, bundle)
      disabled_http, _api = serve(enabled: false, store: Consensus::RaftStore.new(raft))

      assert_widget_data(disabled_http, "plain")
      assert_widget_data(disabled_http, "binary", count: 14)
      assert_equal "200", request(disabled_http, "GET", "#{CONFIG_MAPS}/builtin").code
      snapshot = raft.snapshot!

      assert snapshot
      snapshot = Consensus::SnapshotStore.decode(File.binread(snapshot.path), path: snapshot.path)
      document = Consensus::Canonical.decode(Zlib::Inflate.inflate(snapshot.state))
      objects = document.fetch("versions").values.map { |versions| versions.last.last }

      assert_equal(1, objects.count { |object| object.is_a?(String) })
      tagged = Base64.strict_decode64(objects.find { |object| object.is_a?(String) })

      assert tagged.start_with?(CBOR::PREFIX)
      assert_equal "binary", CBOR.decode(tagged).dig("metadata", "name")
      assert_equal 14, CBOR.decode(tagged).dig("spec", "count")
      disabled_http.stop
      raft.stop

      # Recover after compaction, and keep serving JSON writes with the gate off.
      raft = start_raft(directory, bundle)
      restored_http, _api = serve(enabled: false, store: Consensus::RaftStore.new(raft))

      assert_widget_data(restored_http, "plain")
      assert_widget_data(restored_http, "binary", count: 14)
      write_widget(restored_http, "after-restart")

      assert_widget_data(restored_http, "after-restart")
    ensure
      @servers.reverse_each(&:stop)
      @servers.clear
    end
  end

  def test_malformed_cbor_record_is_recoverable_after_wal_and_snapshot_replay
    Dir.mktmpdir do |directory|
      ca, ca_key = Consensus::Identity.generate_ca("test")
      bundle = Consensus::Identity.issue_node(ca, ca_key, cluster_id: "test", node_id: "a")
      raft = start_raft(directory, bundle)
      key = "registry/example.test/__stored__/widgets/_cluster/unreadable"
      encoded = Base64.strict_encode64(CBOR::PREFIX + "\xa1".b)
      raft.propose({"type" => "create", "key" => key, "object" => encoded, "leader_time" => Time.now.to_f})
      raft.stop

      raft = start_raft(directory, bundle)
      gated = Consensus::RaftStore.new(raft, corrupt_deletion: true)
      failure = assert_raises(Rubernetes::Storage::CorruptObject) { gated.get(key) }
      assert_equal key, failure.key
      assert_raises(Rubernetes::Storage::CorruptObject) { gated.delete(key) }
      snapshot_meta = raft.snapshot!
      snapshot = Consensus::SnapshotStore.decode(File.binread(snapshot_meta.path), path: snapshot_meta.path)
      document = Consensus::Canonical.decode(Zlib::Inflate.inflate(snapshot.state))

      assert_equal encoded, document.fetch("versions").fetch(key).last.last
      raft.stop

      raft = start_raft(directory, bundle)
      gated = Consensus::RaftStore.new(raft, corrupt_deletion: true)
      list_error = assert_raises(Rubernetes::Storage::ReadErrors) { gated.list("registry/example.test/__stored__/widgets") }
      assert_equal key, list_error.details.dig("causes", 0, "field")
      authorizer = Object.new
      authorizer.define_singleton_method(:authorize) { |_attributes| Rubernetes::Security::Authorization::Decision.allow }
      security = Rubernetes::Security::Pipeline.new(authorizer: authorizer)
      api = API::Server.new(registry: widget_registry, store: gated, security: security,
                            feature_gates: {"AllowUnsafeMalformedObjectDeletion" => true})
      get = api.call(method: "GET", path: "#{WIDGETS}/unreadable", identity: {"username" => "admin"})

      assert_equal 500, get.status
      assert_match(/^apiserver_storage_decode_errors_total\{group="example.test",resource="widgets"\} 1$/, api.metrics.render_own)
      watch = gated.watch("registry/example.test/__stored__/widgets", resource_version: gated.revision)
      response = api.call(method: "DELETE", path: "#{WIDGETS}/unreadable", identity: {"username" => "admin"},
                          body: {"ignoreStoreReadErrorWithClusterBreakingPotential" => true})

      assert_equal 200, response.status
      event = watch.next(timeout: 1)

      assert_equal "ERROR", event.type
      assert_equal "StoreReadError", event.object.fetch("reason")
      assert_nil watch.next(timeout: 1)
      raft.stop
      raft = start_raft(directory, bundle)
      assert_raises(Rubernetes::Storage::NotFound) { Consensus::RaftStore.new(raft).get(key) }
    ensure
      @servers.reverse_each(&:stop)
      @servers.clear
    end
  end

  private

  def config_map(name)
    {"kind" => "ConfigMap", "apiVersion" => "v1", "metadata" => {"name" => name}, "data" => {"greeting" => "日本語"}}
  end

  def serve(enabled: true, store: Rubernetes::Storage::MemoryStore.new)
    api = API::Server.new(registry: widget_registry, store: store, feature_gates: {"CBORServingAndStorage" => enabled})
    http = Rubernetes::Transport::HTTPServer.new(api, port: 0)
    @servers << http
    http.start
    [http, api]
  end

  def widget_registry
    registry = API::Registry.new
    registry.register(API::Resource.new(group: "example.test", version: "v1", resource: "widgets", kind: "Widget", custom: true))
    registry
  end

  def request(server, method, path, body: nil, media_type: nil, accept: nil)
    http = Net::HTTP.new("127.0.0.1", server.port, nil)
    http.read_timeout = 5
    request = Net::HTTPGenericRequest.new(method, !body.nil?, true, path)
    request["Content-Type"] = media_type if media_type
    request["Accept"] = accept if accept
    request.body = body
    http.request(request)
  end

  def start_raft(directory, bundle)
    raft = Consensus::Server.new(id: "a", cluster_id: "test", data_directory: directory, bundle: bundle, initial_voters: ["a"])
    @servers << raft
    raft.start
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
    until raft.leader?
      flunk "Raft leader not elected" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      sleep 0.01
    end
    raft
  end

  def write_widget(http, name)
    object = {"kind" => "Widget", "apiVersion" => "example.test/v1", "metadata" => {"name" => name}, "spec" => {"count" => 7}}
    response = request(http, "POST", WIDGETS, body: JSON.generate(object), media_type: "application/json")

    assert_equal "201", response.code, response.body
  end

  def assert_widget_data(http, name, count: 7)
    response = request(http, "GET", "#{WIDGETS}/#{name}")

    assert_equal "200", response.code, response.body
    assert_equal count, JSON.parse(response.body).dig("spec", "count")
  end
end
