# frozen_string_literal: true

require "tmpdir"
require "timeout"

require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/consensus"

class ServiceNodePortAllocationTest < Minitest::Test
  API = Rubernetes::API
  Consensus = Rubernetes::Consensus
  SERVICES = "/api/v1/namespaces/default/services"
  CLAIMS = "registry/_internal/v1/servicenodeports/_cluster/"
  ADDRESSES = "registry/networking.k8s.io/v1/ipaddresses/_cluster/"
  MERGE_PATCH = "application/merge-patch+json"

  def test_concurrent_api_servers_cannot_assign_the_same_port
    with_raft do |raft|
      arrivals = Queue.new
      proceed = Queue.new
      stores = Array.new(2) { Consensus::RaftStore.new(raft) }
      stores.each do |store|
        original = store.method(:list)
        store.define_singleton_method(:list) do |prefix, **options|
          result = original.call(prefix, **options)
          if prefix == "registry/v1/services/"
            arrivals << true
            proceed.pop
          end
          result
        end
      end
      servers = stores.map { |store| api_server(store) }
      writers = servers.each_with_index.map do |server, index|
        Thread.new { request(server, "POST", SERVICES, service("writer-#{index}", "10.96.0.#{index + 1}")) }
      end

      Timeout.timeout(10) { writers.size.times { arrivals.pop } }
      writers.size.times { proceed << true }
      results = writers.map(&:value)

      assert_equal [201, 422], results.map(&:status).sort, results.map(&:body).inspect
      assert_match(/provided port is already allocated/, results.find { |response| response.status == 422 }.body.fetch("message"))
    ensure
      writers&.each(&:kill)
    end
  end

  def test_dry_run_update_and_final_deletion_release_ports_in_durable_store
    with_raft do |raft, restart|
      server = api_server(Consensus::RaftStore.new(raft))
      preview = request(server, "POST", "#{SERVICES}?dryRun=All", service("preview", "10.96.0.1"))

      assert_equal 201, preview.status
      assert_empty raft.store.list(CLAIMS).items
      assert_equal 201, request(server, "POST", SERVICES, service("owner", "10.96.0.1")).status

      restored = restart.call
      server = api_server(Consensus::RaftStore.new(restored))

      assert_equal 0, server.service_allocator.repair!(raise_on_error: true).fetch("released")
      assert_equal 422, request(server, "POST", SERVICES, service("next-owner", "10.96.0.2")).status

      change = {"spec" => {"ports" => [{"port" => 80, "nodePort" => 30_002}]}}
      invalid = change.merge("metadata" => {"uid" => "different-uid"})

      assert_equal 422, request(server, "PATCH", "#{SERVICES}/owner", invalid, content_type: MERGE_PATCH).status
      assert_equal ["30001"], claim_names(restored)

      updated = request(server, "PATCH", "#{SERVICES}/owner", change, content_type: MERGE_PATCH)

      assert_equal 200, updated.status, updated.body.inspect
      assert_equal ["30002"], claim_names(restored)
      assert_equal 201, request(server, "POST", SERVICES, service("next-owner", "10.96.0.2")).status
      finalizer = {"metadata" => {"finalizers" => ["example.test/hold"]}}

      assert_equal 200, request(server, "PATCH", "#{SERVICES}/owner", finalizer, content_type: MERGE_PATCH).status
      assert_equal 200, request(server, "DELETE", "#{SERVICES}/owner").status
      assert_equal 422, request(server, "POST", SERVICES, service("replacement", "10.96.0.3", port: 30_002)).status

      finalize = {"metadata" => {"finalizers" => []}}

      assert_equal 200, request(server, "PATCH", "#{SERVICES}/owner", finalize, content_type: MERGE_PATCH).status
      assert_equal ["30001"], claim_names(restored)
      assert_equal 201, request(server, "POST", SERVICES, service("replacement", "10.96.0.3", port: 30_002)).status
    end
  end

  def test_expired_claim_repair_fences_delayed_service_write
    with_raft do |raft|
      now = Time.utc(2026, 11, 19)
      clock = -> { now }
      slow_store = Consensus::RaftStore.new(raft)
      paused, resume = pause_store_write(slow_store, :create, "registry/v1/services/default/slow")
      slow_server = api_server(slow_store, clock: clock)
      other = api_server(Consensus::RaftStore.new(raft), clock: clock)
      writer = Thread.new { request(slow_server, "POST", SERVICES, service("slow", "10.96.0.1")) }

      Timeout.timeout(10) { paused.pop }

      assert_equal 0, other.service_allocator.repair!(raise_on_error: true).fetch("port_errors")["leak"]
      now += 61
      report = other.service_allocator.repair!(raise_on_error: true)

      assert_equal 1, report.fetch("port_errors")["leak"]
      assert_equal 1, report.fetch("ip_errors")["leak"]
      assert_equal 201, request(other, "POST", SERVICES, service("fast", "10.96.0.2")).status
      resume << true

      assert_equal 409, writer.value.status
      assert_equal 404, request(other, "GET", "#{SERVICES}/slow").status
      assert_equal "fast", raft.store.get("#{CLAIMS}30001").dig("owner", "name")
    ensure
      writer&.kill
    end
  end

  def test_repair_cannot_remove_claims_whose_service_just_committed
    with_raft do |raft|
      now = Time.utc(2026, 11, 19)
      clock = -> { now }
      writer_store = Consensus::RaftStore.new(raft)
      writer_paused, write = pause_store_write(writer_store, :create, "registry/v1/services/default/slow")
      server = api_server(writer_store, clock: clock)
      writer = Thread.new { request(server, "POST", SERVICES, service("slow", "10.96.0.1")) }
      Timeout.timeout(10) { writer_paused.pop }

      now += 61
      repair_store = Consensus::RaftStore.new(raft)
      repair_paused, finish = pause_store_write(repair_store, :delete, "#{ADDRESSES}10.96.0.1")
      other = api_server(repair_store, clock: clock)
      repair = Thread.new { other.service_allocator.repair!(raise_on_error: true) }
      Timeout.timeout(10) { repair_paused.pop }
      write << true

      assert_equal 201, writer.value.status
      finish << true
      report = repair.value

      assert_equal 0, report.fetch("port_errors")["leak"]
      assert_equal 0, report.fetch("ip_errors")["leak"]
      assert_equal "slow", raft.store.get("#{ADDRESSES}10.96.0.1").dig("spec", "parentRef", "name")
      assert_equal "slow", raft.store.get("#{CLAIMS}30001").dig("owner", "name")
    ensure
      writer&.kill
      repair&.kill
    end
  end

  private

  def claim_names(raft)
    raft.store.list(CLAIMS).items.map { |record| record.dig("metadata", "name") }
  end

  def api_server(store, clock: -> { Time.now.utc })
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    API::Server.new(registry: registry, store: store, service_cidrs: ["10.96.0.0/24"], clock: clock)
  end

  def request(server, method, path, object = nil, content_type: "application/json")
    server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                 body: object && JSON.generate(object), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def service(name, ip, port: 30_001)
    {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => name},
     "spec" => {"clusterIP" => ip, "type" => "NodePort", "ports" => [{"nodePort" => port, "port" => 80}]}}
  end

  def pause_store_write(store, method, key)
    original = store.method(method)
    arrived = Queue.new
    proceed = Queue.new
    store.define_singleton_method(method) do |stored_key, *args, **options|
      if stored_key == key
        arrived << true
        proceed.pop
      end
      original.call(stored_key, *args, **options)
    end
    [arrived, proceed]
  end

  def with_raft
    Dir.mktmpdir("rbn-node-port") do |directory|
      ca, ca_key = Consensus::Identity.generate_ca("test")
      bundle = Consensus::Identity.issue_node(ca, ca_key, cluster_id: "test", node_id: "a")
      raft = nil
      start = lambda do
        raft&.stop
        raft = Consensus::Server.new(id: "a", cluster_id: "test", data_directory: directory, bundle: bundle, initial_voters: ["a"])
        raft.start
        Timeout.timeout(10) { sleep 0.01 until raft.leader? }
        raft
      end
      yield start.call, start
    ensure
      raft&.stop
    end
  end
end
