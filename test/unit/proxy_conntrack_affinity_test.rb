# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/proxy"

class ProxyConntrackAffinityTest < Minitest::Test
  Proxy = Rubernetes::Proxy
  SERVICE = "default/echo"
  OTHER_SERVICE = "default/other"
  CLIENT = "192.0.2.1"
  OTHER_CLIENT = "192.0.2.2"
  THIRD_CLIENT = "192.0.2.3"

  def setup
    @table = Proxy::ConntrackTable.new(max_entries: 2)
  end

  def test_prune_and_lookup_remove_expired_affinity_without_expiring_established_connections
    first = route(10_001, now: 0)
    route(10_001, client: OTHER_CLIENT, now: 1)

    assert_empty @table.prune(now: 10)
    assert_equal 1, affinity_count
    assert_equal first.backend, @table.fetch(first.key, now: 10).backend
    assert_nil @table.affinity_for(SERVICE, OTHER_CLIENT, now: 11)
    assert_equal 0, affinity_count
    assert_equal 2, @table.size
  end

  def test_route_affinity_survives_tuple_deletion_and_connection_eviction
    first = route(10_001, now: 0)

    assert_equal first, @table.delete(first.key)
    assert_equal "first", route(10_002, now: 1, target: :last).backend
    route(10_001, client: OTHER_CLIENT, now: 2, affinity: false)
    route(10_001, client: THIRD_CLIENT, now: 3, affinity: false)

    assert_equal 2, @table.size
    assert_nil @table.fetch(tuple(10_002), now: 3)
    assert_equal "first", route(10_003, now: 4, target: :last).backend
  end

  def test_affinity_capacity_evicts_the_least_recently_used_client_independently
    @table.delete(route(10_001, now: 0).key)
    @table.delete(route(10_001, client: OTHER_CLIENT, now: 1).key)
    @table.delete(route(10_002, now: 2, target: :last).key)
    @table.delete(route(10_001, client: THIRD_CLIENT, now: 3).key)

    assert_equal 0, @table.size
    assert_equal 2, affinity_count
    assert_nil @table.affinity_for(SERVICE, OTHER_CLIENT, now: 4)
    assert_equal "first", @table.affinity_for(SERVICE, CLIENT, now: 4).backend
    assert_equal "first", @table.affinity_for(SERVICE, THIRD_CLIENT, now: 4).backend
  end

  def test_affinity_capacity_reuses_an_expired_slot_before_evicting_a_live_client
    route(10_001, now: 0)
    route(10_001, client: OTHER_CLIENT, now: 1, timeout: 1)
    route(10_001, client: THIRD_CLIENT, now: 2)

    assert_equal 2, affinity_count
    assert_equal "first", @table.affinity_for(SERVICE, CLIENT, now: 2).backend
    assert_nil @table.affinity_for(SERVICE, OTHER_CLIENT, now: 2)
  end

  def test_explicit_bind_retains_its_tuple_link_and_does_not_evict_on_replacement
    key = tuple(10_001)
    connection = @table.bind(key, service_key: SERVICE, backend: "first", affinity: true, source_ip: CLIENT, timeout_seconds: 5, now: 0)

    assert_same connection, @table.affinity_for(SERVICE, CLIENT, now: 4)
    assert_equal [connection], @table.prune(now: 5)
    assert_nil @table.affinity_for(SERVICE, CLIENT, now: 5)
    other = route(10_003, client: OTHER_CLIENT, now: 6, affinity: false)
    @table.bind(key, service_key: SERVICE, backend: "first", affinity: true, source_ip: CLIENT, now: 7)
    replacement = @table.bind(key, service_key: SERVICE, backend: "last", now: 8)

    assert_nil @table.affinity_for(SERVICE, CLIENT, now: 8)
    assert_equal other.backend, @table.fetch(other.key, now: 8).backend
    assert_equal replacement, @table.delete(key)
  end

  def test_deleting_an_explicit_binding_removes_its_linked_affinity
    key = tuple(10_001)
    @table.bind(key, service_key: SERVICE, backend: "first", affinity: true, source_ip: CLIENT, now: 0)
    @table.delete(key)

    assert_nil @table.affinity_for(SERVICE, CLIENT, now: 1)
  end

  def test_evicting_an_explicit_binding_removes_its_linked_affinity
    key = tuple(10_001)
    @table.bind(key, service_key: SERVICE, backend: "first", affinity: true, source_ip: CLIENT, now: 0)
    route(10_001, client: OTHER_CLIENT, now: 1, affinity: false)
    route(10_001, client: THIRD_CLIENT, now: 2, affinity: false)

    assert_nil @table.fetch(key, now: 2)
    assert_nil @table.affinity_for(SERVICE, CLIENT, now: 2)
  end

  def test_backend_removal_and_service_clear_remove_independent_affinity
    @table.delete(route(10_001, now: 0).key)
    @table.delete(route(10_002, service: OTHER_SERVICE, now: 1, target: :last).key)
    @table.remove_backend("first")

    assert_nil @table.affinity_for(SERVICE, CLIENT, now: 2)
    assert_equal "last", @table.affinity_for(OTHER_SERVICE, CLIENT, now: 2).backend
    @table.delete(route(10_003, now: 2).key)
    @table.clear(service_key: OTHER_SERVICE)

    assert_nil @table.affinity_for(OTHER_SERVICE, CLIENT, now: 3)
    assert_equal "first", @table.affinity_for(SERVICE, CLIENT, now: 3).backend
    @table.clear

    assert_equal 0, affinity_count
  end

  private

  def route(port, now:, client: CLIENT, service: SERVICE, target: :first, affinity: true, timeout: 10)
    @table.find_or_select(tuple(port, client), service_key: service, backends: %w[first last], selector: target.to_proc,
                                               session_affinity: affinity ? "ClientIP" : "None", source_ip: client, timeout_seconds: timeout, now: now)
  end

  def tuple(port, client = CLIENT)
    Proxy::ConnectionKey.new(protocol: "TCP", source_ip: client, source_port: port,
                             destination_ip: "198.51.100.1", destination_port: 80)
  end

  def affinity_count = @table.instance_variable_get(:@affinity).size
end
