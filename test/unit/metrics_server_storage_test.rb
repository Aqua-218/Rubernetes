# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/metrics_server"

# sigs.k8s.io/metrics-server pkg/storage (v0.8.0) node_test.go / pod_test.go.
class MetricsServerStorageTest < Minitest::Test
  Storage = Rubernetes::MetricsServer::Storage
  CORE_SECOND = 1_000_000_000
  MIB = 1024 * 1024
  START = Time.utc(2026, 9, 24, 0, 0, 0)

  def point(start, at, cpu, memory)
    Storage::Point.new(start_time: start, timestamp: START + at, cumulative_cpu: cpu, memory: memory)
  end

  def nodes(**points) = Storage::Batch.new(nodes: points.transform_keys(&:to_s), pods: {})

  def pods(containers) = Storage::Batch.new(nodes: {}, pods: {%w[ns1 pod1] => containers})

  def test_node_usage_needs_two_points
    storage = Storage.new
    storage.store(nodes(node1: point(START, 10, 1 * CORE_SECOND, 2 * MIB)))

    assert_nil storage.node_usage("node1")
    refute_predicate storage, :ready?
    storage.store(nodes(node1: point(START, 20, 5 * CORE_SECOND, 3 * MIB)))
    usage = storage.node_usage("node1")

    assert_equal "400m", usage.cpu
    assert_equal "3Mi", usage.memory
    assert_equal 10, usage.window
    assert_predicate storage, :ready?
  end

  def test_node_restart_and_decreased_counter_are_skipped
    storage = Storage.new
    storage.store(nodes(node1: point(START, 10, 5 * CORE_SECOND, MIB)))
    storage.store(nodes(node1: point(START + 15, 20, 6 * CORE_SECOND, MIB)))

    refute_nil storage.node_usage("node1"), "a later start time is not a restart"
    storage.store(nodes(node1: point(START, 30, 1 * CORE_SECOND, MIB)))

    assert_nil storage.node_usage("node1"), "start time went backwards and the counter decreased"
  end

  def test_node_point_between_prev_and_last_keeps_prev
    storage = Storage.new
    storage.store(nodes(node1: point(START, 115, 10 * CORE_SECOND, MIB)))
    storage.store(nodes(node1: point(START, 125, 50 * CORE_SECOND, MIB)))
    storage.store(nodes(node1: point(START, 120, 35 * CORE_SECOND, MIB)))
    usage = storage.node_usage("node1")

    assert_equal 5, usage.window
    assert_equal "5", usage.cpu
  end

  def test_container_restart_uses_the_window_from_its_start_time
    storage = Storage.new(metric_resolution: 60)
    storage.store(pods("container1" => point(START, 10, 1 * CORE_SECOND, 4 * MIB)))
    storage.store(pods("container1" => point(START + 15, 25, 5 * CORE_SECOND, 5 * MIB)))
    containers, earliest = storage.pod_usage("ns1", "pod1")

    assert_equal 10, earliest.window
    assert_equal START + 25, earliest.timestamp
    assert_equal([%w[container1 500m 5Mi]], containers.map { |name, usage| [name, usage.cpu, usage.memory] })
  end

  def test_decreased_container_counter_yields_a_pod_without_containers
    storage = Storage.new(metric_resolution: 60)
    storage.store(pods("container1" => point(START, 110, 20 * CORE_SECOND, 4 * MIB)))
    storage.store(pods("container1" => point(START, 120, 10 * CORE_SECOND, 4 * MIB)))
    containers, = storage.pod_usage("ns1", "pod1")

    assert_equal [], containers
  end

  def test_fresh_container_is_served_in_one_cycle_from_its_start
    storage = Storage.new(metric_resolution: 60)
    storage.store(pods("container1" => point(START, 10, 10 * CORE_SECOND, 4 * MIB)))

    assert_predicate storage, :ready?
    containers, earliest = storage.pod_usage("ns1", "pod1")

    assert_equal 10, earliest.window
    assert_equal "1", containers.first.last.cpu
  end

  def test_fresh_container_rules_long_running_future_and_too_young
    [120, -10, 9].each do |age|
      storage = Storage.new(metric_resolution: 60)
      storage.store(pods("container1" => point(START, age, 10 * CORE_SECOND, 4 * MIB)))

      refute_predicate storage, :ready?, "age #{age}"
      assert_nil storage.pod_usage("ns1", "pod1"), "age #{age}"
    end
  end

  def test_zero_start_time_is_before_every_timestamp
    storage = Storage.new(metric_resolution: 60)
    storage.store(pods("container1" => point(nil, 120, 1 * CORE_SECOND, 4 * MIB)))

    assert_nil storage.pod_usage("ns1", "pod1")
    storage.store(pods("container1" => point(nil, 125, 6 * CORE_SECOND, 5 * MIB)))
    containers, earliest = storage.pod_usage("ns1", "pod1")

    assert_equal 5, earliest.window
    assert_equal "1", containers.first.last.cpu
    assert_equal "5Mi", containers.first.last.memory
  end

  def test_a_container_new_in_the_second_scrape_withholds_the_pod
    storage = Storage.new(metric_resolution: 60)
    storage.store(pods("container1" => point(START, 110, 1 * CORE_SECOND, 4 * MIB)))
    storage.store(pods("container1" => point(START, 120, 6 * CORE_SECOND, 6 * MIB),
                       "container2" => point(START, 120, 8 * CORE_SECOND, 5 * MIB)))

    assert_nil storage.pod_usage("ns1", "pod1")
  end

  def test_the_earliest_container_timestamp_is_the_pods
    storage = Storage.new(metric_resolution: 60)
    storage.store(pods("c1" => point(START, 100, 1 * CORE_SECOND, MIB), "c2" => point(START, 100, 1 * CORE_SECOND, MIB)))
    storage.store(pods("c1" => point(START, 110, 2 * CORE_SECOND, MIB), "c2" => point(START, 105, 2 * CORE_SECOND, MIB)))
    _containers, earliest = storage.pod_usage("ns1", "pod1")

    assert_equal START + 105, earliest.timestamp
  end
end
