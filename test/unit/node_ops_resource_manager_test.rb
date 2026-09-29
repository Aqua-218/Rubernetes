# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node/resource_manager"

class NodeOpsResourceManagerTest < Minitest::Test
  def pod(name, requests:, limits: requests, init_containers: [])
    {
      "metadata" => {"name" => name, "namespace" => "default"},
      "spec" => {
        "containers" => [{"name" => "main", "resources" => {"requests" => requests, "limits" => limits}}],
        "initContainers" => init_containers
      }
    }
  end

  def test_allocatable_uses_exact_quantity_arithmetic_and_reservations
    manager = Rubernetes::Node::ResourceManager.new(
      capacity: {"cpu" => "2", "memory" => "4Gi"},
      system_reserved: {"cpu" => "250m", "memory" => "512Mi"},
      kube_reserved: {"cpu" => "250m"}
    )

    assert_equal("1500m", manager.allocatable.fetch("cpu"))
    assert_equal("3584Mi", manager.allocatable.fetch("memory"))
    assert_equal(Rational(1, 2), manager.parse_quantity("500m", "cpu"))
    assert_equal("1Gi", manager.format_quantity(manager.parse_quantity("1Gi", "memory"), "memory"))
  end

  def test_qos_and_init_container_request_semantics
    manager = Rubernetes::Node::ResourceManager.new(capacity: {"cpu" => "4", "memory" => "8Gi"})
    init = {"name" => "init", "resources" => {"requests" => {"cpu" => "2", "memory" => "2Gi"}}}
    burstable = pod("burst", requests: {"cpu" => "500m"}, limits: {"cpu" => "1"}, init_containers: [init])
    guaranteed = pod("guaranteed", requests: {"cpu" => "1", "memory" => "1Gi"})
    besteffort = {"metadata" => {"name" => "best"}, "spec" => {"containers" => [{"name" => "c"}]}}

    assert_equal("Burstable", manager.qos_class(burstable))
    assert_equal("Guaranteed", manager.qos_class(guaranteed))
    assert_equal("BestEffort", manager.qos_class(besteffort))
    assert_equal("2", manager.request_for(burstable).fetch("cpu"))
    assert_equal("2Gi", manager.request_for(burstable).fetch("memory"))
  end

  def test_reservations_are_released_and_capacity_is_not_overcommitted
    manager = Rubernetes::Node::ResourceManager.new(capacity: {"cpu" => "1", "memory" => "1Gi"})
    first = pod("first", requests: {"cpu" => "600m", "memory" => "512Mi"})
    second = pod("second", requests: {"cpu" => "500m", "memory" => "512Mi"})

    manager.reserve(first)
    assert_raises(Rubernetes::Node::ResourceManager::InsufficientResources) { manager.reserve(second) }
    manager.release(first)
    assert(manager.fits?(manager.request_for(second)))
  end
end
