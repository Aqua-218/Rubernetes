# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/bootstrap"

class PodStatusObservedGenerationTest < Minitest::Test
  POD_PATH = "/api/v1/namespaces/dev/pods/generation"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry, store: Rubernetes::Storage::MemoryStore.new, namespace_lifecycle: true)
    @server.call(method: "POST", path: "/api/v1/namespaces", body: {"metadata" => {"name" => "dev"}})
    @server.call(method: "POST", path: "/api/v1/namespaces/dev/pods",
                 body: {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "generation"},
                        "spec" => {"containers" => [{"name" => "app", "image" => "busybox"}]}})
  end

  def test_status_put_preserves_the_old_generation_by_type_and_occurrence
    put_status("observedGeneration" => 8, "conditions" => [condition("A", 11), condition("B", 12), condition("A", 13),
                                                           condition("A"), condition("A", 15), condition("Dropped", 99)])
    conditions = [condition("B", 0), condition("A", 21), condition("New", 0), condition("A"),
                  condition("A", 0), condition("A").merge("observedGeneration" => nil), condition("A", 0)]
    response = put_status("observedGeneration" => 0, "conditions" => conditions)

    assert_equal 8, response["observedGeneration"]
    assert_equal(%w[B A New A A A A], response.fetch("conditions").map { |entry| entry.fetch("type") })
    assert_equal([12, 21, nil, 13, nil, 15, nil], response.fetch("conditions").map { |entry| entry["observedGeneration"] })
    assert(response.fetch("conditions").values_at(2, 4, 6).none? { |entry| entry.key?("observedGeneration") })
    assert_equal response, pod.fetch("status")
  end

  def test_status_merge_patch_preserves_an_omitted_or_null_generation_without_restoring_conditions
    put_status("observedGeneration" => 4, "conditions" => [condition("A", 1), condition("B", 2)])
    response = merge_status("observedGeneration" => nil, "conditions" => [condition("B"), condition("A", 6)])

    assert_equal 4, response["observedGeneration"]
    assert_equal [condition("B", 2), condition("A", 6)], response["conditions"]

    response = merge_status("observedGeneration" => 7, "conditions" => nil)

    assert_equal 7, response["observedGeneration"]
    assert_nil response["conditions"]
    assert_equal response, pod.fetch("status")
  end

  def test_status_put_preserves_an_omitted_top_level_generation
    put_status("observedGeneration" => 3, "conditions" => [condition("A", 11)])
    response = put_status("conditions" => [condition("New")])

    assert_equal 3, response["observedGeneration"]
    assert_equal [condition("New")], response["conditions"]
  end

  def test_status_put_omits_zero_generation_when_there_is_nothing_to_preserve
    response = put_status("observedGeneration" => 0, "conditions" => [condition("New", 0)])

    refute response.key?("observedGeneration")
    assert_equal [condition("New")], response["conditions"]
  end

  private

  def condition(type, generation = nil)
    {"type" => type, "status" => "True", "observedGeneration" => generation}.compact
  end

  def pod
    @server.call(method: "GET", path: POD_PATH).body
  end

  def put_status(status)
    result = @server.call(method: "PUT", path: "#{POD_PATH}/status", body: pod.merge("status" => status))

    assert_equal 200, result.status, result.body.inspect
    result.body.fetch("status")
  end

  def merge_status(status)
    result = @server.call(method: "PATCH", path: "#{POD_PATH}/status", body: {"status" => status},
                          headers: {"content-type" => "application/merge-patch+json"})

    assert_equal 200, result.status, result.body.inspect
    result.body.fetch("status")
  end
end
