# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

class APIPersistentVolumeStatusTest < Minitest::Test
  API = Rubernetes::API
  COLLECTION = "/api/v1/persistentvolumes"
  VOLUME = "#{COLLECTION}/scratch".freeze
  STATUS = "#{VOLUME}/status".freeze
  TIME_FIELD = "lastPhaseTransitionTime"

  def setup
    @now = Time.utc(2026, 11, 19, 19)
    clock = -> { @now }
    registry = API::Registry.new
    registry.register(resource: "persistentvolumes", kind: "PersistentVolume", scope: :cluster, subresources: ["status"])
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new(clock: clock), clock: clock)
    @volume = create_volume
  end

  def test_ordinary_merge_patches_stamp_each_phase_change
    assert_equal({"phase" => "Pending", TIME_FIELD => moment}, @volume["status"])

    @now += 10

    assert_equal moment, merge_status("phase" => "Available").body.dig("status", TIME_FIELD)

    @now += 10

    assert_equal moment, merge_status("phase" => "Bound").body.dig("status", TIME_FIELD)

    @now += 10
    released = merge_status("phase" => "Released")

    assert_equal({"phase" => "Released", TIME_FIELD => moment}, released.body["status"])
    assert_equal released.body["status"], @server.call(method: "GET", path: VOLUME).body["status"]
  end

  def test_status_put_preserves_time_without_a_transition_and_stamps_an_omitted_time_after_change
    original = moment
    @now += 10
    changed = put_status(@volume, "phase" => "Pending", "message" => "same phase")

    assert_equal original, changed.body.dig("status", TIME_FIELD)
    assert_equal "same phase", changed.body.dig("status", "message")

    @now += 10
    released = put_status(changed.body, "phase" => "Bound")

    assert_equal moment, released.body.dig("status", TIME_FIELD)
    assert_equal @volume["spec"], released.body["spec"]
  end

  def test_an_explicit_distinct_time_is_honored_and_an_equal_instant_is_restamped
    client_time = "2026-10-01T02:00:00Z"
    @now += 10
    updated = merge_status("phase" => "Bound", TIME_FIELD => client_time)

    assert_equal client_time, updated.body.dig("status", TIME_FIELD)

    @now += 10

    assert_equal client_time, merge_status(TIME_FIELD => nil).body.dig("status", TIME_FIELD)
    assert_equal moment, merge_status("phase" => "Released", TIME_FIELD => "2026-10-01T11:00:00+09:00").body.dig("status", TIME_FIELD)

    same_phase_time = "2026-11-01T00:00:00Z"

    assert_equal same_phase_time, merge_status(TIME_FIELD => same_phase_time).body.dig("status", TIME_FIELD)
  end

  private

  def create_volume
    created = @server.call(method: "POST", path: COLLECTION,
                           body: {"apiVersion" => "v1", "kind" => "PersistentVolume", "metadata" => {"name" => "scratch"},
                                  "spec" => {"capacity" => {"storage" => "1Gi"}, "accessModes" => ["ReadWriteOnce"],
                                             "nfs" => {"server" => "192.0.2.40", "path" => "/vol"}},
                                  "status" => {"phase" => "Failed", TIME_FIELD => "2025-01-01T00:00:00Z"}})

    assert_equal 201, created.status, created.body.inspect
    created.body
  end

  def moment = @now.utc.iso8601

  def merge_status(status)
    response = @server.call(method: "PATCH", path: STATUS, body: {"status" => status},
                            headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal 200, response.status, response.body.inspect
    response
  end

  def put_status(object, status)
    response = @server.call(method: "PUT", path: STATUS, body: object.merge("status" => status, "spec" => {}))

    assert_equal 200, response.status, response.body.inspect
    response
  end
end
