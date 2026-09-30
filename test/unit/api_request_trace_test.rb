# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api"

# A traced request logs how its time divided between phases, so a slow verb
# names its slow phase instead of being a guess.
class APIRequestTraceTest < Minitest::Test
  class Recorder
    attr_reader :lines

    def initialize = @lines = []
    def info(event, **fields) = @lines << [event, fields]
    def warn(event, **fields) = @lines << [event, fields]
  end

  def test_a_matching_request_logs_its_phases
    logger = Recorder.new
    server = Rubernetes::API::Server.new(store: Rubernetes::API::MemoryStore.new, logger: logger)
    server.trace_requests = /configmaps/

    server.call(method: "POST", path: "/api/v1/namespaces/dev/configmaps", body: {"metadata" => {"name" => "a"}})
    server.call(method: "GET", path: "/api/v1/namespaces/dev/secrets")

    traces = logger.lines.select { |event, _| event == "request.trace" }

    assert_equal 1, traces.length, "only the matching path is traced"
    fields = traces.first.last

    assert_equal "POST", fields[:method]
    assert_equal 201, fields[:status]
    assert fields[:phases].keys.any? { |name| name.start_with?("store.") }, fields[:phases].inspect
    assert_nil Thread.current[Rubernetes::API::Server::REQUEST_PHASES_KEY]
  end

  def test_without_a_pattern_nothing_is_traced
    logger = Recorder.new
    server = Rubernetes::API::Server.new(store: Rubernetes::API::MemoryStore.new, logger: logger)

    server.call(method: "GET", path: "/api/v1/namespaces/dev/configmaps")

    assert_empty(logger.lines.select { |event, _| event == "request.trace" })
  end
end
