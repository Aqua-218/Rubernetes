# frozen_string_literal: true

# apiserver_watch_list_duration_seconds (endpoints/handlers/watch.go): a watch
# with sendInitialEvents=true is observed once, when the initial-events-end
# bookmark has been written, by group, version, resource and scope.

require_relative "../test_helper"
require "rubernetes/api"

class APIServerWatchListMetricsTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    @server = API::Server.new(store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil), metrics: @metrics)
    call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}})
    2.times { |index| call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "c#{index}"}}) }
  end

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, body: body, headers: {},
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def read_until_bookmark(path)
    response = call("GET", path)
    types = []
    response.body.each do |event|
      type = event.respond_to?(:type) ? event.type.to_s : event["type"].to_s
      types << type
      break if type == "BOOKMARK"
    end
    types
  ensure
    response&.body&.close if response&.body.respond_to?(:close)
  end

  def test_the_initial_events_end_bookmark_is_observed
    types = read_until_bookmark("/api/v1/namespaces/dev/configmaps?watch=true&sendInitialEvents=true&allowWatchBookmarks=true" \
                                "&resourceVersionMatch=NotOlderThan&timeoutSeconds=5")

    assert_equal %w[ADDED ADDED BOOKMARK], types
    text = @metrics.render
    labels = 'group="",resource="configmaps",scope="namespace",version="v1"'

    assert_match(/^apiserver_watch_list_duration_seconds_count\{#{labels}\} 1$/, text)
    assert_match(/^apiserver_watch_list_duration_seconds_bucket\{#{labels},le="0\.05"\} \d$/, text)
    assert_match(/^# HELP apiserver_watch_list_duration_seconds \[BETA\] Response latency distribution in seconds for watch list requests/,
                 text)
  end

  def test_a_plain_watch_is_not_a_watch_list
    call("GET",
         "/api/v1/configmaps?watch=true&timeoutSeconds=1").body.each { |_event| break } # rubocop:disable Lint/UnreachableLoop -- reads one event from the stream

    refute_match(/^apiserver_watch_list_duration_seconds_count/, @metrics.render)
  end
end
