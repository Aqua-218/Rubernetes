# frozen_string_literal: true

require "net/http"
require "socket"
require "timeout"
require_relative "../test_helper"
require "rubernetes/api"
require "rubernetes/transport"

class APIServerServingRoutineTest < Minitest::Test
  API = Rubernetes::API

  class RecordingStore < Rubernetes::Storage::MemoryStore
    attr_reader :preparations

    def initialize
      @preparations = Queue.new
      super
    end

    def watch(...)
      @preparations << Thread.current
      super
    end
  end

  def test_gate_releases_the_preparation_worker_before_an_http_watch_finishes
    [true, false].each do |enabled|
      store = RecordingStore.new
      api = API::Server.new(store: store, feature_gates: {"APIServingWithRoutine" => enabled})
      calls = Queue.new
      http = Rubernetes::Transport::HTTPServer.new(lambda do |transport_request|
        calls << Thread.current if transport_request.query_value("watch") == "true"
        api.call(API::Request.new(method: transport_request.method, path: transport_request.target,
                                  body: transport_request.body, headers: transport_request.headers.to_h))
      end, host: "127.0.0.1", port: 0, shutdown_timeout: 1)
      http.start
      socket = TCPSocket.new("127.0.0.1", http.port)
      socket.write("GET /api/v1/namespaces/default/configmaps?watch=true HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_match(/200 OK/, Timeout.timeout(3) { socket.gets })
      transport_thread = calls.pop(timeout: 1)
      preparation = store.preparations.pop(timeout: 1)

      assert_predicate transport_thread, :alive?
      if enabled
        refute_same transport_thread, preparation
        refute_predicate preparation, :alive?
      else
        assert_same transport_thread, preparation
      end

      ready = Net::HTTP.new("127.0.0.1", http.port, nil)
      ready.read_timeout = 2

      assert_equal "200", ready.get("/readyz").code
      assert_equal 1, store.watcher_count
    ensure
      socket&.close
      http&.stop(timeout: 1)
    end
  end
end
