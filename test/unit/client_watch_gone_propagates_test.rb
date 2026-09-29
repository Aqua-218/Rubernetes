# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/client"
require "rubernetes/watch"
require "json"

# A watch resumed after the server compacted its history gets 410 Gone.  The
# client used to answer by fetching a fresh list version itself and resuming
# from there, silently skipping every event in between; the reflector, which
# relists on a 410 and replays the current state, never saw the gap.
class ClientWatchGonePropagatesTest < Minitest::Test
  Client = Rubernetes::Client

  class Response
    attr_reader :status, :body, :headers

    def initialize(status, body)
      @status = status
      @body = body
      @headers = {"content-type" => "application/json"}
    end
  end

  # First connection: one event, then a disconnect.  Second connection: 410.
  class GoneRest
    attr_reader :queries, :list_calls

    def initialize(gone_as: :status)
      @queries = []
      @list_calls = 0
      @gone_as = gone_as
    end

    def stream(_method, path, query:)
      @queries << query
      if @queries.length == 1
        return Enumerator.new do |output|
          output << "#{JSON.generate("type" => "ADDED", "object" => {"metadata" => {"resourceVersion" => "7"}})}\n"
          raise EOFError, "simulated disconnect"
        end
      end
      if @gone_as == :status
        raise Client::APIError.new("Kubernetes watch request GET #{path} failed with HTTP 410",
                                   response: Response.new(410, JSON.generate("kind" => "Status", "code" => 410, "reason" => "Expired")))
      end
      Enumerator.new do |output|
        output << "#{JSON.generate("type" => "ERROR", "object" => {"kind" => "Status", "code" => 410, "reason" => "Expired"})}\n"
      end
    end

    def request(_method, _path, body: nil, headers: {}, query: {})
      @list_calls += 1
      Response.new(200, JSON.generate("kind" => "PodList", "metadata" => {"resourceVersion" => "900"}, "items" => []))
    end
  end

  def test_a_410_on_reconnect_reaches_the_caller_instead_of_a_silent_relist
    rest = GoneRest.new
    client = Client::KubernetesClient.new(rest_client: rest, context: {namespace: "dev"})

    error = assert_raises(Client::APIError) { client.watch_each("pods", max_reconnects: 5).to_a }

    assert_equal 410, error.status
    assert_equal 0, rest.list_calls, "the client must not relist behind the caller's back"
    assert_equal "7", rest.queries[1]["resourceVersion"], "the reconnect resumed from the last event"
    assert Rubernetes::Watch::Reflector.allocate.send(:gone_error?, error)
  end

  def test_an_expired_error_event_reaches_the_caller_as_a_410
    rest = GoneRest.new(gone_as: :event)
    client = Client::KubernetesClient.new(rest_client: rest, context: {namespace: "dev"})

    error = assert_raises(Client::KubernetesClient::WatchReset) { client.watch_each("pods", max_reconnects: 5).to_a }

    assert_equal 410, error.status
    assert_equal 0, rest.list_calls
    assert Rubernetes::Watch::Reflector.allocate.send(:gone_error?, error)
  end
end
