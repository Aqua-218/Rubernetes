# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../support/grpc_fake_server"
require "rubernetes/node"
require "rubernetes/runtime/cri/client"

# EventedPLEG: CRI container events streamed to the lifecycle, counted and
# timed; a stream that keeps failing hands back to the generic relist.
class EventedPLEGTest < Minitest::Test
  Node = Rubernetes::Node

  class FakeClient
    def initialize(scripts) = @scripts = scripts

    def stream(_service, _method, _request)
      script = @scripts.shift or raise Rubernetes::Runtime::CRI::Client::Error, "runtime gone"
      script.each do |message|
        raise Rubernetes::Runtime::CRI::Client::Error, message[:error] if message.is_a?(Hash) && message[:error]

        yield message
      end
      true
    end
  end

  def metrics = @metrics ||= Node::KubeletMetrics.new(node_name: "worker-0")
  def render = metrics.registry.render_own

  def event(uid, type, created_ns)
    {"container_event_type" => type, "container_id" => "c-#{uid}", "created_at" => created_ns.to_i.to_s,
     "pod_sandbox_status" => {"metadata" => {"uid" => uid, "name" => "p", "namespace" => "ns"}}}
  end

  def test_events_reach_the_lifecycle_and_are_measured
    now = 1_700_000_000.0
    seen = []
    relists = 0
    client = FakeClient.new([[:connected, event("u1", "CONTAINER_STARTED_EVENT", (now - 0.25) * 1e9), event("u2", "CONTAINER_CREATED_EVENT", now * 1e9),
                              event("u1", "CONTAINER_STOPPED_EVENT", (now - 0.05) * 1e9)],
                             [{error: "stream broke"}],
                             [:connected]])
    pleg = Node::EventedPLEG.new(client: client, metrics: metrics, on_event: ->(uid, type, id) { seen << [uid, type, id] }, relist: lambda {
      relists += 1
    },
                                 max_stream_retries: 5, retry_delay: 0, clock: -> { now })
    begin
      pleg.watch_events
    rescue StandardError
      nil
    end # the fourth stream raises: FakeClient is empty

    assert_equal [%w[u1 CONTAINER_STARTED_EVENT c-u1], %w[u1 CONTAINER_STOPPED_EVENT c-u1]], seen,
                 "created events are not lifecycle events"
    text = render

    assert_match(/kubelet_evented_pleg_connection_success_count 2/, text)
    assert_match(/kubelet_evented_pleg_connection_latency_seconds_count 3/, text)
    assert_match(/kubelet_evented_pleg_connection_latency_seconds_bucket\{le="0.1"\} 2/, text)
    assert_operator relists, :>=, 1
  end

  def test_giving_up_after_the_retries_hands_back_to_the_generic_relist
    fell_back = false
    client = FakeClient.new([])
    pleg = Node::EventedPLEG.new(client: client, metrics: metrics, on_event: ->(*) {}, on_fallback: lambda {
      fell_back = true
    }, max_stream_retries: 3, retry_delay: 0)
    pleg.start
    pleg.instance_variable_get(:@thread).join(5)

    assert fell_back
    assert_equal 3, pleg.attempts
    refute_predicate pleg, :in_use?
    assert_match(/kubelet_evented_pleg_connection_error_count 3/, render)
  end

  GENERATED = File.expand_path("../../lib/rubernetes/runtime/cri/generated/cri_runtime_v1_services_pb", __dir__)
  RUNTIME_BODY = <<~RUBY
    generated = Rubernetes::Runtime::CRI::Generated::RuntimeV1
    class Runtime < Rubernetes::Runtime::CRI::Generated::RuntimeV1::RuntimeService::Service
      def get_container_events(_request, _call)
        generated = Rubernetes::Runtime::CRI::Generated::RuntimeV1
        Enumerator.new do |yielder|
          2.times do |i|
            yielder << generated::ContainerEventResponse.new(container_id: "c\#{i}", container_event_type: :CONTAINER_STOPPED_EVENT, created_at: Time.now.to_i * 1_000_000_000,
                                                             pod_sandbox_status: generated::PodSandboxStatus.new(metadata: generated::PodSandboxMetadata.new(uid: "uid-\#{i}", name: "p", namespace: "ns")))
          end
        end
      end
    end
    server.handle(Runtime)
  RUBY

  def test_the_cri_client_streams_events_from_a_runtime
    Dir.mktmpdir do |dir|
      socket = File.join(dir, "cri.sock")
      pid = GRPCFakeServer.spawn(socket, RUNTIME_BODY, requires: [GENERATED])
      begin
        client = Rubernetes::Runtime::CRI::Client.new(endpoint: socket, timeout: 10)
        messages = []

        assert client.stream("RuntimeService", "GetContainerEvents", {}) { |message| messages << message }
        assert_equal :connected, messages.first
        events = messages.drop(1)

        assert_equal 2, events.length
        assert_equal "CONTAINER_STOPPED_EVENT", events.first["container_event_type"]
        assert_equal "uid-0", events.first.dig("pod_sandbox_status", "metadata", "uid")
        client.close
      ensure
        GRPCFakeServer.stop(pid)
      end
    end
  end
end
