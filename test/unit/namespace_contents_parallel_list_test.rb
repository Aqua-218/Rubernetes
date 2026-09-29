# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

# Only the kinds some controller watches have an informer; every other
# namespaced kind costs a real list call.  There are over a hundred of them,
# and issuing the lists one after another made a single terminating-namespace
# reconcile take 5-8 s.  A conformance run deletes hundreds of namespaces, so
# the shared worker pool filled with namespace reconciles: measured on a live
# round, the queue grew to 454 keys, the average key waited 87 s, and nothing
# else reconciled for thirteen minutes.
class NamespaceContentsParallelListTest < Minitest::Test
  Adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter
  Descriptor = Rubernetes::Controller::ResourceDescriptor

  # Every list blocks until CONTENT_LIST_PARALLELISM of them are in flight, so
  # the call can only return if they really do overlap.
  class LatchingClient
    attr_reader :listed

    def initialize(width)
      @width = width
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @in_flight = 0
      @listed = []
    end

    def get(resource, namespace: nil, api_version: nil, query: nil)
      @mutex.synchronize do
        @listed << resource
        @in_flight += 1
        @condition.broadcast if @in_flight >= @width
        @condition.wait(@mutex, 5) while @in_flight < @width
      end
      {"apiVersion" => api_version, "kind" => "List",
       "metadata" => {"resourceVersion" => "1"},
       "items" => [{"apiVersion" => api_version, "kind" => resource.to_s,
                    "metadata" => {"name" => "#{resource}-1", "namespace" => namespace}}]}
    end
  end

  KINDS = %w[ConfigMap Secret ServiceAccount Service Endpoints Pod LimitRange ResourceQuota].freeze

  def test_the_content_lists_of_a_namespace_go_out_together
    width = Adapter::CONTENT_LIST_PARALLELISM
    client = LatchingClient.new(width)
    descriptors = KINDS.first(width).map { |kind| Descriptor.parse(kind) }
    adapter = Adapter.new(client: client, resource_descriptors: descriptors)

    contents = Timeout.timeout(20) { adapter.namespaced_contents("ns") }

    assert_equal width, client.listed.length
    assert_equal width, contents.length, "one object came back from each kind"
  end

  # Cluster-scoped kinds cannot hold a namespace's contents, and the Namespace
  # itself is not its own content.
  class RecordingClient
    attr_reader :listed

    def initialize = @listed = []

    def get(resource, namespace: nil, api_version: nil, query: nil)
      @listed << resource.to_s
      {"apiVersion" => api_version, "kind" => "List",
       "metadata" => {"resourceVersion" => "1"}, "items" => []}
    end
  end

  def test_cluster_scoped_kinds_and_the_namespace_itself_are_never_listed
    client = RecordingClient.new
    descriptors = [Descriptor.parse("ConfigMap"), Descriptor.parse("Node"),
                   Descriptor.parse("Namespace"), Descriptor.parse("PersistentVolume")]
    adapter = Adapter.new(client: client, resource_descriptors: descriptors)

    adapter.namespaced_contents("ns")

    assert_equal ["configmaps"], client.listed
  end
end
