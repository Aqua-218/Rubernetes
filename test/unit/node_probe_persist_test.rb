# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"

# A probe pass that changes nothing the Pod status shows no longer
# republishes status or persists the node's state; a readiness change still
# does both.
class NodeProbePersistTest < Minitest::Test
  Node = Rubernetes::Node

  class Runtime
    def initialize = @sequence = 0
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"
    def create_container(_sandbox, _spec) = "container-#{@sequence += 1}"
    def start_container(_id) = true
    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "running"}
  end

  class Result
    def initialize(success) = @success = success
    def failed? = @success == false
    def success? = @success == true
    def message = @success ? nil : "exec exited with 1"
  end

  class Probes
    attr_accessor :ready

    def initialize = @ready = true
    def register(*_args, **_options) = self
    def unregister(_id) = true
    def ready?(_id) = @ready
    def liveness_failed?(_id) = false
    def state(_id) = {readiness: {failed: !@ready}}
    def snapshot = {}
    def evaluate(_id, **_options) = {"startup" => nil, "liveness" => nil, "readiness" => Result.new(@ready)}
  end

  class CountingStore < Node::Lifecycle::StateStore
    attr_reader :saves

    def save_body(body)
      @saves = (@saves || 0) + 1
      super
    end
  end

  def test_only_a_changed_probe_pass_is_persisted
    Dir.mktmpdir do |dir|
      store = CountingStore.new(File.join(dir, "state.json"))
      probes = Probes.new
      pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1"},
             "spec" => {"nodeName" => "n", "containers" => [{"name" => "c", "image" => "img",
                                                             "readinessProbe" => {"exec" => {"command" => ["true"]}}}]}}
      lifecycle = Node::Lifecycle.new(runtime: Runtime.new, state_store: store, probe_manager: probes)
      lifecycle.start(pod)
      lifecycle.probe(pod)
      saves = store.saves

      3.times { lifecycle.probe(pod) }
      assert_equal saves, store.saves, "an unchanged probe pass is not persisted"

      probes.ready = false
      lifecycle.probe(pod)
      assert_operator store.saves, :>, saves
      refute lifecycle.record(pod).fetch(:status).fetch("containerStatuses").first.fetch("ready")
      # prober: a failed probe is a Warning "Unhealthy" event carrying the output.
      unhealthy = lifecycle.record(pod).fetch(:events).select { |entry| entry["type"] == "probe.unhealthy" }
      assert_equal 1, unhealthy.length
      assert_equal "Readiness probe failed: exec exited with 1", unhealthy.first["message"]
      assert_equal "Unhealthy", unhealthy.first["reason"]
    end
  end
end
