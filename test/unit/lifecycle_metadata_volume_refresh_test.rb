# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# A label or annotation change reaches downward API volume files on the
# update itself (kubelet syncs the Pod on the update event), not on the next
# periodic volume sync 15 s later.
class LifecycleMetadataVolumeRefreshTest < Minitest::Test
  class Runtime
    def run_sandbox(_pod, runtime_class: nil) = "sandbox-1"

    def create_container(_sandbox, spec)
      @sequence = @sequence.to_i + 1
      "container-#{@sequence}"
    end

    def start_container(_id) = true
    def stop_container(_id, timeout: nil) = true
    def remove_container(_id) = true
    def remove_sandbox(_id) = true
    def wait_container(_id) = {"state" => "terminated", "exitCode" => 0}
  end

  class FakeVolumes
    attr_reader :refreshes

    def initialize
      @refreshes = []
    end

    def prepare(_pod, **_options) = {"ids" => [], "mounts" => {}}
    def refresh(*_args, **_options) = true
    def release(*_args, **_options) = true

    def refresh_contents(pod, _handle, **_options)
      @refreshes << pod.dig("metadata", "labels")
      []
    end
  end

  def pod(labels)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "p", "namespace" => "ns", "uid" => "u1", "labels" => labels},
     "spec" => {"nodeName" => "n", "restartPolicy" => "Always",
                "containers" => [{"name" => "app", "image" => "img"}],
                "volumes" => [{"name" => "info", "downwardAPI" => {"items" => [{"path" => "labels", "fieldRef" => {"fieldPath" => "metadata.labels"}}]}}]}}
  end

  def setup
    @now = 0.0
    @volumes = FakeVolumes.new
    @lifecycle = Rubernetes::Node::Lifecycle.new(runtime: Runtime.new, pod_volumes: @volumes,
                                                 clock: -> { Time.at(@now).utc }, sleeper: ->(seconds) { @now += seconds })
    @lifecycle.start(pod({"a" => "1"}))
    @lifecycle.reconcile(pod({"a" => "1"}))
  end

  def test_a_label_change_refreshes_at_once
    before = @volumes.refreshes.length
    @lifecycle.reconcile(pod({"a" => "1"}))
    assert_equal before, @volumes.refreshes.length, "an unchanged Pod waits for the periodic sync"

    @lifecycle.reconcile(pod({"a" => "2"}))
    assert_equal before + 1, @volumes.refreshes.length
    assert_equal({"a" => "2"}, @volumes.refreshes.last)
  end
end
