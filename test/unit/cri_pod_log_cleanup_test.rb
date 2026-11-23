# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/cri"

class CRIPodLogCleanupTest < Minitest::Test
  CRI = Rubernetes::Runtime::CRI
  Node = Rubernetes::Node

  def test_inventory_excludes_old_unowned_and_static_logs
    Dir.mktmpdir("cri-pod-log-ownership") do |root|
      owner = log_store(root)
      api_pod = metadata("api-uid")
      static_pod = metadata("static-uid").merge("annotations" => {"kubernetes.io/config.source" => "file", "kubernetes.io/config.hash" => "static-uid"})
      old_pod = metadata("old-uid")
      owner.prepare(api_pod, node_name: "worker-a")
      owner.prepare(static_pod, node_name: "worker-a")
      Dir.mkdir(owner.path_for(old_pod))
      File.write(File.join(owner.path_for(old_pod), "retained.log"), "legacy Log\n")
      owner.prepare(old_pod)

      restarted = log_store(root)

      assert_equal [api_pod], restarted.api_pods(node_name: "worker-a")
      assert_empty restarted.api_pods(node_name: "worker-b")
      refute restarted.remove(api_pod, node_name: "worker-b")
      refute log_store(root, handler: "different").remove(api_pod, node_name: "worker-a")
      refute restarted.remove(old_pod)
      assert restarted.remove(api_pod, node_name: "worker-a")
      refute_path_exists owner.path_for(api_pod)
      assert_path_exists owner.path_for(static_pod)
      assert_path_exists File.join(owner.path_for(old_pod), "retained.log")
      assert restarted.remove(static_pod, node_name: "worker-a")
    end
  end

  def test_terminal_log_cleanup_retries_after_restarting_the_agent
    Dir.mktmpdir("cri-pod-log-retry") do |root|
      runtime = Object.new
      def runtime.remove_pod_logs(_pod) = raise(IOError, "temporarily busy")
      state_file = File.join(root, "lifecycle.json")
      lifecycle = Node::Lifecycle.new(runtime: runtime, state_store: state_file)
      pod = {"metadata" => metadata("retry-uid")}
      result = lifecycle.reconcile(pod, action: "DELETED")

      assert_equal "CleanupPending", result.state
      assert_match(/pod_logs: .*temporarily busy/, result.cleanup_errors.first)

      released = []
      recovered_runtime = Object.new
      recovered_runtime.define_singleton_method(:remove_pod_logs) { |object| released << object.fetch("metadata") }
      restored = Node::Lifecycle.new(runtime: recovered_runtime, state_store: state_file)

      assert_equal ["retry-uid"], restored.retry_pending_cleanups(now: 1.0)
      assert_equal [pod.fetch("metadata")], released
      assert_nil restored.record("retry-uid")
    end
  end

  private

  def log_store(root, handler: "runc") = CRI::PodLogs.new(root, handler: handler, client: Object.new)

  def metadata(uid) = {"namespace" => "dev", "name" => "example", "uid" => uid}
end
