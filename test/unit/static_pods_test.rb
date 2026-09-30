# frozen_string_literal: true

require "fileutils"
require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"

# kubelet staticPodPath: rubernetes-agent.static_pod_path was validated and
# then ignored.  StaticPods reads the manifests, applies the kubelet's
# defaults, refuses Pods that reference API objects
# (PreventStaticPodAPIReferences), runs them through the lifecycle, keeps a
# mirror Pod owned by the Node in the API and writes status to the mirror.
class StaticPodsTest < Minitest::Test
  Node = Rubernetes::Node

  class Lifecycle
    attr_reader :reconciled, :terminated

    def initialize
      @reconciled = []
      @terminated = []
    end

    def reconcile(pod) = @reconciled << pod
    def terminate(pod) = @terminated << pod
  end

  class API
    attr_reader :created, :deleted, :pods

    def initialize
      @pods = []
      @created = []
      @deleted = []
    end

    def list(node_name:) = @pods.select { |pod| pod.dig("spec", "nodeName") == node_name }
    def read_object(resource, name, **) = resource == "nodes" ? {"metadata" => {"name" => name, "uid" => "node-uid"}} : nil

    def create_mirror_pod(pod)
      stored = pod.merge("metadata" => pod["metadata"].merge("uid" => "mirror-#{@created.length}"))
      @created << stored
      @pods << stored
      stored
    end

    def delete_pod(namespace:, name:, uid:)
      @deleted << [namespace, name, uid]
      @pods.reject! { |pod| pod.dig("metadata", "uid") == uid }
    end
  end

  def setup
    @dir = Dir.mktmpdir("rbn-static-")
    @lifecycle = Lifecycle.new
    @api = API.new
    @subject = Node::StaticPods.new(path: @dir, node_name: "Worker-0", lifecycle: @lifecycle, api: @api)
  end

  def teardown = FileUtils.rm_rf(@dir)

  def write(name, pod) = File.write(File.join(@dir, name), JSON.generate(pod))

  def manifest(name = "etcd", spec = {"containers" => [{"name" => "c", "image" => "busybox"}]})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name}, "spec" => spec}
  end

  def test_manifests_run_with_the_kubelet_defaults_and_get_a_mirror
    write("etcd.json", manifest)
    File.write(File.join(@dir, ".hidden.json"), JSON.generate(manifest("hidden")))
    @subject.sync
    pod = @lifecycle.reconciled.last

    assert_equal "etcd-worker-0", pod.dig("metadata", "name")
    assert_equal "default", pod.dig("metadata", "namespace")
    assert_equal "Worker-0", pod.dig("spec", "nodeName")
    assert_equal pod.dig("metadata", "uid"), pod.dig("metadata", "annotations", "kubernetes.io/config.hash")
    assert_equal "file", pod.dig("metadata", "annotations", "kubernetes.io/config.source")
    assert_includes pod.dig("spec", "tolerations"), {"operator" => "Exists", "effect" => "NoExecute"}
    assert_equal 1, @lifecycle.reconciled.length, "a hidden file is not a manifest"
    mirror = @api.created.first

    assert_equal pod.dig("metadata", "uid"), mirror.dig("metadata", "annotations", "kubernetes.io/config.mirror")
    assert_equal [{"apiVersion" => "v1", "kind" => "Node", "name" => "Worker-0", "uid" => "node-uid", "controller" => true}],
                 mirror.dig("metadata", "ownerReferences")
    assert_equal "mirror-0", @subject.mirror_uid(pod.dig("metadata", "uid"))

    @subject.sync

    assert_equal 1, @api.created.length, "an up-to-date mirror is kept"
  end

  def test_status_goes_to_the_mirror_and_waits_for_it
    write("etcd.json", manifest)
    reports = []
    delegate = Object.new
    delegate.define_singleton_method(:report) { |pod, status| reports << [pod.dig("metadata", "uid"), status] }
    reporter = Node::StaticPods::Reporter.new(delegate, @subject)
    @subject.send(:read_manifests).each_value { |pod| reporter.report(pod, {"phase" => "Running"}) }

    assert_empty reports, "no mirror yet"
    @subject.sync
    pod = @lifecycle.reconciled.last
    reporter.report(pod, {"phase" => "Running"})

    assert_equal [["mirror-0", {"phase" => "Running"}]], reports
    reporter.report({"metadata" => {"uid" => "api-pod"}}, {"phase" => "Pending"})

    assert_equal "api-pod", reports.last.first, "an API Pod reports as itself"
  end

  def test_api_references_are_refused_and_a_removed_manifest_stops_its_pod
    write("etcd.json", manifest)
    write("bad.json", manifest("bad", {"serviceAccountName" => "x", "containers" => [{"name" => "c", "image" => "i"}]}))
    write("cm.json",
          manifest("cm",
                   {"containers" => [{"name" => "c", "image" => "i"}], "volumes" => [{"name" => "v", "configMap" => {"name" => "x"}}]}))
    @subject.sync

    assert_equal(%w[etcd-worker-0], @lifecycle.reconciled.map { |pod| pod.dig("metadata", "name") })
    assert_equal "static pods may not reference serviceaccounts", @subject.errors[File.join(@dir, "bad.json")]
    assert_equal "static pods may not reference configmaps", @subject.errors[File.join(@dir, "cm.json")]

    File.delete(File.join(@dir, "etcd.json"))
    @subject.sync

    assert_equal(%w[etcd-worker-0], @lifecycle.terminated.map { |pod| pod.dig("metadata", "name") })
    assert_equal [%w[default etcd-worker-0 mirror-0]], @api.deleted, "the orphaned mirror is deleted"
  end
end
