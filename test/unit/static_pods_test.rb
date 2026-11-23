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
    attr_reader :reconciled, :terminated, :records

    def initialize
      @reconciled = []
      @terminated = []
      @records = {}
    end

    def reconcile(pod) = @reconciled << pod
    def terminate(pod) = @terminated << pod
    def record(uid) = @records[uid]
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

  def teardown
    @subject.stop
    FileUtils.rm_rf(@dir)
  end

  def write(name, pod) = File.write(File.join(@dir, name), JSON.generate(pod))

  def manifest(name = "etcd", spec = {"containers" => [{"name" => "c", "image" => "busybox"}]})
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name}, "spec" => spec}
  end

  def test_http_snapshot_rejects_invalid_lists_and_withdraws_only_http_pods
    write("local.json", manifest("local"))
    remote = manifest("remote")
    body = YAML.dump(remote)
    subject = static_http_subject { body }
    initial = subject.sync
    url_pod = initial.values.find { |pod| pod.dig("metadata", "name") == "remote-worker-0" }
    mirror = @api.created.find { |pod| pod.dig("metadata", "name") == "remote-worker-0" }
    uid = url_pod.dig("metadata", "uid")

    assert_equal "http", url_pod.dig("metadata", "annotations", Node::StaticPods::CONFIG_SOURCE)
    assert_equal uid, mirror.dig("metadata", "annotations", Node::StaticPods::CONFIG_MIRROR)
    assert_equal mirror.dig("metadata", "uid"), subject.mirror_uid(uid)
    assert_nil url_pod.dig("spec", "tolerations")

    invalid = manifest("invalid", {"containers" => [{"name" => "INVALID!", "image" => "busybox"}]})
    body = JSON.generate({"apiVersion" => "v1", "kind" => "PodList", "items" => [manifest("other"), invalid]})

    assert_equal initial.keys, subject.sync.keys
    assert_includes subject.errors, :http
    assert_empty @lifecycle.terminated

    body = JSON.generate({"apiVersion" => "v1", "kind" => "PodList", "items" => []})
    remaining = subject.sync

    assert_equal(["local-worker-0"], remaining.values.map { |pod| pod.dig("metadata", "name") })
    assert_equal [url_pod], @lifecycle.terminated
    assert_equal(["local-worker-0"], @api.pods.map { |pod| pod.dig("metadata", "name") })
  end

  def test_empty_successful_response_withdraws_http_workload_after_transport_failure
    body = JSON.generate(manifest("remote"))
    subject = static_http_subject do
      raise Node::StaticPodHTTP::Error, "HTTP 503" if body.nil?

      body
    end
    initial = subject.sync
    body = nil

    assert_equal initial, subject.sync
    assert_equal "HTTP 503", subject.errors.fetch(:http)
    assert_empty @lifecycle.terminated

    body = ""

    assert_empty subject.sync
    assert_equal initial.values, @lifecycle.terminated
    assert_empty @api.pods
  end

  def test_file_source_updates_while_the_http_source_is_waiting_for_a_response
    write("local.json", manifest("local"))
    release = Queue.new
    requested = Queue.new
    subject = static_http_subject do
      requested << true
      release.pop
      ""
    end
    subject.start
    requested.pop(timeout: 2) or flunk("HTTP poll did not start")
    Timeout.timeout(2) { sleep 0.01 until subject.pods.any? }

    assert_equal "local-worker-0", subject.pods.first.dig("metadata", "name")
  ensure
    release << true
    subject&.stop
  end

  def test_http_transport_rejects_an_oversized_manifest
    listener = TCPServer.new("127.0.0.1", 0)
    worker = Thread.new do
      peer = listener.accept
      while (line = peer.gets)
        break if line == "\r\n"
      end
      peer.write("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n123456")
    ensure
      peer&.close
    end
    url = "http://127.0.0.1:#{listener.addr[1]}/manifest"
    transport = Node::StaticPodHTTP.new(url: url, headers: {}, max_bytes: 4)

    error = assert_raises(Node::StaticPodHTTP::Error) { transport.read }

    assert_match(/manifest exceeds 4 bytes/, error.message)
  ensure
    listener&.close
    worker&.join(2)
  end

  def static_http_subject(&)
    subject = Node::StaticPods.new(path: @dir, url: "https://example.invalid/static-pod", node_name: "worker-0",
                                   lifecycle: @lifecycle, api: @api)
    subject.instance_variable_get(:@http_source).define_singleton_method(:read, &)
    subject
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

  def test_unchanged_status_reaches_new_and_recreated_mirrors
    write("etcd.json", manifest)
    reports = []
    delegate = Object.new
    delegate.define_singleton_method(:report) { |pod, status| reports << [pod.dig("metadata", "uid"), status["phase"]] }
    reporter = Node::StaticPods::Reporter.new(delegate, @subject)
    status = Node::Status.new(reporter: reporter, report_target: reporter.method(:status_report_target))
    @subject.status_publisher = status.method(:republish)
    pod = @subject.read_manifests.values.first
    status.aggregate(pod, phase: "Failed")

    assert_empty reports

    @subject.sync
    @subject.sync
    @api.delete_pod(namespace: "default", name: "etcd-worker-0", uid: "mirror-0")
    2.times { @subject.sync }

    assert_equal [%w[mirror-0 Failed], %w[mirror-1 Failed]], reports
  end

  def test_gracefully_deleted_mirror_is_replaced_without_stopping_its_static_pod
    write("etcd.json", manifest)
    uid = @subject.sync.keys.first
    @api.pods.first.fetch("metadata")["deletionTimestamp"] = "2026-11-19T00:00:00Z"
    @subject.sync

    assert_equal [%w[default etcd-worker-0 mirror-0]], @api.deleted
    assert_equal "mirror-1", @subject.mirror_uid(uid)
    assert_empty @lifecycle.terminated
  end

  def test_replacement_keeps_the_old_mirror_until_termination_finishes
    queued = []
    @subject.enqueue_pod = ->(pod, action:, worker_key:) { queued << [pod.dig("metadata", "uid"), action] }
    write("etcd.json", manifest)
    original = @subject.sync.keys.first
    @lifecycle.records[original] = {state: "Running"}

    write("etcd.json", manifest("etcd", {"containers" => [{"name" => "c", "image" => "nginx"}]}))
    replacement = @subject.sync.keys.first

    assert_equal [[original, "SYNC"], [original, "DELETED"]], queued
    assert_equal "mirror-0", @subject.mirror_uid(original)
    assert_nil @subject.mirror_uid(replacement)

    @lifecycle.records.delete(original)
    @subject.sync

    assert_equal [replacement, "SYNC"], queued.last
    assert_equal "mirror-1", @subject.mirror_uid(replacement)
    assert_equal [%w[default etcd-worker-0 mirror-0]], @api.deleted
  end

  def test_single_manifest_path_keeps_running_pod_during_an_invalid_edit
    file = File.join(@dir, "control.json")
    subject = Node::StaticPods.new(path: file, node_name: "worker-0", lifecycle: @lifecycle, api: @api)
    write("control.json", manifest("control", {"containers" => [{"name" => "c", "image" => "v1"}]}))
    original = subject.sync.keys

    assert_equal 1, original.size
    File.write(file, "unfinished")

    assert_equal original, subject.sync.keys
    assert_includes subject.errors.keys, file
    assert_empty @lifecycle.terminated

    write("control.json", manifest("control", {"containers" => [{"name" => "c", "image" => "v2"}]}))

    refute_equal original, subject.sync.keys
    assert_empty subject.errors
    File.delete(file)

    assert_empty subject.sync
    assert_equal 2, @lifecycle.terminated.length
  end

  def test_file_events_distinguish_an_atomic_update_from_a_rapid_recreation
    skip "inotify requires Linux" unless RUBY_PLATFORM.include?("linux")

    file = File.join(@dir, "control.json")
    write("control.json", manifest)
    actions = Queue.new
    @subject.enqueue_pod = lambda do |pod, action:, worker_key:|
      uid = pod.dig("metadata", "uid")
      action == "DELETED" ? @lifecycle.records.delete(uid) : @lifecycle.records[uid] = {state: "Running"}
      actions << [uid, action]
    end
    @subject.start
    uid, action = actions.pop(timeout: 5)

    assert_equal "SYNC", action
    write(".replacement.json", manifest)
    File.rename(File.join(@dir, ".replacement.json"), file)

    assert_equal [uid, "SYNC"], actions.pop(timeout: 5)
    assert_empty @api.deleted
    File.unlink(file)
    write("control.json", manifest)

    assert_equal [uid, "DELETED"], actions.pop(timeout: 5)
    assert_equal [uid, "SYNC"], actions.pop(timeout: 5)
    assert_equal [%w[default etcd-worker-0 mirror-0]], @api.deleted
    assert_equal "mirror-1", @subject.mirror_uid(uid)
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
