# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/multiplexer"

# ContainerCheckpoint (Beta, on): kubelet POST /checkpoint/{ns}/{pod}/{container}
# asks the container's runtime for a checkpoint archive (CRI
# CheckpointContainer); a runtime that cannot checkpoint answers 500 with
# upstream's message, and unknown Pods and containers 404.
class ContainerCheckpointTest < Minitest::Test
  Node = Rubernetes::Node

  Lifecycle = Struct.new(:records)
  ExecService = Struct.new(:runtime)

  class CheckpointingBackend
    attr_reader :calls

    def initialize = @calls = []
    def checkpoint_container(container, location:, timeout:) = @calls << [container, location, timeout]
  end

  def setup
    @dir = Dir.mktmpdir("rbn-checkpoint-")
    pod = {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1"},
           "spec" => {"containers" => [{"name" => "app"}], "initContainers" => [{"name" => "init"}]}}
    @lifecycle = Lifecycle.new({"u1" => {pod: pod, containers: [{name: "app", id: "ctr-app", started: true}]}})
  end

  def teardown = FileUtils.rm_rf(@dir)

  def server(runtime)
    Node::StreamingServer.new(log_service: Object.new, port: 0, lifecycle: @lifecycle, exec_service: ExecService.new(runtime),
                              checkpoint_dir: @dir)
  end

  def post(server, path)
    request = Rubernetes::Transport::Request.new(method: "POST", target: path, headers: Rubernetes::Transport::Headers.new)
    status, _headers, body = server.call(request)
    [status, body.join]
  end

  def test_the_runtime_writes_the_archive_and_the_path_is_answered
    backend = CheckpointingBackend.new
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => backend})
    status, body = post(server(runtime), "/checkpoint/ns/web/app?timeout=7")

    assert_equal 200, status, body
    location = JSON.parse(body).fetch("items").first

    assert_match(%r{\A#{Regexp.escape(@dir)}/checkpoint-web_ns-app-\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|[+-]\d\d:\d\d)\.tar\z}, location)
    assert_equal [["ctr-app", location, 7]], backend.calls
  end

  def test_errors_follow_the_kubelet
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => Object.new})
    subject = server(runtime)

    assert_equal [404, "pod does not exist\n"], post(subject, "/checkpoint/ns/missing/app")
    assert_equal [404, "container nope does not exist\n"], post(subject, "/checkpoint/ns/web/nope")
    assert_equal [404, "cannot parse value of timeout parameter\n"], post(subject, "/checkpoint/ns/web/app?timeout=x")
    status, body = post(subject, "/checkpoint/ns/web/app")

    assert_equal 500, status
    assert_match(%r{\Acheckpointing of ns/web/app failed \(checkpoint/restore support not available}, body)
  end
end
