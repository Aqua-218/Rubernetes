# frozen_string_literal: true

require "fileutils"
require "json"
require "socket"
require "tmpdir"
require "timeout"
require_relative "../test_helper"
require "rubernetes/runtime/cri"
require "rubernetes/runtime/multiplexer"

# The CRI backend against a real containerd with its CRI plugin, started
# privately for the test: its own root, state, socket and CNI directories
# (the node's no-op network), nothing shared with the host's containerd.
# Pulls images, so it runs only when asked:
#
#   RUBERNETES_CRI_INTEGRATION=1 bundle exec ruby -Ilib -Itest test/integration/cri_backend_test.rb
class CRIBackendIntegrationTest < Minitest::Test
  CRI = Rubernetes::Runtime::CRI
  IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"

  def setup
    skip "set RUBERNETES_CRI_INTEGRATION=1 to run against a private containerd" unless ENV["RUBERNETES_CRI_INTEGRATION"] == "1"
    skip "needs root" unless Process.uid.zero?
    skip "containerd is not installed" unless File.executable?("/usr/bin/containerd")

    @dir = Dir.mktmpdir("rbn-cri-")
    @socket = File.join(@dir, "containerd.sock")
    cni_conf, = CRI::Backend.install_cni(conf_dir: File.join(@dir, "cni", "conf"), bin_dir: File.join(@dir, "cni", "bin"))
    config = File.join(@dir, "config.toml")
    File.write(config, <<~TOML)
      version = 3
      root = '#{@dir}/root'
      state = '#{@dir}/state'
      imports = []
      disabled_plugins = ['io.containerd.nri.v1.nri']
      [grpc]
        address = '#{@socket}'
      [ttrpc]
        address = '#{@socket}.ttrpc'
      [plugins.'io.containerd.cri.v1.runtime'.cni]
        bin_dirs = ['#{@dir}/cni/bin']
        conf_dir = '#{cni_conf}'
      [plugins.'io.containerd.internal.v1.opt']
        path = '#{@dir}/opt'
      [plugins.'io.containerd.grpc.v1.cri']
        stream_server_address = '127.0.0.1'
        stream_server_port = '0'
    TOML
    @log = File.join(@dir, "containerd.log")
    @pid = Process.spawn("/usr/bin/containerd", "--config", config, out: @log, err: @log, pgroup: true)
    Timeout.timeout(60) { sleep 0.1 until File.socket?(@socket) }
    @backend = CRI::Backend.new(client: CRI::Client.new(endpoint: @socket, timeout: 120), log_root: File.join(@dir, "pods"),
                                cgroup_parent: "/rbn-cri-test")
    @sandboxes = []
  end

  def teardown
    Array(@sandboxes).each do |id|
      @backend.remove_sandbox(id)
    rescue StandardError
      nil
    end
    @backend&.client&.close
    if @pid
      begin
        Process.kill(:TERM, -@pid)
      rescue StandardError
        nil
      end
      begin
        Process.wait(@pid)
      rescue StandardError
        nil
      end
    end
    if @dir
      File.readlines("/proc/self/mounts").map { |line| line.split[1] }.select { |mount| mount.start_with?(@dir) }
        .sort_by(&:length).reverse_each { |mount| system("umount", "-l", mount, err: File::NULL) }
      FileUtils.rm_rf(@dir)
    end
    begin
      Dir.rmdir("/sys/fs/cgroup/rbn-cri-test") if Dir.exist?("/sys/fs/cgroup/rbn-cri-test")
    rescue StandardError
      nil
    end
  end

  def pod(name, host_network:)
    {"metadata" => {"name" => name, "namespace" => "devx-cri", "uid" => "uid-#{name}"},
     "spec" => {"hostNetwork" => host_network, "containers" => [{"name" => "main", "image" => IMAGE}]}}
  end

  def test_a_pod_runs_logs_execs_and_stops
    assert_equal "v1", @backend.version["runtime_api_version"]
    sandbox = @backend.run_sandbox(pod("cri-a", host_network: false))
    @sandboxes << sandbox
    context = @backend.network_sandbox_context(sandbox)

    refute_equal File.stat("/proc/self/ns/net").ino, context.dig("netns", "inode"), "the sandbox has its own network namespace"

    container = @backend.create_container(sandbox, {"name" => "main", "image" => IMAGE,
                                                    "command" => ["sh", "-c", "echo hello; sleep 0.3; echo oops >&2; sleep 300"],
                                                    "env" => [{"name" => "GREETING", "value" => "hi"}]})
    @backend.start_container(container)

    assert_equal "running", @backend.container_status(container)["state"]
    Timeout.timeout(20) { sleep 0.2 until @backend.logs(container).include?("oops") }

    assert_equal "hello\noops\n", @backend.logs(container)
    result = @backend.exec_sync(container, ["sh", "-c", "echo $GREETING; exit 3"])

    assert_equal ["hi\n", 3], result.values_at("stdout", "exitCode")
    assert_match %r{\Ahttp://127\.0\.0\.1:\d+/exec/}, @backend.exec_url(container, ["true"])

    @backend.stop_container(container, timeout: 2)
    status = @backend.container_status(container)

    assert_equal "terminated", status["state"]
    assert_includes [137, 143], status["exitCode"], "SIGTERM, or SIGKILL after the grace period"
    @backend.remove_container(container)
    @backend.remove_sandbox(sandbox)
    @sandboxes.delete(sandbox)
  end

  # The node's own Pod path: Lifecycle (with the real ContainerSpec) through
  # the Multiplexer to the CRI handler a RuntimeClass names.
  def test_a_pod_runs_through_the_node_lifecycle
    require "rubernetes/node"
    native = Object.new
    def native.run_sandbox(*, **) = raise("the native backend must not be used")
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri-test" => @backend})
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {},
                                                container_spec: Rubernetes::Node::ContainerSpec.new(node_name: "node-a"),
                                                runtime_class_resolver: ->(pod) { pod.dig("spec", "runtimeClassName") })
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "cri-c", "namespace" => "devx-cri", "uid" => "uid-cri-c"},
           "spec" => {"runtimeClassName" => "cri-test", "restartPolicy" => "Never",
                      "containers" => [{"name" => "main", "image" => IMAGE, "command" => ["sh", "-c", "echo from-node $NAME; sleep 300"],
                                        "env" => [{"name" => "NAME", "value" => "lifecycle"}]}]}}
    lifecycle.start(pod)
    record = lifecycle.send(:record, "uid-cri-c")
    @sandboxes << record[:sandbox_id]
    container = record[:containers].first[:id]

    assert_equal "running", runtime.container_status(container)["state"], record[:error].to_s
    Timeout.timeout(20) { sleep 0.2 until runtime.logs(container).include?("from-node") }

    assert_equal "from-node lifecycle\n", runtime.logs(container)
    lifecycle.terminate(pod)
    assert_raises(CRI::Client::Error) { @backend.container_status(container) }
    @sandboxes.delete(record[:sandbox_id]) if record[:sandbox_id]
  end

  # kubectl exec for a CRI container: the node relays the WebSocket upgrade
  # to the runtime's streaming server (StreamProxy) and the stream flows.
  # (containerd's streaming server speaks up to v4.channel.k8s.io.)
  def test_exec_streams_through_the_node_proxy
    require "rubernetes/node/stream_proxy"
    require "rubernetes/transport/request"
    require "rubernetes/transport/response"
    require "rubernetes/transport/websocket"
    sandbox = @backend.run_sandbox(pod("cri-d", host_network: false))
    @sandboxes << sandbox
    container = @backend.create_container(sandbox, {"name" => "main", "image" => IMAGE, "command" => %w[sleep 300]})
    @backend.start_container(container)
    url = @backend.streaming_url(:exec, container, command: ["sh", "-c", "echo streamed; exit 5"], stdout: true, stderr: true)
    headers = Rubernetes::Transport::Headers.new
    headers.add("Connection", "Upgrade")
    headers.add("Upgrade", "websocket")
    headers.add("Sec-WebSocket-Version", "13")
    headers.add("Sec-WebSocket-Key", ["0123456789abcdef"].pack("m0"))
    headers.add("Sec-WebSocket-Protocol", "v4.channel.k8s.io")
    request = Rubernetes::Transport::Request.new(method: "GET", target: "/exec/devx-cri/cri-d/main", headers: headers)
    response = Rubernetes::Node::StreamProxy.response(url, request)
    flunk "refused: #{response.inspect}" if response.is_a?(Array)

    assert_equal 101, response.status
    assert_equal "v4.channel.k8s.io", response.headers["sec-websocket-protocol"]
    client, peer = UNIXSocket.pair
    relay = Thread.new { response.upgrade.call(peer, nil) }
    connection = Rubernetes::Transport::WebSocket::Connection.new(client, client: true, protocol: "v4.channel.k8s.io")
    output = +""
    status = nil
    Timeout.timeout(20) do
      while (message = connection.read_message)
        payload = message.payload
        channel = payload.getbyte(0)
        output << payload.byteslice(1..) if channel == 1
        status = JSON.parse(payload.byteslice(1..)) if channel == 3
        break if status
      end
    end

    assert_equal "streamed\n", output
    assert_equal "Failure", status["status"]
    assert_equal "5", status.dig("details", "causes").find { |cause| cause["reason"] == "ExitCode" }["message"]
    client.close
    relay.join(5)
  end

  def test_a_host_network_sandbox_shares_the_node_namespace
    sandbox = @backend.run_sandbox(pod("cri-b", host_network: true))
    @sandboxes << sandbox

    assert_equal File.stat("/proc/1/ns/net").ino, @backend.network_sandbox_context(sandbox).dig("netns", "inode")
  end
end
