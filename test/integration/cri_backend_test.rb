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
# Set RUBERNETES_CRI_OCI_RUNTIME to the absolute path of a supporting OCI
# runtime when testing user namespaces with host networking.
class CRIBackendIntegrationTest < Minitest::Test
  CRI = Rubernetes::Runtime::CRI
  IMAGE = "registry.k8s.io/e2e-test-images/busybox:1.37.0-1"

  def setup
    skip "set RUBERNETES_CRI_INTEGRATION=1 to run against a private containerd" unless ENV["RUBERNETES_CRI_INTEGRATION"] == "1"
    skip "needs root" unless Process.uid.zero?
    skip "containerd is not installed" unless File.executable?("/usr/bin/containerd")

    @dir = Dir.mktmpdir("rbn-cri-")
    @cgroup_parent = "/#{File.basename(@dir)}"
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
      #{runtime_options}
    TOML
    @log = File.join(@dir, "containerd.log")
    @pid = Process.spawn("/usr/bin/containerd", "--config", config, out: @log, err: @log, pgroup: true)
    Timeout.timeout(60) { sleep 0.1 until File.socket?(@socket) }
    @backend = CRI::Backend.new(client: CRI::Client.new(endpoint: @socket, timeout: 120), log_root: File.join(@dir, "pods"),
                                cgroup_parent: @cgroup_parent)
    @sandboxes = []
  end

  def runtime_options
    binary = ENV.fetch("RUBERNETES_CRI_OCI_RUNTIME", nil)
    return "" if binary.to_s.empty?

    raise ArgumentError, "RUBERNETES_CRI_OCI_RUNTIME must name an executable absolute path" unless binary.start_with?("/") && File.executable?(binary)

    <<~TOML
      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
        BinaryName = #{JSON.generate(binary)}
    TOML
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
      Dir.rmdir(File.join("/sys/fs/cgroup", @cgroup_parent)) if @cgroup_parent
    rescue SystemCallError
      nil
    end
  end

  def pod(name, host_network:)
    {"metadata" => {"name" => name, "namespace" => "devx-cri", "uid" => "uid-#{name}"},
     "spec" => {"hostNetwork" => host_network, "containers" => [{"name" => "main", "image" => IMAGE}]}}
  end

  def test_image_filesystem_capacity_from_live_containerd
    image = @backend.client.image("ImageFsInfo").fetch("image_filesystems").first
    mountpoint = image.dig("fs_id", "mountpoint")
    source = CRI::ImageGCSource.new(client: @backend.client)
    stats = source.fs_stats

    assert_path_exists mountpoint
    assert_equal Rubernetes::Platform::Linux::Statfs.statfs(mountpoint).capacity_bytes, stats.fetch("capacityBytes")
    assert_equal Integer(image.dig("used_bytes", "value")), stats.fetch("usedBytes")
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

  def test_custom_stop_signal_reaches_the_workload
    sandbox = @backend.run_sandbox(pod("cri-stop-signal", host_network: true))
    @sandboxes << sandbox
    script = "trap 'exit 42' USR1; echo ready; while true; do sleep 1; done"
    container = @backend.create_container(sandbox, {"name" => "main", "image" => IMAGE, "command" => ["sh", "-c", script],
                                                    "stop_signal" => "SIGUSR1"})
    @backend.start_container(container)
    Timeout.timeout(20) { sleep 0.1 until @backend.logs(container).include?("ready") }

    assert_equal "SIGUSR1", @backend.container_stop_signal(container)
    @backend.stop_container(container, timeout: 4)

    assert_equal 42, @backend.container_status(container)["exitCode"]
  end

  def test_container_log_rotation_reopens_independent_live_container_logs
    sandbox = @backend.run_sandbox(pod("cri-log-rotation", host_network: true))
    @sandboxes << sandbox
    logs = %w[first second].map { |name| start_log_rotation_container(sandbox, name) }
    ready = Queue.new
    permits = Queue.new
    errors = Queue.new
    now = Time.utc(2026, 9, 24, 3)
    unavailable = nil
    client = @backend.client
    tracing = Object.new
    tracing.define_singleton_method(:runtime) do |method, request|
      if method == "ReopenContainerLog"
        ready << request.fetch("container_id")
        permits.pop
        request = request.merge("container_id" => "missing-log-fixture-container") if request.fetch("container_id") == unavailable
      end
      client.runtime(method, request)
    end
    manager = CRI::LogManager.new(client: tracing, max_workers: 2, max_files: 3, max_size: "12.8e1", clock: -> { now },
                                  error_handler: ->(error, id) { errors << [id, error] })

    scan = nil
    3.times do |round|
      current_archive = now.strftime(CRI::LogManager::TIMESTAMP)
      scan = Thread.new { manager.rotate_logs }
      actual_ids = Array.new(2) { Timeout.timeout(10) { ready.pop } }

      assert_equal logs.map(&:first).sort, actual_ids.sort
      logs.each do |_, path, name|
        assert_includes File.binread("#{path}.#{current_archive}"), rotation_message(name, round)
      end
      2.times { permits << true }

      assert scan.join(10), "concurrent CRI reopen did not finish"
      assert_empty errors
      logs.each do |id, path, name|
        assert_equal 0, File.size(path)
        assert_equal 0, @backend.exec_sync(id, ["touch", "/tmp/rotate-phase-#{round + 1}"]).fetch("exitCode")
        wait_for_rotation_message(path, rotation_message(name, round + 1))
      end
      now += 60
    end

    logs.each do |_, path, name|
      assert_equal ["#{path}.20260924-030100.gz", "#{path}.20260924-030200"], Dir.glob("#{path}.*")
      assert_includes Zlib::GzipReader.open("#{path}.20260924-030100.gz", &:read), rotation_message(name, 1)
      assert_includes File.binread(path), rotation_message(name, 3)
    end

    unavailable, failed_path, failed_name = logs.first
    scan = Thread.new { manager.rotate_logs }
    2.times { Timeout.timeout(10) { ready.pop } }
    2.times { permits << true }

    assert scan.join(10)
    failed_id, error = errors.pop(true)

    assert_equal unavailable, failed_id
    assert_instance_of CRI::Client::Error, error
    assert_includes File.binread(failed_path), rotation_message(failed_name, 3)
    assert_path_exists "#{failed_path}.20260924-030100.gz"
    _, peer_path, peer_name = logs.last

    assert_includes File.binread("#{peer_path}.20260924-030300"), rotation_message(peer_name, 3)
    assert_equal 0, File.size(peer_path)

    logs.each do |_id, path, _name|
      manager.clean(path)

      refute_path_exists path
      assert_empty Dir.glob("#{path}.*")
    end
  ensure
    permits&.close
    scan&.join(10)
  end

  def start_log_rotation_container(sandbox, name)
    steps = Array.new(4) do |round|
      wait = round.positive? ? "while [ ! -e /tmp/rotate-phase-#{round} ]; do sleep 0.1; done; " : ""
      "#{wait}echo #{rotation_message(name, round)}"
    end
    script = (steps << "exec sleep 300").join("; ")
    container = @backend.create_container(sandbox, {"name" => name, "image" => IMAGE, "command" => ["sh", "-c", script]})
    @backend.start_container(container)
    path = @backend.client.runtime("ContainerStatus", {"container_id" => container}).dig("status", "log_path")
    wait_for_rotation_message(path, rotation_message(name, 0))
    [container, path, name]
  end

  def rotation_message(name, round) = "#{name}-rotation-#{round}-#{"x" * 192}"

  def wait_for_rotation_message(path, message)
    Timeout.timeout(10) { sleep 0.05 until File.file?(path) && File.binread(path).include?(message) }
  end

  # The node's own Pod path: Lifecycle (with the real ContainerSpec) through
  # the Multiplexer to the CRI handler a RuntimeClass names.
  def test_a_pod_runs_through_the_node_lifecycle
    require "rubernetes/node"
    native = Object.new
    def native.run_sandbox(*, **) = raise("the native backend must not be used")
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri-test" => @backend})
    attempted_deletes = []
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, sleeper: ->(_) {},
                                                container_spec: Rubernetes::Node::ContainerSpec.new(node_name: "node-a"),
                                                runtime_class_resolver: ->(pod) { pod.dig("spec", "runtimeClassName") },
                                                pod_deleter: ->(**target) { attempted_deletes << target })
    pod = {"apiVersion" => "v1", "kind" => "Pod",
           "metadata" => {"name" => "cri-c", "namespace" => "devx-cri", "uid" => "uid-cri-c"},
           "spec" => {"nodeName" => "node-a", "runtimeClassName" => "cri-test", "restartPolicy" => "Never",
                      "containers" => [{"name" => "main", "image" => IMAGE, "command" => ["sh", "-c", "echo from-node $NAME; sleep 300"],
                                        "env" => [{"name" => "NAME", "value" => "lifecycle"}]}]}}
    lifecycle.start(pod)
    record = lifecycle.send(:record, "uid-cri-c")
    @sandboxes << record[:sandbox_id]
    container = record[:containers].first[:id]

    assert_equal "running", runtime.container_status(container)["state"], record[:error].to_s
    Timeout.timeout(20) { sleep 0.2 until runtime.logs(container).include?("from-node") }

    assert_equal "from-node lifecycle\n", runtime.logs(container)
    assert_raises(CRI::Backend::Error) { @backend.remove_pod_logs(pod) }
    lifecycle.terminate(pod)
    assert_raises(CRI::Client::Error) { @backend.container_status(container) }
    @sandboxes.delete(record[:sandbox_id]) if record[:sandbox_id]
    log_dir = File.join(@backend.log_root, "devx-cri_cri-c_uid-cri-c")
    log_path = File.join(log_dir, "main", "0.log")

    assert_includes File.read(log_path), "from-node lifecycle"
    deleting = pod.merge("metadata" => pod.fetch("metadata").merge("deletionTimestamp" => "2026-11-19T00:00:00Z", "finalizers" => ["test/finalizer"]))
    lifecycle.reconcile(deleting, action: "MODIFIED")

    assert_equal [{namespace: "devx-cri", name: "cri-c", uid: "uid-cri-c"}], attempted_deletes
    assert_path_exists log_path

    # The node was down when the finalizer was released. Its first complete
    # relist has no watch tombstone and no remaining lifecycle record.
    restored = CRI::Backend.new(client: @backend.client, log_root: @backend.log_root)
    fresh_runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri-test" => restored})
    fresh_lifecycle = Rubernetes::Node::Lifecycle.new(runtime: fresh_runtime, sleeper: ->(_) {})
    source = Object.new
    def source.list(**) = {"items" => [], "metadata" => {"resourceVersion" => "30"}}
    agent = Rubernetes::Node::Agent.new(
      node_name: "node-a", api: source, source: source, runtime: fresh_runtime, lifecycle: fresh_lifecycle, sleeper: ->(_) {}
    )
    agent.sync_loop.resync
    agent.sync_loop.instance_variable_get(:@workers).drain(timeout: 5)

    refute_path_exists log_dir
  ensure
    agent&.sync_loop&.stop
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

  def test_a_user_namespace_pod_can_share_the_host_network
    require "rubernetes/platform/linux/userns"
    allocator = Rubernetes::Platform::Linux::UserNamespace::Allocator.new(path: File.join(@dir, "userns.json"))
    allocations = CRI::UserNamespaces::Allocations.new(-> { allocator })
    @backend = CRI::Backend.new(client: @backend.client, log_root: File.join(@dir, "pods"), cgroup_parent: @cgroup_parent,
                                user_namespace_allocations: allocations, user_namespaces_host_network: true)
    skip "containerd's default handler did not advertise user namespaces with host networking" unless @backend.runtime_features["userNamespacesHostNetwork"]

    workload = pod("cri-userns", host_network: true)
    workload["spec"]["hostUsers"] = false
    sandbox = @backend.run_sandbox(workload)
    @sandboxes << sandbox
    mounted_file = File.join(@dir, "mapped-file")
    File.write(mounted_file, "mapped mount\n")
    File.chmod(0o600, mounted_file)
    mounts = [{"source" => mounted_file, "destination" => "/mapped-file", "readonly" => true}]
    container = @backend.create_container(sandbox, {"name" => "main", "image" => IMAGE, "command" => %w[sleep 300], "mounts" => mounts})
    @backend.start_container(container)
    command = "cat /proc/self/uid_map /proc/self/gid_map; readlink /proc/self/ns/net; cat /mapped-file"
    result = @backend.exec_sync(container, ["sh", "-c", command])

    assert_equal 0, result.fetch("exitCode"), result.inspect
    uid_map, gid_map, netns, file_contents = result.fetch("stdout").lines.map(&:strip)
    mapping = allocator.lookup("cri-pod-uid-cri-userns")

    assert_equal [0, mapping.uid_base, mapping.size], uid_map.split.map(&:to_i)
    assert_equal [0, mapping.gid_base, mapping.size], gid_map.split.map(&:to_i)
    assert_equal File.readlink("/proc/self/ns/net"), netns
    assert_equal "mapped mount", file_contents
  end
end
