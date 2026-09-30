# frozen_string_literal: true

require "socket"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/runtime/cri"
require "rubernetes/runtime/multiplexer"

# The CRI backend's translation (kuberuntime generatePodSandboxConfig /
# generateContainerConfig, status and streaming) against a recording client.
class CRIBackendTest < Minitest::Test
  CRI = Rubernetes::Runtime::CRI

  class FakeClient
    attr_reader :calls

    def initialize(pid: Process.pid)
      @calls = []
      @pid = pid
      @images = {}
    end

    def runtime(method, request = {}, **)
      @calls << [method, request]
      case method
      when "RunPodSandbox" then {"pod_sandbox_id" => "sb1"}
      when "PodSandboxStatus" then {"info" => {"info" => JSON.generate("pid" => @pid)}}
      when "CreateContainer" then {"container_id" => "c1"}
      when "ContainerStatus"
        {"status" => {"id" => "c1", "state" => "CONTAINER_EXITED", "exit_code" => 137, "reason" => "OOMKilled",
                      "started_at" => "1790000000000000000", "finished_at" => "1790000001500000000", "image" => {"image" => "busybox"}}}
      when "ExecSync" then {"stdout" => ["out\n"].pack("m0"), "stderr" => "", "exit_code" => 2}
      when "Exec" then {"url" => "http://127.0.0.1:1/exec/abc"}
      when "PortForward" then {"url" => "http://127.0.0.1:1/portforward/abc"}
      else {}
      end
    end

    def image(method, request = {}, **)
      @calls << [method, request]
      if method == "ImageStatus"
        {"image" => @images[request.dig("image",
                                        "image")]}
      else
        (@images[request.dig("image", "image")] = {"id" => "sha256:x"})
      end
    end

    def close; end
  end

  def setup
    @dir = Dir.mktmpdir("cri-backend")
    @client = FakeClient.new
    # A scratch cgroup tree: the backend never touches the host's here.
    @cgroups = File.join(@dir, "cgroup")
    FileUtils.mkdir_p(@cgroups)
    File.write(File.join(@cgroups, "cgroup.subtree_control"), "")
    @backend = CRI::Backend.new(client: @client, handler: "runc", log_root: File.join(@dir, "pods"), cgroup_parent: "/rbn",
                                cgroup_root: @cgroups)
  end

  def teardown = FileUtils.rm_rf(@dir)

  def pod
    {"metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1", "labels" => {"app" => "web"}},
     "spec" => {"hostname" => "h", "shareProcessNamespace" => true,
                "securityContext" => {"sysctls" => [{"name" => "net.ipv4.ping_group_range", "value" => "0 1"}], "supplementalGroups" => [5]},
                "dnsConfig" => {"nameservers" => ["1.1.1.1"], "options" => [{"name" => "ndots", "value" => "2"}]},
                "containers" => [{"name" => "main", "image" => "busybox", "ports" => [{"containerPort" => 80, "hostPort" => 8080}]}]}}
  end

  def spec
    {"name" => "main", "image" => "busybox", "command" => ["sh", "-c"], "args" => ["echo hi"], "cwd" => "/work",
     "env" => [{"name" => "A", "value" => "1"}],
     "mounts" => [{"source" => "/host/data", "destination" => "/data", "readonly" => true}, {"name" => "no-source"}],
     "resources" => {"requests" => {"cpu" => "250m"}, "limits" => {"cpu" => "500m", "memory" => "64Mi"}},
     "security_context" => {"runAsUser" => 1000, "allowPrivilegeEscalation" => false, "capabilities" => {"drop" => ["ALL"]}}}
  end

  def test_sandbox_config
    assert_equal "sb1", @backend.run_sandbox(pod)
    method, request = @client.calls.last

    assert_equal %w[RunPodSandbox runc], [method, request["runtime_handler"]]
    config = request["config"]

    assert_equal({"name" => "web", "uid" => "u1", "namespace" => "ns", "attempt" => 0}, config["metadata"])
    assert_equal File.join(@dir, "pods", "ns_web_u1"), config["log_directory"]
    assert File.directory?(config["log_directory"])
    assert_equal "u1", config.dig("labels", "io.kubernetes.pod.uid")
    assert_equal [{"protocol" => "TCP", "container_port" => 80, "host_port" => 8080, "host_ip" => ""}], config["port_mappings"]
    assert_equal({"network" => "POD", "pid" => "POD", "ipc" => "POD"}, config.dig("linux", "security_context", "namespace_options"))
    assert_equal({"net.ipv4.ping_group_range" => "0 1"}, config.dig("linux", "sysctls"))
    assert_equal "/rbn/podu1", config.dig("linux", "cgroup_parent"), "the Pod's own cgroup"
    assert_equal({"servers" => ["1.1.1.1"], "searches" => [], "options" => ["ndots:2"]}, config["dns_config"])
  end

  # ResourceConfigForPod: weight from requests, quota and memory only when
  # every container declares the limit; usage read from the Pod's cgroup and
  # its containers'.
  def test_pod_cgroup_limits_and_usage
    guaranteed = pod.merge("spec" => pod["spec"].merge("containers" => [
                                                         {"name" => "main", "image" => "busybox", "resources" => {"requests" => {"cpu" => "500m", "memory" => "64Mi"},
                                                                                                                  "limits" => {
                                                                                                                    "cpu" => "500m", "memory" => "64Mi"
                                                                                                                  }}}
                                                       ]))
    begin
      File.write(File.join(@cgroups, "rbn"), "")
    rescue StandardError
      nil
    end
    FileUtils.rm_f(File.join(@cgroups, "rbn"))
    %w[cpu.weight cpu.max memory.max].each do |file|
      FileUtils.mkdir_p(File.join(@cgroups, "rbn", "podu1"))
      File.write(File.join(@cgroups, "rbn", "podu1", file), "max")
    end
    @backend.run_sandbox(guaranteed)
    read = ->(file) { File.read(File.join(@cgroups, "rbn", "podu1", file)) }

    assert_equal ["20", "50000 100000", (64 * 1024 * 1024).to_s], [read.call("cpu.weight"), read.call("cpu.max"), read.call("memory.max")]

    @backend.create_container("sb1", spec)
    container_dir = File.join(@cgroups, "rbn", "podu1", "c1")
    FileUtils.mkdir_p(container_dir)
    File.write(File.join(container_dir, "cpu.stat"), "usage_usec 1500\nuser_usec 1000\n")
    File.write(File.join(container_dir, "memory.current"), "4096\n")
    File.write(File.join(@cgroups, "rbn", "podu1", "memory.current"), "8192\n")
    usage = @backend.pod_usage("sb1")

    assert_equal 8192, usage.dig("pod", "memory.current")
    assert_equal([["c1", "main", 1500, 4096]],
                 usage["containers"].map do |entry|
                   [entry["id"], entry["name"], entry.dig("usage", "cpu", "usage_usec"), entry.dig("usage", "memory.current")]
                 end)

    %w[cpu.weight cpu.max memory.max memory.current].each { |file| File.delete(File.join(@cgroups, "rbn", "podu1", file)) }
    begin
      Dir.rmdir(container_dir)
    rescue StandardError
      FileUtils.rm_rf(container_dir)
    end
    @backend.remove_sandbox("sb1")

    refute File.directory?(File.join(@cgroups, "rbn", "podu1")), "the Pod's cgroup goes with it"
  end

  def test_container_config_pulls_and_creates
    @backend.run_sandbox(pod)

    assert_equal "c1", @backend.create_container("sb1", spec)
    assert_equal %w[ImageStatus PullImage CreateContainer], @client.calls.drop(1).map(&:first)
    config = @client.calls.last.last["config"]

    assert_equal ["sh", "-c", "echo hi"], config["command"]
    assert_equal [], config["args"]
    assert_equal "/work", config["working_dir"]
    assert_equal [{"key" => "A", "value" => ["1"].pack("m0")}], config["envs"], "KeyValue.value is bytes"
    assert_equal [{"container_path" => "/data", "host_path" => "/host/data", "readonly" => true, "propagation" => "PROPAGATION_PRIVATE",
                   "recursive_read_only" => false}],
                 config["mounts"]
    assert_equal "main/0.log", config["log_path"]
    assert_equal({"cpu_shares" => 256, "cpu_period" => 100_000, "cpu_quota" => 50_000, "memory_limit_in_bytes" => 64 * 1024 * 1024},
                 config.dig("linux", "resources"))
    assert_equal({"run_as_user" => {"value" => 1000}, "no_new_privs" => true, "capabilities" => {"add_capabilities" => [], "drop_capabilities" => ["ALL"]},
                  "supplemental_groups" => [5]}, config.dig("linux", "security_context"))
    FileUtils.mkdir_p(File.join(@dir, "pods", "ns_web_u1", "main"))
    File.write(File.join(@dir, "pods", "ns_web_u1", "main", "0.log"), "")
    @backend.create_container("sb1", spec)

    refute_includes @client.calls.last(2).map(&:first), "PullImage", "a present image is not pulled again"
    restarted = @client.calls.last.last["config"]

    assert_equal [1, "main/1.log"], [restarted.dig("metadata", "attempt"), restarted["log_path"]], "a restart logs to its own file"
  end

  def test_pulls_carry_the_pod_credentials
    @backend.credential_provider = lambda do |pod, image|
      if image.start_with?("registry.example.com")
        {"registry" => "registry.example.com", "username" => "u-#{pod.dig("metadata", "name")}", "password" => "p",
         "identity_token" => nil}
      end
    end
    @backend.run_sandbox(pod)
    @backend.create_container("sb1", spec.merge("image" => "registry.example.com/private:1"))
    pull = @client.calls.find { |method, _| method == "PullImage" }.last

    assert_equal({"username" => "u-web", "password" => "p", "server_address" => "registry.example.com"}, pull["auth"])
    @backend.create_container("sb1", spec.merge("image" => "docker.io/library/public:1"))

    assert_nil @client.calls.reverse.find { |method, _| method == "PullImage" }.last["auth"]
  end

  def test_status_mapping
    status = @backend.container_status("c1")

    assert_equal "terminated", status["state"]
    assert_equal 137, status["exitCode"]
    assert status["oom_killed"]
    assert_equal({"exitCode" => 137, "reason" => "OOMKilled", "startedAt" => "2026-09-21T14:13:20Z", "finishedAt" => "2026-09-21T14:13:21Z",
                  "containerID" => "c1"}, status["terminated"])
  end

  def test_network_context_is_the_pause_process_namespace
    context = @backend.network_sandbox_context("sb1")

    assert_equal "/proc/#{Process.pid}/ns/net", context.dig("netns", "path")
    assert_equal File.stat("/proc/self/ns/net").ino, context.dig("netns", "inode")
  end

  def test_exec_streaming_and_multiplexer_routing
    @backend.run_sandbox(pod)
    @backend.create_container("sb1", spec)
    result = @backend.exec("c1", %w[echo out])
    status = result[:status].pop

    assert_equal [2, "out\n"], [status.exit_status, result[:stdout].read]
    assert_equal "http://127.0.0.1:1/exec/abc", @backend.streaming_url(:exec, "c1", command: ["sh"], tty: true, stdin: true)
    assert_equal({"container_id" => "c1", "cmd" => ["sh"], "tty" => true, "stdin" => true, "stdout" => true, "stderr" => false},
                 @client.calls.last.last)
    assert_equal "http://127.0.0.1:1/portforward/abc", @backend.streaming_url(:port_forward, "c1")
    assert_equal "sb1", @client.calls.last.last["pod_sandbox_id"]

    native = Object.new
    def native.run_sandbox(*, **) = "native-sb"
    multiplexer = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri" => @backend})

    assert_predicate multiplexer, :streaming_backends?
    assert_nil multiplexer.streaming_url(:exec, "unknown-native-container"), "native containers stream through the node"
  end

  def test_probes_run_in_the_sandbox_network_namespace
    skip "setns needs root" unless Process.uid.zero?

    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    acceptor = Thread.new do
      loop do
        client = server.accept
        begin
          client.readpartial(4096)
          client.write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        rescue EOFError
          nil
        ensure
          client.close
        end
      end
    rescue IOError
      nil
    end
    @backend.run_sandbox(pod)
    @backend.create_container("sb1", spec)

    assert_equal true, @backend.tcp_socket("c1", {"port" => port}, timeout: 2)["success"]
    result = @backend.http_get("c1", {"port" => port, "path" => "healthz"}, timeout: 2)

    assert_equal [204, true], result.values_at("status", "success")
  ensure
    server&.close
    acceptor&.kill
  end

  # After an agent restart nothing remembers who owns what: the backend that
  # knows an id claims it, everything else stays the default's.
  def test_ownership_is_rediscovered_after_a_restart
    client = FakeClient.new
    def client.runtime(method, request = {}, **)
      @calls << [method, request]
      case method
      when "ContainerStatus"
        raise Rubernetes::Runtime::CRI::Client::Error.new("not found", code: 5) unless request["container_id"] == "c1"

        {"status" => {"id" => "c1", "state" => "CONTAINER_RUNNING", "log_path" => "/logs/main/0.log",
                      "labels" => {"io.kubernetes.pod.sandbox" => "sb1"}, "metadata" => {"name" => "main"}}}
      when "PodSandboxStatus" then {"status" => {"id" => "sb1", "runtime_handler" => "runc",
                                                 "metadata" => {"name" => "web", "namespace" => "ns", "uid" => "u1"}}}
      when "ListPodSandbox" then {"items" => [{"id" => "sb1", "runtime_handler" => "runc", "metadata" => {"name" => "web"}},
                                              {"id" => "other", "runtime_handler" => "kata"}]}
      when "ListContainers" then {"containers" => [{"id" => "c1", "pod_sandbox_id" => "sb1"}, {"id" => "c9", "pod_sandbox_id" => "other"}]}
      else {}
      end
    end
    backend = CRI::Backend.new(client: client, handler: "runc", log_root: @dir)
    native = Class.new do
      attr_reader :asked

      def initialize = @asked = []
      def container_status(id) = (@asked << id) && {"state" => "running"}
    end.new
    multiplexer = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri" => backend})

    assert_equal "running", multiplexer.container_status("c1")["state"]
    assert_empty native.asked, "the CRI container went to the CRI backend"
    multiplexer.container_status("native-7")
    multiplexer.container_status("native-7")

    assert_equal %w[native-7 native-7], native.asked
    assert_equal 1, client.calls.count { |method, request| method == "ContainerStatus" && request["container_id"] == "native-7" },
                 "the runtime is asked about an id once"

    fresh = CRI::Backend.new(client: client, handler: "runc", log_root: @dir)

    assert_equal({"sandboxes" => 1}, fresh.recover)
    assert fresh.owns_container?("c1")
    refute fresh.owns_container?("c9"), "another handler's container"
  end

  def test_the_noop_cni_plugin_answers_add
    conf, plugin = CRI::Backend.install_cni(conf_dir: File.join(@dir, "conf"), bin_dir: File.join(@dir, "bin"))

    assert_equal "rubernetes-noop", JSON.parse(File.read(File.join(conf, "10-rubernetes.conflist"))).dig("plugins", 0, "type")
    output = IO.popen({"CNI_COMMAND" => "ADD", "CNI_NETNS" => "/var/run/netns/x"}, [plugin], "r+") do |io|
      io.close_write
      io.read
    end

    assert_equal({"cniVersion" => "1.0.0", "interfaces" => [{"name" => "eth0", "sandbox" => "/var/run/netns/x"}],
                  "ips" => [{"address" => "127.0.0.1/8", "interface" => 0}], "dns" => {}}, JSON.parse(output))
  end
end
