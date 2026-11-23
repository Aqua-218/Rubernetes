# frozen_string_literal: true

require "socket"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/node"
require "rubernetes/runtime/cri"
require "rubernetes/runtime/cri/generated/cri_runtime_v1_pb"
require "rubernetes/runtime/multiplexer"

# The CRI backend's translation (kuberuntime generatePodSandboxConfig /
# generateContainerConfig, status and streaming) against a recording client.
class CRIBackendTest < Minitest::Test
  CRI = Rubernetes::Runtime::CRI

  class FakeClient
    attr_reader :calls
    attr_writer :sandbox_network, :sandbox_state, :containers, :container_mounts

    def initialize(pid: Process.pid, runtime_features: {}, runtime_handlers: [])
      @calls = []
      @pid = pid
      @images = {}
      @runtime_status = {"features" => runtime_features, "runtime_handlers" => runtime_handlers}
    end

    def runtime(method, request = {}, **)
      @calls << [method, request]
      case method
      when "Status" then @runtime_status
      when "Version" then {"runtime_name" => "containerd"}
      when "RunPodSandbox"
        @sandbox = request.fetch("config").slice("metadata", "labels", "annotations")
        @sandbox["id"] = "sb1"
        @sandbox["runtime_handler"] = request.fetch("runtime_handler")
        @sandbox_namespaces = request.dig("config", "linux", "security_context", "namespace_options")
        {"pod_sandbox_id" => "sb1"}
      when "PodSandboxStatus"
        linux = {"namespaces" => {"options" => @sandbox_namespaces}}
        status = @sandbox&.merge("network" => @sandbox_network, "state" => @sandbox_state, "linux" => linux)
        {"status" => status, "info" => {"info" => JSON.generate("pid" => @pid)}}
      when "ListPodSandbox" then {"items" => [@sandbox].compact}
      when "ListContainers" then {"containers" => @containers || []}
      when "RemovePodSandbox"
        @sandbox = nil
        {}
      when "CreateContainer" then {"container_id" => "c1"}
      when "ContainerStatus"
        {"status" => {"id" => "c1", "state" => "CONTAINER_EXITED", "exit_code" => 137, "reason" => "OOMKilled",
                      "started_at" => "1790000000000000000", "finished_at" => "1790000001500000000", "image" => {"image" => "busybox"},
                      "mounts" => @container_mounts}}
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

  def test_cancelling_a_probe_reaps_its_network_namespace_helper
    runtime = CRI::Backend.allocate
    reader, writer = IO.pipe
    cancellation = Class.new(StandardError)
    runtime.stub(:sandbox_of, "sandbox") do
      runtime.stub(:network_sandbox_context, {"netns" => {"path" => "/proc/self/ns/net"}}) do
        namespace = Object.new
        namespace.define_singleton_method(:setns) { |**| nil }
        Rubernetes::Platform::Linux::Setns.stub(:new, namespace) do
          probe = Thread.new do
            runtime.send(:within_netns, "container", 30) do
              writer.puts(Process.pid)
              sleep 30
            end
          rescue cancellation
            :cancelled
          end
          child = Integer(Timeout.timeout(5) { reader.gets })
          probe.raise(cancellation)

          assert_equal :cancelled, Timeout.timeout(5) { probe.value }
          assert_raises(Errno::ECHILD) { Process.waitpid(child, Process::WNOHANG) }
        end
      end
    end
  ensure
    reader&.close
    writer&.close
  end

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

  def test_kubelet_uses_one_dns_config_for_sandbox_rpc_and_mounted_resolver
    resolver = File.join(@dir, "resolv.conf")
    File.write(resolver, "nameserver 192.0.2.53\nsearch host.test.\noptions rotate\n")
    writer = Rubernetes::Node::PodFiles.new(cluster_dns: ["10.96.0.10"], resolv_conf: resolver)
    root = File.join(@dir, "node-pods")
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: @backend, pod_root: root, pod_files: writer)
    object = pod
    object["spec"].delete("securityContext")
    lifecycle.start(object)

    _, request = @client.calls.find { |method, _| method == "RunPodSandbox" }
    expected = {"servers" => %w[10.96.0.10 1.1.1.1], "searches" => %w[ns.svc.cluster.local svc.cluster.local cluster.local host.test], "options" => ["ndots:2"]}

    assert_equal expected, request.fetch("config").fetch("dns_config")
    assert_equal "nameserver 10.96.0.10\nnameserver 1.1.1.1\nsearch ns.svc.cluster.local svc.cluster.local cluster.local host.test\noptions ndots:2\n",
                 File.read(File.join(root, "u1", "etc", "resolv.conf"))
  end

  def test_sandbox_network_ips_use_the_owning_runtime_and_preserve_cri_order
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => Object.new, "cri" => @backend})
    sandbox = mux.run_sandbox(pod, runtime_class: "cri")
    @client.sandbox_network = {"ip" => "10.1.0.8", "additional_ips" => [{"ip" => "fd00::2"}]}

    assert_equal %w[10.1.0.8 fd00::2], mux.sandbox_network_ips(sandbox)
    assert_equal ["PodSandboxStatus", {"pod_sandbox_id" => sandbox}], @client.calls.last

    @client.sandbox_network = {"ip" => "10.1.0.8", "additional_ips" => [{"ip" => "fd00::2/64"}]}

    assert_nil mux.sandbox_network_ips(sandbox)

    @client.sandbox_network = nil

    assert_empty mux.sandbox_network_ips(sandbox)
  end

  def test_pod_status_qualifies_cri_container_ids_without_changing_runtime_ids
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => Object.new, "cri" => @backend})
    sandbox = mux.run_sandbox(pod, runtime_class: "cri")
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: mux)
    status = {"terminated" => {"containerID" => "c1"}, "lastState" => {"terminated" => {"containerID" => "previous"}}}
    entry = {id: "c1", status: status}

    observation = lifecycle.send(:container_observation, entry, {sandbox_id: sandbox, state: "Running"})
    again = lifecycle.send(:container_observation, entry, {sandbox_id: sandbox, state: "Running"})

    assert_equal "containerd://c1", observation["containerID"]
    assert_equal "containerd://c1", observation.dig("terminated", "containerID")
    assert_equal "containerd://previous", observation.dig("lastState", "terminated", "containerID")
    assert_equal observation, again
    assert_equal "c1", entry.dig(:status, "terminated", "containerID")
    assert_equal "previous", entry.dig(:status, "lastState", "terminated", "containerID")
    version_calls = @client.calls.select { |method, _| method == "Version" }

    assert_equal [["Version", {"version" => "v1"}]], version_calls
  end

  def test_sandbox_container_ids_only_contain_ids_from_the_requested_sandbox
    @client.containers = [{"id" => "c1", "pod_sandbox_id" => "sb1"}, {"id" => "other", "pod_sandbox_id" => "sb2"}]

    assert_equal ["c1"], @backend.sandbox_container_ids("sb1")
    assert_equal ["ListContainers", {"filter" => {"pod_sandbox_id" => "sb1"}}], @client.calls.last
  end

  def test_pod_args_override_keeps_cri_image_entrypoint
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"cri" => @backend}, default: "cri")
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, container_spec: Rubernetes::Node::ContainerSpec.new)
    object = pod
    object.fetch("spec").delete("securityContext")
    main = object.dig("spec", "containers", 0)
    main["args"] = ["fake-registry-server", "$(MODE)"]
    main["env"] = [{"name" => "MODE", "value" => "--private"}]
    lifecycle.start(object)
    config = @client.calls.find { |method, _| method == "CreateContainer" }.last.fetch("config")

    assert_empty config.fetch("command")
    assert_equal ["fake-registry-server", "--private"], config.fetch("args")
    assert_equal ["fake-registry-server", "$(MODE)"], main.fetch("args")
  end

  def test_cri_sandbox_readiness_is_an_observation_from_its_owner
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => Object.new, "cri" => @backend})
    sandbox = mux.run_sandbox(pod, runtime_class: "cri")
    @client.sandbox_state = "SANDBOX_READY"

    assert_equal :ready, mux.sandbox_state(sandbox)

    @client.sandbox_state = "SANDBOX_NOTREADY"

    assert_equal :stopped, mux.sandbox_state(sandbox)
    assert_nil @backend.sandbox_state("not-the-returned-id")
  end

  def test_private_and_shared_pid_namespaces_are_sent_for_new_and_recovered_containers
    workload = pod
    workload.fetch("spec").delete("shareProcessNamespace")
    [{"pid" => "CONTAINER"}, {"pid" => "POD", "shared" => true}].each do |mode|
      workload.fetch("spec")["shareProcessNamespace"] = mode.fetch("shared", false)
      sandbox = @backend.run_sandbox(workload)
      @backend.create_container(sandbox, spec)
      configured = @client.calls.reverse.find { |method, _| method == "CreateContainer" }.last
      options = {"network" => "POD", "ipc" => "POD", "pid" => mode.fetch("pid")}

      assert_equal options, configured.dig("config", "linux", "security_context", "namespace_options")

      restored = CRI::Backend.new(client: @client, handler: "runc", log_root: File.join(@dir, "pods"), cgroup_root: @cgroups)
      restored.recover
      restored.create_container(sandbox, spec)
      configured = @client.calls.reverse.find { |method, _| method == "CreateContainer" }.last

      assert_equal options, configured.dig("config", "linux", "security_context", "namespace_options")
    end
  end

  def test_user_namespace_allocator_handles_multiple_instances_of_one_node_registry
    allocator = Rubernetes::Platform::Linux::UserNamespace::Allocator
    registry = File.join(@dir, "userns.json")
    first = allocator.new(path: registry)
    second = allocator.new(path: registry)
    allocations = [first, second].each_with_index.map do |instance, index|
      Thread.new { instance.allocate("pod-#{index}") }
    end.map(&:value)

    assert_equal 2, allocations.map(&:uid_base).uniq.length
    assert_equal allocations.last, first.lookup("pod-1")
    assert second.release("pod-0")
    assert_nil first.lookup("pod-0")
    assert_equal allocations.last, first.lookup("pod-1")
  end

  def test_host_network_user_namespace_requires_an_advertised_handler_and_mapped_cri_configuration
    advertised = {"user_namespaces_host_network" => true}
    handlers = [{"name" => "runc", "features" => {"user_namespaces" => true}}]
    client = FakeClient.new(pid: 0, runtime_features: advertised, runtime_handlers: handlers)
    allocator = Rubernetes::Platform::Linux::UserNamespace::Allocator.new(path: File.join(@dir, "userns.json"))
    allocations = CRI::UserNamespaces::Allocations.new(-> { allocator })
    backend = CRI::Backend.new(client: client, handler: "runc", log_root: File.join(@dir, "pods"), user_namespace_allocations: allocations,
                               user_namespaces_host_network: true)
    native = Object.new
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri" => backend})
    workload = pod
    workload["spec"].merge!("hostNetwork" => true, "hostUsers" => false)

    assert_equal({"userNamespacesHostNetwork" => true}, mux.runtime_features)
    assert_raises(ArgumentError) { mux.run_sandbox(workload, runtime_class: "rubernetes-native") }
    assert_equal "sb1", mux.run_sandbox(workload)
    assert_equal File.stat("/proc/self/ns/net").ino, backend.network_sandbox_context("sb1").dig("netns", "inode")
    mux.create_container("sb1", spec)

    _, request = client.calls.find { |method, _| method == "RunPodSandbox" }
    options = request.dig("config", "linux", "security_context", "namespace_options")
    mapping = {"host_id" => allocator.lookup("cri-pod-u1").uid_base, "container_id" => 0, "length" => 65_536}

    assert_equal "NODE", options.fetch("network")
    assert_equal({"mode" => "POD", "uids" => [mapping], "gids" => [mapping]}, options.fetch("userns_options"))
    _, request = client.calls.find { |method, _| method == "CreateContainer" }

    assert_equal options, request.dig("config", "linux", "security_context", "namespace_options")
    proto = CRI::Generated::RuntimeV1::CreateContainerRequest.decode_json(JSON.generate(request), ignore_unknown_fields: true)
    mount = proto.config.mounts.first
    [mount.uidMappings, mount.gidMappings].each do |mappings|
      ids = mappings.map { |entry| [entry.host_id, entry.container_id, entry.length] }

      assert_equal [mapping.values], ids
    end

    resumed = CRI::Backend.new(client: client, handler: "runc", log_root: File.join(@dir, "pods"), user_namespace_allocations: allocations,
                               user_namespaces_host_network: true)

    assert_equal({"sandboxes" => 1}, resumed.recover)
    resumed.create_container("sb1", spec)
    _, restarted_request = client.calls.reverse.find { |method, _| method == "CreateContainer" }

    assert_equal options, restarted_request.dig("config", "linux", "security_context", "namespace_options")
    resumed.remove_sandbox("sb1")

    assert_nil allocator.lookup("cri-pod-u1")

    unavailable = CRI::Backend.new(client: client, handler: "missing", log_root: @dir, user_namespace_allocations: allocations,
                                   user_namespaces_host_network: true)

    assert_equal({"userNamespacesHostNetwork" => false}, unavailable.runtime_features)
    assert_raises(CRI::Backend::Error) { unavailable.run_sandbox(workload) }

    disabled = CRI::Backend.new(client: client, handler: "runc", log_root: @dir, user_namespace_allocations: allocations)

    assert_empty disabled.runtime_features
    assert_raises(CRI::Backend::Error) { disabled.run_sandbox(workload) }
  end

  def test_default_runtime_is_preserved_for_separately_requested_user_or_host_network_namespaces
    observed = []
    native = Object.new
    native.define_singleton_method(:run_sandbox) do |config, **|
      observed << config.fetch("spec")
      "native-#{observed.length}"
    end
    mux = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => native, "cri" => @backend})
    workload = pod
    workload["spec"]["hostUsers"] = false

    assert_equal "native-1", mux.run_sandbox(workload)
    workload["spec"] = workload.fetch("spec").merge("hostUsers" => true, "hostNetwork" => true)

    assert_equal "native-2", mux.run_sandbox(workload)

    host_users = observed.map { |specification| specification.fetch("hostUsers") }

    assert_equal [false, true], host_users
    assert_empty @client.calls
  end

  def test_runtime_class_handler_is_passed_to_image_status_and_pull_when_enabled
    backend = CRI::Backend.new(client: @client, handler: "isolated", log_root: File.join(@dir, "pods"), runtime_class_in_image_api: true)
    workload = pod
    workload["spec"]["runtimeClassName"] = "isolation-class"
    sandbox = backend.run_sandbox(workload)
    backend.create_container(sandbox, spec)

    %w[ImageStatus PullImage].each do |rpc|
      _, request = @client.calls.find { |method, _| method == rpc }

      assert_equal "isolated", request.dig("image", "runtime_handler"), rpc
    end
    _, pull = @client.calls.find { |method, _| method == "PullImage" }

    assert_equal "u1", pull.dig("sandbox_config", "metadata", "uid")
    _, create = @client.calls.find { |method, _| method == "CreateContainer" }

    assert_equal({"image" => "sha256:x", "user_specified_image" => "busybox"}, create.dig("config", "image"))

    assert_raises(CRI::Backend::Error) { backend.ensure_image("missing", {"imagePullPolicy" => "Never"}, pod: workload) }
    assert_equal(1, @client.calls.count { |method, _| method == "PullImage" })
  end

  def test_image_handler_on_recovered_sandbox_uses_the_pods_runtime_class
    {nil => nil, "explicit-class" => "isolated"}.each do |class_name, expected_handler|
      client = FakeClient.new
      options = {client: client, handler: "isolated", log_root: File.join(@dir, "pods"), runtime_class_in_image_api: true}
      workload = pod
      workload["spec"]["runtimeClassName"] = class_name if class_name
      sandbox = CRI::Backend.new(**options).run_sandbox(workload)
      recovered = CRI::Backend.new(**options)
      recovered.recover
      runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"default" => recovered}, default: "default")
      lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
      record = {sandbox_id: sandbox, pod: workload}
      lifecycle.send(:create_in_live_sandbox, record, {spec: spec, category: "app"})

      handlers = client.calls.filter_map do |method, request|
        [method, request.dig("image", "runtime_handler")] if %w[ImageStatus PullImage].include?(method)
      end

      assert_equal [["ImageStatus", expected_handler], ["PullImage", expected_handler]], handlers
    end
  end

  def test_memory_qos_passes_unified_limits_on_create_and_update
    File.write(File.join(@dir, "cgroup.controllers"), "memory cpu")
    backend = CRI::Backend.new(client: @client, log_root: File.join(@dir, "pods"), memory_qos: true,
                               memory_throttling_factor: 0.5, memory_reservation_policy: "TieredReservation",
                               swap_controller: true, cgroup_root: @dir)
    sandbox = backend.run_sandbox(pod)
    resources = {"requests" => {"memory" => "32Mi"}, "limits" => {"memory" => "64Mi"}}
    container = backend.create_container(sandbox, spec.merge("resources" => resources))
    _, create = @client.calls.find { |method, _| method == "CreateContainer" }
    unified = create.dig("config", "linux", "resources", "unified")

    assert_equal({"memory.low" => (32 * (1024**2)).to_s, "memory.high" => (48 * (1024**2)).to_s, "memory.swap.max" => "0",
                  "memory.oom.group" => "1"}, unified)

    backend.update_container_resources(container, resources: resources, pod_spec: pod.fetch("spec"))
    _, update = @client.calls.last

    assert_equal unified, update.dig("linux", "unified")
  end

  def test_cri_oom_kill_follows_config_on_unified_cgroups_only
    controller_file = File.join(@dir, "cgroup.controllers")
    File.write(controller_file, "memory cpu")

    [[nil, "1"], [false, "1"], [true, nil]].each do |configured, expected|
      client = FakeClient.new
      backend = CRI::Backend.new(client: client, log_root: File.join(@dir, "pods"), cgroup_root: @dir, single_process_oom_kill: configured)
      sandbox = backend.run_sandbox(pod)
      backend.create_container(sandbox, spec)
      _, request = client.calls.find { |method, _| method == "CreateContainer" }
      unified = request.fetch("config").fetch("linux").fetch("resources").fetch("unified", {})

      expected ? assert_equal(expected, unified["memory.oom.group"]) : refute(unified.key?("memory.oom.group"))
    end

    File.unlink(controller_file)
    on_v1 = CRI::Backend.new(client: @client, log_root: File.join(@dir, "pods"), cgroup_root: @dir)

    refute on_v1.send(:linux_resources, {}).fetch("unified", {}).key?("memory.oom.group")
  end

  def test_stop_signal_translates_between_the_pod_and_cri_enum_names
    @backend.run_sandbox(pod)
    @backend.create_container("sb1", spec.merge("stop_signal" => "SIGRTMAX-3"))
    _, request = @client.calls.find { |method, _| method == "CreateContainer" }
    message = CRI::Generated::RuntimeV1::CreateContainerRequest.decode_json(JSON.generate(request))

    assert_equal :SIGRTMAXMINUS3, message.config.stop_signal
    @client.stub(:runtime, {"status" => {"id" => "c1", "state" => "CONTAINER_RUNNING", "stop_signal" => "SIGRTMAXMINUS3"}}) do
      assert_equal "SIGRTMAX-3", @backend.container_stop_signal("c1")
    end
    @client.stub(:runtime, {"status" => {"id" => "c1", "state" => "CONTAINER_RUNNING", "stop_signal" => "RUNTIME_DEFAULT"}}) do
      assert_nil @backend.container_stop_signal("c1")
    end
  end

  def test_device_mounts_are_passed_as_cri_devices
    @backend.run_sandbox(pod)
    device = {"source" => "/host/block", "destination" => "/dev/block-data", "device" => true, "permissions" => "r"}
    @backend.create_container("sb1", spec.merge("mounts" => spec["mounts"] + [device]))
    _, request = @client.calls.find { |method, _| method == "CreateContainer" }
    config = CRI::Generated::RuntimeV1::CreateContainerRequest.decode_json(JSON.generate(request)).config

    assert_equal ["/data"], config.mounts.map(&:container_path)
    assert_equal([["/host/block", "/dev/block-data", "r"]], config.devices.map { |item| [item.host_path, item.container_path, item.permissions] })
  end

  # ResourceConfigForPod: weight from requests, quota and memory only when
  # every container declares the limit; usage read from the Pod's cgroup and
  # its containers'.
  def test_pod_cgroup_limits_and_usage
    guaranteed = pod.merge("spec" => pod["spec"].merge("containers" => [
                                                         {"name" => "main", "image" => "busybox",
                                                          "resources" => {"requests" => {"cpu" => "500m", "memory" => "64Mi"},
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
    assert_equal ["/rbn/podu1", @cgroups], usage.fetch("pod").values_at("path", "cgroup_root")
    assert_equal ["/rbn/podu1/c1", @cgroups], usage.dig("containers", 0, "usage").values_at("path", "cgroup_root")
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

  def test_cpu_quota_and_period_apply_to_create_resize_and_recovered_pod_cgroup
    [true, false].each do |enabled|
      metadata = {"name" => "quota", "namespace" => "ns", "uid" => "quota-#{enabled}"}
      sandbox_dir = File.join(@cgroups, "rbn", "pod#{metadata.fetch("uid")}")
      FileUtils.mkdir_p(sandbox_dir)
      %w[cpu.weight cpu.max].each { |file| File.write(File.join(sandbox_dir, file), "max") }
      backend_config = {client: @client, handler: "runc", log_root: File.join(@dir, "pods"), cgroup_parent: "/rbn",
                        cgroup_root: @cgroups, cpu_cfs_quota: enabled, cpu_period: 12_345}
      backend = CRI::Backend.new(**backend_config)
      initial = {"requests" => {"cpu" => "20m"}, "limits" => {"cpu" => "25m"}}
      definition = {"name" => "main", "image" => "busybox", "resources" => initial}
      sandbox = backend.run_sandbox({"metadata" => metadata, "spec" => {"containers" => [definition]}})
      container = backend.create_container(sandbox, definition)
      created = @client.calls.last.last.dig("config", "linux", "resources")

      assert_equal [20, (12_345 if enabled), (1000 if enabled)], created.values_at("cpu_shares", "cpu_period", "cpu_quota")
      assert_equal ["1", "#{enabled ? 1000 : "max"} 12345"], backend.pod_cgroup_readback(sandbox).values_at("cpu.weight", "cpu.max")

      backend = CRI::Backend.new(**backend_config)
      @client.containers = [{"id" => container, "pod_sandbox_id" => sandbox, "metadata" => {"name" => "main"}}]

      assert_equal({"sandboxes" => 1}, backend.recover)

      resized = {"requests" => {"cpu" => "250m"}, "limits" => {"cpu" => "350m"}}
      backend.update_container_resources(container, resources: resized, pod_spec: {"containers" => [definition.merge("resources" => resized)]})
      method, request = @client.calls.last

      assert_equal "UpdateContainerResources", method
      assert_equal [256, (12_345 if enabled), (4320 if enabled)], request.fetch("linux").values_at("cpu_shares", "cpu_period", "cpu_quota")
      assert_equal ["10", "#{enabled ? 4320 : "max"} 12345"], backend.pod_cgroup_readback(sandbox).values_at("cpu.weight", "cpu.max")
    end
  end

  def test_pod_level_cpu_resize_updates_running_cri_containers_inheriting_the_limit
    @client.define_singleton_method(:runtime) do |method, request = {}, **options|
      return {"status" => {"state" => "CONTAINER_RUNNING"}} if method == "ContainerStatus"

      super(method, request, **options)
    end
    pod_spec = {"resources" => {"requests" => {"cpu" => "100m"}, "limits" => {"cpu" => "175m"}},
                "containers" => [{"name" => "main", "image" => "busybox", "resources" => {"requests" => {"cpu" => "50m"}}}]}
    sandbox = @backend.run_sandbox({"metadata" => {"uid" => "inherits", "name" => "inherits", "namespace" => "ns"}, "spec" => pod_spec})
    @backend.create_container(sandbox, pod_spec.fetch("containers").first)
    created = @client.calls.last.last.dig("config", "linux", "resources")

    assert_equal [51, 17_500], created.values_at("cpu_shares", "cpu_quota")

    pod_spec["resources"]["limits"]["cpu"] = "225m"
    @backend.update_pod_resources(sandbox, pod_spec: pod_spec)
    method, request = @client.calls.last

    assert_equal "UpdateContainerResources", method
    assert_equal [51, 22_500], request.fetch("linux").values_at("cpu_shares", "cpu_quota")
  end

  def test_exclusive_cpu_quota_uses_the_cri_affinity_at_creation_and_reconcile
    policy = Object.new
    policy.define_singleton_method(:pod_cpu_quota_exempt?) { |_pod| true }
    policy.define_singleton_method(:container_cpu_quota_exempt?) { |_pod, spec| spec["name"] == "main" }
    @backend.cpu_quota_exemptions = policy
    sandbox = @backend.run_sandbox(pod)
    pinned = spec.merge("limits" => {"cpuset.cpus" => "2-3", "cpuset.mems" => "0"})
    container = @backend.create_container(sandbox, pinned)
    created = @client.calls.last.last.dig("config", "linux", "resources")

    assert_equal [-1, 100_000, "2-3", "0"], created.values_at("cpu_quota", "cpu_period", "cpuset_cpus", "cpuset_mems")

    @backend.update_container_resources(container, resources: pinned.fetch("resources"), pod_spec: pod.fetch("spec"))

    assert_equal(-1, @client.calls.last.last.dig("linux", "cpu_quota"))

    @backend.update_container_cpuset(container, "2")

    assert_equal ["UpdateContainerResources", {"container_id" => container, "linux" => {"cpuset_cpus" => "2"}}], @client.calls.last
  end

  def test_container_config_pulls_and_creates
    @backend.run_sandbox(pod)

    assert_equal "c1", @backend.create_container("sb1", spec)
    assert_equal %w[ImageStatus PullImage CreateContainer], @client.calls.drop(1).map(&:first)
    config = @client.calls.last.last["config"]

    assert_equal ["sh", "-c"], config["command"]
    assert_equal ["echo hi"], config["args"]
    assert_equal "/work", config["working_dir"]
    assert_equal [{"key" => "A", "value" => ["1"].pack("m0")}], config["envs"], "KeyValue.value is bytes"
    assert_equal [{"container_path" => "/data", "host_path" => "/host/data", "readonly" => true, "propagation" => "PROPAGATION_PRIVATE",
                   "recursive_read_only" => false}],
                 config["mounts"]
    assert_equal "main/0.log", config["log_path"]
    assert_equal({"cpu_shares" => 256, "cpu_period" => 100_000, "cpu_quota" => 50_000, "memory_limit_in_bytes" => 64 * 1024 * 1024},
                 config.dig("linux", "resources"))
    assert_equal({"run_as_user" => {"value" => 1000}, "no_new_privs" => true, "capabilities" => {"add_capabilities" => [], "drop_capabilities" => ["ALL"]},
                  "supplemental_groups" => [5], "namespace_options" => {"network" => "POD", "ipc" => "POD", "pid" => "POD"}},
                 config.dig("linux", "security_context"))
    FileUtils.mkdir_p(File.join(@dir, "pods", "ns_web_u1", "main"))
    File.write(File.join(@dir, "pods", "ns_web_u1", "main", "0.log"), "")
    @backend.create_container("sb1", spec)

    refute_includes @client.calls.last(2).map(&:first), "PullImage", "a present image is not pulled again"
    restarted = @client.calls.last.last["config"]

    assert_equal [1, "main/1.log"], [restarted.dig("metadata", "attempt"), restarted["log_path"]], "a restart logs to its own file"
  end

  def test_recursive_mounts_use_only_the_selected_runtime_handler
    handlers = [{"name" => "", "features" => {"recursive_read_only_mounts" => true}},
                {"name" => "limited", "features" => {"recursive_read_only_mounts" => false}}]
    client = FakeClient.new(runtime_handlers: handlers)
    backend = CRI::Backend.new(client: client, handler: "limited", log_root: File.join(@dir, "pods"))
    sandbox = backend.run_sandbox(pod)
    ordinary = spec.fetch("mounts").first
    optional = ordinary.merge("name" => "data", "destination" => "/optional", "recursive_readonly" => "IfPossible")

    backend.create_container(sandbox, spec.merge("mounts" => [ordinary, optional]))
    request = client.calls.last.last.fetch("config")
    mounts = request.fetch("mounts")
    status_calls = client.calls.count { |method,| method == "Status" }
    modes = mounts.map { |mount| mount.values_at("readonly", "recursive_read_only") }

    assert_equal [[true, false], [true, false]], modes
    assert_equal 1, status_calls
    client.container_mounts = mounts

    assert_equal({"/data" => false, "/optional" => false}, backend.container_status("c1").fetch("recursiveReadOnlyMounts"))
  end

  def test_recursive_mounts_accept_support_and_reject_required_modes_without_support
    ordinary = spec.fetch("mounts").first
    required = ordinary.merge("name" => "data", "destination" => "/required", "recursive_readonly" => "Enabled")
    optional = ordinary.merge("name" => "data", "destination" => "/optional", "recursive_readonly" => "IfPossible")
    handlers = [{"name" => "supported", "features" => {"recursive_read_only_mounts" => true}}]
    client = FakeClient.new(runtime_handlers: handlers)
    backend = CRI::Backend.new(client: client, handler: "supported", log_root: File.join(@dir, "pods"))
    sandbox = backend.run_sandbox(pod)
    backend.create_container(sandbox, spec.merge("mounts" => [required, optional]))
    mounts = client.calls.last.last.dig("config", "mounts")
    modes = mounts.map { |mount| mount.values_at("readonly", "recursive_read_only") }

    assert_equal [[true, true], [true, true]], modes
    client.container_mounts = mounts

    assert_equal({"/required" => true, "/optional" => true}, backend.container_status("c1").fetch("recursiveReadOnlyMounts"))

    sandbox = @backend.run_sandbox(pod)
    error = assert_raises(Rubernetes::Runtime::ContainerConfigError) do
      @backend.create_container(sandbox, spec.merge("mounts" => [required]))
    end
    assert_includes error.message, 'volume "data" requested recursive read-only mode, but it is not supported by the runtime'
    refute_includes @client.calls.map(&:first), "CreateContainer"
  end

  def test_cri_required_mount_reports_a_configuration_error_on_the_pod
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"cri" => @backend}, default: "cri")
    volume = Object.new
    volume.define_singleton_method(:prepare) { |_| {"mounts" => {"data" => {"path" => "/host/data"}}} }
    volume.define_singleton_method(:release) { |_| true }
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime, volume: volume, container_spec: Rubernetes::Node::ContainerSpec.new)
    object = pod
    object.fetch("spec").delete("securityContext")
    object.dig("spec", "containers", 0)["volumeMounts"] =
      [{"name" => "data", "mountPath" => "/data", "readOnly" => true, "recursiveReadOnly" => "Enabled"}]
    result = lifecycle.start(object)
    waiting = result.status.dig("containerStatuses", 0, "state", "waiting")

    assert_equal "Pending", result.status["phase"]
    assert_equal "CreateContainerConfigError", waiting.fetch("reason")
    assert_includes waiting.fetch("message"), 'volume "data" requested recursive read-only mode, but it is not supported by the runtime'
    refute_includes @client.calls.map(&:first), "CreateContainer"
  end

  def test_cri_mount_readback_reaches_the_node
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"cri" => @backend}, default: "cri")
    lifecycle = Rubernetes::Node::Lifecycle.new(runtime: runtime)
    sandbox = runtime.run_sandbox(pod)
    optional = spec.fetch("mounts").first.merge("name" => "data", "recursive_readonly" => "IfPossible")
    container_spec = spec.merge("mounts" => [optional])
    container = runtime.create_container(sandbox, container_spec)
    @client.container_mounts = [{"container_path" => "/data", "readonly" => true, "recursive_read_only" => false}]
    entry = {id: container, status: {"state" => "running"}, spec: container_spec}
    record = {sandbox_id: sandbox, pod: pod, state: "Running"}
    observation = lifecycle.send(:container_observation, entry, record)
    definition = {"name" => "main", "image" => "busybox", "volumeMounts" =>
      [{"name" => "data", "mountPath" => "/data", "readOnly" => true, "recursiveReadOnly" => "IfPossible"}]}
    status = Rubernetes::Node::Status.allocate.send(:normalize_container_status, definition, observation)

    assert_equal [{"name" => "data", "mountPath" => "/data", "readOnly" => true, "recursiveReadOnly" => "Disabled"}], status["volumeMounts"]
  end

  def test_retired_cri_log_remains_readable_after_removing_the_container
    runtime = Rubernetes::Runtime::Multiplexer.new(backends: {"rubernetes-native" => Object.new, "runc" => @backend})
    sandbox = runtime.run_sandbox(pod, runtime_class: "runc")
    directory = File.join(@dir, "pods", "ns_web_u1", "main")
    FileUtils.mkdir_p(directory)
    first = runtime.create_container(sandbox, spec.merge("restart_count" => 0))
    first_log = File.join(directory, "0.log")
    File.write(first_log, "2026-01-01T00:00:00Z stdout F first\n")
    File.write(first_log + ".20260101-000000.gz", "rotation")
    receipt = runtime.retire_container(first)

    assert_equal first_log, receipt.fetch("log_path")
    assert_equal ["RemoveContainer", {"container_id" => first}], @client.calls.last
    logs = runtime.logs(first, sandbox_id: sandbox, archived_log_path: receipt.fetch("log_path"),
                               request_id: "logs-request", identity: "node-streaming")

    assert_equal "first\n", logs

    second = runtime.create_container(sandbox, spec.merge("restart_count" => 1))
    second_log = File.join(directory, "1.log")
    File.write(second_log, "2026-01-01T00:00:01Z stderr F second\n")
    extra = File.join(directory, "10.log")
    File.write(extra, "another attempt")
    receipt = runtime.retire_container(second, previous_log_path: first_log)

    assert_equal second_log, receipt.fetch("log_path")
    assert_equal "second\n", runtime.logs(second, sandbox_id: sandbox, archived_log_path: second_log)
    assert_equal %w[1.log 10.log], Dir.children(directory).sort
  end

  def test_apparmor_profile_is_passed_to_cri_with_its_local_name
    object = pod
    object["metadata"]["annotations"] = {"container.apparmor.security.beta.kubernetes.io/main" => "localhost/rbn-profile"}
    object.dig("spec", "securityContext")["appArmorProfile"] = {"type" => "RuntimeDefault"}
    @backend.run_sandbox(object)
    @backend.create_container("sb1", spec)

    assert_equal({"profile_type" => "Localhost", "localhost_ref" => "rbn-profile"},
                 @client.calls.last.last.dig("config", "linux", "security_context", "apparmor"))

    explicit = spec
    explicit["security_context"]["appArmorProfile"] = {"type" => "Unconfined"}
    @backend.create_container("sb1", explicit)

    assert_equal({"profile_type" => "Unconfined"}, @client.calls.last.last.dig("config", "linux", "security_context", "apparmor"))
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
    @backend.run_sandbox(pod)
    context = @backend.network_sandbox_context("sb1")
    pidfd = context.dig("netns", "pidfd")

    assert_equal "/proc/#{Process.pid}/ns/net", context.dig("netns", "path")
    assert_equal File.stat("/proc/self/ns/net").ino, context.dig("netns", "inode")
    assert_operator context.dig("netns", "start_time"), :>, 0
    assert_equal "anon_inode:[pidfd]", File.readlink("/proc/self/fd/#{pidfd}")
    assert_equal pidfd, @backend.network_sandbox_context("sb1").dig("netns", "pidfd")

    @backend.remove_sandbox("sb1")

    assert_raises(Errno::ENOENT) { File.readlink("/proc/self/fd/#{pidfd}") }
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

    begin
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
