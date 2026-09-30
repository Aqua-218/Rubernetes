# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/observability/metrics"
require "rubernetes/node/plugins/manager"
require "rubernetes/node/dra_manager"
require "tmpdir"
require_relative "../support/grpc_fake_server"

# The kubelet side of DRA: a driver registers through the plugin registry
# socket (pluginmanager), and the DRA manager prepares a Pod's claims with
# NodePrepareResources, hands out the CDI device IDs per container request,
# checkpoints what it prepared and unprepares when the Pod is gone.  The
# driver is a real gRPC server in its own process -- a spawned interpreter,
# never a fork, so an earlier in-process grpc test cannot poison it.
class NodeDRAManagerTest < Minitest::Test
  RPC = Rubernetes::Node::Plugins::RPC
  DRIVER = "gpu.example.com"

  def serve(socket, log, versions: ["v1.DRAPlugin"])
    requires = [File.join(RPC::GENERATED, "pluginregistration_v1_services_pb"), File.join(RPC::GENERATED, "dra_v1_services_pb")]
    GRPCFakeServer.spawn(socket, <<~RUBY, params: {"log" => log, "versions" => versions, "driver" => DRIVER}, requires: requires)
      generated = Rubernetes::Node::Plugins::Generated
      log = PARAMS.fetch("log")
      versions = PARAMS.fetch("versions")
      driver = PARAMS.fetch("driver")
      record = ->(entry) { File.open(log, "a") { |file| file.puts(JSON.generate(entry)) } }
      registration = Class.new(generated::PluginRegistrationV1::Registration::Service) do
        define_method(:get_info) do |_request, _call|
          generated::PluginRegistrationV1::PluginInfo.new(type: "DRAPlugin", name: driver, endpoint: "", supported_versions: versions)
        end
        define_method(:notify_registration_status) do |request, _call|
          record.call("notify" => request.plugin_registered, "error" => request.error)
          generated::PluginRegistrationV1::RegistrationStatusResponse.new
        end
      end
      dra = Class.new(generated::DRAV1::DRAPlugin::Service) do
        define_method(:node_prepare_resources) do |request, _call|
          record.call("prepare" => request.claims.map(&:name))
          claims = request.claims.to_h do |claim|
            [claim.uid, generated::DRAV1::NodePrepareResourceResponse.new(devices: [
              generated::DRAV1::Device.new(request_names: ["gpu"], pool_name: "node-1", device_name: "gpu-0",
                                           cdi_device_ids: ["\#{driver}/gpu=gpu-0"]),
              generated::DRAV1::Device.new(request_names: ["nic"], pool_name: "node-1", device_name: "nic-0",
                                           cdi_device_ids: ["\#{driver}/nic=nic-0"])
            ])]
          end
          generated::DRAV1::NodePrepareResourcesResponse.new(claims: claims)
        end
        define_method(:node_unprepare_resources) do |request, _call|
          record.call("unprepare" => request.claims.map(&:name))
          generated::DRAV1::NodeUnprepareResourcesResponse.new(
            claims: request.claims.to_h { |claim| [claim.uid, generated::DRAV1::NodeUnprepareResourceResponse.new] }
          )
        end
      end
      server.handle(registration)
      server.handle(dra)
    RUBY
  end

  class Client
    attr_reader :deleted

    def initialize(claims) = (@claims = claims) && (@deleted = [])
    def get(_resource, name, namespace:, api_version:) = Marshal.load(Marshal.dump(@claims.fetch("#{namespace}/#{name}")))
    def raw(method, path, query: nil, **) = @deleted << [method, path, query]
  end

  def claim(name, pod_uid: "pod-uid")
    {"metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}"},
     "status" => {"allocation" => {"devices" => {"results" => [{"request" => "gpu", "driver" => DRIVER, "pool" => "node-1", "device" => "gpu-0"}]}},
                  "reservedFor" => [{"resource" => "pods", "name" => "p", "uid" => pod_uid}]}}
  end

  def pod(uid: "pod-uid", claims: [{"name" => "g", "resourceClaimName" => "c1"}])
    {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => uid},
     "spec" => {"resourceClaims" => claims,
                "containers" => [{"name" => "app", "resources" => {"claims" => [{"name" => "g", "request" => "gpu"}]}},
                                 {"name" => "side", "resources" => {"claims" => [{"name" => "g"}]}},
                                 {"name" => "plain"}]}}
  end

  def with_driver(**)
    Dir.mktmpdir("dra") do |dir|
      registry = File.join(dir, "plugins_registry")
      FileUtils.mkdir_p(registry)
      socket = File.join(registry, "#{DRIVER}-reg.sock")
      log = File.join(dir, "driver.log")
      pid = serve(socket, log, **)
      yield dir, registry, log, pid
    ensure
      GRPCFakeServer.stop(pid)
    end
  end

  def log_entries(log) = File.exist?(log) ? File.readlines(log).map { |line| JSON.parse(line) } : []

  def test_registration_prepare_cdi_devices_and_unprepare
    with_driver do |dir, registry, log|
      now = 0.0
      client = Client.new("ns/c1" => claim("c1"))
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: File.join(dir, "state"),
                                             monotonic: -> { now })
      plugins = Rubernetes::Node::Plugins::Manager.new(directory: registry, handlers: {"DRAPlugin" => dra}, monotonic: -> { now })
      plugins.reconcile

      assert_equal [DRIVER], dra.registered_drivers
      assert_equal [{"notify" => true, "error" => ""}], log_entries(log)

      metrics = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kubelet")
      dra.metrics = metrics

      assert dra.prepare_resources(pod)
      text = metrics.render

      assert_includes text, %(dra_operations_duration_seconds_count{is_error="false",operation_name="PrepareResources"} 1)
      assert_includes text, %(dra_grpc_operations_duration_seconds_count{driver_name="#{DRIVER}",grpc_status_code="OK",) +
                            %(method_name="/k8s.io.kubelet.pkg.apis.dra.v1.DRAPlugin/NodePrepareResources"} 1)
      assert_includes text, %(dra_resource_claims_in_use{driver_name="#{DRIVER}"} 1)
      assert_includes text, %(dra_resource_claims_in_use{driver_name="<any>"} 1)
      assert_equal ["#{DRIVER}/gpu=gpu-0"], dra.container_cdi_devices(pod, pod["spec"]["containers"][0])
      assert_equal ["#{DRIVER}/gpu=gpu-0", "#{DRIVER}/nic=nic-0"], dra.container_cdi_devices(pod, pod["spec"]["containers"][1]),
                   "a claim without a request name means every device of it"
      assert_empty dra.container_cdi_devices(pod, pod["spec"]["containers"][2])
      dra.prepare_resources(pod)

      assert_equal 1, log_entries(log).count { |entry| entry["prepare"] }, "a prepared claim is not prepared again"

      # A restart restores the cache from the checkpoint; the claim is
      # prepared again on its next use.
      restarted = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: File.join(dir, "state"))

      assert restarted.pod_might_need_unprepare?("pod-uid")
      restarted.register_plugin(DRIVER, dra.plugin(DRIVER).endpoint, ["v1.DRAPlugin"])
      restarted.prepare_resources(pod)

      assert_equal(2, log_entries(log).count { |entry| entry["prepare"] })

      assert restarted.unprepare_resources(pod)
      assert_equal([{"unprepare" => ["c1"]}], log_entries(log).select { |entry| entry["unprepare"] })
      refute restarted.pod_might_need_unprepare?("pod-uid")
    end
  end

  # DRAExtendedResource: the claim in status.extendedResourceClaimStatus is
  # prepared with the Pod's own, and its requests reach the containers the
  # request mappings name.
  def test_the_extended_resource_claim_is_prepared_and_mapped
    with_driver do |dir, registry, log|
      extended = claim("p-extended-resources-abcde")
      client = Client.new("ns/p-extended-resources-abcde" => extended)
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: File.join(dir, "state"))
      Rubernetes::Node::Plugins::Manager.new(directory: registry, handlers: {"DRAPlugin" => dra}).reconcile
      pod = {"metadata" => {"name" => "p", "namespace" => "ns", "uid" => "pod-uid"},
             "spec" => {"containers" => [{"name" => "app", "resources" => {"requests" => {"example.com/gpu" => "1"}}},
                                         {"name" => "other", "resources" => {}}]},
             "status" => {"extendedResourceClaimStatus" => {"resourceClaimName" => "p-extended-resources-abcde",
                                                            "requestMappings" => [{"containerName" => "app", "resourceName" => "example.com/gpu",
                                                                                   "requestName" => "gpu"}]}}}
      dra.prepare_resources(pod)

      assert_equal([{"prepare" => ["p-extended-resources-abcde"]}], log_entries(log).select { |entry| entry["prepare"] })
      assert_equal ["#{DRIVER}/gpu=gpu-0"], dra.container_cdi_devices(pod, pod["spec"]["containers"][0])
      assert_empty dra.container_cdi_devices(pod, pod["spec"]["containers"][1])
      dra.unprepare_resources(pod)

      assert_equal([{"unprepare" => ["p-extended-resources-abcde"]}], log_entries(log).select { |entry| entry["unprepare"] })
    end
  end

  def test_a_shared_claim_is_unprepared_by_its_last_pod
    with_driver do |dir, registry, log|
      shared = claim("c1")
      shared["status"]["reservedFor"] << {"resource" => "pods", "name" => "q", "uid" => "other-uid"}
      client = Client.new("ns/c1" => shared)
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: File.join(dir, "state"))
      Rubernetes::Node::Plugins::Manager.new(directory: registry, handlers: {"DRAPlugin" => dra}).reconcile
      dra.prepare_resources(pod)
      dra.prepare_resources(pod(uid: "other-uid"))
      dra.unprepare_resources(pod)

      assert_empty(log_entries(log).select { |entry| entry["unprepare"] })
      # The reconcile pass unprepares for Pods that are no longer active.
      dra.reconcile

      assert_equal([{"unprepare" => ["c1"]}], log_entries(log).select { |entry| entry["unprepare"] })
    end
  end

  def test_claims_must_be_reserved_and_drivers_registered
    Dir.mktmpdir do |dir|
      client = Client.new("ns/c1" => claim("c1", pod_uid: "someone-else"))
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: dir)
      error = assert_raises(Rubernetes::Node::DRAManager::Error) { dra.prepare_resources(pod) }
      assert_equal "pod p (pod-uid) is not allowed to use ResourceClaim c1 (uid-c1)", error.message

      client = Client.new("ns/c1" => claim("c1"))
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: dir)
      error = assert_raises(Rubernetes::Node::DRAManager::Error) { dra.prepare_resources(pod) }
      assert_equal "DRA driver gpu.example.com is not registered", error.message

      template = pod(claims: [{"name" => "g", "resourceClaimTemplateName" => "t"}])
      error = assert_raises(Rubernetes::Node::DRAManager::Error) { dra.prepare_resources(template) }
      assert_equal "pod \"ns/p\": ResourceClaim not created yet", error.message
    end
  end

  def test_unsupported_versions_are_refused_and_deregistration_wipes_slices
    with_driver(versions: ["v9.DRAPlugin"]) do |dir, registry, log|
      now = 0.0
      client = Client.new({})
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: dir, monotonic: -> { now })
      Rubernetes::Node::Plugins::Manager.new(directory: registry, handlers: {"DRAPlugin" => dra}, monotonic: -> { now }).reconcile

      assert_empty dra.registered_drivers
      notify = log_entries(log).find { |entry| entry.key?("notify") }

      refute notify["notify"]
      assert_match(/\ARegisterPlugin error -- plugin validation failed with err: none of services supported by the plugin/, notify["error"])
    end

    Dir.mktmpdir do |dir|
      now = 0.0
      client = Client.new({})
      dra = Rubernetes::Node::DRAManager.new(client: client, node_name: "node-1", state_directory: dir, monotonic: -> { now })
      dra.register_plugin(DRIVER, "/x.sock", ["v1beta1.DRAPlugin"])
      dra.deregister_plugin(DRIVER, "/x.sock")
      dra.reconcile

      assert_empty client.deleted
      now = 31.0
      dra.reconcile

      assert_equal [["DELETE", "/apis/resource.k8s.io/v1/resourceslices", {"fieldSelector" => "spec.nodeName=node-1,spec.driver=#{DRIVER}"}]],
                   client.deleted
      # Re-registering in time cancels the wipe.
      dra.register_plugin(DRIVER, "/x.sock", ["v1.DRAPlugin"])
      dra.deregister_plugin(DRIVER, "/x.sock")
      dra.register_plugin(DRIVER, "/y.sock", ["v1.DRAPlugin"])
      now = 100.0
      dra.reconcile

      assert_equal 1, client.deleted.length
    end
  end

  def test_the_plugin_manager_deregisters_removed_sockets_and_retries_failures
    with_driver do |dir, registry, _log, pid|
      now = 0.0
      dra = Rubernetes::Node::DRAManager.new(client: Client.new({}), node_name: "node-1", state_directory: dir, monotonic: -> { now })
      plugins = Rubernetes::Node::Plugins::Manager.new(directory: registry, handlers: {"DRAPlugin" => dra}, monotonic: -> { now })
      plugins.reconcile

      assert_equal [DRIVER], dra.registered_drivers
      Process.kill("TERM", pid)
      Process.wait(pid)
      FileUtils.rm_f(File.join(registry, "#{DRIVER}-reg.sock"))
      plugins.reconcile

      assert_empty dra.registered_drivers
      assert_empty plugins.registered
    end
  end
end
