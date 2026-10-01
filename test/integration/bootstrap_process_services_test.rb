# frozen_string_literal: true

require_relative "../test_helper"
require "stringio"
require "rubernetes/bootstrap"

class BootstrapProcessServicesTest < Minitest::Test
  class Logger
    attr_reader :events

    def initialize
      @events = []
    end

    %i[debug info warn error fatal].each do |level|
      define_method(level) do |event, **fields|
        @events << [level, event, fields]
        true
      end
    end
  end

  class API
    attr_reader :patches, :applied, :updated

    def initialize(objects = {})
      @objects = objects
      @leases = {}
      @patches = []
    end

    # Mirrors Client::KubernetesClient#get: a name makes it a point lookup,
    # no name makes it a list.  The adapter uses the point lookup, so a fake
    # that only lists sends every controller down the list path.
    def get(resource, name = nil, namespace: nil, api_version: nil, query: nil, **_options)
      # `:all` means every namespace, the way the real client renders a
      # cluster-wide path; treating it as a namespace *name* filtered
      # everything out and made the source look empty.
      scoped = namespace.nil? || namespace == :all || namespace.to_s.empty?
      values = Array(@objects.fetch(resource.to_s, [])).select do |object|
        scoped || object.dig("metadata", "namespace").to_s == namespace.to_s
      end
      return values.find { |object| object.dig("metadata", "name").to_s == name.to_s } if name

      {"items" => values, "metadata" => {"resourceVersion" => "1"}}
    end

    # A created object has to be visible to the next get, the way it is
    # against a real API server: a fake that forgets its writes sends the
    # caller round the acquire path forever and never reaches the steady
    # state the test is about.
    def create(object, namespace:, api_version:)
      value = deep_copy(object)
      value["apiVersion"] ||= api_version
      value["metadata"] ||= {}
      value["metadata"]["namespace"] ||= namespace if namespace
      value["metadata"]["resourceVersion"] = "2"
      @leases[value.dig("metadata", "name")] = value if value["kind"] == "Lease"
      store(value)
      value
    end

    def apply(object, namespace:, field_manager:, **_options)
      (@applied ||= []) << deep_copy(object)
      create(object, namespace: namespace, api_version: object["apiVersion"])
    end

    # Mirrors Client::KubernetesClient#update: a PUT of the whole object.
    def update(object, namespace: nil, **_options)
      (@updated ||= []) << deep_copy(object)
      value = deep_copy(object)
      value["metadata"]["namespace"] ||= namespace if namespace
      value["metadata"]["resourceVersion"] = (value.dig("metadata", "resourceVersion").to_i + 1).to_s
      store(value)
      value
    end

    def patch(resource, body, **options)
      @patches << [resource, body, options]
      current = Array(@objects[resource.to_s]).find do |object|
        object.dig("metadata", "name").to_s == options.fetch(:name).to_s
      end
      merged = deep_copy(current || {"metadata" => {"name" => options.fetch(:name),
                                                    "namespace" => options[:namespace]}})
      deep_merge!(merged, deep_copy(body))
      merged["kind"] ||= "Pod"
      merged["metadata"]["resourceVersion"] = (merged.dig("metadata", "resourceVersion").to_i + 1).to_s
      store(merged, resource: resource.to_s)
      merged
    end

    def delete(*_args, **_options)
      {}
    end

    def watch_each(*_args, **_options)
      [].each
    end

    private

    def resource_for(object)
      "#{object.fetch("kind").to_s.downcase}s"
    end

    def store(object, resource: nil)
      key = resource || resource_for(object)
      values = (@objects[key] ||= [])
      index = values.index do |candidate|
        candidate.dig("metadata", "name").to_s == object.dig("metadata", "name").to_s &&
          candidate.dig("metadata", "namespace").to_s == object.dig("metadata", "namespace").to_s
      end
      index ? values[index] = object : values << object
      object
    end

    def deep_merge!(target, patch)
      patch.each do |key, value|
        if value.is_a?(Hash) && target[key].is_a?(Hash)
          deep_merge!(target[key], value)
        else
          target[key] = value
        end
      end
      target
    end

    def deep_copy(value)
      case value
      when Hash then value.to_h { |key, child| [key.to_s, deep_copy(child)] }
      when Array then value.map { |child| deep_copy(child) }
      else value
      end
    end
  end

  class StatusAPI < API
    attr_reader :applies

    def initialize(objects = {})
      super
      @applies = []
    end

    def apply(object, namespace:, field_manager:, **options)
      @applies << {object: object, namespace: namespace, field_manager: field_manager, options: options}
      object
    end
  end

  NetworkPort = Class.new

  VolumePort = Class.new

  def setup
    @logger = Logger.new
  end

  def test_controller_manager_uses_registry_informers_and_reconcile_loop
    registry = Rubernetes::Controller::ControllerRegistry.new(require_corpus: false)
    source_registry = Rubernetes::Controller.build_default_registry
    source_registry.definitions.each { |definition| registry.register(definition) }
    service = Rubernetes::Bootstrap::ControllerManagerService.new(
      config: {}, logger: @logger, client: API.new, registry: registry
    )

    service.start

    assert_predicate(service, :ready?)
    assert_equal(registry.size, service.manager.controllers.size)
    refute_empty(service.informers)
    assert(@logger.events.any? { |event| event[1] == "process.ready" })
  ensure
    service&.stop(reason: "test")
  end

  def test_scheduler_starts_informers_and_binds_a_pending_pod
    client = API.new(
      "nodes" => [{"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "node-a"},
                   "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}],
                                "allocatable" => {"cpu" => "2"}}}],
      "pods" => [{"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "pod-a", "namespace" => "default"},
                  "spec" => {"containers" => []}}]
    )
    service = Rubernetes::Bootstrap::SchedulerService.new(config: {}, logger: @logger, client: client)

    service.start
    Timeout.timeout(2) do
      sleep(0.01) until client.patches.any?
    end

    assert_predicate(service, :ready?)
    assert_instance_of(Rubernetes::Controller::LeaseElector, service.elector)
    assert_predicate(service.elector, :leader?)
    assert_equal("pods", client.patches.fetch(0).fetch(0))
    assert_equal("node-a", client.patches.fetch(0).fetch(1).fetch("spec").fetch("nodeName"))
  ensure
    service&.stop(reason: "test")
  end

  def test_scheduler_fences_bind_before_the_api_side_effect
    client = API.new
    service = Rubernetes::Bootstrap::SchedulerService.new(config: {}, logger: @logger, client: client,
                                                          framework: Object.new)
    follower = Class.new do
      def step
        :follower
      end

      def leader?
        false
      end
    end.new
    service.instance_variable_set(:@elector, follower)
    pod = Rubernetes::Scheduler::Pod.new(
      "apiVersion" => "v1", "kind" => "Pod",
      "metadata" => {"name" => "pod-a", "namespace" => "default"}, "spec" => {}
    )
    node = Rubernetes::Scheduler::Node.new(
      {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => "node-a"}}
    )

    assert_raises(Rubernetes::Controller::LeadershipLostError) do
      service.send(:bind_pod, pod, node)
    end
    assert_empty(client.patches)
  end

  # resourcelock.LeaseLock.Update: a PUT of the whole Lease carrying the
  # resourceVersion it was read at (the RBAC bootstrap grants get/update on
  # the lease, not patch).
  def test_remote_lease_update_uses_resource_version_cas_put
    client = API.new
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(
      client: client,
      resource_descriptors: [Rubernetes::Controller::ResourceDescriptor.parse("Lease")]
    )
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("Lease")
    existing = {
      "apiVersion" => "coordination.k8s.io/v1",
      "kind" => "Lease",
      "metadata" => {"name" => "leader", "namespace" => "kube-system", "uid" => "uid-1", "resourceVersion" => "7"},
      "spec" => {"holderIdentity" => "worker-a", "renewTime" => "2026-01-01T00:00:00Z"}
    }
    candidate = Marshal.load(Marshal.dump(existing))
    candidate["spec"]["renewTime"] = "2026-01-01T00:00:01Z"

    adapter.update(candidate, descriptor: descriptor, existing: existing)

    assert_empty client.patches
    body = client.updated.fetch(0)

    assert_equal "Lease", body["kind"]
    assert_equal "7", body.dig("metadata", "resourceVersion")
    assert_equal "worker-a", body.dig("spec", "holderIdentity")
    assert_equal "2026-01-01T00:00:01Z", body.dig("spec", "renewTime")
    assert_equal "leader", body.dig("metadata", "name")
    assert_equal "kube-system", body.dig("metadata", "namespace")
  end

  # A controller update is an ordinary authoritative PUT (client-go Update),
  # never a forced server-side apply: it carries the resourceVersion the plan
  # was made from, so a stale plan fails 409 and a plan for an object deleted
  # meanwhile fails 404 instead of re-creating it (a forced apply of a cached
  # Node re-created every Node the e2e suite deleted).  Server-owned
  # bookkeeping stays with the server.
  def test_an_update_is_a_put_carrying_its_resource_version_and_no_server_owned_bookkeeping
    client = API.new
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("PersistentVolumeClaim")
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(
      client: client, resource_descriptors: [descriptor]
    )
    existing = {
      "apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
      "metadata" => {"name" => "pvc-1", "namespace" => "dev", "uid" => "uid-1",
                     "resourceVersion" => "7", "generation" => 3,
                     "managedFields" => [{"manager" => "someone"}]},
      "spec" => {"volumeName" => "pv-1"}
    }
    candidate = Marshal.load(Marshal.dump(existing))
    candidate["metadata"]["finalizers"] = ["kubernetes.io/pvc-protection"]

    adapter.update(candidate, descriptor: descriptor, existing: existing)

    assert_nil client.applied, "an update must not be a server-side apply"
    applied = client.updated.fetch(0)

    assert_equal "7", applied.dig("metadata", "resourceVersion"),
                 "an update carries the resourceVersion it was planned from as its precondition"
    refute applied.fetch("metadata").key?("managedFields"), "managedFields is owned by the server"
    refute applied.fetch("metadata").key?("generation"), "generation is owned by the server"
    assert_equal ["kubernetes.io/pvc-protection"], applied.dig("metadata", "finalizers")
    assert_equal "uid-1", applied.dig("metadata", "uid")
  end

  class ConflictAPI < API
    attr_reader :create_attempts

    def initialize(objects = {})
      super
      @create_attempts = 0
      @existing = {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
                   "metadata" => {"name" => "svc-abc-0", "namespace" => "ns", "uid" => "live-uid",
                                  "resourceVersion" => "9"},
                   "endpoints" => [{"addresses" => ["10.0.0.1"]}]}
    end

    def create(_object, namespace: nil, api_version: nil)
      @create_attempts += 1
      response = Struct.new(:status, :body, :headers).new(409, "", {})
      raise Rubernetes::Client::APIError.new("endpointslices \"svc-abc-0\" already exists", response: response)
    end

    def get(resource, name = nil, **options)
      return @existing if name.to_s == "svc-abc-0"

      super
    end
  end

  # AlreadyExists on a deterministically named object is not a sync failure:
  # upstream adopts what the server already holds, so the next reconcile plans
  # an update.  Failing instead re-queued the key forever (533 reconcile
  # failures across 426 Services in one conformance round).
  def test_a_conflicting_create_adopts_the_live_object_and_seeds_the_cache
    client = ConflictAPI.new
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("EndpointSlice")
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [descriptor])
    added = []
    cache = Object.new
    cache.define_singleton_method(:add) { |object| added << object }
    adapter.caches = {descriptor.identifier => cache}
    slice = {"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
             "metadata" => {"name" => "svc-abc-0", "namespace" => "ns"}, "endpoints" => []}

    result = adapter.create(slice, descriptor: descriptor)

    assert_equal 1, client.create_attempts
    assert_equal "live-uid", result.dig("metadata", "uid"), "the live object is adopted"
    assert_equal ["svc-abc-0"], added.map { |o| o.dig("metadata", "name") }, "the cache is seeded with it"
  end

  class GoneAPI < API
    def update(_object, **_options)
      response = Struct.new(:status, :body, :headers).new(404, "", {})
      raise Rubernetes::Client::APIError.new("nodes \"n\" not found", response: response)
    end
  end

  # The object the plan was made from was deleted meanwhile: the update fails
  # and the stale copy leaves the cache, so the next reconcile sees nothing.
  def test_an_update_of_a_deleted_object_fails_and_drops_it_from_the_cache
    client = GoneAPI.new
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("Node")
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: client, resource_descriptors: [descriptor])
    deleted = []
    cache = Object.new
    cache.define_singleton_method(:delete) { |object| deleted << object }
    cache.define_singleton_method(:update) { |_object| nil }
    adapter.caches = {descriptor.identifier => cache}
    existing = {"apiVersion" => "v1", "kind" => "Node",
                "metadata" => {"name" => "n", "uid" => "uid-n", "resourceVersion" => "3"},
                "spec" => {"unschedulable" => true}}
    candidate = Marshal.load(Marshal.dump(existing))
    candidate["spec"]["taints"] = [{"key" => "k", "effect" => "NoSchedule"}]

    assert_raises(Rubernetes::Client::APIError) { adapter.update(candidate, descriptor: descriptor, existing: existing) }
    assert_equal(["n"], deleted.map { |object| object.dig("metadata", "name") })
  end

  def test_remote_status_write_distinguishes_absent_and_empty_status
    descriptor = Rubernetes::Controller::ResourceDescriptor.parse("CronJob")
    cron_job = {
      "apiVersion" => "batch/v1", "kind" => "CronJob",
      "metadata" => {"name" => "suspended", "namespace" => "default", "uid" => "cron-uid"}
    }
    operation = Rubernetes::Controller::Operation.new(
      action: :status_update, resource: descriptor, object: cron_job, patch: {}
    )

    absent_status_client = StatusAPI.new("cronjobs" => [cron_job])
    absent_status_adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(
      client: absent_status_client, resource_descriptors: [descriptor]
    )
    absent_status_adapter.apply_status(operation)

    # UpdateStatus (a PUT of the status subresource), as the CronJob
    # controller writes it.
    assert_empty absent_status_client.applies
    assert_equal({}, absent_status_client.updated.fetch(0).fetch("status"))

    persisted_status_client = StatusAPI.new("cronjobs" => [cron_job.merge("status" => {})])
    persisted_status_adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(
      client: persisted_status_client, resource_descriptors: [descriptor]
    )
    persisted_status_adapter.apply_status(operation)

    assert_empty persisted_status_client.applies
    assert_nil persisted_status_client.updated
  end

  def test_proxy_primes_backend_and_starts_service_and_endpoint_watches
    client = API.new(
      "services" => [{"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "web", "namespace" => "default"},
                      "spec" => {"clusterIP" => "10.0.0.1", "ports" => [{"port" => 80, "targetPort" => 8080}],
                                 "selector" => {"app" => "web"}}}],
      "endpointslices" => [{"apiVersion" => "discovery.k8s.io/v1", "kind" => "EndpointSlice",
                            "metadata" => {"name" => "web-1", "namespace" => "default",
                                           "labels" => {"kubernetes.io/service-name" => "web"}},
                            "addressType" => "IPv4", "ports" => [{"port" => 8080}],
                            "endpoints" => [{"addresses" => ["10.1.0.2"], "conditions" => {"ready" => true}}]}]
    )
    service = Rubernetes::Bootstrap::ProxyService.new(
      config: {"node_name" => "node-a", "backend" => "memory"}, logger: @logger, client: client
    )

    service.start

    assert_predicate(service, :ready?)
    assert_equal(["default/web"], service.proxy.services.map(&:key))
    assert_equal(2, service.subscriptions.length)
    assert_predicate(service.proxy.backend, :ready?)
  ensure
    service&.stop(reason: "test")
  end

  def test_assembler_routes_control_plane_processes_to_concrete_services
    client = API.new
    %w[rubernetes-controller-manager rubernetes-scheduler rubernetes-proxy].each do |process_name|
      adapters = {
        "#{process_name.delete_prefix("rubernetes-").tr("-", "_")}_client" => client
      }
      adapters["proxy"] = Rubernetes::Proxy::Proxy.new(backend: Rubernetes::Proxy::MemoryBackend.new) if process_name == "rubernetes-proxy"
      assembly = Rubernetes::Bootstrap::Assembler.new(
        process_name: process_name, log_io: StringIO.new, runtime_adapters: adapters
      ).build
      expected = case process_name
                 when "rubernetes-controller-manager" then Rubernetes::Bootstrap::ControllerManagerService
                 when "rubernetes-scheduler" then Rubernetes::Bootstrap::SchedulerService
                 else Rubernetes::Bootstrap::ProxyService
                 end

      assert_instance_of(expected, assembly.service)
    end
  end

  def test_assembler_injects_network_and_volume_ports_into_node_agent
    network = NetworkPort.new
    volume = VolumePort.new
    assembly = Rubernetes::Bootstrap::Assembler.new(
      process_name: "rubernetes-agent", log_io: StringIO.new,
      runtime_adapters: {network: network, volume: volume}
    ).build

    assert_same(network, assembly.service.node_agent.lifecycle.network)
    assert_same(volume, assembly.service.node_agent.lifecycle.volume)
  end

  def test_control_plane_services_fail_closed_when_production_api_is_missing
    %w[rubernetes-controller-manager rubernetes-scheduler rubernetes-proxy].each do |process_name|
      service = Rubernetes::Bootstrap::Assembler.new(process_name: process_name, log_io: StringIO.new).build.service
      assert_raises(Rubernetes::Bootstrap::Config::Error) { service.start }
    end
  end
end
