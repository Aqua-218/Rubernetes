# frozen_string_literal: true

require "stringio"
require "tmpdir"
require "timeout"
require "yaml"
require_relative "../test_helper"
require "rubernetes/bootstrap"
require "rubernetes/transport"

class KubeletNodeRegistrationTest < Minitest::Test
  AGENT = "rubernetes-agent"
  NAME = "registration-worker"
  NODE = "/api/v1/nodes/#{NAME}".freeze
  LEASE = "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/#{NAME}".freeze
  MIRROR = "/api/v1/namespaces/default/pods/static-#{NAME}".freeze
  INITIAL = {"key" => "team.example/initial", "value" => "one", "effect" => "NoSchedule"}.freeze
  CLOUD = {"key" => "node.cloudprovider.kubernetes.io/uninitialized", "value" => "true", "effect" => "NoSchedule"}.freeze
  OPERATOR = {"key" => "team.example/operator", "effect" => "PreferNoSchedule"}.freeze

  # The pure runtime exercises local Pod lifecycle without pulling an image
  # or making a workload-specific change to the host.
  class Images
    def resolve(reference, **)
      {"reference" => reference, "digest" => "sha256:#{"ab" * 32}"}
    end

    def release(*) = true
    def staging_root = nil
    def pull_records = nil
  end

  def setup
    @directory = Dir.mktmpdir("kubelet-node-registration")
    @services = []
    @requests = Queue.new
    @boot_logs = {}
  end

  def teardown
    @services.reverse_each { |service| service.stop(reason: "test end") }
    @transport&.stop(timeout: 1)
    FileUtils.remove_entry(@directory)
  end

  def test_registration_taints_are_create_only_and_disabled_registration_keeps_local_working
    start_api
    first = boot("register", true)
    initial_node = await { get(NODE) }
    initial_uid = initial_node.dig("metadata", "uid")

    assert_equal [INITIAL, CLOUD], initial_node.dig("spec", "taints")
    assert_equal initial_uid, await { get(LEASE) }.dig("metadata", "ownerReferences", 0, "uid")

    first.stop(reason: "restart")
    @services.delete(first)
    @client.patch(NODE, {"spec" => {"taints" => [OPERATOR]}}, type: :merge)
    Rubernetes::Node::APIClientAdapter.new(client: @client, node_name: NAME, external_cloud_provider: true)
      .register_node(first.node_agent.node)

    assert_equal [OPERATOR], get(NODE).dig("spec", "taints")

    delete(NODE)
    delete(LEASE)
    node_creates_before_boot = node_creates
    disabled = boot("externally-managed", false, static_pod_path: write_static_pod)
    agent = disabled.node_agent

    assert_predicate agent, :running?, @boot_logs.fetch(disabled).string
    static = await(message: -> { @boot_logs.fetch(disabled).string.lines.last(12).join }) { static_record(agent) }

    assert_nil get(NODE)
    assert_nil get(LEASE)
    assert_nil get(MIRROR)
    assert_equal node_creates_before_boot, node_creates
    assert_equal "Running", static.fetch(:phase)
    assert_equal [false, [INITIAL]], configz(disabled).values_at("registerNode", "registerWithTaints")

    existing = @client.create({"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => NAME},
                               "spec" => {"taints" => [OPERATOR]}})
    uid = existing.dig("metadata", "uid")

    assert agent.sync_node_status(force: true)
    agent.renew_lease(force: true)
    mirror = await { get(MIRROR) }

    refute_equal initial_uid, uid
    assert_equal [OPERATOR], get(NODE).dig("spec", "taints")
    assert_equal "True", get(NODE).dig("status", "conditions").find { |entry| entry["type"] == "Ready" }.fetch("status")
    assert_equal uid, get(LEASE).dig("metadata", "ownerReferences", 0, "uid")
    assert_equal uid, mirror.dig("metadata", "ownerReferences", 0, "uid")

    delete(NODE)
    delete(LEASE)

    refute agent.sync_node_status(force: true)
    assert_nil agent.renew_lease(force: true)
    assert_nil get(NODE)
    assert_nil get(LEASE)
    assert_equal node_creates_before_boot + 1, node_creates
    assert_equal "Running", static_record(agent).fetch(:phase)
  end

  def test_typed_configuration_validates_registration_taints_and_time_added
    cases = {
      {"registerNode" => "false"} => "registerNode must be a boolean",
      {"registerWithTaints" => INITIAL} => "registerWithTaints must be an array",
      {"registerWithTaints" => [INITIAL.merge("key" => "Invalid.prefix/initial")]} => "key is invalid",
      {"registerWithTaints" => [INITIAL.merge("value" => "spaces are invalid")]} => "value must be a valid label value",
      {"registerWithTaints" => [INITIAL.merge("effect" => "Invalid")]} => "effect must be one of",
      {"registerWithTaints" => [INITIAL.merge("timeAdded" => "2026-11-20T00:00:00Z")]} => "taint.TimeAdded is not nil",
      {"registerWithTaints" => [INITIAL.merge("typo" => "invalid")]} => "must contain only"
    }
    cases.each do |document, message|
      path = write_component("validation", document)
      error = assert_raises(Rubernetes::Bootstrap::Config::Error) { Rubernetes::Bootstrap::Config.load(process_name: AGENT, path: path) }

      assert_includes error.message, message
    end
    path = write_component("validation", "registerNode" => false, "registerWithTaints" => [INITIAL.merge("timeAdded" => nil)])
    config = Rubernetes::Bootstrap::Config.load(process_name: AGENT, path: path)
    readback = Rubernetes::Node::KubeletConfigz.build(config.process).fetch("kubeletconfig")

    assert_equal [false, [INITIAL]], readback.values_at("registerNode", "registerWithTaints")
    assert_empty config.kubelet_read_only_fields
  end

  private

  def start_api
    bootstrap = Rubernetes::Bootstrap::APIServerService.allocate
    registry = bootstrap.send(:build_registry, Rubernetes::Schema::Catalog.default)
    server = Rubernetes::API::Server.new(registry: registry)
    requests = @requests
    server.define_singleton_method(:call) do |request|
      requests << true if request.method == "POST" && request.path == "/api/v1/nodes"
      super(request)
    end
    @transport = Rubernetes::Transport::HTTPServer.new(server, host: "127.0.0.1", port: 0, shutdown_timeout: 1).start
    @url = "http://127.0.0.1:#{@transport.port}"
    @client = Rubernetes::Client::KubernetesClient.new(server: @url)
  end

  def boot(label, register_node, static_pod_path: nil)
    root = File.join(@directory, label)
    FileUtils.mkdir_p(root)
    native = {"node_name" => NAME, "api_server" => @url, "cloud_provider" => "external", "runtime_profile" => "pure",
              "sandbox_root" => File.join(root, "sandbox"), "journal_path" => File.join(root, "ledger.jsonl"),
              "log_root" => File.join(root, "logs"), "sync" => {"watch_timeout_seconds" => 1}, "lease" => {"renew_fraction" => 0.1}}
    path = File.join(@directory, "#{label}-native.yml")
    File.write(path, YAML.dump({"processes" => {AGENT => native}}))
    settings = {"enableServer" => false, "healthzPort" => 0, "registerNode" => register_node, "registerWithTaints" => [INITIAL],
                "nodeStatusUpdateFrequency" => "200ms"}
    if static_pod_path
      settings["staticPodPath"] = static_pod_path
      settings["fileCheckFrequency"] = "100ms"
    end
    component = write_component(label, settings)
    log = StringIO.new
    assembly = Rubernetes::Bootstrap::Assembler.new(process_name: AGENT, config_path: path, kubelet_config_path: component,
                                                    runtime_adapters: {image_resolver: Images.new}, log_io: log).build
    service = assembly.service
    @services << service
    @boot_logs[service] = log
    service.start
    service
  end

  def write_component(label, settings)
    path = File.join(@directory, "#{label}-kubelet.yml")
    File.write(path, YAML.dump({"apiVersion" => "kubelet.config.k8s.io/v1beta1", "kind" => "KubeletConfiguration"}.merge(settings)))
    path
  end

  def write_static_pod
    path = File.join(@directory, "static.yml")
    File.write(path, <<~YAML)
      apiVersion: v1
      kind: Pod
      metadata:
        name: static
        namespace: default
      spec:
        containers:
        - name: busy
          image: example.test/local:1
          command: ["sleep", "60"]
    YAML
    path
  end

  def static_record(agent)
    agent.lifecycle.records.values.find { |record| record.dig(:pod, "metadata", "name") == "static-#{NAME}" && record[:phase] == "Running" }
  end

  def get(path)
    @client.get(path)
  rescue Rubernetes::Client::APIError => error
    raise unless error.status == 404

    nil
  end

  def delete(path)
    object = get(path)
    return unless object

    @client.delete(path, options: {"gracePeriodSeconds" => 0, "preconditions" => {"uid" => object.dig("metadata", "uid")}})
  end

  def configz(service) = Rubernetes::Node::KubeletConfigz.build(service.config).fetch("kubeletconfig")

  def node_creates
    @node_creates ||= 0
    @node_creates += 1 while @requests.pop(timeout: 0)
    @node_creates
  end

  def await(message: nil)
    Timeout.timeout(8) do
      loop do
        value = yield
        return value if value

        sleep 0.02
      end
    end
  rescue Timeout::Error
    flunk "timed out waiting for node state\n#{message&.call}"
  end
end
