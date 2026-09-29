# frozen_string_literal: true

# kube-controller-manager --use-service-account-credentials: each controller
# reconciles through its own kube-system ServiceAccount (the client name
# upstream's ClientBuilder is asked for), created if missing, with a
# TokenRequest token refreshed before it expires; the token controller keeps
# the controller manager's identity.

require_relative "../test_helper"
require "rubernetes/controller"
require "rubernetes/controller/service_account_credentials"
require "rubernetes/bootstrap"
require "rubernetes/storage/memory_store"

class ControllerServiceAccountCredentialsTest < Minitest::Test
  Controller = Rubernetes::Controller
  Credentials = Controller::ServiceAccountCredentials
  Response = Struct.new(:status)

  class Root
    attr_reader :calls, :context
    attr_accessor :accounts

    def initialize
      @calls = []
      @accounts = {}
      @issued = 0
      @context = Rubernetes::Client::Kubeconfig::KubeContext.new(
        name: "cm", server: "https://127.0.0.1:6443", namespace: "default", ca_file: "/pki/ca.crt",
        client_certificate_file: "/pki/cm.crt", client_key_file: "/pki/cm.key", bearer_token: nil
      )
    end

    def get(resource, name, namespace:, api_version:)
      @calls << [:get, resource, namespace, name]
      return @accounts[name] if @accounts.key?(name)

      raise Rubernetes::Client::APIError.new("not found", response: Response.new(404))
    end

    def create(object, namespace:, api_version:, path: nil)
      @calls << [:create, path || object["kind"], namespace, object.dig("metadata", "name")]
      if path
        @issued += 1
        return {"status" => {"token" => "token-#{path.split("/")[-2]}-#{@issued}"}}
      end
      @accounts[object.dig("metadata", "name")] = object
    end
  end

  def setup
    @now = 0.0
    @root = Root.new
    @contexts = []
    @credentials = Credentials.new(root_client: @root, clock: -> { @now },
                                   client_factory: ->(context) { @contexts << context; context })
  end

  def test_upstream_client_names
    assert_equal "daemon-set-controller", Credentials.service_account_for("daemonset-controller")
    assert_equal "generic-garbage-collector", Credentials.service_account_for("garbage-collector-controller")
    assert_equal "node-controller", Credentials.service_account_for("taint-eviction-controller")
    assert_equal "certificate-controller", Credentials.service_account_for("certificatesigningrequest-signing-controller")
    assert_equal "selinux-warning-controller", Credentials.service_account_for("selinux-warning-controller"), "NewClient(controllerName)"
    assert_nil Credentials.service_account_for("serviceaccount-token-controller")
  end

  def test_a_controller_client_uses_its_service_account_token
    context = @credentials.client_for("deployment-controller")
    assert_equal "https://127.0.0.1:6443", context.server
    assert_equal "/pki/ca.crt", context.ca_file
    assert_nil context.client_certificate_file, "the controller manager's certificate is not presented"
    assert_equal "kube-system", context.namespace
    assert_equal "token-deployment-controller-1", context.bearer_token
    assert_includes @root.calls, [:create, "ServiceAccount", "kube-system", "deployment-controller"]
    assert_includes @root.calls, [:create, "/api/v1/namespaces/kube-system/serviceaccounts/deployment-controller/token",
                                  "kube-system", nil]
    assert_same context, @credentials.client_for("deployment-controller"), "one client per service account"

    @now += 3600 * 0.79
    assert_equal "token-deployment-controller-1", context.bearer_token
    @now += 3600 * 0.02
    assert_equal "token-deployment-controller-2", context.bearer_token, "refreshed at 80% of its lifetime"
    assert_equal 1, @root.calls.count { |call| call[0] == :create && call[1] == "ServiceAccount" }
  end

  def test_a_real_http_client_sends_the_current_token
    token = "first"
    context = Credentials::TokenContext.new(@root.context, -> { token })
    client = Rubernetes::Client::KubernetesClient.new(context: context)
    headers = client.rest_client.send(:build_headers, {}, nil)
    assert_equal "Bearer first", headers["Authorization"]
    token = "second"
    assert_equal "Bearer second", client.rest_client.send(:build_headers, {}, nil)["Authorization"]
  end

  # The default factory builds a real client, which reads its bearer token
  # while it is constructed: building it under the credentials' lock raised
  # "deadlock; recursive locking" in every controller.
  def test_the_default_factory_builds_a_client_without_recursive_locking
    credentials = Credentials.new(root_client: @root, clock: -> { @now })
    client = credentials.client_for("deployment-controller")
    headers = client.rest_client.send(:build_headers, {}, nil)
    assert_equal "Bearer token-deployment-controller-1", headers["Authorization"]
    assert_match %r{\A[^/]+/v1\.36\.2 \(linux/[a-z0-9]+\) kubernetes/unknown/deployment-controller\z}, headers["User-Agent"]
    assert_same client, credentials.client_for("deployment-controller")
  end

  def test_the_token_controller_keeps_the_managers_identity
    assert_same @root, @credentials.client_for("serviceaccount-token-controller")
  end

  def test_manager_reconciles_each_controller_through_its_store
    store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    other = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    seen = []
    kind = Controller::ResourceDescriptor.parse("ConfigMap")
    definition = Controller::ControllerDefinition.new(
      name: "configmap-sa-controller", kind: kind,
      watches: [Controller::WatchSpec.new(resource: kind, via: :all, index_name: "sa/configmaps",
                                          queue_key: ->(object) { "#{Controller::Support.namespace(object)}/#{Controller::Support.name(object)}" })],
      reconcile_block: lambda do |resource, context|
        seen << context[:store]
        Controller::ReconcileResult.new(operations: [], controller: "configmap-sa-controller", key: Controller::Support.name(resource))
      end,
      implementation: Class.new(Controller::BaseController)
    )
    registry = Controller::ControllerRegistry.new(require_corpus: false)
    registry.register(definition)
    names = []
    manager = Controller::Manager.new(store: store, identity: "sa-#{Process.pid}", registry: registry,
                                      lease: {lease_duration_seconds: 10, renew_deadline_seconds: 6, retry_period_seconds: 1},
                                      store_for: ->(name) { names << name; other })
    manager.register_definition(definition, store: store)
    informer = Class.new do
      def on(_event = nil, &handler) = (@handler = handler) && self
      def emit(object) = @handler.call(object, nil)
    end.new
    manager.register_informer(definition.name, informer)
    Controller::StoreAdapter.new(store).create({"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "c", "namespace" => "default"}},
                                               descriptor: kind)
    informer.emit({"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "c", "namespace" => "default", "uid" => "u"}})
    manager.step
    assert_equal ["configmap-sa-controller"], names.uniq
    assert_same other, seen.last
  ensure
    manager&.stop
  end

  def test_the_kubernetes_store_adapter_view_shares_the_caches
    client = Object.new
    caches = {"x" => 1}
    adapter = Rubernetes::Bootstrap::KubernetesStoreAdapter.new(client: Object.new, resource_descriptors: ["ConfigMap"], caches: caches)
    view = adapter.with_client(client)
    assert_same client, view.client
    assert_same caches, view.caches
    assert_equal adapter.resource_descriptors, view.resource_descriptors
  end

  def test_the_option_is_validated
    config = Rubernetes::Bootstrap::Config
    assert_includes config::CONTROL_PLANE_KEYS, "use_service_account_credentials"
  end
end
