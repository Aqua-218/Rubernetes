# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/cluster"
require "tmpdir"

class BootstrapDiscoveryTest < Minitest::Test
  Cluster = Rubernetes::Cluster
  Discovery = Cluster::BootstrapDiscovery

  class Client
    attr_reader :objects

    def initialize
      @objects = {}
    end

    def create(path, object)
      member = "#{path}/#{object.dig("metadata", "name")}"
      if objects.key?(member)
        response = Struct.new(:status).new(409)
        raise Rubernetes::Client::APIError.new("already exists", response: response, status_object: {"reason" => "AlreadyExists"})
      end

      objects[member] = object
    end

    def get(path) = objects.fetch(path)
    def close = nil
  end

  def with_cluster
    Dir.mktmpdir do |directory|
      client = Client.new
      cluster = Cluster::Provisioner.new(root: directory, identities: :bootstrap)
      cluster.define_singleton_method(:api_client) { |_config| client }
      cluster.define_singleton_method(:host_advertise_address) { |_family| "192.0.2.5" }
      ca = File.join(directory, "ca.crt")
      File.binwrite(ca, "public CA fixture")
      install = -> { cluster.send(:install_bootstrap_discovery!, "admin-config", "https://127.0.0.1:6443", ca) }
      yield client, install
    end
  end

  def test_public_record_contains_ca_and_endpoint_and_the_binding_is_narrow
    with_cluster do |client, install|
      install.call
      config_map = client.get(Discovery::PUBLIC_PATH)
      config = YAML.safe_load(config_map.dig("data", "kubeconfig"))

      assert_equal({"apiVersion" => "v1", "kind" => "Config", "clusters" => [
                     {"name" => "", "cluster" => {"server" => "https://192.0.2.5:6443", "certificate-authority-data" => Base64.strict_encode64("public CA fixture")}}
                   ]}, config)
      role = client.get("#{Discovery::RBAC_PATH}/roles/#{Discovery::ROLE_NAME}")
      binding = client.get("#{Discovery::RBAC_PATH}/rolebindings/#{Discovery::ROLE_NAME}")
      subjects = binding.fetch("subjects").map { |subject| subject.values_at("kind", "name") }

      assert_equal [{"apiGroups" => [""], "resources" => ["configmaps"], "resourceNames" => ["cluster-info"], "verbs" => ["get"]}], role["rules"]
      assert_equal [["User", "system:anonymous"]], subjects
    end
  end

  def test_retry_fills_a_missing_binding_without_replacing_objects
    with_cluster do |client, install|
      install.call
      config_map = client.get(Discovery::PUBLIC_PATH)
      binding_path = "#{Discovery::RBAC_PATH}/rolebindings/#{Discovery::ROLE_NAME}"
      original = client.objects.delete(binding_path)

      install.call

      assert_same config_map, client.get(Discovery::PUBLIC_PATH)
      assert_equal original, client.get(binding_path)
    end
  end

  def test_preexisting_custom_discovery_contents_are_preserved
    with_cluster do |client, install|
      custom = {"metadata" => {"name" => "cluster-info"}, "data" => {"kubeconfig" => "operator-managed entry"}}
      client.create(Discovery::CONFIG_MAPS_PATH, custom)

      install.call

      assert_equal({Discovery::PUBLIC_PATH => custom}, client.objects)
    end
  end

  def test_preexisting_custom_discovery_role_is_preserved_without_adding_a_binding
    with_cluster do |client, install|
      custom_role = {"metadata" => {"name" => Discovery::ROLE_NAME}, "rules" => []}
      client.create("#{Discovery::RBAC_PATH}/roles", custom_role)

      install.call

      assert_same custom_role, client.get("#{Discovery::RBAC_PATH}/roles/#{Discovery::ROLE_NAME}")
      refute client.objects.key?("#{Discovery::RBAC_PATH}/rolebindings/#{Discovery::ROLE_NAME}")
    end
  end

  def test_anonymous_authentication_is_limited_to_the_bootstrap_profile
    admin = Cluster::Provisioner.new(root: "/tmp/bootstrap-discovery-test", identities: :admin)
    components = Cluster::Provisioner.new(root: admin.root, identities: :components)
    bootstrap = Cluster::Provisioner.new(root: admin.root, identities: :bootstrap)

    assert_equal({"enabled" => false}, admin.send(:api_anonymous_authentication))
    assert_equal({"enabled" => false}, components.send(:api_anonymous_authentication))
    assert_equal({"enabled" => true, "conditions" => [{"path" => Discovery::PUBLIC_PATH}]}, bootstrap.send(:api_anonymous_authentication))
  end
end
