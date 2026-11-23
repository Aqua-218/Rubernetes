# frozen_string_literal: true

require "base64"
require "uri"

module Rubernetes
  module Cluster
    # The public cluster record downloaded by kubeadm token discovery.
    module BootstrapDiscovery
      NAMESPACE = "kube-public"
      NAME = "cluster-info"
      ROLE_NAME = "kubeadm:bootstrap-signer-clusterinfo"
      CONFIG_MAPS_PATH = "/api/v1/namespaces/#{NAMESPACE}/configmaps".freeze
      PUBLIC_PATH = "#{CONFIG_MAPS_PATH}/#{NAME}".freeze
      RBAC_PATH = "/apis/rbac.authorization.k8s.io/v1/namespaces/#{NAMESPACE}".freeze

      private

      def install_bootstrap_discovery!(kubeconfig, local_endpoint, ca_path)
        client = api_client(kubeconfig)
        data = {"kubeconfig" => bootstrap_discovery_kubeconfig(local_endpoint, ca_path)}
        config_map = create_discovery_object(client, CONFIG_MAPS_PATH, "v1", "ConfigMap", NAME, "data" => data)
        # A preexisting custom ConfigMap belongs to its operator. Do not
        # grant anonymous access to contents this provisioner did not write.
        return unless config_map["data"] == data && (config_map["binaryData"] || {}).empty?

        group_version = "rbac.authorization.k8s.io/v1"
        rules = [{"apiGroups" => [""], "resources" => ["configmaps"], "resourceNames" => [NAME], "verbs" => ["get"]}]
        role = create_discovery_object(client, "#{RBAC_PATH}/roles", group_version, "Role", ROLE_NAME, "rules" => rules)
        return unless role["rules"] == rules

        create_discovery_object(client, "#{RBAC_PATH}/rolebindings", group_version, "RoleBinding", ROLE_NAME,
                                "roleRef" => {"apiGroup" => "rbac.authorization.k8s.io", "kind" => "Role", "name" => ROLE_NAME},
                                "subjects" => [{"apiGroup" => "rbac.authorization.k8s.io", "kind" => "User", "name" => "system:anonymous"}])
      rescue Client::Error => error
        raise Error, "installing bootstrap discovery failed: #{error.message[0, 300]}"
      ensure
        client&.close
      end

      def bootstrap_discovery_kubeconfig(local_endpoint, ca_path)
        endpoint = URI.parse(local_endpoint)
        endpoint.hostname = host_advertise_address(families.first)
        cluster = {"certificate-authority-data" => Base64.strict_encode64(File.binread(ca_path)), "server" => endpoint.to_s}
        YAML.dump("apiVersion" => "v1", "kind" => "Config", "clusters" => [{"name" => "", "cluster" => cluster}])
      end

      def create_discovery_object(client, path, api_version, kind, name, attributes)
        object = {"apiVersion" => api_version, "kind" => kind, "metadata" => {"name" => name, "namespace" => NAMESPACE}}.merge(attributes)
        client.create(path, object)
      rescue Client::APIError => error
        raise unless error.status == 409 && error.status_object&.fetch("reason", nil) == "AlreadyExists"

        client.get("#{path}/#{name}")
      end
    end
  end
end
