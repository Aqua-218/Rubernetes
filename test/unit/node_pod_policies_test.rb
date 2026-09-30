# frozen_string_literal: true

require_relative "../test_helper"
require "base64"
require "json"
require "rubernetes/node/admission"
require "rubernetes/node/image_credentials"
require "rubernetes/proxy/model"

# Node-side Pod policies added for kubelet parity: the sysctl allowlist,
# imagePullSecrets keyrings, and kube-proxy's port-name endpoint matching.
class NodePodPoliciesTest < Minitest::Test
  Admission = Rubernetes::Node::Admission
  ImageCredentials = Rubernetes::Node::ImageCredentials

  def pod_with_sysctls(sysctls, host_network: false, host_ipc: false)
    {"metadata" => {"name" => "p", "namespace" => "default"},
     "spec" => {"hostNetwork" => host_network, "hostIPC" => host_ipc,
                "securityContext" => {"sysctls" => sysctls.map { |name, value| {"name" => name, "value" => value} }},
                "containers" => [{"name" => "c", "image" => "busybox"}]}}
  end

  def test_safe_sysctls_are_admitted
    admission = Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"})
    decision = admission.admit(pod_with_sysctls({"kernel.shm_rmid_forced" => "1", "net.ipv4.ip_local_port_range" => "1024 65535"}))

    assert decision.accepted, decision.message
  end

  def test_unsafe_sysctl_is_forbidden_unless_allowlisted
    admission = Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"})
    decision = admission.admit(pod_with_sysctls({"kernel.msgmax" => "1000"}))

    refute decision.accepted
    assert_equal "SysctlForbidden", decision.reason
    assert_match(/not allowlisted/, decision.message)

    permissive = Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"},
                               allowed_unsafe_sysctls: ["kernel.msg*"])

    assert permissive.admit(pod_with_sysctls({"kernel.msgmax" => "1000"})).accepted
  end

  def test_namespaced_sysctls_are_refused_with_host_namespaces
    admission = Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"})
    decision = admission.admit(pod_with_sysctls({"net.ipv4.tcp_syncookies" => "1"}, host_network: true))

    assert_equal "SysctlForbidden", decision.reason
    assert_match(/host net/, decision.message)
    decision = admission.admit(pod_with_sysctls({"kernel.shm_rmid_forced" => "1"}, host_ipc: true))

    assert_match(/host ipc/, decision.message)
  end

  def test_pods_without_a_runtime_class_list_are_not_rejected_for_runtime_class
    admission = Admission.new(node_name: "n1", capacity: {"cpu" => "4", "memory" => "8Gi", "pods" => "10"}, runtime_classes: nil)
    pod = {"metadata" => {"name" => "p"}, "spec" => {"runtimeClassName" => "gvisor", "containers" => [{"name" => "c", "image" => "x"}]}}

    assert admission.admit(pod).accepted
  end

  # ------------------------------------------------------ imagePullSecrets

  class FakeReader
    def initialize(objects)
      @objects = objects
    end

    def get(plural, name, namespace:)
      @objects.fetch([plural, namespace, name])
    end
  end

  def docker_secret(name, auths, type: "kubernetes.io/dockerconfigjson")
    document = {"auths" => auths}
    {"metadata" => {"name" => name, "namespace" => "default"}, "type" => type,
     "data" => {".dockerconfigjson" => Base64.strict_encode64(JSON.generate(document))}}
  end

  def test_keyring_merges_pod_and_service_account_secrets_and_matches_registries
    reader = FakeReader.new(
      %w[secrets default
         hub] => docker_secret("hub", {"https://index.docker.io/v1/" => {"auth" => Base64.strict_encode64("hubuser:hubpass")}}),
      %w[secrets default
         private] => docker_secret("private", {"registry.example.com/team" => {"username" => "u", "password" => "p"}}),
      %w[serviceaccounts default default] => {"metadata" => {"name" => "default"}, "imagePullSecrets" => [{"name" => "private"}]}
    )
    pod = {"metadata" => {"name" => "p", "namespace" => "default"},
           "spec" => {"imagePullSecrets" => [{"name" => "hub"}], "containers" => []}}
    keyring = ImageCredentials.for_pod(pod, reader: reader)

    assert_equal({username: "hubuser", password: "hubpass"}, keyring.lookup("busybox:1.36").to_h)
    assert_equal({username: "hubuser", password: "hubpass"}, keyring.lookup("docker.io/library/nginx").to_h)
    assert_equal({username: "u", password: "p"}, keyring.lookup("registry.example.com/team/app:v1").to_h)
    assert_nil keyring.lookup("registry.example.com/other/app:v1")
    assert_nil keyring.lookup("registry.k8s.io/pause:3.10")
  end

  def test_keyring_survives_missing_secrets
    reader = FakeReader.new({})
    pod = {"metadata" => {"name" => "p", "namespace" => "default"},
           "spec" => {"imagePullSecrets" => [{"name" => "missing"}], "containers" => []}}

    assert_empty ImageCredentials.for_pod(pod, reader: reader)
  end

  # ------------------------------------------------------ proxy port names

  def test_endpoint_ports_match_service_ports_by_name
    service_port = Rubernetes::Proxy::ServicePort.new(name: "https", port: 443, target_port: 43_741, protocol: "TCP")
    endpoint_class = Rubernetes::Proxy::Endpoint
    matching = endpoint_class.new(address: "10.0.0.1", port: 37_729, port_name: "https", protocol: "TCP")
    other_name = endpoint_class.new(address: "10.0.0.1", port: 43_741, port_name: "metrics", protocol: "TCP")

    assert matching.port_compatible?(service_port)
    refute other_name.port_compatible?(service_port)

    unnamed = Rubernetes::Proxy::ServicePort.new(port: 80, target_port: 8080, protocol: "TCP")

    assert endpoint_class.new(address: "10.0.0.2", port: 8080, protocol: "TCP").port_compatible?(unnamed)
    refute endpoint_class.new(address: "10.0.0.2", port: 8080, protocol: "UDP").port_compatible?(unnamed)
  end
end
