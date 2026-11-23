# frozen_string_literal: true

require "tempfile"
require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)
require "rubernetes/api"
require "rubernetes/bootstrap/config"

class PodProjectionValidationTest < Minitest::Test
  API = Rubernetes::API
  PODS = "/api/v1/namespaces/default/pods"
  DEPLOYMENTS = "/apis/apps/v1/namespaces/default/deployments"
  STATEFULSETS = "/apis/apps/v1/namespaces/default/statefulsets"
  PATH = "spec.volumes[0].projected"

  def test_downward_environment_and_volume_fields_have_distinct_validation
    body = pod([])
    body["spec"]["volumes"] = [{"name" => "identity", "downwardAPI" => {"items" => [
      {"path" => "owner", "fieldRef" => {"fieldPath" => "metadata.name", "apiVersion" => "v2"}}
    ]}}]
    body["spec"]["containers"][0]["env"] = [{"name" => "NODE", "valueFrom" => {"fieldRef" => {"fieldPath" => "spec.host"}}}]
    body["spec"]["initContainers"] = [{"name" => "prepare", "image" => "busybox", "env" => [
      {"name" => "CPU", "valueFrom" => {"resourceFieldRef" => {"resource" => "requests.cpu", "divisor" => "100m"}}}
    ]}]
    api = server
    response = request(api, "POST", PODS, body)

    assert_equal 422, response.status
    assert_equal [cause("spec.volumes[0].downwardAPI.fieldRef.fieldPath", "Invalid",
                        'Invalid value: "metadata.name": error converting fieldPath: unsupported pod version: v2'),
                  cause("spec.initContainers[0].env[0].valueFrom.resourceFieldRef.divisor", "Invalid",
                        'Invalid value: "requests.cpu": only divisor\'s values 1m and 1 are supported with the cpu resource')],
                 response.body.dig("details", "causes")
    body.dig("spec", "volumes", 0, "downwardAPI", "items", 0, "fieldRef").delete("apiVersion")
    body.dig("spec", "initContainers", 0, "env", 0, "valueFrom", "resourceFieldRef")["divisor"] = "1m"
    accepted = request(api, "POST", PODS, body)

    assert_equal 201, accepted.status, accepted.body.inspect
    assert_equal "spec.host", accepted.body.dig("spec", "containers", 0, "env", 0, "valueFrom", "fieldRef", "fieldPath")
  end

  def test_omitted_and_null_resource_divisors_round_trip_as_zero
    direct = {"path" => "cpu", "resourceFieldRef" => {"containerName" => "main", "resource" => "requests.cpu", "divisor" => nil}}
    projected = {"path" => "memory", "resourceFieldRef" => {"containerName" => "main", "resource" => "limits.memory", "divisor" => "1Mi"}}
    body = pod([{"downwardAPI" => {"items" => [projected]}}])
    body.fetch("spec").fetch("volumes") << {"name" => "direct", "downwardAPI" => {"items" => [direct]}}
    body.dig("spec", "containers", 0)["env"] = [{"name" => "CPU", "valueFrom" => {"resourceFieldRef" => {"resource" => "requests.cpu"}}}]
    api = server
    created = request(api, "POST", "#{PODS}?fieldValidation=Strict", body)
    read = request(api, "GET", "#{PODS}/projection", nil)

    assert_equal [201, 200], [created.status, read.status]
    [created.body, read.body].each do |object|
      assert_equal "0", object.dig("spec", "containers", 0, "env", 0, "valueFrom", "resourceFieldRef", "divisor")
      assert_equal "0", object.dig("spec", "volumes", 1, "downwardAPI", "items", 0, "resourceFieldRef", "divisor")
      assert_equal "1Mi", object.dig("spec", "volumes", 0, "projected", "sources", 0, "downwardAPI", "items", 0, "resourceFieldRef", "divisor")
    end
  end

  def test_apply_defaults_after_atomic_selector_ownership_is_computed
    labels = {"app" => "resources"}
    reference = {"resource" => "requests.cpu"}
    spec = {"containers" => [{"name" => "main", "image" => "busybox", "env" => [{"name" => "CPU", "valueFrom" => {"resourceFieldRef" => reference}}]}]}
    deployment = {"kind" => "Deployment", "apiVersion" => "apps/v1", "metadata" => {"name" => "resources"},
                  "spec" => {"selector" => {"matchLabels" => labels}, "template" => {"metadata" => {"labels" => labels}, "spec" => spec}}}
    api = server
    apply = lambda do |manager|
      api.call(method: "PATCH", path: "#{DEPLOYMENTS}/resources?fieldManager=#{manager}&fieldValidation=Strict",
               headers: {"Content-Type" => "application/apply-patch+yaml"}, body: JSON.generate(deployment))
    end
    created = apply.call("alpha")
    conflict = apply.call("beta")
    reference["divisor"] = "0"
    shared = apply.call("beta")

    assert_equal [201, 409, 200], [created.status, conflict.status, shared.status]
    assert_equal "0", created.body.dig("spec", "template", "spec", "containers", 0, "env", 0, "valueFrom", "resourceFieldRef", "divisor")
    ownership = created.body.dig("metadata", "managedFields", 0, "fieldsV1", "f:spec", "f:template", "f:spec", "f:containers", 'k:{"name":"main"}',
                                 "f:env", 'k:{"name":"CPU"}', "f:valueFrom")

    assert_equal({"f:resourceFieldRef" => {}}, ownership)
  end

  def test_defaulting_legacy_resource_selectors_does_not_rewrite_storage
    body = pod([])
    env_path = ["spec", "containers", 0, "env", 0, "valueFrom", "resourceFieldRef"]
    body.dig("spec", "containers", 0)["env"] = [{"name" => "CPU", "valueFrom" => {"resourceFieldRef" => {"resource" => "requests.cpu"}}}]
    store = API::MemoryStore.new
    keys = {gvr: "v1/pods", namespace: "default", name: "projection"}
    store.create(**keys, object: body)
    api = server(store: store)
    get = request(api, "GET", "#{PODS}/projection", nil)
    listed = request(api, "GET", PODS, nil).body.fetch("items").first

    assert_equal "0", get.body.dig(*env_path, "divisor")
    assert_equal "0", listed.dig(*env_path, "divisor")
    refute store.get(**keys).dig(*env_path).key?("divisor")
  end

  def test_each_source_can_select_at_most_one_type
    projections = [
      {"secret" => {"name" => "credentials"}, "configMap" => {"name" => "settings"}},
      {},
      {"downwardAPI" => {}, "serviceAccountToken" => {"path" => "token"}}
    ]
    response = request(server, "POST", PODS, pod(projections))

    assert_equal 422, response.status
    assert_equal [0, 2].map { |index|
      cause("#{PATH}.sources[#{index}]", "Forbidden", "Forbidden: may not specify more than 1 volume type per source")
    }, response.body.dig("details", "causes")
  end

  def test_duplicate_paths_in_explicit_sources_and_items
    projections = [
      {"secret" => {"name" => "credentials", "items" => [{"key" => "a", "path" => "file"}, {"key" => "b", "path" => "file"}]}},
      {"configMap" => {"name" => "settings", "items" => [{"key" => "c", "path" => "file"}]}},
      {"downwardAPI" => {"items" => [{"path" => "file", "fieldRef" => {"fieldPath" => "metadata.name"}}]}},
      {"clusterTrustBundle" => {"name" => "trust", "path" => "file"}},
      {"podCertificate" => {"signerName" => "example.com/sign", "keyType" => "ED25519", "credentialBundlePath" => "file"}}
    ]
    response = request(server(gates: feature_gates), "POST", PODS, pod(projections))

    assert_equal 422, response.status
    assert_equal %w[credentials settings file file file].map { |value|
      cause(PATH, "Invalid", "Invalid value: #{value.inspect}: conflicting duplicate paths")
    }, response.body.dig("details", "causes")
  end

  def test_empty_implicit_and_token_sources_are_accepted
    projections = [
      {},
      {"secret" => {"name" => "credentials"}},
      {"configMap" => {"name" => "settings", "items" => [{"key" => "one", "path" => "file"}, {"key" => "two", "path" => "./file"}]}},
      {"serviceAccountToken" => {"path" => "file"}}
    ]
    response = request(server, "POST", PODS, pod(projections))

    assert_equal 201, response.status, response.body.inspect
    assert_equal [420, 3600], [response.body.dig("spec", "volumes", 0, "projected", "defaultMode"),
                               response.body.dig("spec", "volumes", 0, "projected", "sources", 3, "serviceAccountToken", "expirationSeconds")]
  end

  def test_invalid_paths_and_default_mode_use_kubernetes_causes
    projections = [
      {"secret" => {"name" => "credentials", "items" => [{"key" => "entry", "path" => "/../file"}]}},
      {"downwardAPI" => {"items" => [{"fieldRef" => {"fieldPath" => "spec.nodeName"}}]}},
      {"serviceAccountToken" => {"expirationSeconds" => 599}}
    ]
    response = request(server, "POST", PODS, pod(projections, default_mode: 512))

    assert_equal 422, response.status
    assert_equal [
      cause("#{PATH}.defaultMode", "Invalid", "Invalid value: 512: must be a number between 0 and 0777 (octal), both inclusive"),
      cause("#{PATH}.sources[0].secret.items[0].path", "Invalid", 'Invalid value: "/../file": must be a relative path'),
      cause("#{PATH}.sources[0].secret.items[0].path", "Invalid", %q(Invalid value: "/../file": must not contain '..')),
      cause("#{PATH}.sources[1].downwardAPI.path", "Required", "Required value"),
      cause("#{PATH}.sources[1].downwardAPI.fieldRef.fieldPath", "NotSupported",
            'Unsupported value: "spec.nodeName": supported values: "metadata.annotations", "metadata.labels", ' \
            '"metadata.name", "metadata.namespace", "metadata.uid"'),
      cause("#{PATH}.sources[2].serviceAccountToken.expirationSeconds", "Invalid",
            "Invalid value: 599: may not specify a duration less than 10 minutes"),
      cause("#{PATH}.path", "Required", "Required value")
    ], response.body.dig("details", "causes")
  end

  def test_statefulset_update_checks_new_projections_when_the_stored_template_is_valid
    spec = pod([{"secret" => {"name" => "credentials"}}]).fetch("spec")
    labels = {"app" => "workload"}
    statefulset = {"apiVersion" => "apps/v1", "kind" => "StatefulSet", "metadata" => {"name" => "workload", "namespace" => "default"},
                   "spec" => {"serviceName" => "workload", "selector" => {"matchLabels" => labels},
                              "template" => {"metadata" => {"labels" => labels}, "spec" => spec}}}
    api = server
    created = request(api, "POST", STATEFULSETS, statefulset)

    assert_equal 201, created.status, created.body.inspect

    bad_volume = pod([{"secret" => {"name" => "credentials"}, "configMap" => {"name" => "settings"}}]).dig("spec", "volumes")
    response = request(api, "PATCH", "#{STATEFULSETS}/workload", "spec" => {"template" => {"spec" => {"volumes" => bad_volume}}})

    assert_equal 422, response.status
    assert_equal [cause("spec.template.#{PATH}.sources[0]", "Forbidden", "Forbidden: may not specify more than 1 volume type per source")],
                 response.body.dig("details", "causes")
  end

  def test_deployment_template_uses_its_own_projection_field_path
    spec = pod([{"secret" => {"name" => "credentials"}, "configMap" => {"name" => "settings"}}]).fetch("spec")
    labels = {"app" => "workload"}
    deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "workload", "namespace" => "default"},
                  "spec" => {"selector" => {"matchLabels" => labels}, "template" => {"metadata" => {"labels" => labels}, "spec" => spec}}}
    response = request(server, "POST", DEPLOYMENTS, deployment)

    assert_equal 422, response.status
    assert_equal [cause("spec.template.#{PATH}.sources[0]", "Forbidden", "Forbidden: may not specify more than 1 volume type per source")],
                 response.body.dig("details", "causes")
  end

  def test_projection_features_are_pruned_before_validation_and_retained_if_already_used
    projections = [
      {"clusterTrustBundle" => {"name" => "trust", "path" => "ca"}},
      {"podCertificate" => {"keyType" => "ED25519", "credentialBundlePath" => "tls", "signerName" => "example.com/sign"}}
    ]
    store = API::MemoryStore.new
    enabled = request(server(gates: feature_gates, store: store), "POST", PODS, pod(projections))

    assert_equal 201, enabled.status, enabled.body.inspect
    assert_equal projections, enabled.body.dig("spec", "volumes", 0, "projected", "sources")

    updated = request(server(store: store), "PATCH", "#{PODS}/projection", "metadata" => {"labels" => {"changed" => "true"}})

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal projections, updated.body.dig("spec", "volumes", 0, "projected", "sources")

    disabled = request(server, "POST", PODS, pod([{"clusterTrustBundle" => {}, "podCertificate" => {}}]))

    assert_equal 201, disabled.status, disabled.body.inspect
    assert_equal [{}], disabled.body.dig("spec", "volumes", 0, "projected", "sources")
  end

  def test_projection_gate_dependencies_are_checked_for_api_server_and_node
    config_class = Rubernetes::Bootstrap::Config
    %w[rubernetes-apiserver rubernetes-agent].each do |process|
      error = assert_raises(config_class::Error) do
        load_gate_config(process, {"ClusterTrustBundleProjection" => true})
      end
      assert_match(/ClusterTrustBundleProjection requires ClusterTrustBundle/, error.message)

      error = assert_raises(config_class::Error) do
        load_gate_config(process, {"PodCertificateRequest" => true, "AuthorizeNodeWithSelectors" => false})
      end
      assert_match(/PodCertificateRequest requires AuthorizeNodeWithSelectors/, error.message)

      config = load_gate_config(process, feature_gates)

      assert_equal true, config.process.fetch("security", config.process).dig("feature_gates", "ClusterTrustBundleProjection")
    end
  end

  private

  def cause(path, reason, message)
    {"field" => path, "reason" => "FieldValue#{reason}", "message" => message}
  end

  def pod(projections, default_mode: nil)
    projected = {"sources" => projections}
    projected["defaultMode"] = default_mode if default_mode
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "projection", "namespace" => "default"},
     "spec" => {"serviceAccountName" => "default", "containers" => [{"name" => "main", "image" => "busybox"}],
                "volumes" => [{"name" => "files", "projected" => projected}]}}
  end

  def feature_gates
    {"ClusterTrustBundle" => true, "ClusterTrustBundleProjection" => true, "PodCertificateRequest" => true}
  end

  def load_gate_config(process, flags)
    gates = {"feature_gates" => flags}
    settings = process == "rubernetes-apiserver" ? {"security" => gates} : gates
    Tempfile.create(["rubernetes-projection-gates", ".yml"]) do |file|
      file.write(JSON.generate("processes" => {process => settings}))
      file.flush
      Rubernetes::Bootstrap::Config.load(process_name: process, path: file.path)
    end
  end

  def server(gates: {}, store: API::MemoryStore.new)
    types = [["", "v1", "pods", "Pod", "core"], ["apps", "v1", "deployments", "Deployment", "apps"],
             ["apps", "v1", "statefulsets", "StatefulSet", "apps"]]
    resources = types.map do |group, version, resource, kind, schema_group|
      API::Resource.new(group: group, version: version, resource: resource, kind: kind, scope: :namespaced,
                        schema: Rubernetes::Generated.definition_for("io.k8s.api.#{schema_group}.#{version}.#{kind}"))
    end
    API::Server.new(registry: API::Registry.new(resources: resources, defaults: false), store: store, feature_gates: gates)
  end

  def request(api, method, path, body)
    headers = method == "PATCH" ? {"Content-Type" => "application/merge-patch+json"} : {}
    api.call(API::Request.new(method: method, path: path, headers: headers, body: body))
  end
end
