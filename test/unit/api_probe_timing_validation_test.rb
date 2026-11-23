# frozen_string_literal: true

require "json"
require "stringio"
require_relative "../test_helper"
require "rubernetes/bootstrap"

class APIProbeTimingValidationTest < Minitest::Test
  API = Rubernetes::API
  Bootstrap = Rubernetes::Bootstrap
  PODS = "/api/v1/namespaces/default/pods"
  DEPLOYMENTS = "/apis/apps/v1/namespaces/default/deployments"
  NAME = "probe-check"
  FIELDS = %w[initialDelaySeconds timeoutSeconds periodSeconds successThreshold failureThreshold].freeze

  def setup
    config = Bootstrap::Config.load(process_name: "rubernetes-apiserver")
    logger = Bootstrap::StructuredLogger.new(process_name: "rubernetes-apiserver", io: StringIO.new, level: "fatal")
    @service = Bootstrap::APIServerService.new(config: config.process, logger: logger)
  end

  def test_negative_liveness_probe_values_return_ordered_kubernetes_causes
    options = FIELDS.to_h { |field| [field, -1] }.merge("terminationGracePeriodSeconds" => -1)
    object = pod("livenessProbe" => probe(options))
    response = send_request("POST", "#{PODS}?dryRun=All", object)
    path = "spec.containers[0].livenessProbe"
    expected = FIELDS.map { |field| cause("#{path}.#{field}", "Invalid value: -1: must be greater than or equal to 0") }
    expected << cause("#{path}.terminationGracePeriodSeconds", "Invalid value: -1: must be greater than 0")
    expected << cause("#{path}.successThreshold", "Invalid value: -1: must be 1")

    assert_causes response, expected
  end

  def test_probe_defaults_and_readiness_success_threshold
    zeros = FIELDS.to_h { |field| [field, 0] }
    object = pod("startupProbe" => probe(zeros), "readinessProbe" => probe("successThreshold" => 2, "terminationGracePeriodSeconds" => nil))
    response = send_request("POST", PODS, object)

    assert_equal 201, response.status, response.body.inspect
    container = response.body.dig("spec", "containers", 0)

    assert_equal 2, container.dig("readinessProbe", "successThreshold")
    assert_equal [1, 10, 1, 3], container.fetch("startupProbe").values_at("timeoutSeconds", "periodSeconds", "successThreshold", "failureThreshold")
  end

  def test_init_container_probe_rules_apply_to_deployment_templates
    object = pod
    container = {"name" => "initial", "image" => "busybox:1.36", "readinessProbe" => probe("terminationGracePeriodSeconds" => 0)}
    object["spec"]["initContainers"] = [container]
    deployment = deployment_with(object.fetch("spec"))
    field = "spec.template.spec.initContainers[0].readinessProbe"

    assert_causes send_request("POST", "#{DEPLOYMENTS}?dryRun=All", deployment), [
      {"field" => field, "reason" => "FieldValueForbidden",
       "message" => "Forbidden: may not be set for init containers without restartPolicy=Always"}
    ]

    container["restartPolicy"] = "Always"
    sidecar = deployment_with(object.fetch("spec"))
    path = "#{field}.terminationGracePeriodSeconds"

    assert_causes send_request("POST", "#{DEPLOYMENTS}?dryRun=All", sidecar), [
      cause(path, "Invalid value: 0: must be greater than 0"),
      cause(path, "Invalid value: 0: must not be set for readinessProbes")
    ]
  end

  def test_status_update_does_not_revalidate_legacy_probe_timing
    legacy = pod("livenessProbe" => probe("successThreshold" => 2))
    legacy.fetch("metadata").merge!("namespace" => "default", "uid" => "probe-uid")
    stored = @service.store.create("registry/v1/pods/default/#{NAME}", legacy)
    body = stored.merge("status" => {"phase" => "Running"})
    result = send_request("PUT", "#{PODS}/#{NAME}/status", body)

    assert_equal 200, result.status, result.body.inspect
    assert_equal 2, result.body.dig("spec", "containers", 0, "livenessProbe", "successThreshold")
  end

  def test_custom_resource_with_a_builtin_kind_has_no_probe_strategy_rules
    group = "apps.example.com"
    names = {"kind" => "Deployment", "plural" => "deployments", "singular" => "deployment"}
    schema = {"type" => "object", "x-kubernetes-preserve-unknown-fields" => true}
    version = {"name" => "v1", "served" => true, "storage" => true, "schema" => {"openAPIV3Schema" => schema}}
    crd = {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition",
           "metadata" => {"name" => "deployments.#{group}"},
           "spec" => {"group" => group, "scope" => "Cluster", "names" => names, "versions" => [version]}}
    created = send_request("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", crd)

    assert_equal 201, created.status, created.body.inspect

    object = deployment_with(pod("livenessProbe" => probe("successThreshold" => 4)).fetch("spec")).merge("apiVersion" => "#{group}/v1")
    result = send_request("POST", "/apis/#{group}/v1/deployments?dryRun=All", object)

    assert_equal 201, result.status, result.body.inspect
    assert_equal 4, result.body.dig("spec", "template", "spec", "containers", 0, "livenessProbe", "successThreshold")
  end

  private

  def send_request(method, path, object)
    @service.api_server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                              body: JSON.generate(object)))
  end

  def probe(options)
    {"httpGet" => {"path" => "/health", "port" => 8080}}.merge(options)
  end

  def pod(probes = {})
    container = {"name" => "app", "image" => "busybox:1.36"}.merge(probes)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => NAME}, "spec" => {"containers" => [container]}}
  end

  def deployment_with(spec)
    label = {"app" => NAME}
    template = {"metadata" => {"labels" => label}, "spec" => spec}
    {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => NAME},
     "spec" => {"selector" => {"matchLabels" => label}, "template" => template}}
  end

  def cause(field, message)
    {"field" => field, "reason" => "FieldValueInvalid", "message" => message}
  end

  def assert_causes(response, expected)
    assert_equal 422, response.status, response.body.inspect
    assert_equal expected, response.body.dig("details", "causes")
  end
end
