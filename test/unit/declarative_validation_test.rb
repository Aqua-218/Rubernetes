# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class DeclarativeValidationTest < Minitest::Test
  API = Rubernetes::API
  RUNTIME_CLASSES = "/apis/node.k8s.io/v1/runtimeclasses"
  POOL_REQUESTS = "/apis/resource.k8s.io/v1alpha3/resourcepoolstatusrequests"
  IP_ADDRESSES = "/apis/networking.k8s.io/v1/ipaddresses"
  WORKLOADS = "/apis/scheduling.k8s.io/v1alpha2/namespaces/default/workloads"
  POD_GROUPS = "/apis/scheduling.k8s.io/v1alpha2/namespaces/default/podgroups"
  PRIORITY_LEVELS = "/apis/flowcontrol.apiserver.k8s.io/v1/prioritylevelconfigurations"
  CLAIMS = "/apis/resource.k8s.io/v1/namespaces/default/resourceclaims"
  SLICES = "/apis/resource.k8s.io/v1/resourceslices"
  CERTIFICATE_REQUESTS = "/apis/certificates.k8s.io/v1/certificatesigningrequests"
  VALIDATION_METRICS = "apiserver_validation_declarative_validation"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry, runtime_config: {"resource.k8s.io/v1alpha3" => true, "scheduling.k8s.io/v1alpha2" => true},
                              feature_gates: {"DeclarativeValidationBeta" => false, "DeclarativeValidationTakeover" => true,
                                              "GenericWorkload" => true, "TopologyAwareWorkloadScheduling" => true})
  end

  def request(method, path, object = nil)
    content_type = method == "PATCH" ? "application/merge-patch+json" : "application/json"
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => content_type},
                                  body: object && JSON.generate(object),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def runtime_class(handler)
    {"apiVersion" => "node.k8s.io/v1", "kind" => "RuntimeClass", "metadata" => {"name" => "runtime"}, "handler" => handler}
  end

  def pool_request(**spec)
    {"apiVersion" => "resource.k8s.io/v1alpha3", "kind" => "ResourcePoolStatusRequest",
     "metadata" => {"name" => "request"}, "spec" => {"driver" => "GPU.Example.COM"}.merge(spec.transform_keys(&:to_s))}
  end

  def causes(response)
    assert_equal 422, response.status, response.body.inspect
    response.body.fetch("details").fetch("causes")
  end

  def test_master_feature_gate_is_locked_in_v1_36
    assert_raises(ArgumentError) { API::Server.new(feature_gates: {"DeclarativeValidation" => false}) }
  end

  def test_runtime_class_create_validates_handler_and_matching_errors_leave_counters_unchanged
    errors = causes(request("POST", RUNTIME_CLASSES, runtime_class("Bad/Handler")))

    assert_equal(["handler"], errors.map { |error| error.fetch("field") })
    assert_includes @server.metrics.render, "#{VALIDATION_METRICS}_mismatch_total 0\n"
    assert_includes @server.metrics.render, "#{VALIDATION_METRICS}_panic_total 0\n"
  end

  def test_alpha_runtime_class_error_is_shadowed_and_divergence_is_counted
    created = request("POST", RUNTIME_CLASSES, runtime_class("runc"))

    assert_equal 201, created.status, created.body.inspect

    # The generated Alpha rules stop at immutability for a nonempty handler.
    # The handwritten update strategy also validates the format.
    errors = causes(request("PUT", "#{RUNTIME_CLASSES}/runtime", created.body.merge("handler" => "Bad/Handler")))

    assert_equal(%w[handler handler], errors.map { |error| error.fetch("field") })
    assert_equal(%w[FieldValueInvalid FieldValueInvalid], errors.map { |error| error.fetch("reason") })
    assert_match(/RFC 1123 label/, errors.first.fetch("message"))
    assert_match(/field is immutable/, errors.last.fetch("message"))
    metrics = @server.metrics.render

    assert_includes metrics, "#{VALIDATION_METRICS}_mismatch_total 1\n"
    assert_includes metrics, %(#{VALIDATION_METRICS}_parity_discrepancies_total{validation_identifier="runtimeclass_update"} 1\n)
  end

  def test_shadow_validation_failure_is_counted_without_changing_a_valid_write
    Rubernetes::Schema::DeclarativeValidation.stub(:runtime_class_mismatches, ->(*) { raise "validator failed" }) do
      created = request("POST", RUNTIME_CLASSES, runtime_class("runc"))

      assert_equal 201, created.status, created.body.inspect
    end
    metrics = @server.metrics.render

    assert_includes metrics, "#{VALIDATION_METRICS}_panic_total 1\n"
    assert_includes metrics, %(#{VALIDATION_METRICS}_panics_total{validation_identifier="runtimeclass_create"} 1\n)
  end

  def test_generated_address_comparison_records_unmatched_nested_required_field
    address = {"apiVersion" => "networking.k8s.io/v1", "kind" => "IPAddress", "metadata" => {"name" => "192.0.2.10"},
               "spec" => {"parentRef" => {"resource" => "services", "name" => "service", "namespace" => "default"}}}
    created = request("POST", IP_ADDRESSES, address)

    assert_equal 201, created.status, created.body.inspect
    invalid = causes(request("PATCH", "#{IP_ADDRESSES}/192.0.2.10", {"spec" => {"parentRef" => {"name" => nil}}}))

    assert_equal(%w[spec.parentRef.name spec.parentRef], invalid.map { |error| error.fetch("field") })
    assert_includes @server.metrics.render, %(#{VALIDATION_METRICS}_parity_discrepancies_total{validation_identifier="ipaddress_update"} 1\n)
  end

  def test_priority_level_keeps_the_handwritten_response_and_reports_unmatched_generated_rules
    object = {"apiVersion" => "flowcontrol.apiserver.k8s.io/v1", "kind" => "PriorityLevelConfiguration",
              "metadata" => {"name" => "probe"}, "spec" => {"type" => "Unknown", "exempt" => {}}}

    errors = causes(request("POST", PRIORITY_LEVELS, object))

    assert_equal(["spec.type"], errors.map { |error| error.fetch("field") })
    assert_includes @server.metrics.render, %(#{VALIDATION_METRICS}_parity_discrepancies_total{validation_identifier="prioritylevelconfiguration_create"} 1\n)
  end

  def test_claim_status_compares_the_generated_validator_for_patch_requests
    object = {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim", "metadata" => {"name" => "claim"}}
    created = request("POST", CLAIMS, object)

    assert_equal 201, created.status, created.body.inspect

    comparison = Rubernetes::Schema::DeclarativeValidation.method(:mismatches)
    operations = []
    Rubernetes::Schema::DeclarativeValidation.stub(:mismatches, lambda do |schema, candidate, old, operation, **options|
      operations << [schema.split(".").last, operation, options[:subresource]]
      comparison.call(schema, candidate, old, operation, **options)
    end) do
      patched = request("PATCH", "#{CLAIMS}/claim/status", {"status" => {"reservedFor" => []}})

      assert_equal 200, patched.status, patched.body.inspect
    end

    assert_equal [["ResourceClaim", :update, "status"]], operations
    assert_includes @server.metrics.render, "#{VALIDATION_METRICS}_panic_total 0\n"
  end

  def test_resource_slice_comparison_uses_the_feature_gated_strategy_view
    attributes = {"example.com/property" => {"int" => 3, "bools" => [true]}}
    object = {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceSlice", "metadata" => {"name" => "slice"},
              "spec" => {"driver" => "example.com", "pool" => {"name" => "pool", "resourceSliceCount" => 1, "generation" => 0},
                         "allNodes" => true, "devices" => [{"name" => "device", "attributes" => attributes}]}}
    comparison = Rubernetes::Schema::DeclarativeValidation.method(:mismatches)
    observed = []
    Rubernetes::Schema::DeclarativeValidation.stub(:mismatches, lambda do |schema, candidate, old, operation, **options|
      observed << candidate.dig("spec", "devices", 0, "attributes")
      comparison.call(schema, candidate, old, operation, **options)
    end) do
      created = request("POST", SLICES, object)

      assert_equal 201, created.status, created.body.inspect
    end

    assert_equal [{"example.com/property" => {"int" => 3}}], observed
    assert_includes @server.metrics.render, "#{VALIDATION_METRICS}_panic_total 0\n"
  end

  def test_certificate_approval_compares_after_the_subresource_sets_conditions
    key = OpenSSL::PKey::EC.generate("prime256v1")
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.parse("/CN=probe")
    csr.public_key = key
    csr.sign(key, OpenSSL::Digest.new("SHA256"))
    object = {"apiVersion" => "certificates.k8s.io/v1", "kind" => "CertificateSigningRequest", "metadata" => {"name" => "probe"},
              "spec" => {"request" => [csr.to_pem].pack("m0"), "signerName" => "example.com/probe", "usages" => ["client auth"]}}
    created = request("POST", CERTIFICATE_REQUESTS, object)

    assert_equal 201, created.status, created.body.inspect

    comparison = Rubernetes::Schema::DeclarativeValidation.method(:mismatches)
    observed = []
    Rubernetes::Schema::DeclarativeValidation.stub(:mismatches, lambda do |schema, candidate, old, operation, **options|
      observed << [options[:subresource], candidate.dig("status", "conditions", 0, "type")]
      comparison.call(schema, candidate, old, operation, **options)
    end) do
      patch = {"status" => {"conditions" => [{"type" => "Approved", "status" => "True", "reason" => "Probe"}]}}
      updated = request("PATCH", "#{CERTIFICATE_REQUESTS}/probe/approval", patch)

      assert_equal 200, updated.status, updated.body.inspect
    end

    assert_equal [%w[approval Approved]], observed
    assert_includes @server.metrics.render, "#{VALIDATION_METRICS}_panic_total 0\n"
  end

  def test_workload_uses_generated_union_list_and_immutable_rules
    template = {"name" => "group", "schedulingPolicy" => {"basic" => {}}}
    workload = {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "Workload", "metadata" => {"name" => "work"},
                "spec" => {"podGroupTemplates" => [template, template]}}
    duplicate = causes(request("POST", WORKLOADS, workload))

    assert_equal(["spec.podGroupTemplates[1]"], duplicate.map { |error| error.fetch("field") })

    invalid = template.merge("schedulingPolicy" => {"gang" => {"minCount" => -1}})
    workload["spec"]["podGroupTemplates"] = [invalid]
    causes = causes(request("POST", WORKLOADS, workload))

    assert_equal(["spec.podGroupTemplates[0].schedulingPolicy.gang.minCount"], causes.map { |error| error.fetch("field") })

    workload["spec"]["podGroupTemplates"] = [template]
    created = request("POST", WORKLOADS, workload)

    assert_equal 201, created.status, created.body.inspect
    causes = causes(request("PATCH", "#{WORKLOADS}/work", {"spec" => {"podGroupTemplates" => [template.merge("name" => "other")]}}))

    assert_equal(["spec.podGroupTemplates"], causes.map { |error| error.fetch("field") })
  end

  def test_pod_group_forbids_invalid_topology_and_drops_disabled_fields
    pod_group = {"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup", "metadata" => {"name" => "group"},
                 "spec" => {"schedulingPolicy" => {"basic" => {}}, "disruptionMode" => "Invalid",
                            "schedulingConstraints" => {"topology" => [{"key" => "bad key"}]}}}
    errors = causes(request("POST", POD_GROUPS, pod_group))

    assert_equal(["spec.schedulingConstraints.topology[0].key"], errors.map { |error| error.fetch("field") })

    pod_group["spec"].delete("schedulingConstraints")
    created = request("POST", POD_GROUPS, pod_group)

    assert_equal 201, created.status, created.body.inspect
    refute created.body.fetch("spec").key?("disruptionMode")
  end

  def test_pool_request_standard_rules_are_enforced_with_beta_disabled
    missing = causes(request("POST", POOL_REQUESTS, pool_request.except("spec")))

    assert_equal(["spec.driver"], missing.map { |error| error.fetch("field") })

    errors = causes(request("POST", POOL_REQUESTS, pool_request(poolName: "invalid//pool", limit: 0)))

    assert_equal(%w[spec.poolName spec.limit], errors.map { |error| error.fetch("field") })
    assert_match(/segment 1: must not be empty/, errors.first.fetch("message"))

    created = request("POST", POOL_REQUESTS, pool_request.merge("status" => {"poolCount" => -1}))

    assert_equal 201, created.status, created.body.inspect
    assert_equal 100, created.body.dig("spec", "limit")
    refute created.body.key?("status")
    path = "#{POOL_REQUESTS}/request"
    updated = request("PATCH", path, {"status" => {"poolCount" => 0}})

    assert_equal 200, updated.status, updated.body.inspect
    refute updated.body.key?("status")

    errors = causes(request("PATCH", path, {"spec" => {"limit" => 101}}))

    assert_equal(["spec"], errors.map { |error| error.fetch("field") })
    assert_match(/field is immutable/, errors.first.fetch("message"))
  end

  def test_pool_status_validates_nested_rules_and_can_only_be_written_once
    created = request("POST", POOL_REQUESTS, pool_request)

    assert_equal 201, created.status, created.body.inspect
    path = "#{POOL_REQUESTS}/request/status"
    invalid = {"poolCount" => -1, "pools" => [{"driver" => "GPU.Example.COM", "poolName" => "node/pool", "generation" => 1, "totalDevices" => -2}]}
    errors = causes(request("PATCH", path, {"status" => invalid}))

    assert_equal(%w[status.poolCount status.pools[0].totalDevices], errors.map { |error| error.fetch("field") })

    errors = causes(request("PATCH", path, {"status" => {"pools" => []}}))

    assert_equal(["status.poolCount"], errors.map { |error| error.fetch("field") })

    errors = causes(request("PATCH", path, {"status" => {"poolCount" => "bad"}}))

    assert_equal(["patch"], errors.map { |error| error.fetch("field") })
    assert_match(/cannot unmarshal string into Go struct field .*status\.poolCount of type int32/, errors.first.fetch("message"))

    stored = request("PATCH", path, {"status" => {"poolCount" => 0}})

    assert_equal 200, stored.status, stored.body.inspect
    assert_equal 0, stored.body.dig("status", "poolCount")
    same = request("PATCH", path, {"status" => {"poolCount" => 0}})

    assert_equal 200, same.status, same.body.inspect

    errors = causes(request("PATCH", path, {"status" => nil}))

    assert_equal(["status"], errors.map { |error| error.fetch("field") })
    assert_match(/field is immutable/, errors.first.fetch("message"))
  end

  def test_pool_request_stored_before_the_limit_default_remains_updatable
    resource = @server.registry.find_gvr(group: "resource.k8s.io", version: "v1alpha3", resource: "resourcepoolstatusrequests")
    @server.store.create(resource: resource, namespace: :cluster, object: pool_request)
    updated = request("PATCH", "#{POOL_REQUESTS}/request", {"metadata" => {"labels" => {"checked" => "true"}}})

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal "true", updated.body.dig("metadata", "labels", "checked")
    explicit_default = request("PATCH", "#{POOL_REQUESTS}/request", {"spec" => {"limit" => 100}})

    assert_equal 200, explicit_default.status, explicit_default.body.inspect
    assert_equal 100, explicit_default.body.dig("spec", "limit")
  end
end
