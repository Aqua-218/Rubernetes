#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require_relative "../../lib/rubernetes"
require_relative "../../lib/rubernetes/schema"
require_relative "../../lib/rubernetes/schema/declarative_validation"

rules = Rubernetes::Schema::DeclarativeRules
artifact = JSON.parse(File.read(rules::SOURCE))
if ARGV == ["--matrix"]
  registry = JSON.parse(File.read(File.join(File.dirname(rules::SOURCE), "registry.json")))
  registered = registry.fetch("resources").map { |resource| resource.fetch("schema") }
  registered << "io.k8s.api.autoscaling.v1.Scale"
  authoritative = [Rubernetes::Schema::KubernetesValidator::POOL_STATUS_SCHEMA,
                   *Rubernetes::Schema::KubernetesValidator::SCHEDULING_DECLARATIVE_KINDS.map do |kind|
                     "io.k8s.api.scheduling.v1alpha2.#{kind}"
                   end]
  shadowed = Rubernetes::Schema::DeclarativeValidation::SHADOWED_SCHEMAS
  puts "schema\trest_integration\tunhandled_constructs"
  (registered.uniq & artifact.fetch("types").keys).sort.each do |schema|
    integration = if authoritative.include?(schema)
                    "authoritative"
                  elsif shadowed.include?(schema)
                    "shadow comparison"
                  elsif schema.end_with?(".DeviceTaintRule", ".ResourceClaimTemplate")
                    "upstream does not invoke generated REST validation"
                  else
                    "pending"
                  end
    puts [schema, integration, rules.outstanding(schema).join(", ")].join("\t")
  end
  exit
end

# Run the importer and this comparison against the same pinned checkout.
source = File.realpath(ENV.fetch("KUBERNETES_SOURCE_ROOT", "/tmp/kubernetes-v1.36.2"))
head, status = Open3.capture2("git", "-C", source, "rev-parse", "HEAD")
abort "Kubernetes checkout differs from the generated artifact" unless status.success? && head.strip == artifact.fetch("commit")

fixtures = []
def probe(fixtures, schema, group, object, **options)
  fixtures << {"schema" => "io.k8s.api.#{schema}", "group" => group, "object" => object}.merge(options.transform_keys(&:to_s))
end

runtime = "node.v1.RuntimeClass"
probe(fixtures, runtime, "node.k8s.io", {})
probe(fixtures, runtime, "node.k8s.io", {"handler" => "Bad/Handler"})
probe(fixtures, runtime, "node.k8s.io", {"handler" => ""}, old: {"handler" => "runc"})
probe(fixtures, runtime, "node.k8s.io", {"handler" => "quoted/handler"}, old: {"handler" => "runc"})
probe(fixtures, runtime, "node.k8s.io", {"handler" => "Bad/Handler"}, old: {"handler" => "Bad/Handler"})

address = "networking.v1.IPAddress"
probe(fixtures, address, "networking.k8s.io", {})
probe(fixtures, address, "networking.k8s.io", {"spec" => {"parentRef" => {}}})
probe(fixtures, address, "networking.k8s.io", {"spec" => {"parentRef" => {"resource" => "services"}}},
      old: {"spec" => {"parentRef" => {"resource" => "services", "name" => "a"}}})
probe(fixtures, "storage.v1.StorageClass", "storage.k8s.io", {"parameters" => {"x" => "new"}, "provisioner" => ""},
      old: {"parameters" => {"x" => "old"}, "provisioner" => "test", "volumeBindingMode" => "Immediate"})
probe(fixtures, "discovery.v1.EndpointSlice", "discovery.k8s.io", {"addressType" => "IPv5", "endpoints" => []})
probe(fixtures, "networking.v1.IngressClass", "networking.k8s.io", {"spec" => {"parameters" => {}}})
probe(fixtures, "networking.v1.NetworkPolicy", "networking.k8s.io", {"spec" => {"egress" => [{"to" => [{"ipBlock" => {}}]}]}})
probe(fixtures, "batch.v1.CronJob", "batch", {"spec" => {}})
probe(fixtures, "rbac.v1.Role", "rbac.authorization.k8s.io", {"rules" => [{}]})
probe(fixtures, "rbac.v1.ClusterRole", "rbac.authorization.k8s.io", {"rules" => [{"verbs" => []}]})
probe(fixtures, "rbac.v1.RoleBinding", "rbac.authorization.k8s.io", {"subjects" => [{}], "roleRef" => {}})
probe(fixtures, "rbac.v1.ClusterRoleBinding", "rbac.authorization.k8s.io", {"subjects" => [{}], "roleRef" => {}})
probe(fixtures, "admissionregistration.v1.ValidatingAdmissionPolicyBinding", "admissionregistration.k8s.io", {"spec" => {}})
probe(fixtures, "storage.v1.VolumeAttachment", "storage.k8s.io", {"spec" => {"attacher" => "Bad/Driver"}})
probe(fixtures, "autoscaling.v1.Scale", "autoscaling", {"spec" => {"replicas" => -1}}, old: {"spec" => {"replicas" => 1}},
                                                                                       subresource: "scale")
probe(fixtures, "autoscaling.v1.HorizontalPodAutoscaler", "autoscaling", {"spec" => {"minReplicas" => 0, "maxReplicas" => -1}})
probe(fixtures, "autoscaling.v2.HorizontalPodAutoscaler", "autoscaling", {"spec" => {"minReplicas" => 0, "maxReplicas" => 0}},
      options: ["HPAScaleToZero"])
probe(fixtures, "core.v1.ReplicationController", "", {"metadata" => {"name" => "Bad/Name"},
                                                      "spec" => {"replicas" => -1, "minReadySeconds" => -2}})
probe(fixtures, "core.v1.ReplicationController", "", {"metadata" => {"name" => "Bad/Name", "labels" => {"new" => "label"}}},
      old: {"metadata" => {"name" => "Bad/Name"}})

pool = "resource.v1alpha3.ResourcePoolStatusRequest"
probe(fixtures, pool, "resource.k8s.io", {"spec" => {"driver" => "GPU.Example.COM", "poolName" => "node//pool", "limit" => 1020}})
probe(fixtures, pool, "resource.k8s.io", {"spec" => {"driver" => "GPU.Example.COM", "limit" => 100},
                                          "status" => {"poolCount" => -1, "pools" => [{"driver" => "GPU.Example.COM", "poolName" => "node/pool",
                                                                                       "generation" => 0, "totalDevices" => -2}]}},
      old: {"spec" => {"driver" => "GPU.Example.COM", "limit" => 100}}, subresource: "status")
dra_group = "resource.k8s.io"
%w[v1 v1beta1 v1beta2].each do |version|
  device_class = "resource.#{version}.DeviceClass"
  probe(fixtures, device_class, dra_group, {"spec" => {"extendedResourceName" => "requests.kubernetes.io/!", "config" => [{"opaque" => {}}]}})
  probe(fixtures, device_class, dra_group, {"spec" => {"extendedResourceName" => "example.com/gpu"}})
  probe(fixtures, device_class, dra_group, {"spec" => {"extendedResourceName" => "example.com/#{"é" * 32}"}})

  claim = "resource.#{version}.ResourceClaim"
  constraints = %w[bad-name /name bad.example/! other.example/a/b].map { |name| {"matchAttribute" => name} }
  constraints << {"matchAttribute" => "#{"a" * 64}/#{"x" * 33}"}
  probe(fixtures, claim, dra_group, {"spec" => {"devices" => {"constraints" => constraints, "config" => [{"opaque" => {}}]}}})
  allocation = {"devices" => {"results" => [{"driver" => "example.com", "pool" => "pool", "device" => "d", "shareID" => "invalid-id"}]}}
  allocated = {"driver" => "example.com", "pool" => "pool", "device" => "d", "shareID" => "invalid-id"}
  probe(fixtures, claim, dra_group, {"status" => {"allocation" => allocation, "devices" => [allocated, allocated]}}, old: {}, subresource: "status")
  probe(fixtures, claim, dra_group, {"status" => {"allocation" => allocation, "devices" => [allocated]}},
        old: {"status" => {"allocation" => {}, "devices" => [allocated]}}, subresource: "status")
  probe(fixtures, claim, dra_group, {"status" => {"devices" => [allocated.merge("shareID" => nil), allocated.merge("shareID" => "")]}},
        old: {"status" => {"allocation" => allocation}}, subresource: "status")
  exact = {"deviceClassName" => "gpu", "allocationMode" => "Unknown", "tolerations" => [{"key" => "bad key", "operator" => "Maybe"}]}
  request = {"name" => "request"}.merge(version == "v1beta1" ? exact : {"exactly" => exact})
  claim_object = {"spec" => {"devices" => {"requests" => [request, request]}}}
  probe(fixtures, claim, dra_group, claim_object)
  probe(fixtures, claim, dra_group, claim_object, old: {"spec" => {"devices" => {"requests" => [request]}}})

  slice = "resource.#{version}.ResourceSlice"
  attributes = {"attributes" => {"example.com/property" => {}}}
  device = {"name" => "device"}.merge(version == "v1beta1" ? {"basic" => attributes} : attributes)
  probe(fixtures, slice, dra_group, {"spec" => {"driver" => "example.com", "pool" => {"name" => "pool", "resourceSliceCount" => 1},
                                                "devices" => [device],
                                                "sharedCounters" => [{"name" => "counters", "counters" => {"Bad/Key" => {"value" => "1"}}}]}})
  advanced = {"taints" => [{"effect" => ""}], "consumesCounters" => [{"counterSet" => "", "counters" => {}}]}
  advanced_device = {"name" => "device"}.merge(version == "v1beta1" ? {"basic" => advanced} : advanced)
  previous_device = {"name" => "device"}.merge(version == "v1beta1" ? {"basic" => advanced.except("consumesCounters")} : advanced.except("consumesCounters"))
  probe(fixtures, slice, dra_group, {"spec" => {"devices" => [advanced_device]}}, old: {"spec" => {"devices" => [previous_device]}})
end

csr = "certificates.v1.CertificateSigningRequest"
csr_group = "certificates.k8s.io"
approved = {"type" => "Approved", "status" => "True"}
denied = {"type" => "Denied", "status" => "True"}
conflicting = {"status" => {"conditions" => [approved, denied]}}
probe(fixtures, csr, csr_group, conflicting)
probe(fixtures, csr, csr_group, conflicting, old: {"status" => {"conditions" => [approved]}}, subresource: "approval")
probe(fixtures, csr, csr_group, conflicting, old: {"status" => {"conditions" => [denied, approved]}}, subresource: "status")

priority = "flowcontrol.v1.PriorityLevelConfiguration"
flow_group = "flowcontrol.apiserver.k8s.io"
limited = {"type" => "Limited", "limited" => {"limitResponse" => {"type" => "Queue"}}}
probe(fixtures, priority, flow_group, {"spec" => limited.merge("exempt" => {})})
probe(fixtures, priority, flow_group, {"spec" => {"type" => "Exempt", "limited" => {}}})
probe(fixtures, priority, flow_group, {"spec" => {"type" => "Unknown", "limited" => {}, "exempt" => {}}})
probe(fixtures, priority, flow_group, {"spec" => limited}, old: {"spec" => limited.merge("exempt" => {})})
probe(fixtures, priority, flow_group, {"spec" => limited.merge("exempt" => {})}, old: {"spec" => limited})
probe(fixtures, priority, flow_group, {"spec" => {"type" => "Limited", "limited" => {}}}, old: {"spec" => {"type" => "Limited"}})
fixtures.each do |fixture|
  schema = fixture.fetch("schema")
  next unless [Rubernetes::Schema::DeclarativeValidation::CSR, Rubernetes::Schema::DeclarativeValidation::PRIORITY_LEVEL,
               *Rubernetes::Schema::DeclarativeValidation::RESOURCE_SCHEMAS].include?(schema)

  fixture["compare"] = true
  [fixture["object"], fixture["old"]].compact.each { |object| object["apiVersion"] = "#{fixture.fetch("group")}/#{schema.split(".")[-2]}" }
end

workload = "scheduling.v1alpha2.Workload"
pod_group = "scheduling.v1alpha2.PodGroup"
test_group = "scheduling.k8s.io"
template = {"name" => "group", "schedulingPolicy" => {"basic" => {}}}
probe(fixtures, workload, test_group, {"spec" => {"podGroupTemplates" => [template, template]}})
probe(fixtures, workload, test_group, {"spec" => {"podGroupTemplates" => [template.merge("schedulingPolicy" => {"gang" => {"minCount" => -1}})]}})
probe(fixtures, workload, test_group, {"spec" => {"podGroupTemplates" => [template.merge("schedulingPolicy" => {})]}})
probe(fixtures, workload, test_group, {"spec" => {"podGroupTemplates" => [template.merge("schedulingConstraints" => {"topology" => [{"key" => "bad key"}]})]}},
      options: ["TopologyAwareWorkloadScheduling"])
probe(fixtures, pod_group, test_group, {"spec" => {"schedulingPolicy" => {"basic" => {}}, "disruptionMode" => "Invalid", "priority" => 1_000_000_001}},
      options: ["WorkloadAwarePreemption"])
probe(fixtures, pod_group, test_group, {"spec" => {"schedulingPolicy" => {"basic" => {}}, "disruptionMode" => "Pod"}})
probe(fixtures, pod_group, test_group, {"spec" => {"schedulingPolicy" => {"basic" => {}}}},
      old: {"spec" => {"schedulingPolicy" => {"gang" => {"minCount" => 1}}}})

runner = File.expand_path("../../test/conformance/kubernetes/declarative_validation/oracle.go", __dir__)
output, error, status = Open3.capture3("go", "run", runner, chdir: source, stdin_data: JSON.generate(fixtures))
abort error unless status.success?

upstream = JSON.parse(output)
reasons = {required: "FieldValueRequired", forbidden: "FieldValueForbidden", invalid: "FieldValueInvalid",
           unsupported: "FieldValueNotSupported", duplicate: "FieldValueDuplicate", too_many: "FieldValueTooMany",
           too_long: "FieldValueTooLong"}.freeze
failures = fixtures.each_with_index.filter_map do |fixture, index|
  old = fixture["old"]
  schema, object, options = fixture.values_at("schema", "object", "options")
  operation = old ? :update : :create
  actual = rules.new(operation: operation, options: options || []).evaluate(schema, object, old).map do |finding|
    {"reason" => reasons.fetch(finding.issue.code), "field" => finding.issue.kubernetes_field,
     "origin" => finding.origin.to_s, "stage" => finding.stage.to_s}
  end
  result = {"findings" => actual}
  if fixture["compare"]
    result["mismatches"] = Rubernetes::Schema::DeclarativeValidation.mismatches(schema, object, old, operation,
                                                                                subresource: fixture["subresource"])
  end
  next if result == upstream[index]

  {fixture: fixture, upstream: upstream[index], actual: result}
end
abort JSON.pretty_generate(failures) unless failures.empty?
puts "#{fixtures.length} declarative fixtures and #{fixtures.count { |fixture| fixture["compare"] }} migration comparisons matched Kubernetes v1.36.2"
