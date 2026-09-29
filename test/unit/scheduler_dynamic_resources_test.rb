# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/scheduler"

# The scheduler's DynamicResources plugin (pkg/scheduler/framework/plugins/
# dynamicresources, v1.36.2) end to end through the Framework: claims are
# allocated by the structured allocator in Filter, held in flight from
# Reserve, and written to the API in PreBind (finalizer, allocation,
# reservedFor); a claim another Pod already uses keeps a second Pod off.
class SchedulerDynamicResourcesTest < Minitest::Test
  Scheduler = Rubernetes::Scheduler
  DRIVER = "gpu.example.com"

  class API
    attr_reader :claims, :calls

    def initialize(claims)
      @claims = claims.to_h { |claim| [[claim.dig("metadata", "namespace"), claim.dig("metadata", "name")], Marshal.load(Marshal.dump(claim))] }
      @calls = []
      @rv = 100
    end

    def get_claim(namespace, name) = Marshal.load(Marshal.dump(@claims.fetch([namespace, name])))

    def update_claim(claim)
      @calls << [:update, claim.dig("metadata", "name")]
      store(claim)
    end

    def update_claim_status(claim)
      @calls << [:update_status, claim.dig("metadata", "name")]
      store(claim)
    end

    def patch_claim_status(namespace, name, patch)
      @calls << [:patch_status, name, patch]
      claim = @claims.fetch([namespace, name])
      uid = patch.dig("status", "reservedFor", 0, "uid")
      claim["status"]["reservedFor"] = Array(claim.dig("status", "reservedFor")).reject { |entry| entry["uid"] == uid }
      claim
    end

    def create_claim(claim)
      @calls << [:create, claim.dig("metadata", "generateName")]
      created = Marshal.load(Marshal.dump(claim))
      created["metadata"]["name"] = "#{claim.dig("metadata", "generateName")}abcde"
      created["metadata"]["uid"] = "uid-created"
      created["status"] ||= {}
      store(created)
    end

    def delete_claim(namespace, name)
      @calls << [:delete, name]
      @claims.delete([namespace, name])
    end

    attr_reader :pod_statuses

    def patch_pod_status(namespace, name, status)
      (@pod_statuses ||= []) << [namespace, name, status]
      @calls << [:patch_pod_status, name]
    end

    private

    def store(claim)
      copy = Marshal.load(Marshal.dump(claim))
      copy["metadata"]["resourceVersion"] = (@rv += 1).to_s
      @claims[[copy.dig("metadata", "namespace"), copy.dig("metadata", "name")]] = copy
      Marshal.load(Marshal.dump(copy))
    end
  end

  def node(name) = {"metadata" => {"name" => name, "labels" => {"kubernetes.io/hostname" => name}},
                    "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                                 "conditions" => [{"type" => "Ready", "status" => "True"}]}}

  def slice(node_name, devices)
    {"metadata" => {"name" => "#{node_name}-gpus"},
     "spec" => {"driver" => DRIVER, "nodeName" => node_name, "pool" => {"name" => node_name, "generation" => 1, "resourceSliceCount" => 1},
                "devices" => devices.map { |name| {"name" => name} }}}
  end

  def device_class = {"metadata" => {"name" => "gpu"}, "spec" => {"selectors" => [{"cel" => {"expression" => "device.driver == \"#{DRIVER}\""}}]}}

  def claim(name, count: 1, uid: "claim-#{name}")
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim",
     "metadata" => {"name" => name, "namespace" => "ns", "uid" => uid, "resourceVersion" => "1"},
     "spec" => {"devices" => {"requests" => [{"name" => "gpu", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "ExactCount",
                                                                               "count" => count}}]}},
     "status" => {}}
  end

  def pod(name, claims: [], template: nil, status: {})
    resource_claims = claims.map { |claim_name| {"name" => claim_name, "resourceClaimName" => claim_name} }
    resource_claims << {"name" => "t", "resourceClaimTemplateName" => template} if template
    {"metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}", "creationTimestamp" => "2026-01-01T00:00:00Z"},
     "spec" => {"containers" => [{"name" => "c", "image" => "x"}], "resourceClaims" => resource_claims},
     "status" => status}
  end

  def framework(api)
    Scheduler::Framework.new(dynamic_resources: Scheduler::DynamicResources.new(api: api), random: Random.new(1))
  end

  def volume_data(api, slices)
    {"resourceClaims" => api.claims.values, "resourceSlices" => slices, "deviceClasses" => [device_class]}
  end

  def test_pod_is_placed_where_devices_exist_and_claim_is_written
    api = API.new([claim("c1")])
    subject = framework(api)
    result = subject.schedule(pod("p1", claims: ["c1"]), [node("n1"), node("n2")],
                              volume_data: volume_data(api, [slice("n2", %w[gpu-0])]))
    assert result.scheduled?, result.reason
    assert_equal "n2", result.node.name
    stored = api.claims.fetch(%w[ns c1])
    assert_includes stored.dig("metadata", "finalizers"), "resource.kubernetes.io/delete-protection"
    assert_equal [{"request" => "gpu", "driver" => DRIVER, "pool" => "n2", "device" => "gpu-0"}],
                 stored.dig("status", "allocation", "devices", "results")
    assert_equal [{"resource" => "pods", "name" => "p1", "uid" => "uid-p1"}], stored.dig("status", "reservedFor")
    refute_nil stored.dig("status", "allocation", "allocationTimestamp")
    assert_equal [[:update, "c1"], [:update_status, "c1"]], api.calls
    assert_nil subject.dynamic_resources.pending_allocation("claim-c1"), "in-flight state is cleared after PreBind"
  end

  def test_devices_taken_by_a_bound_claim_are_not_allocated_again
    api = API.new([claim("c1"), claim("c2")])
    subject = framework(api)
    slices = [slice("n1", %w[gpu-0])]
    assert subject.schedule(pod("p1", claims: ["c1"]), [node("n1")], volume_data: volume_data(api, slices)).scheduled?
    # The informer has not seen the update yet: the assume cache has.
    stale = {"resourceClaims" => [claim("c1"), claim("c2")], "resourceSlices" => slices, "deviceClasses" => [device_class]}
    second = subject.schedule(pod("p2", claims: ["c2"]), [node("n1")], volume_data: stale)
    refute second.scheduled?
    assert_equal "cannot allocate all claims", second.filtered.dig("n1", "reason")
  end

  def test_an_allocated_claim_restricts_the_pod_to_its_node
    allocated = claim("shared")
    allocated["status"] = {"allocation" => {"devices" => {"results" => [{"request" => "gpu", "driver" => DRIVER, "pool" => "n1", "device" => "gpu-0"}]},
                                            "nodeSelector" => {"nodeSelectorTerms" => [{"matchFields" => [{"key" => "metadata.name", "operator" => "In",
                                                                                                           "values" => ["n1"]}]}]}},
                           "reservedFor" => [{"resource" => "pods", "name" => "other", "uid" => "uid-other"}]}
    api = API.new([allocated])
    result = framework(api).schedule(pod("p2", claims: ["shared"]), [node("n1"), node("n2")], volume_data: volume_data(api, [slice("n1", %w[gpu-0])]))
    assert result.scheduled?
    assert_equal "n1", result.node.name
    assert_equal "resourceclaim not available on the node", result.filtered.dig("n2", "reason")
    assert_equal [{"resource" => "pods", "name" => "other", "uid" => "uid-other"}, {"resource" => "pods", "name" => "p2", "uid" => "uid-p2"}],
                 api.claims.fetch(%w[ns shared]).dig("status", "reservedFor"), "a shared claim gains a second consumer"
    assert_equal [[:update_status, "shared"]], api.calls
  end

  def test_pre_enqueue_waits_for_template_claims_and_checks_ownership
    api = API.new([])
    subject = framework(api)
    waiting = subject.schedule(pod("p1", template: "tmpl"), [node("n1")], volume_data: volume_data(api, []))
    refute waiting.scheduled?
    assert_equal "pod \"ns/p1\": ResourceClaim not created yet", waiting.reason

    foreign = claim("p1-t-abcde")
    foreign["metadata"]["ownerReferences"] = [{"apiVersion" => "v1", "kind" => "Pod", "name" => "someone", "uid" => "uid-someone", "controller" => true}]
    api = API.new([foreign])
    result = framework(api).schedule(pod("p1", template: "tmpl", status: {"resourceClaimStatuses" => [{"name" => "t", "resourceClaimName" => "p1-t-abcde"}]}),
                                     [node("n1")], volume_data: volume_data(api, [slice("n1", %w[gpu-0])]))
    assert_equal "ResourceClaim ns/p1-t-abcde was not created for Pod ns/p1 (Pod is not owner)", result.reason
  end

  def test_missing_class_and_missing_claim_are_unschedulable
    api = API.new([claim("c1")])
    result = framework(api).schedule(pod("p1", claims: ["c1"]), [node("n1")],
                                     volume_data: {"resourceClaims" => api.claims.values, "resourceSlices" => [], "deviceClasses" => []})
    assert_equal "request gpu: device class gpu does not exist", result.reason
    missing = framework(API.new([])).schedule(pod("p1", claims: ["nope"]), [node("n1")], volume_data: {})
    assert_equal "resourceclaim.resource.k8s.io \"nope\" not found", missing.reason
  end

  def test_pods_without_claims_are_untouched
    api = API.new([])
    result = framework(api).schedule(pod("plain"), [node("n1")], volume_data: {})
    assert result.scheduled?
    assert_empty api.calls
    assert_equal 0, result.scores.first.plugins.find { |entry| entry["plugin"] == "DynamicResources" }&.fetch("score").to_i
  end

  def extended_class = {"metadata" => {"name" => "gpu", "creationTimestamp" => "2026-01-01T00:00:00Z"},
                         "spec" => {"extendedResourceName" => "example.com/gpu",
                                    "selectors" => [{"cel" => {"expression" => "device.driver == \"#{DRIVER}\""}}]}}

  def gpu_pod(name, amount: "1")
    {"metadata" => {"name" => name, "namespace" => "ns", "uid" => "uid-#{name}", "creationTimestamp" => "2026-01-01T00:00:00Z"},
     "spec" => {"containers" => [{"name" => "c", "image" => "x", "resources" => {"requests" => {"example.com/gpu" => amount},
                                                                              "limits" => {"example.com/gpu" => amount}}}]},
     "status" => {}}
  end

  # DRAExtendedResource: an extended resource no node advertises, provided
  # by a DeviceClass, is allocated through a claim the scheduler creates.
  def test_an_extended_resource_backed_by_a_device_class_is_allocated
    api = API.new([])
    result = framework(api).schedule(gpu_pod("p1"), [node("n1"), node("n2")],
                                     volume_data: {"resourceClaims" => [], "resourceSlices" => [slice("n2", %w[gpu-0])],
                                                   "deviceClasses" => [extended_class]})
    assert result.scheduled?, result.reason
    assert_equal "n2", result.node.name
    assert_equal [[:create, "p1-extended-resources-"], [:update, "p1-extended-resources-abcde"],
                  [:update_status, "p1-extended-resources-abcde"], [:patch_pod_status, "p1"]], api.calls
    created = api.claims.fetch(%w[ns p1-extended-resources-abcde])
    assert_equal "true", created.dig("metadata", "annotations", "resource.kubernetes.io/extended-resource-claim")
    assert_equal [{"name" => "container-0-request-0", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 1}}],
                 created.dig("spec", "devices", "requests")
    assert_equal [{"request" => "container-0-request-0", "driver" => DRIVER, "pool" => "n2", "device" => "gpu-0"}],
                 created.dig("status", "allocation", "devices", "results")
    assert_equal [{"resource" => "pods", "name" => "p1", "uid" => "uid-p1"}], created.dig("status", "reservedFor")
    _, _, status = api.pod_statuses.fetch(0)
    assert_equal({"extendedResourceClaimStatus" => {"resourceClaimName" => "p1-extended-resources-abcde",
                                                    "requestMappings" => [{"containerName" => "c", "resourceName" => "example.com/gpu",
                                                                           "requestName" => "container-0-request-0"}]}}, status)
  end

  def test_a_node_advertising_the_extended_resource_needs_no_claim
    api = API.new([])
    advertising = node("n1")
    advertising["status"]["allocatable"]["example.com/gpu"] = "2"
    result = framework(api).schedule(gpu_pod("p1"), [advertising],
                                     volume_data: {"resourceClaims" => [], "resourceSlices" => [], "deviceClasses" => [extended_class]})
    assert result.scheduled?, result.reason
    assert_empty api.calls
  end

  def test_an_extended_resource_nobody_provides_does_not_fit
    api = API.new([])
    result = framework(api).schedule(gpu_pod("p1"), [node("n1")], volume_data: {"resourceClaims" => [], "resourceSlices" => [], "deviceClasses" => []})
    refute result.scheduled?
    assert_equal "node has insufficient resources", result.filtered.dig("n1", "reason")
  end

  def test_first_available_choices_score_higher
    api = API.new([{"metadata" => {"name" => "pref", "namespace" => "ns", "uid" => "u-pref", "resourceVersion" => "1"},
                    "spec" => {"devices" => {"requests" => [{"name" => "r", "firstAvailable" => [
                      {"name" => "big", "deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 2},
                      {"name" => "small", "deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 1}
                    ]}]}}, "status" => {}}])
    result = framework(api).schedule(pod("p", claims: ["pref"]), [node("n1"), node("n2")],
                                     volume_data: volume_data(api, [slice("n1", %w[a]), slice("n2", %w[a b])]))
    assert_equal "n2", result.node.name, "the node that can satisfy the first choice wins"
    scores = result.scores.to_h { |breakdown| [breakdown.node.name, breakdown.plugins.find { |entry| entry["plugin"] == "DynamicResources" }["score"]] }
    assert_equal({"n1" => 87, "n2" => 100}, scores, "raw 7 and 8, DefaultNormalizeScore: 100*7/8 truncated")
  end
end
