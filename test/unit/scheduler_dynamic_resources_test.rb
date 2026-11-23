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
    attr_reader :claims, :calls, :pod_statuses

    def initialize(claims)
      @claims = claims.to_h do |claim|
        [[claim.dig("metadata", "namespace"), claim.dig("metadata", "name")], Marshal.load(Marshal.dump(claim))]
      end
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

  def node(name)
    {"metadata" => {"name" => name, "labels" => {"kubernetes.io/hostname" => name}},
     "status" => {"allocatable" => {"cpu" => "4", "memory" => "8Gi", "pods" => "110"},
                  "conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def slice(node_name, devices)
    {"metadata" => {"name" => "#{node_name}-gpus"},
     "spec" => {"driver" => DRIVER, "nodeName" => node_name, "pool" => {"name" => node_name, "generation" => 1, "resourceSliceCount" => 1},
                "devices" => devices.map { |name| {"name" => name} }}}
  end

  def device_class
    {"metadata" => {"name" => "gpu"}, "spec" => {"selectors" => [{"cel" => {"expression" => "device.driver == \"#{DRIVER}\""}}]}}
  end

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

  def test_cel_runtime_error_preserves_queued_pod_for_retry_without_allocating
    selected = claim("c1")
    selected.dig("spec", "devices", "requests", 0, "exactly")["selectors"] = [
      {"cel" => {"expression" => "device.attributes['#{DRIVER}'].exists"}}
    ]
    slices = [slice("n1", ["gpu-0"]), slice("n2", ["gpu-1"])]
    slices.first.dig("spec", "devices", 0)["attributes"] = {"exists" => {"bool" => true}}
    api = API.new([selected])
    subject = framework(api)
    subject.enqueue(pod("p1", claims: ["c1"]))

    result = subject.schedule_next(nodes: [node("n1"), node("n2")], volume_data: volume_data(api, slices))

    assert_predicate result, :requeued?
    assert_equal "p1", result.pod.name
    assert_instance_of Scheduler::FilterError, result.error
    assert_includes result.error.message, "CEL runtime error: no such key: exists"
    assert_equal 1, subject.queue.backoff_size
    assert_empty api.calls
  end

  def test_list_attributes_use_cel_and_intersection_when_the_scheduler_gate_is_enabled
    gpu_claim = claim("c1", count: 2)
    devices = gpu_claim.fetch("spec").fetch("devices")
    devices["constraints"] = [{"matchAttribute" => "#{DRIVER}/zones"}]
    devices["requests"].first.fetch("exactly")["selectors"] = [
      {"cel" => {"expression" => "device.attributes['#{DRIVER}'].zones.includes('blue')"}}
    ]
    gpu_slice = slice("n1", %w[gpu-0 gpu-1 gpu-2])
    gpu_slice.dig("spec", "devices").zip([
                                           {"strings" => %w[red blue]}, {"strings" => %w[red]}, {"string" => "blue"}
                                         ]).each { |device, attribute| device["attributes"] = {"zones" => attribute} }

    [false, true].each do |enabled|
      api = API.new([gpu_claim])
      subject = Scheduler::Framework.new(feature_gates: {"DRAListTypeAttributes" => enabled})
      subject.dynamic_resources.api = api
      schedule = lambda do
        subject.schedule(pod("p1", claims: ["c1"]), [node("n1")], volume_data: volume_data(api, [gpu_slice]))
      end

      if enabled
        result = schedule.call

        assert_predicate result, :scheduled?, result.inspect
        devices = api.get_claim("ns", "c1").dig("status", "allocation", "devices", "results")

        assert_equal(%w[gpu-0 gpu-2], devices.map { |device| device.fetch("device") })
      else
        error = assert_raises(Scheduler::PluginError, &schedule)
        assert_includes error.message, "unsupported attribute value"
        assert_empty api.calls
      end
    end
  end

  def test_node_allocatable_claims_fit_and_account_for_the_footprint_of_bound_pods
    gpu_slice = slice("n1", %w[gpu-0])
    gpu_slice.dig("spec", "devices").first["nodeAllocatableResourceMappings"] = {"cpu" => {"allocationMultiplier" => "3"}}
    first = pod("p1", claims: ["c1"])
    first.dig("spec", "containers").first["resources"] = {"claims" => [{"name" => "c1"}], "requests" => {"cpu" => "500m"}}
    statuses = [{"resourceClaimName" => "c1", "containers" => ["c"], "resources" => {"cpu" => "3"}}]

    [false, true].each do |enabled|
      api = API.new([claim("c1")])
      subject = Scheduler::Framework.new(feature_gates: {"DRANodeAllocatableResources" => enabled})
      subject.dynamic_resources.api = api
      undersized = node("n1")
      undersized["status"]["allocatable"]["cpu"] = "3"
      result = subject.schedule(first, [undersized], volume_data: volume_data(api, [gpu_slice]))

      assert_equal !enabled, result.scheduled?, result.inspect
      next unless enabled

      result = subject.schedule(first, [node("n1")], volume_data: volume_data(api, [gpu_slice]))

      assert_predicate result, :scheduled?, result.inspect
      assert_equal [["ns", "p1", {"nodeAllocatableResourceClaimStatuses" => statuses}]], api.pod_statuses
      assert_equal statuses, result.pod.dig("status", "nodeAllocatableResourceClaimStatuses")

      second = pod("p2")
      second.dig("spec", "containers").first["resources"] = {"requests" => {"cpu" => "1"}}
      result = subject.schedule(second, [node("n1"), node("n2")], pods: [result.pod])

      assert_predicate result, :scheduled?, result.inspect
      assert_equal "n2", result.node.name
    end
  end

  def test_gang_members_share_a_pod_group_owned_claim_when_enabled
    group = {"metadata" => {"namespace" => "ns", "name" => "batch", "uid" => "batch-uid"},
             "spec" => {"schedulingPolicy" => {"gang" => {"minCount" => 2}},
                        "resourceClaims" => [{"name" => "t", "resourceClaimTemplateName" => "template"}]}}
    shared = claim("claim-batch")
    shared["metadata"]["ownerReferences"] = [{"apiVersion" => "scheduling.k8s.io/v1alpha2", "kind" => "PodGroup",
                                              "name" => "batch", "uid" => "batch-uid", "controller" => true}]
    members = %w[p1 p2].map do |name|
      pod(name, template: "template", status: {"resourceClaimStatuses" => [{"name" => "t", "resourceClaimName" => "claim-batch"}]}).tap do |object|
        object["spec"]["schedulingGroup"] = {"podGroupName" => "batch"}
      end
    end

    [false, true].each do |enabled|
      api = API.new([shared])
      bound = []
      binder = lambda do |object, _node|
        bound << object.name
        true
      end
      subject = Scheduler::Framework.new(bind: binder,
                                         feature_gates: {"GenericWorkload" => true, "GangScheduling" => true,
                                                         "DRAWorkloadResourceClaims" => enabled})
      subject.dynamic_resources.api = api
      members.each { |member| subject.enqueue(member) }
      result = subject.schedule_next(nodes: [node("n1")], pods: members, pod_groups: {"ns/batch" => group},
                                     volume_data: volume_data(api, [slice("n1", %w[gpu-0])]))

      assert_equal enabled, result.scheduled?, result.inspect
      assert_equal(enabled ? %w[p1 p2] : [], bound.sort)
      if enabled
        ref = {"apiGroup" => "scheduling.k8s.io", "resource" => "podgroups", "name" => "batch", "uid" => "batch-uid"}

        assert_equal [ref], api.get_claim("ns", "claim-batch").dig("status", "reservedFor")
        assert_equal(1, api.calls.count { |op, _| op == :update_status })
      else
        assert_empty api.calls
      end
    end
  end

  def test_pod_is_placed_where_devices_exist_and_claim_is_written
    api = API.new([claim("c1")])
    subject = framework(api)
    result = subject.schedule(pod("p1", claims: ["c1"]), [node("n1"), node("n2")],
                              volume_data: volume_data(api, [slice("n2", %w[gpu-0])]))

    assert_predicate result, :scheduled?, result.reason
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

    assert_predicate subject.schedule(pod("p1", claims: ["c1"]), [node("n1")], volume_data: volume_data(api, slices)), :scheduled?
    # The informer has not seen the update yet: the assume cache has.
    stale = {"resourceClaims" => [claim("c1"), claim("c2")], "resourceSlices" => slices, "deviceClasses" => [device_class]}
    second = subject.schedule(pod("p2", claims: ["c2"]), [node("n1")], volume_data: stale)

    refute_predicate second, :scheduled?
    assert_equal "cannot allocate all claims", second.filtered.dig("n1", "reason")
  end

  def test_an_allocated_claim_restricts_the_pod_to_its_node
    allocated = claim("shared")
    allocated["status"] = {"allocation" => {"devices" => {"results" => [{"request" => "gpu", "driver" => DRIVER, "pool" => "n1", "device" => "gpu-0"}]},
                                            "nodeSelector" => {"nodeSelectorTerms" => [{"matchFields" => [{"key" => "metadata.name", "operator" => "In",
                                                                                                           "values" => ["n1"]}]}]}},
                           "reservedFor" => [{"resource" => "pods", "name" => "other", "uid" => "uid-other"}]}
    api = API.new([allocated])
    result = framework(api).schedule(pod("p2", claims: ["shared"]), [node("n1"), node("n2")],
                                     volume_data: volume_data(api, [slice("n1", %w[gpu-0])]))

    assert_predicate result, :scheduled?
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

    refute_predicate waiting, :scheduled?
    assert_equal "pod \"ns/p1\": ResourceClaim not created yet", waiting.reason

    foreign = claim("p1-t-abcde")
    foreign["metadata"]["ownerReferences"] =
      [{"apiVersion" => "v1", "kind" => "Pod", "name" => "someone", "uid" => "uid-someone", "controller" => true}]
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

    assert_predicate result, :scheduled?
    assert_empty api.calls
    assert_equal 0, result.scores.first.plugins.find { |entry| entry["plugin"] == "DynamicResources" }&.fetch("score").to_i
  end

  def extended_class
    {"metadata" => {"name" => "gpu", "creationTimestamp" => "2026-01-01T00:00:00Z"},
     "spec" => {"extendedResourceName" => "example.com/gpu",
                "selectors" => [{"cel" => {"expression" => "device.driver == \"#{DRIVER}\""}}]}}
  end

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

    assert_predicate result, :scheduled?, result.reason
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

    assert_predicate result, :scheduled?, result.reason
    assert_empty api.calls
  end

  def test_an_extended_resource_nobody_provides_does_not_fit
    api = API.new([])
    result = framework(api).schedule(gpu_pod("p1"), [node("n1")],
                                     volume_data: {"resourceClaims" => [], "resourceSlices" => [], "deviceClasses" => []})

    refute_predicate result, :scheduled?
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
    scores = result.scores.to_h do |breakdown|
      [breakdown.node.name, breakdown.plugins.find do |entry|
        entry["plugin"] == "DynamicResources"
      end["score"]]
    end

    assert_equal({"n1" => 87, "n2" => 100}, scores, "raw 7 and 8, DefaultNormalizeScore: 100*7/8 truncated")
  end
end
