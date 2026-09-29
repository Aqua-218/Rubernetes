# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

# pkg/apis/resource/{v1,v1beta2,v1beta1}/defaults.go: an exact request (and a
# subrequest) defaults to ExactCount with count 1, a taint gets its timeAdded,
# a node-allocatable mapping its multiplier -- in a claim, a claim template
# and a slice alike.
class ResourceAPIDefaultingTest < Minitest::Test
  def defaulted(name, object)
    Rubernetes::Generated.definition_for(name).defaulting.apply_hash(object, kubernetes_admission_defaults: true)
  end

  def test_v1_claim_requests_default_to_exact_count_one
    claim = defaulted("io.k8s.api.resource.v1.ResourceClaim",
                      "metadata" => {"name" => "c", "namespace" => "ns"},
                      "spec" => {"devices" => {"requests" => [
                        {"name" => "a", "exactly" => {"deviceClassName" => "gpu"}},
                        {"name" => "b", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "All"}},
                        {"name" => "c", "firstAvailable" => [{"name" => "s", "deviceClassName" => "gpu"}]}
                      ]}})
    requests = claim.dig("spec", "devices", "requests")
    assert_equal({"deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 1}, requests[0]["exactly"])
    assert_equal({"deviceClassName" => "gpu", "allocationMode" => "All"}, requests[1]["exactly"])
    assert_equal "ExactCount", requests[2].dig("firstAvailable", 0, "allocationMode")
    assert_equal 1, requests[2].dig("firstAvailable", 0, "count")
  end

  def test_the_template_spec_is_defaulted_too
    template = defaulted("io.k8s.api.resource.v1.ResourceClaimTemplate",
                         "metadata" => {"name" => "t", "namespace" => "ns"},
                         "spec" => {"spec" => {"devices" => {"requests" => [{"name" => "a", "exactly" => {"deviceClassName" => "gpu", "count" => 3}}]}}})
    assert_equal({"deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 3},
                 template.dig("spec", "spec", "devices", "requests", 0, "exactly"))
  end

  def test_v1beta1_flat_requests_are_defaulted_only_with_a_class
    claim = defaulted("io.k8s.api.resource.v1beta1.ResourceClaim",
                      "metadata" => {"name" => "c", "namespace" => "ns"},
                      "spec" => {"devices" => {"requests" => [
                        {"name" => "a", "deviceClassName" => "gpu"},
                        {"name" => "b", "firstAvailable" => [{"name" => "s", "deviceClassName" => "gpu"}]}
                      ]}})
    requests = claim.dig("spec", "devices", "requests")
    assert_equal "ExactCount", requests[0]["allocationMode"]
    assert_equal 1, requests[0]["count"]
    refute requests[1].key?("allocationMode")
    assert_equal "ExactCount", requests[1].dig("firstAvailable", 0, "allocationMode")
  end

  def test_slice_taints_get_a_time_added
    slice = defaulted("io.k8s.api.resource.v1.ResourceSlice",
                      "metadata" => {"name" => "s"},
                      "spec" => {"driver" => "d", "pool" => {"name" => "p", "generation" => 1, "resourceSliceCount" => 1}, "nodeName" => "n",
                                 "devices" => [{"name" => "d0", "taints" => [{"key" => "k", "effect" => "NoSchedule"},
                                                                            {"key" => "k2", "effect" => "NoSchedule", "timeAdded" => "2026-01-01T00:00:00Z"}]}]})
    taints = slice.dig("spec", "devices", 0, "taints")
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\z/, taints[0]["timeAdded"])
    assert_equal "2026-01-01T00:00:00Z", taints[1]["timeAdded"]
  end
end
