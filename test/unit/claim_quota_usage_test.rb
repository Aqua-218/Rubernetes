# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes"

# ResourceQuota for DRA (quota/v1/evaluator/core/resource_claims.go):
# count/resourceclaims.resource.k8s.io and <class>.deviceclass.resource.k8s.io/devices.
class ClaimQuotaUsageTest < Minitest::Test
  Usage = Rubernetes::ClaimQuotaUsage

  def claim(requests)
    {"kind" => "ResourceClaim", "metadata" => {"name" => "c", "namespace" => "ns"},
     "spec" => {"devices" => {"requests" => requests}}}
  end

  def test_devices_per_class
    usage = Usage.usage(claim([
                                {"name" => "a", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 2}},
                                {"name" => "b", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "All"}},
                                {"name" => "c", "firstAvailable" => [
                                  {"name" => "big", "deviceClassName" => "nic", "allocationMode" => "ExactCount", "count" => 4},
                                  {"name" => "small", "deviceClassName" => "nic", "allocationMode" => "ExactCount", "count" => 1},
                                  {"name" => "other", "deviceClassName" => "fpga", "allocationMode" => "ExactCount", "count" => 1}
                                ]}
                              ]))

    assert_equal({"count/resourceclaims.resource.k8s.io" => 1, "gpu.deviceclass.resource.k8s.io/devices" => 34,
                  "nic.deviceclass.resource.k8s.io/devices" => 4, "fpga.deviceclass.resource.k8s.io/devices" => 1}, usage)
  end

  def test_the_quota_controller_counts_claims_and_devices
    controller = Rubernetes::Controller::ResourceQuotaController.new(name: "resourcequota-controller")
    claims = [claim([{"name" => "a", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 2}}]),
              claim([{"name" => "a", "exactly" => {"deviceClassName" => "gpu", "allocationMode" => "ExactCount", "count" => 1}}])]

    assert_equal 3, controller.send(:usage_for, "gpu.deviceclass.resource.k8s.io/devices", claims)
    assert_equal 2, controller.send(:usage_for, "count/resourceclaims.resource.k8s.io", claims)
    assert_equal "ResourceClaim", controller.send(:counted_kind, "gpu.deviceclass.resource.k8s.io/devices")
  end
end
