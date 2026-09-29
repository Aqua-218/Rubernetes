# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

# ValidateResourceClaimStatusUpdate (pkg/apis/resource/validation, v1.36.2)
# with DRAResourceClaimDeviceStatus.
class ResourceClaimStatusValidationTest < Minitest::Test
  def definition = Rubernetes::Generated.definition_for("io.k8s.api.resource.v1.ResourceClaim")

  def claim(status, deleted: false)
    metadata = {"name" => "c", "namespace" => "ns", "resourceVersion" => "1", "uid" => "u"}
    metadata["deletionTimestamp"] = "2026-09-24T00:00:00Z" if deleted
    {"apiVersion" => "resource.k8s.io/v1", "kind" => "ResourceClaim", "metadata" => metadata,
     "spec" => {"devices" => {"requests" => [{"name" => "gpu", "exactly" => {"deviceClassName" => "gpu.example"}}]}}, "status" => status}
  end

  ALLOCATION = {"devices" => {"results" => [{"request" => "gpu", "driver" => "gpu.example", "pool" => "node-1", "device" => "gpu-0"}]}}.freeze

  def errors(status, old_status: {}, deleted: false)
    definition.validator.errors(claim(status, deleted: deleted), operation: :update, old: claim(old_status), subresource: "status")
              .map { |issue| "#{issue.kubernetes_field}: #{issue.kubernetes_type}: #{issue.message}" }
  end

  def device(**overrides)
    {"driver" => "gpu.example", "pool" => "node-1", "device" => "gpu-0",
     "conditions" => [{"type" => "Ready", "status" => "True", "reason" => "Configured", "lastTransitionTime" => "2026-09-24T00:00:00Z"}],
     "networkData" => {"interfaceName" => "eth1", "ips" => ["10.0.0.5/24"], "hardwareAddress" => "ea:9f:cb:40:b1:7b"}}
      .merge(overrides.transform_keys(&:to_s))
  end

  def test_a_valid_allocation_and_device_status
    assert_empty errors({"allocation" => ALLOCATION})
    assert_empty errors({"allocation" => ALLOCATION, "devices" => [device]}, old_status: {"allocation" => ALLOCATION})
  end

  def test_device_status_rules
    found = errors({"allocation" => ALLOCATION, "devices" => [device(device: "gpu-9"), device, device,
                                                                device(pool: "node-1", networkData: {"ips" => ["10.0.0.5"]}, conditions: [{"type" => "Ready", "status" => "Maybe"}])]},
                   old_status: {"allocation" => ALLOCATION})
    assert(found.any? { |message| message.include?("status.devices[0]: Invalid value") && message.include?("must be an allocated device in the claim") })
    assert(found.any? { |message| message.start_with?("status.devices[2]: Duplicate value") })
    assert(found.any? { |message| message.include?("networkData.ips[0]") && message.include?("must be a valid address in CIDR form") })
    assert(found.any? { |message| message.include?("conditions[0].status: Unsupported value") })
    assert(found.any? { |message| message.include?("conditions[0].lastTransitionTime: Required value") })
    assert(found.any? { |message| message.include?("conditions[0].reason: Required value") })
  end

  def test_reserved_for_and_allocation_rules
    consumer = {"resource" => "pods", "name" => "p", "uid" => "pod-1"}
    assert_includes errors({"reservedFor" => [consumer]}), "status.reservedFor: Forbidden: may not be specified when `allocated` is not set"
    assert_includes errors({"allocation" => ALLOCATION, "reservedFor" => [consumer, consumer]}), "status.reservedFor[1]: Duplicate value: "
    assert_includes errors({"allocation" => ALLOCATION, "reservedFor" => [{"resource" => "pods"}]}), "status.reservedFor[0].uid: Required value: "
    changed = {"devices" => {"results" => [ALLOCATION["devices"]["results"][0].merge("device" => "gpu-1")]}}
    assert_includes errors({"allocation" => changed}, old_status: {"allocation" => ALLOCATION}), "status.allocation: Invalid value: field is immutable"
    bad = {"devices" => {"results" => [{"request" => "nope", "driver" => "Bad_Driver", "pool" => "node-1", "device" => "gpu-0"}]}}
    found = errors({"allocation" => bad})
    assert(found.any? { |message| message.include?("results[0].request") && message.include?("must be the name of a request in the claim") })
    assert(found.any? { |message| message.include?("results[0].driver") })
    assert_includes errors({"allocation" => ALLOCATION, "reservedFor" => [consumer]}, old_status: {"allocation" => ALLOCATION}, deleted: true),
                    "status.reservedFor: Forbidden: new entries may not be added while `deallocationRequested` or `deletionTimestamp` are set"
  end
end
