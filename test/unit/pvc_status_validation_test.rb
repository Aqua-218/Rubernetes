# frozen_string_literal: true

require_relative "../test_helper"
require File.expand_path("../../generated/ruby/kubernetes_types", __dir__)

class PVCStatusValidationTest < Minitest::Test
  def errors(status)
    definition = Rubernetes::Generated.definition_for("io.k8s.api.core.v1.PersistentVolumeClaim")
    claim = {"apiVersion" => "v1", "kind" => "PersistentVolumeClaim",
             "metadata" => {"name" => "p", "namespace" => "ns", "resourceVersion" => "1"},
             "spec" => {"accessModes" => ["ReadWriteOnce"], "resources" => {"requests" => {"storage" => "1Gi"}}}}
    definition.validator.errors(claim.merge("status" => status), operation: :update, old: claim, subresource: "status")
  end

  def test_negative_capacity_and_allocation_report_signed_whole_bytes
    found = errors("capacity" => {"other" => "-100m"}, "allocatedResources" => {"storage" => "-2"})

    assert_equal ["status.capacity[other]", "status.allocatedResources[storage]"], found.map(&:kubernetes_field)
    assert_equal [-1, -2], found.map(&:value)
    assert(found.all? { |issue| issue.message == "must be a valid resource quantity" })
  end

  def test_resize_status_and_resource_key_are_checked_independently
    issues = errors("allocatedResourceStatuses" => {"kubernetes.io/other" => "shrinking"})

    assert_equal %i[unsupported unsupported], issues.map(&:code)
    assert(issues.all? { |issue| issue.kubernetes_field == "status.allocatedResourceStatuses" })
    assert_match(/NodeResizePending/, issues.last.message)
    assert_equal "kubernetes.io/other", issues.last.value
  end

  def test_qualified_extension_resources_are_accepted_and_malformed_keys_are_reported_once
    assert_empty errors("capacity" => {"disk" => "1.2"}, "allocatedResources" => {"example.org/data" => "1.5"},
                        "allocatedResourceStatuses" => {"example.org/data" => "NodeResizeInfeasible", "storage" => "NodeResizePending"})
    issues = errors("allocatedResources" => {"Bad Group/data" => "-2"})

    assert_equal [:invalid], issues.map(&:code)
    assert_equal "status.allocatedResources", issues.first.kubernetes_field
  end
end
