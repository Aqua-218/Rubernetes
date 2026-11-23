# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/api/object_validation"
require "rubernetes/security/admission"
require_relative "../support/security_admission_fake_context"

class PriorityClassValidationTest < Minitest::Test
  def priority_class(name, value, **extra)
    {"metadata" => {"name" => name}, "value" => value}.merge(extra.transform_keys(&:to_s))
  end

  def fields(object, old: nil)
    Rubernetes::API::ObjectValidation.validate("PriorityClass", object, old: old, namespaced: false).map { |cause| [cause.field, cause.reason] }
  end

  def test_system_names_values_and_preemption_policy_are_checked_on_create
    assert_empty(fields(priority_class("normal", 1_000_000_000)))
    assert_equal([%w[value FieldValueForbidden]], fields(priority_class("normal", 1_000_000_001)))
    assert_empty(fields(priority_class("system-node-critical", 2_000_001_000)))
    assert_equal([%w[metadata.name FieldValueForbidden]], fields(priority_class("system-unknown", 0)))
    assert_equal([%w[metadata.name FieldValueForbidden]], fields(priority_class("system-cluster-critical", 0)))
    assert_equal([%w[metadata.name FieldValueForbidden]], fields(priority_class("system-cluster-critical", 2_000_000_000, globalDefault: true)))
    assert_equal([%w[preemptionPolicy FieldValueRequired]], fields(priority_class("normal", 1, preemptionPolicy: "")))
    assert_equal([%w[preemptionPolicy FieldValueNotSupported]], fields(priority_class("normal", 1, preemptionPolicy: "Always")))
  end

  def test_a_class_can_change_its_description_and_default_flag_but_cannot_change_its_scheduling_policy
    old = priority_class("normal", 100, preemptionPolicy: "Never")

    assert_empty(fields(old.merge("description" => "For batch jobs", "globalDefault" => true), old: old))
    assert_equal([%w[preemptionPolicy FieldValueInvalid]], fields(old.merge("preemptionPolicy" => "PreemptLowerPriority"), old: old))
    assert_equal([%w[value FieldValueForbidden]], fields(old.merge("value" => 200), old: old))
  end

  def test_pod_group_priority_is_admitted_only_on_enabled_creates
    admission = Rubernetes::Security::Admission
    context = SecurityAdmissionFakeContext.new
    priority = admission::Registry.factories.fetch("Priority").call(context, {})
    context.put("priorityclasses", nil, "urgent", priority_class("urgent", 42), group: "scheduling.k8s.io")
    group = {"spec" => {"priorityClassName" => "urgent"}}
    create = admission::Attributes.new(operation: "CREATE", user: nil, group: "scheduling.k8s.io", resource: "podgroups", version: "v1alpha2",
                                       kind: "PodGroup", object: group)
    priority.admit(create)

    refute(group["spec"].key?("priority"))
    context.feature_gates["WorkloadAwarePreemption"] = true
    priority.admit(create)

    assert_equal(42, create.object.dig("spec", "priority"))
    create.object["spec"]["priority"] = 100
    assert_raises(admission::Rejected) { priority.admit(create) }
  end
end
