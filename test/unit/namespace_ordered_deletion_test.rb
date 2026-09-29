# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# pkg/controller/namespace/deletion/namespaced_resources_deleter.go
# deleteAllContent: with OrderedNamespaceDeletion every Pod is deleted first
# and nothing else is touched until none remain, so a workload is never
# stripped of the ConfigMaps and Secrets it is still running on.  The deleter
# also publishes its full condition set on every pass -- clients read the mere
# presence of NamespaceDeletionContentFailure as proof the namespace was
# processed, which is how "[sig-api-machinery] OrderedNamespaceDeletion
# namespace deletion should delete pod first" gates the rest of its checks.
class NamespaceOrderedDeletionTest < Minitest::Test
  Controller = Rubernetes::Controller

  def namespace(terminating: true)
    metadata = {"name" => "ns", "uid" => "ns-uid"}
    metadata["deletionTimestamp"] = "2026-01-01T00:00:00Z" if terminating
    {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => metadata,
     "spec" => {"finalizers" => ["kubernetes"]}, "status" => {"phase" => "Active"}}
  end

  def object(kind, name, finalizers: [])
    metadata = {"name" => name, "namespace" => "ns", "uid" => "#{name}-uid"}
    metadata["finalizers"] = finalizers unless finalizers.empty?
    {"apiVersion" => "v1", "kind" => kind, "metadata" => metadata}
  end

  def plan(contents, terminating: true)
    Controller::NamespaceController.new.plan(namespace(terminating: terminating), objects: contents)
  end

  def deleted_kinds(result)
    result.operations.select { |operation| operation.action == :delete }
          .map { |operation| operation.object.fetch("kind") }
  end

  def conditions(result)
    Array(result.status["conditions"]).to_h { |condition| [condition.fetch("type"), condition] }
  end

  def test_pods_are_deleted_before_anything_else
    result = plan([object("Pod", "p"), object("ConfigMap", "cm"), object("Secret", "s")])

    assert_equal(%w[Pod], deleted_kinds(result))
  end

  def test_other_content_is_deleted_once_no_pod_remains
    result = plan([object("ConfigMap", "cm"), object("Secret", "s")])

    assert_equal(%w[ConfigMap Secret], deleted_kinds(result).sort)
  end

  def test_every_deletion_condition_is_published
    result = plan([])

    assert_equal(Controller::NamespaceController::CONDITION_OK.keys.sort, conditions(result).keys.sort)
    assert_equal("False", conditions(result).fetch("NamespaceDeletionContentFailure").fetch("status"))
    assert_equal("ContentDeleted", conditions(result).fetch("NamespaceDeletionContentFailure").fetch("reason"))
  end

  def test_remaining_content_is_named_in_the_condition
    result = plan([object("Pod", "p"), object("ConfigMap", "cm")])
    remaining = conditions(result).fetch("NamespaceContentRemaining")

    assert_equal("True", remaining.fetch("status"))
    assert_equal("SomeResourcesRemain", remaining.fetch("reason"))
    assert_includes(remaining.fetch("message"), "Pod has 1 resource instances")
    assert_includes(remaining.fetch("message"), "ConfigMap has 1 resource instances")
  end

  def test_a_finalizer_holding_content_is_named_in_the_condition
    result = plan([object("Pod", "p", finalizers: ["e2e.example.com/finalizer"])])
    remaining = conditions(result).fetch("NamespaceFinalizersRemaining")

    assert_equal("True", remaining.fetch("status"))
    assert_equal("SomeFinalizersRemain", remaining.fetch("reason"))
    assert_includes(remaining.fetch("message"), "e2e.example.com/finalizer in 1 resource instances")
  end

  # A namespace that is not being deleted carries no deletion conditions.
  def test_an_active_namespace_has_no_deletion_conditions
    result = plan([object("Pod", "p")], terminating: false)

    assert_empty(conditions(result))
    assert_empty(deleted_kinds(result))
  end
end
