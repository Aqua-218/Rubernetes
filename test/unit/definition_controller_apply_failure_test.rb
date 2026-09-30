# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/controller"

# A refused write from a controller wrapped in a DefinitionController (the
# ReplicationController among them) must reach ApplyFailures, not crash the
# reconcile with NoMethodError and hide the original error.
class DefinitionControllerApplyFailureTest < Minitest::Test
  Controller = Rubernetes::Controller

  def test_record_apply_failure_is_available
    definition = Controller.default_registry.fetch("deployment-controller")
    wrapper = Controller::DefinitionController.new(definition, store: nil)
    create = Controller::Operation.new(action: :create, resource: Controller::ResourceDescriptor.parse("Pod"),
                                       key: "ns/pod", object: {"metadata" => {"name" => "pod"}}, owner: nil, reason: "t")
    result = Controller::ReconcileResult.new(operations: [create], status: {}, controller: "rc", key: "ns/rc")
    Controller::ApplyFailures.reset!
    wrapper.send(:record_apply_failure, result, RuntimeError.new("exceeded quota"))

    assert_equal "exceeded quota", Controller::ApplyFailures["rc", "ns/rc"]
  end
end
