# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/node"

# container.restartPolicyRules (types.go ContainerRestartRule) decides restart
# behaviour for the exit codes it names, overriding the container/Pod restart
# policy.  The field was validated by the API server and read by nobody.
class NodeRestartPolicyRulesTest < Minitest::Test
  Manager = Rubernetes::Node::RestartManager

  def manager
    Manager.new
  end

  def rules(operator, values, action: "Restart")
    [{"action" => action, "exitCodes" => {"operator" => operator, "values" => values}}]
  end

  def test_a_matching_in_rule_restarts_despite_policy_never
    assert manager.should_restart?(policy: "Never", exit_code: 42, rules: rules("In", [42])),
           "a matching restart rule overrides restartPolicy: Never"
  end

  def test_a_non_matching_in_rule_leaves_policy_never_alone
    refute manager.should_restart?(policy: "Never", exit_code: 7, rules: rules("In", [42]))
  end

  def test_not_in_matches_everything_else
    assert manager.should_restart?(policy: "Never", exit_code: 7, rules: rules("NotIn", [0]))
    refute manager.should_restart?(policy: "Never", exit_code: 0, rules: rules("NotIn", [0]))
  end

  def test_a_clean_exit_named_by_a_rule_still_restarts
    assert manager.should_restart?(policy: "OnFailure", exit_code: 0, rules: rules("In", [0])),
           "exit 0 restarts when a rule names it"
  end

  def test_no_rules_keeps_the_existing_behaviour
    refute manager.should_restart?(policy: "Never", exit_code: 1)
    assert manager.should_restart?(policy: "OnFailure", exit_code: 1)
    refute manager.should_restart?(policy: "OnFailure", exit_code: 0)
    assert manager.should_restart?(policy: "Always", exit_code: 0)
  end

  def test_an_unknown_action_is_ignored
    refute manager.should_restart?(policy: "Never", exit_code: 42,
                                   rules: rules("In", [42], action: "Nonsense"))
  end

  def test_a_liveness_failure_still_follows_the_policy
    refute manager.should_restart?(policy: "Never", exit_code: 42, liveness_failure: true,
                                   rules: rules("In", [42])),
           "restartPolicy Never still wins for a liveness kill"
  end

  def test_malformed_rules_never_raise
    refute manager.should_restart?(policy: "Never", exit_code: 1, rules: [{"action" => "Restart"}])
    refute manager.should_restart?(policy: "Never", exit_code: 1, rules: "nonsense")
  end
end
