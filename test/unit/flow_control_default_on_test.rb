# frozen_string_literal: true

# kube-apiserver enables API Priority and Fairness by default with the
# bootstrap PriorityLevelConfigurations and FlowSchemas;
# security.flow_control.enabled: false switches it off.

require_relative "../test_helper"
require "rubernetes/bootstrap"

class FlowControlDefaultOnTest < Minitest::Test
  def assembly(config)
    Rubernetes::Bootstrap::SecurityAssembly.new(config: config, store: Rubernetes::Storage::MemoryStore.new, key_for: ->(*) { "" })
  end

  def test_on_by_default_with_the_bootstrap_configuration
    flow_control = assembly({}).pipeline.flow_control

    assert_kind_of Rubernetes::Security::FlowControl::Controller, flow_control
    assert_equal %w[catch-all exempt global-default leader-election node-high system workload-high workload-low],
                 flow_control.priority_levels.keys.sort
    assert_equal "exempt", flow_control.flow_schemas.first.dig("metadata", "name")
    assert_equal 600,
                 Rubernetes::Security::FlowControl::Controller::DEFAULT_READ_SEATS + Rubernetes::Security::FlowControl::Controller::DEFAULT_MUTATING_SEATS, "--max-requests-inflight 400 + --max-mutating-requests-inflight 200"
  end

  def test_explicit_settings_and_the_off_switch
    refute_nil assembly({"flow_control" => {}}).pipeline.flow_control
    refute_nil assembly({"flow_control" => {"enabled" => true, "read_seats" => 10}}).pipeline.flow_control
    assert_nil assembly({"flow_control" => {"enabled" => false}}).pipeline.flow_control
  end
end
