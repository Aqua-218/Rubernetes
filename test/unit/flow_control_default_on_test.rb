# frozen_string_literal: true

# kube-apiserver enables API Priority and Fairness by default with the
# bootstrap PriorityLevelConfigurations and FlowSchemas;
# security.flow_control.enabled: false switches it off.

require_relative "../test_helper"
require "rubernetes/bootstrap"

class FlowControlDefaultOnTest < Minitest::Test
  APF = Rubernetes::Security::FlowControl

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
                 Rubernetes::Security::FlowControl::Controller::DEFAULT_READ_SEATS + Rubernetes::Security::FlowControl::Controller::DEFAULT_MUTATING_SEATS,
                 "--max-requests-inflight 400 + --max-mutating-requests-inflight 200"
  end

  def test_explicit_settings_and_the_off_switch
    refute_nil assembly({"flow_control" => {}}).pipeline.flow_control
    refute_nil assembly({"flow_control" => {"enabled" => true, "read_seats" => 10}}).pipeline.flow_control
    assert_nil assembly({"flow_control" => {"enabled" => false}}).pipeline.flow_control
  end

  def test_reconciler_resolves_dangling_references_after_storage_changes
    controller = APF::Controller.new(flow_schemas: [], priority_level_configurations: [], borrowing_adjustment_seconds: nil)
    store = Rubernetes::Storage::MemoryStore.new
    key_for = ->(*parts) { parts.compact.join("/") }
    reconciler = APF::ConfigurationReconciler.new(controller: controller, store: store, key_for: key_for, clock: -> { Time.now.utc })
    schema_key = key_for.call(APF::ConfigurationReconciler::GROUP, "v1", "flowschemas", :cluster, "test")
    level_key = key_for.call(APF::ConfigurationReconciler::GROUP, "v1", "prioritylevelconfigurations", :cluster, "limited")
    store.create(schema_key, {"kind" => "FlowSchema", "metadata" => {"name" => "test", "uid" => "schema-id"},
                              "spec" => {"priorityLevelConfiguration" => {"name" => "limited"}}})
    reconciler.start

    assert(wait_for { store.get(schema_key).dig("status", "conditions", 0, "reason") == "NotFound" })
    assert_empty controller.flow_schemas

    store.create(level_key, {"kind" => "PriorityLevelConfiguration", "metadata" => {"name" => "limited", "uid" => "level-id"},
                             "spec" => {"type" => "Limited", "limited" => {"nominalConcurrencyShares" => 10}}})

    assert(wait_for { store.get(schema_key).dig("status", "conditions", 0, "status") == "False" })
    assert_equal "schema-id", controller.flow_schemas.first.dig("metadata", "uid")
    assert_equal "level-id", controller.priority_levels.fetch("limited").uid

    store.delete(level_key)

    assert(wait_for { store.get(schema_key).dig("status", "conditions", 0, "status") == "True" })
    assert_empty controller.priority_levels
  ensure
    reconciler&.stop
  end

  def wait_for
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5
    until yield
      return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

      sleep(0.02)
    end
    true
  end
end
