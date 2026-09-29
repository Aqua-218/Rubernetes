# frozen_string_literal: true

require "minitest/autorun"
require "rubernetes/controller"

class M3RegistryIntegrationTest < Minitest::Test
  Controller = Rubernetes::Controller

  def setup
    @registry = Controller.build_default_registry
  end

  def test_default_registry_covers_the_pinned_52_name_inventory
    corpus = Controller::BuiltinControllerCorpus

    assert_equal 52, corpus.names.length
    assert_equal corpus.names.sort, @registry.names
    assert_equal corpus.names.sort, @registry.definitions.map(&:name)
    assert_empty @registry.missing_names
    assert_empty @registry.unimplemented_names
    assert_equal 52, @registry.registered_complete_count
  end

  def test_each_definition_validates_gvk_watch_scope_and_ownership_contract
    @registry.definitions.each do |definition|
      definition.validate!(corpus_entry: @registry.entry(definition.name))
      assert_instance_of Class, definition.implementation, definition.name
      implementation = definition.implementation
      assert implementation.public_instance_methods(true).include?(:plan) ||
             implementation.protected_instance_methods(true).include?(:plan), definition.name
      assert definition.reconcile_block.respond_to?(:call), definition.name
      assert definition.owns.all? { |edge| edge.owner == definition.kind }, definition.name
      assert definition.watches.all? { |watch| watch.scope == watch.resource.scope }, definition.name
      assert_equal definition.watches.map { |watch| [watch.resource.gvk, watch.via, watch.index_name] }.uniq.length,
                   definition.watches.length, definition.name
    end
  end

  def test_startup_validation_accepts_all_pinned_concrete_controllers
    assert_empty @registry.incomplete_controllers
    assert_same @registry, @registry.startup_validate!
  end

  def test_pinned_non_core_descriptors_keep_exact_gvk_and_scope
    assert_equal ["certificates.k8s.io", "v1beta1", "PodCertificateRequest"],
                 @registry.fetch("podcertificaterequest-cleaner-controller").kind.gvk
    assert_equal :cluster, @registry.fetch("resourcepoolstatusrequest-controller").kind.scope
    assert_equal ["resource.k8s.io", "v1alpha3", "ResourcePoolStatusRequest"],
                 @registry.fetch("resourcepoolstatusrequest-controller").kind.gvk
    assert_equal ["scheduling.k8s.io", "v1alpha2", "PodGroup"],
                 @registry.fetch("podgroup-protection-controller").kind.gvk
  end

  def test_definition_projection_is_idempotent_and_ownership_edges_are_indexed
    @registry.definitions.each do |definition|
      assert_equal definition.to_h, definition.to_h, definition.name
      definition.owns.each do |edge|
        assert @registry.ownership_index.registered?(edge.owner, edge.dependent), definition.name
      end
    end
  end
end
