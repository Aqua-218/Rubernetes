# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/manifest/builder"

class ManifestDisruptionBudgetTest < Minitest::Test
  M = Rubernetes::Manifest
  ROOT = File.expand_path("../..", __dir__)
  WORKLOAD = 'web = deployment("web") { container("web", image: "nginx") }'

  def test_uses_a_workloads_final_selector_and_namespace
    %w[deployment replica_set stateful_set].each do |kind|
      workload, budget = render(<<~RUBY)
        web = in_namespace "preview" do
          #{kind}("web") { container("web", image: "nginx") }
        end
        in_namespace "staging" do
          disruption_budget web, max_unavailable: 1
        end
      RUBY

      assert_equal %w[policy/v1 PodDisruptionBudget], budget.values_at("apiVersion", "kind")
      assert_equal({"name" => "web", "namespace" => "preview"}, budget.fetch("metadata"))
      assert_equal({"maxUnavailable" => 1, "selector" => {"matchLabels" => {"app" => "web"}}}, budget.fetch("spec"))
      assert_equal workload.dig("spec", "selector"), budget.dig("spec", "selector")
    end
  end

  def test_copies_label_expressions_without_rewriting_them
    workload, budget = render(<<~RUBY)
      web = deployment "web" do
        selector match_labels: {app: "web"}, match_expressions: [
          {key: "tier", operator: "In", values: ["blue", "green"]},
          {key: "retired", operator: "NotIn", values: [""]},
          {key: "zone", operator: "Exists", values: []},
          {key: "obsolete", operator: "DoesNotExist"}
        ]
        template metadata: {labels: {tier: "blue", zone: ""}}
        container "web", image: "nginx"
      end
      in_namespace("preview") { disruption_budget web, min_available: "025%", name: "maintenance" }
    RUBY

    assert_equal({"name" => "maintenance"}, budget.fetch("metadata"))
    assert_equal "025%", budget.dig("spec", "minAvailable")
    assert_equal workload.dig("spec", "selector"), budget.dig("spec", "selector")
    refute budget.fetch("spec").key?("maxUnavailable")
  end

  def test_wraps_replication_controller_selectors_and_follows_the_upstream_default
    [true, false].each do |explicit|
      workload, budget = render(<<~RUBY)
        web = replication_controller "web", namespace: "preview" do
          #{'selector app: "web"' if explicit}
          template metadata: {labels: {app: "web", tier: "blue"}}
          container "web", image: "nginx"
        end
        disruption_budget web, min_available: "100%"
      RUBY
      labels = explicit ? {"app" => "web"} : {"app" => "web", "tier" => "blue"}

      assert_equal({"matchLabels" => labels}, budget.dig("spec", "selector"))
      assert_equal "preview", budget.dig("metadata", "namespace")
      refute workload.fetch("spec").key?("selector") unless explicit
    end
  end

  def test_requires_one_supported_threshold_at_the_call_site
    ["", ", min_available: 1, max_unavailable: 0"].each do |options|
      assert_match(/app.rb:2: disruption_budget requires exactly one/, diagnostic("#{WORKLOAD}\ndisruption_budget web#{options}"))
    end
    [-1, 2_147_483_648, 12.0, true, "1", "-1%", "0.5%", "101%", "1%\n"].each do |value|
      assert_match(/app.rb:2: disruption_budget max_unavailable must be an integer/,
                   diagnostic("#{WORKLOAD}\ndisruption_budget web, max_unavailable: #{value.inspect}"))
    end
    [0, 2_147_483_647, "0%", "100%", "00100%"].each do |value|
      assert_equal value, render("#{WORKLOAD}\ndisruption_budget web, max_unavailable: #{value.inspect}").last.dig("spec", "maxUnavailable")
    end
  end

  def test_rejects_unsupported_targets_and_namespace_wide_selectors
    assert_match(/app.rb:2: disruption_budget expects a workload declared/, diagnostic("#{WORKLOAD}\ndisruption_budget web.dup, max_unavailable: 1"))
    assert_match(/app.rb:1: disruption_budget expects a Deployment/, diagnostic('disruption_budget daemon_set("agent"), max_unavailable: 1'))
    ["selector({})", "selector(match_labels: {}, match_expressions: [])"].each do |declaration|
      assert_match(%r{app.rb:2: Deployment/web needs a nonempty Pod selector}, diagnostic(<<~RUBY))
        web = deployment("web") { #{declaration}; container("web", image: "nginx") }
        disruption_budget web, max_unavailable: 1
      RUBY
    end
    assert_match(%r{app.rb:2: ReplicationController/web needs a nonempty Pod selector}, diagnostic(<<~RUBY))
      web = replication_controller("web") { container("web", image: "nginx") }
      disruption_budget web, max_unavailable: 1
    RUBY
  end

  def test_rejects_selector_requirements_that_are_invalid_or_cannot_select_the_workload
    {operator: "not a valid selector operator", null: "cannot contain null", absent: "does not match"}.each do |mode, error|
      expression = {key: "tier", operator: mode == :operator ? "Foo" : "In", values: [mode == :null ? nil : ""]}

      message = diagnostic(<<~RUBY)
        web = deployment "web" do
          selector match_expressions: [#{expression.inspect}]
          container "web", image: "nginx"
        end
        disruption_budget web, max_unavailable: 1
      RUBY

      assert_includes message, "app.rb:5: Deployment/web"
      assert_includes message, error
    end
  end

  def test_rejects_the_deprecated_conversion_expression_that_can_expand_to_every_pod
    message = diagnostic(<<~RUBY)
      web = deployment "web" do
        selector match_expressions: [{key: "pdb.kubernetes.io/deprecated-v1beta1-empty-selector-match", operator: "DoesNotExist"}]
        container "web", image: "nginx"
      end
      disruption_budget web, max_unavailable: 1
    RUBY

    assert_includes message, "app.rb:5: Deployment/web selector uses"
    assert_includes message, "the PDB API reserves for conversion"
  end

  def self.inputs
    @inputs ||= [JSON.parse(File.binread(File.join(ROOT, "generated/schema/registry.json")), max_nesting: 512),
                 JSON.parse(File.binread(File.join(ROOT, "generated/openapi/v2.json")), max_nesting: 512).fetch("definitions")]
  end

  private

  def render(source)
    registry, definitions = self.class.inputs
    M::Builder.new(registry: registry, definitions: definitions).evaluate(source, "app.rb")
  end

  def diagnostic(source) = assert_raises(M::Error) { render(source) }.message
end
