# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/manifest/builder"

class ManifestPodCredentialsTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  MANIFEST = Rubernetes::Manifest

  DECLARATIONS = <<~RUBY
    account = service_account "app", namespace: "team"
    registry = secret "registry", namespace: "team" do
      type "kubernetes.io/dockerconfigjson"
      string_data ".dockerconfigjson" => '{"auths":{}}'
    end
    legacy = secret "legacy", namespace: "team" do
      type "kubernetes.io/dockercfg"
      string_data ".dockercfg" => '{}'
    end
  RUBY

  def test_merges_the_final_raw_list_and_keeps_only_reference_names
    _, registry, _, workload = build(DECLARATIONS + <<~RUBY)
      pod "web", namespace: "team" do
        use_service_account account
        image_pull_secrets registry, legacy, registry
        image_pull_secrets [{name: "existing"}, {name: "registry"}, {name: "existing"}]
        service_account_name "app"
        pod do
          use_service_account account
          image_pull_secrets secret("external")
        end
      end
    RUBY

    assert_equal({".dockerconfigjson" => '{"auths":{}}'}, registry.fetch("stringData"))
    assert_equal({"serviceAccountName" => "app", "imagePullSecrets" => named(%w[existing registry legacy external])}, workload.fetch("spec"))
  end

  def test_applies_references_to_workload_templates_and_cronjob_pod_spec
    _, _, _, deployment, stateful, daemon, job, cron, template = build(DECLARATIONS + <<~RUBY)
      deployment("app", namespace: "team") { use_service_account account; image_pull_secrets registry }
      stateful_set("app", namespace: "team") { use_service_account account; image_pull_secrets registry }
      daemon_set("app", namespace: "team") { pod { use_service_account account; image_pull_secrets registry } }
      job("app", namespace: "team") { use_service_account account; image_pull_secrets registry }
      cron_job "nightly", namespace: "team" do
        schedule "0 3 * * *"
        use_service_account account
        pod do
          image_pull_secrets [{name: "existing"}]
          image_pull_secrets registry
        end
      end
      pod_template("saved", namespace: "team") { use_service_account account; image_pull_secrets registry }
    RUBY

    [deployment, stateful, daemon, job].each do |workload|
      spec = workload.dig("spec", "template", "spec")

      assert_equal "app", spec.fetch("serviceAccountName")
      assert_equal named(["registry"]), spec.fetch("imagePullSecrets")
    end
    spec = cron.dig("spec", "jobTemplate", "spec", "template", "spec")

    assert_equal "app", spec.fetch("serviceAccountName")
    assert_equal named(%w[existing registry]), spec.fetch("imagePullSecrets")
    assert_equal "Never", spec.fetch("restartPolicy")
    spec = template.dig("template", "spec")

    assert_equal "app", spec.fetch("serviceAccountName")
    assert_equal named(["registry"]), spec.fetch("imagePullSecrets")
  end

  def test_preserves_raw_schema_assignments_without_typed_references
    duplicates = named(%w[legacy legacy])
    pod, deployment = build(<<~RUBY)
      pod "p" do
        service_account_name "legacy"
        image_pull_secrets [{name: "legacy"}, {name: "legacy"}]
      end
      deployment "d" do
        template do
          spec { image_pull_secrets nil }
        end
      end
    RUBY

    assert_equal({"serviceAccountName" => "legacy", "imagePullSecrets" => duplicates}, pod.fetch("spec"))
    assert_equal({"imagePullSecrets" => nil}, deployment.dig("spec", "template", "spec"))
  end

  def test_explicit_null_is_forwarded_to_the_pod_spec_field
    pod, deployment = build(<<~RUBY)
      pod("p") { image_pull_secrets nil }
      deployment("d") { pod { image_pull_secrets nil } }
    RUBY

    assert_nil pod.fetch("spec").fetch("imagePullSecrets")
    assert_nil deployment.dig("spec", "template", "spec").fetch("imagePullSecrets")
  end

  def test_raw_image_pull_secrets_are_rejected_without_a_pod_spec_field
    assert_match(/app\.rb:1: .*image_pull_secrets/, error_of('deployment("d") { image_pull_secrets nil }'))
    assert_match(/app\.rb:1: .*image_pull_secrets/, error_of('deployment("d") { image_pull_secrets [{name: "legacy"}] }'))
  end

  def test_conflicts_point_to_the_manifest_in_either_order
    direct = <<~RUBY
      deployment "app", namespace: "team" do
        use_service_account account
        pod { service_account_name "another" }
      end
    RUBY
    reverse = <<~RUBY
      pod "app", namespace: "team" do
        service_account "another"
        use_service_account account
      end
    RUBY
    other = <<~RUBY
      other = service_account "another", namespace: "team"
      job "app", namespace: "team" do
        use_service_account account
        use_service_account other
      end
    RUBY

    assert_match(/app\.rb:\d+: use_service_account conflicts with serviceAccountName\z/, error_of(DECLARATIONS + direct))
    assert_match(/app\.rb:\d+: use_service_account conflicts with serviceAccount\z/, error_of(DECLARATIONS + reverse))
    assert_match(/app\.rb:\d+: use_service_account refers to different ServiceAccounts\z/, error_of(DECLARATIONS + other))
  end

  def test_rejects_undeclared_wrong_kind_and_other_namespace_references
    assert_includes error_of(DECLARATIONS + 'pod("p") { use_service_account account.dup }'), "expected ServiceAccount declared in this manifest"
    assert_includes error_of(DECLARATIONS + 'pod("p") { image_pull_secrets account }'), "expected Secret declared in this manifest"
    assert_includes error_of(DECLARATIONS + 'pod("p") { use_service_account registry }'), "expected ServiceAccount declared in this manifest"
    assert_includes error_of(DECLARATIONS + 'pod("p") { image_pull_secrets configmap("app") }'), "expected a reference to Secret"
    assert_includes error_of(DECLARATIONS + 'job("j", namespace: "other") { use_service_account account }'), 'ServiceAccount/app is in namespace "team"'
    assert_includes error_of(DECLARATIONS + 'cron_job("j", namespace: "other") { image_pull_secrets registry }'), 'Secret/registry is in namespace "team"'
  end

  def test_invalid_registry_type_reports_only_the_declaration_identity
    error = error_of(<<~RUBY)
      registry = secret("registry") { string_data token: "never-print-this-value" }
      pod("app") { image_pull_secrets registry }
    RUBY

    assert_match(%r{app\.rb:2: Secret/registry needs type kubernetes\.io/dockerconfigjson or kubernetes\.io/dockercfg\z}, error)
    refute_includes error, "never-print-this-value"
  end

  private

  def named(names) = names.map { |name| {"name" => name} }

  def build(source)
    MANIFEST::Builder.load(registry_path: File.join(ROOT, "generated/schema/registry.json"), openapi_path: File.join(ROOT, "generated/openapi/v2.json"))
      .evaluate(source, "app.rb")
  end

  def error_of(source) = assert_raises(MANIFEST::Error) { build(source) }.message
end
