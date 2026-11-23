# frozen_string_literal: true

require "tmpdir"
require_relative "../test_helper"
require_relative "../support/admission_policy_harness"
require "rubernetes/bootstrap/security_assembly"

class StaticAdmissionManifestTest < Minitest::Test
  include AdmissionPolicyHarness

  API = Rubernetes::API
  SOURCE = A::StaticManifestSource
  GROUP = SOURCE::GROUP
  VERSION = SOURCE::API_VERSION
  POLICY = "limit.static.k8s.io"
  BINDING = "apply.static.k8s.io"
  RULE = {"apiGroups" => ["apps"], "apiVersions" => ["v1"], "operations" => ["CREATE"], "resources" => ["deployments"]}.freeze

  def test_startup_rejects_a_disabled_gate_relative_paths_and_mixed_plugin_kinds
    Dir.mktmpdir do |directory|
      error = assert_raises(S::ConfigurationError) { assembly(directory, enabled: false) }
      assert_match(/requires the ManifestBasedAdmissionControlConfig feature gate/, error.message)
      error = assert_raises(S::ConfigurationError) { assembly("relative") }
      assert_match(/existing absolute directory/, error.message)

      write(directory, "incorrect.yaml", webhook_configuration("wrong.static.k8s.io"))
      error = assert_raises(S::ConfigurationError) { assembly(directory) }
      assert_match(/unsupported resource type .*ValidatingWebhookConfiguration for ValidatingAdmissionPolicy/, error.message)
    end
  end

  def test_loads_static_policy_binding_pairs_while_api_bindings_cannot_attach_to_static_policies
    Dir.mktmpdir do |directory|
      filename = write(directory, "policy.yaml", policy("object.spec.replicas <= 2"))
      service = assembly(directory)
      source = service.reload_controllers.find { |controller| controller.is_a?(SOURCE) }

      refute_nil source
      plugin = build_plugin("ValidatingAdmissionPolicy", source)
      put_binding("stored-binding", POLICY, %w[Deny])
      rejected_request = -> { attributes("CREATE", object: deployment(replicas: 3)) }
      plugin.validate(rejected_request.call)

      File.write(filename, YAML.dump({"apiVersion" => "v1", "kind" => "List", "items" => [binding, policy("object.spec.replicas <= 2")]}))

      assert source.check!
      rejection = assert_raises(A::Rejected) { plugin.validate(rejected_request.call) }
      assert_match(/'limit.static.k8s.io' with binding 'apply.static.k8s.io'/, rejection.message)

      File.write(filename, YAML.dump(binding))

      refute source.check!
      assert_raises(A::Rejected) { plugin.validate(rejected_request.call) }

      File.write(filename, YAML.dump_stream(policy("true"), binding))

      assert source.check!
      plugin.validate(rejected_request.call)
    end
  end

  def test_reload_detects_atomic_replacement_and_records_failures_without_dropping_old_config
    Dir.mktmpdir do |directory|
      filename = write(directory, "policy.yml", policy("true"))
      source = static_source(directory, "ValidatingAdmissionPolicy")
      source.metrics = Rubernetes::Observability::Metrics.new
      source.note_loaded
      source.start
      replaced_file = File.join(directory, "next.tmp")
      File.write(replaced_file, YAML.dump_stream(policy("false"), binding))
      File.rename(replaced_file, filename)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
      loop do
        break if source.snapshot.fetch("validatingadmissionpolicybindings").any?

        flunk "static manifest reload did not observe the file change" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep(0.02)
      end
      source.stop
      snapshot = source.snapshot
      File.write(filename, "kind: ValidatingAdmissionPolicy\nkind: ConfigMap\n")

      refute source.check!
      assert_same snapshot, source.snapshot
      metrics = source.metrics.render
      pattern = /^#{Regexp.escape(SOURCE::RELOADS)}\{.*plugin="ValidatingAdmissionPolicy",status="success"\} 2$/o

      assert_match pattern, metrics
      pattern = /^#{Regexp.escape(SOURCE::RELOADS)}\{.*plugin="ValidatingAdmissionPolicy",status="failure"\} 1$/o

      assert_match pattern, metrics
    ensure
      source&.stop
    end
  end

  def test_static_webhooks_dispatch_first_and_only_static_hooks_see_admission_configuration_writes
    Dir.mktmpdir do |directory|
      write(directory, "hook.json", webhook_configuration("z.static.k8s.io"), json: true)
      source = static_source(directory, "ValidatingAdmissionWebhook")
      dynamic = webhook_configuration("a-dynamic", url: "https://dynamic.example/validate")
      @context.put("validatingwebhookconfigurations", nil, "a-dynamic", dynamic, group: GROUP)
      calls = []
      client = Object.new
      client.define_singleton_method(:call) do |config, review, timeout_seconds:|
        calls << [config.fetch("url"), timeout_seconds]
        [200, {"response" => {"uid" => review.dig("request", "uid"), "allowed" => true}}]
      end
      plugin = build_plugin("ValidatingAdmissionWebhook", source, "client" => client)
      plugin.validate(attributes("CREATE", object: deployment(replicas: 1)))

      assert_equal ["https://static.example/validate", "https://dynamic.example/validate"], calls.map(&:first)
      assert_equal 10, calls.first.last

      calls.clear
      config_request = attributes("CREATE", object: binding, resource: "validatingadmissionpolicybindings", group: GROUP,
                                            kind: "ValidatingAdmissionPolicyBinding", namespace: nil)

      assert plugin.handles?(config_request)
      plugin.validate(config_request)

      assert_equal [["https://static.example/validate", 10]], calls
    end
  end

  def test_webhook_url_parameters_and_static_policy_parameters_are_validated_on_startup
    Dir.mktmpdir do |directory|
      file = write(directory, "webhook.yaml", webhook_configuration("one.static.k8s.io", url: "http://wrong.example/"))
      error = assert_raises(S::ConfigurationError) { static_source(directory, "ValidatingAdmissionWebhook") }
      assert_match(/clientConfig.url must be a valid https/, error.message)
      File.write(file, YAML.dump(webhook_configuration("one.static.k8s.io", service: {"name" => "service", "namespace" => "ns"})))
      error = assert_raises(S::ConfigurationError) { static_source(directory, "ValidatingAdmissionWebhook") }
      assert_match(/clientConfig.service is not supported/, error.message)

      invalid = policy("true")
      invalid.fetch("spec")["paramKind"] = {"apiVersion" => "v1", "kind" => "ConfigMap"}
      File.write(file, YAML.dump(invalid))
      error = assert_raises(S::ConfigurationError) { static_source(directory, "ValidatingAdmissionPolicy") }
      assert_match(/spec.paramKind is not supported/, error.message)
    end
  end

  def test_rest_reserved_names_warn_when_disabled_reject_creation_when_enabled_and_warn_on_existing_updates
    store = API::MemoryStore.new
    registry = API::Registry.new(resources: [API::Resource.new(group: GROUP, version: "v1", kind: "ValidatingAdmissionPolicy",
                                                               resource: "validatingadmissionpolicies", scope: :cluster)])
    path = "/apis/#{VERSION}/validatingadmissionpolicies"
    disabled = API::Server.new(registry: registry, store: store, feature_gates: {SOURCE::GATE => false})
    created = disabled.call(API::Request.new(method: "POST", path: path, body: policy("true")))

    assert_equal 201, created.status, created.body.inspect
    assert_match(/metadata.name: names ending with/, created.header("warning"))

    enabled = API::Server.new(registry: registry, store: store, feature_gates: {SOURCE::GATE => true})
    forbidden = enabled.call(API::Request.new(method: "POST", path: path, body: policy("true", name: "other.static.k8s.io")))

    assert_equal 422, forbidden.status
    assert_equal "metadata.name", forbidden.body.dig("details", "causes", 0, "field")
    assert_nil forbidden.header("warning")

    updated = enabled.call(API::Request.new(method: "PUT", path: "#{path}/#{POLICY}", body: created.body))

    assert_equal 200, updated.status, updated.body.inspect
    assert_match(/metadata.name: names ending with/, updated.header("warning"))
  end

  private

  def build_plugin(name, source, config = {})
    A::Registry.factories.fetch(name).call(@context, config.merge("manifest_source" => source))
  end

  def object(kind, name, body = {})
    {"apiVersion" => VERSION, "kind" => kind, "metadata" => {"name" => name}}.merge(body)
  end

  def policy(expression, name: POLICY)
    object("ValidatingAdmissionPolicy", name, "spec" => {"matchConstraints" => {"resourceRules" => [RULE]},
                                                         "validations" => [{"expression" => expression}]})
  end

  def binding
    object("ValidatingAdmissionPolicyBinding", BINDING, "spec" => {"policyName" => POLICY, "validationActions" => ["Deny"]})
  end

  def webhook_configuration(name, url: "https://static.example/validate", service: nil)
    rule = {"apiGroups" => ["*"], "apiVersions" => ["*"], "operations" => ["CREATE"], "resources" => ["*"]}
    client = service ? {"service" => service} : {"url" => url}
    object("ValidatingWebhookConfiguration", name, "webhooks" => [{"name" => "test.webhook.example", "clientConfig" => client,
                                                                   "admissionReviewVersions" => ["v1"], "sideEffects" => "None", "rules" => [rule]}])
  end

  def write(directory, file, manifest, json: false)
    File.join(directory, file).tap { |path| File.write(path, json ? JSON.generate(manifest) : YAML.dump(manifest)) }
  end

  def static_source(directory, plugin)
    SOURCE.new(plugin: plugin, path: directory, feature_enabled: true, apiserver_id: "test-apiserver", interval: 0.1)
  end

  def assembly(directory, enabled: true)
    config = {"feature_gates" => {SOURCE::GATE => enabled},
              "admission" => {"config" => {"ValidatingAdmissionPolicy" => {"staticManifestsDir" => directory}}}}
    Rubernetes::Bootstrap::SecurityAssembly.new(config: config, store: Rubernetes::Storage::MemoryStore.new, key_for: ->(*) { "" })
  end
end
