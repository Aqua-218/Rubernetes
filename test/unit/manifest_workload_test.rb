# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/manifest/builder"
require "rubernetes/rubectl"
require "stringio"

# A manifest written in Ruby is checked against the schema while it is built
# and comes out as the JSON any Kubernetes client could have sent.
class ManifestWorkloadTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  M = Rubernetes::Manifest

  def self.builder_inputs
    @builder_inputs ||= [JSON.parse(File.binread(File.join(ROOT, "generated/schema/registry.json")), max_nesting: 512),
                         JSON.parse(File.binread(File.join(ROOT, "generated/openapi/v2.json")), max_nesting: 512).fetch("definitions")]
  end

  def build(source)
    registry, definitions = self.class.builder_inputs
    M::Builder.new(registry: registry, definitions: definitions).evaluate(source, "app.rb")
  end

  def error_of(source) = assert_raises(M::Error) { build(source) }.message

  def test_fields_may_be_written_in_snake_case_at_any_depth
    service = build('service("web") { ports [{port: 80, target_port: 8080}]; session_affinity_config client_ip: {timeout_seconds: 60} }').first

    assert_equal [{"port" => 80, "targetPort" => 8080}], service.dig("spec", "ports")
    assert_equal 60, service.dig("spec", "sessionAffinityConfig", "clientIP", "timeoutSeconds")
  end

  # Labels, annotations and ConfigMap data are the user's own names.
  def test_the_keys_of_a_map_are_left_as_written
    config = build('config_map("c", labels: {"app.kubernetes.io/part_of" => "shop"}) { data log_level: "debug", "max_conn" => "5" }').first

    assert_equal({"app.kubernetes.io/part_of" => "shop"}, config.dig("metadata", "labels"))
    assert_equal({"log_level" => "debug", "max_conn" => "5"}, config.fetch("data"))
  end

  def test_a_field_the_type_does_not_have_is_named_with_its_place_and_the_nearest_field
    assert_equal 'app.rb:1: spec.ports[0]: ServicePort has no field "taget_port" (did you mean "target_port"?)',
                 error_of('service("web") { ports [{port: 80, taget_port: 80}] }')
    assert_equal 'app.rb:2: Deployment has no field or helper "replica" (did you mean "replicas"?)', error_of("deployment \"web\" do\n  replica 3\nend")
    assert_match(/containers\.c\.readinessProbe\.httpGet: HTTPGetAction has no field "pathh"/,
                 error_of('deployment("web") { container("c", image: "x") { readiness_probe http_get: {pathh: "/"} } }'))
  end

  def test_a_workload_is_its_containers_and_the_rest_follows
    deployment = build(<<~RUBY).first
      deployment "web", namespace: "prod" do
        replicas 3
        container "nginx", image: "nginx:1.27" do
          port 80
          port 9113, name: "metrics"
          cpu request: "100m", limit: "500m"
          memory request: "128Mi"
          env "LOG_LEVEL", :debug
          env from: configmap("app-config")
          env "PASSWORD", from: secret("db"), key: "password"
          mount "cache", at: "/var/cache/nginx"
        end
        volume "cache"
        volume "config", from: configmap("app-config")
      end
    RUBY
    spec = deployment.fetch("spec")
    container = spec.dig("template", "spec", "containers", 0)

    assert_equal({"matchLabels" => {"app" => "web"}}, spec.fetch("selector"), "an unwritten selector selects app: <name>")
    assert_equal({"app" => "web"}, spec.dig("template", "metadata", "labels"), "and the template carries what it selects")
    assert_equal [{"containerPort" => 80}, {"containerPort" => 9113, "name" => "metrics"}], container.fetch("ports")
    assert_equal({"requests" => {"cpu" => "100m", "memory" => "128Mi"}, "limits" => {"cpu" => "500m"}}, container.fetch("resources"))
    assert_equal [{"configMapRef" => {"name" => "app-config"}}], container.fetch("envFrom")
    assert_equal [{"name" => "LOG_LEVEL", "value" => "debug"},
                  {"name" => "PASSWORD", "valueFrom" => {"secretKeyRef" => {"name" => "db", "key" => "password"}}}], container.fetch("env")
    assert_equal [{"name" => "cache", "mountPath" => "/var/cache/nginx"}], container.fetch("volumeMounts")
    assert_equal [{"name" => "cache", "emptyDir" => {}}, {"name" => "config", "configMap" => {"name" => "app-config"}}],
                 spec.dig("template", "spec", "volumes")
  end

  def test_a_written_selector_is_kept_and_reaches_the_template
    spec = build('stateful_set("db") { service_name "db"; selector match_labels: {tier: "data"}; container "pg", image: "postgres:17" }').first.fetch("spec")

    assert_equal({"matchLabels" => {"tier" => "data"}}, spec.fetch("selector"))
    assert_equal({"tier" => "data"}, spec.dig("template", "metadata", "labels"))
  end

  def test_the_short_form_and_the_generated_fields_describe_one_template
    spec = build(<<~RUBY).first.fetch("spec")
      deployment "web" do
        container "nginx", image: "nginx:1.27", image_pull_policy: "Always"
        pod { service_account_name "web"; termination_grace_period_seconds 5 }
        template { metadata annotations: {"team" => "shop"} }
      end
    RUBY

    assert_equal "Always", spec.dig("template", "spec", "containers", 0, "imagePullPolicy")
    assert_equal "web", spec.dig("template", "spec", "serviceAccountName")
    assert_equal({"annotations" => {"team" => "shop"}, "labels" => {"app" => "web"}}, spec.dig("template", "metadata"))
  end

  def test_anti_affinity_keeps_the_workloads_own_pods_apart
    deployment = build('deployment("web") { container "c", image: "x"; anti_affinity on: "kubernetes.io/hostname" }').first
    terms = deployment.dig("spec", "template", "spec", "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution")

    assert_equal [{"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "kubernetes.io/hostname"}], terms
    assert_match(/anti_affinity needs labels on the Pods/, error_of('job("once") { container "c", image: "x"; anti_affinity on: "zone" }'))
  end

  # The API accepts no restartPolicy a Job's Pods would default to.
  def test_jobs_run_to_completion_unless_told_otherwise
    job, cron, kept = build(<<~RUBY)
      job("once") { container "c", image: "x" }
      cron_job("nightly") { schedule "0 3 * * *"; container "c", image: "x" }
      job("retry") { container "c", image: "x"; pod { restart_policy "OnFailure" } }
    RUBY

    assert_equal "Never", job.dig("spec", "template", "spec", "restartPolicy")
    assert_nil job.dig("spec", "selector"), "the Job controller writes a Job's selector"
    assert_equal "Never", cron.dig("spec", "jobTemplate", "spec", "template", "spec", "restartPolicy")
    assert_equal "OnFailure", kept.dig("spec", "template", "spec", "restartPolicy")
    assert_nil build('deployment("web") { container "c", image: "x" }').first.dig("spec", "template", "spec", "restartPolicy")
  end

  def test_a_method_defined_at_the_top_of_the_file_is_visible_in_every_block
    pod = build(<<~RUBY).first
      def image_of(name) = "registry.example/\#{name}:1.0"
      pod("p") { container("c", image: image_of("api")) { env "IMAGE", image_of("api") } }
    RUBY

    assert_equal "registry.example/api:1.0", pod.dig("spec", "containers", 0, "image")
    assert_equal "registry.example/api:1.0", pod.dig("spec", "containers", 0, "env", 0, "value")
  end

  # Inside a container's block `image "x"` sets the image.  A method of the
  # manifest with that name would be shadowed there without a word.
  def test_a_method_named_like_a_field_is_refused
    message = error_of("def image(name) = name\npod(\"p\") { container(\"c\", image: \"x\") { env \"A\", \"b\" } }")

    assert_match(/the method `image` defined in the manifest has the name of a field of Container; rename it/, message)
  end

  # `secret` declares a Secret at the top level and names one inside a block.
  def test_secret_declares_at_the_top_and_refers_inside_a_block
    secret, pod = build('secret("db") { string_data password: "x" }; pod("p") { container("c", image: "x") { env from: secret("db") } }')

    assert_equal %w[Secret db], [secret.fetch("kind"), secret.dig("metadata", "name")]
    assert_equal [{"secretRef" => {"name" => "db"}}], pod.dig("spec", "containers", 0, "envFrom")
  end

  def test_a_kind_without_a_pod_template_has_no_container_helper
    assert_match(/Service has no field or helper "container"/, error_of('service("web") { container "c", image: "x" }'))
  end

  def test_every_example_manifest_builds
    examples = Dir[File.join(ROOT, "examples/manifests/*.rb")]

    assert_operator examples.length, :>=, 3
    examples.each do |path|
      registry, definitions = self.class.builder_inputs
      objects = M::Builder.new(registry: registry, definitions: definitions).evaluate(File.read(path), path)

      refute_empty objects, path
      objects.each { |object| assert object.dig("metadata", "name"), "#{path}: #{object["kind"]} without a name" }
    end
  end

  class FixedSandbox
    def compile(_path, allow_code:, environment: [], env: {})
      raise M::Error, "Ruby manifests require --allow-code" unless allow_code

      [{"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "a"}, "data" => {"MODE" => env.fetch("APP_ENV", "none")}},
       {"apiVersion" => "v1", "kind" => "Service", "metadata" => {"name" => "b"}}]
    end
  end

  # `rubectl render` prints what `apply` would send; nothing is contacted.
  def test_render_prints_the_manifests_without_a_cluster
    stdout = StringIO.new
    cli = Rubernetes::Rubectl::CLI.new(stdout: stdout, stderr: StringIO.new, sandbox: FixedSandbox.new, env: {"APP_ENV" => "production"},
                                       client_factory: ->(_options) { flunk("render must not build a client") })
    status = cli.run(%w[render -f app.rb --allow-code --env APP_ENV -o yaml])
    objects = YAML.load_stream(stdout.string)

    assert_equal 0, status
    assert_equal(%w[ConfigMap Service], objects.map { |object| object.fetch("kind") })
    assert_equal "production", objects.first.dig("data", "MODE"), "a value passed with --env is part of the manifest, not a secret to mask"
    assert_equal 64, Rubernetes::Rubectl::CLI.new(stdout: StringIO.new, stderr: StringIO.new).run(%w[render])
  end
end
