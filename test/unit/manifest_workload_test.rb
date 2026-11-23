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

  def test_downward_environment_fields_preserve_order_and_qualified_metadata_keys
    pod = build(<<~RUBY).first
      pod "api" do
        container "app", image: "busybox" do
          env_field "IP", "status.podIP"
          env_field "TEAM", label: "example.com/team"
          env_field "REVISION", annotation: "example.com/Revision"
          env "ENDPOINT", "http://$(IP)"
        end
      end
    RUBY
    entries = pod.dig("spec", "containers", 0, "env")

    assert_equal(%w[IP TEAM REVISION ENDPOINT], entries.map { |entry| entry.fetch("name") })
    assert_equal(["status.podIP", "metadata.labels['example.com/team']", "metadata.annotations['example.com/Revision']"],
                 entries.first(3).map { |entry| entry.dig("valueFrom", "fieldRef", "fieldPath") })
    assert_equal ["v1"], entries.first(3).map { |entry| entry.dig("valueFrom", "fieldRef", "apiVersion") }.uniq
    assert_equal "http://$(IP)", entries.last["value"]
  end

  def test_downward_environment_field_errors_identify_the_manifest_line
    source = "pod 'api' do\n container 'app', image: 'busybox' do\n  env_field 'FIELD', %s\n end\nend"

    assert_match(/app.rb:3: unknown Pod environment field .*status\.podIP/, error_of(format(source, "'status.podId'")))
    assert_match(/app.rb:3: invalid Pod label key/, error_of(format(source, "label: 'example.com/a b'")))
    assert_match(/app.rb:3: env_field expects one/, error_of(format(source, "'metadata.name', annotation: 'team'")))
  end

  def test_downward_resource_environment_references_survive_pod_template_rendering
    workload = build(<<~RUBY).first
      deployment "web" do
        container "app", image: "busybox" do
          env_field "POD_NAME", "metadata.name"
          env_resource "CPU_UNITS", "requests.cpu", divisor: "0.001"
          env_resource "BUFFER_MIB", "limits.memory", divisor: "1024Ki", container: :proxy
          env "REPORT", "$(POD_NAME):$(CPU_UNITS)"
        end
        sidecar "proxy", image: "busybox" do
          env_resource "STORAGE", "limits.ephemeral-storage", container: "app"
          env_resource "HUGE_PAGES", "requests.hugepages-2Mi", divisor: "1Mi", container: "seed"
        end
        init_container "seed", image: "busybox"
      end
    RUBY
    spec = workload.dig("spec", "template", "spec")
    env = spec.dig("containers", 0, "env")

    assert_equal(%w[POD_NAME CPU_UNITS BUFFER_MIB REPORT], env.map { |entry| entry.fetch("name") })
    assert_equal({"resource" => "requests.cpu", "divisor" => "1m"}, env.dig(1, "valueFrom", "resourceFieldRef"))
    assert_equal({"resource" => "limits.memory", "containerName" => "proxy", "divisor" => "1Mi"}, env.dig(2, "valueFrom", "resourceFieldRef"))
    assert_equal({"resource" => "limits.ephemeral-storage", "containerName" => "app"},
                 spec.dig("initContainers", 0, "env", 0, "valueFrom", "resourceFieldRef"))
    assert_equal({"resource" => "requests.hugepages-2Mi", "containerName" => "seed", "divisor" => "1Mi"},
                 spec.dig("initContainers", 0, "env", 1, "valueFrom", "resourceFieldRef"))
  end

  def test_downward_resource_environment_errors_identify_the_manifest_line
    source = "pod 'api' do\n container 'app', image: 'busybox' do\n  env_resource 'RESOURCE', %s\n end\nend"

    assert_match(/app.rb:3: unknown Pod environment resource .*requests.cpu/, error_of(format(source, "'requests.example.com/gpu'")))
    assert_match(/app.rb:3: invalid env_resource divisor "banana"/, error_of(format(source, "'requests.cpu', divisor: 'banana'")))
    assert_match(/app.rb:3: env_resource divisor .* must be positive/, error_of(format(source, "'requests.cpu', divisor: 0")))
    assert_match(/app.rb:3: env_resource divisor .* must be positive/, error_of(format(source, "'limits.memory', divisor: '-1Mi'")))
    assert_match(/app.rb:3: env_resource divisor .*1m and 1 are supported/, error_of(format(source, "'limits.cpu', divisor: '100m'")))
    assert_match(/app.rb:3: env_resource divisor .*are supported with the local ephemeral storage resource/,
                 error_of(format(source, "'limits.ephemeral-storage', divisor: '4Mi'")))
    assert_match(/app.rb:3: env_resource container "worker" is missing\. Available containers: app/,
                 error_of(format(source, "'limits.memory', container: 'worker'")))
  end

  def test_downward_resource_environment_cannot_target_an_ephemeral_container
    message = error_of(<<~RUBY)
      pod "api" do
        container "app", image: "busybox" do
          env_resource "MEMORY", "limits.memory", container: "debug"
        end
        pod { ephemeral_containers [{name: "debug", image: "busybox"}] }
      end
    RUBY

    assert_equal 'app.rb:3: env_resource container "debug" is missing. Available containers: app', message
  end

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

  def test_an_empty_dir_can_be_shared_as_a_ruby_value_between_containers
    pod = build(<<~RUBY).first
      pod "p" do
        cache = empty_dir "work", medium: :memory, size_limit: "1024Mi"
        disk = empty_dir "data"
        init_container("seed", image: "tool") { mount cache, at: "/out" }
        container "web", image: "app" do
          mount cache, at: "/cache", read_only: true
          mount disk, at: "/data"
        end
      end
    RUBY
    spec = pod.fetch("spec")

    assert_equal [{"name" => "work", "emptyDir" => {"medium" => "Memory", "sizeLimit" => "1Gi"}},
                  {"name" => "data", "emptyDir" => {}}], spec.fetch("volumes")
    assert_equal({"name" => "work", "mountPath" => "/out"}, spec.dig("initContainers", 0, "volumeMounts", 0))
    assert_equal({"name" => "work", "mountPath" => "/cache", "readOnly" => true}, spec.dig("containers", 0, "volumeMounts", 0))
    assert_equal "data", spec.dig("containers", 0, "volumeMounts", 1, "name")
  end

  def test_empty_dir_diagnostics_point_to_the_manifest
    ref = 'vol = nil; pod("p") { vol = empty_dir "cache" }'

    assert_match(/app.rb:2: .*belongs to a different workload/, error_of([ref, 'pod("q") { container("x", image: "i") { mount vol, at: "/tmp" } }'].join("\n")))
    assert_match(/app.rb:2: .*conflicts/, error_of("pod \"p\" do\n empty_dir \"cache\"\n volume \"cache\"\nend"))
    assert_match(/size_limit must be non-negative/, error_of('pod("p") { empty_dir "scratch", size_limit: "-1Mi" }'))
    assert_match(/invalid empty_dir size_limit/, error_of('pod("p") { empty_dir "scratch", size_limit: "large" }'))
    assert_match(/use mount/, error_of('pod("p") { v = empty_dir "cache"; container("x", image: "x") { device v, at: "/dev/x" } }'))
    assert_match(/medium must be/, error_of('pod("p") { empty_dir "cache", medium: :memroy }'))
  end

  def test_http_probes_resolve_names_after_all_ports_in_the_same_container
    workload = build(<<~RUBY).first
      deployment "web" do
        sidecar "proxy", image: "example" do
          http_probe :startup, port: 8000
        end
        container "app", image: "example" do
          http_probe :readiness, port: :web, path: "/ready", period_seconds: 2
          http_probe :liveness, port: :web, path: "/live", scheme: :https, failure_threshold: 4
          port 8443, name: :web, protocol: :TCP
        end
      end
    RUBY
    spec = workload.dig("spec", "template", "spec")
    app = spec.fetch("containers").first

    assert_equal({"path" => "/", "port" => 8000, "scheme" => "HTTP"}, spec.dig("initContainers", 0, "startupProbe", "httpGet"))
    assert_equal({"periodSeconds" => 2, "httpGet" => {"path" => "/ready", "port" => "web", "scheme" => "HTTP"}}, app.fetch("readinessProbe"))
    assert_equal({"failureThreshold" => 4, "httpGet" => {"path" => "/live", "port" => "web", "scheme" => "HTTPS"}}, app.fetch("livenessProbe"))
  end

  def test_http_probe_reports_the_manifest_line_and_the_current_containers_tcp_ports
    source = <<~RUBY
      pod "web" do
        sidecar("proxy", image: "example") { port 443, name: "secure" }
        container "app", image: "example" do
          http_probe :readiness, port: :secure
          ports [{name: :dns, container_port: 53, protocol: "UDP"}, {name: :web, container_port: 80}]
        end
      end
    RUBY

    assert_equal 'app.rb:4: readinessProbe port "secure" must name one TCP port on container "app". Available: web', error_of(source)
    assert_match(/port "dns" must name one TCP port/, error_of(source.sub("port: :secure", "port: :dns")))
    assert_match(/integer from 1 to 65535/, error_of(source.sub("port: :secure", "port: 0")))
    assert_match(/http_probe scheme must be/, error_of(source.sub("port: :secure", 'port: 80, scheme: "udp"')))
    assert_match(/unknown http_probe option :period_second/, error_of(source.sub("port: :secure", "port: 80, period_second: 3")))
    assert_match(/app.rb:4: .*expected integer/, error_of(source.sub("port: :secure", 'port: 80, period_seconds: "2"')))
  end

  def test_http_probe_headers_preserve_name_value_pairs
    source = <<~RUBY
      pod "catalog" do
        container "app", image: "example" do
          http_probe :readiness, port: 8080, headers: { Host: "catalog.test", "X-Group" => ["primary", "fallback"] }
        end
      end
    RUBY
    pod = build(source).first

    assert_equal [{"name" => "Host", "value" => "catalog.test"}, {"name" => "X-Group", "value" => "primary"},
                  {"name" => "X-Group", "value" => "fallback"}], pod.dig("spec", "containers", 0, "readinessProbe", "httpGet", "httpHeaders")
    assert_match(/app.rb:3: .*X-Group.*needs a string/, error_of(source.sub('["primary", "fallback"]', "[]")))
  end

  def test_http_probe_reports_invalid_timing_and_preserves_kubernetes_zero_defaults
    source = <<~RUBY
      pod "web" do
        container "app", image: "example" do
          http_probe :startup, port: 80, success_threshold: 2
        end
      end
    RUBY

    readiness = source.sub(":startup", ":readiness").sub("success_threshold", "termination_grace_period_seconds")

    assert_equal "app.rb:3: startupProbe.successThreshold must be 1 (got 2)", error_of(source)
    assert_match(/app.rb:3: readinessProbe.terminationGracePeriodSeconds must not be set/, error_of(readiness))
    pod = build(source.sub("success_threshold: 2", "success_threshold: 0")).first

    assert_equal 0, pod.dig("spec", "containers", 0, "startupProbe", "successThreshold")
  end

  def test_tcp_grpc_and_exec_probes_render_the_standard_kubernetes_actions
    source = <<~RUBY
      pod "db" do
        container "db", image: "example" do
          tcp_probe :startup, port: :sql, failure_threshold: 12
          grpc_probe :readiness, port: 9000, service: "catalog"
          exec_probe :liveness, command: ["check", "one argument"]
          port 5432, name: :sql
        end
      end
    RUBY
    container = build(source).first.dig("spec", "containers", 0)

    assert_equal({"tcpSocket" => {"port" => "sql"}, "failureThreshold" => 12}, container.fetch("startupProbe"))
    assert_equal({"grpc" => {"port" => 9000, "service" => "catalog"}}, container.fetch("readinessProbe"))
    assert_equal({"exec" => {"command" => ["check", "one argument"]}}, container.fetch("livenessProbe"))
    assert_match(/app.rb:3: startupProbe port "missing" must name one TCP port/, error_of(source.sub("port: :sql", "port: :missing")))
    assert_match(/app.rb:4: grpc_probe port must be an integer/, error_of(source.sub("port: 9000", "port: :sql")))
    assert_match(/app.rb:5: exec_probe command must be a non-empty array/, error_of(source.sub('["check", "one argument"]', '"check"')))
  end

  def test_resource_helpers_reject_invalid_quantities_at_the_declaration
    {"ephemeral_storage" => ['limit: "2GB"', /invalid ephemeral-storage limit quantity "2GB"/],
     "cpu" => ['request: "-1m"', /cpu request must be non-negative/],
     "memory" => ["request: false", /invalid memory request quantity false/]}.each do |helper, (argument, diagnostic)|
      error = error_of(<<~RUBY)
        pod "work" do
          container "app", image: "example" do
            #{helper} #{argument}
          end
        end
      RUBY

      assert_match(/app\.rb:3:/, error)
      assert_match diagnostic, error
    end
  end

  def test_resource_helpers_compare_the_final_request_and_limit_in_common_units
    invalid = <<~RUBY
      pod "cache" do
        container "app", image: "example" do
          ephemeral_storage request: "2Gi"
          ephemeral_storage limit: "2000Mi"
        end
      end
    RUBY
    assert_equal "app.rb:4: ephemeral-storage request 2Gi exceeds limit 2000Mi", error_of(invalid)

    source = invalid.sub('limit: "2000Mi"', "limit: \"2000Mi\"\n    ephemeral_storage limit: \"2048Mi\"")
    pod = build(source).first

    assert_equal "2048Mi", pod.dig("spec", "containers", 0, "resources", "limits", "ephemeral-storage")
  end

  def test_declared_configs_connect_to_env_and_volumes_and_roll_out_on_content_change
    source = <<~RUBY
      cfg = config_map("app", namespace: "prod") { data MODE: "fast"; binary_data packet: "AQ==" }
      db = secret("db", namespace: "prod") { string_data PASSWORD: "test" }
      deployment "api", namespace: "prod" do
        rollout_on cfg
        volume "db", from: db
        container "app", image: "busybox" do
          env from: cfg
          env "PWD", from: db, key: :PASSWORD
        end
      end
    RUBY
    template = build(source).last.dig("spec", "template")
    spec = template.fetch("spec")
    checksum = template.dig("metadata", "annotations", M::ConfigRollout::ANNOTATION)

    assert_match(/\A[0-9a-f]{64}\z/, checksum)
    assert_equal({"secretName" => "db"}, spec.dig("volumes", 0, "secret"))
    assert_equal({"name" => "app"}, spec.dig("containers", 0, "envFrom", 0, "configMapRef"))
    assert_equal({"name" => "db", "key" => "PASSWORD"}, spec.dig("containers", 0, "env", 0, "valueFrom", "secretKeyRef"))
    %w[fast AQ==].zip(%w[slow Ag==]).each do |old, replacement|
      changed = build(source.sub(old, replacement)).last

      refute_equal checksum, changed.dig("spec", "template", "metadata", "annotations", M::ConfigRollout::ANNOTATION)
    end
  end

  def test_mount_wires_a_declared_config_or_secret_into_the_pod_once
    objects = build(<<~RUBY)
      cfg = config_map("settings", namespace: "team") { data MODE: "fast" }
      token = secret("private-config", namespace: "team")
      deployment "app", namespace: "team" do
        init_container("check", image: "busybox") { mount cfg, at: "/etc/config" }
        container "app", image: "busybox" do
          mount "settings", from: cfg, at: "/app/config"
          mount "credentials", from: token, at: "/etc/creds"
        end
        volume "settings", config_map: {name: "settings", default_mode: 0o440}
      end
    RUBY
    pod = objects.last.dig("spec", "template", "spec")

    assert_equal [{"name" => "settings", "configMap" => {"name" => "settings", "defaultMode" => 0o440}},
                  {"name" => "credentials", "secret" => {"secretName" => "private-config"}}], pod.fetch("volumes")
    assert_equal(["/app/config", "/etc/creds"], pod.dig("containers", 0, "volumeMounts").map { |mount| mount["mountPath"] })
    assert_equal([true, true], pod.dig("containers", 0, "volumeMounts").map { |mount| mount["readOnly"] })
    assert_equal "settings", pod.dig("initContainers", 0, "volumeMounts", 0, "name")
    assert_match(/needs an explicit volume name/, error_of('pod("p") { container("c", image: "x") { mount configmap("app.conf"), at: "/config" } }'))
    assert_match(/volume "cfg" conflicts/, error_of(<<~RUBY))
      cfg = config_map("settings")
      pod "p" do
        container("c", image: "x") { mount "cfg", from: cfg, at: "/config" }
        volume "cfg"
      end
    RUBY
  end

  def test_mount_projects_ordered_configmaps_and_secrets_from_ruby_arrays
    rendered = build(<<~RUBY)
      defaults = config_map("defaults")
      overrides = secret("site")
      sources = [defaults, overrides]
      pod "app" do
        volume "cfg", from: sources, projected: {default_mode: 0o440}
        init_container("init", image: "busybox") { mount "cfg", from: sources, at: "/init" }
        container("app", image: "busybox") { mount "cfg", from: sources, at: "/etc/app" }
      end
    RUBY
    pod = rendered.last.fetch("spec")
    expected = [{"configMap" => {"name" => "defaults"}}, {"secret" => {"name" => "site"}}]

    assert_equal [{"name" => "cfg", "projected" => {"defaultMode" => 0o440, "sources" => expected}}], pod.fetch("volumes")
    assert pod.dig("containers", 0, "volumeMounts", 0, "readOnly")
    assert_equal "cfg", pod.dig("initContainers", 0, "volumeMounts", 0, "name")
    assert_match(/at least one ConfigMap or Secret/, error_of('pod("p") { volume "cfg", from: [] }'))
    assert_match(/different volume sources/, error_of(<<~RUBY))
      a = config_map("one")
      b = secret("two")
      pod "p" do
        init_container("init", image: "x") { mount "cfg", from: [a, b], at: "/cfg" }
        container("reader", image: "x") { mount "cfg", from: [b, a], at: "/cfg" }
      end
    RUBY
  end

  def test_mounting_a_declared_claim_shares_the_volume_across_reader_and_writer
    declaration = 'data = persistent_volume_claim("data", namespace: "team")'
    objects = build(<<~RUBY)
      #{declaration}
      pod "app", namespace: "team" do
        init_container("writer", image: "busybox") { mount data, at: "/data" }
        container("reader", image: "busybox") { mount data, at: "/data", read_only: true }
        volume "data", from: data
      end
    RUBY
    pod = objects.last.fetch("spec")

    assert_equal [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "data"}}], pod.fetch("volumes")
    assert_equal({"name" => "data", "mountPath" => "/data"}, pod.dig("initContainers", 0, "volumeMounts", 0))
    assert_equal true, pod.dig("containers", 0, "volumeMounts", 0, "readOnly")
    cross_namespace = 'pod("p", namespace: "other") { container("c", image: "x") { mount data, at: "/d" } }'

    assert_match(/is in namespace "team"/, error_of([declaration, cross_namespace].join("\n")))
    assert_match(/expected ConfigMap or Secret/, error_of([declaration, 'pod("p") { container("c", image: "x") { env from: data } }'].join("\n")))
    assert_match(/conflicts with its declared source/, error_of([declaration, 'pod("p") { volume "cfg", from: data, empty_dir: {} }'].join("\n")))
  end

  def test_declared_block_claim_becomes_a_device_and_reports_a_mode_mismatch_at_render
    declaration = 'disk = persistent_volume_claim("disk") { volume_mode "Block" }'
    workload = 'pod("app") { container("app", image: "busybox") { device disk, at: "/dev/data" } }'
    spec = build([declaration, workload].join("\n")).last.fetch("spec")

    assert_equal [{"name" => "disk", "persistentVolumeClaim" => {"claimName" => "disk"}}], spec.fetch("volumes")
    assert_equal [{"name" => "disk", "devicePath" => "/dev/data"}], spec.dig("containers", 0, "volumeDevices")
    assert_match(%r{app.rb:2: PersistentVolumeClaim/disk has volumeMode Block}, error_of([declaration, workload.sub("device disk", "mount disk")].join("\n")))
    assert_match(/has volumeMode Filesystem/, error_of([declaration.sub("Block", "Filesystem"), workload].join("\n")))
  end

  def test_named_volume_checks_claim_modes_before_and_after_a_container
    source = <<~RUBY
      disk = persistent_volume_claim("claim") { volume_mode "Block" }
      pod "app" do
        container "app", image: "busybox" do
          mount "data", at: "/data"
        end
        volume "data", from: disk
      end
    RUBY

    assert_equal "app.rb:4: PersistentVolumeClaim/claim has volumeMode Block; use device", error_of(source)
    filesystem = <<~RUBY
      disk = persistent_volume_claim("claim")
      pod "app" do
        volume "data", from: disk
        container "app", image: "busybox" do
          device "data", at: "/dev/data"
        end
      end
    RUBY

    assert_equal "app.rb:5: PersistentVolumeClaim/claim has volumeMode Filesystem; use mount", error_of(filesystem)
    spec = build(source.sub('mount "data"', 'device "data"')).last.fetch("spec")

    assert_equal [{"name" => "data", "devicePath" => "/data"}], spec.dig("containers", 0, "volumeDevices")
    assert_equal [{"name" => "data", "persistentVolumeClaim" => {"claimName" => "claim"}}], spec.fetch("volumes")
  end

  def test_named_volume_inherits_the_mode_from_a_helper_alias
    source = <<~RUBY
      disk = persistent_volume_claim("claim") { volume_mode "Block" }
      deployment "app" do
        sidecar("reader", image: "busybox") { mount "data", at: "/data" }
        container("app", image: "busybox") { device "data", from: disk, at: "/dev/data" }
      end
    RUBY

    assert_equal "app.rb:3: PersistentVolumeClaim/claim has volumeMode Block; use device", error_of(source)
    spec = build(source.sub('mount "data"', 'device "data"')).last.dig("spec", "template", "spec")

    assert_equal [{"name" => "data", "devicePath" => "/data"}], spec.dig("initContainers", 0, "volumeDevices")
    assert_equal "Always", spec.dig("initContainers", 0, "restartPolicy")
    assert_equal 1, spec.fetch("volumes").length
  end

  def test_pvc_names_and_references_can_refer_to_claims_outside_the_manifest
    spec = build(<<~RUBY).first.fetch("spec")
      claim = Rubernetes::Manifest::Reference.new("PersistentVolumeClaim", "external")
      pod "app" do
        volume "disk", from: claim
        volume "data", persistent_volume_claim: {claim_name: "filesystem"}
        container "app", image: "busybox" do
          device "disk", at: "/dev/data"
          mount "data", at: "/data"
        end
      end
    RUBY

    assert_equal "external", spec.dig("volumes", 0, "persistentVolumeClaim", "claimName")
    assert_equal "filesystem", spec.dig("volumes", 1, "persistentVolumeClaim", "claimName")
    assert_equal "disk", spec.dig("containers", 0, "volumeDevices", 0, "name")
    assert_equal "data", spec.dig("containers", 0, "volumeMounts", 0, "name")
  end

  def test_rollout_checksum_ignores_order_metadata_and_repeated_declarations
    source = <<~RUBY
      a = config_map("a", labels: {team: "one"}) { data X: "1", Y: "2" }
      b = config_map("b") { binary_data b: "AA==" }
      daemon_set("api") { rollout_on a, b; container "app", image: "busybox" }
    RUBY
    reordered = source.sub('X: "1", Y: "2"', 'Y: "2", X: "1"').sub("one", "two").sub("a, b;", "b, a; rollout_on b;")

    assert_equal build(source).last, build(reordered).last
  end

  def test_invalid_declared_config_uses_the_ruby_source_line
    config = 'cfg = config_map("settings", namespace: "prod") { data MODE: "fast" }'

    assert_match(%r{app.rb:2: ConfigMap/settings has no environment key "MOED"},
                 error_of([config, 'deployment("app") { container("c", image: "x") { env "MODE", from: cfg, key: "MOED" } }'].join("\n")))
    assert_match(%r{app.rb:2: ConfigMap/settings is in namespace "prod"},
                 error_of([config, 'deployment("app", namespace: "staging") { volume "cfg", from: cfg }'].join("\n")))
    assert_match(/app.rb:2: expected ConfigMap declared in this manifest/,
                 error_of(['cfg = secret("db") { string_data key: "hidden" }', 'deployment("app") { rollout_on cfg }'].join("\n")))
  end

  def test_type_errors_identify_the_nested_field_before_apply
    assert_equal "app.rb:1: spec.replicas: expected integer, got String", error_of('deployment("web") { replicas "three" }')
    assert_equal "app.rb:1: data.RETRIES: expected string, got Integer", error_of('config_map("web") { data RETRIES: 3 }')
    assert_equal "app.rb:1: spec.ports: expected array, got Hash", error_of('service("web") { ports port: 80 }')
    assert_equal "app.rb:1: spec.ports[0]: expected ServicePort, got String", error_of('service("web") { ports ["http"] }')
    assert_nil build('deployment("web") { replicas nil }').first.dig("spec", "replicas")
    assert_equal "http", build('service("web") { ports [{port: 80, target_port: :http}] }').first.dig("spec", "ports", 0, "targetPort")
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
          ephemeral_storage request: "32Mi", limit: "128Mi"
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
    assert_equal({"requests" => {"cpu" => "100m", "memory" => "128Mi", "ephemeral-storage" => "32Mi"},
                  "limits" => {"cpu" => "500m", "ephemeral-storage" => "128Mi"}}, container.fetch("resources"))
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

  def test_stateful_set_claim_templates_write_standard_pvc_fields_and_use_named_mounts
    objects = build(<<~RUBY)
      stateful_set "db", namespace: "team" do
        service_name "db"
        replicas 2
        volume_claim_template "data", labels: {tier: "data"} do
          access_modes ["ReadWriteOnce"]
          storage_class_name "fast"
          resources { requests storage: "10Gi" }
          selector { match_labels backend: "local" }
        end
        volume_claim_template "disk" do
          access_modes ["ReadWriteOnce"]
          volume_mode "Block"
          resources requests: {storage: "2Gi"}
        end
        container "db", image: "postgres:17" do
          mount "data", at: "/data"
          device "disk", at: "/dev/cache"
        end
      end
    RUBY
    spec = objects.first.fetch("spec")
    pod = spec.dig("template", "spec")

    assert_equal(["StatefulSet"], objects.map { |object| object["kind"] })
    assert_equal [{"metadata" => {"name" => "data", "labels" => {"tier" => "data"}},
                   "spec" => {"accessModes" => ["ReadWriteOnce"], "storageClassName" => "fast",
                              "resources" => {"requests" => {"storage" => "10Gi"}}, "selector" => {"matchLabels" => {"backend" => "local"}}}},
                  {"metadata" => {"name" => "disk"},
                   "spec" => {"accessModes" => ["ReadWriteOnce"], "volumeMode" => "Block", "resources" => {"requests" => {"storage" => "2Gi"}}}}],
                 spec.fetch("volumeClaimTemplates")
    refute pod.key?("volumes")
    assert_equal [{"name" => "data", "mountPath" => "/data"}], pod.dig("containers", 0, "volumeMounts")
    assert_equal [{"name" => "disk", "devicePath" => "/dev/cache"}], pod.dig("containers", 0, "volumeDevices")
  end

  def test_later_raw_claim_template_determines_the_mode_of_shadowed_volumes
    source = <<~RUBY
      filesystem = persistent_volume_claim("outside")
      stateful_set "db" do
        service_name "db"
        sidecar("reader", image: "busybox") { mount "data", at: "/data" }
        volume "data", from: filesystem
        volume_claim_templates [{metadata: {name: "data"}, spec: {volume_mode: "Block"}}]
      end
    RUBY

    assert_equal "app.rb:4: volumeClaimTemplates/data has volumeMode Block; use device", error_of(source)
    accepted = build(source.sub('mount "data"', 'device "data"')).last.fetch("spec")

    assert_equal "data", accepted.dig("template", "spec", "initContainers", 0, "volumeDevices", 0, "name")
    assert_equal "outside", accepted.dig("template", "spec", "volumes", 0, "persistentVolumeClaim", "claimName")
    raw_filesystem = source.sub('mount "data"', 'device "data"').sub('spec: {volume_mode: "Block"}', "spec: {}")

    assert_equal "app.rb:4: volumeClaimTemplates/data has volumeMode Filesystem; use mount", error_of(raw_filesystem)
  end

  def test_later_claim_template_overrides_a_direct_claim_helper_with_the_same_name
    source = <<~RUBY
      disk = persistent_volume_claim("data") { volume_mode "Block" }
      stateful_set "db" do
        service_name "db"
        container("db", image: "busybox") { mount disk, at: "/data" }
        volume_claim_template("data") { resources requests: {storage: "5Gi"} }
      end
    RUBY
    pod = build(source).last.dig("spec", "template", "spec")

    refute pod.key?("volumes")
    assert_equal "data", pod.dig("containers", 0, "volumeMounts", 0, "name")
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

  def test_spread_across_uses_the_final_workload_selector_and_preserves_raw_constraints
    workload = build(<<~RUBY).first
      deployment :api do
        spread_across "topology.kubernetes.io/zone"
        spread_across "topology.kubernetes.io/zone", max_skew: 2, when_unsatisfiable: :schedule_anyway
        pod { topology_spread_constraints [{topology_key: "rack", max_skew: 1, when_unsatisfiable: "ScheduleAnyway"}] }
        selector match_expressions: [{key: "tier", operator: "In", values: ["api"]}]
        template { metadata labels: {tier: "api", revision: "blue"} }
        container :api, image: "example"
      end
    RUBY
    raw, hard, soft = workload.dig("spec", "template", "spec", "topologySpreadConstraints")

    assert_equal({"topologyKey" => "rack", "maxSkew" => 1, "whenUnsatisfiable" => "ScheduleAnyway"}, raw)
    assert_equal({"topologyKey" => "topology.kubernetes.io/zone", "maxSkew" => 1, "whenUnsatisfiable" => "DoNotSchedule",
                  "labelSelector" => workload.dig("spec", "selector")}, hard)
    assert_equal hard.merge("maxSkew" => 2, "whenUnsatisfiable" => "ScheduleAnyway"), soft
    pod = build('pod(:worker, labels: {app: "worker"}) { spread_across :rack }').first

    assert_equal({"matchLabels" => {"app" => "worker"}}, pod.dig("spec", "topologySpreadConstraints", 0, "labelSelector"))
  end

  def test_spread_across_reports_the_constraint_at_its_ruby_line
    manifest = "deployment :web do\n  container :app, image: 'example'\n  spread_across :rack%s\nend"

    assert_match(/app.rb:3: spread_across max_skew/, error_of(format(manifest, ", max_skew: 0")))
    assert_match(/app.rb:3: spread_across max_skew/, error_of(format(manifest, ", max_skew: 2147483648")))
    assert_match(/app.rb:3: spread_across when_unsatisfiable/, error_of(format(manifest, ", when_unsatisfiable: :unknown")))
    duplicate = <<~RUBY
      deployment :web do
        container :app, image: "example"
        spread_across :rack
        pod { topology_spread_constraints [{topology_key: "rack", max_skew: 2, when_unsatisfiable: "DoNotSchedule"}] }
      end
    RUBY
    assert_match(/app.rb:3: duplicate topology spread constraint/, error_of(duplicate))
    assert_match(/app.rb:3: spread_across needs labels/, error_of(format(manifest, "").sub("deployment", "job")))
  end

  def test_anti_affinity_keeps_the_workloads_own_pods_apart
    deployment = build('deployment("web") { container "c", image: "x"; anti_affinity on: "kubernetes.io/hostname" }').first
    terms = deployment.dig("spec", "template", "spec", "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution")

    assert_equal [{"labelSelector" => {"matchLabels" => {"app" => "web"}}, "topologyKey" => "kubernetes.io/hostname"}], terms
    assert_match(/anti_affinity needs labels on the Pods/, error_of('job("once") { container "c", image: "x"; anti_affinity on: "zone" }'))
  end

  def test_anti_affinity_uses_the_complete_controller_selector
    [true, false].each do |with_labels|
      workload = build(<<~RUBY).first
        deployment "worker" do
          anti_affinity on: "kubernetes.io/hostname"
          selector match_expressions: [{key: "tier", operator: "In", values: ["worker"]}]#{', match_labels: {app: "queue"}' if with_labels}
          template metadata: {labels: {tier: "worker", revision: "blue"}}
          container "worker", image: "example"
        end
      RUBY
      spec = workload.fetch("spec")
      term = spec.dig("template", "spec", "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution", 0)

      assert_equal spec.fetch("selector"), term.fetch("labelSelector")
    end

    rc = build(<<~RUBY).first
      replication_controller "queue" do
        template metadata: {labels: {app: "queue", version: "v2"}}
        selector app: "queue"
        anti_affinity on: "rack"
        container "queue", image: "example"
      end
    RUBY
    term = rc.dig("spec", "template", "spec", "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution", 0)

    assert_equal({"matchLabels" => {"app" => "queue"}}, term.fetch("labelSelector"))
  end

  def test_anti_affinity_reports_invalid_terms_at_their_declarations
    source = "job \"work\" do\n  container \"c\", image: \"example\"\n  anti_affinity on: :rack\nend"

    assert_match(/app.rb:3: anti_affinity needs labels/, error_of(source))
    assert_match(%r{app.rb:3: invalid topology key "two/slashes/here"}, error_of(source.sub(":rack", '"two/slashes/here"')))
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

  def test_sidecars_keep_init_order_and_can_be_exposed_by_their_named_port
    app, service = build(<<~RUBY)
      app = deployment "web" do
        sidecar("proxy", image: "proxy:1") { port 8443, name: "https" }
        init_container "seed", image: "busybox"
        sidecar "logs", image: "logger:1", args: ["follow"]
        container "web", image: "web:1"
      end
      expose app, ports: {https: 443}
    RUBY
    init = app.dig("spec", "template", "spec", "initContainers")

    assert_equal(%w[proxy seed logs], init.map { |entry| entry.fetch("name") })
    assert_equal(["Always", nil, "Always"], init.map { |entry| entry["restartPolicy"] })
    assert_equal ["follow"], init.last.fetch("args")
    assert_equal "https", service.dig("spec", "ports", 0, "targetPort")
    assert_includes error_of('job("j") { sidecar("worker", image: "x") { restart_policy "Never" } }'),
                    'app.rb:1: sidecar "worker" requires restartPolicy Always'
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

  def test_namespace_blocks_apply_to_namespaced_resources_and_preserve_workload_references
    objects = build(<<~RUBY)
      web = in_namespace "preview" do
        namespace "preview"
        settings = config_map("settings") { data MODE: "test" }
        in_namespace "staging" do
          resource(api_version: "v1", kind: "ConfigMap", name: "stage")
          config_map "explicit", namespace: "shared"
        end
        deployment "web" do
          container "web", image: "web" do
            env "MODE", from: settings, key: :MODE
            port 8080, name: "http"
          end
        end
      end
      in_namespace "staging" do
        expose web, ports: {http: 80}
        autoscale web, replicas: 1..3, cpu: 70
      end
      config_map "outside"
    RUBY

    namespaces = objects.map { |object| object.dig("metadata", "namespace") }

    assert_equal [nil, "preview", "staging", "shared", "preview", "preview", "preview", nil], namespaces
    assert_equal "settings", objects[4].dig("spec", "template", "spec", "containers", 0, "env", 0, "valueFrom", "configMapKeyRef", "name")
    assert_equal(%w[Service HorizontalPodAutoscaler], objects.values_at(5, 6).map { |object| object.fetch("kind") })
  end

  def test_namespace_block_checks_references_and_keeps_an_unscoped_workloads_namespace
    message = error_of(<<~RUBY)
      cfg = in_namespace("shared") { config_map("settings") { data MODE: "test" } }
      in_namespace "preview" do
        pod "web" do
          container("web", image: "web") { env "MODE", from: cfg, key: :MODE }
        end
      end
    RUBY

    assert_includes message, 'app.rb:4: ConfigMap/settings is in namespace "shared", but this workload is in "preview"'

    _, service, hpa = build(<<~RUBY)
      web = deployment("web") { container("web", image: "web") { port 8080, name: "http" } }
      in_namespace "preview" do
        expose web, ports: {http: 80}
        autoscale web, replicas: 1..3, cpu: 70
      end
    RUBY

    [service, hpa].each { |object| refute object.fetch("metadata").key?("namespace") }
  end

  def test_expose_uses_the_workload_selector_named_ports_and_namespace
    deployment, service = build(<<~RUBY)
      app = deployment "backend", namespace: "team" do
        selector match_labels: {tier: "backend"}
        container "api", image: "web" do
          port 8181, name: "http"
          port 5353, name: "dns", protocol: "UDP"
        end
      end
      expose app, name: "public", ports: {http: 80, dns: 53}, type: "LoadBalancer"
    RUBY

    assert_equal %w[team public], service.fetch("metadata").values_at("namespace", "name")
    assert_equal deployment.dig("spec", "selector", "matchLabels"), service.dig("spec", "selector")
    assert_equal "LoadBalancer", service.dig("spec", "type")
    refute service.fetch("spec").key?("trafficDistribution")
    assert_equal [{"name" => "http", "port" => 80, "targetPort" => "http", "protocol" => "TCP"},
                  {"name" => "dns", "port" => 53, "targetPort" => "dns", "protocol" => "UDP"}], service.dig("spec", "ports")
  end

  def test_expose_selects_the_load_balancer_class_without_allocating_node_ports
    workload = 'app = deployment("web") { container("web", image: "test") { port 8080, name: "http" } }'
    _, service = build(<<~RUBY)
      #{workload}
      expose app, ports: {http: 80}, type: :load_balancer, load_balancer_class: "rubernetes.io/routed", allocate_node_ports: false
    RUBY

    assert_equal ["LoadBalancer", "rubernetes.io/routed", false], service.fetch("spec").values_at("type", "loadBalancerClass", "allocateLoadBalancerNodePorts")
    {"type: :node_port, allocate_node_ports: false" => "require a LoadBalancer Service",
     'type: :load_balancer, load_balancer_class: "bad name"' => "Kubernetes qualified name",
     "type: :load_balancer, allocate_node_ports: :no" => "must be true or false"}.each do |options, reason|
      message = error_of("#{workload}\nexpose app, ports: {http: 80}, #{options}")

      assert_includes message, reason
    end
  end

  def test_expose_uses_replication_controller_selectors_and_their_upstream_default
    [true, false].each do |explicit|
      _, service = build(<<~RUBY)
        app = replication_controller "api", namespace: "shop" do
          #{'selector tier: "backend"' if explicit}
          template metadata: {labels: {tier: "backend", version: "green"}}
          container("web", image: "app") { port 8080, name: "http" }
        end
        expose app, ports: {http: 80}
      RUBY
      labels = {"tier" => "backend"}
      labels["version"] = "green" unless explicit

      assert_equal labels, service.dig("spec", "selector")
      assert_equal "shop", service.dig("metadata", "namespace")
      assert_equal "http", service.dig("spec", "ports", 0, "targetPort")
    end
  end

  def test_expose_prefers_same_zone_or_node_endpoints
    _, same_zone, same_node = build(<<~RUBY)
      web = deployment "web" do
        container("api", image: "web") { port 8080, name: "http" }
      end
      expose web, ports: {http: 80}, prefer: :same_zone
      expose web, name: "local", ports: {http: 80}, prefer: :same_node
    RUBY

    assert_equal "PreferSameZone", same_zone.dig("spec", "trafficDistribution")
    assert_equal "PreferSameNode", same_node.dig("spec", "trafficDistribution")
  end

  def test_expose_reports_invalid_traffic_preference_at_its_ruby_line
    message = error_of(<<~RUBY)
      web = deployment "web" do
        container("api", image: "web") { port 8080, name: "http" }
      end
      expose web, ports: {http: 80}, prefer: :same_znoe
    RUBY

    assert_equal "app.rb:4: expose prefer: must be :same_zone or :same_node (got :same_znoe)", message
  end

  def test_expose_reports_misspelled_port_at_its_ruby_line
    message = error_of(<<~RUBY)
      app = deployment "web" do
        container("api", image: "web") { port 8080, name: "http" }
      end
      expose app, ports: {htp: 80}
    RUBY

    assert_includes message, 'app.rb:4: Deployment/web has no port named "htp"'
    assert_includes message, "Declared ports: http"
  end

  def test_expose_rejects_selectors_a_service_cannot_represent
    message = error_of(<<~RUBY)
      app = deployment "web" do
        selector match_labels: {tier: "api"}, match_expressions: [{key: "role", operator: "Exists"}]
        container("api", image: "web") { port 8080, name: "http" }
      end
      expose app, ports: {http: 80}
    RUBY

    assert_includes message, "Service selectors cannot express Deployment matchExpressions"
  end

  def test_expose_converts_label_expressions_only_when_they_select_one_value_per_key
    source = <<~RUBY
      app = deployment "web" do
        selector match_labels: {app: "web"}, match_expressions: [
          {key: "track", operator: "NotIn", values: ["canary"]},
          {key: "track", operator: "In", values: ["stable", "canary"]},
          {key: "track", operator: "Exists"}, {key: "app", operator: "In", values: ["web", "worker"]}]
        template metadata: {labels: {track: "stable", app: "web", release: "v2"}}
        container("api", image: "web") { port 8080, name: "http" }
      end
      expose app, ports: {http: 80}
    RUBY
    deployment, service = build(source)

    assert_equal({"app" => "web", "track" => "stable"}, service.dig("spec", "selector"))
    assert_equal({"app" => "web"}, deployment.dig("spec", "selector", "matchLabels"))
    assert_match(/cannot express Deployment matchExpressions for "track"/, error_of(source.sub('values: ["canary"]', 'values: ["other"]')))
    assert_match(/cannot express Deployment matchExpressions for "track"/, error_of(source.sub('operator: "Exists"', 'operator: "DoesNotExist"')))
    assert_match(/selector does not match its Pod labels/, error_of(source.sub('track: "stable"', 'track: "canary"')))
  end

  def test_autoscale_projects_a_ruby_range_and_workload_reference_into_an_hpa
    workload, hpa = build(<<~RUBY)
      app = stateful_set("db", namespace: "team") { container("db", image: "test") }
      autoscale app, replicas: 2...6, cpu: 125, memory: 70, name: "load"
    RUBY

    assert_equal %w[autoscaling/v2 HorizontalPodAutoscaler], hpa.values_at("apiVersion", "kind")
    assert_equal %w[team load], hpa.fetch("metadata").values_at("namespace", "name")
    assert_equal [2, 5], hpa.fetch("spec").values_at("minReplicas", "maxReplicas")
    assert_equal({"apiVersion" => "apps/v1", "kind" => "StatefulSet", "name" => "db"}, hpa.dig("spec", "scaleTargetRef"))
    targets = hpa.dig("spec", "metrics").map do |metric|
      [metric.dig("resource", "name"), metric.dig("resource", "target", "averageUtilization")]
    end

    assert_equal [["cpu", 125], ["memory", 70]], targets
    refute workload.fetch("spec").key?("replicas")
  end

  def test_autoscale_reports_invalid_targets_and_bounds_at_the_declaration
    unsupported = error_of("app = daemon_set('d')\nautoscale app, replicas: 1..3, cpu: 70")

    assert_includes unsupported, "app.rb:2: DaemonSet does not declare a writable scale subresource"
    ["0..3", "3...3", "(1..)", "1.5..2"].each do |range|
      assert_includes error_of("autoscale deployment('d'), replicas: #{range}, cpu: 70"), "app.rb:1: autoscale replicas"
    end
    assert_includes error_of("autoscale deployment('d'), replicas: 1..2"), "needs a target utilization"
  end

  def test_autoscale_can_track_a_single_running_container
    source = <<~RUBY
      web = deployment "shop" do
        init_container "setup", image: "setup:1"
        sidecar "proxy", image: "proxy:1"
        container "api", image: "app:1"
      end
    RUBY
    _, hpa, sidecar = build(source + <<~RUBY)
      autoscale web, container: :api, replicas: 2..8, cpu: 70, memory: 60
      autoscale web, container: "proxy", replicas: 1..2, memory: 85, name: "proxy-load"
    RUBY

    metrics = hpa.dig("spec", "metrics")
    targets = metrics.map do |metric|
      resource = metric.fetch("containerResource")
      [*resource.values_at("name", "container"), resource.dig("target", "averageUtilization")]
    end

    assert_equal(%w[ContainerResource ContainerResource], metrics.map { |metric| metric.fetch("type") })
    assert_equal [["cpu", "api", 70], ["memory", "api", 60]], targets
    assert_equal "proxy", sidecar.dig("spec", "metrics", 0, "containerResource", "container")
    %w[setup typo].each do |name|
      assert_includes error_of(source + "autoscale web, container: :#{name}, replicas: 1..2, cpu: 75"),
                      "app.rb:6: autoscale cannot target container :#{name} in Deployment/shop. Running containers: api, proxy"
    end
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

  def test_rendered_json_round_trips_multiple_objects_through_standard_input
    json = StringIO.new
    cli = Rubernetes::Rubectl::CLI.new(stdout: json, stderr: StringIO.new, sandbox: FixedSandbox.new)

    assert_equal 0, cli.run(%w[render -f app.rb --allow-code])
    assert_equal "List", JSON.parse(json.string).fetch("kind")
    yaml = StringIO.new
    rerender = Rubernetes::Rubectl::CLI.new(stdin: StringIO.new(json.string), stdout: yaml, stderr: StringIO.new)

    assert_equal 0, rerender.run(%w[render -f - -o yaml])
    assert_equal(%w[ConfigMap Service], YAML.load_stream(yaml.string).map { |object| object.fetch("kind") })
  end
end
