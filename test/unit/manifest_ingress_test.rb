# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/manifest/builder"

class ManifestIngressTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  Manifest = Rubernetes::Manifest

  def test_uses_an_exposed_service_name_and_namespace_across_blocks
    builder = new_builder
    _, service, route = builder.evaluate(<<~RUBY, "app.rb")
      frontend = in_namespace "apps" do
        web = deployment("web") { container("app", image: "nginx") { port 8080, name: "http" } }
        expose web, ports: {http: 80}, name: "frontend"
      end
      in_namespace "elsewhere" do
        ingress_for frontend, host: "*.example.test", port: :http, class_name: "example.nginx"
      end
    RUBY

    assert_equal %w[networking.k8s.io/v1 Ingress], route.values_at("apiVersion", "kind")
    assert_equal service["metadata"], route["metadata"]
    assert_equal "example.nginx", route.dig("spec", "ingressClassName")
    assert_equal "*.example.test", route.dig("spec", "rules", 0, "host")
    assert_equal({"path" => "/", "pathType" => "Prefix", "backend" => {"service" => {"name" => "frontend", "port" => {"name" => "http"}}}}, path(route))
    assert_equal [2, 3, 6], builder.declaration_lines
  end

  def test_infers_single_tcp_service_ports_and_preserves_unscoped_service_namespace
    _, numeric, _, named = build(<<~RUBY)
      web = service("web") { ports [{port: 80, target_port: 8080}] }
      in_namespace("unrelated") { ingress_for web, host: "web.example.test" }
      metrics = service("metrics") { ports [{name: "http", port: 80}] }
      ingress_for metrics, host: "metrics.example.test", path: "/live", path_type: :exact
    RUBY

    refute numeric["metadata"].key?("namespace")
    refute numeric["spec"].key?("ingressClassName")
    assert_equal({"number" => 80}, path(numeric).dig("backend", "service", "port"))
    assert_equal ["/live", "Exact"], path(named).values_at("path", "pathType")
    assert_equal({"name" => "http"}, path(named).dig("backend", "service", "port"))
  end

  def test_uses_explicit_service_port_number_and_keeps_the_generic_ingress_dsl
    _, route, generic = build(<<~RUBY)
      web = service("web") { ports [{name: "http", port: 80, target_port: 8080}, {name: "dns", port: 53, protocol: "UDP"}] }
      ingress_for web, host: "web.example.test", port: 80, path_type: "Exact"
      ingress "fallback" do
        default_backend service: {name: "web", port: {number: 80}}
      end
    RUBY

    assert_equal({"number" => 80}, path(route).dig("backend", "service", "port"))
    assert_equal({"service" => {"name" => "web", "port" => {"number" => 80}}}, generic.dig("spec", "defaultBackend"))
  end

  def test_reports_port_defaults_and_mismatches_at_the_helper_line
    source = <<~RUBY
      web = service "web" do
        ports [{name: "http", port: 80, target_port: 8080}, {name: "dns", port: 53, protocol: "UDP"}]
      end
    RUBY
    omitted = error_of(source + 'ingress_for web, host: "web.example.test"')

    assert_includes omitted, "app.rb:4: Service/web has multiple ports."
    assert_includes omitted, "Available TCP ports are http (80)"
    %w[:dns 8080 :htp].each do |selection|
      message = error_of(source + "ingress_for web, host: 'web.example.test', port: #{selection}")

      assert_includes message, "app.rb:4: Service/web has no TCP Service port"
      assert_includes message, "Available TCP ports are http (80)"
    end
  end

  def test_rejects_undeclared_references_and_non_tcp_services
    assert_includes error_of(<<~RUBY), "app.rb:2: ingress_for expects a Service declared in this manifest"
      web = service("web") { ports [{port: 80}] }
      ingress_for web.dup, host: "web.example.test"
    RUBY
    assert_includes error_of(<<~RUBY), "app.rb:2: ingress_for expects a Service declared in this manifest"
      workload = pod("web") { container("web", image: "nginx") }
      ingress_for workload, host: "web.example.test"
    RUBY
    assert_includes error_of(<<~RUBY), "app.rb:2: Service/dns has no TCP Service ports"
      dns = service("dns") { ports [{port: 53, protocol: "UDP"}] }
      ingress_for dns, host: "dns.example.test"
    RUBY
  end

  def test_rejects_invalid_hosts_paths_classes_and_path_types
    source = 'web = service("web") { ports [{port: 80}] }' + "\n"
    inputs = {
      'host: "https://web.example.test"' => "invalid ingress_for host",
      'host: "192.000.2.1"' => "must be a DNS name",
      'host: "*.*.example.test"' => "invalid ingress_for host",
      'host: "web.example.test", path: "admin"' => "must be an absolute path",
      'host: "web.example.test", path: "/a%2fb"' => "must not contain",
      'host: "web.example.test", path: "/a/.."' => "cannot end with",
      'host: "web.example.test", class_name: "NGINX"' => "invalid ingress_for class_name",
      'host: "web.example.test", path_type: "ImplementationSpecific"' => "must be Prefix or Exact"
    }
    inputs.each do |options, expected|
      message = error_of(source + "ingress_for web, #{options}")

      assert_includes message, "app.rb:2:"
      assert_includes message, expected
    end
  end

  def self.schema_inputs
    @schema_inputs ||= [JSON.parse(File.binread(File.join(ROOT, "generated/schema/registry.json")), max_nesting: 512),
                        JSON.parse(File.binread(File.join(ROOT, "generated/openapi/v2.json")), max_nesting: 512).fetch("definitions")]
  end

  private

  def new_builder
    registry, definitions = self.class.schema_inputs
    Manifest::Builder.new(registry: registry, definitions: definitions)
  end

  def build(source) = new_builder.evaluate(source, "app.rb")
  def error_of(source) = assert_raises(Manifest::Error) { build(source) }.message
  def path(ingress) = ingress.dig("spec", "rules", 0, "http", "paths", 0)
end
