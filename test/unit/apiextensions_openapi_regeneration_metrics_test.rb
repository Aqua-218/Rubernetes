# frozen_string_literal: true

# apiextensions_openapi_v2_regeneration_count{crd,reason} and
# apiextensions_openapi_v3_regeneration_count{crd,group,version,reason}:
# upstream's CRD OpenAPI controllers create (never increment) a series per
# add, update and removal -- v2 per CRD on every sync, v3 per served
# group/version whose spec changed ("add" when the group/version had none).

require_relative "../test_helper"
require "rubernetes/api"

class ApiextensionsOpenAPIRegenerationMetricsTest < Minitest::Test
  API = Rubernetes::API

  def setup
    @metrics = Rubernetes::Observability::Metrics.new
    @previous = API::CRD.metrics
    API::CRD.metrics = @metrics
    @manager = API::CRD::Manager.new(registry: API::Registry.new(resources: [], defaults: false),
                                     store: Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil),
                                     openapi: API::OpenAPIRepository.new)
  end

  def teardown
    API::CRD.metrics = @previous
  end

  def crd(plural, versions, description: "a")
    schema = {"openAPIV3Schema" => {"type" => "object", "description" => description, "x-kubernetes-preserve-unknown-fields" => true}}
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "#{plural}.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced",
                "names" => {"plural" => plural, "singular" => plural.chomp("s"), "kind" => plural.capitalize.chomp("s"), "listKind" => "#{plural.capitalize}List"},
                "versions" => versions.map { |name| {"name" => name, "served" => true, "storage" => name == versions.first, "schema" => schema} }}}
  end

  def series(name) = @metrics.render.lines.grep(/\A#{name}\{/).map(&:strip)

  def test_add_update_and_remove
    @manager.sync(crd("widgets", %w[v1]))
    @manager.sync(crd("gadgets", %w[v1 v2]))
    @manager.sync(crd("widgets", %w[v1], description: "b"))
    @manager.withdraw("gadgets.example.com")

    assert_equal [%(apiextensions_openapi_v2_regeneration_count{crd="widgets.example.com",reason="add"} 0),
                  %(apiextensions_openapi_v2_regeneration_count{crd="gadgets.example.com",reason="add"} 0),
                  %(apiextensions_openapi_v2_regeneration_count{crd="widgets.example.com",reason="update"} 0),
                  %(apiextensions_openapi_v2_regeneration_count{crd="gadgets.example.com",reason="remove"} 0)],
                 series("apiextensions_openapi_v2_regeneration_count")
    v3 = series("apiextensions_openapi_v3_regeneration_count")
    assert_includes v3, %(apiextensions_openapi_v3_regeneration_count{crd="widgets.example.com",group="example.com",reason="add",version="v1"} 0)
    # example.com/v1 already had widgets' spec; v2 was new.
    assert_includes v3, %(apiextensions_openapi_v3_regeneration_count{crd="gadgets.example.com",group="example.com",reason="update",version="v1"} 0)
    assert_includes v3, %(apiextensions_openapi_v3_regeneration_count{crd="gadgets.example.com",group="example.com",reason="add",version="v2"} 0)
    assert_includes v3, %(apiextensions_openapi_v3_regeneration_count{crd="widgets.example.com",group="example.com",reason="update",version="v1"} 0)
    assert_includes v3, %(apiextensions_openapi_v3_regeneration_count{crd="gadgets.example.com",group="example.com",reason="remove",version="v2"} 0)
    assert_equal 6, v3.length
  end

  def test_an_unchanged_resync_is_an_update_for_v2_only
    @manager.sync(crd("widgets", %w[v1]))
    @manager.sync(crd("widgets", %w[v1]))
    assert_includes series("apiextensions_openapi_v2_regeneration_count"),
                    %(apiextensions_openapi_v2_regeneration_count{crd="widgets.example.com",reason="update"} 0)
    assert_equal 1, series("apiextensions_openapi_v3_regeneration_count").length
  end
end
