# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"

# A graceful DELETE of a Pod bumps metadata.generation
# (registry/core/pod/strategy.go, PodObservedGenerationTracking).
class APIPodGenerationDeleteTest < Minitest::Test
  API = Rubernetes::API

  def call(method, path, body = nil)
    @server.call(API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                  body: body && JSON.generate(body),
                                  identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def test_terminating_pod_survives_updates_and_repeated_delete_until_force
    @server = API::Server.new(store: Rubernetes::Storage::MemoryStore.new)
    path = "/api/v1/namespaces/ns/pods"
    pod = {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "grace"},
           "spec" => {"nodeName" => "worker", "containers" => [{"name" => "app", "image" => "example:1"}]}}
    created = call("POST", path, pod)
    member = "#{path}/grace"
    initial = call("DELETE", member, {"gracePeriodSeconds" => 60})

    assert_equal 201, created.status
    assert_equal 60, initial.body.dig("metadata", "deletionGracePeriodSeconds")
    update = initial.body.merge("metadata" => initial.body["metadata"].merge("labels" => {"stage" => "terminating"}))

    assert_equal 200, call("PUT", member, update).status
    pending = call("GET", member)

    assert_equal "terminating", pending.body.dig("metadata", "labels", "stage")
    assert_equal pending.body, call("DELETE", member).body
    assert_equal pending.body, call("DELETE", member, {"gracePeriodSeconds" => 90}).body
    shorter = {"gracePeriodSeconds" => 15}
    preview = call("DELETE", member, shorter.merge("dryRun" => ["All"]))

    assert_equal 15, preview.body.dig("metadata", "deletionGracePeriodSeconds")
    assert_equal pending.body, call("GET", member).body
    shortened = call("DELETE", member, shorter)

    assert_equal preview.body.dig("metadata", "deletionTimestamp"), shortened.body.dig("metadata", "deletionTimestamp")
    assert_equal initial.body.dig("metadata", "generation"), shortened.body.dig("metadata", "generation")
    watch = call("GET", "#{path}?watch=true&resourceVersion=#{shortened.body.dig("metadata", "resourceVersion")}")
    removed = call("DELETE", member, {"gracePeriodSeconds" => 0})
    events = watch.body.to_a

    assert_equal 0, removed.body.dig("metadata", "deletionGracePeriodSeconds")
    assert_equal %w[MODIFIED DELETED], events.map(&:type)
    assert_equal events.last.object, removed.body
    assert_equal 404, call("GET", member).status
  end

  def test_graceful_delete_bumps_the_generation
    @server = API::Server.new(store: Rubernetes::Storage::MemoryStore.new)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
    created = call("POST", "/api/v1/namespaces/ns/pods",
                   {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "p", "generation" => 100},
                    "spec" => {"nodeName" => "n1", "containers" => [{"name" => "c", "image" => "x"}]}})

    assert_equal 1, created.body.dig("metadata", "generation")

    deleted = call("DELETE", "/api/v1/namespaces/ns/pods/p?gracePeriodSeconds=60")

    assert_equal 200, deleted.status
    assert_equal 2, call("GET", "/api/v1/namespaces/ns/pods/p").body.dig("metadata", "generation")
  end

  def test_negative_pod_grace_is_normalized_on_create_and_update
    @server = API::Server.new
    path = "/api/v1/namespaces/ns/pods"
    pod = grace_pod("grace", -4)
    created = call("POST", path, pod)

    assert_equal 201, created.status, created.body.inspect
    assert_equal 1, created.body.dig("spec", "terminationGracePeriodSeconds")

    update = created.body.merge("spec" => created.body.fetch("spec").merge("terminationGracePeriodSeconds" => -3))
    updated = call("PUT", "#{path}/grace", update)

    assert_equal 200, updated.status, updated.body.inspect
    assert_equal 1, call("GET", "#{path}/grace").body.dig("spec", "terminationGracePeriodSeconds")

    zero = call("POST", path, grace_pod("zero", 0))

    assert_equal 0, zero.body.dig("spec", "terminationGracePeriodSeconds")
  end

  def test_legacy_negative_grace_is_normalized_in_get_list_and_watch
    registry = API::Registry.new
    store = API::MemoryStore.new
    @server = API::Server.new(registry: registry, store: store)
    resource = registry.find_gvr(group: "", version: "v1", resource: "pods")
    path = "/api/v1/namespaces/ns/pods"
    watch = call("GET", "#{path}?watch=true&timeoutSeconds=1")
    store.create(gvr: resource.gvr, namespace: "ns", object: grace_pod("legacy", -7))

    assert_equal 1, call("GET", "#{path}/legacy").body.dig("spec", "terminationGracePeriodSeconds")
    assert_equal 1, call("GET", path).body.fetch("items").first.dig("spec", "terminationGracePeriodSeconds")
    assert_equal 1, watch.body.next(timeout: 1).object.dig("spec", "terminationGracePeriodSeconds")
  ensure
    watch&.body&.close
  end

  def test_pod_template_retains_its_negative_grace
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry)
    template = {"apiVersion" => "v1", "kind" => "PodTemplate", "metadata" => {"name" => "legacy"},
                "template" => {"spec" => grace_pod("legacy", -5).fetch("spec")}}
    created = call("POST", "/api/v1/namespaces/ns/podtemplates", template)

    assert_equal 201, created.status, created.body.inspect
    assert_equal(-5, created.body.dig("template", "spec", "terminationGracePeriodSeconds"))
  end

  def grace_pod(name, grace)
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => name},
     "spec" => {"terminationGracePeriodSeconds" => grace, "containers" => [{"name" => "c", "image" => "busybox"}]}}
  end
end
