# frozen_string_literal: true

# fieldmanager.FieldManager.Update (k8s.io/apimachinery managedfields,
# v1.36.2) for writes that are not an apply: the updater owns only the fields
# it changed, those leave every other manager, client-sent managedFields
# [] or [{}] reset the set (and an existing object that has none is not
# tracked again until an apply), and Update managers are capped at ten with
# the oldest merged into "ancient-changes".

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"

class FieldManagerUpdateTest < Minitest::Test
  API = Rubernetes::API
  MF = Rubernetes::API::ManagedFields

  def setup
    @now = Time.utc(2026, 1, 1)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = API::Server.new(registry: registry,
                              store: API::MemoryStore.new(clock: -> { @now }), clock: -> { @now })
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
  end

  def call(method, path, body = nil, content_type: "application/json", manager: nil)
    path = "#{path}?fieldManager=#{manager}" if manager
    headers = body ? {"content-type" => content_type} : {}
    response = @server.call(API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body),
                                             identity: {"username" => "admin", "groups" => ["system:masters"]}))
    body = response.body
    body = body.is_a?(Hash) ? Marshal.load(Marshal.dump(body)) : JSON.parse(Array(body).join)
    [response.status, body]
  end

  def owned(object)
    Array(object.dig("metadata", "managedFields")).to_h do |entry|
      paths = MF::FieldPath::Set.from_fields_v1(entry["fieldsV1"]).each_path.map do |path|
        path.map { |element| element.field? ? element.data : element.serialize }
      end
      [[entry["manager"], entry["subresource"]].compact.join("/"), paths.sort]
    end
  end

  def configmap_path = "/api/v1/namespaces/team/configmaps/cm"

  def create_configmap
    status, = call("POST", "/api/v1/namespaces/team/configmaps",
                   {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm", "labels" => {"a" => "1"}},
                    "data" => {"x" => "1", "y" => "2"}}, manager: "creator")
    assert_equal 201, status
  end

  def test_an_update_owns_only_what_it_changed_and_takes_it_from_others
    create_configmap
    _, current = call("GET", configmap_path)
    # Maps the create added are owned themselves too ("." in FieldsV1).
    assert_equal [%w[data], %w[data x], %w[data y], %w[metadata labels], %w[metadata labels a]], owned(current)["creator"]

    current["data"]["x"] = "changed"
    status, updated = call("PUT", configmap_path, current, manager: "editor")
    assert_equal 200, status
    assert_equal [%w[data x]], owned(updated)["editor"]
    assert_equal [%w[data], %w[data y], %w[metadata labels], %w[metadata labels a]], owned(updated)["creator"]

    status, patched = call("PATCH", configmap_path, {"data" => {"y" => "3"}, "metadata" => {"labels" => {"a" => "1"}}},
                           content_type: "application/merge-patch+json", manager: "patcher")
    assert_equal 200, status
    # The label was sent unchanged, so it stays the creator's.
    assert_equal [%w[data y]], owned(patched)["patcher"]
    assert_equal [%w[data], %w[metadata labels], %w[metadata labels a]], owned(patched)["creator"]
  end

  def test_a_manager_that_loses_every_field_is_dropped
    create_configmap
    status, patched = call("PATCH", configmap_path,
                           {"data" => nil, "metadata" => {"labels" => nil}},
                           content_type: "application/merge-patch+json", manager: "taker")
    assert_equal 200, status
    # Removing a field takes it from every manager; the remover owns nothing
    # it removed.
    assert_equal({}, owned(patched))
    assert_nil patched.dig("metadata", "managedFields")
  end

  def test_client_sent_managed_fields
    create_configmap
    _, current = call("GET", configmap_path)
    current["metadata"]["managedFields"] = [{}]
    _, stripped = call("PUT", configmap_path, current, manager: "editor")
    assert_nil stripped.dig("metadata", "managedFields")

    # An existing object without managed fields is not tracked by updates
    # (skipNonAppliedManager); [] resets exactly like [{}].
    stripped["data"]["x"] = "again"
    _, untracked = call("PUT", configmap_path, stripped, manager: "editor")
    assert_nil untracked.dig("metadata", "managedFields")

    # An apply starts tracking again: what was there before belongs to
    # before-first-apply.
    status, applied = call("PATCH", "#{configmap_path}", {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "cm"},
                                                           "data" => {"z" => "1"}},
                           content_type: "application/apply-patch+yaml", manager: "applier")
    assert_equal 200, status
    assert_equal [%w[data z]], owned(applied)["applier"]
    assert_equal [%w[data], %w[data x], %w[data y], %w[metadata labels], %w[metadata labels a]],
                 owned(applied)["before-first-apply"]

    applied["metadata"]["managedFields"] = []
    applied["data"]["x"] = "third"
    _, reset = call("PUT", configmap_path, applied, manager: "editor")
    assert_nil reset.dig("metadata", "managedFields")
  end

  def test_update_managers_are_capped_with_ancient_changes
    create_configmap
    12.times do |index|
      @now += 1
      status, = call("PATCH", configmap_path, {"data" => {"k#{index}" => "v"}},
                     content_type: "application/merge-patch+json", manager: "m#{index}")
      assert_equal 200, status
    end
    _, current = call("GET", configmap_path)
    managers = owned(current)
    assert_equal 10, managers.length
    assert_includes managers.keys, "ancient-changes"
    ancient = managers["ancient-changes"]
    assert_includes ancient, %w[data x]
    assert_includes ancient, %w[data k0]
    assert_includes ancient, %w[data k1]
    assert_equal [%w[data k11]], managers["m11"]
  end

  def test_status_and_scale_updates_record_their_subresource
    deployment = {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "d"},
                  "spec" => {"replicas" => 1, "selector" => {"matchLabels" => {"app" => "d"}},
                             "template" => {"metadata" => {"labels" => {"app" => "d"}},
                                            "spec" => {"containers" => [{"name" => "c", "image" => "i"}]}}}}
    status, created = call("POST", "/apis/apps/v1/namespaces/team/deployments", deployment, manager: "creator")
    assert_equal 201, status
    assert_includes owned(created)["creator"], %w[spec replicas]
    # Defaults applied at decode time belong to the creator; status never does.
    assert_includes owned(created)["creator"], %w[spec revisionHistoryLimit]
    assert(owned(created)["creator"].none? { |path| path.first == "status" })

    status, = call("PUT", "/apis/apps/v1/namespaces/team/deployments/d/scale",
                   {"apiVersion" => "autoscaling/v1", "kind" => "Scale", "metadata" => {"name" => "d", "namespace" => "team"},
                    "spec" => {"replicas" => 3}}, manager: "scaler")
    assert_equal 200, status
    _, scaled = call("GET", "/apis/apps/v1/namespaces/team/deployments/d")
    assert_equal [%w[spec replicas]], owned(scaled)["scaler/scale"]
    refute_includes owned(scaled)["creator"], %w[spec replicas]
    assert_equal "apps/v1", scaled["metadata"]["managedFields"].find { |entry| entry["manager"] == "scaler" }["apiVersion"]

    status, = call("PATCH", "/apis/apps/v1/namespaces/team/deployments/d/status", {"status" => {"observedGeneration" => 2}},
                   content_type: "application/merge-patch+json", manager: "controller")
    assert_equal 200, status
    _, reported = call("GET", "/apis/apps/v1/namespaces/team/deployments/d")
    assert_equal [%w[status], %w[status observedGeneration]], owned(reported)["controller/status"]
  end

  def test_an_update_that_changes_nothing_keeps_the_entries
    create_configmap
    _, current = call("GET", configmap_path)
    before = current.dig("metadata", "managedFields")
    @now += 60
    _, same = call("PUT", configmap_path, current, manager: "someone-else")
    assert_equal before, same.dig("metadata", "managedFields")
    assert_equal current.dig("metadata", "resourceVersion"), same.dig("metadata", "resourceVersion")
  end
end
