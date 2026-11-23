# frozen_string_literal: true

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/storage/memory_store"

# A custom resource with selectableFields that differ between versions is
# stored in one version and served in another, so the store cannot apply the
# field selector: list, watch and DeleteCollection all have to match the
# converted object ("[sig-api-machinery] CustomResourceFieldSelectors MUST list
# and watch custom resources matching the field selector").
class CustomResourceFieldSelectorTest < Minitest::Test
  def setup
    require "json"
    require "rubernetes/api"
    require "rubernetes/storage/memory_store"
    @store = store = Rubernetes::Storage::MemoryStore.new(history_revisions: nil, history_seconds: nil)
    registry = Rubernetes::API::Registry.new(resources: [], defaults: false)
    registry.register(Rubernetes::API::Resource.new(group: "apiextensions.k8s.io", version: "v1", resource: "customresourcedefinitions",
                                                    kind: "CustomResourceDefinition", scope: :cluster, subresources: [{resource: "status",
                                                                                                                       verbs: %w[get patch update]}]))
    registry.register(Rubernetes::API::Resource.new(group: "", version: "v1", resource: "namespaces", kind: "Namespace", scope: :cluster))
    converter = lambda do |_config, review, timeout_seconds: 30|
      req = review["request"]
      to = req["desiredAPIVersion"]
      objs = req["objects"].map do |o|
        o = JSON.parse(JSON.generate(o))
        if to.end_with?("/v2") && o.key?("hostPort")
          h, p = o.delete("hostPort").split(":", 2)
          o["host"] = h
          o["port"] = p if p
        elsif to.end_with?("/v1") && o.key?("host")
          o["hostPort"] = [o.delete("host"), o.delete("port")].compact.join(":")
        end
        o["apiVersion"] = to
        o
      end
      [200, {"response" => {"uid" => req["uid"], "result" => {"status" => "Success"}, "convertedObjects" => objs}}]
    end
    openapi = Rubernetes::API::OpenAPIRepository.new
    mgr = Rubernetes::API::CRD::Manager.new(registry: registry, store: store, openapi: openapi, webhook_client: converter)
    server = Rubernetes::API::Server.new(registry: registry, store: store, crd_manager: mgr, openapi_repository: openapi)
    @call = lambda do |m, path, body = nil|
      server.call(Rubernetes::API::Request.new(method: m, path: path, headers: body ? {"content-type" => "application/json"} : {},
                                               body: body && JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
    end
    @call.call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "ns"}})
    v = lambda { |name, storage, props, sel|
      {"name" => name, "served" => true, "storage" => storage,
       "schema" => {"openAPIV3Schema" => {"type" => "object", "properties" => props.to_h do |k|
         [k, {"type" => "string"}]
       end}},
       "selectableFields" => sel.map { |s| {"jsonPath" => s} }}
    }
    {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "es.example.com"},
     "spec" => {"group" => "example.com", "scope" => "Namespaced", "names" => {"plural" => "es", "singular" => "e", "kind" => "E", "listKind" => "EList"},
                "conversion" => {"strategy" => "Webhook", "webhook" => {"clientConfig" => {"url" => "https://x"}, "conversionReviewVersions" => ["v1"]}},
                "versions" => [v.call("v1", true, %w[hostPort], %w[.hostPort]), v.call("v2", false, %w[host port], %w[.host .port])]}}

    crd = {"apiVersion" => "apiextensions.k8s.io/v1", "kind" => "CustomResourceDefinition", "metadata" => {"name" => "es.example.com"},
           "spec" => {"group" => "example.com", "scope" => "Namespaced", "names" => {"plural" => "es", "singular" => "e", "kind" => "E", "listKind" => "EList"},
                      "conversion" => {"strategy" => "Webhook", "webhook" => {"clientConfig" => {"url" => "https://x"}, "conversionReviewVersions" => ["v1"]}},
                      "versions" => [v.call("v1", true, %w[hostPort], %w[.hostPort]), v.call("v2", false, %w[host port], %w[.host .port])]}}

    status = @call.call("POST", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", crd).status
    raise "setup: CRD create returned #{status}" unless status == 201

    deadline = Time.now + 5
    sleep 0.05 until @call.call("GET", "/apis/example.com/v2/namespaces/ns/es").status == 200 || Time.now > deadline

    [{"host" => "host1", "port" => "80"}, {"host" => "host1", "port" => "8080"}, {"host" => "host2"}].each_with_index do |spec, i|
      status = @call.call("POST", "/apis/example.com/v2/namespaces/ns/es",
                          {"apiVersion" => "example.com/v2", "kind" => "E", "metadata" => {"name" => "cr#{i}"}}.merge(spec)).status
      raise "setup: custom resource create returned #{status}" unless status == 201
    end
  end

  def names(path)
    response = @call.call("GET", path)

    assert_equal 200, response.status
    response.body["items"].map { |item| item["metadata"]["name"] }.sort
  end

  def test_list_matches_the_served_version
    assert_equal %w[cr0 cr1], names("/apis/example.com/v2/namespaces/ns/es?fieldSelector=host=host1")
    assert_equal %w[cr0], names("/apis/example.com/v2/namespaces/ns/es?fieldSelector=host=host1,port=80")
    assert_equal %w[cr0], names("/apis/example.com/v1/namespaces/ns/es?fieldSelector=hostPort=host1:80")
  end

  def test_paginated_list_counts_matches_in_the_served_version
    path = "/apis/example.com/v2/namespaces/ns/es"
    {"a" => "other", "cr3" => "host1"}.each do |name, host|
      response = @call.call("POST", path, {"apiVersion" => "example.com/v2", "kind" => "E",
                                           "metadata" => {"name" => name}, "host" => host, "port" => "80"})

      assert_equal 201, response.status
    end
    query = "#{path}?limit=2&fieldSelector=host=host1"
    first = @call.call("GET", query).body
    token = first.fetch("metadata").fetch("continue")
    second = @call.call("GET", "#{query}&continue=#{token}").body

    assert_equal(%w[cr0 cr1], first.fetch("items").map { |object| object.dig("metadata", "name") })
    assert_equal(["cr3"], second.fetch("items").map { |object| object.dig("metadata", "name") })
    assert_equal first.dig("metadata", "resourceVersion"), second.dig("metadata", "resourceVersion")
    assert_empty second.dig("metadata", "continue").to_s
    [first, second].each { |page| refute page.fetch("metadata").key?("remainingItemCount") }
  end

  def test_watch_replays_selector_transitions_from_the_given_revision
    path = "/apis/example.com/v2/namespaces/ns/es"
    cursor = @call.call("GET", path).body.dig("metadata", "resourceVersion")
    revisions = %w[cr1 other cr2 host1].each_slice(2).map do |name, host|
      current = @call.call("GET", "#{path}/#{name}").body
      changed = @call.call("PUT", "#{path}/#{name}", current.merge("host" => host))

      assert_equal 200, changed.status

      changed.body.dig("metadata", "resourceVersion")
    end
    expected = [["DELETED", "cr1", "host1", revisions[0]], ["ADDED", "cr2", "host1", revisions[1]]]
    url = "#{path}?watch=1&fieldSelector=host=host1&resourceVersion=#{cursor}&timeoutSeconds=1"
    ["", "&sendInitialEvents=false&resourceVersionMatch=NotOlderThan"].each do |options|
      response = @call.call("GET", url + options)

      assert_equal expected, watch_events(response.body)
    ensure
      response&.body&.close
    end
  end

  def test_watch_without_initial_events_at_zero_uses_the_current_selector_state
    path = "/apis/example.com/v2/namespaces/ns/es"
    query = "watch=1&fieldSelector=host=host1&resourceVersion=0&" \
            "sendInitialEvents=false&resourceVersionMatch=NotOlderThan&timeoutSeconds=1"
    response = @call.call("GET", "#{path}?#{query}")

    assert_equal 200, response.status

    current = @call.call("GET", "#{path}/cr1").body
    changed = @call.call("PUT", "#{path}/cr1", current.merge("host" => "other"))

    assert_equal 200, changed.status
    assert_equal [["DELETED", "cr1", "host1", changed.body.dig("metadata", "resourceVersion")]], watch_events(response.body)
  ensure
    response&.body&.close
  end

  def watch_events(stream)
    stream.each_json_line(timeout: 1).map do |line|
      type, object = JSON.parse(line).values_at("type", "object")
      [type, object.dig("metadata", "name"), object["host"], object.dig("metadata", "resourceVersion")]
    end
  end

  def test_watch_converts_and_reports_selector_transitions
    rv = @call.call("GET", "/apis/example.com/v2/namespaces/ns/es").body["metadata"]["resourceVersion"]
    watch = @call.call("GET",
                       "/apis/example.com/v2/namespaces/ns/es?watch=1&fieldSelector=host=host1&resourceVersion=#{rv}&timeoutSeconds=2").body
    reader = Thread.new do
      lines = []
      watch.each_json_line(timeout: 2) { |line| lines << JSON.parse(line) }
      lines
    end
    sleep 0.2
    %w[cr1 host3 cr2 host1].each_slice(2) do |name, host|
      current = @call.call("GET", "/apis/example.com/v2/namespaces/ns/es/#{name}").body
      current["host"] = host

      assert_equal 200, @call.call("PUT", "/apis/example.com/v2/namespaces/ns/es/#{name}", current).status
    end
    assert_equal 200, @call.call("DELETE", "/apis/example.com/v2/namespaces/ns/es?fieldSelector=host=host1").status
    assert_equal([%w[cr1 host3]], @call.call("GET", "/apis/example.com/v2/namespaces/ns/es").body["items"].map do |i|
      [i["metadata"]["name"], i["host"]]
    end)

    events = reader.value.map { |event| [event["type"], event["object"]["metadata"]["name"], event["object"]["apiVersion"]] }

    assert_equal [["DELETED", "cr1", "example.com/v2"], ["ADDED", "cr2", "example.com/v2"]], events.first(2)
    assert_equal [%w[DELETED cr0], %w[DELETED cr2]], events.drop(2).map { |t, n, _| [t, n] }.sort_by(&:last)
  end
end
