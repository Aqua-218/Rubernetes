# frozen_string_literal: true

require "json"
require "fileutils"
require "tmpdir"
require_relative "../test_helper"
require "rubernetes/api"

class APICoreTest < Minitest::Test
  def setup
    @server = Rubernetes::API::Server.new(
      registry: Rubernetes::API::Registry.new,
      store: Rubernetes::API::MemoryStore.new(uid_generator: -> { "fixed-uid" }, clock: -> { Time.utc(2026, 1, 1) }),
      namespace_lifecycle: true
    )
    # NamespaceLifecycle admission: namespaced objects need their namespace.
    status = call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev"}}).status
    raise "setup: namespace create returned #{status}" unless status == 201
  end

  def test_discovery_and_health_endpoints_are_available_without_transport
    assert_equal("v1.36.2", call("GET", "/version").body.fetch("gitVersion"))
    assert_includes(call("GET", "/api").body.fetch("versions"), "v1")
    assert_equal("APIGroupList", call("GET", "/apis").body.fetch("kind"))
    resource_list = call("GET", "/api/v1")

    assert_equal("APIResourceList", resource_list.body.fetch("kind"))
    assert(resource_list.body.fetch("resources").any? { |resource| resource.fetch("name") == "configmaps" })
    assert_equal("ok", call("GET", "/readyz").body)
  end

  def test_namespaced_crud_and_cluster_scoped_namespace_crud
    created = call("POST", "/api/v1/namespaces/dev/configmaps", {
                     "metadata" => {"name" => "settings", "labels" => {"app" => "demo"}},
                     "data" => {"feature" => "on"}
                   })

    assert_equal(201, created.status)
    assert_match(/\A[1-9][0-9]*\z/, created.body.dig("metadata", "resourceVersion"))
    assert_equal("dev", created.body.dig("metadata", "namespace"))
    assert_match(/\A[0-9a-f-]{36}\z/, created.body.dig("metadata", "uid"))
    assert(created.body.dig("metadata", "creationTimestamp"))

    fetched = call("GET", "/api/v1/namespaces/dev/configmaps/settings")

    assert_equal("settings", fetched.body.dig("metadata", "name"))
    listed = call("GET", "/api/v1/namespaces/dev/configmaps", query: {"labelSelector" => "app=demo"})

    assert_equal(["settings"], listed.body.fetch("items").map { |item| item.dig("metadata", "name") })

    deleted = call("DELETE", "/api/v1/namespaces/dev/configmaps/settings")

    assert_equal("Status", deleted.body.fetch("kind"))
    assert_equal("Success", deleted.body.fetch("status"))
    assert_equal("configmaps", deleted.body.dig("details", "kind"))
    assert_equal("settings", deleted.body.dig("details", "name"))

    namespace = call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "dev2"}})

    assert_equal(201, namespace.status)
    refute(namespace.body.dig("metadata", "namespace"))
    assert_equal(200, call("GET", "/api/v1/namespaces/dev2").status)
    assert_equal(404, call("POST", "/api/v1/namespaces/missing/configmaps", {"metadata" => {"name" => "x"}}).status)
  end

  def test_patch_formats_and_server_side_apply_ownership
    call("POST", "/api/v1/namespaces/dev/configmaps", {
           "metadata" => {"name" => "settings"}, "data" => {"one" => "1"}
         })
    merged = call("PATCH", "/api/v1/namespaces/dev/configmaps/settings", {"data" => {"two" => "2"}},
                  headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal(%w[one two], merged.body.fetch("data").keys.sort)

    patched = call("PATCH", "/api/v1/namespaces/dev/configmaps/settings",
                   [{"op" => "replace", "path" => "/data/one", "value" => "updated"}],
                   headers: {"Content-Type" => "application/json-patch+json"})

    assert_equal("updated", patched.body.dig("data", "one"))

    applied = call("PATCH", "/api/v1/namespaces/dev/configmaps/settings",
                   {"metadata" => {"name" => "settings"}, "data" => {"owned" => "yes"}},
                   query: {"fieldManager" => "test-manager"},
                   headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert(Array(applied.body.dig("metadata", "managedFields")).any? do |entry|
      entry["manager"] == "test-manager" && entry["operation"] == "Apply"
    end)

    conflict = call("PATCH", "/api/v1/namespaces/dev/configmaps/settings",
                    {"metadata" => {"name" => "settings"}, "data" => {"owned" => "no"}},
                    query: {"fieldManager" => "other-manager"},
                    headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(409, conflict.status)
    assert_equal("Conflict", conflict.body.fetch("reason"))
  end

  def test_finalizer_delays_physical_delete_and_watch_replays_changes
    call("POST", "/api/v1/namespaces/dev/configmaps", {
           "metadata" => {"name" => "protected", "finalizers" => ["example.test/cleanup"]}
         })
    watch = call("GET", "/api/v1/namespaces/dev/configmaps",
                 query: {"watch" => "true", "resourceVersion" => "0"})

    assert_equal(200, watch.status)

    deleting = call("DELETE", "/api/v1/namespaces/dev/configmaps/protected")

    assert(deleting.body.dig("metadata", "deletionTimestamp"))
    assert_equal(200, call("GET", "/api/v1/namespaces/dev/configmaps/protected").status)
    events = watch.body.to_a

    assert_equal(%w[ADDED MODIFIED], events.map(&:type))

    removed = call("PATCH", "/api/v1/namespaces/dev/configmaps/protected",
                   [{"op" => "remove", "path" => "/metadata/finalizers/0"}],
                   headers: {"Content-Type" => "application/json-patch+json"})

    assert_equal([], removed.body.dig("metadata", "finalizers"))
    # Removing the last finalizer from an object already marked for deletion
    # removes the OBJECT: registry/generic/registry/store.go
    # updateForGracefulDeletionAndFinalizers deletes immediately when "the
    # object has a deletionTimestamp and no finalizers".  Nobody sends a second
    # DELETE, and one sent anyway finds nothing left.
    assert_equal(404, call("GET", "/api/v1/namespaces/dev/configmaps/protected").status)
    assert_equal(404, call("DELETE", "/api/v1/namespaces/dev/configmaps/protected").status)
  end

  def test_status_errors_are_structured_and_do_not_expose_internal_class_names
    missing = call("GET", "/api/v1/namespaces/dev/configmaps/missing")

    assert_equal(404, missing.status)
    assert_equal("Status", missing.body.fetch("kind"))
    assert_equal("NotFound", missing.body.fetch("reason"))
    refute_includes(missing.body.fetch("message"), "MemoryStore")

    unsupported = call("PATCH", "/api/v1/namespaces/dev/configmaps/missing", {},
                       headers: {"Content-Type" => "application/cbor"})

    assert_equal(415, unsupported.status)
  end

  def test_json_patch_pointer_rules_are_strict_and_original_is_not_mutated
    original = {
      "data" => {"a/b" => "old", "t~key" => "old"},
      "items" => ["first"]
    }
    patched = Rubernetes::API::Patch.apply_json_patch(
      original,
      [
        {"op" => "replace", "path" => "/data/a~1b", "value" => "new"},
        {"op" => "replace", "path" => "/data/t~0key", "value" => "newer"},
        {"op" => "add", "path" => "/items/-", "value" => "second"}
      ]
    )

    assert_equal("old", original.dig("data", "a/b"))
    assert_equal("new", patched.dig("data", "a/b"))
    assert_equal("newer", patched.dig("data", "t~key"))
    assert_equal(%w[first second], patched.fetch("items"))
    assert_raises(Rubernetes::API::Patch::Error) do
      Rubernetes::API::Patch.apply_json_patch({"a" => {"b" => 1}}, [{"op" => "move", "from" => "/a", "path" => "/a/b"}])
    end
    assert_raises(Rubernetes::API::Patch::Error) do
      Rubernetes::API::Patch.apply_json_patch({"items" => ["x"]}, [{"op" => "replace", "path" => "/items/01", "value" => "y"}])
    end
    assert_raises(Rubernetes::API::Patch::Error) do
      Rubernetes::API::Patch.apply_json_patch({"~2" => true}, [{"op" => "test", "path" => "/~2", "value" => true}])
    end
  end

  def test_merge_patch_replaces_arrays_deletes_nulls_and_rejects_scalar_resources
    call("POST", "/api/v1/namespaces/dev/configmaps", {
           "metadata" => {"name" => "merge"},
           "data" => {"keep" => "yes", "remove" => "yes"},
           "binaryData" => ["old"]
         })
    merged = call("PATCH", "/api/v1/namespaces/dev/configmaps/merge",
                  {"data" => {"remove" => nil, "add" => "yes"}, "binaryData" => ["new"]},
                  headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal(200, merged.status)
    assert_equal({"keep" => "yes", "add" => "yes"}, merged.body.fetch("data"))
    assert_equal(["new"], merged.body.fetch("binaryData"))

    scalar = call("PATCH", "/api/v1/namespaces/dev/configmaps/merge", "null",
                  headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal(422, scalar.status)
    assert_equal("Invalid", scalar.body.fetch("reason"))
    empty_merge = call("PATCH", "/api/v1/namespaces/dev/configmaps/merge", [],
                       headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal(422, empty_merge.status)
    empty_json = call("PATCH", "/api/v1/namespaces/dev/configmaps/merge", [],
                      headers: {"Content-Type" => "application/json-patch+json"})

    assert_equal(200, empty_json.status)
    assert_equal(200, call("GET", "/api/v1/namespaces/dev/configmaps/merge").status)
  end

  def test_strategic_merge_honors_merge_keys_delete_and_replace_directives
    call("POST", "/api/v1/namespaces/dev/pods", {
           "metadata" => {"name" => "workload"},
           "spec" => {"containers" => [
             {"name" => "web", "image" => "old", "ports" => [{"containerPort" => 80, "name" => "http"}],
              "env" => [{"name" => "A", "value" => "1"}]},
             {"name" => "side", "image" => "side"}
           ]}
         })
    merged = call("PATCH", "/api/v1/namespaces/dev/pods/workload", {
                    "spec" => {"containers" => [
                      {"name" => "web", "image" => "new", "ports" => [{"containerPort" => 80, "name" => "http", "protocol" => "TCP"}, {"containerPort" => 443, "name" => "https"}],
                       "env" => [{"name" => "A", "value" => "2"}, {"name" => "B", "value" => "3"}]},
                      {"name" => "side", "$patch" => "delete"},
                      {"name" => "helper", "image" => "helper"}
                    ]}
                  }, headers: {"Content-Type" => "application/strategic-merge-patch+json"})
    containers = merged.body.dig("spec", "containers")

    assert_equal(%w[web helper], containers.map { |container| container.fetch("name") })
    assert_equal("new", containers.first.fetch("image"))
    assert_equal(%w[A B], containers.first.fetch("env").map { |entry| entry.fetch("name") })
    assert_equal([80, 443], containers.first.fetch("ports").map { |entry| entry.fetch("containerPort") })

    replaced = call("PATCH", "/api/v1/namespaces/dev/pods/workload", {
                      "spec" => {"containers" => [{"name" => "web", "$patch" => "replace", "image" => "replacement"}]}
                    }, headers: {"Content-Type" => "application/strategic-merge-patch+json"})
    web = replaced.body.dig("spec", "containers").find { |container| container.fetch("name") == "web" }

    assert_equal({"name" => "web", "image" => "replacement"}, web)
    refute(web.key?("$patch"))
    assert_raises(Rubernetes::API::Patch::Error) do
      Rubernetes::API::Patch.apply_strategic_merge({"spec" => {}}, {"spec" => {"$patch" => "unknown"}})
    end
  end

  def test_server_side_apply_conflict_force_and_omitted_field_ownership
    first = call("PATCH", "/api/v1/namespaces/dev/configmaps/ssa", {
                   "metadata" => {"name" => "ssa"}, "data" => {"keep" => "one", "drop" => "two"}
                 }, query: {"fieldManager" => "manager-one"}, headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(201, first.status)

    omitted = call("PATCH", "/api/v1/namespaces/dev/configmaps/ssa", {
                     "metadata" => {"name" => "ssa"}, "data" => {"keep" => "updated"}
                   }, query: {"fieldManager" => "manager-one"}, headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(200, omitted.status)
    refute(omitted.body.fetch("data").key?("drop"))
    refute(fields_for(omitted.body, "manager-one").any? { |path| path.end_with?("drop") })

    conflict = call("PATCH", "/api/v1/namespaces/dev/configmaps/ssa", {
                      "metadata" => {"name" => "ssa"}, "data" => {"keep" => "other"}
                    }, query: {"fieldManager" => "manager-two"}, headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(409, conflict.status)
    assert_equal("Conflict", conflict.body.fetch("reason"))
    assert_equal(".data.keep", conflict.body.dig("details", "causes", 0, "field"))
    assert_equal("FieldManagerConflict", conflict.body.dig("details", "causes", 0, "reason"))
    assert_equal("updated", call("GET", "/api/v1/namespaces/dev/configmaps/ssa").body.dig("data", "keep"))

    forced = call("PATCH", "/api/v1/namespaces/dev/configmaps/ssa", {
                    "metadata" => {"name" => "ssa"}, "data" => {"keep" => "other"}
                  }, query: {"fieldManager" => "manager-two", "force" => "true"},
                     headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(200, forced.status)
    assert_equal("other", forced.body.dig("data", "keep"))
    assert_includes(fields_for(forced.body, "manager-two"), "data.keep")
  end

  # apivalidation.IsValidSysctlName -- the conformance spec asserts that the
  # API server names exactly the two malformed sysctls and neither valid one.
  def test_malformed_sysctl_names_are_rejected_by_the_api_server
    response = call("POST", "/api/v1/namespaces/dev/pods",
                    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "sysctl-pod"},
                     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}],
                                "securityContext" => {"sysctls" => [
                                  {"name" => "foo-", "value" => "bar"},
                                  {"name" => "kernel.shmmax", "value" => "100000000"},
                                  {"name" => "safe-and-unsafe", "value" => "100000000"},
                                  {"name" => "bar..", "value" => "42"}
                                ]}}})

    assert_equal(422, response.status, response.body.inspect)
    message = response.body.to_s

    assert_includes(message, "foo-")
    assert_includes(message, "bar..")
    refute_includes(message, "safe-and-unsafe")
    refute_includes(message, "kernel.shmmax")
  end

  # validation.go ValidateSecretUpdate: once `immutable` is true the data and
  # the flag itself are frozen, and the API server is what enforces it.
  def test_an_immutable_secret_refuses_data_and_flag_changes
    created = call("POST", "/api/v1/namespaces/dev/secrets",
                   {"apiVersion" => "v1", "kind" => "Secret", "metadata" => {"name" => "frozen"},
                    "data" => {"key" => "dmFsdWU="}, "immutable" => true})

    assert_includes([200, 201], created.status, created.body.inspect)
    version = created.body.dig("metadata", "resourceVersion")

    changed = call("PUT", "/api/v1/namespaces/dev/secrets/frozen",
                   {"apiVersion" => "v1", "kind" => "Secret",
                    "metadata" => {"name" => "frozen", "namespace" => "dev", "resourceVersion" => version},
                    "data" => {"key" => "b3RoZXI="}, "immutable" => true})

    assert_equal(422, changed.status, changed.body.inspect)

    unfrozen = call("PUT", "/api/v1/namespaces/dev/secrets/frozen",
                    {"apiVersion" => "v1", "kind" => "Secret",
                     "metadata" => {"name" => "frozen", "namespace" => "dev", "resourceVersion" => version},
                     "data" => {"key" => "dmFsdWU="}, "immutable" => false})

    assert_equal(422, unfrozen.status, "the immutable flag itself cannot be cleared")

    # A metadata-only update is still allowed.
    labelled = call("PUT", "/api/v1/namespaces/dev/secrets/frozen",
                    {"apiVersion" => "v1", "kind" => "Secret",
                     "metadata" => {"name" => "frozen", "namespace" => "dev", "resourceVersion" => version,
                                    "labels" => {"team" => "core"}},
                     "data" => {"key" => "dmFsdWU="}, "immutable" => true})

    assert_equal(200, labelled.status, labelled.body.inspect)
  end

  # kube-apiserver treats a request that names no Content-Type as JSON.
  # Asking a nil for #include? turned every such request into a 500 -- the
  # scheduler's Binding post among them, which made it fall back to patching
  # the Pod's spec directly and bump metadata.generation a second time.
  def test_a_request_without_a_content_type_is_read_as_json
    created = call("POST", "/api/v1/namespaces/dev/pods",
                   {"apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "bindme"},
                    "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}},
                   headers: {})

    assert_includes([200, 201], created.status, created.body.inspect)
    assert_equal(1, created.body.dig("metadata", "generation"))

    bound = call("POST", "/api/v1/namespaces/dev/pods/bindme/binding",
                 {"apiVersion" => "v1", "kind" => "Binding",
                  "metadata" => {"name" => "bindme", "namespace" => "dev"},
                  "target" => {"apiVersion" => "v1", "kind" => "Node", "name" => "node-a"}},
                 headers: {})

    assert_equal(201, bound.status, bound.body.inspect)

    pod = call("GET", "/api/v1/namespaces/dev/pods/bindme").body

    assert_equal("node-a", pod.dig("spec", "nodeName"))
    assert_equal(1, pod.dig("metadata", "generation"),
                 "binding is a subresource and must not bump the Pod's generation")
  end

  # An Accept header is an ordered preference list.  client-go asks for
  # "application/vnd.kubernetes.protobuf, application/json" by default, and
  # /version and the discovery documents are not protobuf-encodable -- so
  # answering 406 instead of falling through to JSON broke every client that
  # simply asked for the server version.
  def test_a_body_that_cannot_be_protobuf_encoded_falls_back_to_json
    protobuf = "application/vnd.kubernetes.protobuf"
    both = call("GET", "/version", nil, headers: {"Accept" => "#{protobuf},application/json"})

    assert_equal(200, both.status, both.body.inspect)
    assert_equal("v1.36.2", both.body.fetch("gitVersion"))

    # APIResourceList *is* protobuf-encodable, so it is served as protobuf --
    # metav1.Verbs inside it is a named []string with a custom marshaler.
    discovery = call("GET", "/api/v1", nil, headers: {"Accept" => "#{protobuf},application/json"})

    assert_equal(200, discovery.status, discovery.body.to_s[0, 200])

    # Nothing else acceptable is still a 406.
    assert_equal(406, call("GET", "/version", nil, headers: {"Accept" => protobuf}).status)
  end

  # registry.Store#Update treats an object submitted without a
  # resourceVersion as an unconditional update wherever the strategy allows
  # one.  Upstream's own conformance spec "should update ConfigMap
  # successfully" relies on it: it updates the object it built locally,
  # having discarded the one the server returned from Create.
  def test_an_update_without_a_resource_version_is_unconditional
    created = call("POST", "/api/v1/namespaces/dev/configmaps",
                   {"metadata" => {"name" => "cm-uncond"}, "data" => {"a" => "1"}})

    assert_equal(201, created.status)

    # No resourceVersion, exactly as a client that never read the object back.
    updated = call("PUT", "/api/v1/namespaces/dev/configmaps/cm-uncond",
                   {"apiVersion" => "v1", "kind" => "ConfigMap",
                    "metadata" => {"name" => "cm-uncond", "namespace" => "dev"},
                    "data" => {"data" => "value"}})

    assert_equal(200, updated.status, updated.body.inspect)
    assert_equal({"data" => "value"}, updated.body.fetch("data"))
    assert_equal({"data" => "value"},
                 call("GET", "/api/v1/namespaces/dev/configmaps/cm-uncond").body.fetch("data"))

    # A resourceVersion that is present is still a precondition.
    stale = call("PUT", "/api/v1/namespaces/dev/configmaps/cm-uncond",
                 {"apiVersion" => "v1", "kind" => "ConfigMap",
                  "metadata" => {"name" => "cm-uncond", "namespace" => "dev", "resourceVersion" => "1"},
                  "data" => {"data" => "other"}})

    assert_equal(409, stale.status)

    # An unconditional update still cannot create a missing object.
    missing = call("PUT", "/api/v1/namespaces/dev/configmaps/absent",
                   {"apiVersion" => "v1", "kind" => "ConfigMap",
                    "metadata" => {"name" => "absent", "namespace" => "dev"}, "data" => {}})

    assert_equal(404, missing.status)
  end

  # A status apply owns the status fields it sends.  When the next apply
  # stops sending one, that field must go: without it a StatefulSet whose
  # Pods stopped being ready keeps reporting its old readyReplicas forever,
  # because the controller omits the counter once it reaches zero.
  def test_status_apply_drops_a_field_its_manager_stops_sending
    created = call("POST", "/api/v1/namespaces/dev/pods", {
                     "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "ssa-status"},
                     "spec" => {"containers" => [{"name" => "c", "image" => "busybox"}]}
                   })

    assert_includes([200, 201], created.status, created.body.inspect)

    ready = call("PATCH", "/api/v1/namespaces/dev/pods/ssa-status/status", {
                   "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "ssa-status"},
                   "status" => {"phase" => "Running", "podIP" => "10.0.0.1", "message" => "up"}
                 }, query: {"fieldManager" => "kubelet", "force" => "true"},
                    headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(200, ready.status, ready.body.inspect)
    assert_equal("10.0.0.1", ready.body.dig("status", "podIP"))

    dropped = call("PATCH", "/api/v1/namespaces/dev/pods/ssa-status/status", {
                     "apiVersion" => "v1", "kind" => "Pod", "metadata" => {"name" => "ssa-status"},
                     "status" => {"phase" => "Running"}
                   }, query: {"fieldManager" => "kubelet", "force" => "true"},
                      headers: {"Content-Type" => "application/apply-patch+yaml"})

    assert_equal(200, dropped.status, dropped.body.inspect)
    refute(dropped.body.fetch("status").key?("podIP"),
           "podIP must be dropped once its manager stops sending it")
    refute(dropped.body.fetch("status").key?("message"))
    assert_nil(call("GET", "/api/v1/namespaces/dev/pods/ssa-status").body.dig("status", "podIP"))
  end

  def test_status_details_retry_after_and_subresource_boundaries
    status = Rubernetes::API::Status::Conflict.new(
      "field conflict",
      details: {"group" => "", "kind" => "ConfigMap", "name" => "demo"},
      causes: [{"field" => "data.key", "reason" => "FieldValueConflict"}],
      retry_after_seconds: 7
    ).to_status

    assert_equal("Failure", status.fetch("status"))
    assert_equal(409, status.fetch("code"))
    assert_equal("Conflict", status.fetch("reason"))
    assert_equal("data.key", status.dig("details", "causes", 0, "field"))
    assert_equal(7, status.dig("details", "retryAfterSeconds"))

    invalid = call("POST", "/api/v1/namespaces/dev/configmaps", {"data" => {"key" => "value"}})

    assert_equal(422, invalid.status)
    assert_equal("Invalid", invalid.body.fetch("reason"))
    assert_equal("metadata.name", invalid.body.dig("details", "causes", 0, "field"))
    call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "duplicate"}})
    duplicate = call("POST", "/api/v1/namespaces/dev/configmaps", {"metadata" => {"name" => "duplicate"}})

    assert_equal(409, duplicate.status)
    assert_equal("AlreadyExists", duplicate.body.fetch("reason"))
    assert_equal("configmaps", duplicate.body.dig("details", "kind"))
    assert_equal("duplicate", duplicate.body.dig("details", "name"))
    refute_includes(duplicate.body.fetch("message"), "registry/")

    call("POST", "/api/v1/namespaces/dev/pods", {
           "metadata" => {"name" => "status-pod", "finalizers" => ["example.test/cleanup"]},
           "spec" => {"containers" => [{"name" => "web", "image" => "old"}]},
           "status" => {"phase" => "Pending"}
         })
    status_update = call("PATCH", "/api/v1/namespaces/dev/pods/status-pod/status", {"status" => {"phase" => "Running"}},
                         headers: {"Content-Type" => "application/merge-patch+json"})

    assert_equal(200, status_update.status)
    assert_equal("Running", status_update.body.dig("status", "phase"))
    assert_equal("old", call("GET", "/api/v1/namespaces/dev/pods/status-pod").body.dig("spec", "containers", 0, "image"))
    assert_equal("old", call("GET", "/api/v1/namespaces/dev/pods/status-pod/status").body.dig("spec", "containers", 0, "image"))
    assert_equal(404, call("GET", "/api/v1/namespaces/dev/configmaps/missing/status").status)

    deleting = call("DELETE", "/api/v1/namespaces/dev/pods/status-pod")

    assert(deleting.body.dig("metadata", "deletionTimestamp"))
    assert_equal(200, call("GET", "/api/v1/namespaces/dev/pods/status-pod").status)
    removed = call("PATCH", "/api/v1/namespaces/dev/pods/status-pod", [{"op" => "remove", "path" => "/metadata/finalizers/0"}],
                   headers: {"Content-Type" => "application/json-patch+json"})

    assert_equal([], removed.body.dig("metadata", "finalizers"))
    # The last finalizer going is itself the delete; see above.
    assert_equal(404, call("GET", "/api/v1/namespaces/dev/pods/status-pod").status)
  end

  # pkg/registry/core/namespace: a namespace is created Active with the
  # built-in "kubernetes" finalizer, DELETE only marks it Terminating, new
  # content is refused while it terminates, and the object disappears only
  # once the finalizer is removed.
  def test_namespace_termination_is_finalizer_driven
    created = call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "doomed"}})

    assert_equal(201, created.status)
    assert_equal(["kubernetes"], created.body.dig("spec", "finalizers"))
    assert_equal("Active", created.body.dig("status", "phase"))

    assert_equal(201, call("POST", "/api/v1/namespaces/doomed/configmaps",
                           {"metadata" => {"name" => "inside"}}).status)

    deleted = call("DELETE", "/api/v1/namespaces/doomed")

    assert_equal(200, deleted.status)
    assert_equal("Namespace", deleted.body.fetch("kind"))
    assert_equal("Terminating", deleted.body.dig("status", "phase"))
    assert(deleted.body.dig("metadata", "deletionTimestamp"))
    assert_equal(200, call("GET", "/api/v1/namespaces/doomed").status)

    refused = call("POST", "/api/v1/namespaces/doomed/configmaps", {"metadata" => {"name" => "late"}})

    assert_equal(403, refused.status)
    assert_match(/being terminated/, refused.body.fetch("message"))

    current = Marshal.load(Marshal.dump(call("GET", "/api/v1/namespaces/doomed").body))
    current["spec"] = {"finalizers" => []}
    finalized = call("PUT", "/api/v1/namespaces/doomed/finalize", current)

    assert_equal(200, finalized.status)
    assert_equal(404, call("GET", "/api/v1/namespaces/doomed").status)
  end

  def test_openapi_reads_injected_generated_documents_and_fails_closed
    v2 = call("GET", "/openapi/v2")

    assert_equal(200, v2.status)
    assert_equal("application/json", v2.content_type)
    assert_equal("2.0", v2.body.fetch("swagger"))
    assert_equal(200, call("GET", "/openapi/v3").status)
    assert_equal(200, call("GET", "/openapi/v3/api/v1").status)
    assert_equal(200, call("GET", "/openapi/v3/apis/apps/v1").status)
    assert_equal(404, call("GET", "/openapi/v3/apis/apps/v9").status)
    assert_equal(404, call("GET", "/openapi/v3/../../openapi/v2").status)
    assert_equal(404, call("GET", "/openapi/v3/%2e%2e/%2e%2e/openapi/v2").status)

    Dir.mktmpdir("rubernetes-openapi-") do |root|
      FileUtils.mkdir_p(File.join(root, "v3", "api"))
      File.write(File.join(root, "v2.json"), JSON.generate("swagger" => "custom"))
      File.write(File.join(root, "v3", "index.json"), JSON.generate("kind" => "OpenAPIV3Discovery"))
      File.write(File.join(root, "v3", "api", "v1.json"), JSON.generate("openapi" => "3.0.0"))
      server = Rubernetes::API::Server.new(openapi_root: root)

      assert_equal("custom", server.call(method: "GET", path: "/openapi/v2").body.fetch("swagger"))
      File.symlink("v2.json", File.join(root, "v3", "api", "symlink.json"))

      assert_equal(404, server.call(method: "GET", path: "/openapi/v3/api/symlink").status)
    end
  end

  def test_router_only_accepts_registered_subresources_and_preserves_namespace_routes
    call("POST", "/api/v1/namespaces/dev/pods", {"metadata" => {"name" => "routed"},
                                                 "spec" => {"containers" => [{"name" => "app", "image" => "example/app:1"}]}})

    assert_equal(200, call("GET", "/api/v1/namespaces/dev/pods/routed/status").status)
    assert_equal(404, call("GET", "/api/v1/namespaces/dev/pods/routed/unknown").status)
    assert_equal(404, call("GET", "/api/v1/namespaces/dev/configmaps/unknown/status").status)
    assert_equal(405, call("POST", "/api/v1/namespaces/dev/pods/routed/status", {}).status)

    namespace = call("POST", "/api/v1/namespaces", {"metadata" => {"name" => "finalize-me"}})

    assert_equal(201, namespace.status)
    assert_equal(405, call("GET", "/api/v1/namespaces/finalize-me/finalize").status)
    update = call("PUT", "/api/v1/namespaces/finalize-me/finalize", {
                    "metadata" => {"name" => "finalize-me", "resourceVersion" => namespace.body.dig("metadata", "resourceVersion")}
                  })

    assert_equal(200, update.status)
  end

  private

  def call(method, path, body = nil, query: nil, headers: {})
    @server.call(method: method, path: path, body: body, query: query, headers: headers)
  end

  def fields_for(object, manager)
    entry = Array(object.dig("metadata", "managedFields")).find { |candidate| candidate.fetch("manager") == manager }
    flatten_fields(entry && entry["fieldsV1"])
  end

  def flatten_fields(value, prefix = [])
    return [] unless value.is_a?(Hash)

    value.each_with_object([]) do |(key, child), paths|
      next unless key.start_with?("f:")

      path = prefix + [key.delete_prefix("f:")]
      nested = flatten_fields(child, path)
      paths.concat(nested.empty? ? [path.join(".")] : nested)
    end
  end

  # Label keys carry dots ("app.kubernetes.io/name"); the selector must match
  # the exact key rather than walking it as a dotted path.
  def test_label_selector_matches_dotted_label_keys
    selectors = Rubernetes::API::Selectors.new(label_selector: "app.kubernetes.io/name=web,tier!=cache")

    assert selectors.matches?({"metadata" => {"labels" => {"app.kubernetes.io/name" => "web", "tier" => "frontend"}}})
    refute selectors.matches?({"metadata" => {"labels" => {"app.kubernetes.io/name" => "api"}}})
    fields = Rubernetes::API::Selectors.new(field_selector: "metadata.name=web")

    assert fields.matches?({"metadata" => {"name" => "web"}})
    refute fields.matches?({"metadata" => {"name" => "other"}})
  end
end
