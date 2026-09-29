# frozen_string_literal: true

# Server-side apply through the API server with the structured-merge-diff
# field manager (k8s.io/apimachinery managedfields, v1.36.2): associative
# lists merged by key, conflicts worded as kube-apiserver words them, apply
# to /scale mapped onto the parent's .spec.replicas (and a CRD's
# specReplicasPath), the write-option validation, and the manager a write
# without fieldManager is recorded under.

require_relative "../test_helper"
require "json"
require "rubernetes/api"
require "rubernetes/bootstrap"

class ServerSideApplyUpstreamTest < Minitest::Test
  API = Rubernetes::API
  MF = Rubernetes::API::ManagedFields

  def setup
    @now = Time.utc(2026, 1, 1)
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @openapi = API::OpenAPIRepository.new
    @server = API::Server.new(registry: registry, store: API::MemoryStore.new(clock: -> { @now }), clock: -> { @now },
                              openapi_repository: @openapi)
    call("POST", "/api/v1/namespaces", {"apiVersion" => "v1", "kind" => "Namespace", "metadata" => {"name" => "team"}})
  end

  def call(method, path, body = nil, content_type: "application/json", manager: nil, query: {}, user_agent: nil)
    params = query.dup
    params["fieldManager"] = manager if manager
    path = "#{path}?#{URI.encode_www_form(params)}" unless params.empty?
    headers = body ? {"content-type" => content_type} : {}
    headers["user-agent"] = user_agent if user_agent
    response = @server.call(API::Request.new(method: method, path: path, headers: headers, body: body && JSON.generate(body),
                                             identity: {"username" => "admin", "groups" => ["system:masters"]}))
    body = response.body
    body = body.is_a?(Hash) ? Marshal.load(Marshal.dump(body)) : JSON.parse(Array(body).join)
    [response.status, body]
  end

  def apply(path, object, manager:, force: false)
    call("PATCH", path, object, content_type: "application/apply-patch+yaml", manager: manager,
                                query: force ? {"force" => "true"} : {})
  end

  def owned(object)
    Array(object.dig("metadata", "managedFields")).to_h do |entry|
      paths = MF::FieldPath::Set.from_fields_v1(entry["fieldsV1"]).leaves.each_path.map { |path| MF::FieldPath.path_string(path) }
      [[entry["manager"], entry["operation"], entry["subresource"]].compact.join("/"), paths.sort]
    end
  end

  def deployment(containers:, replicas: nil)
    spec = {"selector" => {"matchLabels" => {"app" => "web"}},
            "template" => {"metadata" => {"labels" => {"app" => "web"}}, "spec" => {"containers" => containers}}}
    spec["replicas"] = replicas if replicas
    {"apiVersion" => "apps/v1", "kind" => "Deployment", "metadata" => {"name" => "web"}, "spec" => spec}
  end

  DEPLOYMENT = "/apis/apps/v1/namespaces/team/deployments/web"

  def test_applies_merge_associative_lists_by_key
    status, = apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:1"}]), manager: "team-a")
    assert_equal 201, status
    status, merged = apply(DEPLOYMENT, deployment(containers: [{"name" => "sidecar", "image" => "proxy:1"}]), manager: "team-b")
    assert_equal 200, status
    names = merged.dig("spec", "template", "spec", "containers").map { |container| container["name"] }
    assert_equal %w[app sidecar], names
    assert_includes owned(merged)["team-a/Apply"], '.spec.template.spec.containers[name="app"].image'
    assert_includes owned(merged)["team-b/Apply"], '.spec.template.spec.containers[name="sidecar"].image'

    # Dropping a container from team-a's configuration removes it; team-b's
    # stays.
    status, pruned = apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:1"}]).tap do |object|
      object["spec"]["template"]["spec"]["containers"] = [{"name" => "app", "image" => "app:2"}]
    end, manager: "team-a")
    assert_equal 200, status
    assert_equal [["app", "app:2"], ["sidecar", "proxy:1"]],
                 pruned.dig("spec", "template", "spec", "containers").map { |container| container.values_at("name", "image") }
  end

  def test_conflicts_are_reported_like_kube_apiserver
    apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:1"}], replicas: 2), manager: "owner")
    status, conflict = apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:9"}], replicas: 5),
                             manager: "intruder")
    assert_equal 409, status
    assert_equal "Conflict", conflict["reason"]
    assert_equal "Apply failed with 2 conflicts: conflicts with \"owner\":\n- .spec.replicas\n" \
                 "- .spec.template.spec.containers[name=\"app\"].image", conflict["message"]
    assert_equal [{"reason" => "FieldManagerConflict", "message" => "conflict with \"owner\"", "field" => ".spec.replicas"},
                  {"reason" => "FieldManagerConflict", "message" => "conflict with \"owner\"",
                   "field" => ".spec.template.spec.containers[name=\"app\"].image"}],
                 conflict.dig("details", "causes")

    status, forced = apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:9"}], replicas: 5),
                           manager: "intruder", force: true)
    assert_equal 200, status
    assert_equal 5, forced.dig("spec", "replicas")
    refute_includes owned(forced)["owner/Apply"], ".spec.replicas"
  end

  def test_an_update_manager_conflict_names_its_version
    create = deployment(containers: [{"name" => "app", "image" => "app:1"}], replicas: 1)
    assert_equal 201, call("POST", "/apis/apps/v1/namespaces/team/deployments", create, manager: "creator").first
    status, conflict = apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:1"}], replicas: 3),
                             manager: "applier")
    assert_equal 409, status
    assert_equal "Apply failed with 1 conflict: conflict with \"creator\" using apps/v1: .spec.replicas", conflict["message"]
  end

  def test_apply_to_scale_owns_the_parent_replicas
    apply(DEPLOYMENT, deployment(containers: [{"name" => "app", "image" => "app:1"}], replicas: 1), manager: "owner")
    scale = {"apiVersion" => "autoscaling/v1", "kind" => "Scale", "metadata" => {"name" => "web"}, "spec" => {"replicas" => 4}}
    status, conflict = apply("#{DEPLOYMENT}/scale", scale, manager: "autoscaler")
    assert_equal 409, status
    assert_equal "Apply failed with 1 conflict: conflict with \"owner\": .spec.replicas", conflict["message"]

    status, applied = apply("#{DEPLOYMENT}/scale", scale, manager: "autoscaler", force: true)
    assert_equal 200, status
    assert_equal 4, applied.dig("spec", "replicas")
    _, parent = call("GET", DEPLOYMENT)
    assert_equal 4, parent.dig("spec", "replicas")
    entry = parent.dig("metadata", "managedFields").find { |item| item["manager"] == "autoscaler" }
    assert_equal({"manager" => "autoscaler", "operation" => "Apply", "apiVersion" => "apps/v1", "fieldsType" => "FieldsV1",
                  "fieldsV1" => {"f:spec" => {"f:replicas" => {}}}, "subresource" => "scale"}, entry.except("time"))
    refute_includes owned(parent)["owner/Apply"], ".spec.replicas"

    # kubectl scale (a PUT of the Scale) records an Update on the subresource.
    status, = call("PUT", "#{DEPLOYMENT}/scale", scale.merge("spec" => {"replicas" => 2}), user_agent: "kubectl/v1.36.2 (linux/amd64) kubernetes/abc")
    assert_equal 200, status
    _, parent = call("GET", DEPLOYMENT)
    assert_equal [".spec.replicas"], owned(parent)["kubectl/Update/scale"]
    refute owned(parent).key?("autoscaler/Apply/scale")
  end

  def test_write_options_are_validated
    status, missing = apply(DEPLOYMENT, deployment(containers: [{"name" => "app"}]), manager: nil)
    assert_equal 422, status
    assert_equal "PatchOptions.meta.k8s.io \"\" is invalid: fieldManager: Required value: is required for apply patch", missing["message"]

    status, forced = call("PATCH", DEPLOYMENT, {"spec" => {}}, content_type: "application/merge-patch+json", query: {"force" => "true"})
    assert_equal 422, status
    assert_equal "PatchOptions.meta.k8s.io \"\" is invalid: force: Forbidden: may not be specified for non-apply patch", forced["message"]

    status, long = call("POST", "/api/v1/namespaces/team/configmaps", {"metadata" => {"name" => "c"}}, manager: "m" * 129)
    assert_equal 422, status
    assert_equal "CreateOptions.meta.k8s.io \"\" is invalid: fieldManager: Too long: may not be more than 128 bytes", long["message"]

    status, dry = call("POST", "/api/v1/namespaces/team/configmaps", {"metadata" => {"name" => "c"}}, query: {"dryRun" => "Some"})
    assert_equal 422, status
    assert_equal "CreateOptions.meta.k8s.io \"\" is invalid: dryRun: Unsupported value: [\"Some\"]: supported values: \"All\"", dry["message"]

    status, validation = call("POST", "/api/v1/namespaces/team/configmaps", {"metadata" => {"name" => "c"}},
                              query: {"fieldValidation" => "Loud"})
    assert_equal 422, status
    assert_equal "CreateOptions.meta.k8s.io \"\" is invalid: fieldValidation: Unsupported value: \"Loud\": " \
                 "supported values: \"\", \"Ignore\", \"Strict\", \"Warn\"", validation["message"]
  end

  def test_the_manager_of_a_write_without_field_manager_is_the_user_agent_command
    status, created = call("POST", "/api/v1/namespaces/team/configmaps", {"metadata" => {"name" => "ua"}, "data" => {"a" => "1"}},
                           user_agent: "kube-controller-manager/v1.36.2 (linux/amd64) kubernetes/abc/deployment-controller")
    assert_equal 201, status
    assert_equal ["kube-controller-manager"], created.dig("metadata", "managedFields").map { |entry| entry["manager"] }

    status, anonymous = call("POST", "/api/v1/namespaces/team/configmaps", {"metadata" => {"name" => "none"}, "data" => {"a" => "1"}})
    assert_equal 201, status
    assert_equal ["unknown"], anonymous.dig("metadata", "managedFields").map { |entry| entry["manager"] }
  end

  def test_kubectl_client_side_apply_values_do_not_conflict
    annotation = {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "csa"}, "data" => {"key" => "old"}}
    object = annotation.merge("metadata" => {"name" => "csa", "annotations" => {
      "kubectl.kubernetes.io/last-applied-configuration" => JSON.generate(annotation)
    }})
    assert_equal 201, call("POST", "/api/v1/namespaces/team/configmaps", object, manager: "kubectl-client-side-apply").first
    status, migrated = apply("/api/v1/namespaces/team/configmaps/csa",
                             {"apiVersion" => "v1", "kind" => "ConfigMap", "metadata" => {"name" => "csa"}, "data" => {"key" => "new"}},
                             manager: "kubectl")
    assert_equal 200, status
    assert_equal "new", migrated.dig("data", "key")
    last = JSON.parse(migrated.dig("metadata", "annotations", "kubectl.kubernetes.io/last-applied-configuration"))
    assert_equal({"key" => "new"}, last["data"])
  end
  # A create's update is compared with Creater.New(kind), the Go zero value:
  # struct fields that are not pointers are already there and are not owned
  # with "." (TokenReview's spec, a Deployment's spec and template), while
  # a map that was nil (the template's labels) is.
  def test_a_create_starts_from_the_kinds_zero_value
    _, review = call("POST", "/apis/authentication.k8s.io/v1/tokenreviews",
                     {"apiVersion" => "authentication.k8s.io/v1", "kind" => "TokenReview", "spec" => {"token" => "t"}}, manager: "m")
    assert_equal({"f:spec" => {"f:token" => {}}}, review.dig("metadata", "managedFields", 0, "fieldsV1"))
    _, created = call("POST", "/apis/apps/v1/namespaces/team/deployments",
                      deployment(containers: [{"name" => "c", "image" => "i"}]).merge("metadata" => {"name" => "web"}), manager: "m")
    spec = created.dig("metadata", "managedFields", 0, "fieldsV1", "f:spec")
    refute spec.key?("."), spec.inspect
    assert_equal({}, spec.fetch("f:selector")) # atomic
    refute spec.dig("f:template", "f:spec").key?(".")
    assert spec.dig("f:template", "f:metadata", "f:labels").key?(".")
  end
end
