# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class JobSelectorUpdateTest < Minitest::Test
  JOBS = "/apis/batch/v1/namespaces/default/jobs"
  SELECTOR_PATH = "spec.selector"
  TEMPLATE_LABELS_PATH = "spec.template.metadata.labels"
  CONTROLLER_UID = "batch.kubernetes.io/controller-uid"

  def setup
    catalog = Rubernetes::Schema::Catalog.default
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, catalog)
    @job_resource = registry.find_gvr(group: "batch", version: "v1", resource: "jobs")
    @store = Rubernetes::Storage::MemoryStore.new
    @server = Rubernetes::API::Server.new(registry: registry, store: @store)
  end

  def test_empty_selector_collections_are_equivalent_but_selector_removal_is_rejected
    original = create_job("empty-selector", {"manualSelector" => true, "selector" => {}})
    candidate = copy(original)
    candidate["spec"]["selector"] = {"matchExpressions" => [], "matchLabels" => {}}
    accepted = put(candidate)

    assert_equal 200, accepted.status
    assert_equal({}, accepted.body.dig("spec", "selector"))
    assert_equal original, accepted.body

    original = accepted.body
    candidate = copy(original)
    candidate["spec"]["selector"] = nil
    refused = apply(candidate)

    assert_equal 422, refused.status
    assert_equal [SELECTOR_PATH, TEMPLATE_LABELS_PATH, SELECTOR_PATH, TEMPLATE_LABELS_PATH, SELECTOR_PATH], cause_fields(refused)
    assert_equal "Invalid value: null: field is immutable", causes(refused).last.fetch("message")
    assert_equal original, get(original)
  end

  def test_rejected_generated_selector_replacement_preserves_job_and_managed_fields
    original = create_job("generated")
    candidate = copy(original)
    candidate["spec"]["selector"]["matchLabels"][CONTROLLER_UID] = "wrong"

    [put(candidate), apply(candidate)].each do |refused|
      assert_equal 422, refused.status
      assert_equal [SELECTOR_PATH, TEMPLATE_LABELS_PATH, TEMPLATE_LABELS_PATH, SELECTOR_PATH], cause_fields(refused)
      assert_match(/`selector` not auto-generated\z/, causes(refused).first.fetch("message"))
      assert_match(/field is immutable\z/, causes(refused).last.fetch("message"))
      assert_equal original, get(original)
    end
  end

  def test_first_write_materializes_read_defaulted_labels_under_preconditions
    original = create_job("materialize-labels")
    labels = original.dig("spec", "template", "metadata", "labels")

    assert_nil stored_job(original).dig("metadata", "labels")
    assert_equal labels, get(original).dig("metadata", "labels")

    uid_conflict = copy(original)
    uid_conflict["metadata"]["uid"] = "other-uid"
    stale = copy(original)
    stale["metadata"]["resourceVersion"] = "999999"

    assert_equal 409, put(uid_conflict).status
    assert_equal 409, put(stale).status
    assert_equal original, get(original)
    assert_nil stored_job(original).dig("metadata", "labels")

    committed = put(original)

    assert_equal 200, committed.status
    assert_equal labels, stored_job(original).dig("metadata", "labels")
    refute_equal original.dig("metadata", "resourceVersion"), committed.body.dig("metadata", "resourceVersion")
    assert_equal original.dig("metadata", "generation"), committed.body.dig("metadata", "generation")
    assert_equal original.dig("metadata", "managedFields"), committed.body.dig("metadata", "managedFields")
    assert_equal committed.body, put(committed.body).body
  end

  def test_materializing_labels_respects_a_competing_revision
    original = create_job("competing-revision")
    key = "registry/batch/v1/jobs/default/competing-revision"
    update_store = @store.method(:update)
    concurrent_update = lambda do |*args, **options|
      current = copy(stored_job(original))
      current["metadata"]["labels"] = {"owner" => "other-client"}
      update_store.call(key, current, resource_version: current.dig("metadata", "resourceVersion"))
      update_store.call(*args, **options)
    end

    refused = @store.stub(:update, concurrent_update) { put(original) }

    assert_equal 409, refused.status
    assert_equal({"owner" => "other-client"}, get(original).dig("metadata", "labels"))
    assert_equal original.dig("metadata", "uid"), get(original).dig("metadata", "uid")
  end

  def test_stored_and_decoded_selection_respect_explicit_root_labels
    original = create_job("selector-visible")
    candidate = job("explicit-root", labels: {"app" => "pods"})
    candidate["metadata"]["labels"] = {"app" => "job"}
    explicit = request("POST", JOBS, candidate).body
    uid = original.dig("metadata", "uid")
    label_selector = "#{CONTROLLER_UID}=#{uid}"

    assert_equal({"app" => "job"}, stored_job(explicit).dig("metadata", "labels"))
    assert_equal explicit, put(explicit).body
    listed = request("GET", "#{JOBS}?labelSelector=#{label_selector}")

    assert_equal 200, listed.status
    assert_equal(["selector-visible"], listed.body.fetch("items").map { |item| item.dig("metadata", "name") })
    raw = @store.list("registry/batch/v1/jobs/default", label_selector: label_selector)

    assert_equal(["selector-visible"], raw.items.map { |item| item.dig("metadata", "name") })
    assert_nil raw.items.first.dig("metadata", "labels")

    selectors = Rubernetes::API::Selectors.new(label_selector: label_selector)

    assert selectors.matches?(raw.items.first)

    adapter = Rubernetes::API::StoreAdapter.new(@store)
    watch = adapter.watch(resource: @job_resource, namespace: "default", selectors: selectors, resource_version: "0")
    event = watch.next(timeout: 1)

    assert_equal "ADDED", event.type
    assert_equal uid, event.object.dig("metadata", "labels", CONTROLLER_UID)
    custom = copy(raw.items.first).merge("apiVersion" => "example.test/v1")
    custom_resource = Rubernetes::API::Resource.new(group: "example.test", version: "v1", resource: "jobs", kind: "Job", custom: true)

    refute selectors.matches?(custom)
    assert_equal custom, adapter.convert_out(custom_resource, custom)
    raw_selector = Rubernetes::Storage::Selector.new(label_selector: label_selector, field_selector: nil)

    refute raw_selector.matches?(custom)
  ensure
    watch&.close
  end

  def test_stored_legacy_selectors_survive_updates
    uid = "legacy-uid"
    invalid_values = {"matchExpressions" => [{"key" => "tier", "operator" => "In", "values" => ["invalid value"]}]}
    legacy = [
      ["legacy-auto", false, {"matchLabels" => {"controller-uid" => uid}}],
      ["legacy-manual", true, invalid_values]
    ]
    legacy.each do |name, manual, selector|
      seed_job(name, uid, selector, manual: manual)
      candidate = copy(get(job(name)))
      candidate["spec"]["parallelism"] = 2
      accepted = apply(candidate)

      assert_equal 200, accepted.status, accepted.body.inspect
      assert_equal selector, accepted.body.dig("spec", "selector")
      assert_equal 2, accepted.body.dig("spec", "parallelism")
    end
  end

  def test_null_label_value_is_a_present_empty_string_on_put_and_apply
    selector = {"matchExpressions" => [{"key" => "tier", "operator" => "In", "values" => [""]}]}
    original = create_job("empty-label", {"manualSelector" => true, "selector" => selector}, labels: {"tier" => ""})
    candidate = copy(original)
    candidate["spec"]["template"]["metadata"]["labels"]["tier"] = nil

    [put(candidate), apply(candidate)].each do |accepted|
      assert_equal 200, accepted.status, accepted.body.inspect
      assert_equal({"tier" => ""}, accepted.body.dig("spec", "template", "metadata", "labels"))
    end
  end

  def test_suspended_job_checks_pod_spec_immutability_once
    original = create_job("suspended")
    candidate = copy(original)
    candidate["spec"]["template"]["metadata"]["name"] = "renamed"
    accepted = put(candidate)

    assert_equal 200, accepted.status
    assert_equal "renamed", accepted.body.dig("spec", "template", "metadata", "name")
    candidate = copy(accepted.body)
    candidate["spec"]["template"]["spec"]["containers"][0]["image"] = "other"
    refused = apply(candidate)

    assert_equal 422, refused.status
    assert_equal ["spec.template.spec"], cause_fields(refused)
    pod_spec = immutable_error_value(refused)

    assert_equal "other", pod_spec.fetch("Containers").first.fetch("Image")
    assert_nil pod_spec.fetch("InitContainers")
    assert_equal false, pod_spec.dig("SecurityContext", "HostNetwork")
    assert_equal accepted.body, get(candidate)
  end

  def test_unsuspended_template_error_prints_go_metadata_and_pod_spec
    owner = {"apiVersion" => "v1", "kind" => "ConfigMap", "name" => "parent", "uid" => "owner",
             "controller" => false, "blockOwnerDeletion" => false}
    candidate = job("immutable-template", {"manualSelector" => true, "selector" => {}, "suspend" => false})
    candidate["spec"]["template"]["metadata"] = {
      "labels" => {"test" => "x"}, "ownerReferences" => [owner], "annotations" => {"example.test/value" => "<x&>"}
    }
    created = request("POST", JOBS, candidate)

    assert_equal 201, created.status
    candidate = copy(created.body)
    candidate["spec"]["template"]["spec"]["containers"][0].merge!("image" => "other", "command" => [])
    refused = put(candidate)

    assert_equal 422, refused.status
    assert_equal ["spec.template"], cause_fields(refused)
    assert_includes causes(refused).first.fetch("message"), '\u003cx\u0026\u003e'
    internal_template = immutable_error_value(refused)

    assert_equal %w[labels annotations ownerReferences Spec], internal_template.keys
    assert_equal [owner], internal_template.fetch("ownerReferences")
    assert_empty internal_template.dig("Spec", "Containers", 0, "Command")
  end

  def test_json_patch_null_retains_a_label_while_merge_patch_removes_it
    selector = {"matchLabels" => {"tier" => ""}}
    original = create_job("patch-label", {"manualSelector" => true, "selector" => selector}, labels: {"tier" => ""})
    json_patch = [{"op" => "replace", "path" => "/spec/template/metadata/labels/tier", "value" => nil}]
    accepted = request("PATCH", endpoint(original), json_patch, "application/json-patch+json")

    assert_equal 200, accepted.status
    assert_equal({"tier" => ""}, accepted.body.dig("spec", "template", "metadata", "labels"))

    merge_patch = {"spec" => {"template" => {"metadata" => {"labels" => {"tier" => nil}}}}}
    refused = request("PATCH", endpoint(original), merge_patch, "application/merge-patch+json")

    assert_equal 422, refused.status
    assert_equal [TEMPLATE_LABELS_PATH, TEMPLATE_LABELS_PATH], cause_fields(refused)
    assert_equal accepted.body, get(original)
  end

  private

  def job(name, fields = {}, labels: nil)
    template = {"spec" => {"containers" => [{"name" => "main", "image" => "busybox"}], "restartPolicy" => "Never"}}
    template["metadata"] = {"labels" => labels} if labels
    {"apiVersion" => "batch/v1", "kind" => "Job", "metadata" => {"name" => name, "namespace" => "default"},
     "spec" => {"suspend" => true, "template" => template}.merge(fields)}
  end

  def seed_job(name, uid, selector, manual:)
    fields = {"selector" => selector, "manualSelector" => manual}
    labels = {"controller-uid" => uid, "job-name" => name}
    object = job(name, fields, labels: labels)
    object["metadata"]["uid"] = uid
    definition = Rubernetes::Generated.definition_for("io.k8s.api.batch.v1.Job")
    @store.create("registry/batch/v1/jobs/default/#{name}", definition.defaulting.apply_hash(object, kubernetes_admission_defaults: :update))
  end

  def create_job(name, fields = {}, labels: nil)
    response = request("POST", JOBS, job(name, fields, labels: labels))

    assert_equal 201, response.status, response.body.inspect
    response.body
  end

  def get(object)
    request("GET", endpoint(object)).body
  end

  def stored_job(object)
    @store.get("registry/batch/v1/jobs/default/#{object.dig("metadata", "name")}")
  end

  def put(object)
    request("PUT", endpoint(object), object)
  end

  def apply(object)
    body = object.except("status").merge("metadata" => object.fetch("metadata").slice("name", "namespace"))
    request("PATCH", "#{endpoint(object)}?fieldManager=selector-probe&force=true", body, "application/apply-patch+yaml")
  end

  def endpoint(object)
    "#{JOBS}/#{object.dig("metadata", "name")}"
  end

  def request(method, path, body = nil, type = "application/json")
    identity = {"username" => "admin", "groups" => ["system:masters"]}
    request = Rubernetes::API::Request.new(
      method: method, path: path, body: body && JSON.generate(body), identity: identity, headers: {"content-type" => type}
    )
    @server.call(request)
  end

  def copy(object)
    Marshal.load(Marshal.dump(object))
  end

  def causes(response)
    response.body.dig("details", "causes")
  end

  def cause_fields(response)
    causes(response).map { |cause| cause.fetch("field") }
  end

  def immutable_error_value(response)
    JSON.parse(causes(response).first.fetch("message").delete_prefix("Invalid value: ").delete_suffix(": field is immutable"))
  end
end
