# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class BatchSelectorAdmissionTest < Minitest::Test
  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry)
  end

  def test_cronjob_rejects_user_owned_job_selectors
    response = create("CronJob", "schedule" => "@daily", "jobTemplate" => {"spec" => job_spec.merge(
      "selector" => {"matchExpressions" => []}, "manualSelector" => true
    )})

    assert_equal 422, response.status
    assert_equal([
                   ["spec.jobTemplate.spec.selector", "Invalid value: {}: `selector` will be auto-generated"],
                   ["spec.jobTemplate.spec.manualSelector", 'Unsupported value: true: supported values: "nil", "false"']
                 ], response.body.dig("details", "causes").map { |entry| entry.values_at("field", "message") })
  end

  def test_cronjob_collects_scheduling_limits_and_name_errors_in_registry_order
    spec = {"schedule" => "@hourly", "timeZone" => "local", "jobTemplate" => {"spec" => job_spec},
            "startingDeadlineSeconds" => -1, "concurrencyPolicy" => "parallel", "successfulJobsHistoryLimit" => -1}
    response = create("CronJob", spec, {"name" => "a" * 53})

    assert_equal 422, response.status
    fields = response.body.dig("details", "causes").map { |cause| cause.fetch("field") }

    assert_equal %w[spec.startingDeadlineSeconds spec.timeZone spec.timeZone spec.concurrencyPolicy spec.successfulJobsHistoryLimit metadata.name], fields
  end

  def test_status_patch_preserves_an_old_cronjob_with_a_retained_invalid_schedule
    resource = @server.registry.find_gvr(group: "batch", version: "v1", resource: "cronjobs")
    name = "a" * 53
    path = "/apis/batch/v1/namespaces/ns/cronjobs/#{name}"
    @server.store.create(resource: resource, namespace: "ns", object: {
                           "apiVersion" => "batch/v1", "kind" => "CronJob", "metadata" => {"name" => name, "namespace" => "ns"},
                           "spec" => {"schedule" => "retired-schedule", "jobTemplate" => {"spec" => job_spec}}
                         })
    headers = {"content-type" => "application/merge-patch+json"}
    time = "2026-11-01T05:30:00Z"
    response = @server.call(method: "PATCH", path: "#{path}/status", headers: headers, body: {"status" => {"lastScheduleTime" => time}})

    assert_equal 200, response.status, response.body.inspect
    assert_equal time, response.body.dig("status", "lastScheduleTime")
    assert_equal "retired-schedule", response.body.dig("spec", "schedule")
    repaired = @server.call(method: "PATCH", path: path, headers: headers, body: {"spec" => {"schedule" => "@daily"}})

    assert_equal 200, repaired.status, repaired.body.inspect
  end

  def test_metadata_schedule_label_is_ordinary_data
    assert_equal 201, create("Job", job_spec).status
    assert_equal 201, create("CronJob", "schedule" => "@hourly", "jobTemplate" => {"spec" => job_spec}).status
  end

  def test_manual_job_selector_requires_presence_for_an_empty_value
    expression = {"key" => "tier", "operator" => "In", "values" => [""]}
    spec = job_spec.merge("manualSelector" => true, "selector" => {"matchExpressions" => [expression]})
    response = create("Job", spec)

    assert_equal 422, response.status
    assert_equal(["spec.template.metadata.labels"], response.body.dig("details", "causes").map { |cause| cause.fetch("field") })
    spec.dig("template", "metadata", "labels")["tier"] = ""

    assert_equal 201, create("Job", spec).status
  end

  def test_automatic_job_selector_uses_server_uid_and_inherits_template_labels
    response = create("Job", job_spec.merge("selector" => {}), {"name" => "sample", "uid" => "client-uid"})

    assert_equal 201, response.status
    uid = response.body.dig("metadata", "uid")

    refute_equal "client-uid", uid
    assert_equal uid, response.body.dig("spec", "selector", "matchLabels", "batch.kubernetes.io/controller-uid")
    assert_equal uid, response.body.dig("metadata", "labels", "controller-uid")
    assert_equal response.body.dig("spec", "template", "metadata", "labels"), response.body.dig("metadata", "labels")
  end

  def test_job_without_any_labels_returns_generated_labels_on_both_objects
    spec = job_spec
    spec["template"].delete("metadata")
    response = create("Job", spec)

    assert_equal 201, response.status
    assert_equal response.body.dig("spec", "template", "metadata", "labels"), response.body.dig("metadata", "labels")
    assert_equal "sample", response.body.dig("metadata", "labels", "batch.kubernetes.io/job-name")
  end

  def test_explicit_root_labels_matching_template_stay_independent
    response = create("Job", job_spec, {"name" => "sample", "labels" => {"schedule" => "nightly"}})

    assert_equal 201, response.status
    assert_equal({"schedule" => "nightly"}, response.body.dig("metadata", "labels"))
    assert_equal "sample", response.body.dig("spec", "template", "metadata", "labels", "job-name")
  end

  def test_generation_preserves_conflicting_labels_for_admission
    spec = job_spec
    spec.dig("template", "metadata", "labels")["job-name"] = "other"
    response = create("Job", spec)

    assert_equal 422, response.status
    cause = response.body.dig("details", "causes").fetch(0)

    assert_equal "spec.template.metadata.labels[job-name]", cause["field"]
    assert_includes cause["message"], "must be 'sample'"
  end

  def test_automatic_selector_must_match_job_identity
    response = create("Job", job_spec.merge("selector" => {"matchLabels" => {"schedule" => "nightly"}}))

    assert_equal 422, response.status
    assert_equal "spec.selector", response.body.dig("details", "causes", 0, "field")
    assert_includes response.body.dig("details", "causes", 0, "message"), "`selector` not auto-generated"
  end

  private

  def job_spec
    {"template" => {"metadata" => {"labels" => {"schedule" => "nightly"}},
                    "spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "worker", "image" => "example/test"}]}}}
  end

  def create(kind, spec, metadata = {"name" => "sample"})
    document = {"apiVersion" => "batch/v1", "kind" => kind, "metadata" => metadata, "spec" => spec}
    request = Rubernetes::API::Request.new(method: "POST", path: "/apis/batch/v1/namespaces/ns/#{kind.downcase}s",
                                           headers: {"content-type" => "application/json"}, body: JSON.generate(document),
                                           identity: {"username" => "admin", "groups" => ["system:masters"]})
    @server.call(request)
  end
end
