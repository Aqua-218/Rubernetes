# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/schema"

# validatePodTemplateUpdate (pkg/apis/batch/validation, v1.36.2): a Job's pod
# template is immutable, but a suspended Job that has no active Pods and never
# started (or is marked JobSuspended) may change its scheduling directives
# (MutableSchedulingDirectivesForSuspendedJobs) and its containers' resources
# (MutablePodResourcesForSuspendedJobs).
class JobTemplateUpdateValidationTest < Minitest::Test
  V = Rubernetes::Schema::KubernetesValidator

  def job(suspend: false, status: {}, resources: {"requests" => {"cpu" => "1"}}, node_selector: nil, labels: {"job-name" => "j"},
          image: "busybox")
    pod = {"containers" => [{"name" => "c", "image" => image, "resources" => resources}], "restartPolicy" => "Never"}
    pod["nodeSelector"] = node_selector if node_selector
    {"metadata" => {"name" => "j"}, "spec" => {"suspend" => suspend, "template" => {"metadata" => {"labels" => labels}, "spec" => pod}},
     "status" => status}
  end

  def errors(new_job, old_job)
    V.job_template_update_errors(new_job, old_job, :update).map { |issue| "#{issue.path.join(".")}: #{issue.message}" }
  end

  def test_a_running_job_template_is_immutable
    old = job

    assert_empty errors(job, old)
    assert_equal ["spec.template: field is immutable"], errors(job(image: "other"), old)
    assert_equal ["spec.template: field is immutable"], errors(job(resources: {"requests" => {"cpu" => "2"}}), old)
  end

  def test_a_suspended_never_started_job_may_change_resources_and_scheduling
    old = job(suspend: true)

    assert_empty errors(job(suspend: true, resources: {"requests" => {"cpu" => "4"}}), old)
    assert_empty errors(job(suspend: true, node_selector: {"zone" => "a"}, labels: {"job-name" => "j", "x" => "y"}), old)
    # Anything else still is immutable.
    assert_equal ["spec.template.spec: field is immutable"], errors(job(suspend: true, image: "other"), old)
  end

  def test_a_started_suspended_job_needs_the_suspended_condition_and_no_active_pods
    started = {"startTime" => "2026-09-24T00:00:00Z"}
    old = job(suspend: true, status: started)

    assert_equal ["spec.template: field is immutable"], errors(job(suspend: true, resources: {"requests" => {"cpu" => "4"}}), old)
    marked = job(suspend: true, status: started.merge("conditions" => [{"type" => "JobSuspended", "status" => "True"}]))

    assert_empty errors(job(suspend: true, resources: {"requests" => {"cpu" => "4"}}), marked)
    busy = job(suspend: true, status: {"active" => 1})

    assert_equal ["spec.template: field is immutable"], errors(job(suspend: true, resources: {"requests" => {"cpu" => "4"}}), busy)
  end

  def test_nil_and_empty_collections_compare_equal
    old = job(resources: {})
    new_job = job(resources: {})
    new_job["spec"]["template"]["spec"]["containers"][0].delete("resources")
    new_job["spec"]["template"]["spec"]["volumes"] = []

    assert_empty errors(new_job, old)
  end
end
