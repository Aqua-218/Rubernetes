# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class APIJobStatusUpdateTest < Minitest::Test
  JOBS = "/apis/batch/v1/namespaces/ns/jobs"
  PATH = "#{JOBS}/sample".freeze
  START = "2026-11-19T08:30:00Z"
  FINISH = "2026-11-19T08:31:00Z"

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry)
    @job = create_job
  end

  private def create_job
    template = {"spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "job", "image" => "worker"}]}}
    created = @server.call(method: "POST", path: JOBS, body: {"apiVersion" => "batch/v1", "kind" => "Job",
                                                              "metadata" => {"name" => "sample"}, "spec" => {"template" => template}})

    assert_equal 201, created.status
    created.body
  end

  def test_valid_terminal_status_cannot_be_reopened
    complete = %w[SuccessCriteriaMet Complete].map { |type| {"type" => type, "status" => "True"} }
    final = put(@job, "conditions" => complete, "succeeded" => 1, "startTime" => START, "completionTime" => FINISH)

    assert_equal 200, final.status
    rejected = put(final.body, {})

    assert_equal 422, rejected.status
    causes = rejected.body.dig("details", "causes")

    assert_equal "Invalid value: cannot disable the terminal Complete=True condition", causes.first["message"]
    assert_equal(%w[status.conditions status.succeeded status.startTime status.conditions], causes.map { |cause| cause.fetch("field") })
    assert_equal final.body, @server.call(method: "GET", path: PATH).body
  end

  def test_patch_checks_pod_counts_and_preserves_the_previous_version
    rejected = @server.call(method: "PATCH", path: "#{PATH}/status", body: {"status" => {"active" => 1, "ready" => 2}},
                            headers: {"content-type" => "application/merge-patch+json"})

    assert_equal 422, rejected.status
    assert_equal "Invalid value: 2: cannot set more ready pods than active", rejected.body.dig("details", "causes", 0, "message")
    assert_equal @job, @server.call(method: "GET", path: PATH).body
  end

  def test_legacy_invalid_fields_do_not_block_unrelated_status_updates
    state = @job.merge("status" => {"ready" => 7, "active" => 1})
    update = state.merge("status" => state["status"].merge("startTime" => START))
    issues = Rubernetes::Schema::KubernetesValidator::JobStatusUpdate.new(update, state).errors

    assert_empty issues
  end

  def test_main_resource_patch_preserves_absent_and_populated_status
    headers = {"content-type" => "application/merge-patch+json"}
    patch = {"status" => {"active" => 3}}
    initial = @server.call(method: "PATCH", path: PATH, body: patch, headers: headers)

    assert_equal 200, initial.status
    refute initial.body.key?("status")
    published = put(initial.body, "active" => 1)

    assert_equal 200, published.status

    changed = @server.call(method: "PATCH", path: PATH, body: patch, headers: headers)

    assert_equal 200, changed.status
    assert_equal published.body.fetch("status"), changed.body.fetch("status")
    assert_equal changed.body, @server.call(method: "GET", path: PATH).body
  end

  private

  def put(job, status)
    @server.call(method: "PUT", path: "#{PATH}/status", body: job.merge("spec" => {}, "status" => status))
  end
end
