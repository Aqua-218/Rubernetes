# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class JobSpecLimitsAdmissionTest < Minitest::Test
  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry)
  end

  def test_batch_admission_reports_nonnegative_fields_before_index_dependencies
    negative = {"parallelism" => -1, "completions" => -2, "activeDeadlineSeconds" => -3, "backoffLimit" => -4,
                "ttlSecondsAfterFinished" => -5, "backoffLimitPerIndex" => -6, "maxFailedIndexes" => -7}
    %w[Job CronJob].each do |kind|
      prefix = kind == "Job" ? "spec" : "spec.jobTemplate.spec"
      expected = negative.map do |field, value|
        ["#{prefix}.#{field}", "Invalid value: #{value}: must be greater than or equal to 0"]
      end
      expected += [%w[backoffLimitPerIndex -6], %w[maxFailedIndexes -7]].map do |field, value|
        ["#{prefix}.#{field}", "Invalid value: #{value}: requires indexed completion mode"]
      end

      assert_equal expected, rejection(create(kind, negative))
    end
  end

  def test_indexed_boundaries_and_limit_dependencies
    at_limits = {"completionMode" => "Indexed", "parallelism" => 100_000, "completions" => 100_000,
                 "backoffLimitPerIndex" => 0, "maxFailedIndexes" => 100_000}
    high_completions = at_limits.merge("completions" => 100_001, "parallelism" => 10_000, "maxFailedIndexes" => 10_000)

    assert_equal 201, create("Job", at_limits, name: "indexed-boundary").status
    assert_equal 201, create("CronJob", high_completions).status
    assert_equal [
      ["spec.maxFailedIndexes", "Required value: must be specified when completions is above 100000"],
      ["spec.parallelism", "Invalid value: 10001: must be less than or equal to 10000 when completions are above 100000 and used with backoff limit per index"]
    ], rejection(create("Job", at_limits.merge("completions" => 100_001, "parallelism" => 10_001, "maxFailedIndexes" => nil)))
    assert_equal [["spec.completions", "Required value: when completion mode is Indexed"]],
                 rejection(create("Job", {"completionMode" => "Indexed", "parallelism" => 1}))
  end

  def test_replacement_errors_precede_pod_template_restart_constraints
    fields = {"podReplacementPolicy" => "TerminatingOrFailed",
              "podFailurePolicy" => {"rules" => [{"action" => "FailJob", "onExitCodes" => {"operator" => "In", "values" => [1]}}]},
              "template" => pod_template("OnFailure")}

    assert_equal [
      ["spec.jobTemplate.spec.podReplacementPolicy", 'Unsupported value: "TerminatingOrFailed": supported values: "Failed"'],
      ["spec.jobTemplate.spec.template.spec.restartPolicy", 'Invalid value: "OnFailure": only "Never" is supported when podFailurePolicy is specified']
    ], rejection(create("CronJob", fields))
    assert_equal [
      ["spec.parallelism", "Invalid value: -1: must be greater than or equal to 0"],
      ["spec.template.spec.containers", "Required value"],
      ["spec.template.spec.restartPolicy", 'Required value: valid values: "OnFailure", "Never"']
    ], rejection(create("Job", {"parallelism" => -1, "template" => {"spec" => {"containers" => []}}}))
    assert_equal [
      ["spec.template.spec.restartPolicy", 'Unsupported value: "Sometimes": supported values: "Always", "OnFailure", "Never"'],
      ["spec.template.spec.restartPolicy", 'Unsupported value: "Sometimes": supported values: "OnFailure", "Never"']
    ], rejection(create("Job", {"template" => pod_template("Sometimes")}))
  end

  def test_failed_indexes_require_index_backoff_and_completion_mode_is_an_enum
    assert_equal [
      ["spec.backoffLimitPerIndex", "Required value: when maxFailedIndexes is specified"],
      ["spec.maxFailedIndexes", "Invalid value: 0: requires indexed completion mode"]
    ], rejection(create("Job", {"maxFailedIndexes" => 0}))
    assert_equal [["spec.completionMode", 'Unsupported value: "invalid": supported values: "NonIndexed", "Indexed"']],
                 rejection(create("Job", {"completionMode" => "invalid", "backoffLimitPerIndex" => 1}))
  end

  def test_job_update_repeats_ordered_validation_before_immutability
    current = create("Job", {"completionMode" => "Indexed", "parallelism" => 2, "completions" => 4, "backoffLimitPerIndex" => 1})

    assert_equal 201, current.status
    pass_errors = [
      ["spec.parallelism", "Invalid value: -1: must be greater than or equal to 0"],
      ["spec.completions", "Invalid value: -2: must be greater than or equal to 0"],
      ["spec.backoffLimitPerIndex", "Invalid value: -1: must be greater than or equal to 0"]
    ]
    expected = pass_errors + pass_errors + [
      ["spec.completions", "Invalid value: -2: can only be modified in tandem with spec.parallelism"],
      ["spec.backoffLimitPerIndex", "Invalid value: -1: field is immutable"]
    ]

    assert_equal expected, rejection(update(current, "parallelism" => -1, "completions" => -2, "backoffLimitPerIndex" => -1))
    assert_equal 200, update(current, "parallelism" => 5, "completions" => 5).status
  end

  def test_cronjob_update_validates_embedded_spec_once_and_accepts_replacement_changes
    current = create("CronJob", {"completionMode" => "Indexed", "completions" => 4, "backoffLimitPerIndex" => 1})

    assert_equal 201, current.status
    assert_equal [["spec.jobTemplate.spec.backoffLimitPerIndex", "Invalid value: 1: requires indexed completion mode"]],
                 rejection(update(current, "completionMode" => "NonIndexed"))
    fields = {"completionMode" => "NonIndexed", "backoffLimitPerIndex" => nil, "podReplacementPolicy" => "Failed"}

    assert_equal 200, update(current, fields).status
  end

  private

  def pod_template(restart_policy = "Never")
    {"spec" => {"restartPolicy" => restart_policy, "containers" => [{"name" => "worker", "image" => "example/test"}]}}
  end

  def create(kind, fields, name: "sample")
    spec = {"suspend" => true, "template" => pod_template}.merge(fields)
    spec = {"schedule" => "@daily", "jobTemplate" => {"spec" => spec}} if kind == "CronJob"
    body = {"apiVersion" => "batch/v1", "kind" => kind, "metadata" => {"name" => name}, "spec" => spec}
    request("POST", "/apis/batch/v1/namespaces/ns/#{kind.downcase}s", body)
  end

  def update(current, fields)
    body = JSON.parse(JSON.generate(current.body))
    kind = body.fetch("kind")
    spec = kind == "Job" ? body.fetch("spec") : body.dig("spec", "jobTemplate", "spec")
    spec.merge!(fields)
    request("PUT", "/apis/batch/v1/namespaces/ns/#{kind.downcase}s/#{body.dig("metadata", "name")}", body)
  end

  def request(method, path, body)
    request = Rubernetes::API::Request.new(
      method: method, path: path, headers: {"content-type" => "application/json"},
      body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}
    )
    @server.call(request)
  end

  def rejection(response)
    assert_equal 422, response.status, response.body.inspect
    response.body.dig("details", "causes").map { |cause| cause.values_at("field", "message") }
  end
end
