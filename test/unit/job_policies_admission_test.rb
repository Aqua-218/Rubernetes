# frozen_string_literal: true

require_relative "../test_helper"
require "rubernetes/bootstrap"

class JobPoliciesAdmissionTest < Minitest::Test
  INDEXED = {"completionMode" => "Indexed", "completions" => 5, "parallelism" => 2}.freeze

  def setup
    registry = Rubernetes::Bootstrap::APIServerService.allocate.send(:build_registry, Rubernetes::Schema::Catalog.default)
    @server = Rubernetes::API::Server.new(registry: registry)
  end

  def test_pod_failure_policies_validate_rule_members_before_the_conflict
    fields = failure({"action" => "FailIndex", "onExitCodes" => {"containerName" => "absent", "operator" => "In", "values" => [1, 0, 0]},
                      "onPodConditions" => [{"type" => "example.org/Ready", "status" => "Maybe"}]})
    expected = [
      [".action", "FieldValueInvalid", 'Invalid value: "FailIndex": requires the backoffLimitPerIndex to be set'],
      [".onExitCodes.containerName", "FieldValueInvalid", 'Invalid value: "absent": must be one of the container or initContainer names in the pod template'],
      [".onExitCodes.values[1]", "FieldValueInvalid", "Invalid value: 0: must not be 0 for the In operator"],
      [".onExitCodes.values[2]", "FieldValueInvalid", "Invalid value: 0: must not be 0 for the In operator"],
      [".onExitCodes.values[2]", "FieldValueDuplicate", "Duplicate value: 0"],
      [".onExitCodes.values", "FieldValueInvalid", "Invalid value: [1,0,0]: must be ordered"],
      [".onPodConditions[0].status", "FieldValueNotSupported", 'Unsupported value: "Maybe": supported values: "False", "True", "Unknown"'],
      ["", "FieldValueInvalid", "Invalid value: specifying both OnExitCodes and OnPodConditions is not supported"]
    ]

    %w[Job CronJob].each do |kind|
      prefix = "#{spec_path(kind)}.podFailurePolicy.rules[0]"

      assert_equal expected.map { |suffix, reason, message| [prefix + suffix, reason, message] }, causes(create(kind, fields))
    end
  end

  def test_empty_exit_requirements_report_strategy_causes_and_init_names_are_supported
    base = "spec.podFailurePolicy.rules[0].onExitCodes"

    assert_equal [
      ["#{base}.operator", "FieldValueRequired", 'Required value: valid values: ["In" "NotIn"]'],
      ["#{base}.values", "FieldValueInvalid", "Invalid value: null: at least one value is required"]
    ], causes(create("Job", failure({"action" => "Count", "onExitCodes" => {}})))

    allowed = {"action" => "Ignore", "onExitCodes" => {"operator" => "NotIn", "values" => [-1, 0, 1], "containerName" => "setup"}}

    assert_equal 201, create("Job", failure(allowed)).status
  end

  def test_success_policies_count_intervals_and_preserve_error_order
    fields = INDEXED.merge(success({"succeededIndexes" => "0,3-2", "succeededCount" => 6}))
    expected = [
      ["succeededIndexes", "FieldValueInvalid", 'Invalid value: "0,3-2": error parsing succeededIndexes: non-increasing order, previous: 3, current: 2'],
      ["succeededCount", "FieldValueInvalid", "Invalid value: 6: must be less than or equal to 5 (the number of specified completions)"],
      ["succeededCount", "FieldValueInvalid",
       "Invalid value: 6: must be less than or equal to 0 (the number of indexes in the specified succeededIndexes field)"]
    ]
    %w[Job CronJob].each do |kind|
      prefix = "#{spec_path(kind)}.successPolicy.rules[0]"

      assert_equal expected.map { |field, reason, message| ["#{prefix}.#{field}", reason, message] }, causes(create(kind, fields))
    end
    large = INDEXED.merge("completions" => 2_147_483_647).merge(success({"succeededIndexes" => "+0-2147483646", "succeededCount" => 2_147_483_647}))

    assert_equal 201, create("Job", large).status
  end

  def test_null_pod_condition_uses_the_default_status_and_requires_a_type
    fields = failure({"action" => "Count", "onPodConditions" => [nil]})
    errors = causes(create("Job", fields))

    assert_equal ["spec.podFailurePolicy.rules[0].onPodConditions[0].type"] * 2, errors.map(&:first)
    assert_equal 'Invalid value: "": name part must be non-empty', errors.first.last
  end

  def test_empty_and_oversized_success_rules
    assert_equal [["spec.successPolicy", "FieldValueInvalid", 'Invalid value: {"Rules":null}: requires indexed completion mode']],
                 causes(create("Job", {"successPolicy" => {}}))
    assert_equal [
      ["spec.successPolicy.rules", "FieldValueRequired", "Required value: at least one rules must be specified when the successPolicy is specified"]
    ], causes(create("Job", INDEXED.merge(success)))
    assert_equal [["spec.successPolicy.rules", "FieldValueTooMany", "Too many: 21: must have at most 20 items"]],
                 causes(create("Job", INDEXED.merge(success(*Array.new(21, {"succeededCount" => 1})))))
    assert_equal [["spec.successPolicy.rules[0].succeededIndexes", "FieldValueTooLong", "Too long: may not be more than 65536 bytes"]],
                 causes(create("Job", INDEXED.merge(success({"succeededIndexes" => "0" * 65_537}))))
  end

  def test_indexed_success_policy_without_completions_returns_a_field_error
    fields = INDEXED.except("completions").merge(success({"succeededCount" => 1}))

    assert_equal [["spec.completions", "FieldValueRequired", "Required value: when completion mode is Indexed"]], causes(create("Job", fields))
  end

  def test_job_policy_immutability_reports_upstream_values_and_cronjob_allows_updates
    initial = INDEXED.merge(failure({"action" => "Count", "onPodConditions" => [{"type" => "Ready"}]})).merge(success({"succeededCount" => 1}))
    fields = failure({"action" => "Ignore", "onPodConditions" => [{"type" => "Ready"}]}).merge(success({"succeededIndexes" => "0-2", "succeededCount" => 2}))
    job = create("Job", initial)
    cron = create("CronJob", initial)

    assert_equal 201, job.status
    assert_equal 201, cron.status
    assert_equal [
      ["spec.podFailurePolicy", "FieldValueInvalid",
       'Invalid value: {"Rules":[{"Action":"Ignore","OnExitCodes":null,"OnPodConditions":[{"Type":"Ready","Status":"True"}]}]}: field is immutable'],
      ["spec.successPolicy", "FieldValueInvalid", 'Invalid value: {"Rules":[{"SucceededIndexes":"0-2","SucceededCount":2}]}: field is immutable']
    ], causes(update(job, fields))
    assert_equal 200, update(cron, fields).status
  end

  private

  def failure(*rules) = {"podFailurePolicy" => {"rules" => rules}}

  def success(*rules) = {"successPolicy" => {"rules" => rules}}

  def spec_path(kind) = kind == "Job" ? "spec" : "spec.jobTemplate.spec"

  def create(kind, fields)
    template = {"spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "worker", "image" => "example/test"}],
                           "initContainers" => [{"name" => "setup", "image" => "example/test"}]}}
    spec = {"suspend" => true, "template" => template}.merge(fields)
    spec = {"schedule" => "@daily", "jobTemplate" => {"spec" => spec}} if kind == "CronJob"
    manifest = {"apiVersion" => "batch/v1", "kind" => kind, "metadata" => {"name" => "test"}, "spec" => spec}
    request("POST", "/apis/batch/v1/namespaces/ns/#{kind.downcase}s", manifest)
  end

  def update(current, fields)
    manifest = JSON.parse(JSON.generate(current.body))
    kind = manifest.fetch("kind")
    manifest.dig(*spec_path(kind).split(".")).merge!(fields)
    request("PUT", "/apis/batch/v1/namespaces/ns/#{kind.downcase}s/test", manifest)
  end

  def request(method, path, body)
    @server.call(Rubernetes::API::Request.new(method: method, path: path, headers: {"content-type" => "application/json"},
                                              body: JSON.generate(body), identity: {"username" => "admin", "groups" => ["system:masters"]}))
  end

  def causes(response)
    assert_equal 422, response.status, response.body.inspect
    response.body.dig("details", "causes").map { |cause| cause.values_at("field", "reason", "message") }
  end
end
