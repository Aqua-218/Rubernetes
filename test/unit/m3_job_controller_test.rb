# frozen_string_literal: true

# The controller package is loaded directly so an unrelated package syntax
# error cannot mask a Job semantics regression.
require "minitest/autorun"
require "rubernetes/controller"
require "rubernetes/storage/memory_store"
require "rubernetes/observability/metrics"

# Job controller semantics pinned to pkg/controller/job at Kubernetes v1.36.2.
class M3JobControllerTest < Minitest::Test
  Controller = Rubernetes::Controller
  FINALIZER = "batch.kubernetes.io/job-tracking"
  INDEX = "batch.kubernetes.io/job-completion-index"
  NOW = Time.utc(2026, 1, 1, 12, 0, 0)

  def test_non_indexed_job_creates_parallelism_pods_with_tracking_finalizer_and_generate_name
    job = job(completions: 3, parallelism: 2)
    result = controller.plan(job, pods: [], now: NOW)

    assert_equal 2, result.creates.length
    result.creates.each do |create|
      metadata = create.object.fetch("metadata")

      assert_equal "batch-", metadata.fetch("generateName")
      assert_nil metadata["name"]
      assert_includes metadata.fetch("finalizers"), FINALIZER
      assert_equal "Job", metadata.fetch("ownerReferences").first.fetch("kind")
    end
    status = result.status

    assert_equal 2, status.fetch("active")
    assert_equal 0, status.fetch("ready")
    assert_equal 0, status.fetch("terminating")
    assert_equal({}, status.fetch("uncountedTerminatedPods"))
    assert_equal NOW.iso8601(6), status.fetch("startTime")
    assert_equal 0, status.fetch("succeeded")
    refute status.key?("conditions")
    assert_equal(%w[SuccessfulCreate SuccessfulCreate], result.events.map { |event| event.fetch("reason") })
  end

  def test_completed_pods_are_counted_through_uncounted_terminated_pods_and_finalizer_removal
    job = job(completions: 1, parallelism: 1)
    done = pod("batch-a", job, phase: "Succeeded", finalizer: true)
    result = controller.plan(job, pods: [done], now: NOW)

    statuses = result.operations.select { |operation| operation.action == :status_update }

    assert_equal 2, statuses.length, "interim and final status writes"
    interim = statuses.first.patch

    assert_equal ["uid-batch-a"], interim.dig("uncountedTerminatedPods", "succeeded")
    assert_equal "SuccessCriteriaMet", interim.fetch("conditions").first.fetch("type")
    removal = result.updates.find { |operation| operation.resource.kind == "Pod" }

    assert_equal [], removal.object.dig("metadata", "finalizers")
    final = result.status

    assert_equal 1, final.fetch("succeeded")
    assert_equal({}, final.fetch("uncountedTerminatedPods"))
    types = final.fetch("conditions").map { |condition| condition.fetch("type") }

    assert_equal %w[SuccessCriteriaMet Complete], types
    complete = final.fetch("conditions").last

    assert_equal "CompletionsReached", complete.fetch("reason")
    assert_equal "Reached expected number of succeeded pods", complete.fetch("message")
    assert_equal complete.fetch("lastTransitionTime"), final.fetch("completionTime")
    assert_includes result.events.map { |event| event.fetch("reason") }, "Completed"

    finished_job = job.merge("status" => final)

    assert_empty controller.plan(finished_job, pods: [done], now: NOW + 60).operations
  end

  def test_backoff_limit_exceeded_sets_failure_target_then_failed_and_deletes_active_pods
    job = job(completions: 1, parallelism: 1, backoff_limit: 1)
    failed = [pod("batch-f1", job, phase: "Failed", finalizer: true, finished_at: NOW - 30),
              pod("batch-f2", job, phase: "Failed", finalizer: true, finished_at: NOW - 20)]
    active = pod("batch-run", job, phase: "Running", finalizer: true)
    result = controller.plan(job, pods: failed + [active], now: NOW)

    assert_equal(["batch-run"], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    interim = result.operations.find { |operation| operation.action == :status_update }.patch
    failure_target = interim.fetch("conditions").find { |condition| condition.fetch("type") == "FailureTarget" }

    assert_equal "BackoffLimitExceeded", failure_target.fetch("reason")
    assert_equal "Job has reached the specified backoff limit", failure_target.fetch("message")
    final = result.status

    assert_equal 3, final.fetch("failed"), "active pods are counted failed once the Job fails"
    assert_equal 1, final.fetch("terminating")
    refute final.fetch("conditions").any? { |condition| condition.fetch("type") == "Failed" },
           "the Failed condition waits for the terminating pod"

    second = controller.plan(job.merge("status" => final), pods: failed.map { |pod| strip_finalizer(pod) }, now: NOW + 1)
    types = second.status.fetch("conditions").map { |condition| condition.fetch("type") }

    assert_equal %w[FailureTarget Failed], types
    assert_equal "BackoffLimitExceeded", second.status.fetch("conditions").last.fetch("reason")
    assert_equal 0, second.status.fetch("terminating")
  end

  def test_pod_failure_backoff_delays_replacement_with_exponential_requeue
    job = job(completions: 1, parallelism: 1, backoff_limit: 6)
    failed = [pod("batch-f1", job, phase: "Failed", finalizer: false, finished_at: NOW - 12),
              pod("batch-f2", job, phase: "Failed", finalizer: false, finished_at: NOW - 5)]
    result = controller.plan(job.merge("status" => {"failed" => 2}), pods: failed, now: NOW)

    assert_empty result.creates
    assert_in_delta 15.0, result.requeue_after, 0.001, "two failures: 20s backoff minus 5s elapsed"

    later = controller.plan(job.merge("status" => {"failed" => 2}), pods: failed, now: NOW + 16)

    assert_equal 1, later.creates.length
    assert_nil later.requeue_after
  end

  def test_backoff_caps_at_six_minutes_and_resets_after_success
    job = job(completions: 4, parallelism: 1, backoff_limit: 20)
    many = (1..8).map { |index| pod("batch-f#{index}", job, phase: "Failed", finalizer: false, finished_at: NOW - 60) }
    capped = controller.plan(job.merge("status" => {"failed" => 8}), pods: many, now: NOW)

    assert_in_delta 540.0, capped.requeue_after, 0.001

    success = pod("batch-ok", job, phase: "Succeeded", finalizer: false, finished_at: NOW - 30)
    reset = controller.plan(job.merge("status" => {"failed" => 8, "succeeded" => 1}), pods: many + [success], now: NOW)

    assert_equal 1, reset.creates.length
  end

  def test_indexed_job_assigns_completion_indexes_env_and_hostname
    job = job(completions: 3, parallelism: 3, completion_mode: "Indexed")
    existing = pod("batch-1-x", job, phase: "Running", finalizer: true, index: 1)
    result = controller.plan(job, pods: [existing], now: NOW)

    indexes = result.creates.map { |create| Integer(create.object.dig("metadata", "annotations", INDEX)) }

    assert_equal [0, 2], indexes
    first = result.creates.first.object

    assert_equal "batch-0-", first.dig("metadata", "generateName")
    assert_equal "0", first.dig("metadata", "labels", INDEX)
    assert_equal "batch-0", first.dig("spec", "hostname")
    env = first.dig("spec", "containers", 0, "env").first

    assert_equal "JOB_COMPLETION_INDEX", env.fetch("name")
    assert_equal "metadata.annotations['#{INDEX}']", env.dig("valueFrom", "fieldRef", "fieldPath")
  end

  def test_indexed_job_tracks_completed_indexes_and_completes_when_all_indexes_succeed
    job = job(completions: 3, parallelism: 3, completion_mode: "Indexed")
    pods = [pod("batch-0-a", job, phase: "Succeeded", finalizer: true, index: 0),
            pod("batch-2-a", job, phase: "Succeeded", finalizer: true, index: 2)]
    partial = controller.plan(job, pods: pods, now: NOW)

    assert_equal "0,2", partial.status.fetch("completedIndexes")
    assert_equal 2, partial.status.fetch("succeeded")
    assert_equal([1], partial.creates.map { |create| Integer(create.object.dig("metadata", "annotations", INDEX)) })

    job_with_status = job.merge("status" => partial.status)
    middle = pod("batch-1-a", job, phase: "Succeeded", finalizer: true, index: 1)
    complete = controller.plan(job_with_status, pods: pods.map { |pod| strip_finalizer(pod) } + [middle], now: NOW + 5)

    assert_equal "0-2", complete.status.fetch("completedIndexes")
    assert_equal 3, complete.status.fetch("succeeded")
    assert_equal(%w[SuccessCriteriaMet Complete], complete.status.fetch("conditions").map { |condition| condition.fetch("type") })
  end

  def test_backoff_limit_per_index_marks_failed_indexes_and_fails_the_job_at_max_failed_indexes
    job = job(completions: 2, parallelism: 2, completion_mode: "Indexed", backoff_limit_per_index: 1, max_failed_indexes: 0)
    failed_once = pod("batch-0-a", job, phase: "Failed", finalizer: true, index: 0, finished_at: NOW - 30,
                                        annotations: {"batch.kubernetes.io/job-index-failure-count" => "1"})
    result = controller.plan(job, pods: [failed_once], now: NOW)

    assert_equal "0", result.status.fetch("failedIndexes")
    reasons = result.status.fetch("conditions").map { |condition| condition.fetch("reason") }

    assert_includes reasons, "MaxFailedIndexesExceeded"
  end

  def test_backoff_limit_per_index_replacement_carries_failure_count_annotation
    job = job(completions: 1, parallelism: 1, completion_mode: "Indexed", backoff_limit_per_index: 3)
    failed = pod("batch-0-a", job, phase: "Failed", finalizer: true, index: 0, finished_at: NOW - 60,
                                   annotations: {"batch.kubernetes.io/job-index-failure-count" => "1"})
    result = controller.plan(job, pods: [failed], now: NOW)

    assert_empty result.updates.select { |operation| operation.resource.kind == "Pod" },
                 "finalizer removal is delayed until the replacement carries the count"
    replacement = result.creates.first.object

    assert_equal "2", replacement.dig("metadata", "annotations", "batch.kubernetes.io/job-index-failure-count")
  end

  def test_pod_failure_policy_fail_job_uses_upstream_message_and_ignore_does_not_count
    policy = {"rules" => [
      {"action" => "Ignore", "onPodConditions" => [{"type" => "DisruptionTarget", "status" => "True"}]},
      {"action" => "FailJob", "onExitCodes" => {"operator" => "In", "values" => [42]}}
    ]}
    job = job(completions: 2, parallelism: 2, backoff_limit: 6, pod_failure_policy: policy)
    disrupted = pod("batch-disrupted", job, phase: "Failed", finalizer: true, finished_at: NOW - 10,
                                            conditions: [{"type" => "DisruptionTarget", "status" => "True"}])
    ignored = controller.plan(job, pods: [disrupted], now: NOW)

    assert_equal 0, ignored.status.fetch("failed"), "Ignore rule must not count towards backoffLimit"
    assert_equal 2, ignored.creates.length

    crashed = pod("batch-crash", job, phase: "Failed", finalizer: true, finished_at: NOW - 10, exit_code: 42)
    failed = controller.plan(job, pods: [crashed], now: NOW)
    interim = failed.operations.find { |operation| operation.action == :status_update }.patch
    target = interim.fetch("conditions").find { |condition| condition.fetch("type") == "FailureTarget" }

    assert_equal "PodFailurePolicy", target.fetch("reason")
    assert_equal "Container job for pod default/batch-crash failed with exit code 42 matching FailJob rule at index 1",
                 target.fetch("message")
    assert_equal(%w[FailureTarget Failed], failed.status.fetch("conditions").map { |condition| condition.fetch("type") })
  end

  def test_success_policy_marks_success_criteria_met_and_deletes_remaining_pods
    job = job(completions: 3, parallelism: 3, completion_mode: "Indexed",
              success_policy: {"rules" => [{"succeededIndexes" => "0"}]})
    pods = [pod("batch-0-a", job, phase: "Succeeded", finalizer: true, index: 0),
            pod("batch-1-a", job, phase: "Running", finalizer: true, index: 1)]
    result = controller.plan(job, pods: pods, now: NOW)

    assert_equal(["batch-1-a"], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    interim = result.operations.find { |operation| operation.action == :status_update }.patch
    met = interim.fetch("conditions").find { |condition| condition.fetch("type") == "SuccessCriteriaMet" }

    assert_equal "SuccessPolicy", met.fetch("reason")
    assert_equal "Matched rules at index 0", met.fetch("message")
    assert_equal 0, result.status.fetch("failed"), "running pods deleted after SuccessCriteriaMet are not failures"
  end

  def test_suspend_deletes_active_pods_and_resume_resets_start_time
    job = job(completions: 2, parallelism: 2, suspend: true)
    running = pod("batch-run", job, phase: "Running", finalizer: true)
    suspended = controller.plan(job.merge("status" => {"startTime" => (NOW - 100).iso8601(6)}), pods: [running], now: NOW)

    assert_equal(["batch-run"], suspended.deletes.map { |operation| operation.object.dig("metadata", "name") })
    condition = suspended.status.fetch("conditions").first

    assert_equal(["Suspended", "True", "JobSuspended", "Job suspended"],
                 %w[type status reason message].map { |key| condition.fetch(key) })
    refute suspended.status.key?("startTime")
    assert_includes suspended.events.map { |event| event.fetch("reason") }, "Suspended"

    resumed_job = job.merge("spec" => job.fetch("spec").merge("suspend" => false), "status" => suspended.status)
    resumed = controller.plan(resumed_job, pods: [], now: NOW + 30)
    condition = resumed.status.fetch("conditions").first

    assert_equal(["Suspended", "False", "JobResumed", "Job resumed"],
                 %w[type status reason message].map { |key| condition.fetch(key) })
    assert_equal (NOW + 30).iso8601(6), resumed.status.fetch("startTime")
    assert_equal 2, resumed.creates.length
  end

  def test_active_deadline_requeues_then_fails_with_deadline_exceeded
    job = job(completions: 1, parallelism: 1, active_deadline_seconds: 100)
    started = job.merge("status" => {"startTime" => (NOW - 40).iso8601(6), "active" => 1})
    running = pod("batch-run", job, phase: "Running", finalizer: true)
    pending = controller.plan(started, pods: [running], now: NOW)

    assert_in_delta 60.0, pending.requeue_after, 0.001

    expired = controller.plan(started, pods: [running], now: NOW + 61)

    assert_equal(["batch-run"], expired.deletes.map { |operation| operation.object.dig("metadata", "name") })
    target = expired.status.fetch("conditions").find { |condition| condition.fetch("type") == "FailureTarget" }

    assert_equal "DeadlineExceeded", target.fetch("reason")
    assert_equal "Job was active longer than specified deadline", target.fetch("message")
  end

  def test_pod_replacement_policy_failed_waits_for_terminating_pods
    job = job(completions: 2, parallelism: 2, pod_replacement_policy: "Failed")
    terminating = pod("batch-term", job, phase: "Running", finalizer: true, deleting: true)
    result = controller.plan(job, pods: [terminating], now: NOW)

    assert_equal 1, result.creates.length, "one terminating pod reserves one slot"
    assert_equal 1, result.status.fetch("terminating")
    assert_equal 0, result.status.fetch("failed"), "a terminating pod is not a failure under the Failed replacement policy"
  end

  def test_externally_managed_and_finished_jobs_are_left_untouched
    managed = job(completions: 1,
                  parallelism: 1).merge("spec" => job(completions: 1,
                                                      parallelism: 1).fetch("spec").merge("managedBy" => "example.com/other"))

    assert_empty controller.plan(managed, pods: [], now: NOW).operations
  end

  def test_excess_active_pods_are_deleted_with_upstream_ordering
    job = job(completions: 3, parallelism: 1)
    unscheduled = pod("batch-unsched", job, phase: "Pending", finalizer: true, node: nil)
    running = pod("batch-run", job, phase: "Running", finalizer: true)
    result = controller.plan(job, pods: [running, unscheduled], now: NOW)

    assert_equal(["batch-unsched"], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
    assert_empty result.creates
  end

  # job/metrics: syncs by action, Pod creations by reason, finished Pods and
  # the Job finishing once its status was written.
  def test_job_controller_metrics
    registry = Rubernetes::Observability::Metrics.new(apiserver: false, process: false, component: "kube-controller-manager")
    Controller.metrics = registry
    batch = job(completions: 1, parallelism: 1)
    created = Controller::JobController.new(clock: -> { NOW }).plan(batch, pods: [])
    created.operations.each { |operation| operation.notify(true) }
    done = pod("p1", batch, phase: "Succeeded", finalizer: true, finished_at: NOW - 5)
    finished = Controller::JobController.new(clock: -> { NOW }).plan(batch, pods: [done])
    finished.operations.each { |operation| operation.notify(true) }
    text = registry.render

    assert_includes text, %(job_controller_job_syncs_total{action="pods_created",completion_mode="NonIndexed",result="success"} 1)
    assert_includes text, %(job_controller_job_pods_creation_total{reason="new",status="succeeded"} 1)
    assert_match(/job_controller_job_pods_finished_total\{completion_mode="NonIndexed",result="succeeded"\} [1-9]/, text)
  ensure
    Controller.metrics = nil
  end

  def test_orphaned_pods_lose_the_tracking_finalizer_when_their_job_is_gone
    owner = job(completions: 1, parallelism: 1)
    orphan = pod("batch-a", owner, phase: "Succeeded", finalizer: true)
    adapter = Controller::StoreAdapter.new(Rubernetes::Storage::MemoryStore.new)
    adapter.create(orphan, descriptor: Controller::ResourceDescriptor.parse("Pod"))

    result = controller.plan_orphans("default/batch", store: adapter)

    refute_nil result, "an orphaned pod must be planned for finalizer removal"
    update = result.updates.fetch(0)

    assert_equal "Pod", update.resource.kind
    assert_equal [], update.object.dig("metadata", "finalizers")

    # With the Job present the Pod is not an orphan and the normal sync owns it.
    adapter.create(owner, descriptor: Controller::ResourceDescriptor.parse("Job"))

    assert_nil controller.plan_orphans("default/batch", store: adapter)
  end

  def test_the_orphan_hook_is_visible_through_the_definition_wrapper
    registry = Rubernetes::Controller.default_registry
    definition = registry.fetch("job-controller")
    wrapper = Controller::DefinitionController.new(definition, store: nil)

    assert_predicate wrapper, :orphan_cleanup?, "job-controller must advertise orphan cleanup through its wrapper"

    plain = Controller::DefinitionController.new(registry.fetch("deployment-controller"), store: nil)

    refute_predicate plain, :orphan_cleanup?, "a controller without orphan work must not advertise any"
  end

  private

  # A Job deleted while its Pods still carry the tracking finalizer leaves
  # them unreleasable: no Job sync will ever run for them again.  Upstream's
  # syncOrphanPod strips the finalizer so the Pod can finish deleting, and
  # its namespace with it.
  # In the controller manager a built-in controller reaches the reconcile
  # loop wrapped in a DefinitionController.  The orphan hook has to survive
  # that wrapping: while it did not, the finalizer cleanup existed only in
  # this test file and every CronJob namespace stayed Terminating forever.
  def controller
    Controller::JobController.new(clock: -> { NOW })
  end

  def job(completions:, parallelism:, backoff_limit: nil, completion_mode: nil, backoff_limit_per_index: nil,
          max_failed_indexes: nil, pod_failure_policy: nil, success_policy: nil, suspend: nil,
          active_deadline_seconds: nil, pod_replacement_policy: nil)
    spec = {"completions" => completions, "parallelism" => parallelism,
            "selector" => {"matchLabels" => {"batch.kubernetes.io/controller-uid" => "uid-job"}},
            "template" => {"metadata" => {"labels" => {"batch.kubernetes.io/controller-uid" => "uid-job", "job" => "batch"}},
                           "spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "job", "image" => "example/job:1"}]}}}
    spec["backoffLimit"] = backoff_limit unless backoff_limit.nil?
    spec["completionMode"] = completion_mode unless completion_mode.nil?
    spec["backoffLimitPerIndex"] = backoff_limit_per_index unless backoff_limit_per_index.nil?
    spec["maxFailedIndexes"] = max_failed_indexes unless max_failed_indexes.nil?
    spec["podFailurePolicy"] = pod_failure_policy unless pod_failure_policy.nil?
    spec["successPolicy"] = success_policy unless success_policy.nil?
    spec["suspend"] = suspend unless suspend.nil?
    spec["activeDeadlineSeconds"] = active_deadline_seconds unless active_deadline_seconds.nil?
    spec["podReplacementPolicy"] = pod_replacement_policy unless pod_replacement_policy.nil?
    {"apiVersion" => "batch/v1", "kind" => "Job",
     "metadata" => {"name" => "batch", "namespace" => "default", "uid" => "uid-job"},
     "spec" => spec}
  end

  def pod(name, owner, phase:, finalizer:, index: nil, finished_at: nil, annotations: {}, conditions: nil,
          exit_code: nil, deleting: false, node: "node-a")
    metadata = {"name" => name, "namespace" => "default", "uid" => "uid-#{name}",
                "creationTimestamp" => (NOW - 600).iso8601(6),
                "ownerReferences" => [Controller::Support.owner_reference(owner)]}
    metadata["finalizers"] = [FINALIZER] if finalizer
    metadata["annotations"] = annotations.dup
    metadata["annotations"][INDEX] = index.to_s unless index.nil?
    # A Job-owned Pod always carries the Job's selector labels (the generated
    # controller-uid label); without them the controller releases it.
    selector_labels = Controller::Support.value(
      Controller::Support.value(Controller::Support.spec(owner), "selector", {}), "matchLabels", {}
    ) || {}
    metadata["labels"] = (index.nil? ? {} : {INDEX => index.to_s}).merge(selector_labels)
    metadata["deletionTimestamp"] = NOW.iso8601(6) if deleting
    status = {"phase" => phase}
    status["conditions"] = conditions || [{"type" => "Ready", "status" => phase == "Running" ? "True" : "False",
                                           "lastTransitionTime" => (finished_at || (NOW - 300)).iso8601(6)}]
    if finished_at || exit_code
      status["containerStatuses"] = [{"name" => "job", "state" => {"terminated" => {
        "exitCode" => exit_code || (phase == "Succeeded" ? 0 : 1), "finishedAt" => (finished_at || (NOW - 10)).iso8601(6)
      }}}]
    end
    spec = {"containers" => [{"name" => "job", "image" => "example/job:1"}]}
    spec["nodeName"] = node if node
    {"apiVersion" => "v1", "kind" => "Pod", "metadata" => metadata, "spec" => spec, "status" => status}
  end

  def strip_finalizer(pod)
    candidate = Controller::Support.deep_copy(pod)
    candidate["metadata"]["finalizers"] = []
    candidate
  end
end
