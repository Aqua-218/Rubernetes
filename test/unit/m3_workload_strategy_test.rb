# frozen_string_literal: true

# The controller package is loaded directly so an unrelated package syntax
# error cannot mask a workload strategy regression.
require "minitest/autorun"
require "rubernetes/controller"

# StatefulSet, DaemonSet, and CronJob strategy semantics pinned to Kubernetes
# v1.36.2 (pkg/controller/{statefulset,daemon,cronjob}).
class M3WorkloadStrategyTest < Minitest::Test
  Controller = Rubernetes::Controller
  Support = Rubernetes::Controller::Support
  NOW = Time.utc(2026, 1, 1, 12, 0, 0)
  REVISION_LABEL = "controller-revision-hash"

  # ---- StatefulSet ----------------------------------------------------------

  def test_statefulset_rolling_update_replaces_one_pod_at_a_time_without_max_unavailable
    set = stateful_set(replicas: 3, image: "example/db:2")
    old_set = set.merge("spec" => set["spec"].merge("template" => template("example/db:1")))
    old_revision = revision_object(old_set, 1)
    set["status"] = {"currentRevision" => old_revision.dig("metadata", "name")}
    pods = (0..2).map { |ordinal| stateful_pod(set, ordinal, revision: old_revision.dig("metadata", "name"), ready: true) }
    result = Controller::StatefulSetController.new(clock: -> { NOW }).plan(set, pods: pods, revisions: [old_revision], now: NOW)

    deletes = result.deletes.map { |operation| operation.object.dig("metadata", "name") }

    assert_equal ["db-2"], deletes, "the default strategy terminates the highest ordinal only"
    assert_equal 2, result.status.fetch("currentReplicas")
    assert_equal 2, result.creates.find { |operation| operation.resource.kind == "ControllerRevision" }.object.fetch("revision")
  end

  def test_statefulset_max_unavailable_terminates_up_to_the_budget_from_the_highest_ordinal
    set = stateful_set(replicas: 4, image: "example/db:2", max_unavailable: 2, policy: "Parallel")
    old_set = set.merge("spec" => set["spec"].merge("template" => template("example/db:1")))
    old_revision = revision_object(old_set, 1)
    set["status"] = {"currentRevision" => old_revision.dig("metadata", "name")}
    pods = (0..3).map { |ordinal| stateful_pod(set, ordinal, revision: old_revision.dig("metadata", "name"), ready: true) }
    # MaxUnavailableStatefulSet is Beta and off: one Pod at a time.
    gate_off = Controller::StatefulSetController.new(clock: -> { NOW }).plan(set, pods: pods, revisions: [old_revision], now: NOW)

    assert_equal 1, gate_off.deletes.length
    result = Controller::StatefulSetController.new(clock: -> { NOW }, max_unavailable_stateful_set: true)
      .plan(set, pods: pods, revisions: [old_revision], now: NOW)

    deletes = result.deletes.map { |operation| operation.object.dig("metadata", "name") }

    assert_equal %w[db-3 db-2], deletes

    unavailable = pods.dup
    unavailable[3] = stateful_pod(set, 3, revision: old_revision.dig("metadata", "name"), ready: false)
    throttled = Controller::StatefulSetController.new(clock: lambda {
      NOW
    }, max_unavailable_stateful_set: true).plan(set, pods: unavailable, revisions: [old_revision], now: NOW)

    assert_equal ["db-3"], throttled.deletes.map { |operation| operation.object.dig("metadata", "name") },
                 "an already unavailable pod consumes the maxUnavailable budget"
  end

  def test_statefulset_ordered_ready_waits_for_min_ready_seconds_before_the_next_ordinal
    set = stateful_set(replicas: 2, image: "example/db:1", min_ready_seconds: 30)
    revision = revision_name(set)
    first = stateful_pod(set, 0, revision: revision, ready: true, ready_since: NOW - 10)
    waiting = Controller::StatefulSetController.new(clock: -> { NOW }).plan(set, pods: [first], revisions: [], now: NOW)

    assert_empty waiting.creates.select { |operation| operation.resource.kind == "Pod" }, "db-0 is ready but not yet available"
    assert_equal 1, waiting.status.fetch("readyReplicas")
    assert_equal 0, waiting.status.fetch("availableReplicas")

    ready = Controller::StatefulSetController.new(clock: -> { NOW + 31 }).plan(set, pods: [first], revisions: [], now: NOW + 31)

    assert_equal(["db-1"], ready.creates.select do |operation|
      operation.resource.kind == "Pod"
    end.map { |operation| operation.object.dig("metadata", "name") })
    assert_equal 1, ready.status.fetch("availableReplicas")
  end

  def test_statefulset_pod_revision_label_is_the_controller_revision_name
    set = stateful_set(replicas: 1, image: "example/db:1")
    result = Controller::StatefulSetController.new(clock: -> { NOW }).plan(set, pods: [], revisions: [], now: NOW)
    revision = result.creates.find { |operation| operation.resource.kind == "ControllerRevision" }.object
    pod = result.creates.find { |operation| operation.resource.kind == "Pod" }.object

    assert_equal revision.dig("metadata", "name"), pod.dig("metadata", "labels", REVISION_LABEL)
    assert_match(/\Adb-[bcdfghjklmnpqrstvwxz2456789]{1,10}\z/, revision.dig("metadata", "name"))
    assert_equal revision.dig("metadata", "name").delete_prefix("db-"), revision.dig("metadata", "labels", "controller.kubernetes.io/hash")
    assert_equal revision.dig("metadata", "name"), result.status.fetch("updateRevision")
  end

  # ---- DaemonSet ---------------------------------------------------------------

  def test_daemonset_on_delete_strategy_never_replaces_outdated_pods
    daemon = daemon_set(image: "example/agent:2", strategy: {"type" => "OnDelete"}, generation: 2)
    nodes = [node("node-a"), node("node-b")]
    pods = nodes.map { |candidate| daemon_pod(daemon, candidate, hash: "stale", ready: true) }
    result = Controller::DaemonSetController.new(clock: -> { NOW }).plan(daemon, pods: pods, nodes: nodes, revisions: [], now: NOW)

    assert_empty result.deletes
    assert_empty(result.creates.select { |operation| operation.resource.kind == "Pod" })
    assert_equal 2, result.status.fetch("currentNumberScheduled")
    assert_equal 0, result.status.fetch("updatedNumberScheduled")
  end

  def test_daemonset_rolling_update_respects_max_unavailable
    daemon = daemon_set(image: "example/agent:2", strategy: {"type" => "RollingUpdate", "rollingUpdate" => {"maxUnavailable" => 2}},
                        generation: 2)
    nodes = %w[node-a node-b node-c node-d].map { |name| node(name) }
    pods = nodes.map { |candidate| daemon_pod(daemon, candidate, hash: "stale", ready: true) }
    result = Controller::DaemonSetController.new(clock: -> { NOW }).plan(daemon, pods: pods, nodes: nodes, revisions: [], now: NOW)

    assert_equal 2, result.deletes.length
    assert_equal(%w[node-a node-b], result.deletes.map { |operation| operation.object.dig("spec", "nodeName") })
  end

  def test_daemonset_rolling_update_with_max_surge_creates_before_deleting
    daemon = daemon_set(image: "example/agent:2",
                        strategy: {"type" => "RollingUpdate", "rollingUpdate" => {"maxSurge" => 1, "maxUnavailable" => 0}}, generation: 2)
    nodes = [node("node-a"), node("node-b")]
    pods = nodes.map { |candidate| daemon_pod(daemon, candidate, hash: "stale", ready: true) }
    controller = Controller::DaemonSetController.new(clock: -> { NOW })
    surge = controller.plan(daemon, pods: pods, nodes: nodes, revisions: [], now: NOW)

    assert_empty surge.deletes
    creates = surge.creates.select { |operation| operation.resource.kind == "Pod" }

    assert_equal 1, creates.length
    target = creates.first.object.dig("spec", "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution",
                                      "nodeSelectorTerms", 0, "matchFields", 0, "values", 0)

    assert_equal "node-a", target

    hash = surge.creates.find do |operation|
      operation.resource.kind == "ControllerRevision"
    end.object.dig("metadata", "labels", REVISION_LABEL)
    replacement = daemon_pod(daemon, nodes.first, hash: hash, ready: true, name: "agent-new", generation: 2)
    settled = controller.plan(daemon, pods: pods + [replacement], nodes: nodes, revisions: [], now: NOW)

    assert_equal ["agent-node-a"], settled.deletes.map { |operation| operation.object.dig("metadata", "name") },
                 "the old pod is removed once the surged replacement is available"
  end

  def test_daemonset_keeps_controller_revision_history_within_the_limit
    daemon = daemon_set(image: "example/agent:9", strategy: {"type" => "RollingUpdate"})
    daemon["spec"]["revisionHistoryLimit"] = 1
    old = (1..3).map do |index|
      {"apiVersion" => "apps/v1", "kind" => "ControllerRevision",
       "metadata" => {"name" => "agent-old#{index}", "namespace" => "default", "uid" => "uid-old#{index}",
                      "labels" => {REVISION_LABEL => "old#{index}"}, "ownerReferences" => [Support.owner_reference(daemon)]},
       "data" => {"spec" => {"template" => {"$patch" => "replace", "spec" => {"containers" => [{"name" => "agent", "image" => "example/agent:#{index}"}]}}}},
       "revision" => index}
    end
    result = Controller::DaemonSetController.new(clock: -> { NOW }).plan(daemon, pods: [], nodes: [], revisions: old, now: NOW)

    created = result.creates.find { |operation| operation.resource.kind == "ControllerRevision" }.object

    assert_equal 4, created.fetch("revision")
    assert_equal(%w[agent-old1 agent-old2], result.deletes.map { |operation| operation.object.dig("metadata", "name") })
  end

  def test_daemonset_pod_carries_upstream_tolerations_and_generation_label
    daemon = daemon_set(image: "example/agent:1", strategy: {"type" => "RollingUpdate"})
    result = Controller::DaemonSetController.new(clock: -> { NOW }).plan(daemon, pods: [], nodes: [node("node-a")], revisions: [], now: NOW)
    pod = result.creates.find { |operation| operation.resource.kind == "Pod" }.object
    keys = pod.dig("spec", "tolerations").map { |toleration| [toleration["key"], toleration["effect"]] }

    assert_includes keys, ["node.kubernetes.io/not-ready", "NoExecute"]
    assert_includes keys, ["node.kubernetes.io/unschedulable", "NoSchedule"]
    assert_equal "1", pod.dig("metadata", "labels", "pod-template-generation")
    assert_equal 1, result.status.fetch("desiredNumberScheduled")
    assert_equal 1, result.status.fetch("numberUnavailable")
  end

  # ---- CronJob -------------------------------------------------------------------

  def test_cronjob_history_limits_delete_oldest_finished_jobs_and_track_last_successful_time
    # History cleanup and lastSuccessfulTime are evaluated before the suspend check.
    cron = cron_job(successful_limit: 1, failed_limit: 0, suspend: true)
    jobs = [
      finished_job(cron, "cron-1", "Complete", start: NOW - 300, completion: NOW - 240),
      finished_job(cron, "cron-2", "Complete", start: NOW - 200, completion: NOW - 100),
      finished_job(cron, "cron-3", "Failed", start: NOW - 150, completion: nil)
    ]
    result = Controller::CronJobController.new(clock: -> { NOW }).plan(cron, jobs: jobs, now: NOW)

    deletes = result.deletes.map { |operation| operation.object.dig("metadata", "name") }

    assert_equal %w[cron-1 cron-3], deletes
    assert_equal (NOW - 100).iso8601(6), result.status.fetch("lastSuccessfulTime")
    refute result.status.key?("active")
  end

  # The planner cannot know the uid of a Job it has only asked to create, so
  # the reference it records carries none.  The next sync must still
  # recognise that Job -- otherwise status.active empties out permanently and
  # the Forbid policy, which reads it, stops holding anything back.
  def test_cronjob_active_is_rebuilt_from_observed_jobs_so_forbid_keeps_holding
    cron = cron_job(policy: "Forbid")
    first = Controller::CronJobController.new(clock: -> { NOW }).plan(cron, jobs: [], now: NOW)
    created = first.creates.fetch(0).object

    assert_equal([Controller::Support.name(created)], Array(first.status["active"]).map { |ref| ref.fetch("name") })

    # The API server assigned a uid the planner never saw.
    running = finished_job(cron, Controller::Support.name(created), nil, start: NOW - 5, completion: nil)
    scheduled = cron.merge("status" => first.status)
    second = Controller::CronJobController.new(clock: -> { NOW }).plan(scheduled, jobs: [running], now: NOW)

    assert_equal [Controller::Support.name(created)], Array(second.status["active"]).map { |ref| ref.fetch("name") },
                 "the running Job must stay in status.active once it is observed"
    assert_equal(["uid-#{Controller::Support.name(created)}"], Array(second.status["active"]).map { |ref| ref.fetch("uid") })
    refute(second.events.any? { |event| event.fetch("reason") == "UnexpectedJob" },
           "a Job this CronJob created is not unexpected")
    assert_empty second.creates, "Forbid must not start a second Job while one is active"
  end

  def test_cronjob_forbid_policy_skips_when_a_job_is_active_and_replace_deletes_it
    cron = cron_job(policy: "Forbid")
    cron["status"] =
      {"active" => [{"apiVersion" => "batch/v1", "kind" => "Job", "name" => "cron-running", "namespace" => "default",
                     "uid" => "uid-cron-running"}]}
    running = finished_job(cron, "cron-running", nil, start: NOW - 60, completion: nil)
    forbid = Controller::CronJobController.new(clock: -> { NOW }).plan(cron, jobs: [running], now: NOW)

    assert_empty forbid.creates
    assert_includes forbid.events.map { |event| event.fetch("reason") }, "JobAlreadyActive"

    replace = Controller::CronJobController.new(clock: lambda {
      NOW
    }).plan(cron.merge("spec" => cron["spec"].merge("concurrencyPolicy" => "Replace")),
            jobs: [running], now: NOW)

    assert_equal(["cron-running"], replace.deletes.map { |operation| operation.object.dig("metadata", "name") })
    created = replace.creates.first.object

    assert_equal "cron-#{NOW.to_i / 60}", created.dig("metadata", "name")
    assert_equal NOW.iso8601, created.dig("metadata", "annotations", "batch.kubernetes.io/cronjob-scheduled-timestamp")
    assert_equal([{"apiVersion" => "batch/v1", "kind" => "Job", "name" => created.dig("metadata", "name"), "namespace" => "default"}],
                 replace.status.fetch("active").map { |reference| reference.reject { |key, _| key == "uid" } })
    assert_in_delta 300.1, replace.requeue_after, 0.001, "next schedule in five minutes plus the upstream jitter"
  end

  private

  def template(image, name: "db")
    {"metadata" => {"labels" => {"app" => name}}, "spec" => {"containers" => [{"name" => name, "image" => image}]}}
  end

  def stateful_set(replicas:, image:, max_unavailable: nil, min_ready_seconds: nil, policy: "OrderedReady")
    rolling = {"partition" => 0}
    rolling["maxUnavailable"] = max_unavailable unless max_unavailable.nil?
    spec = {"replicas" => replicas, "serviceName" => "db", "selector" => {"matchLabels" => {"app" => "db"}},
            "podManagementPolicy" => policy, "updateStrategy" => {"type" => "RollingUpdate", "rollingUpdate" => rolling},
            "template" => template(image)}
    spec["minReadySeconds"] = min_ready_seconds unless min_ready_seconds.nil?
    {"apiVersion" => "apps/v1", "kind" => "StatefulSet",
     "metadata" => {"name" => "db", "namespace" => "default", "uid" => "uid-set", "generation" => 1}, "spec" => spec}
  end

  def revision_name(set)
    revision_object(set, 1).dig("metadata", "name")
  end

  def revision_object(set, number)
    data = {"spec" => {"template" => set.dig("spec", "template").merge("$patch" => "replace")}}
    hash = Support.controller_revision_hash(data, 0)
    {"apiVersion" => "apps/v1", "kind" => "ControllerRevision",
     "metadata" => {"name" => "db-#{hash}", "namespace" => "default", "uid" => "uid-rev-#{number}",
                    "labels" => {"app" => "db", "controller.kubernetes.io/hash" => hash},
                    "ownerReferences" => [Support.owner_reference(set)]},
     "data" => data, "revision" => number}
  end

  def stateful_pod(set, ordinal, revision:, ready:, ready_since: NOW - 3600)
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => "db-#{ordinal}", "namespace" => "default", "uid" => "uid-db-#{ordinal}",
                    "labels" => {"app" => "db", REVISION_LABEL => revision, "statefulset.kubernetes.io/pod-name" => "db-#{ordinal}",
                                 "apps.kubernetes.io/pod-index" => ordinal.to_s},
                    "ownerReferences" => [Support.owner_reference(set)]},
     "spec" => {"nodeName" => "node-a", "containers" => [{"name" => "db", "image" => "example/db:1"}]},
     "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False",
                                                          "lastTransitionTime" => ready_since.iso8601(6)}]}}
  end

  def daemon_set(image:, strategy:, generation: 1)
    {"apiVersion" => "apps/v1", "kind" => "DaemonSet",
     "metadata" => {"name" => "agent", "namespace" => "default", "uid" => "uid-daemon", "generation" => generation},
     "spec" => {"selector" => {"matchLabels" => {"app" => "agent"}}, "updateStrategy" => strategy,
                "template" => template(image, name: "agent")}}
  end

  def node(name)
    {"apiVersion" => "v1", "kind" => "Node", "metadata" => {"name" => name, "uid" => "uid-#{name}", "labels" => {}},
     "spec" => {}, "status" => {"conditions" => [{"type" => "Ready", "status" => "True"}]}}
  end

  def daemon_pod(daemon, node, hash:, ready:, name: nil, generation: 1)
    node_name = node.dig("metadata", "name")
    {"apiVersion" => "v1", "kind" => "Pod",
     "metadata" => {"name" => name || "agent-#{node_name}", "namespace" => "default", "uid" => "uid-#{name || node_name}",
                    "creationTimestamp" => (NOW - 3600).iso8601(6),
                    "labels" => {"app" => "agent", REVISION_LABEL => hash, "pod-template-generation" => generation.to_s},
                    "ownerReferences" => [Support.owner_reference(daemon)]},
     "spec" => {"nodeName" => node_name, "containers" => [{"name" => "agent", "image" => "example/agent:1"}]},
     "status" => {"phase" => "Running", "conditions" => [{"type" => "Ready", "status" => ready ? "True" : "False",
                                                          "lastTransitionTime" => (NOW - 3600).iso8601(6)}]}}
  end

  def cron_job(successful_limit: nil, failed_limit: nil, policy: "Allow", suspend: nil)
    spec = {"schedule" => "*/5 * * * *", "concurrencyPolicy" => policy,
            "jobTemplate" => {"spec" => {"template" => {"spec" => {"containers" => [{"name" => "job", "image" => "example/job:1"}]}}}}}
    spec["successfulJobsHistoryLimit"] = successful_limit unless successful_limit.nil?
    spec["failedJobsHistoryLimit"] = failed_limit unless failed_limit.nil?
    spec["suspend"] = suspend unless suspend.nil?
    {"apiVersion" => "batch/v1", "kind" => "CronJob",
     "metadata" => {"name" => "cron", "namespace" => "default", "uid" => "uid-cron", "creationTimestamp" => (NOW - 120).iso8601(6)},
     "spec" => spec}
  end

  def finished_job(cron, name, type, start:, completion:)
    status = {"startTime" => start.iso8601(6)}
    status["completionTime"] = completion.iso8601(6) if completion
    status["conditions"] = [{"type" => type, "status" => "True"}] if type
    {"apiVersion" => "batch/v1", "kind" => "Job",
     "metadata" => {"name" => name, "namespace" => "default", "uid" => "uid-#{name}", "ownerReferences" => [Support.owner_reference(cron)]},
     "spec" => {}, "status" => status}
  end
end
