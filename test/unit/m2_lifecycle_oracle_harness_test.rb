# frozen_string_literal: true

require "json"
require "tmpdir"
require_relative "../test_helper"
require_relative "../../test/conformance/kubernetes/m2_lifecycle_oracle/harness"
require_relative "../../test/conformance/kubernetes/m2_lifecycle_oracle/registry_image"

# Pure normalization of the privileged harness: these tests feed synthetic
# Kubernetes API objects, Events, and CRI records in the exact shapes the
# cluster reports and check the derived observables without any cluster.
class M2LifecycleOracleHarnessTest < Minitest::Test
  H = M2LifecycleOracleHarness

  def test_order_operations_follow_cri_nanosecond_timestamps_and_only_wait_for_regular_init_containers
    containers = [
      {"name" => "app", "createdAt" => "2026-09-04T04:42:41.060077507Z", "startedAt" => "2026-09-04T04:42:41.126256123Z",
       "finishedAt" => "0001-01-01T00:00:00Z", "init" => false, "restartable" => false},
      {"name" => "sidecar", "createdAt" => "2026-09-04T04:42:40.957533605Z", "startedAt" => "2026-09-04T04:42:41.040192019Z",
       "finishedAt" => "0001-01-01T00:00:00Z", "init" => true, "restartable" => true},
      {"name" => "prepare", "createdAt" => "2026-09-04T04:42:40.454639767Z", "startedAt" => "2026-09-04T04:42:40.552469375Z",
       "finishedAt" => "2026-09-04T04:42:40.554810922Z", "init" => true, "restartable" => false}
    ]

    assert_equal %w[create:prepare start:prepare wait:prepare create:sidecar start:sidecar create:app start:app],
                 H.order_operations(containers)
  end

  def test_order_observable_is_timestamp_free
    pod = {
      "spec" => {"initContainers" => [{"name" => "prepare"}, {"name" => "sidecar", "restartPolicy" => "Always"}],
                 "containers" => [{"name" => "app"}]},
      "status" => {
        "phase" => "Running",
        "initContainerStatuses" => [
          {"name" => "prepare", "ready" => true, "started" => false, "restartCount" => 0,
           "state" => {"terminated" => {"exitCode" => 0, "reason" => "Completed", "startedAt" => "2026-09-04T04:42:40Z",
                                        "finishedAt" => "2026-09-04T04:42:40Z"}}},
          {"name" => "sidecar", "ready" => true, "started" => true, "restartCount" => 0,
           "state" => {"running" => {"startedAt" => "2026-09-04T04:42:41Z"}}}
        ],
        "containerStatuses" => [{"name" => "app", "ready" => true, "started" => true, "restartCount" => 0,
                                 "state" => {"running" => {"startedAt" => "2026-09-04T04:42:41Z"}}}]
      }
    }
    observable = H.order_observable(pod,
                                    [{"name" => "prepare", "createdAt" => "2026-09-04T04:42:40.4Z", "startedAt" => "2026-09-04T04:42:40.5Z",
                                      "finishedAt" => "2026-09-04T04:42:40.6Z", "init" => true}])

    assert_equal %w[create:prepare start:prepare wait:prepare], observable.fetch("operations")
    assert_equal "Running", observable.fetch("phase")
    assert_equal({"name" => "prepare", "state" => "terminated", "restartCount" => 0, "ready" => true, "started" => false, "exitCode" => 0},
                 observable.dig("status", "initContainerStatuses", 0))
    assert_equal({"name" => "app", "state" => "running", "restartCount" => 0, "ready" => true, "started" => true},
                 observable.dig("status", "containerStatuses", 0))
    refute_match(/startedAt|finishedAt/, JSON.generate(observable))
  end

  def test_backoff_messages_are_parsed_into_durations
    assert_equal "10s",
                 H.parse_backoff_message("back-off 10s restarting failed container=app " \
                                         "pod=m2-restart-always-exit-0_default(496f3187-1756-43e1-9477-133c85427e27)")
    assert_equal "2m40s", H.parse_backoff_message("back-off 2m40s restarting failed container=app pod=x_default(uid)")
    assert_nil H.parse_backoff_message("Container image already present on machine")
    assert_nil H.parse_backoff_message(nil)
  end

  def test_restart_observable_settles_per_variant_and_records_the_backoff_progression
    variants = {
      "always_exit_0" => {"spec" => {"restartPolicy" => "Always", "containers" => [{"name" => "app"}]}},
      "on_failure_exit_0" => {"spec" => {"restartPolicy" => "OnFailure", "containers" => [{"name" => "app"}]}},
      "on_failure_exit_1" => {"spec" => {"restartPolicy" => "OnFailure", "containers" => [{"name" => "app"}]}},
      "never_exit_1" => {"spec" => {"restartPolicy" => "Never", "containers" => [{"name" => "app"}]}}
    }
    restarting = lambda do |exit_code, reason|
      [
        pod("Running", terminated(0, exit_code, reason)),
        pod("Running", terminated(1, exit_code, reason)),
        pod("Running", waiting(1, "back-off 10s restarting failed container=app pod=x_default(u)", exit_code, reason)),
        pod("Running", terminated(2, exit_code, reason)),
        pod("Running", waiting(2, "back-off 20s restarting failed container=app pod=x_default(u)", exit_code, reason)),
        pod("Running", waiting(3, "back-off 40s restarting failed container=app pod=x_default(u)", exit_code, reason))
      ]
    end
    histories = {
      "always_exit_0" => restarting.call(0, "Completed"),
      "on_failure_exit_0" => [
        pod("Pending",
            {"name" => "app", "restartCount" => 0,
             "state" => {"waiting" => {"reason" => "ContainerCreating"}}}), pod("Succeeded", terminated(0, 0, "Completed"))
      ],
      "on_failure_exit_1" => restarting.call(1, "Error"),
      "never_exit_1" => [pod("Failed", terminated(0, 1, "Error"))]
    }

    observable = H.restart_observable(variants, histories)

    assert_equal(
      {"always_exit_0" => "Always", "on_failure_exit_0" => "OnFailure", "on_failure_exit_1" => "OnFailure",
       "never_exit_1" => "Never"}, observable.fetch("restartPolicy")
    )
    assert_equal({"always_exit_0" => 2, "on_failure_exit_0" => 0, "on_failure_exit_1" => 2, "never_exit_1" => 0},
                 observable.fetch("restartCount"))
    assert_equal(
      {"always_exit_0" => "Running", "on_failure_exit_0" => "Succeeded", "on_failure_exit_1" => "Running",
       "never_exit_1" => "Failed"}, observable.fetch("phase")
    )
    assert_equal(
      {"state" => "waiting", "reason" => "CrashLoopBackOff", "exitCode" => nil, "lastState" => "terminated", "lastReason" => "Completed",
       "lastExitCode" => 0}, observable.dig("status", "always_exit_0")
    )
    assert_equal(
      {"state" => "terminated", "reason" => "Error", "exitCode" => 1, "lastState" => nil, "lastReason" => nil,
       "lastExitCode" => nil}, observable.dig("status", "never_exit_1")
    )
    assert_equal({"always_exit_0" => %w[10s 20s], "on_failure_exit_1" => %w[10s 20s]}, observable.fetch("backoff_seconds"))
  end

  def test_probe_observable_counts_liveness_failures_before_the_kill_and_readiness_before_it
    container = {
      "name" => "app",
      "startupProbe" => {"exec" => {"command" => ["/bin/true"]}, "successThreshold" => 1, "failureThreshold" => 3, "periodSeconds" => 1},
      "livenessProbe" => {"exec" => {"command" => ["/bin/false"]}, "failureThreshold" => 2, "periodSeconds" => 1,
                          "initialDelaySeconds" => 10},
      "readinessProbe" => {"exec" => {"command" => ["/bin/true"]}, "successThreshold" => 2, "failureThreshold" => 1, "periodSeconds" => 1}
    }
    running = lambda { |at, ready, started, restarts|
      {"at" => at, "type" => "MODIFIED",
       "object" => pod("Running",
                       {"name" => "app", "ready" => ready, "started" => started, "restartCount" => restarts,
                        "state" => {"running" => {"startedAt" => "2026-09-04T04:42:40Z"}}})}
    }
    pod_history = [running.call(1.0, false, false, 0), running.call(2.0, false, true, 0), running.call(4.0, true, true, 0),
                   running.call(15.0, false, false, 1)]
    event = lambda { |at, reason, message, count|
      {"at" => at, "type" => "ADDED",
       "object" => {"reason" => reason, "message" => message, "count" => count,
                    "involvedObject" => {"name" => "m2-probes", "fieldPath" => "spec.containers{app}"}}}
    }
    event_history = [
      event.call(0.5, "Scheduled", "Successfully assigned", 1),
      event.call(12.0, "Unhealthy", "Liveness probe failed: ", 1),
      event.call(13.0, "Unhealthy", "Liveness probe failed: ", 2),
      event.call(13.1, "Killing", "Container app failed liveness probe, will be restarted", 1),
      event.call(16.0, "Unhealthy", "Liveness probe failed: ", 3)
    ]

    observable = H.probe_observable(container, pod_history, event_history)

    assert_equal(
      {"probe" => "exec:/bin/true", "successThreshold" => 1, "failureThreshold" => 3, "periodSeconds" => 1, "result" => "succeeded",
       "started" => true}, observable.fetch("startup")
    )
    assert_equal(
      {"probe" => "exec:/bin/true", "successThreshold" => 2, "failureThreshold" => 1, "periodSeconds" => 1, "result" => "succeeded",
       "ready" => true, "ready_before_liveness_kill" => true}, observable.fetch("readiness")
    )
    assert_equal(
      {"probe" => "exec:/bin/false", "failureThreshold" => 2, "periodSeconds" => 1, "initialDelaySeconds" => 10, "result" => "failed",
       "failures_before_kill" => 2, "kill_reason" => "Killing", "kill_message" => "Container app failed liveness probe, will be " \
                                                                                  "restarted", "restartCount_after_kill" => 1}, observable.fetch("liveness")
    )
  end

  def test_probe_observable_refuses_to_invent_a_kill_that_was_not_observed
    container = {"name" => "app", "startupProbe" => {"exec" => {"command" => ["/bin/true"]}},
                 "livenessProbe" => {"exec" => {"command" => ["/bin/false"]}}, "readinessProbe" => {"exec" => {"command" => ["/bin/true"]}}}

    error = assert_raises(H::HarnessError) { H.probe_observable(container, [], []) }
    assert_match(/Killing event for container app was not observed/, error.message)
  end

  def test_termination_observable_derives_hook_signal_grace_and_kill_from_api_state
    document = {"spec" => {"terminationGracePeriodSeconds" => 2, "containers" => [{"name" => "app"}]}}
    final_pod = {
      "metadata" => {"name" => "m2-grace", "deletionTimestamp" => "2026-09-04T04:45:22Z", "deletionGracePeriodSeconds" => 2},
      "status" => {"phase" => "Failed",
                   "containerStatuses" => [{"name" => "app", "ready" => false, "started" => false, "restartCount" => 0,
                                            "state" => {"terminated" => {"exitCode" => 137, "reason" => "Error", "message" => "preStop\nTERM\n",
                                                                         "startedAt" => "2026-09-04T04:45:00Z", "finishedAt" => "2026-09-04T04:45:23Z"}}}]}
    }
    events = [{"at" => 1.0, "object" => {"reason" => "Killing", "message" => "Stopping container app"}},
              {"at" => 1.5, "object" => {"reason" => "Killing", "message" => "Stopping container app"}}]

    observable = H.termination_observable(document, final_pod, events)

    assert_equal %w[exec:preStop signal:TERM wait:2 signal:KILL], observable.fetch("operations")
    assert_equal ["Killing"], observable.fetch("events")
    assert_equal "Failed", observable.fetch("phase")
    assert_equal({"state" => "terminated", "exitCode" => 137, "reason" => "Error", "message" => "preStop\nTERM\n"},
                 observable.fetch("status"))
    assert_equal true, observable.fetch("killed_after_grace_period")
    assert_equal 2, observable.fetch("terminationGracePeriodSeconds")
  end

  def test_termination_observable_uses_the_measured_delete_interval_for_the_grace_wait
    document = {"spec" => {"terminationGracePeriodSeconds" => 2, "containers" => [{"name" => "app"}]}}
    # finishedAt truncated onto the deletionTimestamp second: the API
    # timestamps alone cannot tell whether the grace period elapsed.
    final_pod = {
      "metadata" => {"deletionTimestamp" => "2026-09-04T04:45:22Z"},
      "status" => {"phase" => "Failed",
                   "containerStatuses" => [{"name" => "app",
                                            "state" => {"terminated" => {"exitCode" => 137, "reason" => "Error", "message" => "preStop\nTERM\n",
                                                                         "finishedAt" => "2026-09-04T04:45:21Z"}}}]}
    }

    waited = H.termination_observable(document, final_pod, [], elapsed_seconds: 2.31)

    assert_equal %w[exec:preStop signal:TERM wait:2 signal:KILL], waited.fetch("operations")
    assert_equal true, waited.fetch("killed_after_grace_period")

    early = H.termination_observable(document, final_pod, [], elapsed_seconds: 1.2)

    assert_equal %w[exec:preStop signal:TERM signal:KILL], early.fetch("operations")
    assert_equal false, early.fetch("killed_after_grace_period")
  end

  def test_termination_observable_does_not_claim_kill_or_grace_for_a_clean_exit
    document = {"spec" => {"terminationGracePeriodSeconds" => 2, "containers" => [{"name" => "app"}]}}
    final_pod = {
      "metadata" => {"deletionTimestamp" => "2026-09-04T04:45:22Z"},
      "status" => {"phase" => "Succeeded",
                   "containerStatuses" => [{"name" => "app",
                                            "state" => {"terminated" => {"exitCode" => 0, "reason" => "Completed", "message" => "TERM\n",
                                                                         "finishedAt" => "2026-09-04T04:45:20Z"}}}]}
    }

    observable = H.termination_observable(document, final_pod, [])

    assert_equal %w[signal:TERM], observable.fetch("operations")
    assert_equal false, observable.fetch("killed_after_grace_period")
    assert_empty observable.fetch("events")
  end

  def test_trace_entries_keep_raw_timestamps_but_observables_do_not
    entry = {"at" => 1_788_500_000.123456, "type" => "MODIFIED", "object" => pod("Running", terminated(1, 0, "Completed"))}
    trace = H.trace_pod_entry(entry)

    assert_equal "pod_watch", trace.fetch("kind")
    assert_match(/\A\d{4}-\d{2}-\d{2}T/, trace.fetch("at"))
    assert_equal "2026-09-04T04:43:14Z", trace.dig("containers", 0, "finishedAt")
  end

  def test_registry_reference_parsing_and_oci_layout_round_trip
    parsed = M2LifecycleOracleRegistryImage.parse_reference("registry.k8s.io/e2e-test-images/busybox@sha256:#{"c" * 64}")

    assert_equal(
      {"registry" => "registry.k8s.io", "repository" => "e2e-test-images/busybox", "digest" => "sha256:#{"c" * 64}",
       "name" => "registry.k8s.io/e2e-test-images/busybox"}, parsed
    )
    assert_raises(M2LifecycleOracleRegistryImage::FetchError) { M2LifecycleOracleRegistryImage.parse_reference("registry.k8s.io/e2e-test-images/busybox:1.36.1-1") }

    config = JSON.generate({"architecture" => "amd64", "os" => "linux"})
    layer = "layer-bytes"
    manifest = JSON.generate({"schemaVersion" => 2, "mediaType" => "application/vnd.docker.distribution.manifest.v2+json",
                              "config" => {"digest" => "sha256:#{Digest::SHA256.hexdigest(config)}", "size" => config.bytesize},
                              "layers" => [{"digest" => "sha256:#{Digest::SHA256.hexdigest(layer)}", "size" => layer.bytesize}]})
    reference = M2LifecycleOracleRegistryImage.parse_reference("registry.k8s.io/e2e-test-images/busybox@sha256:#{Digest::SHA256.hexdigest(manifest)}")
    Dir.mktmpdir("rubernetes-m2-oci-") do |directory|
      archive = File.join(directory, "image.oci.tar")
      M2LifecycleOracleRegistryImage.write_oci_layout(archive, reference, manifest, "application/vnd.docker.distribution.manifest.v2+json",
                                                      {"sha256:#{Digest::SHA256.hexdigest(config)}" => config,
                                                       "sha256:#{Digest::SHA256.hexdigest(layer)}" => layer})

      assert_equal true, M2LifecycleOracleRegistryImage.verify_archive(archive, reference)
      other = M2LifecycleOracleRegistryImage.parse_reference("registry.k8s.io/e2e-test-images/busybox@sha256:#{"d" * 64}")

      assert_equal false, M2LifecycleOracleRegistryImage.verify_archive(archive, other)
    end
  end

  private

  def pod(phase, status)
    {"metadata" => {"name" => "m2-pod"}, "status" => {"phase" => phase, "containerStatuses" => [status]}}
  end

  def terminated(restart_count, exit_code, reason)
    {"name" => "app", "ready" => false, "started" => false, "restartCount" => restart_count,
     "state" => {"terminated" => {"exitCode" => exit_code, "reason" => reason, "startedAt" => "2026-09-04T04:43:14Z", "finishedAt" => "2026-09-04T04:43:14Z"}}}
  end

  def waiting(restart_count, message, last_exit_code, last_reason)
    {"name" => "app", "ready" => false, "started" => false, "restartCount" => restart_count,
     "state" => {"waiting" => {"reason" => "CrashLoopBackOff", "message" => message}},
     "lastState" => {"terminated" => {"exitCode" => last_exit_code, "reason" => last_reason, "startedAt" => "2026-09-04T04:43:14Z", "finishedAt" => "2026-09-04T04:43:14Z"}}}
  end
end
