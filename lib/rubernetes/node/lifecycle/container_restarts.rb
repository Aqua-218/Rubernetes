# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Restarting containers: the restart policy and CrashLoopBackOff for one
      # container, and RestartAllContainers for the whole Pod.
      module ContainerRestarts
        def restart_container(pod, record = nil, entry = nil, reason: "Failure", now: nil, attempt: nil)
          object = normalize_pod(pod)
          uid = pod_uid(object)
          record ||= self.record(uid)
          raise LifecycleError, "Pod #{uid} is not running" unless record

          entry ||= record[:containers].first
          policy = container_policy(object, entry[:spec])
          restart_key = restart_identity(record, entry)
          attempt ||= @restarts.record_exit(
            restart_key, exit_code: 1, reason: reason, policy: policy,
                         at: now, liveness_failure: reason.to_s == "LivenessProbe"
          )
          return attempt unless @restarts.should_restart?(policy: policy, exit_code: 1, reason: reason,
                                                          liveness_failure: reason.to_s == "LivenessProbe")

          if reason.to_s == "LivenessProbe"
            # kubelet: events.Killing "Container <name> failed liveness probe, will be restarted"
            event(record, "container.killing", name: entry[:name], container_id: entry[:id], reason: "Killing",
                                               message: "Container #{entry[:name]} failed liveness probe, will be restarted")
          end
          remove_endpoints(object, uid)
          stop_one(entry[:id], grace_seconds(object), release_process: false)
          # kubelet keeps the dead container until its replacement starts: its
          # log is what `kubectl logs` serves while the restart backs off
          # (CrashLoopBackOff), and the e2e DNS specs read exactly that.
          # Removing it here answered every such request with "waiting to
          # start".  The retired container goes when the next one is created.
          entry[:retired_id] = entry[:id]
          last_state = if entry[:status].is_a?(Hash) && entry[:status]["state"] == "terminated"
                         {"exitCode" => Integer(entry[:status]["exitCode"] || 0), "reason" => entry[:status]["reason"].to_s}
                       else
                         {"exitCode" => reason.to_s == "LivenessProbe" ? 137 : 1, "reason" => "Error"}
                       end
          entry[:last_state] = {"terminated" => last_state}
          if attempt.delay_seconds.positive?
            wait_out_backoff(object, uid, record, entry, attempt, restart_key)
            return attempt
          end
          resume_restart(object, record, entry, attempt.restart_count)
          attempt
        end

        # No restart can put a container into a sandbox the runtime no longer
        # has (an agent restart found the namespace holder dead): the Pod kept
        # "restarting" into it for ever, one backoff period at a time.  kubelet:
        # pod sandbox changed -- kill the Pod and sync it from scratch.  Yields
        # the error when the sandbox is gone.
        def create_in_live_sandbox(record, entry)
          create_container(record[:sandbox_id], entry[:spec])
        rescue StandardError => error
          raise unless sandbox_lost_error?(error) || sandbox_lost?(record)

          yield error
        end

        # The tail of a restart: create and start the container again, register
        # its probes, and publish it as running.
        def resume_restart(pod, record, entry, restart_count)
          object = normalize_pod(pod)
          uid = pod_uid(object)
          entry.delete(:restart_pending)
          entry.delete(:restart_attempt)
          entry[:id] = create_in_live_sandbox(record, entry) { |error| return lose_sandbox!(object, record, error) }
          # The new container is this restart count's run from now on: an exit
          # observed before this thread records the start (exit 0 within 100 ms)
          # takes the count from the status, and with the previous run's 0 there
          # the Pod finished Succeeded with restartCount 0 where 1 was due
          # ("Container Runtime blackbox test ... terminate-cmd-rpof", round 101).
          entry[:status] = entry[:status].merge("restartCount" => restart_count) if entry[:status].is_a?(Hash)
          # kubelet emits Created/Started for every restart, not only the first.
          event(record, "container.create", name: entry[:name], container_id: entry[:id])
          pre_start_container(record, entry)
          start_container(entry[:id])
          entry[:started] = true
          # The retired container served the log until this moment; now the
          # replacement has one of its own.
          if (retired = entry.delete(:retired_id))
            begin
              remove_container(retired)
            rescue StandardError => error
              event(record, "container.remove_failed", name: entry[:name], container_id: retired,
                                                       message: Helpers.failure_message(error))
            end
          end
          # A restarted container can run to completion before this thread gets
          # here: the exit observer already recorded "terminated" for this very
          # container id (exit 0, 90 ms after start).  Writing "running" over it
          # reported a Succeeded Pod's container as Running again --
          # "[sig-node] Container Runtime blackbox test ... terminate-cmd-rpof"
          # expected Terminated.  The exit wins; nothing here may undo it.
          if exited_already?(entry)
            entry[:started] = false
            event(record, "container.started", name: entry[:name], container_id: entry[:id],
                                               restart_count: restart_count, exited_before_start_recorded: true)
            update_status(object, record)
            persist_state!
            return
          end
          started_at = mark_container_started(entry, record)
          entry[:status] = {"state" => "running", "running" => {"startedAt" => started_at},
                            "ready" => false, "started" => true, "restartCount" => restart_count,
                            "lastState" => entry[:last_state]}
          @probes.register(entry[:id], probes: probes_for(entry[:spec]))
          schedule_probe_wakeup(uid, [entry], first: true)
          entry[:status]["ready"] = @probes.ready?(entry[:id])
          mark_ready(object, uid) if @probes.ready?(entry[:id])
          event(record, "container.started", name: entry[:name], container_id: entry[:id],
                                             restart_count: restart_count)
          update_status(object, record)
          persist_state!
        end

        # A container waiting out its CrashLoopBackOff is restarted by the first
        # sync that finds the backoff elapsed.
        def resume_backoff_restarts(record, pod, now: nil)
          record[:containers].each do |entry|
            key = entry[:restart_pending]
            next if key.nil?
            next unless @restarts.restart_ready?(key, now: now)

            begin
              resume_restart(pod, record, entry, entry[:restart_attempt].to_i)
            rescue StandardError => error
              # A failed re-create must not strand the container: drop the
              # pending marker so the next sync tries again rather than leaving
              # it waiting for ever.
              entry.delete(:restart_pending)
              event(record, "container.restart_failed", name: entry[:name],
                                                        message: Helpers.failure_message(error))
            end
          end
        end

        # kubelet: after every regular container exited, running sidecars are
        # terminated so the Pod can reach its terminal phase.
        def stop_sidecars(record)
          record[:containers].select { |entry| entry[:category] == "sidecar" && entry[:started] }.reverse_each do |entry|
            # A sidecar that cannot be stopped cleanly is reported from what
            # the runtime says of it; the Pod is finishing either way.
            best_effort { stop_one(entry[:id], grace_seconds(record[:pod])) }
            entry[:started] = false
            terminated = stopped_termination(entry[:id])
            entry[:status] = {"state" => "terminated", "exitCode" => terminated.fetch("exitCode"), "reason" => terminated.fetch("reason"),
                              "terminated" => terminated, "ready" => false, "started" => false,
                              "restartCount" => entry[:status]["restartCount"].to_i}
          end
        end

        private

        # kubelet parity: while the restart backoff runs the container waits
        # in CrashLoopBackOff and reports its last termination.  The wait is
        # RECORDED rather than slept through -- sleeping here held the node's
        # whole sync loop for every other Pod, and a restart interrupted
        # anywhere after the sleep left the container waiting for ever: a
        # liveness-failing Pod restarted exactly once and then sat in
        # "back-off 10s" until it was deleted.  kubelet's SyncPod does the
        # same: the backoff is a check on the next sync, not a sleep.
        def wait_out_backoff(object, uid, record, entry, attempt, restart_key)
          entry[:started] = false
          # kubelet reports the exited container's own restart count while it
          # waits (the CRI annotation of the container that just died); the
          # count moves when the next container is created.
          identity = backoff_pod_identity(object, uid)
          entry[:status] = {
            "state" => "waiting", "ready" => false, "started" => false,
            "restartCount" => entry[:restart_count_before_exit] || attempt.restart_count,
            "waiting" => {"reason" => "CrashLoopBackOff",
                          "message" => "back-off #{attempt.delay_seconds}s restarting failed container=#{entry[:name]} pod=#{identity}"},
            "lastState" => entry[:last_state]
          }
          entry[:restart_pending] = restart_key
          entry[:restart_attempt] = attempt.restart_count
          update_status(object, record)
          persist_state!
          schedule_wakeup(uid, attempt.delay_seconds)
        end

        def backoff_pod_identity(pod, uid)
          metadata = Helpers.key(pod, "metadata", {})
          "#{Helpers.key(metadata, "name", "")}_#{Helpers.key(metadata, "namespace", "")}(#{uid})"
        end

        # container.restartPolicyRules: does this exit match a rule whose action
        # is RestartAllContainers?
        def restart_all_rule?(entry, exit_code)
          rule = @restarts.matching_restart_rule(Helpers.key(entry[:spec], "restartPolicyRules", nil), exit_code)
          rule && Helpers.key(rule, "action", nil).to_s == "RestartAllContainers"
        end

        RESTARTING_ALL_CONTAINERS = "RestartingAllContainers"
        RESTARTING_ALL_CONTAINERS_MESSAGE = "The container is removed because RestartAllContainers in place"

        # kuberuntime SyncPod with restartAllContainers (KEP-5532): a container
        # exited with a RestartAllContainers rule, so every init, sidecar and
        # regular container is killed without grace and removed -- the
        # containers that did not trigger it first, the source last -- while
        # the sandbox, its network and its volumes stay.  The Pod then starts
        # again from its first init container.  The rule was matched and
        # treated as a plain restart of the one container that exited.
        def restart_all_containers(pod, record, sources)
          object = normalize_pod(pod)
          reset_all_containers(object, record, sources)
          begin
            start_init_containers(object, record)
            start_application_containers(object, record)
          rescue LifecycleError => error
            fail_record(record, error)
            return
          rescue StandardError => error
            fail_record(record, LifecycleError.new("Pod restart failed: #{Helpers.failure_message(error)}"))
            return
          end
          record[:reason] = nil
          record[:error] = nil
          update_status(object, record)
        end

        def reset_all_containers(pod, record, sources)
          object = normalize_pod(pod)
          uid = record[:uid]
          resettable = record[:containers].reject { |entry| entry[:category] == "ephemeral" }
          targets = resettable - sources
          by_category = ->(entries, app) { entries.select { |entry| (entry[:category] == "app") == app } }
          ordered = by_category.call(targets, true) + by_category.call(targets, false) +
                    by_category.call(sources, true) + by_category.call(sources, false)
          event(record, "pod.restart_all_containers", sources: sources.map { |entry| entry[:name] })
          remove_endpoints(object, uid)
          record[:restarting_all] = true
          record[:previous_terminations] = {} unless record[:previous_terminations].is_a?(Hash)
          ordered.each do |entry|
            if entry[:started]
              event(record, "container.killing", name: entry[:name], container_id: entry[:id], reason: "Killing", message: "killing")
              entry[:started] = false
              # Killed without grace; the container is removed just below
              # whatever the stop answered.
              best_effort { stop_one(entry[:id], 0) }
            end
            @probes.unregister(entry[:id])
            [entry.delete(:retired_id), entry[:id]].compact.each do |container_id|
              remove_container(container_id)
            rescue StandardError => error
              event(record, "container.remove_failed", name: entry[:name], container_id: container_id,
                                                       message: Helpers.failure_message(error))
            end
            entry.delete(:restart_pending)
            terminated = {"exitCode" => 137, "reason" => RESTARTING_ALL_CONTAINERS, "message" => RESTARTING_ALL_CONTAINERS_MESSAGE}
            before = entry.delete(:restart_count_before_exit)
            before = nil unless sources.include?(entry)
            before = entry[:status].is_a?(Hash) ? entry[:status]["restartCount"].to_i : 0 if before.nil?
            restart_count = before + 1
            @restarts.advance_restart_count(restart_identity(record, entry), to: restart_count)
            entry[:last_state] = {"terminated" => terminated}
            entry[:status] = {"state" => "waiting", "ready" => false, "started" => false, "restartCount" => restart_count,
                              "waiting" => {"reason" => RESTARTING_ALL_CONTAINERS, "message" => RESTARTING_ALL_CONTAINERS_MESSAGE},
                              "lastState" => entry[:last_state]}
            record[:previous_terminations][entry[:name].to_s] = entry[:last_state]
          end
          # Published once with AllContainersRestarting=True while nothing runs.
          update_status(object, record)
          persist_state!
          record[:containers] = record[:containers] - resettable
          record[:restarting_all] = false
        end
      end
    end
  end
end
