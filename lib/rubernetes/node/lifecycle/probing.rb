# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Probes of running containers: liveness restarts, readiness and
      # endpoint membership, and waking a Pod when its next probe is due.
      module Probing
        PROBE_EVENT_NAMES = {"startup" => "Startup", "liveness" => "Liveness", "readiness" => "Readiness"}.freeze

        # Probe one live container and restart it when liveness fails.  Readiness
        # only changes endpoint membership; it never triggers a restart.
        def probe(pod_or_uid, container_name: nil, now: nil)
          object, uid, record = resolve_record(pod_or_uid)
          raise LifecycleError, "Pod #{uid} is not running" unless record && record[:state] == "Running"

          # A container waiting out its restart backoff has no live container to
          # probe; probing the address anyway would fail liveness again and push
          # the backoff out on every sync.
          selected = record[:containers].select do |entry|
            entry[:started] && entry[:restart_pending].nil? && (container_name.nil? || entry[:name] == container_name.to_s)
          end
          probe_entries(object, uid, record, selected, now)
        end

        alias probe_containers probe

        def probe_entries(object, uid, record, selected, now)
          results = selected.to_h { |entry| [entry[:name], evaluate_probes(object, record, entry, now)] }
          readiness_before = selected.map { |entry| entry[:status].values_at("ready", "started") if entry[:status].is_a?(Hash) }
          restarted = false
          selected.each do |entry|
            restarted = true if apply_probe_results(object, uid, record, entry, results.fetch(entry[:name]), now)
          end
          # A probe pass that changed nothing the Pod status shows -- the
          # common case, every periodSeconds for every probed container --
          # neither republishes status nor persists the node's state (kubelet
          # keeps probe results in memory only).  It was half of what the agent
          # allocated once probes ran on their own schedule.
          readiness_after = selected.map { |entry| entry[:status].values_at("ready", "started") if entry[:status].is_a?(Hash) }
          # A container status replaced since the last publish (a started
          # ephemeral container, say) is published here too, as every pass did.
          if restarted || readiness_after != readiness_before || record[:published_status_signature] != status_signature(record)
            update_status(object, record)
            persist_state!
          end
          results
        end

        private :probe_entries

        # Which status object each container holds: transitions replace it, so
        # a difference means something was not published yet.
        # Device health (ResourceHealthStatus) is part of it: a health change
        # alone republishes the status, as the kubelet's update channel does.
        def status_signature(record)
          record[:containers].map { |entry| [entry[:name], entry[:status].object_id, resource_health(record, entry)] }
        end

        # Called with (pod uid, seconds) when a Pod needs a sync at a given time
        # rather than at the next periodic one (the agent enqueues it then).
        attr_accessor :wakeup

        # A backoff ended between two periodic syncs (every five seconds) and the
        # restart waited for the next one: 2-5 s on top of each of kubelet's
        # 10/20/40 s delays ("Probing container should have monotonically
        # increasing restart count" ran 20-30 s over upstream).  The Pod is now
        # woken when its backoff ends.
        def schedule_wakeup(uid, delay)
          return if @wakeup.nil? || delay.nil?

          # The wakeup is the agent's callback; its failure is not the Pod's.
          best_effort { @wakeup.call(uid, Float(delay)) }
        end

        private

        # SyncTerminatingPod stops startup and liveness while readiness keeps
        # observing containers through preStop and TERM until the runtime stops.
        def with_terminating_readiness(pod, record)
          return yield if pod.nil? || %w[Succeeded Failed].include?(record[:phase])

          probes = record[:containers].filter_map do |entry|
            definition = Helpers.key(entry[:spec], "readinessProbe", nil)
            [entry, definition] if entry[:started] && definition && @probes.startup_succeeded?(entry[:id])
          end
          return yield if probes.empty?

          stopped = Queue.new
          publish_lock = Mutex.new
          probes.each do |entry, definition|
            watch_terminating_readiness(pod, record, entry, definition, stopped, publish_lock)
          end
          yield
        ensure
          # Let an in-progress report finish before publishing the stopped status.
          publish_lock&.synchronize { stopped.close }
        end

        def watch_terminating_readiness(pod, record, entry, definition, stopped, publish_lock)
          period = [Helpers.key(definition, "periodSeconds", ProbeManager::DEFAULT_PERIOD_SECONDS).to_i, 1].max
          context = probe_context(pod, record, entry)
          Thread.new do
            until stopped.closed? || !entry[:started]
              stopped.pop(timeout: period)
              break if stopped.closed? || !entry[:started]

              best_effort do
                result = @probes.check(entry[:id], probe: definition, type: "readiness", context: context, registered_only: true)
                publish_lock.synchronize do
                  publish_terminating_readiness(pod, record, entry, result) unless stopped.closed?
                end
              end
            end
          end
        end

        def publish_terminating_readiness(pod, record, entry, result)
          observation = entry[:status]
          return unless result && !result.deferred && entry[:started] && observation.is_a?(Hash)

          record_probe_event(record, entry, "readiness", result)
          ready = @probes.ready?(entry[:id])
          return if observation["ready"] == ready || !entry[:status].equal?(observation)

          observation["ready"] = ready
          update_status(pod, record)
        end

        # One container's startup, liveness and readiness probes, evaluated by
        # the probe manager.
        def evaluate_probes(object, record, entry, now, startup_only: false)
          definition = entry[:spec]
          context = probe_context(object, record, entry)
          if startup_only
            outcome = @probes.check(entry[:id], probe: definition.fetch("startupProbe"), type: "startup", context: context, now: now)
            return {"startup" => outcome}
          end

          @probes.evaluate(entry[:id], probes: probes_for(definition), context: context, now: now)
        end

        def probe_context(object, record, entry)
          context = {"ports" => Helpers.key(entry[:spec], "ports", [])}
          pod_metadata = Helpers.key(object, "metadata", {})
          context["metric_labels"] = {"container" => entry[:name].to_s, "pod" => Helpers.key(pod_metadata, "name", "").to_s,
                                      "namespace" => Helpers.key(pod_metadata, "namespace", "").to_s,
                                      "pod_uid" => Helpers.key(pod_metadata, "uid", "").to_s}
          # kubelet probes the Pod IP (or the node when hostNetwork); the
          # loopback default only fits runtimes that execute the probe inside
          # the sandbox.
          probe_host = pod_ips(record).first
          probe_host = @host_ip if Helpers.key(Helpers.key(object, "spec", {}), "hostNetwork", false) == true
          context["host"] = probe_host if probe_host
          context
        end

        # Acts on one container's probe results: Unhealthy events, a liveness
        # restart, endpoint membership.  True when the container was restarted.
        def apply_probe_results(object, uid, record, entry, result, now)
          # prober: every failed probe records a Warning "Unhealthy" event with the
          # probe's output ("Liveness probe failed: ...") -- without it a failing
          # probe was invisible until the Killing event.
          PROBE_EVENT_NAMES.each_key do |key|
            outcome = result[key]
            record_probe_event(record, entry, key, outcome) if outcome
          end
          if result["startup"]&.failed? && @probes.startup_failed?(entry[:id])
            restart_container(object, record, entry, reason: "StartupProbe", now: now)
            return true
          end
          if result["liveness"]&.failed? && @probes.liveness_failed?(entry[:id])
            restart_container(object, record, entry, reason: "LivenessProbe", now: now)
            return true
          end

          apply_readiness(object, uid, entry, result["readiness"]) if record[:state] == "Running"
          update_probe_status(entry) if entry[:started] && entry[:status].is_a?(Hash)
          false
        end

        def record_probe_event(record, entry, type, result)
          if result.is_a?(ProbeManager::Result) && result.state == "Warning"
            event(record, "probe.warning", name: entry[:name], container_id: entry[:id], probe: type, message: result.message)
          elsif result.failed?
            label = PROBE_EVENT_NAMES.fetch(type)
            event(record, "probe.unhealthy", name: entry[:name], container_id: entry[:id], reason: "Unhealthy",
                                             probe: type, message: "#{label} probe failed: #{result.message}".rstrip)
          end
        end

        def update_probe_status(entry)
          entry[:status]["ready"] = @probes.ready?(entry[:id])
          startup = Helpers.key(entry[:spec], "startupProbe", nil)
          entry[:status]["started"] = startup.nil? || @probes.startup_succeeded?(entry[:id])
        end

        # Readiness only moves the Pod in or out of its endpoints, and only
        # once the probe manager's failure threshold agrees with the result.
        def apply_readiness(object, uid, entry, readiness)
          return unless readiness

          state = begin
            @probes.state(entry[:id])
          rescue KeyError
            return
          end
          readiness_state = state[:readiness] || state["readiness"] || {failed: false}
          if readiness.failed? && readiness_state.fetch(:failed)
            remove_endpoints(object, uid)
          elsif readiness.success? && !readiness_state.fetch(:failed)
            mark_ready(object, uid)
          end
        end

        def probe_running_containers(record, pod)
          return if record[:containers].empty?

          probe(pod)
          running = record[:containers].select { |entry| entry[:restart_pending].nil? && entry[:started] }
          schedule_probe_wakeup(record[:uid], running, first: false)
        rescue LifecycleError
          nil
        end

        def probe_initialized_sidecars(pod, record)
          current = pod.dig("spec", "initContainers", record.fetch(:next_init_index), "name")
          entries = record[:containers].select { |entry| entry[:category] == "sidecar" && entry[:started] && entry[:name] != current }
          return if entries.empty?

          probe_entries(pod, record[:uid], record, entries, nil)
          schedule_probe_wakeup(record[:uid], entries, first: false)
        end

        # kubelet runs each probe from its own ticker: the first at
        # initialDelaySeconds, then every periodSeconds (default 10).  Here the
        # Pod is woken for its next due probe; left to whatever event happened
        # to reconcile it, a liveness probe ran about every 10 s from the
        # container's start and first failed at 20 s where kubelet's does at
        # 10-20 ("Probing container should have monotonically increasing
        # restart count": 5 restarts in 172 s, upstream 146).
        DEFAULT_PROBE_PERIOD_SECONDS = 10
        FIRST_PROBE_MINIMUM_SECONDS = 0.2

        def schedule_probe_wakeup(uid, entries, first:)
          return if uid.nil? || @wakeup.nil?

          definitions = Array(entries).flat_map { |entry| probes_for(entry[:spec]).values.compact }.grep(Hash)
          return if definitions.empty?

          delay = if first
                    [definitions.map { |probe| Helpers.key(probe, "initialDelaySeconds", 0).to_f }.min, FIRST_PROBE_MINIMUM_SECONDS].max
                  else
                    definitions.map { |probe| Helpers.key(probe, "periodSeconds", DEFAULT_PROBE_PERIOD_SECONDS).to_f }.min
                  end
          schedule_wakeup(uid, delay)
        end

        def remove_endpoints(pod, uid)
          @status.remove_from_endpoints(uid, pod: pod)
        end

        def mark_ready(pod, uid)
          endpoint = @status.endpoint_manager
          return unless endpoint

          if endpoint_supports?(:set_ready)
            endpoint.set_ready(uid, true)
          elsif endpoint_supports?(:add)
            endpoint.add(uid, pod)
          elsif endpoint_supports?(:mark_ready)
            endpoint.mark_ready(uid)
          end
        end
      end
    end
  end
end
