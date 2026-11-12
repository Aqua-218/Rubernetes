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
            entry[:restart_pending].nil? && (container_name.nil? || entry[:name] == container_name.to_s)
          end
          results = selected.to_h { |entry| [entry[:name], evaluate_probes(object, record, entry, now)] }
          readiness_before = selected.map { |entry| entry[:status].is_a?(Hash) ? entry[:status]["ready"] : nil }
          restarted = false
          selected.each do |entry|
            restarted = true if apply_probe_results(object, uid, record, entry, results.fetch(entry[:name]), now)
          end
          # A probe pass that changed nothing the Pod status shows -- the
          # common case, every periodSeconds for every probed container --
          # neither republishes status nor persists the node's state (kubelet
          # keeps probe results in memory only).  It was half of what the agent
          # allocated once probes ran on their own schedule.
          readiness_after = selected.map { |entry| entry[:status].is_a?(Hash) ? entry[:status]["ready"] : nil }
          # A container status replaced since the last publish (a started
          # ephemeral container, say) is published here too, as every pass did.
          if restarted || readiness_after != readiness_before || record[:published_status_signature] != status_signature(record)
            update_status(object, record)
            persist_state!
          end
          results
        end

        alias probe_containers probe

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

        # One container's startup, liveness and readiness probes, evaluated by
        # the probe manager.
        def evaluate_probes(object, record, entry, now)
          definition = entry[:spec]
          context = {"ports" => Helpers.key(definition, "ports", [])}
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
          @probes.evaluate(entry[:id], probes: probes_for(definition), context: context, now: now)
        end

        # Acts on one container's probe results: Unhealthy events, a liveness
        # restart, endpoint membership.  True when the container was restarted.
        def apply_probe_results(object, uid, record, entry, result, now)
          # prober: every failed probe records a Warning "Unhealthy" event with the
          # probe's output ("Liveness probe failed: ...") -- without it a failing
          # probe was invisible until the Killing event.
          PROBE_EVENT_NAMES.each do |key, label|
            outcome = result[key]
            next unless outcome&.failed?

            event(record, "probe.unhealthy", name: entry[:name], container_id: entry[:id], reason: "Unhealthy",
                                             probe: key, message: "#{label} probe failed: #{outcome.message}".rstrip)
          end
          restarted = false
          liveness = result["liveness"]
          if liveness && liveness.failed? && @probes.liveness_failed?(entry[:id])
            restart_container(object, record, entry, reason: "LivenessProbe", now: now)
            restarted = true
          end
          apply_readiness(object, uid, entry, result["readiness"])
          entry[:status]["ready"] = @probes.ready?(entry[:id]) if entry[:started] && entry[:status].is_a?(Hash)
          restarted
        end

        # Readiness only moves the Pod in or out of its endpoints, and only
        # once the probe manager's failure threshold agrees with the result.
        def apply_readiness(object, uid, entry, readiness)
          return unless readiness

          state = @probes.state(entry[:id])
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
