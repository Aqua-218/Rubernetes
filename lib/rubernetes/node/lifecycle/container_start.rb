# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Creating and starting containers in order: init containers one by one,
      # sidecars, application containers, and ephemeral containers added to a
      # running Pod.
      module ContainerStart
        INIT_EXIT_REASON = "Init:Error"

        private

        # An init container whose exit matches a RestartAllContainers rule
        # resets the Pod and the init sequence runs again from the first one.
        def start_init_containers(pod, record)
          loop do
            result = run_init_containers(pod, record)
            return result unless result == :restart_all
          end
        end

        def run_init_containers(pod, record)
          spec = Helpers.key(pod, "spec", {})
          first_index = record[:next_init_index].to_i
          Array(Helpers.key(spec, "initContainers", [])).each_index do |index|
            next if index < first_index

            record[:next_init_index] = index
            pod = adopt_init_image_updates(record)
            return :pending unless pod

            definition = Helpers.string_keys(pod.dig("spec", "initContainers", index))
            name = Helpers.key(definition, "name", "")
            sidecar = restartable_init?(definition)
            entry = init_entry(record, definition, sidecar ? "sidecar" : "init", index)
            if sidecar
              return :pending unless sidecar_startup_ready?(pod, record, entry)

              event(record, "init.sidecar.running", name: name)
              next
            end
            return :pending if entry[:restart_pending]

            # Controllers issuing certificates need the Pod IP while the init
            # container is still waiting for its mounted Secret.
            update_status(pod, record)
            exit_status = wait_for_init(entry, record)
            pod = record[:pod]
            exit_code = init_exit_code(exit_status)
            if exit_code && restart_all_rule?(entry, exit_code)
              reset_all_containers(pod, record, [entry])
              return :restart_all
            end
            return handle_failed_init(pod, record, entry, exit_status, exit_code: exit_code) unless exit_code == 0

            # kubelet reports a completed init container as Ready and no longer
            # started (kubelet/status: initialized init containers are ready).
            entry[:status] = completed_init_status(entry, status_hash(exit_status), observed_at: Helpers.now(@clock).iso8601(6))
            entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
            entry[:started] = false
            event(record, "init.completed", name: name)
          end
          record.delete(:next_init_index)
          :completed
        end

        # Native wait can report only a flat exit result. Preserve the runtime's
        # times when available and use the lifecycle's start and exit observation.
        def completed_init_status(entry, status, observed_at: nil)
          runtime = status["terminated"]
          runtime = status unless runtime.is_a?(Hash)
          terminated = runtime.slice("message", "signal")
          terminated["exitCode"] = 0
          terminated["reason"] = runtime["reason"].to_s.empty? ? "Completed" : runtime["reason"]
          terminated["containerID"] = runtime["containerID"].to_s.empty? ? entry[:id] : runtime["containerID"]
          terminated["startedAt"] = runtime["startedAt"] || entry[:started_at]
          terminated["finishedAt"] = runtime["finishedAt"] || observed_at
          status.merge("state" => "terminated", "exitCode" => 0, "terminated" => terminated.compact,
                       "ready" => true, "started" => false, "restartCount" => entry[:status]["restartCount"].to_i)
        end

        def init_entry(record, definition, category, index)
          existing = record[:containers].find { |entry| entry[:name] == definition["name"] }
          return existing if existing

          event(record, "init.start", name: definition["name"])
          entry = create_entry(record, definition, category: category, index: index)
          record[:containers] << entry
          start_entry(entry, record)
          entry
        end

        def sidecar_startup_ready?(pod, record, entry)
          return true if entry[:status]["started"]

          return false unless entry[:started]

          check_start_cancelled!(record)
          outcomes = evaluate_probes(pod, record, entry, nil, startup_only: true)
          apply_probe_results(pod, record[:uid], record, entry, outcomes, nil)
          schedule_probe_wakeup(record[:uid], [entry], first: false) if entry[:started] && !entry[:status]["started"]
          entry[:status]["started"] == true
        end

        def init_exit_code(exit_status)
          return 0 if init_success?(exit_status)
          return Integer(exit_status) if exit_status.is_a?(Numeric)

          status = status_hash(exit_status)
          code, signal = exit_details(status)
          code ||= status["code"]
          if value_reports?(exit_status, :exit_status)
            code = exit_status.exit_status
            signal = exit_status.term_signal if value_reports?(exit_status, :term_signal)
          end
          return Integer(code) unless code.nil?

          128 + Integer(signal) if signal
        rescue ArgumentError, TypeError
          nil
        end

        # A non-zero init container exit is a container exit like any other: it
        # is what the restart backoff counts and what the next attempt reports as
        # its previous state.  Only the app-container path recorded exits, so an
        # init container that failed on every attempt stayed at restartCount 0
        # with an empty lastState no matter how long the Pod had been looping.
        def record_failed_init_exit(record, entry, exit_status, exit_code:)
          status = status_hash(exit_status, fallback: {"state" => "terminated", "exitCode" => 1})
          reason = Helpers.key(status, "reason", nil).to_s
          reason = "Error" if reason.empty?
          terminated = {"exitCode" => exit_code, "reason" => reason,
                        "finishedAt" => Helpers.now(@clock).iso8601(6), "containerID" => entry[:id]}
          terminated["startedAt"] = entry[:started_at] if entry[:started_at]
          attempt = @restarts.record_exit(restart_identity(record, entry), exit_code: exit_code, reason: reason,
                                                                           policy: container_policy(record[:pod], entry[:spec]),
                                                                           rules: Helpers.key(entry[:spec], "restartPolicyRules", nil))
          entry[:started] = false
          entry[:restart_count_before_exit] = entry[:status]["restartCount"].to_i
          entry[:status] = status.merge("state" => "terminated", "exitCode" => exit_code, "reason" => reason,
                                        "terminated" => terminated, "ready" => false, "started" => false,
                                        "restartCount" => attempt.restart_count)
          entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
          entry[:last_state] = {"terminated" => terminated}
          attempt
        end

        def handle_failed_init(pod, record, entry, exit_status, exit_code:)
          message = "init container #{entry[:name].inspect} failed"
          raise LifecycleError, message if exit_code.nil?

          attempt = record_failed_init_exit(record, entry, exit_status, exit_code: exit_code)
          if attempt.restart_pending?
            restart_container(pod, record, entry, reason: entry[:status].fetch("reason"), attempt: attempt)
            return :pending
          end

          record[:reason] = INIT_EXIT_REASON
          record[:error] = message
          :failed
        end

        INIT_WAIT_INTERVAL = 0.25

        def wait_for_init(entry, record)
          if runtime_supports?(:wait_container)
            return invoke(@runtime, :wait_container, entry[:id]) unless accepts_keyword?(@runtime, :wait_container, :timeout)

            loop do
              check_start_cancelled!(record)
              desired = desired_during_initialization(record)
              resize_while_initializing(record, desired) if desired
              result = invoke(@runtime, :wait_container, entry[:id], timeout: INIT_WAIT_INTERVAL)
              check_start_cancelled!(record)
              return result unless %w[running created].include?(Helpers.key(result, "state", nil).to_s)

              follow_running_init_sidecars(record) if record[:containers].any? { |candidate| candidate[:category] == "sidecar" }
              sync_volumes(record, record[:pod]) if volume_sync_due?(record)
            end
          elsif runtime_supports?(:container_status)
            invoke(@runtime, :container_status, entry[:id])
          else
            raise LifecycleError, "runtime cannot confirm init container exit"
          end
        end

        def follow_running_init_sidecars(record)
          previous = record[:pod]
          current = adopt_init_image_updates(record, sidecars_only: true)
          raise StartCancelled unless record[:state] == "WorkloadStopped"

          update_status(current, record) if current && !current.equal?(previous)
          resume_backoff_restarts(record, record[:pod])
          raise StartCancelled unless record[:state] == "WorkloadStopped"

          probe_initialized_sidecars(record[:pod], record)
        end

        def check_start_cancelled!(record)
          raise StartCancelled if @mutex.synchronize { record[:config_removed] }
        end

        def desired_during_initialization(record)
          desired = @desired_pod_lookup&.call(record[:uid])
          if desired.nil?
            raise StartCancelled if record[:desired_pod_seen]

            return nil
          end
          record[:desired_pod_seen] = true
          raise StartCancelled if deletion_requested?(desired)

          desired
        end

        def init_success?(value)
          # A missing wait result is an unknown/timeout outcome.  Treating nil
          # as exit 0 lets an init container race ahead of the runtime and makes
          # recovery indistinguishable from a successful completion.
          return false if value.nil?
          return true if value == true

          if value_reports?(value, :exit_status)
            exit_status = value.exit_status
            term_signal = value_reports?(value, :term_signal) ? value.term_signal : nil
            return false if exit_status.nil? && term_signal.nil?

            return Integer(exit_status).zero? unless exit_status.nil?

            return false
          end
          if value.is_a?(Hash)
            exit_code = Helpers.key(value, "exitCode", Helpers.key(value, "exit_code", Helpers.key(value, "code", nil)))
            if value.key?("exitCode") || value.key?("exit_code") || value.key?("code") || value.key?(:exitCode) || value.key?(:exit_code) || value.key?(:code)
              return false if exit_code.nil?

              return Integer(exit_code).zero?
            end
            return false if Helpers.key(value, "state", nil).to_s.match?(/\A(?:created|running|waiting|pending)\z/i)

            return Helpers.success_result?(value) if value.key?("success") || value.key?("allowed") || value.key?(:success) || value.key?(:allowed)
            return false if value.key?("state") || value.key?(:state)

            status = Helpers.key(value, "status", nil)
            return Helpers.success_result?(value) if status.is_a?(Numeric)

            return false
          end
          return value.to_i.zero? if value.is_a?(Numeric)

          Helpers.success_result?(value)
        end

        def status_hash(value, fallback: {})
          result = value.is_a?(Hash) ? Helpers.string_keys(value) : {}
          result.empty? ? fallback : result
        end

        def start_application_containers(pod, record)
          spec = Helpers.key(pod, "spec", {})
          Array(Helpers.key(spec, "containers", [])).each_with_index do |definition, index|
            definition = Helpers.string_keys(definition)
            name = Helpers.key(definition, "name", "")
            event(record, "app.start", name: name)
            entry = create_entry(record, definition, category: "app", index: index)
            record[:containers] << entry
            start_entry(entry, record)
          end
        end

        def restartable_init?(definition)
          Helpers.key(definition, "restartPolicy", nil).to_s == "Always"
        end

        # True when the desired spec names an ephemeral container this record has
        # not started yet.  The config digest deliberately ignores
        # spec.ephemeralContainers, so the containers actually started -- not the
        # digest -- are what the desired spec must be compared against.
        def pending_ephemeral_containers?(pod, record)
          started = Array(record[:containers]).select { |entry| entry[:category] == "ephemeral" }
            .map { |entry| entry[:name].to_s }
          started.concat(record.fetch(:rejected_ephemeral_containers, {}).keys)
          ephemeral_definitions(pod).any? do |definition|
            name = Helpers.key(definition, "name", "").to_s
            !name.empty? && !started.include?(name)
          end
        end

        def ephemeral_definitions(pod)
          Array(Helpers.key(Helpers.key(pod, "spec", {}), "ephemeralContainers", [])).map do |entry|
            Helpers.string_keys(entry)
          end
        end

        # Ephemeral containers never restart and carry no resources or probes;
        # they join the Pod's existing sandbox.
        def start_ephemeral_containers(pod, record)
          prepare_ephemeral_volumes(pod, record)
          started = record[:containers].select { |entry| entry[:category] == "ephemeral" }.map { |entry| entry[:name].to_s }
          started.concat(record.fetch(:rejected_ephemeral_containers, {}).keys)
          ephemeral_definitions(pod).each_with_index do |definition, index|
            name = Helpers.key(definition, "name", "").to_s
            next if name.empty? || started.include?(name)
            next if reject_ephemeral_apparmor(pod, record, definition)

            pin_ephemeral_image(pod, record, definition, index)
            event(record, "ephemeral.start", name: name)
            entry = create_entry(record, definition, category: "ephemeral", index: index)
            record[:containers] << entry
            start_entry(entry, record)
            # Published at once: nothing else is bound to run for this Pod soon
            # (its probes pass rarely republishes), and clients wait for the
            # debug container to show as running.
            update_status(pod, record)
            persist_state!
          end
        end

        def reject_ephemeral_apparmor(pod, record, definition)
          return false unless Runtime::AppArmor.enforced?(Runtime::AppArmor.profile(pod, definition))

          message = apparmor_support_error(pod)
          return false unless message

          waiting = {"reason" => "CreateContainerConfigError", "message" => message}
          (record[:rejected_ephemeral_containers] ||= {})[definition.fetch("name")] = {"waiting" => waiting}
          update_status(pod, record)
          persist_state!
          true
        end

        def create_entry(record, definition, category:, index:)
          definition = Helpers.deep_copy(definition)
          # Restartable init containers are represented as sidecars for runtime
          # status/restart policy, but their image was pinned in the init list.
          # Keep the source-list key stable so a sidecar cannot silently lose its
          # digest/entrypoint on the first start or on a restart.
          source_category = category == "sidecar" ? "init" : category
          if (resolved_image = record[:image_by_container][image_key(source_category, index)])
            definition["resolved_image"] = resolved_image
          end
          definition = build_container_spec(record, definition, category: category, index: index)
          container_id = create_container(record, definition, category: category)
          if container_id.to_s.empty?
            raise LifecycleError,
                  "runtime returned an empty container identity for #{Helpers.key(definition, "name", "")}"
          end

          name = Helpers.key(definition, "name", "").to_s
          # A Pod whose start failed is started again from a fresh record, so the
          # container object is new -- but it is the SAME container restarting,
          # and kubelet numbers it as such.  Seeding from zero reported
          # restartCount 0 for ever no matter how many times the Pod had been
          # through this, which is exactly what an init container that keeps
          # failing is counted by.
          entry = {
            id: container_id.to_s,
            name: name,
            spec: definition,
            category: category,
            started: false,
            status: {"state" => "waiting", "ready" => false,
                     "restartCount" => previous_restart_count(record, name)}
          }
          if (last = previous_termination(record, name))
            entry[:last_state] = last
            entry[:status]["lastState"] = last
          end
          entry
        end

        def previous_restart_count(record, name)
          @restarts.restart_count("#{record[:uid]}/#{name}").to_i
        rescue StandardError
          0
        end

        # What each container of the previous attempt ended with, keyed by name.
        def terminations_of(previous)
          return {} unless previous.is_a?(Hash)

          Array(previous[:containers]).each_with_object({}) do |entry, result|
            state = entry[:last_state] || begin
              terminated = entry[:status].is_a?(Hash) ? entry[:status]["terminated"] : nil
              terminated.nil? ? nil : {"terminated" => terminated}
            end
            result[entry[:name].to_s] = state if state
          end
        end

        # The terminated state of the previous attempt, so a restarted container
        # reports where it came from (status.lastState.terminated).
        def previous_termination(record, name)
          terminations = record[:previous_terminations]
          terminations.is_a?(Hash) ? terminations[name.to_s] : nil
        end

        # kubelet generateContainerConfig: the Pod container definition becomes
        # the runtime spec only after env, security context, mounts and the
        # termination message file are resolved against the live Pod.
        def build_container_spec(record, definition, category:, index:)
          return definition unless @container_spec

          pod = record[:pod]
          spec = @container_spec.build(
            pod: pod, container: definition, category: category, index: index,
            resolved_image: definition["resolved_image"], volumes: record[:volume].is_a?(Hash) ? record[:volume] : {},
            pod_files: record[:pod_files] || {}, pod_ips: pod_ips(record), host_ip: (@host_ips unless @host_ips.empty?),
            pod_directory: pod_directory(record), default_home: false, resolve_image_command: !cri_runtime_for_pod?(pod)
          )
          spec = apply_cdi_devices(record, spec, definition)
          spec = apply_device_plugin_allocation(record, spec, definition)
          ContainerSpec.ensure_home!(spec, definition["resolved_image"])
          apply_resource_affinity(record, spec, definition)
        rescue ContainerSpec::ConfigError, PodVolumes::Error => error
          record[:reason] = "CreateContainerConfigError"
          raise LifecycleError, "container #{Helpers.key(definition, "name", "").inspect}: #{error.message}"
        end

        def start_entry(entry, record)
          event(record, "container.create", name: entry[:name], container_id: entry[:id])
          pre_start_container(record, entry)
          start_container(entry[:id])
          entry[:started] = true
          remember_stop_signal(entry)
          started_at = mark_container_started(entry, record)
          entry[:status] = {"state" => "running", "running" => {"startedAt" => started_at},
                            "ready" => false, "started" => true,
                            "restartCount" => entry[:status]["restartCount"].to_i}
          entry[:status]["lastState"] = entry[:last_state] if entry[:last_state]
          @probes.register(entry[:id], probes: probes_for(entry[:spec]), started_at: @clock.call)
          schedule_probe_wakeup(record[:uid], [entry], first: true)
          # Without a readiness probe a running container is Ready (kubelet parity).
          update_probe_status(entry)
          run_post_start_hook(entry, record)
          @restarts.record_start(restart_identity(record, entry), policy: container_policy(record[:pod], entry[:spec]))
          event(record, "container.started", name: entry[:name], container_id: entry[:id])
        end

        def remember_stop_signal(entry)
          return unless @container_stop_signals && runtime_supports?(:container_stop_signal)

          entry[:stop_signal] = best_effort { invoke(@runtime, :container_stop_signal, entry[:id]) }
        end

        def probes_for(definition)
          {
            "startupProbe" => Helpers.key(definition, "startupProbe", nil),
            "livenessProbe" => Helpers.key(definition, "livenessProbe", nil),
            "readinessProbe" => Helpers.key(definition, "readinessProbe", nil)
          }
        end

        def create_container(record, definition, category:)
          definition = definition.except("stop_signal") if definition.key?("stop_signal")
          if @container_stop_signals && category != "ephemeral"
            signal = ContainerStopSignals.custom_signal(definition)
            definition = definition.merge("stop_signal" => signal) if ContainerStopSignals.cri_name(signal)
          end
          # Recovering a CRI sandbox restores its metadata from the runtime.
          # The Pod still supplies the original RuntimeClass on container restart.
          image_options = {runtime_class_name: record.dig(:pod, "spec", "runtimeClassName")}.compact
          value = invoke(@runtime, :create_container, record[:sandbox_id], definition, **image_options)
          return value.id.to_s if value_reports?(value, :id) && !value.id.to_s.empty?

          if value.is_a?(Hash)
            identifier = Helpers.key(value, "id", Helpers.key(value, "containerID", nil))
            return identifier.to_s unless identifier.nil? || identifier.to_s.empty?
          end

          value
        rescue Runtime::ContainerConfigError => error
          record[:reason] = "CreateContainerConfigError"
          raise LifecycleError, error.message
        end

        def start_container(container_id)
          invoke(@runtime, :start_container, container_id)
        end

        def remove_container(container_id)
          # PostStopContainer: the topology manager forgets the container.
          @container_manager&.post_stop(container_id)
          invoke(@runtime, :remove_container, container_id)
        end
      end
    end
  end
end
