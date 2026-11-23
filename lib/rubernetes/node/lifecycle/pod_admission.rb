# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Node admission of a Pod: host port conflicts, the admission handler
      # with critical-Pod preemption, and device plugin allocation.
      module PodAdmission
        # A Pod marked for removal leaves admission's active set and releases
        # any startup waiting for an init container. The worker does the stop.
        def pod_removed(uid)
          @mutex.synchronize do
            record = @records[uid.to_s]
            if record
              record[:config_removed] = true
            else
              @pending_removals[uid.to_s] = true
            end
          end
        end

        # The Pods this node has admitted and not finished with: what the
        # kubelet's predicate admit handler sizes the node's remaining room by.
        # Public: it is the agent's activePods for the shutdown, eviction, QoS,
        # container and DRA managers (the agent checks respond_to?, which a
        # private method fails).
        # Resource managers also retain assignments while admission is in flight.
        def admitted_pods(except: nil, include_allocating: false)
          @mutex.synchronize do
            @records.values.filter_map do |candidate|
              next if candidate[:uid].to_s == except.to_s
              next if INACTIVE_STATES.include?(candidate[:state].to_s) || %w[Succeeded Failed].include?(candidate[:phase].to_s)
              next if candidate[:config_removed]
              # A Pod whose eviction is queued (preemption, node pressure) is
              # being killed: the kubelet no longer counts it as active.
              next if @eviction_requests.key?(candidate[:uid].to_s)

              awaiting_admission = candidate[:state] == "New" && !candidate[:admitted] &&
                                   candidate[:containers].to_a.empty? && candidate[:sandbox_id].nil?
              next if awaiting_admission && !(include_allocating && candidate[:allocating_resources])

              candidate[:pod]
            end
          end
        end

        private

        # A hostPort is a node-wide resource: two Pods cannot both have it.
        #
        # kubelet's own admission refuses the second one (PodFitsHostPorts in
        # lifecycle/predicate.go GeneralPredicates), which is what makes the Pod
        # Failed so its controller can replace it.  Admitting both instead let
        # each install its own DNAT rule for the same port and neither Pod ever
        # failed -- "[sig-apps] StatefulSet Should recreate evicted statefulset"
        # waits for exactly that failure, because it deliberately parks a Pod on
        # the port the StatefulSet wants.
        HOST_PORT_CONFLICT_REASON = "PodFitsHostPorts"

        def host_port_conflict(pod)
          wanted = host_port_claims(pod)
          return nil if wanted.empty?

          uid = pod_uid(pod)
          @records.each do |other_uid, other|
            next if other_uid.to_s == uid.to_s
            next if %w[Stopped Removed CleanupPending].include?(other[:state].to_s)
            next if %w[Succeeded Failed].include?(other[:phase].to_s)
            # A Pod still in admission holds nothing yet, and one admission
            # refused never will (kubelet's predicate counts admitted Pods
            # only).  Counting them let a StatefulSet's rapidly recreated Pod
            # collide with its own previous incarnation for ever: "host port
            # 21017 is already used by ss-0" for five minutes after the real
            # conflicting Pod was gone ("Should recreate evicted statefulset").
            next if other[:state].to_s == "New" || other[:reason].to_s == "PodAdmissionFailed"

            taken = host_port_claims(other[:pod])
            conflict = wanted.find { |claim| taken.any? { |held| host_ports_collide?(claim, held) } }
            return [conflict, pod_name(other[:pod])] if conflict
          end
          nil
        end

        # A claim on 0.0.0.0 collides with every address on that port.
        def host_ports_collide?(left, right)
          return false unless left[:port] == right[:port] && left[:protocol] == right[:protocol]

          left[:ip] == right[:ip] || left[:ip] == "0.0.0.0" || right[:ip] == "0.0.0.0"
        end

        def host_port_claims(pod)
          spec = Helpers.key(pod || {}, "spec", {})
          containers = Array(Helpers.key(spec, "initContainers", [])) + Array(Helpers.key(spec, "containers", []))
          containers.flat_map do |container|
            Array(Helpers.key(Helpers.string_keys(container), "ports", [])).filter_map do |value|
              port = Helpers.string_keys(value)
              number = Helpers.key(port, "hostPort", nil)
              next nil if number.nil? || number.to_i.zero?

              {port: number.to_i,
               protocol: Helpers.key(port, "protocol", "TCP").to_s.upcase,
               ip: Helpers.key(port, "hostIP", "0.0.0.0").to_s}
            end
          end
        end

        def admit!(pod, record)
          if Runtime::AppArmor.required?(pod) && (message = apparmor_support_error(pod))
            reject_admission!(pod, record, "AppArmor", message)
          end
          if (conflict = host_port_conflict(pod))
            claim, holder = conflict
            reject_admission!(pod, record, HOST_PORT_CONFLICT_REASON,
                              "host port #{claim[:port]}/#{claim[:protocol]} on #{claim[:ip]} is already used by #{holder}")
          end
          result = admit_and_reserve(pod, record)
          allowed = Helpers.success_result?(result)
          # lifecycle/predicate.go Admit: a refusal goes to the admission failure
          # handler (critical-Pod preemption); once it made room the Pod is
          # judged again against what is left.
          attempts = 0
          while !allowed && @preemption && attempts < PREEMPTION_ATTEMPTS
            attempts += 1
            begin
              break unless @preemption.handle_admission_failure(pod, result)
            rescue Preemption::Error => error
              result = {"reason" => Preemption::UNEXPECTED_REASON, "message" => Preemption.unexpected_message(error)}
              break
            end
            event(record, "pod.preempted_others", attempt: attempts)
            result = admit_and_reserve(pod, record)
            allowed = Helpers.success_result?(result)
          end
          return allocate_devices!(pod, record) if allowed

          reason, message = if result.is_a?(Hash)
                              [Helpers.key(result, "reason", "Rejected"),
                               Helpers.key(result, "message", "Pod was rejected by node admission")]
                            elsif value_reports?(result, :reason) && value_reports?(result, :message)
                              [result.reason || "Rejected", result.message || "Pod was rejected by node admission"]
                            else
                              ["Rejected", "Pod was rejected by node admission"]
                            end
          reject_admission!(pod, record, reason, message)
        end

        def admit_and_reserve(pod, record)
          @allocation_mutex.synchronize do
            @mutex.synchronize { record[:allocating_resources] = true }
            result = run_admission(pod)
            @mutex.synchronize { record[:admitted] = true } if Helpers.success_result?(result)
            result
          ensure
            @mutex.synchronize { record.delete(:allocating_resources) }
          end
        end

        def apparmor_support_error(pod)
          return "AppArmor is not enabled on the host" unless Runtime::AppArmor.kernel_enabled?

          backend = @runtime
          if defined?(Runtime::Multiplexer) && backend.is_a?(Runtime::Multiplexer)
            handler = backend.handler_for(pod, runtime_class: pod_runtime_class(pod))
            backend = backend.backends[handler.to_s]
          end
          return if defined?(Runtime::CRI::Backend) && backend.is_a?(Runtime::CRI::Backend)

          "The Pod's runtime cannot enforce AppArmor profiles"
        end

        # Admission rejections are terminal. The public status and event use
        # the predicate's reason and message.
        def reject_admission!(pod, record, reason, message)
          record[:reason] = "PodAdmissionFailed"
          record[:admission_reason] = reason.to_s
          record[:admission_message] = message.to_s
          record[:forced_terminal] = true
          raise LifecycleError, "admission rejected Pod #{pod_name(pod)}: #{reason}: #{message}"
        end

        # One admission per resource a preemption can free (cpu, memory,
        # ephemeral-storage, pods, ...), then the refusal stands.
        PREEMPTION_ATTEMPTS = 4

        def run_admission(pod)
          if @admission.nil?
            true
          elsif admission_supports?(:admit) && accepts_keyword?(@admission, :admit, :other_pods)
            @admission.admit(pod, other_pods: admitted_pods(except: pod_uid(pod)))
          elsif admission_supports?(:admit)
            @admission.admit(pod)
          elsif admission_supports?(:call)
            @admission.call(pod)
          else
            raise LifecycleError, "admission dependency must implement admit or call"
          end
        end

        # devicemanager Allocate in the admit handler: a request the plugins
        # cannot meet rejects the Pod (UnexpectedAdmissionError).
        def allocate_devices!(pod, record)
          return true if @device_plugins.nil?

          @device_plugins.remove_stale(@records.keys)
          @device_plugins.allocate_pod(Helpers.string_keys(pod))
          true
        rescue DevicePlugins::Manager::Error => error
          reject_admission!(pod, record, "UnexpectedAdmissionError", "Allocate failed due to #{error.message}, which is unexpected")
        end
      end
    end
  end
end
