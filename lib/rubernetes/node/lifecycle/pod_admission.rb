# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # Node admission of a Pod: host port conflicts, the admission handler
      # with critical-Pod preemption, and device plugin allocation.
      module PodAdmission
        # HandlePodRemoves: the Pod left the API; admission stops counting it
        # now, even while a worker is still killing its containers.
        def pod_removed(uid)
          @mutex.synchronize do
            record = @records[uid.to_s]
            record[:config_removed] = true if record
          end
        end

        # The Pods this node has admitted and not finished with: what the
        # kubelet's predicate admit handler sizes the node's remaining room by.
        # Public: it is the agent's activePods for the shutdown, eviction, QoS,
        # container and DRA managers (the agent checks respond_to?, which a
        # private method fails).
        def admitted_pods(except: nil)
          @mutex.synchronize do
            @records.values.filter_map do |candidate|
              next if candidate[:uid].to_s == except.to_s
              next if INACTIVE_STATES.include?(candidate[:state].to_s) || %w[Succeeded Failed].include?(candidate[:phase].to_s)
              next if candidate[:config_removed]
              # A Pod whose eviction is queued (preemption, node pressure) is
              # being killed: the kubelet no longer counts it as active.
              next if @eviction_requests.key?(candidate[:uid].to_s)
              next if %w[New].include?(candidate[:state].to_s) && candidate[:containers].to_a.empty? && candidate[:sandbox_id].nil?

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
          if (conflict = host_port_conflict(pod))
            claim, holder = conflict
            record[:reason] = "PodAdmissionFailed"
            record[:admission_reason] = HOST_PORT_CONFLICT_REASON
            raise LifecycleError,
                  "admission rejected Pod #{pod_name(pod)}: #{HOST_PORT_CONFLICT_REASON}: " \
                  "host port #{claim[:port]}/#{claim[:protocol]} on #{claim[:ip]} is already used by #{holder}"
          end
          result = run_admission(pod)
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
            result = run_admission(pod)
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
          # kubelet: an admission rejection is terminal (phase Failed with the
          # admission reason); every other start failure is retried.
          record[:reason] = "PodAdmissionFailed"
          record[:admission_reason] = reason.to_s
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
          record[:reason] = "PodAdmissionFailed"
          record[:admission_reason] = "UnexpectedAdmissionError"
          raise LifecycleError,
                "admission rejected Pod #{pod_name(pod)}: UnexpectedAdmissionError: Allocate failed due to #{error.message}, which is unexpected"
        end
      end
    end
  end
end
