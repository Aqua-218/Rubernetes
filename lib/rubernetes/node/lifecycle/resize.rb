# frozen_string_literal: true

module Rubernetes
  module Node
    class Lifecycle
      # In-place Pod resize (InPlacePodVerticalScaling): feasibility,
      # admission, actuation through the Pod and container cgroups, and the
      # resize conditions.
      module Resize
        private

        def resizing_in_place?(record, object)
          # A Pod whose resources cannot be compared is not being resized.
          best_effort(false) do
            record[:state] == "Running" && record[:pod] && PodResize.resources_changed?(record[:pod], object) &&
              resize_only_change?(record[:pod], object)
          end
        end

        # InPlacePodVerticalScaling: the only difference between the running
        # Pod and the desired one is container resources.
        def resize_only_change?(current, desired)
          strip = lambda do |pod|
            value = Helpers.deep_copy(Helpers.string_keys(pod))
            spec = value["spec"].is_a?(Hash) ? value["spec"] : {}
            %w[containers initContainers].each do |field|
              Array(spec[field]).each { |container| container.delete("resources") if container.is_a?(Hash) }
            end
            # InPlacePodLevelResourcesVerticalScaling: pod-level resources are
            # resized in place too, not by recreating the Pod.
            spec.delete("resources")
            value
          end
          config_digest(strip.call(current)) == config_digest(strip.call(desired))
        end

        # allocation manager handlePodResourcesResize + kuberuntime
        # doPodResizeAction.  A resize that does not fit what the node has left
        # waits as PodResizePending/Deferred (retried on every sync); one that
        # fits is actuated -- pod-level resources through the Pod cgroup,
        # container resources through each container's -- with
        # PodResizeInProgress while it runs and, on failure (a memory limit
        # below current usage), until the next attempt.
        def resize_pod(record, pod)
          timing = {}
          object = normalize_pod(pod)
          allocated = record[:pod]
          generation = Helpers.key(Helpers.key(object, "metadata", {}), "generation", nil)
          generation = generation.nil? ? nil : Integer(generation)
          unless PodResize.resources_changed?(allocated, object)
            record[:resize_pending] = nil
            resize_containers(record, object)
            return
          end
          # HandlePodUpdates recordContainerResizeOperations: once per update
          # that changes what is asked for.
          requested = record[:resize_requested] || allocated
          if PodResize.resources_changed?(requested, object)
            metrics_call(:resize_requested, requested, object)
            record[:resize_requested] = object
          end
          return if hold_infeasible_resize(record, allocated, object, generation)
          return if defer_refused_resize(record, object, generation)

          actuate_resize(record, allocated, object, generation, timing)
        rescue StandardError => error
          raise unless record[:resize_in_progress]

          metrics_call(:pod_resize_duration, Process.clock_gettime(Process::CLOCK_MONOTONIC) - timing[:started], false) if timing[:started]
          record[:resize_in_progress] = record[:resize_in_progress].merge("reason" => "Error", "message" => Helpers.failure_message(error))
          event(record, "pod.resize_error",
                message: PodResize.message("Pod resize error", object, generation, Helpers.failure_message(error)))
          update_status(object, record)
        end

        # PodResizePending/Infeasible: the node can never satisfy the resize
        # (the static CPU or memory manager policy pins what it would change).
        # True when the resize waits for that reason.
        def hold_infeasible_resize(record, allocated, object, generation)
          infeasible = resize_infeasible(allocated, object)
          return false unless infeasible

          detail, message = infeasible
          previous = record[:resize_pending]
          record[:resize_pending] = {"type" => "PodResizePending", "reason" => "Infeasible", "message" => message,
                                     "observedGeneration" => generation,
                                     "lastTransitionTime" => if previous &&
                                                                previous["reason"] == "Infeasible"
                                                               previous["lastTransitionTime"]
                                                             else
                                                               Helpers.now(@clock).iso8601(6)
                                                             end}
          metrics_call(:pod_infeasible_resize, detail)
          if previous.nil? || previous["reason"] != "Infeasible" || previous["observedGeneration"] != generation
            event(record, "pod.resize_infeasible", message: PodResize.message("Pod resize Infeasible", object, generation, message))
          end
          update_status(object, record)
          true
        end

        # PodResizePending/Deferred: the resized Pod does not fit what the
        # other Pods leave on the node right now; retried on every sync.
        # True when the resize waits for that reason.
        def defer_refused_resize(record, object, generation)
          decision = resize_admission(record, object)
          return false if decision.nil? || Helpers.success_result?(decision)

          message = value_reports?(decision, :message) ? decision.message.to_s : Helpers.key(decision, "message", "").to_s
          previous = record[:resize_pending]
          record[:resize_pending] = {"type" => "PodResizePending", "reason" => "Deferred", "message" => message,
                                     "observedGeneration" => generation,
                                     "lastTransitionTime" => previous ? previous["lastTransitionTime"] : Helpers.now(@clock).iso8601(6)}
          if previous.nil? || previous["observedGeneration"] != generation
            event(record, "pod.resize_deferred", message: PodResize.message("Pod resize Deferred", object, generation, message))
          end
          update_status(object, record)
          true
        end

        # doPodResizeAction: PodResizeInProgress while the cgroups are
        # rewritten.  +timing+ receives the moment actuation started, for the
        # caller's failure report.
        def actuate_resize(record, allocated, object, generation, timing)
          deferred = record[:resize_pending]
          if deferred && deferred["reason"] == "Deferred"
            # retryPendingResizes: the Pod's own update, or a later retry.
            metrics_call(:deferred_resize_accepted, deferred["observedGeneration"] == generation ? "periodic_retry" : "pod_updated")
          end
          record[:resize_pending] = nil
          started = Helpers.now(@clock).iso8601(6)
          actuation = timing[:started] = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          record[:resize_in_progress] = {"type" => "PodResizeInProgress", "observedGeneration" => generation, "lastTransitionTime" => started}
          event(record, "pod.resize_started", message: PodResize.message("Pod resize started", object, generation))
          pod_level = PodResize.pod_level_changed?(allocated, object)
          error = resize_memory_error(record, allocated, object)
          unless error.nil?
            record[:resize_in_progress] = record[:resize_in_progress].merge("reason" => "Error", "message" => error)
            metrics_call(:pod_resize_duration, Process.clock_gettime(Process::CLOCK_MONOTONIC) - actuation, false)
            event(record, "pod.resize_error", message: PodResize.message("Pod resize error", object, generation, error))
            update_status(object, record)
            return
          end

          grows = pod_level && pod_level_grows?(allocated, object)
          update_pod_cgroup(record, object) if pod_level && grows
          resize_containers(record, object)
          update_pod_cgroup(record, object) if pod_level && !grows
          record[:pod_cgroup] = runtime_pod_cgroup(record)
          record[:resize_in_progress] = nil
          metrics_call(:pod_resize_duration, Process.clock_gettime(Process::CLOCK_MONOTONIC) - actuation, true)
          event(record, "pod.resize_completed", message: PodResize.message("Pod resize completed", object, generation))
          update_status(object, record)
        end

        def resize_infeasible(allocated, desired)
          return nil unless @container_manager

          # Feasibility is a refinement of the answer; when the managers'
          # policies cannot be read the resize goes on to admission.
          best_effort do
            PodResize.infeasible(allocated, desired, cpu_policy: @container_manager.cpu_manager_policy,
                                                     memory_policy: @container_manager.memory_manager_policy)
          end
        end

        # canAdmitPod(..., ResizeOperation): the resized Pod against what the
        # other admitted Pods leave on the node.
        def resize_admission(record, pod)
          return nil if @admission.nil? || !admission_supports?(:admit) || !accepts_keyword?(@admission, :admit, :other_pods)

          @admission.admit(pod, other_pods: admitted_pods(except: record[:uid]))
        end

        # validateMemoryResizeAction: a pod-level memory limit that decreases
        # below what the Pod uses now is refused.
        def resize_memory_error(record, allocated, desired)
          resources = Runtime::Native::Resources
          old_limit = resources.pod_cgroup_limits(allocated)["memory.max"]
          new_limit = resources.pod_cgroup_limits(desired)["memory.max"]
          return nil if new_limit.nil?
          return nil if old_limit && Integer(new_limit) >= Integer(old_limit)

          readback = runtime_pod_cgroup(record)
          usage = readback && readback["memory.current"]
          return "cannot decrease memory limits: missing pod memory usage" if usage.nil? && readback
          return nil if usage.nil?
          return nil if Integer(usage) < Integer(new_limit)

          "cannot decrease memory limits: attempting to set pod memory limit (#{Integer(new_limit)}) below current usage (#{Integer(usage)})"
        rescue ArgumentError, TypeError
          nil
        end

        def pod_level_grows?(allocated, desired)
          before = ResourceHelpers.pod_limits(allocated)
          after = ResourceHelpers.pod_limits(desired)
          %w[cpu memory].any? { |name| after[name] && (before[name].nil? || after[name].value > before[name].value) }
        end

        def update_pod_cgroup(record, pod)
          return unless runtime_supports?(:update_pod_resources) && record[:sandbox_id]

          invoke(@runtime, :update_pod_resources, record[:sandbox_id], pod_spec: Helpers.key(pod, "spec", {}))
        end

        def runtime_pod_cgroup(record)
          return nil unless runtime_supports?(:pod_cgroup_readback) && record[:sandbox_id]

          # A cgroup that cannot be read back (the Pod is going away) leaves
          # the status without the actual resources.
          best_effort { invoke(@runtime, :pod_cgroup_readback, record[:sandbox_id]) }
        end

        # kubelet doPodResizeAction: reconfigure the container (and Pod) cgroups
        # for the new requests/limits; the Pod keeps running and its status
        # reports the resources it now runs with.
        def resize_containers(record, pod)
          object = normalize_pod(pod)
          spec = Helpers.key(object, "spec", {})
          %w[containers initContainers].each do |field|
            Array(Helpers.key(spec, field, [])).each do |definition|
              name = Helpers.key(definition, "name", "").to_s
              entry = record[:containers].find { |candidate| candidate[:name] == name }
              next if entry.nil?

              resources = Helpers.deep_copy(Helpers.key(definition, "resources", {}) || {})
              next if Helpers.deep_copy(Helpers.key(entry[:spec], "resources", {}) || {}) == resources

              # container.resizePolicy: a resource whose policy is
              # RestartContainer cannot be changed in place -- the container is
              # restarted with the new value instead (types.go: "resize the
              # container in-place" vs "RestartContainer").  The field was
              # validated by the API server and read by nobody, so a container
              # that asked to be restarted for a memory change was silently
              # resized in place.
              restart_needed = resize_requires_restart?(definition, entry, resources)
              applied = nil
              if restart_needed && entry[:started]
                event(record, "container.resize_restart", name: name, container_id: entry[:id])
                entry[:spec] = Helpers.immutable(Helpers.deep_copy(entry[:spec]).merge("resources" => resources))
                restart_container(object, record, entry, reason: "ResizeRestart")
                next
              end
              if entry[:started] && runtime_supports?(:update_container_resources)
                applied = invoke(@runtime, :update_container_resources, entry[:id], resources: resources, pod_spec: spec)
              end
              entry[:spec] = Helpers.immutable(Helpers.deep_copy(entry[:spec]).merge("resources" => resources))
              event(record, "container.resized", name: name, container_id: entry[:id], started: entry[:started],
                                                 runtime: runtime_supports?(:update_container_resources),
                                                 runtime_class: @runtime.class.name, limits: applied)
            end
          end
          record[:pod] = Helpers.immutable(object)
          update_status(object, record)
        end

        # Which resources changed, and does any of them carry
        # resizePolicy: RestartContainer?
        def resize_requires_restart?(definition, entry, desired_resources)
          policies = Array(Helpers.key(definition, "resizePolicy", [])).to_h do |rule|
            [Helpers.key(rule, "resourceName", "").to_s, Helpers.key(rule, "restartPolicy", "").to_s]
          end
          return false if policies.empty?

          current = Helpers.deep_copy(Helpers.key(entry[:spec], "resources", {}) || {})
          changed_resource_names(current, desired_resources).any? do |name|
            policies[name].to_s == "RestartContainer"
          end
        end

        def changed_resource_names(current, desired)
          names = []
          %w[requests limits].each do |section|
            before = Helpers.key(current, section, {}) || {}
            after = Helpers.key(desired, section, {}) || {}
            (before.keys | after.keys).each do |key|
              names << key.to_s if before[key].to_s != after[key].to_s
            end
          end
          names.uniq
        end
      end
    end
  end
end
