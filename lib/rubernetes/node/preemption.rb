# frozen_string_literal: true

require_relative "../resource_helpers"
require_relative "../schema/quantity"
require_relative "static_pods"
require_relative "status"

module Rubernetes
  module Node
    # pkg/kubelet/preemption (v1.36.2): CriticalPodAdmissionHandler.  When
    # the node's admission turns a critical Pod down for lack of resources,
    # lower-priority Pods are evicted to make room and the Pod is admitted
    # after all.
    #
    # Only insufficient-resource failures are recoverable; any other failure
    # reason stands.  The Pods to evict are chosen per QoS class -- BestEffort
    # first, then Burstable, then Guaranteed, each class only as far as the
    # classes before it fell short -- and within a class by "distance": the
    # squared, normalised shortfall each candidate leaves, the smaller request
    # winning a tie (memory before CPU).  Every chosen Pod is killed as
    # Failed / Preempting with a DisruptionTarget condition, a Warning
    # "Preempting" event and a kubelet_preemptions count.
    class Preemption
      MESSAGE = "Preempted in order to admit critical pod"
      # events.PreemptContainer.
      REASON = "Preempting"
      DISRUPTION_MESSAGE = "Pod was preempted by Kubelet to accommodate a critical pod."
      # scheduling.SystemCriticalPriority.
      SYSTEM_CRITICAL_PRIORITY = 2_000_000_000
      # An admission failure the handler could not recover from
      # (lifecycle/predicate.go Admit).
      UNEXPECTED_REASON = "UnexpectedAdmissionError"
      QOS_ORDER = %w[BestEffort Burstable Guaranteed].freeze

      class Error < StandardError; end

      # One InsufficientResourceError: the amount the Pod is short of.
      Requirement = Struct.new(:resource, :quantity) do
        def to_s = "(res: #{resource}, q: #{quantity}), "
      end

      # kubetypes.IsCriticalPod: a static Pod, a mirror Pod, or one whose
      # priority is system-critical.
      def self.critical?(pod)
        pod = Helpers.string_keys(pod || {})
        return true if static?(pod) || mirror?(pod)

        priority = pod.dig("spec", "priority")
        !priority.nil? && Integer(priority) >= SYSTEM_CRITICAL_PRIORITY
      rescue ArgumentError, TypeError
        false
      end

      # kubetypes.IsStaticPod: a Pod whose config source is not the API server.
      def self.static?(pod)
        source = (pod.dig("metadata", "annotations") || {})[StaticPods::CONFIG_SOURCE]
        !source.nil? && source.to_s != "api"
      end

      def self.mirror?(pod)
        (pod.dig("metadata", "annotations") || {}).key?(StaticPods::CONFIG_MIRROR)
      end

      # kubetypes.Preemptable.
      def self.preemptable?(preemptor, preemptee)
        return true if critical?(preemptor) && !critical?(preemptee)

        left = Helpers.string_keys(preemptor || {}).dig("spec", "priority")
        right = Helpers.string_keys(preemptee || {}).dig("spec", "priority")
        return false if left.nil? || right.nil?

        Integer(left) > Integer(right)
      end

      # resource.GetResourceRequest: milli-CPUs for cpu, the integer value
      # otherwise, 1 for pods; container requests replaced by pod-level ones
      # when set; the overhead added only to a non-zero request.
      def self.resource_request(pod, resource)
        return 1 if resource.to_s == "pods"

        pod = Helpers.string_keys(pod || {})
        pod_level = ResourceHelpers.pod_level_resources_set?(pod)
        requests = ResourceHelpers.pod_requests(pod, skip_container_level: pod_level, exclude_overhead: true)
        quantity = requests[resource.to_s]
        value = quantity.nil? ? 0r : quantity.value
        overhead = ResourceHelpers.resource_list(pod.dig("spec", "overhead"))[resource.to_s]
        value += overhead.value if overhead && !value.zero?
        resource.to_s == "cpu" ? (value * 1000).ceil : value.ceil
      end

      # The insufficient-resource requirement an admission Decision carries
      # (Node::Admission#insufficient), nil for any other refusal.
      def self.requirement_for(decision)
        details = if decision.respond_to?(:details)
                    decision.details
                  elsif decision.is_a?(Hash)
                    Helpers.key(decision, "details", nil)
                  end
        return nil unless details.is_a?(Hash)

        details = Helpers.string_keys(details)
        resource = details["resource"].to_s
        return nil if resource.empty? || !details.key?("requested") || !details.key?("used") || !details.key?("capacity")

        # InsufficientResourceError.GetInsufficientAmount.
        amount = Integer(details["requested"]) - (Integer(details["capacity"]) - Integer(details["used"]))
        Requirement.new(resource, amount)
      rescue ArgumentError, TypeError
        nil
      end

      # +active_pods+: the admitted Pods (getAllocatedPods); +kill_pod+:
      # killPodFunc(pod, message:, condition:, reason:), raising on failure;
      # +recorder+: an EventRecorder-like #record for the Preempting event;
      # +metrics+: a KubeletMetrics (or a lambda returning one).
      def initialize(active_pods:, kill_pod:, recorder: nil, metrics: nil, logger: nil)
        @active_pods = active_pods
        @kill_pod = kill_pod
        @recorder = recorder
        @metrics = metrics
        @logger = logger
      end

      # HandleAdmissionFailure for our single-decision admission: returns
      # true when the Pod is critical, the refusal was an insufficient
      # resource and Pods were evicted to cover it (the caller re-admits),
      # false when the refusal stands as it is.  Raises Error when no set of
      # Pods can free the resource (the caller refuses with
      # UnexpectedAdmissionError).
      def handle_admission_failure(pod, decision)
        return false unless self.class.critical?(pod)

        requirement = self.class.requirement_for(decision)
        return false if requirement.nil?

        evict_pods_to_free_requests(pod, [requirement])
        true
      end

      # Message of the admission refusal for an unrecoverable failure.
      def self.unexpected_message(error)
        "Unexpected error while attempting to recover from admission failure: #{error.message}"
      end

      def evict_pods_to_free_requests(admit_pod, requirements)
        pods = Array(@active_pods.call).map { |pod| Helpers.string_keys(pod) }
        begin
          to_preempt = self.class.pods_to_preempt(admit_pod, pods, requirements)
        rescue Error => error
          raise Error, "preemption: error finding a set of pods to preempt: #{error.message}"
        end
        to_preempt.each do |pod|
          record_event(pod)
          @logger&.call(:info, "preemption.evict", pod: "#{pod.dig("metadata", "namespace")}/#{pod.dig("metadata", "name")}",
                                                   insufficient: self.class.requirements_to_s(requirements),
                                                   requesting: "#{admit_pod.dig("metadata", "namespace")}/#{admit_pod.dig("metadata", "name")}")
          condition = {"type" => "DisruptionTarget", "status" => "True", "reason" => "TerminationByKubelet",
                       "message" => DISRUPTION_MESSAGE, "observedGeneration" => pod.dig("metadata", "generation")}.compact
          begin
            @kill_pod.call(pod, message: MESSAGE, condition: condition, reason: REASON)
          rescue StandardError => error
            @logger&.call(:error, "preemption.evict_failed", pod: pod.dig("metadata", "name"), error: error.message)
            next
          end
          metrics&.preemption(requirements.empty? ? "" : requirements.first.resource)
        end
        to_preempt
      end

      # getPodsToPreempt.
      def self.pods_to_preempt(preemptor, pods, requirements)
        best_effort, burstable, guaranteed = sort_pods_by_qos(preemptor, pods)
        unable = subtract(requirements, best_effort + burstable + guaranteed)
        raise Error, "no set of running pods found to reclaim resources: #{requirements_to_s(unable)}" unless unable.empty?

        guaranteed_to_evict = pods_to_preempt_by_distance(guaranteed, subtract(requirements, best_effort + burstable))
        burstable_to_evict = pods_to_preempt_by_distance(burstable, subtract(requirements, best_effort + guaranteed_to_evict))
        best_effort_to_evict = pods_to_preempt_by_distance(best_effort, subtract(requirements, burstable_to_evict + guaranteed_to_evict))
        best_effort_to_evict + burstable_to_evict + guaranteed_to_evict
      end

      # getPodsToPreemptByDistance, including Go's swap-remove of the chosen
      # Pod (the last candidate takes its slot), which decides ties.
      def self.pods_to_preempt_by_distance(pods, requirements)
        pods = pods.dup
        to_evict = []
        until requirements.empty?
          raise Error, "no set of running pods found to reclaim resources: #{requirements_to_s(requirements)}" if pods.empty?

          best_distance = (requirements.length + 1).to_f
          best_index = 0
          pods.each_with_index do |pod, index|
            dist = distance(requirements, pod)
            if dist < best_distance || (best_distance == dist && smaller_resource_request?(pod, pods[best_index]))
              best_distance = dist
              best_index = index
            end
          end
          requirements = subtract(requirements, [pods[best_index]])
          to_evict << pods[best_index]
          pods[best_index] = pods[-1]
          pods.pop
        end
        to_evict
      end

      # admissionRequirementList.distance.
      def self.distance(requirements, pod)
        requirements.sum(0.0) do |requirement|
          remaining = (requirement.quantity - resource_request(pod, requirement.resource)).to_f
          remaining.positive? ? (remaining / requirement.quantity.to_f)**2 : 0.0
        end
      end

      # admissionRequirementList.subtract.
      def self.subtract(requirements, pods)
        requirements.filter_map do |requirement|
          quantity = requirement.quantity
          pods.each do |pod|
            quantity -= resource_request(pod, requirement.resource)
            break if quantity <= 0
          end
          Requirement.new(requirement.resource, quantity) if quantity.positive?
        end
      end

      def self.requirements_to_s(requirements)
        "[#{requirements.map(&:to_s).join}]"
      end

      # sortPodsByQOS: the preemptable Pods by QoS class.
      def self.sort_pods_by_qos(preemptor, pods)
        classes = {"BestEffort" => [], "Burstable" => [], "Guaranteed" => []}
        pods.each do |pod|
          next unless preemptable?(preemptor, pod)

          qos = ResourceHelpers.qos_class(pod).to_s
          classes[qos] << pod if classes.key?(qos)
        end
        QOS_ORDER.map { |qos| classes[qos] }
      end

      # smallerResourceRequest: memory first, then CPU; equal is true.
      def self.smaller_resource_request?(left, right)
        %w[memory cpu].each do |resource|
          first = resource_request(left, resource)
          second = resource_request(right, resource)
          return true if first < second
          return false if first > second
        end
        true
      end

      private

      def metrics
        value = @metrics.respond_to?(:call) && !@metrics.respond_to?(:preemption) ? @metrics.call : @metrics
        value.respond_to?(:preemption) ? value : nil
      end

      def record_event(pod)
        return unless @recorder.respond_to?(:record)

        metadata = pod["metadata"] || {}
        @recorder.record(
          involved_object: {"apiVersion" => "v1", "kind" => "Pod", "namespace" => metadata["namespace"],
                            "name" => metadata["name"], "uid" => metadata["uid"]}.compact,
          reason: REASON, type: "Warning", namespace: metadata["namespace"], message: MESSAGE
        )
      rescue StandardError => error
        @logger&.call(:debug, "preemption.event_failed", error: "#{error.class}: #{error.message}")
      end
    end
  end
end
