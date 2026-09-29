# frozen_string_literal: true

require "json"

module Rubernetes
  module Scheduler
    # OpportunisticBatching (Beta, on): kube-scheduler reuses the node scores
    # of the previous Pod for the next one when both have the same scheduling
    # signature and the previous Pod filled the node it chose
    # (framework/runtime/batch.go).  A Pod is signed only when every filter
    # and score plugin can sign it; PodTopologySpread cannot sign anything
    # while system default constraints are configured -- the default -- so in
    # a default configuration no Pod is batched, upstream and here alike.
    class OpportunisticBatch
      MAX_BATCH_AGE_SECONDS = 0.5

      # Plugins that implement SignPlugin upstream, and what they contribute.
      # A plugin missing here (a custom DSL plugin) disables signatures.
      SIGNERS = {
        "NodeUnschedulable" => ->(pod, _options) { {"tolerations" => pod.tolerations} },
        "NodeName" => ->(pod, _options) { {"nodeName" => pod.node_name} },
        "TaintToleration" => ->(pod, _options) { {"tolerations" => pod.tolerations} },
        "NodeAffinity" => lambda do |pod, _options|
          {"nodeAffinity" => Support.value(pod.node_affinity, "requiredDuringSchedulingIgnoredDuringExecution", nil),
           "nodeSelector" => pod.node_selector}
        end,
        "NodePorts" => lambda do |pod, _options|
          ports = (pod.init_containers + pod.containers).flat_map { |container| Array(Support.value(container, "ports", [])) }
          {"hostPorts" => ports.select { |port| Support.value(port, "hostPort", 0).to_i.positive? }}
        end,
        "NodeResourcesFit" => ->(pod, _options) { {"resources" => pod.requests.to_h} },
        "NodeResourcesBalancedAllocation" => ->(pod, _options) { {"resources" => pod.requests.to_h} },
        "VolumeRestrictions" => ->(pod, _options) { {"volumes" => pod.volumes} },
        "NodeVolumeLimits" => ->(pod, _options) { {"volumes" => pod.volumes} },
        "VolumeBinding" => ->(pod, _options) { {"volumes" => pod.volumes} },
        "VolumeZone" => ->(pod, _options) { {"volumes" => pod.volumes} },
        "ImageLocality" => lambda do |pod, _options|
          {"imageNames" => (pod.containers + pod.init_containers).map { |container| Support.value(container, "image", "").to_s }.uniq.sort}
        end,
        "InterPodAffinity" => lambda do |pod, _options|
          next :unsignable unless pod.pod_affinity.empty? && pod.pod_anti_affinity.empty?

          {"labels" => pod.labels}
        end,
        "PodTopologySpread" => lambda do |pod, options|
          next :unsignable unless pod.topology_spread_constraints.empty?
          next :unsignable if options[:system_default_constraints]

          {}
        end,
        "DynamicResources" => lambda do |pod, _options|
          Array(Support.value(pod.spec, "resourceClaims", [])).empty? ? {} : :unsignable
        end,
        "NodeDeclaredFeatures" => ->(_pod, _options) { {} }
      }.freeze

      attr_reader :batched_pods

      def initialize(plugin_names:, system_default_constraints: true, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @enabled = plugin_names.all? { |name| SIGNERS.key?(name) }
        @plugin_names = plugin_names.uniq.freeze
        @options = {system_default_constraints: system_default_constraints}.freeze
        @clock = clock
        @state = nil
        @last_cycle = nil
        @batched_pods = 0
        @mutex = Mutex.new
        @metrics = nil
        @flushed = false
      end

      def enabled? = @enabled

      # Scheduler::Metrics (the scheduler_batch_* and node hint series).
      attr_accessor :metrics

      # The Pod's signature, or nil when it cannot be batched.
      def sign(pod)
        return nil unless @enabled

        signature = {"schedulerName" => pod.scheduler_name}
        @plugin_names.each do |name|
          fragments = SIGNERS.fetch(name).call(pod, @options)
          return nil if fragments == :unsignable

          signature.merge!(fragments)
        end
        JSON.generate(signature)
      rescue StandardError
        # SignPod failing leaves the Pod unsigned, never the cycle failed.
        nil
      end

      # GetNodeHint: the next node of the previous Pod's ranking, when the
      # previous cycle scheduled a Pod with this signature onto a node this
      # Pod no longer fits (+fits_last+ runs the filters there).
      def node_hint(signature, cycle, fits_last:)
        started = @clock.call
        hint = fetch_node_hint(signature, cycle, fits_last: fits_last)
        @metrics&.node_hint(!hint.nil?, @clock.call - started)
        hint
      end

      def fetch_node_hint(signature, cycle, fits_last:)
        @mutex.synchronize do
          return nil if @state.nil? || @state[:nodes].empty? || @last_cycle.nil?
          return drop_state("cycle_gap") if cycle != @last_cycle[:cycle] + 1
          return drop_state("signature_mismatch") if signature.nil? || signature != @state[:signature]
          return drop_state("expired") if @clock.call - @state[:created] > MAX_BATCH_AGE_SECONDS
        end
        return nil if fits_last.call(@last_cycle[:chosen])

        @mutex.synchronize { @state && @state[:nodes].shift }
      end
      private :fetch_node_hint

      # StoreScheduleResults.  +ranked+: the other feasible nodes, best first.
      def store(signature, hinted, chosen, ranked, cycle)
        @mutex.synchronize do
          @last_cycle = {cycle: cycle, chosen: chosen}
          if hinted && hinted == chosen
            @batched_pods += 1
            return
          end

          @state = if signature && ranked && !ranked.empty?
                     {signature: signature, nodes: ranked.dup, created: @clock.call}
                   end
        end
      end

      # A cycle that did not schedule its Pod makes the state unusable.
      def failed(cycle)
        @mutex.synchronize do
          @last_cycle = nil
          @state = nil
          _ = cycle
        end
      end

      private

      def drop_state
        @state = nil
        nil
      end
    end
  end
end
