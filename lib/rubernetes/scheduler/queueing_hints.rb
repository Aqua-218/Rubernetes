# frozen_string_literal: true

module Rubernetes
  module Scheduler
    # SchedulerQueueingHints: each plugin registers the cluster events that
    # can make a Pod it rejected schedulable, with a QueueingHint function
    # that looks at the event's old and new object and answers Queue or
    # QueueSkip.  The scheduling queue asks the hints of a Pod's rejecting
    # plugins before moving it, instead of retrying every unschedulable Pod
    # on every change (pkg/scheduler/framework/plugins/*: EventsToRegister
    # and isSchedulableAfter*).
    module QueueingHints
      QUEUE = :queue
      SKIP = :skip

      # A ClusterEvent as its label spells it: resource + action.  A plugin's
      # registration is "Node" with actions %w[Add UpdateNodeLabel ...];
      # "Update" matches every Update* subtype, "*" every action.
      Registration = Struct.new(:resource, :actions, :hint, keyword_init: true) do
        def matches?(event)
          resource_label, action = QueueingHints.split_event(event)
          return false unless resource_label == resource

          actions.any? do |wanted|
            wanted == "*" || wanted == action || (wanted == "Update" && action.start_with?("Update"))
          end
        end
      end

      RESOURCES = %w[Node assignedPod Pod PersistentVolumeClaim PersistentVolume StorageClass CSINode CSIDriver
                     CSIStorageCapacity VolumeAttachment ResourceClaim ResourceSlice DeviceClass Namespace Service PodGroup Workload].freeze

      def self.split_event(event)
        label = event.to_s
        resource = RESOURCES.sort_by { |name| -name.length }.find { |name| label.start_with?(name) }
        return [label, ""] if resource.nil?

        [resource, label.delete_prefix(resource)]
      end

      # Pod events cover both the assigned and unassigned Pod resources.
      def self.pod_registration(actions, hint = nil)
        [Registration.new(resource: "Pod", actions: actions, hint: hint),
         Registration.new(resource: "assignedPod", actions: actions, hint: hint)]
      end

      def self.node(actions, hint = nil) = Registration.new(resource: "Node", actions: actions, hint: hint)

      def self.value(object, *path)
        source = object.respond_to?(:to_h) && !object.is_a?(Hash) ? object.to_h : object
        path.reduce(source) do |current, key|
          break nil unless current.is_a?(Hash)

          current.key?(key) ? current[key] : current[key.to_sym]
        end
      end

      def self.uid(object) = value(object, "metadata", "uid").to_s
      def self.namespace(object) = value(object, "metadata", "namespace").to_s
      def self.name(object) = value(object, "metadata", "name").to_s
      def self.labels(object) = value(object, "metadata", "labels") || {}
      def self.node_name(pod) = value(pod, "spec", "nodeName").to_s
      def self.nominated(pod) = value(pod, "status", "nominatedNodeName").to_s
      def self.bound?(pod) = !node_name(pod).empty? || !nominated(pod).empty?
      def self.volumes(pod) = Array(value(pod, "spec", "volumes"))
      def self.tolerations(pod) = Array(value(pod, "spec", "tolerations"))
      def self.taints(node) = Array(value(node, "spec", "taints"))

      def self.claim_names(pod)
        volumes(pod).filter_map do |volume|
          if (claim = value(volume, "persistentVolumeClaim")) then value(claim, "claimName").to_s
          elsif value(volume, "ephemeral") then "#{name(pod)}-#{value(volume, "name")}"
          end
        end
      end

      # v1helper.TolerationsTolerateTaint for NoSchedule/NoExecute taints.
      def self.tolerates?(toleration, taint)
        return false unless toleration.is_a?(Hash) && taint.is_a?(Hash)

        effect = value(toleration, "effect").to_s
        return false unless effect.empty? || effect == value(taint, "effect").to_s

        operator = value(toleration, "operator").to_s
        key = value(toleration, "key").to_s
        return true if key.empty? && operator == "Exists"
        return false unless key == value(taint, "key").to_s

        operator == "Exists" || ((operator.empty? || operator == "Equal") && value(toleration, "value").to_s == value(taint, "value").to_s)
      end

      def self.untolerated_taint?(node, pod)
        taints(node).any? do |taint|
          next false unless %w[NoSchedule NoExecute].include?(value(taint, "effect").to_s)

          tolerations(pod).none? { |toleration| tolerates?(toleration, taint) }
        end
      end

      def self.node_selector_matches?(pod, node)
        node_labels = labels(node)
        selector = value(pod, "spec", "nodeSelector") || {}
        return false unless selector.all? { |key, wanted| node_labels[key.to_s] == wanted }

        terms = Array(value(pod, "spec", "affinity", "nodeAffinity", "requiredDuringSchedulingIgnoredDuringExecution", "nodeSelectorTerms"))
        return true if terms.empty?

        terms.any? { |term| term_matches?(term, node) }
      end

      def self.term_matches?(term, node)
        node_labels = labels(node)
        Array(value(term, "matchExpressions")).all? { |requirement| requirement_matches?(requirement, node_labels) } &&
          Array(value(term, "matchFields")).all? { |requirement| requirement_matches?(requirement, {"metadata.name" => name(node)}) }
      end

      def self.requirement_matches?(requirement, labels)
        key = value(requirement, "key").to_s
        values = Array(value(requirement, "values")).map(&:to_s)
        present = labels.key?(key)
        actual = labels[key].to_s
        case value(requirement, "operator").to_s
        when "In" then present && values.include?(actual)
        when "NotIn" then !present || !values.include?(actual)
        when "Exists" then present
        when "DoesNotExist" then !present
        when "Gt" then present && actual.match?(/\A-?\d+\z/) && actual.to_i > values.first.to_i
        when "Lt" then present && actual.match?(/\A-?\d+\z/) && actual.to_i < values.first.to_i
        else false
        end
      end

      def self.host_ports(pod)
        %w[initContainers containers].flat_map { |field| Array(value(pod, "spec", field)) }.flat_map do |container|
          Array(value(container, "ports")).filter_map do |port|
            host_port = value(port, "hostPort").to_i
            next if host_port.zero?

            [value(port, "hostIP").to_s.empty? ? "0.0.0.0" : value(port, "hostIP").to_s, (value(port, "protocol") || "TCP").to_s, host_port]
          end
        end
      end

      def self.ports_conflict?(wanted, used)
        wanted.any? do |ip, protocol, port|
          used.any? do |used_ip, used_protocol, used_port|
            port == used_port && protocol == used_protocol && (ip == used_ip || ip == "0.0.0.0" || used_ip == "0.0.0.0")
          end
        end
      end

      def self.resource_requests(pod)
        return Support.requests_for(pod).transform_values(&:to_f) if pod.respond_to?(:to_h) && !pod.is_a?(Hash)

        totals = Hash.new(0.0)
        Array(value(pod, "spec", "containers")).each do |container|
          (value(container, "resources", "requests") || {}).each { |key, quantity| totals[key.to_s] += Support.quantity(quantity).to_f }
        end
        Array(value(pod, "spec", "initContainers")).each do |container|
          (value(container, "resources", "requests") || {}).each do |key, quantity|
            totals[key.to_s] = [totals[key.to_s], Support.quantity(quantity).to_f].max
          end
        end
        totals
      end

      def self.quantities(map)
        (map || {}).to_h { |key, quantity| [key.to_s, Support.quantity(quantity).to_f] }
      end

      # isFit ignoring the other Pods: does the node's allocatable hold the requests at all?
      def self.fits_allocatable?(pod, node)
        allocatable = quantities(value(node, "status", "allocatable"))
        resource_requests(pod).all? { |key, amount| amount <= 0 || allocatable.fetch(key, 0.0) >= amount }
      end

      def self.requested_resources_increased?(pod, old_node, new_node)
        before = quantities(value(old_node, "status", "allocatable"))
        after = quantities(value(new_node, "status", "allocatable"))
        resource_requests(pod).any? { |key, amount| amount.positive? && after.fetch(key, 0.0) > before.fetch(key, 0.0) }
      end

      def self.selector_matches?(selector, labels)
        return false if selector.nil?

        (value(selector, "matchLabels") || {}).all? { |key, wanted| labels[key.to_s] == wanted } &&
          Array(value(selector, "matchExpressions")).all? { |requirement| requirement_matches?(requirement, labels) }
      end

      def self.spread_constraints(pod) = Array(value(pod, "spec", "topologySpreadConstraints"))

      def self.affinity_terms(pod, kind)
        Array(value(pod, "spec", "affinity", kind, "requiredDuringSchedulingIgnoredDuringExecution"))
      end

      def self.term_matches_pod?(term, pod, other)
        namespaces = Array(value(term, "namespaces"))
        namespaces = [namespace(pod)] if namespaces.empty? && value(term, "namespaceSelector").nil?
        return false unless namespaces.empty? || namespaces.include?(namespace(other))

        selector_matches?(value(term, "labelSelector"), labels(other))
      end

      def self.pod_matches_all_terms?(terms, pod, other)
        !terms.empty? && terms.all? { |term| term_matches_pod?(term, pod, other) }
      end

      def self.resource_claim_names(pod)
        statuses = Array(value(pod, "status", "resourceClaimStatuses"))
        Array(value(pod, "spec", "resourceClaims")).filter_map do |claim|
          value(claim, "resourceClaimName") || statuses.find do |status|
            value(status, "name") == value(claim, "name")
          end&.then { |status| value(status, "resourceClaimName") }
        end.map(&:to_s)
      end

      # -- the registrations, per plugin -------------------------------------

      NODE_UNSCHEDULABLE = lambda do |_pod, old_node, new_node|
        was = old_node && value(old_node, "spec", "unschedulable") == true
        now = value(new_node, "spec", "unschedulable") == true
        (old_node && was && !now) || (old_node.nil? && !now) ? QUEUE : SKIP
      end

      TOLERATES_UNSCHEDULABLE = lambda do |pod, _old, new_pod|
        next SKIP unless uid(pod) == uid(new_pod)

        taint = {"key" => "node.kubernetes.io/unschedulable", "effect" => "NoSchedule"}
        tolerations(new_pod).any? { |toleration| tolerates?(toleration, taint) } ? QUEUE : SKIP
      end

      TAINT_NODE_CHANGE = lambda do |pod, old_node, new_node|
        was_untolerated = old_node.nil? || untolerated_taint?(old_node, pod)
        was_untolerated && !untolerated_taint?(new_node, pod) ? QUEUE : SKIP
      end

      SAME_POD = ->(pod, _old, new_pod) { uid(pod) == uid(new_pod) ? QUEUE : SKIP }

      NODE_AFFINITY_CHANGE = lambda do |pod, old_node, new_node|
        next SKIP unless node_selector_matches?(pod, new_node)
        next QUEUE if old_node.nil?

        node_selector_matches?(pod, old_node) ? SKIP : QUEUE
      end

      POD_DELETED_PORTS = lambda do |pod, deleted, _new|
        next SKIP unless bound?(deleted)

        used = host_ports(deleted)
        next SKIP if used.empty?

        ports_conflict?(host_ports(pod), used) ? QUEUE : SKIP
      end

      FIT_POD_EVENT = lambda do |pod, old_pod, new_pod|
        if new_pod.nil?
          bound?(old_pod) ? QUEUE : SKIP
        else
          # UpdatePodScaleDown: the running Pod asks for less than before.
          before = resource_requests(old_pod)
          after = resource_requests(new_pod)
          wanted = resource_requests(pod)
          before.any? { |key, amount| wanted.fetch(key, 0.0).positive? && after.fetch(key, 0.0) < amount } ? QUEUE : SKIP
        end
      end

      FIT_NODE_CHANGE = lambda do |pod, old_node, new_node|
        next SKIP unless fits_allocatable?(pod, new_node)
        next QUEUE if old_node.nil?

        requested_resources_increased?(pod, old_node, new_node) ? QUEUE : SKIP
      end

      VOLUME_RESTRICTIONS_POD_DELETED = lambda do |pod, deleted, _new|
        next SKIP unless namespace(deleted) == namespace(pod)

        mine = claim_names(pod)
        claim_names(deleted).any? { |claim| mine.include?(claim) } ? QUEUE : SKIP
      end

      PVC_OF_POD = lambda do |pod, _old, claim|
        namespace(claim) == namespace(pod) && claim_names(pod).include?(name(claim)) ? QUEUE : SKIP
      end

      VOLUME_LIMITS_POD_DELETED = lambda do |_pod, deleted, _new|
        next SKIP if volumes(deleted).empty? || !bound?(deleted)

        volumes(deleted).any? { |volume| value(volume, "persistentVolumeClaim") || value(volume, "ephemeral") } ? QUEUE : SKIP
      end

      CSINODE_LIMIT_RAISED = lambda do |_pod, old_csi_node, new_csi_node|
        old_limits = Array(value(old_csi_node, "spec", "drivers")).to_h do |driver|
          [value(driver, "name"), value(driver, "allocatable", "count").to_i]
        end
        if Array(value(new_csi_node, "spec", "drivers")).any? do |driver|
          value(driver, "allocatable", "count").to_i > old_limits.fetch(value(driver, "name"), 0)
        end
          QUEUE
        else
          SKIP
        end
      end

      VOLUME_ATTACHMENT_DELETED = lambda do |pod, _deleted, _new|
        volumes(pod).any? { |volume| value(volume, "persistentVolumeClaim") } ? QUEUE : SKIP
      end

      STORAGE_CLASS_CHANGE = lambda do |_pod, old_class, new_class|
        next QUEUE if old_class.nil?

        value(old_class, "allowedTopologies") == value(new_class, "allowedTopologies") ? SKIP : QUEUE
      end

      CSINODE_MIGRATION_CHANGE = lambda do |_pod, old_csi_node, new_csi_node|
        next QUEUE if old_csi_node.nil?

        key = "storage.alpha.kubernetes.io/migrated-plugins"
        value(old_csi_node, "metadata", "annotations", key) == value(new_csi_node, "metadata", "annotations", key) ? SKIP : QUEUE
      end

      STORAGE_CLASS_WFFC = lambda do |_pod, _old, new_class|
        value(new_class, "volumeBindingMode").to_s == "WaitForFirstConsumer" ? QUEUE : SKIP
      end

      PV_TOPOLOGY_CHANGE = lambda do |_pod, old_pv, new_pv|
        next QUEUE if old_pv.nil?

        topology = lambda { |pv|
          [value(pv, "spec", "nodeAffinity"), labels(pv)["topology.kubernetes.io/zone"], labels(pv)["topology.kubernetes.io/region"]]
        }
        topology.call(old_pv) == topology.call(new_pv) ? SKIP : QUEUE
      end

      SPREAD_POD_CHANGE = lambda do |pod, old_pod, new_pod|
        constraints = spread_constraints(pod)
        involved = ->(other) { namespace(other) == namespace(pod) && bound?(other) }
        next SKIP if (new_pod && !involved.call(new_pod)) || (old_pod && !involved.call(old_pod))

        matches = ->(other) { constraints.any? { |constraint| selector_matches?(value(constraint, "labelSelector"), labels(other)) } }
        if new_pod && old_pod
          next QUEUE if uid(pod) == uid(new_pod) && tolerations(old_pod) != tolerations(new_pod) && constraints.any? do |constraint|
            value(constraint, "nodeTaintsPolicy").to_s == "Honor"
          end
          next SKIP if labels(old_pod) == labels(new_pod)

          if constraints.any? do |constraint|
            selector_matches?(value(constraint, "labelSelector"),
                              labels(old_pod)) != selector_matches?(value(constraint, "labelSelector"), labels(new_pod))
          end
            QUEUE
          else
            SKIP
          end
        else
          matches.call(new_pod || old_pod) ? QUEUE : SKIP
        end
      end

      SPREAD_NODE_CHANGE = lambda do |pod, old_node, new_node|
        constraints = spread_constraints(pod)
        matching = ->(node) { constraints.all? { |constraint| labels(node).key?(value(constraint, "topologyKey").to_s) } }
        if old_node && new_node
          before = matching.call(old_node)
          after = matching.call(new_node)
          next QUEUE if before != after

          keys = constraints.map { |constraint| value(constraint, "topologyKey").to_s }
          if after && (keys.any? do |key|
            labels(old_node)[key] != labels(new_node)[key]
          end || taints(old_node) != taints(new_node))
            QUEUE
          else
            SKIP
          end
        elsif new_node
          matching.call(new_node) ? QUEUE : SKIP
        else
          matching.call(old_node) ? QUEUE : SKIP
        end
      end

      AFFINITY_POD_CHANGE = lambda do |pod, old_pod, new_pod|
        next QUEUE if new_pod && old_pod && uid(pod) == uid(new_pod)
        next SKIP if (new_pod && !bound?(new_pod)) || (old_pod && !bound?(old_pod))

        terms = affinity_terms(pod, "podAffinity")
        anti = affinity_terms(pod, "podAntiAffinity")
        if new_pod && old_pod
          next QUEUE if !pod_matches_all_terms?(terms, pod, old_pod) && pod_matches_all_terms?(terms, pod, new_pod)
          next QUEUE if pod_matches_all_terms?(anti, pod, old_pod) && !pod_matches_all_terms?(anti, pod, new_pod)

          SKIP
        elsif new_pod
          pod_matches_all_terms?(terms, pod, new_pod) ? QUEUE : SKIP
        else
          next QUEUE if pod_matches_all_terms?(anti, pod, old_pod)

          pod_matches_all_terms?(affinity_terms(old_pod, "podAntiAffinity"), old_pod, pod) ? QUEUE : SKIP
        end
      end

      AFFINITY_NODE_CHANGE = lambda do |pod, old_node, new_node|
        terms = affinity_terms(pod, "podAffinity")
        anti = affinity_terms(pod, "podAntiAffinity")
        queue = terms.any? do |term|
          key = value(term, "topologyKey").to_s
          if old_node.nil? then labels(new_node).key?(key)
          else
            (!labels(old_node).key?(key) && labels(new_node).key?(key)) ||
              (labels(old_node).key?(key) && labels(new_node).key?(key) && labels(old_node)[key] != labels(new_node)[key])
          end
        end
        queue ||= anti.any? do |term|
          key = value(term, "topologyKey").to_s
          old_node.nil? || (labels(old_node).key?(key) && !labels(new_node).key?(key)) ||
            (labels(old_node).key?(key) && labels(new_node).key?(key) && labels(old_node)[key] != labels(new_node)[key])
        end
        queue ? QUEUE : SKIP
      end

      CLAIM_CHANGE = lambda do |pod, old_claim, new_claim|
        uses = resource_claim_names(pod).include?(name(new_claim)) && namespace(new_claim) == namespace(pod)
        next QUEUE if old_claim && value(old_claim, "status", "allocation") && value(new_claim, "status", "allocation").nil?
        next SKIP unless uses
        next QUEUE if old_claim.nil?

        value(old_claim, "status") == value(new_claim, "status") ? SKIP : QUEUE
      end

      GENERATED_CLAIM = lambda do |pod, _old, new_pod|
        next SKIP unless uid(pod) == uid(new_pod)

        if Array(value(new_pod, "spec", "resourceClaims")).all? do |claim|
          value(claim, "resourceClaimName") || Array(value(new_pod, "status", "resourceClaimStatuses")).any? do |status|
            value(status, "name") == value(claim, "name") && value(status, "resourceClaimName")
          end
        end
          QUEUE
        else
          SKIP
        end
      end

      # helper.MatchingSchedulingGroup: same namespace and podGroupName.
      SAME_GANG_POD_ADDED = lambda do |pod, _old, added|
        mine = value(pod, "spec", "schedulingGroup", "podGroupName").to_s
        theirs = value(added, "spec", "schedulingGroup", "podGroupName").to_s
        !mine.empty? && mine == theirs && namespace(pod) == namespace(added) ? QUEUE : SKIP
      end

      OWN_POD_GROUP_ADDED = lambda do |pod, _old, group|
        mine = value(pod, "spec", "schedulingGroup", "podGroupName").to_s
        !mine.empty? && namespace(group) == namespace(pod) && name(group) == mine ? QUEUE : SKIP
      end

      NODE_UPDATE_ALL = %w[Add UpdateNodeTaint UpdateNodeLabel].freeze

      REGISTRATIONS = {
        "NodeUnschedulable" => [node(NODE_UPDATE_ALL, NODE_UNSCHEDULABLE),
                                *pod_registration(%w[UpdatePodToleration], TOLERATES_UNSCHEDULABLE)],
        "NodeName" => [node(NODE_UPDATE_ALL)],
        "TaintToleration" => [node(%w[Add UpdateNodeTaint], TAINT_NODE_CHANGE), *pod_registration(%w[UpdatePodToleration], SAME_POD)],
        "NodeAffinity" => [node(NODE_UPDATE_ALL, NODE_AFFINITY_CHANGE)],
        "NodePorts" => [*pod_registration(%w[Delete], POD_DELETED_PORTS), node(NODE_UPDATE_ALL)],
        "NodeResourcesFit" => [*pod_registration(%w[Delete UpdatePodScaleDown], FIT_POD_EVENT),
                               node(%w[Add UpdateNodeAllocatable UpdateNodeTaint UpdateNodeLabel], FIT_NODE_CHANGE),
                               Registration.new(resource: "DeviceClass", actions: %w[Add Update], hint: nil)],
        "VolumeRestrictions" => [*pod_registration(%w[Delete], VOLUME_RESTRICTIONS_POD_DELETED), node(NODE_UPDATE_ALL),
                                 Registration.new(resource: "PersistentVolumeClaim", actions: %w[Add], hint: PVC_OF_POD)],
        "NodeVolumeLimits" => [Registration.new(resource: "CSINode", actions: %w[Add], hint: nil),
                               Registration.new(resource: "CSINode", actions: %w[Update], hint: CSINODE_LIMIT_RAISED),
                               *pod_registration(%w[Delete], VOLUME_LIMITS_POD_DELETED),
                               Registration.new(resource: "PersistentVolumeClaim", actions: %w[Add], hint: PVC_OF_POD),
                               Registration.new(resource: "VolumeAttachment", actions: %w[Delete], hint: VOLUME_ATTACHMENT_DELETED)],
        "VolumeBinding" => [Registration.new(resource: "StorageClass", actions: %w[Add Update], hint: STORAGE_CLASS_CHANGE),
                            Registration.new(resource: "PersistentVolumeClaim", actions: %w[Add Update], hint: PVC_OF_POD),
                            Registration.new(resource: "PersistentVolume", actions: %w[Add Update], hint: nil),
                            node(%w[Add UpdateNodeLabel UpdateNodeTaint]),
                            Registration.new(resource: "CSINode", actions: %w[Add Update], hint: CSINODE_MIGRATION_CHANGE),
                            Registration.new(resource: "CSIDriver", actions: %w[Add Update], hint: nil),
                            Registration.new(resource: "CSIStorageCapacity", actions: %w[Add Update], hint: nil)],
        "VolumeZone" => [Registration.new(resource: "StorageClass", actions: %w[Add], hint: STORAGE_CLASS_WFFC), node(%w[Add UpdateNodeLabel UpdateNodeTaint]),
                         Registration.new(resource: "PersistentVolumeClaim", actions: %w[Add Update], hint: PVC_OF_POD),
                         Registration.new(resource: "PersistentVolume", actions: %w[Add Update], hint: PV_TOPOLOGY_CHANGE)],
        "PodTopologySpread" => [*pod_registration(%w[Add UpdatePodLabel UpdatePodToleration Delete], SPREAD_POD_CHANGE),
                                node(%w[Add Delete UpdateNodeLabel UpdateNodeTaint], SPREAD_NODE_CHANGE)],
        "InterPodAffinity" => [*pod_registration(%w[Add UpdatePodLabel Delete], AFFINITY_POD_CHANGE),
                               node(%w[Add UpdateNodeLabel UpdateNodeTaint], AFFINITY_NODE_CHANGE)],
        "DynamicResources" => [node(%w[Add UpdateNodeLabel UpdateNodeTaint UpdateNodeAllocatable]),
                               Registration.new(resource: "ResourceClaim", actions: %w[Add Update], hint: CLAIM_CHANGE),
                               *pod_registration(%w[UpdatePodGeneratedResourceClaim], GENERATED_CLAIM),
                               Registration.new(resource: "DeviceClass", actions: %w[Add Update], hint: nil),
                               Registration.new(resource: "ResourceSlice", actions: %w[Add Update], hint: nil)],
        "SchedulingGates" => pod_registration(%w[UpdatePodSchedulingGatesEliminated], SAME_POD),
        "GangScheduling" => [*pod_registration(%w[Add], SAME_GANG_POD_ADDED),
                             Registration.new(resource: "PodGroup", actions: %w[Add], hint: OWN_POD_GROUP_ADDED)],
        "NodeDeclaredFeatures" => [node(%w[Add UpdateNodeDeclaredFeature])],
        "DefaultPreemption" => pod_registration(%w[Delete], nil)
      }.freeze

      # The registrations of one plugin (none: the plugin is retried on any event).
      def self.registrations(plugin) = REGISTRATIONS[plugin.to_s]

      # isPodWorthRequeuing: :skip, :after_backoff or :immediately.
      # +observer+ (optional): ->(plugin, event, hint_label, seconds).
      def self.strategy(pod, rejecting_plugins, event, old_object, new_object, pending_plugins: [], observer: nil)
        plugins = Array(rejecting_plugins).map(&:to_s).uniq
        return :after_backoff if plugins.empty?

        strategy = :skip
        plugins.each do |plugin|
          registrations = REGISTRATIONS[plugin]
          # An unknown plugin registers no hints: any event may help.
          return :after_backoff if registrations.nil?

          registrations.each do |registration|
            next unless registration.matches?(event)

            hint = QUEUE
            label = "Queue"
            if registration.hint
              started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
              begin
                hint = registration.hint.call(pod, old_object, new_object)
                label = hint == QUEUE ? "Queue" : "QueueSkip"
              rescue StandardError
                hint = QUEUE
                label = "Error"
              end
              observer&.call(plugin, event, label, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
            end
            next if hint == SKIP
            return :immediately if pending_plugins.include?(plugin)

            strategy = :after_backoff
          end
        end
        strategy
      end
    end
  end
end
